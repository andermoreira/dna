# POCDNA Architecture

## Overview

POCDNA implements terminal-based authentication through a three-layer fingerprinting strategy. Each layer provides signals from a different trust domain — the browser (untrusted), a local daemon (trusted, external to the browser), and the TLS transport (server-observed, client-unaware).

```
TRUST DOMAIN MODEL
═══════════════════════════════════════════════════════════════

  UNTRUSTED (Browser JS)          TRUSTED (OS Daemon)        OBSERVED (Server TLS)
  ┌──────────────────┐            ┌──────────────────┐       ┌──────────────────┐
  │ Canvas   5.7 bits │            │ os.cpus()         │       │ JA4 Hash         │
  │ WebGL    8-10 bits│   HMAC     │ os.hostname()     │       │ Cipher Suites    │
  │ Audio    5-7 bits │ ────────→  │ os.totalmem()     │       │ Extensions       │
  │ Fonts            │  signed    │ os.userInfo()     │       │ Version          │
  │ Screen           │            │ os.networkIfs()   │       │                  │
  │ ...              │            │ fs.readdir()      │       │                  │
  └──────────────────┘            └──────────────────┘       └──────────────────┘
         │                               │                          │
         │  Layer 1: browser             │  Layer 2: daemon         │  Layer 3: tls
         │  fuzzy Jaccard match          │  HMAC validation         │  hash comparison
         │                               │                          │
         └───────────────────────────────┼──────────────────────────┘
                                         │
                                   ┌─────▼──────┐
                                   │  CONFIDENCE │
                                   │   SCORING   │
                                   │  ≥2/3 layers│
                                   └─────┬──────┘
                                         │
                                   ┌─────▼──────┐
                                   │  ALLOW/DENY │
                                   └────────────┘
```

## Component Interaction

```mermaid
sequenceDiagram
    participant Browser
    participant Daemon as Local Daemon (root)
    participant Express as Express Server
    participant DB as SQLite

    Note over Browser,DB: Registration Flow

    Browser->>Browser: Fingerprint.collectAll()
    Note over Browser: Canvas render → SHA-256<br/>WebGL params → SHA-256<br/>Audio sample → SHA-256<br/>Font detection array<br/>Screen/Platform data

    Browser->>Daemon: GET https://127.0.0.1:30900/fingerprint
    Note over Daemon: Reads os.cpus(), hostname,<br/>network interfaces, installed apps<br/>Signs: HMAC-SHA256(payload, secret)

    Daemon-->>Browser: { payload: {...15 fields}, signature: "hex..." }

    Browser->>Express: POST /api/auth/register-terminal
    Note over Express: Validates browser FP<br/>Validates daemon HMAC signature<br/>Extracts JA4 from TLS socket<br/>Stores composite fingerprint

    Express->>DB: INSERT terminals, daemon_secrets, auth_events
    DB-->>Express: ok
    Express-->>Browser: { terminalId, layers: {browser, daemon, tls} }

    Note over Browser,DB: Verification Flow (subsequent)

    Browser->>Browser: Fingerprint.collectAll()
    Browser->>Daemon: GET /fingerprint
    Daemon-->>Browser: { payload, signature }
    Browser->>Express: POST /api/auth/verify-terminal

    Express->>DB: SELECT terminals WHERE user_id
    DB-->>Express: [{ stored_browser_fp, stored_daemon_fp, stored_secret, ja4_hash }]

    Note over Express: Layer 1: fuzzyMatch(known, candidate)<br/>→ weighted Jaccard per signal<br/>Layer 2: HMAC(payload, stored_secret) == signature<br/>Layer 3: req.ja4.hash == stored_ja4_hash

    Express->>DB: UPDATE last_seen_at
    Express-->>Browser: { known: true, confidence: 0.95 }
```

## Database Schema

```mermaid
erDiagram
    users {
        TEXT id PK "UUID"
        TEXT username UK "Unique username"
        TEXT password_hash "bcrypt 12 rounds"
        TEXT created_at "ISO 8601"
    }

    terminals {
        TEXT id PK "UUID"
        TEXT user_id FK "References users.id"
        TEXT label "User-given name"
        TEXT browser_fp_hash "SHA-256 of browser components"
        TEXT browser_fp_data "JSON blob of components"
        TEXT daemon_fp_hash "SHA-256 of daemon payload"
        TEXT daemon_fp_data "JSON blob of payload"
        TEXT ja4_hash "TLS ClientHello hash"
        TEXT registered_at "ISO 8601"
        TEXT last_seen_at "ISO 8601"
        TEXT revoked_at "NULL until revoked"
    }

    daemon_secrets {
        TEXT terminal_id PK_FK "1:1 with terminals"
        TEXT secret_key "Base64-encoded 256-bit key"
        TEXT created_at "ISO 8601"
    }

    auth_events {
        TEXT id PK "UUID"
        TEXT user_id FK "References users.id"
        TEXT terminal_id FK "Nullable"
        TEXT event_type "REGISTER, VERIFY_OK, VERIFY_FAIL, REVOKE"
        REAL confidence "0.0 to 1.0"
        TEXT layers_matched "JSON: {browser, daemon, tls}"
        TEXT ip_address "Request IP"
        TEXT user_agent "Browser UA"
        TEXT ja4_observed "JA4 at event time"
        TEXT created_at "ISO 8601"
    }

    users ||--o{ terminals : "owns"
    terminals ||--o| daemon_secrets : "has"
    users ||--o{ auth_events : "generates"
    terminals ||--o{ auth_events : "referenced in"
```

## Confidence Scoring Algorithm

```mermaid
flowchart TD
    subgraph Inputs
        BF["browserScore: 0.0-1.0"]
        DV["daemonValid: true|false|null"]
        TM["tlsMatch: true|false|null"]
    end

    subgraph Process
        BW{"browserScore ≥ 0.7?"}
        BW -->|"Yes"| BW1["matched++, available++\nbrowser = true"]
        BW -->|"Score > 0 and <0.7"| BW2["available++\nbrowser = false"]
        BW -->|"Score = 0"| BW3["browser = null"]

        DM{"daemonValid?"}
        DM -->|"true"| DM1["matched++, available++"]
        DM -->|"false"| DM2["available++"]
        DM -->|"null"| DM3["daemon = null"]

        TL{"tlsMatch?"}
        TL -->|"true"| TL1["matched++, available++"]
        TL -->|"false"| TL2["available++"]
        TL -->|"null"| TL3["tls = null"]
    end

    subgraph Decision
        BW1 & DM1 & TL1 --> Calc
        BW2 & DM2 & TL2 --> Calc
        BW3 & DM3 & TL3 --> Calc

        Calc["required = min(2, max(1, available))\nknown = matched ≥ required\nconfidence = matched / available"]
    end
```

### Browser FP Fuzzy Matching

The weighted Jaccard algorithm compares stored vs candidate fingerprint components:

```
FOR each signal WITH weight:
  IF signal is list (fonts, plugins):
    similarity = |intersection| / |union|
    score += similarity × weight
  ELSE:
    score += (stored == candidate) ? weight : 0

totalScore = score / totalWeight
```

Hardware-dependent signals (Canvas: 25%, WebGL: 20%, Audio: 15%) receive higher weights because they're stable across browser upgrades and resistant to spoofing. Software signals (Plugins: 1%) receive low weights because they change frequently.

## Daemon Architecture

```mermaid
flowchart TD
    subgraph Startup
        Key{"/tmp/pocdna-secret.key\nexists?"}
        Key -->|"Yes"| Load["Load existing key"]
        Key -->|"No"| Gen["crypto.randomBytes(32)\nSave with chmod 600\nPrint base64 for user"]
        Load --> CertCheck
        Gen --> CertCheck
    end

    subgraph TLS["TLS Setup"]
        CertCheck{"/tmp/pocdna-cert.pem\nexists & valid?"}
        CertCheck -->|"Yes"| LoadCert["Load existing cert + key"]
        CertCheck -->|"No"| Mkcert{"mkcert available?"}
        Mkcert -->|"Yes"| GenMkcert["mkcert -cert-file -key-file\n127.0.0.1 localhost ::1\n→ locally-trusted, zero warnings"]
        Mkcert -->|"No"| OpenSSL{"openssl available?"}
        OpenSSL -->|"Yes"| GenCert["openssl req -x509\nCN=POCDNA Daemon\n→ self-signed, browser warning"]
        OpenSSL -->|"No"| Fallback["Fallback to HTTP\n(localhost only)"]
        LoadCert --> Listen
        GenMkcert --> Listen
        GenCert --> Listen
        Fallback --> Listen
    end

    subgraph Server
        Listen["Listen 127.0.0.1:30900"]
        Listen --> Health["GET /health → {status:ok}"]
        Listen --> FP["GET /fingerprint"]
        FP --> Collect["Collect 15 OS fields"]
        Collect --> Sort["Sort keys deterministically"]
        Sort --> Sign["HMAC-SHA256(payload, key)"]
        Sign --> Respond["{ payload, signature }"]
    end
```

### Why the daemon runs outside Docker

The daemon must run on the host machine (not containerized) because:
1. It collects **real** OS data (`os.cpus()`, `os.networkInterfaces()`, `os.hostname()`)
2. Container isolation would expose the container's virtualized OS, not the host's
3. This mirrors Warsaw — the daemon is an **external, privileged component**, not part of the browser or server

## Session & Terminal Binding

```mermaid
sequenceDiagram
    participant Browser
    participant Server

    Note over Browser,Server: After successful /api/auth/verify-terminal

    Server->>Server: req.session.terminalId = matchedTerminalId
    Server->>Server: req.session.terminalVerifiedAt = Date.now()

    Note over Browser,Server: User attempts sensitive action

    Browser->>Server: POST /api/actions/sensitive (with session cookie)

    Server->>Server: requireAuth → check req.session.userId
    Server->>Server: requireKnownTerminal → check req.session.terminalId
    Server->>Server: Load terminal from DB, check not revoked

    alt Terminal valid & not revoked
        Server-->>Browser: 200 { message: "Action completed" }
    else No terminal in session
        Server-->>Browser: 403 { error: "Terminal not authorized" }
    else Terminal revoked
        Server-->>Browser: 403 { error: "Terminal revoked" }
    end
```

The terminal verification result is cached in the session — subsequent requests from the same session don't need to re-collect the fingerprint. This is a POC optimization; production would re-verify at configurable intervals.

## Security Considerations

### What the daemon solves

| Threat | Browser-only FP | With Daemon |
|---|---|---|
| Headless browser spoofing (Puppeteer) | ❌ Trivial bypass | ✅ Daemon HMAC can't be forged from browser context |
| Canvas fingerprint replay | ❌ Capture & replay | ✅ Daemon timestamp rejects old payloads |
| User-Agent spoofing | ❌ Trivial string change | ✅ JA4 cross-validates UA against actual TLS stack |

### What remains (production gaps)

| Gap | POC State | Production Path |
|---|---|---|
| Secret key on disk | Readable by any process (`/tmp`) | TPM/HSM-bound key, Secure Enclave |
| Daemon is a script | Can be killed, replaced | Native binary with kernel driver (Warsaw's `gbpkm.sys`) |
| No anti-VM detection | VM fingerprint identical to host | Detect hypervisor artifacts, SMBIOS |
| CA cert not trusted | User sees browser warning (openssl) or zero warnings (mkcert) | Inject CA into trust stores (Warsaw's `certutil -A`) |
| HMAC symmetric key | Server knows the secret | WebAuthn asymmetric (private key never leaves device) |

## File Map

```
pocdna/
├── docker-compose.yml          → Single service: server on port 3000
├── server/
│   ├── Dockerfile              → node:20-alpine, npm install, runs src/index.js
│   ├── src/
│   │   ├── index.js            → Express app: session, JA4 middleware, all routers
│   │   ├── db.js               → better-sqlite3 with WAL, 4 tables, lazy init
│   │   ├── seed.js             → Creates demo/demo123 if not exists
│   │   ├── middleware/
│   │   │   ├── auth.js         → requireAuth: checks req.session.userId
│   │   │   ├── ja4.js          → extractJa4: reads TLS ClientHello from socket
│   │   │   └── requireTerminal.js → requireKnownTerminal: checks req.session.terminalId
│   │   ├── routes/
│   │   │   ├── auth.js         → /api/auth/register|login|logout|me
│   │   │   ├── terminals.js    → /api/auth/register-terminal|verify-terminal|user/terminals
│   │   │   └── admin.js        → /api/admin/terminals (list + revoke)
│   │   └── services/
│   │       └── fingerprint.js  → hashComponents, fuzzyMatchBrowserFP, validateDaemonHmac, computeConfidence
│   └── public/
│       ├── login.html          → Login/register form, dark theme
│       ├── index.html          → Dashboard: status, registration, device list, sensitive action
│       ├── admin.html          → Admin: all terminals table, revoke button
│       └── js/
│           └── fingerprint.js  → Browser FP engine: 10 signals → visitorId + components
└── daemon/
    └── daemon.js               → OS daemon: secret key, os.* collection, HMAC signing, HTTPS server
```
