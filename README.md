# POCDNA — Terminal Authentication POC

Demonstrates an extra security layer for web applications where each user terminal is uniquely identified by a **three-layer fingerprint** (browser signals + local OS daemon + TLS fingerprint). Only pre-registered terminals can execute sensitive actions.

Inspired by **Warsaw/G-Buster** (GAS Tecnologia/Diebold Nixdorf) — the mandatory security module used by ~25 Brazilian banks (Banco do Brasil, Itaú, Caixa, etc.) for internet banking.

## The Problem

Browser-only fingerprinting (Canvas, WebGL, Audio) is **spoofable** — an attacker with a headless browser (Puppeteer, Playwright) can forge every JavaScript-collected signal.

Warsaw solves this by running a **native daemon** outside the browser that collects real OS-level data the browser cannot access. POCDNA demonstrates this architecture in pure Node.js.

## Architecture

```mermaid
flowchart TB
    subgraph Browser["Browser (User's Machine)"]
        direction TB
        JS["JavaScript\nCanvas, WebGL, Audio\nFonts, Screen, Plugins"]
        Fetch["fetch() to Daemon"]
        JS --> Fetch
    end

    subgraph Daemon["Local Daemon (root/privileged)"]
        direction TB
        OS["os.cpus(), os.hostname()\nos.networkInterfaces()\nos.totalmem(), os.userInfo()\nfs.readdir('/Applications')"]
        HMAC["HMAC-SHA256(payload, secret.key)"]
        TLS["HTTPS Server\n127.0.0.1:30900"]
        OS --> HMAC --> TLS
    end

    subgraph Server["Application Server"]
        direction TB
        L1["Layer 1: Fuzzy match\nbrowser fingerprint"]
        L2["Layer 2: Validate\nHMAC signature"]
        L3["Layer 3: TLS fingerprint\n(JA4 ClientHello)"]
        Score["Confidence Scoring\n≥2/3 layers → known"]
        L1 --> Score
        L2 --> Score
        L3 --> Score
    end

    Browser -- "POST /api/auth/verify-terminal\n{browserFP, daemonPayload, daemonSignature}" --> Server
    Fetch -- "GET /fingerprint" --> TLS
    Server -. "JA4 extracted from TLS handshake" .-> L3

    Score --> Decision{"Known?"}
    Decision -->|"Yes (≥2/3)"| Allow["Allow sensitive action"]
    Decision -->|"No (≤1/3)"| Block["Block with 403"]
```

### Layer Breakdown

```mermaid
flowchart LR
    subgraph L1["Layer 1: Browser FP"]
        direction TB
        L1c["Canvas fingerprint\n(5.7 bits entropy)"]
        L1w["WebGL fingerprint\n(8-10 bits entropy)"]
        L1a["Audio fingerprint\n(5-7 bits entropy)"]
        L1f["Font detection"]
        L1s["Screen, tz, platform..."]
    end

    subgraph L2["Layer 2: Daemon FP"]
        direction TB
        L2c["CPU model & cores"]
        L2h["Hostname, username"]
        L2m["RAM, uptime"]
        L2n["Network interfaces"]
        L2a["Installed applications"]
        L2hmac["HMAC-SHA256 signed\nsecret never exposed to JS"]
    end

    subgraph L3["Layer 3: TLS FP"]
        direction TB
        L3j["JA4 hash from ClientHello\n(cipher suites, extensions...)"]
        L3ua["Cross-validate with\nUser-Agent header"]
    end

    L1 --> Weighted["Weighted Jaccard Score\nHW signals > SW signals"]
    L2 --> Validate["HMAC Signature Check"]
    L3 --> Compare["Hash Comparison"]
```

## Authentication Flow

```mermaid
sequenceDiagram
    actor User
    participant Browser
    participant Daemon as Local Daemon
    participant Server

    Note over User,Server: First Access (Unknown Terminal)

    User->>Browser: Login (username + password)
    Browser->>Server: POST /api/auth/login
    Server-->>Browser: Session cookie

    Browser->>Browser: Fingerprint.collectAll()
    Note over Browser: Canvas, WebGL, Audio, fonts, screen...

    Browser->>Daemon: GET https://127.0.0.1:30900/fingerprint
    Daemon-->>Browser: { payload, signature }

    Browser->>Server: POST /api/auth/verify-terminal
    Note over Server: Layer 1: fuzzy match browser FP<br/>Layer 2: validate HMAC<br/>Layer 3: extract JA4<br/>Result: 1/3 layers matched

    Server-->>Browser: { known: false, confidence: 0.33 }
    Browser->>User: "Unknown Terminal — Register?"

    User->>Browser: Enter label + daemon secret key
    Browser->>Server: POST /api/auth/register-terminal
    Note over Server: Store browser FP hash<br/>Store daemon payload hash<br/>Store daemon secret key<br/>Store JA4 hash

    Server-->>Browser: { terminalId, layers: {browser,daemon,tls} }
    Browser->>User: "Terminal Registered"

    Note over User,Server: Subsequent Access (Known Terminal)

    User->>Browser: Login
    Browser->>Server: POST /api/auth/login
    Browser->>Browser: Fingerprint.collectAll()
    Browser->>Daemon: GET /fingerprint
    Browser->>Server: POST /api/auth/verify-terminal
    Note over Server: Layer 1: match ✓<br/>Layer 2: HMAC valid ✓<br/>Layer 3: JA4 match ✓<br/>Confidence: 1.0

    Server-->>Browser: { known: true }
    Browser->>User: "Terminal Recognized"

    User->>Browser: Perform Sensitive Action
    Browser->>Server: POST /api/actions/sensitive
    Note over Server: Terminal guard: session.terminalId exists ✓

    Server-->>Browser: 200 OK
```

## The Warsaw Comparison

```mermaid
flowchart LR
    subgraph Warsaw["Warsaw/G-Buster (Production)"]
        direction TB
        W1["Native daemon (C binary)\nRuns as root via systemd"]
        W2["Kernel driver (gbpkm.sys)\nAnti-keylogger, anti-termination"]
        W3["CA cert injection\ncertutil into browser trust stores"]
        W4["WebSocket wss://127.0.0.1:30900\nSelf-signed TLS"]
        W5["Anti-VM/sandbox detection\nReturns r:0 in containers"]
    end

    subgraph POCDNA["POCDNA (Demonstration)"]
        direction TB
        P1["Node.js daemon\nnode daemon.js"]
        P2["No kernel driver\nDocumented as production gap"]
        P3["Manual cert trust\nUser accepts browser warning"]
        P4["HTTPS GET 127.0.0.1:30900\nSelf-signed TLS"]
        P5["No anti-VM detection\nDocumented as production gap"]
    end

    Warsaw -. "Mirrors architecture" .-> POCDNA
```

## Quick Start

Prerequisites: **Docker**, **Node.js 20+**, **openssl** (for daemon TLS cert)

```bash
# 1. Start the server
docker compose up -d

# 2. Start the local daemon
node daemon/daemon.js

# 3. Open http://localhost:3000/login.html
#    Login: demo / demo123
```

## Demo Flow

| Step | Action | Expected |
|---|---|---|
| 1 | Open `http://localhost:3000/login.html` | Login form |
| 2 | Login with `demo` / `demo123` | Redirect to dashboard |
| 3 | Dashboard collects fingerprint + queries daemon | Terminal status badge appears |
| 4 | If unknown: enter label + paste daemon secret key | "Register This Terminal" |
| 5 | Terminal registered → automatically verified | Green badge "Secure" or "Basic" |
| 6 | Click "Perform Sensitive Action" | Success toast |
| 7 | Remove terminal from device list | Terminal gone |
| 8 | Click "Perform Sensitive Action" again | 403 blocked |
| 9 | Open `/admin.html` with key `pocdna-admin-secret` | View/revoke all terminals |

## Confidence Scoring

```mermaid
flowchart TD
    Start["Collect 3 layers"] --> BW{"Browser FP\nfuzzy match ≥ 0.7?"}
    BW -->|Yes| BwPass["browser: true"]
    BW -->|No| BwFail["browser: false"]

    Start --> DM{"Daemon HMAC\nvalid signature?"}
    DM -->|Yes| DmPass["daemon: true"]
    DM -->|No| DmFail["daemon: false"]
    DM -->|Not provided| DmNull["daemon: null"]

    Start --> TL{"TLS JA4\nhash matches?"}
    TL -->|Yes| TlPass["tls: true"]
    TL -->|No| TlFail["tls: false"]
    TL -->|Not available| TlNull["tls: null"]

    BwPass & DmPass & TlPass --> Count["Count matched layers\nCount available layers"]
    BwFail & DmFail & TlFail --> Count
    DmNull & TlNull --> Count

    Count --> Thresh{"matched ≥ min(2, available)?"}
    Thresh -->|Yes| Known["known: true\nconfidence = matched/available"]
    Thresh -->|No| Unknown["known: false\nconfidence = matched/available"]
```

### Weighted Browser Signals

| Signal | Weight | Type | Stability |
|---|---|---|---|
| Canvas | 25% | Hardware | High (GPU/driver dependent) |
| WebGL | 20% | Hardware | High (GPU vendor/renderer) |
| Audio | 15% | Hardware | High (CPU/DSP dependent) |
| Platform | 10% | Software | Medium |
| Screen | 10% | Software | Medium |
| Fonts | 8% | Software | Medium |
| Timezone | 5% | Config | High |
| HardwareConcurrency | 4% | Hardware | High |
| TouchSupport | 2% | Hardware | High |
| Plugins | 1% | Software | Low (frequently changes) |

## API Reference

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/api/auth/register` | — | Create user account |
| POST | `/api/auth/login` | — | Login, creates session |
| POST | `/api/auth/logout` | Session | Destroy session |
| GET | `/api/auth/me` | Session | Current user info |
| POST | `/api/auth/register-terminal` | Session | Register new terminal |
| POST | `/api/auth/verify-terminal` | Session | Verify current terminal |
| GET | `/api/auth/user/terminals` | Session | List user's terminals |
| DELETE | `/api/auth/user/terminals/:id` | Session | Remove terminal |
| POST | `/api/actions/sensitive` | Session + Terminal | Simulated sensitive action |
| GET | `/api/admin/terminals` | `x-admin-key` | List all terminals |
| POST | `/api/admin/terminals/:id/revoke` | `x-admin-key` | Revoke terminal |

### Daemon Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `https://127.0.0.1:30900/health` | Health check |
| GET | `https://127.0.0.1:30900/fingerprint` | Returns `{ payload, signature }` |

## Project Structure

```
pocdna/
├── docker-compose.yml
├── README.md
├── docs/
│   └── architecture.md          (detailed architecture docs)
├── specs/
│   ├── terminal-auth-poc.md     (full spec)
│   └── steps/                   (atomic step definitions)
├── daemon/
│   ├── package.json
│   └── daemon.js                (local OS-level daemon, port 30900)
└── server/
    ├── Dockerfile
    ├── package.json
    ├── src/
    │   ├── index.js             (Express application entry point)
    │   ├── db.js                (SQLite database schema & connection)
    │   ├── seed.js              (demo user seeder)
    │   ├── middleware/
    │   │   ├── auth.js          (session authentication guard)
    │   │   ├── ja4.js           (TLS ClientHello fingerprint extraction)
    │   │   └── requireTerminal.js (terminal authorization guard)
    │   ├── routes/
    │   │   ├── auth.js          (user registration & login)
    │   │   ├── terminals.js     (terminal registration & verification)
    │   │   └── admin.js         (admin panel API)
    │   └── services/
    │       └── fingerprint.js   (hashing, fuzzy matching, HMAC, confidence)
    └── public/
        ├── login.html           (login page)
        ├── index.html           (user dashboard)
        ├── admin.html           (admin panel)
        └── js/
            └── fingerprint.js   (browser fingerprinting engine)
```

## Limitations (POC vs Production)

| Aspect | POC | Production (Warsaw/WebAuthn) |
|---|---|---|
| Browser FP | Custom JS (~10 signals) | Fingerprint Pro (100+ signals) |
| Daemon | Node.js script | Native binary (C) |
| Kernel protection | None | Kernel driver (anti-keylogger) |
| Secret storage | Plain file (`/tmp`) | TPM / Secure Enclave |
| TLS trust | Manual browser warning | CA cert injected via certutil |
| Anti-VM detection | None | Detects bwrap/FHS containers |
| Device binding | HMAC symmetric key | WebAuthn asymmetric (ECDSA) |

## License

MIT
