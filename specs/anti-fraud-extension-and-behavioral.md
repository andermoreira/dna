# Anti-Fraud: Browser Extension + Behavioral Biometrics

## Goal

O navegador prova sua integridade ao servidor de forma contínua, detectando spoofing de fingerprint, automação, VPN/proxy e hijacking de sessão — sem depender exclusivamente do daemon externo (Layer 2).

> **Formato:** spec completa (API nova, schema novo, superfície de segurança).

## Non-goals

- Publicação na Chrome Web Store — a extensão é side-loaded (developer mode), escopo de POC.
- Substituição do daemon (Layer 2) — a extensão é uma camada complementar, não alternativa.
- Machine learning para behavioral biometrics — usamos thresholds e heurísticas, sem treinamento de modelo.
- Identificação biométrica individual (quem é a pessoa) — detectamos anomalias de sessão e padrões de bot, não identidade pessoal.
- Mobile browsers — desktop Chrome/Edge/Firefox apenas.
- Coleta de behavioral fora da sessão ativa — apenas enquanto o usuário está na página da aplicação.

## Architecture overview

```
                          ANTES (pocdna atual)
                          ═══════════════════
Layer 1: Browser JS fingerprint (spoofable)
Layer 2: Daemon HMAC (trusted, external)
Layer 3: TLS JA4 (server-observed)
→ Quórum: 2/3 para reconhecer; daemon obrigatório para ação sensível


                          DEPOIS
                          ═══════════════════
Layer 1:   Browser JS fingerprint (coleta como antes)
Layer 1.5: Browser Extension (oráculo de integridade — cross-valida Layer 1)
Layer 2:   Daemon HMAC (trusted, external — sem alteração)
Layer 3:   TLS JA4 (server-observed — sem alteração)
Layer 4:   Behavioral Biometrics (identidade contínua — alimentada por eventos validados pela extensão)
→ Quórum: 2/4 para reconhecer (anti-downgrade: se registrou com extensão, extensão conta como disponível)
→ Ações sensíveis exigem daemon OU (extensão + behavioral) na sessão atual
```

**Por que extensão + behavioral juntas:**
- Extensão sem behavioral: detecta spoofing no momento da verificação, mas não sabe se a sessão foi hijackada depois.
- Behavioral sem extensão: coleta padrões de input, mas não confia na origem dos eventos (headless browser injeta eventos sintéticos perfeitos).
- Juntas: a extensão valida que os eventos são reais (`isTrusted`, sem WebDriver), e a behavioral monitora se quem está operando é consistente ao longo da sessão.

## User stories

### US-01 — Extensão detecta headless browser

**Given** um usuário acessando a aplicação com a extensão instalada,
**When** a página coleta os sinais da extensão,
**Then** a extensão reporta `automation: { webdriver: false, selenium: false, puppeteer: false }` e a página segue normalmente. Se qualquer flag for `true`, o terminal é marcado como suspeito e a confidence é zerada independentemente das outras camadas.

### US-02 — Extensão cross-valida fingerprint do browser

**Given** um terminal com extensão instalada e registrada,
**When** a verificação de terminal ocorre,
**Then** a extensão coleta Canvas/WebGL/Audio usando suas próprias APIs privilegiadas e compara com os valores coletados pelo JS da página. Divergência → Layer 1 marcada como spoofed (score = 0), independentemente do fuzzy match.

### US-03 — Extensão detecta VPN/proxy via WebRTC leak

**Given** um terminal com extensão instalada,
**When** a verificação ocorre,
**Then** a extensão coleta os IPs locais via WebRTC (`RTCPeerConnection`) e os envia ao servidor. O servidor compara com o IP da requisição HTTP. Se o IP real (WebRTC) não corresponde ao IP da conexão, o terminal é marcado com flag `vpn_detected`.

### US-04 — Behavioral detecta automação (bot)

**Given** um terminal com extensão instalada e behavioral ativo,
**When** o usuário interage com a página (mouse, teclado, scroll),
**Then** o behavioral coleta métricas de entropia dos movimentos. Se os padrões forem robóticos (linhas retas, timing uniforme, ausência de jitter), o servidor emite `behavioral.anomaly: automation_suspected` e reduz a confidence contínua.

### US-05 — Behavioral detecta possível hijacking de sessão

**Given** um usuário com sessão verificada e behavioral ativo com baseline estabelecida,
**When** os padrões de input mudam bruscamente (ex: ritmo de digitação triplica, padrão de mouse muda de curva para reta),
**Then** o servidor emite `behavioral.anomaly: profile_diverged` e a sessão perde o status de verificada (`terminalVerifiedAt` invalidado), forçando re-verificação completa.

### US-06 — Terminal sem extensão opera em modo degradado

**Given** um terminal sem extensão instalada,
**When** a verificação ocorre,
**Then** o sistema opera como antes (Layers 1+2+3, quórum 2/3). A extensão é opcional — sua ausência não bloqueia o fluxo, apenas reduz a confidence máxima e desabilita o behavioral (sem extensão, eventos não são confiáveis).

### US-07 — Extensão detecta eventos sintéticos (não-humanos)

**Given** um terminal com extensão instalada,
**When** eventos de mouse/teclado são disparados na página,
**Then** a extensão verifica `event.isTrusted` no contexto privilegiado. Se eventos sintéticos (`isTrusted === false` ou dispatcher é script de automação) forem detectados, o behavioral é desligado para a sessão e um alerta é emitido.

### US-08 — Registro de terminal com extensão

**Given** um usuário registrando um terminal com a extensão instalada,
**When** o fluxo de registro ocorre,
**Then** o servidor armazena os sinais da extensão (`extensionInstalled`, `extensionSignals`) junto com o fingerprint. A extensão não requer segredo — sua presença é auto-verificável porque o content script só é injetado se a extensão estiver instalada.

## Assumptions

- Extensão é side-loaded em modo desenvolvedor no Chrome/Edge (chrome://extensions) ou Firefox (about:debugging). O README documenta o processo de instalação.
- A extensão usa Manifest V3 (MV3) com service worker, content script e host_permissions para o domínio da aplicação.
- A comunicação extensão↔página é via `window.postMessage` no content script — a página JS expõe `window.pocdna.extension` como API de conveniência.
- O behavioral coleta dados apenas enquanto o usuário está na página da aplicação (`focus`/`blur` pausam a coleta).
- Os dados de behavioral são enviados via beacon batch a cada 30 segundos (POST) ou WebSocket, dependendo da disponibilidade. Beacon é o fallback universal.
- A baseline comportamental é construída com dados das últimas N sessões do mesmo terminal (mínimo 3 sessões para baseline confiável).
- O servidor já tem TLS terminado (necessário para JA4) — sem mudança nessa camada.
- A extensão não armazena dados localmente — apenas coleta e transmite.

## Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Extensão pode ser desabilitada pelo usuário ou por política de TI | Perda das Layers 1.5 e 4 | Degradação graciosa: sistema opera com Layers 1+2+3 como antes. Sinalizar `extension_missing` no dashboard. |
| Behavioral gera falsos positivos (mudança legítima de comportamento) | Usuário legítimo bloqueado | Threshold conservador inicial; ajustar com dados. Hijacking suspicion invalida a sessão mas não bloqueia o usuário — força re-verify, não lockout. |
| Extensão é reverse-engineered | Atacante sabe quais sinais são coletados | A segurança não depende de ofuscação — a extensão cross-valida sinais que exigem acesso privilegiado (chrome.* APIs) que a página JS não tem. |
| Coleta contínua de behavioral é percebida como invasiva | Rejeição do usuário | Transparência: indicador visual no dashboard explicando o que é coletado. Dados brutos nunca saem do navegador — apenas métricas agregadas são enviadas. |
| WebSocket cai durante a sessão | Perda de monitoramento contínuo | Fallback para beacon POST a cada 30s. Se ambos falham, behavioral é desligado para a sessão corrente — sem bloqueio. |
| Extensão não disponível no Firefox (APIs diferentes) | Suporte parcial | Foco inicial Chrome/Edge (Chromium). Firefox como consideração futura. |

## API contract

### Extensão → Página (window.postMessage)

A extensão injeta um content script que expõe uma API via `window.postMessage`. A página JS consulta via `window.pocdna.extension.*`.

**Mensagens request (page → extension):**

```json
{
  "type": "POCDNA_EXT_REQ",
  "id": "uuid-v4",
  "method": "getSignals" | "getCrossValidation" | "getNetworkInfo" | "checkAutomation" | "checkEvents"
}
```

**Mensagens response (extension → page):**

```json
{
  "type": "POCDNA_EXT_RES",
  "id": "uuid-v4",
  "method": "getSignals",
  "result": {
    "extensionInstalled": true,
    "extensionId": "abcdef...",
    "installedExtensions": ["Extension A", "Extension B"],
    "browserInfo": { "name": "Chrome", "version": "126.0" }
  }
}
```

```json
{
  "type": "POCDNA_EXT_RES",
  "id": "uuid-v4",
  "method": "getCrossValidation",
  "result": {
    "canvas": "sha256...",
    "webgl": "sha256...",
    "audio": "sha256..."
  }
}
```

```json
{
  "type": "POCDNA_EXT_RES",
  "id": "uuid-v4",
  "method": "getNetworkInfo",
  "result": {
    "localIPs": ["192.168.1.10", "10.0.0.5"],
    "publicIP": "203.0.113.1"
  }
}
```

### Server endpoint: POST /api/auth/verify-terminal (modificado)

Adiciona campos opcionais `extensionSignals` e `behavioralToken` ao request body existente.

- **Request (campos novos)**:
```json
{
  "...campos existentes...": "...",
  "extensionSignals": {
    "installed": true,
    "crossValidation": {
      "canvas": "sha256...",
      "webgl": "sha256...",
      "audio": "sha256..."
    },
    "network": {
      "localIPs": ["192.168.1.10"],
      "publicIP": "203.0.113.1"
    },
    "automation": {
      "webdriver": false,
      "selenium": false,
      "puppeteer": false,
      "playwright": false
    },
    "browserInfo": {
      "name": "Chrome",
      "version": "126.0",
      "extensionsCount": 5,
      "cdpDetected": false
    }
  }
}
```

- **Response 200 (campos novos)**:
```json
{
  "...campos existentes...": "...",
  "layers": {
    "browser": 0.82,
    "extension": true,
    "daemon": true,
    "tls": true,
    "behavioral": 0.75
  },
  "alerts": []
}
```

### Server endpoint: POST /api/auth/behavioral/beacon

Endpoint para envio periódico de métricas comportamentais agregadas.

- **Auth**: Session cookie
- **Rate limit**: 1 request a cada 15 segundos
- **Request**:
```json
{
  "sessionNonce": "nonce-da-sessao-atual",
  "interval": { "start": 1712345678000, "end": 1712345708000 },
  "mouse": {
    "events": 142,
    "avgVelocity": 345.2,
    "avgCurvature": 0.73,
    "clickCount": 3,
    "clickPositions": [[320, 450], [680, 120], [200, 800]],
    "jitter": 0.12
  },
  "keyboard": {
    "events": 89,
    "avgTypingSpeed": 42.5,
    "avgInterKeyMs": 234,
    "backspaceCount": 3,
    "pasteCount": 1
  },
  "scroll": {
    "events": 25,
    "totalDistance": 3400,
    "avgDeceleration": 0.87,
    "smoothness": 0.91
  },
  "focus": {
    "blurCount": 0,
    "visibilityChanges": 0
  }
}
```

- **Response 200**:
```json
{
  "behavioralScore": 0.85,
  "alerts": [],
  "reverifyRequired": false
}
```

- **Response 401**: Session expired (redirect to login)
- **Response 400**: Missing sessionNonce or invalid interval

### Server endpoint: GET /api/auth/behavioral/token

Emite um token de sessão para o behavioral. Usado para vincular beacons à sessão corrente.

- **Auth**: Session cookie
- **Response 200**: `{ "token": "hex-nonce", "beaconIntervalMs": 30000 }`

## Data model

### Tabela: terminals (colunas novas)

| Column | Type | Constraints |
|---|---|---|
| extension_signals | TEXT | NULLABLE (JSON: sinais coletados pela extensão no registro) |
| extension_public_key | TEXT | NULLABLE (chave pública da extensão para verificação de origem, se implementado futuramente) |
| behavioral_baseline | TEXT | NULLABLE (JSON: baseline agregada de behavioral — médias e desvios) |
| behavioral_session_count | INTEGER | DEFAULT 0 (número de sessões usadas para construir a baseline) |

### Tabela: behavioral_events (nova)

Registro individual de beacon comportamental para auditoria e construção de baseline.

| Column | Type | Constraints |
|---|---|---|
| id | TEXT | PK, UUID |
| terminal_id | TEXT | FK → terminals.id, NOT NULL |
| user_id | TEXT | FK → users.id, NOT NULL |
| session_id | TEXT | NOT NULL (referência à sessão express-session) |
| interval_start | TEXT | NOT NULL (ISO 8601, início da janela do beacon) |
| interval_end | TEXT | NOT NULL (ISO 8601, fim da janela do beacon) |
| mouse_metrics | TEXT | NOT NULL (JSON: aggregated mouse metrics) |
| keyboard_metrics | TEXT | NOT NULL (JSON: aggregated keyboard metrics) |
| scroll_metrics | TEXT | NOT NULL (JSON: aggregated scroll metrics) |
| focus_metrics | TEXT | NOT NULL (JSON: focus/blur/visibility metrics) |
| score | REAL | NULLABLE (score calculado para este beacon, 0.0–1.0) |
| alerts | TEXT | NULLABLE (JSON array of alert codes) |
| created_at | TEXT | NOT NULL (ISO 8601) |

### Tabela: auth_events (colunas novas)

| Column | Type | Constraints |
|---|---|---|
| extension_installed | INTEGER | DEFAULT 0 (0 ou 1) |
| vpn_detected | INTEGER | DEFAULT 0 (0 ou 1) |
| automation_detected | INTEGER | DEFAULT 0 (0 ou 1) |

## Error handling

| Scenario | HTTP Status | User-facing message | Internal behavior |
|---|---|---|---|
| Extensão não instalada | 200 (verify) | Sem mensagem — fluxo normal degradado | `extension.installed: false`; behavioral desabilitado |
| Extensão detecta WebDriver | 200 (verify) | "Automation detected" no dashboard | `extension.automation.webdriver: true`; confidence zerada; log VERIFY_FAIL |
| Cross-validation diverge (spoofing) | 200 (verify) | "Terminal fingerprint mismatch" no dashboard | Layer 1 score = 0; log mismatch com detalhes da divergência |
| VPN/proxy detectado | 200 (verify) | "Network anomaly detected" no dashboard | Flag `vpn_detected`; confidence reduzida em 0.2; não bloqueia sozinho |
| Behavioral beacon falha (rede) | N/A (cliente) | Sem mensagem — silencioso | Cliente acumula métricas e reenvia no próximo beacon |
| Behavioral baseline insuficiente (<3 sessões) | 200 (beacon) | Sem mensagem | `behavioralScore` = null; baseline em construção |
| Behavioral diverge da baseline (>2σ) | 200 (beacon) | Sem mensagem imediata | `reverifyRequired: true`; sessão perde terminalVerifiedAt |
| Extensão detecta eventos sintéticos | 200 (verify) | "Input integrity check failed" no dashboard | Behavioral desabilitado para a sessão; alerta persistido |
| Session expirada durante beacon | 401 | Redirect ao login (tratado pelo frontend) | Beacon descartado |

## Observability

**Novos log events:**
- `extension.detected` — user_id, terminal_id, extension_signals hash
- `extension.missing` — user_id (terminal registrado com extensão mas extensão ausente na verificação)
- `extension.spoof_detected` — user_id, terminal_id, divergent_signal (canvas|webgl|audio), page_hash, extension_hash
- `extension.automation_detected` — user_id, terminal_id, flags (webdriver|selenium|puppeteer|playwright|cdp)
- `extension.vpn_detected` — user_id, terminal_id, http_ip, webrtc_ips
- `behavioral.beacon_received` — user_id, terminal_id, session_id, mouse_events, keyboard_events
- `behavioral.anomaly` — user_id, terminal_id, session_id, anomaly_type (automation_suspected|profile_diverged), score
- `behavioral.baseline_updated` — user_id, terminal_id, session_count

**Novas métricas (via log aggregation):**
- Taxa de terminais com extensão instalada
- Taxa de spoofing detectado (cross-validation divergente)
- Taxa de anomalias comportamentais por sessão
- Latência do beacon behavioral (cliente → servidor)

## Quality attributes

- Coleta de behavioral não deve causar jank perceptível na UI (<5ms por evento de input capturado).
- Beacon POST deve ser enviado em background (navigator.sendBeacon ou fetch com keepalive) — não bloqueia a thread principal.
- Armazenamento de behavioral_events: retenção de 90 dias, depois agregado em baseline e descartado (POC: sem TTL automático, mas documentado).

## Threat model

| Vector | Risk | Mitigation |
|---|---|---|
| Atacante desabilita a extensão | Perda de Layer 1.5 + 4 | Sistema degrada para Layers 1+2+3. Se terminal foi registrado COM extensão, sua ausência é detectada e reportada. Não bloqueia — apenas reduz confidence. |
| Atacante forja respostas da extensão (spoofing de postMessage) | Sinais falsos | O content script da extensão executa em contexto isolado (MV3 content script world: MAIN vs ISOLATED). A página JS NÃO pode injetar listeners no mundo ISOLATED onde a extensão opera. A presença do content script é prova de instalação. |
| Atacante injeta behavioral sintético (eventos perfeitamente humanos) | Behavioral não detecta bot sofisticado | É um problema real, mas requer atacante com recursos avançados (ML para gerar movimentos humanos). A extensão mitiga parcialmente: verifica `isTrusted` e WebDriver. Para POC, é risco aceitável. |
| Atacante faz replay de beacon behavioral | Dados de behavioral falsos | Cada beacon inclui `sessionNonce` único por sessão + `interval` com timestamps. Timestamps fora de ordem ou duplicados são rejeitados. |
| Beacon behavioral expõe padrões de digitação (PII indireto) | Vazamento de behavioral | Métricas são agregadas no cliente (médias, contagens, distribuições) — eventos individuais de tecla NUNCA saem do navegador. O servidor nunca vê quais teclas foram pressionadas. |
| Extensão coleta lista de extensões do usuário (privacidade) | Exposição de outras extensões | A lista de extensões instaladas NÃO é enviada ao servidor como array — apenas a contagem (`extensionsCount`). A lista é usada apenas localmente para detectar ferramentas de automação conhecidas. |
| Content script pode ser desativado por outra extensão | Perda de Layer 1.5 | MV3 content scripts rodam em sandbox por extensão. Outra extensão não consegue remover o content script desta. Se a execução falhar (ex: CSP bloqueia), a página detecta timeout na resposta e reporta `extension.timeout`. |

## Acceptance criteria

1. **AC-01**: Extensão instalada → página detecta `window.pocdna.extension` disponível → sinais `getSignals`, `getCrossValidation`, `getNetworkInfo`, `checkAutomation` retornam dados reais.
2. **AC-02**: Extensão NÃO instalada → `window.pocdna.extension` é `undefined` → sistema opera em modo degradado (Layers 1+2+3, sem behavioral).
3. **AC-03**: Terminal registrado COM extensão → verificação futura COM extensão → cross-validation de Canvas/WebGL/Audio bate → extension layer = true.
4. **AC-04**: Terminal registrado COM extensão → verificação futura COM extensão mas Canvas diverge entre página e extensão → Layer 1 score = 0 → event `extension.spoof_detected` logado.
5. **AC-05**: Extensão detecta `navigator.webdriver === true` → automation flag = true → confidence zerada → ação sensível bloqueada (403).
6. **AC-06**: Extensão coleta IPs via WebRTC → um dos IPs difere do IP da requisição HTTP → flag `vpn_detected` no auth_event.
7. **AC-07**: Behavioral coleta 3+ sessões para um terminal → baseline construída → beacon de uma sessão normal retorna `behavioralScore ≥ 0.7` e `reverifyRequired: false`.
8. **AC-08**: Sessão ativa com behavioral → padrão de mouse muda para linhas retas e velocidade constante (simulação de bot) → próximo beacon retorna `behavioral.anomaly: automation_suspected` e `score < 0.3`.
9. **AC-09**: Sessão com behavioral verificada → ritmo de digitação triplica repentinamente → beacon retorna `reverifyRequired: true` → ação sensível seguinte exige re-verify completo.
10. **AC-10**: Behavioral beacon enviado sem sessionNonce ou com nonce inválido → 400.
11. **AC-11**: Extensão detecta eventos `isTrusted === false` → behavioral desabilitado para a sessão → `extension.events_synthetic` logado.
12. **AC-12**: `scripts/verify-manual.mjs` atualizado para cobrir os novos fluxos com extensão (simulando extensão via header custom nos testes).

## Open questions

| # | Question | Owner | Status |
|---|---|---|---|
| Q1 | WebSocket ou apenas beacon POST para behavioral? WebSocket reduz latência mas adiciona complexidade de reconexão. | @andersonalves | Pendente — beacon POST a cada 30s parece suficiente para POC |
| Q2 | Extensão deve ter um mecanismo de desafio-resposta (nonce) para provar que está viva e não é um mock de postMessage? | @andersonalves | Pendente |
| Q3 | Firefox support? MV3 é suportado no Firefox mas APIs específicas (webRequest, declarativeNetRequest) diferem. | @andersonalves | Pendente — começar apenas Chrome/Edge |
| Q4 | Baseline comportamental: global por terminal ou por sessão? Se for global, usuários diferentes no mesmo terminal contaminam a baseline. | @andersonalves | Pendente |
| Q5 | Armazenamento dos beacons: SQLite mesmo ou arquivo rotativo? 30s de beacon por sessão ativa pode gerar volume. | @andersonalves | Pendente — SQLite com retenção de 90 dias declarada |

## Implementation plan

> Será preenchido após aprovação da spec.
