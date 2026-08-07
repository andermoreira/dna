# Step 3: Browser fingerprinting engine

## Goal

Client-side JavaScript module that collects 10 fingerprinting signals from the browser (Canvas, WebGL, Audio, fonts, screen, timezone, plugins, platform, hardware concurrency, touch support), normalizes them, and produces a deterministic `visitorId` (SHA-256 hash) + structured `components` object.

## Tasks

1. **Create `public/js/fingerprint.js`** — self-contained module (IIFE or global `Fingerprint` object) with:

   Functions:
   - `collectCanvas()` — renders text + emoji in offscreen canvas, returns `toDataURL()` SHA-256 hash
   - `collectWebGL()` — creates WebGL context, reads `RENDERER` + `VENDOR` via `getParameter` + `getExtension('WEBGL_debug_renderer_info')`, returns hash
   - `collectAudio()` — uses `OfflineAudioContext` + `OscillatorNode` + `DynamicsCompressorNode`, renders audio buffer, returns hash of samples
   - `collectFonts()` — measures bounding boxes for known font list (monospace, sans-serif, serif, standard fonts), returns sorted array of detected fonts
   - `collectScreen()` — returns `screen.width`, `screen.height`, `screen.colorDepth`, `screen.pixelDepth`, `devicePixelRatio` as a stable string
   - `collectTimezone()` — returns `Intl.DateTimeFormat().resolvedOptions().timeZone`
   - `collectPlugins()` — iterates `navigator.plugins`, returns sorted array of plugin names
   - `collectPlatform()` — returns `navigator.platform`, `navigator.userAgentData?.platform` (if available)
   - `collectHardware()` — returns `navigator.hardwareConcurrency`
   - `collectTouch()` — returns boolean: `'ontouchstart' in window || navigator.maxTouchPoints > 0`
   - `generateVisitorId(components)` — takes the components object, JSON-stringifies it, returns SHA-256 hex digest (use `crypto.subtle.digest` via async wrapper)
   - `async collectAll()` — runs all collectors in parallel, builds components object, generates visitorId, returns `{ visitorId, components }`

   Fallback handling: each collector wrapped in try/catch. Failed signals return `null` instead of throwing. Document which signals failed in `components._errors`.

   SHA-256 via Web Crypto API (`crypto.subtle.digest('SHA-256', encoder.encode(data))`). Hex encode the result.

2. **Create `public/index.html`** — basic dashboard placeholder:
   - Loads `js/fingerprint.js`
   - On page load, calls `Fingerprint.collectAll()` and displays the `visitorId` and a table of collected components
   - Shows "Loading fingerprint..." spinner during collection
   - Shows red markers for any failed signals
   - Redirects to `/login.html` if not authenticated (check via `GET /api/auth/me`)

## Out of scope

- Sending fingerprint to server (step 6)
- Displaying terminal registration UI (step 7)
- Daemon query integration (step 7)
- Persistent storage of fingerprint client-side

## Done criteria

- `Fingerprint.collectAll()` resolves with `{ visitorId: string, components: object }`
- Same browser + same page load → same visitorId (deterministic)
- Different browser → different visitorId
- Any individual signal failure does not crash `collectAll()`
- `public/index.html` displays collected fingerprint data
- Canvas, WebGL, and Audio collectors produce non-null values in standard Chrome/Firefox

## Dependencies

- Step 2 (auth available, `/api/auth/me` endpoint for page guard)

## Checklist pré-handoff

- [ ] `Fingerprint.collectAll()` works in Chrome
- [ ] `Fingerprint.collectAll()` works in Firefox
- [ ] VisitorId is stable across page reloads
- [ ] `index.html` renders fingerprint data
- [ ] Failed signals don't break collection
- [ ] No lint errors

---

Implemente APENAS o step abaixo — não expanda o escopo.

**Files:**
- `public/js/fingerprint.js`
- `public/index.html`

**Out of scope:** daemon, JA4, terminal APIs, registration UI, guard, admin.

**Done criteria:** `Fingerprint.collectAll()` produces stable visitorId. `index.html` shows fingerprint data. Unauthenticated users redirected to login.

Siga as convenções do repositório.

---

@specs/steps/terminal-auth-poc-step-3.md
@specs/terminal-auth-poc.md
