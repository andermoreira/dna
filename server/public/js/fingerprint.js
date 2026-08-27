/**
 * POCDNA Browser Fingerprinting Engine — Layer 1
 *
 * Collects 11 signals from the browser environment to generate a unique
 * terminal fingerprint. The result is a deterministic visitorId (SHA-256)
 * and a structured components object sent to the server for fuzzy matching.
 *
 * Signals collected:
 *   Canvas          — GPU/driver fingerprint via rendered image hash
 *   WebGL           — GPU vendor, renderer string, supported extensions
 *   Audio           — Audio processing fingerprint (oscillator + compressor)
 *   Fonts           — Detected fonts via bounding box measurement
 *   Screen          — Resolution, color depth, pixel ratio
 *   Timezone        — IANA timezone string from Intl API
 *   Plugins         — Browser plugin list
 *   Platform        — OS platform string
 *   Hardware Cores  — CPU core count
 *   Touch Support   — Touchscreen detection
 *   Languages       — Preferred languages
 *
 * Hardware-dependent signals (Canvas, WebGL, Audio) contribute the most
 * entropy and are the hardest to spoof because they depend on GPU drivers,
 * DSP chips, and rendering pipelines.
 *
 * Spoofing resistance:
 *   - Browser-only: LOW (headless browsers can fake all signals)
 *   - Combined with Layer 2 (daemon): HIGH (HMAC proves real OS)
 *
 * Usage:
 *   const { visitorId, components } = await Fingerprint.collectAll();
 *
 * Exposed as window.Fingerprint (IIFE).
 */

window.Fingerprint = (() => {

  /**
   * SHA-256 hashing via Web Crypto API.
   *
   * The Web Crypto API (crypto.subtle.digest) is available in all modern
   * browsers and runs asynchronously. This is the same crypto primitive
   * used by the server for fingerprint hashing.
   *
   * @param {string} text — input to hash
   * @returns {Promise<string>} 64-character hex digest
   */
  async function sha256(text) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Canvas Fingerprinting (~5.7 bits entropy)
   *
   * Renders text with slight variations in an offscreen <canvas> element.
   * The rendered image varies by:
   *   - GPU model and driver version
   *   - OS font rendering engine (ClearType, CoreText, FreeType)
   *   - Anti-aliasing and subpixel rendering settings
   *
   * Different GPUs produce slightly different pixel values, making this
   * one of the most stable and unique fingerprinting signals.
   *
   * @returns {Promise<string|null>} SHA-256 of the canvas data URL, or null on error
   */
  async function collectCanvas() {
    try {
      const canvas = document.createElement('canvas');
      canvas.width = 280;
      canvas.height = 60;
      const ctx = canvas.getContext('2d');

      // Render text with deliberate rendering complexity
      ctx.textBaseline = 'top';
      ctx.font = '14px Arial';
      ctx.fillStyle = '#f60';
      ctx.fillRect(125, 1, 62, 20);
      ctx.fillStyle = '#069';
      ctx.fillText('POCDNA Terminal Auth \u30C4', 2, 15);  // Unicode to increase entropy
      ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
      ctx.fillText('POCDNA Terminal Auth \u30C4', 4, 17);

      // toDataURL() produces different output per GPU/driver
      const dataUrl = canvas.toDataURL();
      return await sha256(dataUrl);
    } catch {
      return null;  // Canvas blocked (privacy browser, extension)
    }
  }

  /**
   * WebGL Fingerprinting (~8-10 bits entropy)
   *
   * WebGL exposes the GPU vendor and renderer string through the
   * WEBGL_debug_renderer_info extension. Combined with the list of
   * supported WebGL extensions, this provides high entropy.
   *
   * Falls back to 'experimental-webgl' for older browsers.
   *
   * @returns {Promise<string|null>} SHA-256 of vendor|renderer|extensions
   */
  async function collectWebGL() {
    try {
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (!gl) return null;  // WebGL not supported

      // WEBGL_debug_renderer_info exposes GPU details
      const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
      const vendor = debugInfo ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : '';
      const renderer = debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : '';

      // Supported extensions vary by GPU/driver
      const extensions = gl.getSupportedExtensions()?.sort().join(',') || '';

      return await sha256(`${vendor}|${renderer}|${extensions}`);
    } catch {
      return null;
    }
  }

  /**
   * Audio Fingerprinting (~5-7 bits entropy)
   *
   * Uses the Web Audio API to generate a waveform and measure its
   * characteristics after processing through DynamicsCompressorNode.
   *
   * The output varies by:
   *   - CPU audio processing implementation
   *   - Browser audio stack (differs between Chrome, Firefox, Safari)
   *   - Sample rate conversion artifacts
   *
   * Uses a high-frequency triangle wave (10kHz) to maximize entropy
   * from the compressor's non-linear processing.
   *
   * @returns {Promise<string|null>} SHA-256 of the last 500 audio samples
   */
  async function collectAudio() {
    try {
      const context = new OfflineAudioContext(1, 5000, 44100);
      const oscillator = context.createOscillator();
      const compressor = context.createDynamicsCompressor();

      // Triangle wave at 10kHz — high frequency maximizes compressor artifacts
      oscillator.type = 'triangle';
      oscillator.frequency.value = 10000;

      // Aggressive compression settings to increase uniqueness
      compressor.threshold.value = -50;
      compressor.knee.value = 40;
      compressor.ratio.value = 12;
      compressor.attack.value = 0;
      compressor.release.value = 0.25;

      oscillator.connect(compressor);
      compressor.connect(context.destination);
      oscillator.start(0);

      // Render 5000 samples and extract the last 500
      const buffer = await context.startRendering();
      const samples = buffer.getChannelData(0).slice(4500);
      return await sha256(String(samples));
    } catch {
      return null;  // Audio API blocked (Safari, privacy extensions)
    }
  }

  /**
   * Font Detection via Bounding Box Measurement
   *
   * Renders a test string in known fonts and measures the width to
   * determine which fonts are installed. Different OSes and user
   * configurations have different font sets.
   *
   * Technique: render text in a base font (monospace, sans-serif, serif),
   * then try each test font as a fallback. If the measured width differs
   * from the base, the test font is installed.
   *
   * About 34% of users are uniquely identifiable by fonts alone.
   *
   * @returns {Promise<string[]|null>} sorted array of detected font names
   */
  async function collectFonts() {
    try {
      const baseFonts = ['monospace', 'sans-serif', 'serif'];
      const testFonts = [
        'Arial', 'Verdana', 'Times New Roman', 'Courier New',
        'Georgia', 'Palatino', 'Garamond', 'Bookman', 'Comic Sans MS',
        'Trebuchet MS', 'Arial Black', 'Impact', 'Lucida Console'
      ];

      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d');
      canvas.width = 300;
      canvas.height = 30;

      // Measure baseline widths for each base font family (rounded to 0.1px for zoom resilience)
      ctx.font = '16px monospace';
      ctx.fillText('mmmmmmmmmmlllllllllliiiiiiiiii', 0, 15);
      const baseMeasures = {};
      for (const font of baseFonts) {
        ctx.font = `16px ${font}`;
        baseMeasures[font] = Math.round(ctx.measureText('mmmmmmmmmmlllllllllliiiiiiiiii').width * 10) / 10;
      }

      // Test each font — if width differs from all base fonts, it's installed
      const detected = [];
      for (const font of testFonts) {
        for (const base of baseFonts) {
          ctx.font = `16px '${font}', ${base}`;
          const width = Math.round(ctx.measureText('mmmmmmmmmmlllllllllliiiiiiiiii').width * 10) / 10;
          if (width !== baseMeasures[base]) {
            detected.push(font);
            break;  // Font detected — move to next test font
          }
        }
      }

      return detected.sort();
    } catch {
      return null;
    }
  }

  /**
   * Screen properties — resolution, color depth, pixel ratio.
   *
   * @returns {string|null} formatted as "WxHxColorDepthxPixelDepth@DPR"
   */
  function collectScreen() {
    try {
      return `${screen.width}x${screen.height}x${screen.colorDepth}x${screen.pixelDepth}@${devicePixelRatio}`;
    } catch {
      return null;
    }
  }

  /**
   * Timezone — IANA timezone string from Intl.DateTimeFormat.
   *
   * More reliable than Date.getTimezoneOffset() because it includes
   * the named timezone (e.g. "America/Sao_Paulo"), not just the offset.
   *
   * @returns {string|null}
   */
  function collectTimezone() {
    try {
      return Intl.DateTimeFormat().resolvedOptions().timeZone;
    } catch {
      return null;
    }
  }

  /**
   * Browser plugins — navigator.plugins list.
   *
   * The set of installed plugins is unique per browser installation.
   * Note: many modern browsers limit this to a fixed set for privacy.
   *
   * @returns {string[]|null} sorted plugin names
   */
  function collectPlugins() {
    try {
      const plugins = [];
      for (let i = 0; i < navigator.plugins.length; i++) {
        plugins.push(navigator.plugins[i].name);
      }
      return plugins.sort();
    } catch {
      return null;
    }
  }

  /**
   * OS Platform — from navigator.userAgentData (modern) or navigator.platform (legacy).
   *
   * @returns {string|null}
   */
  function collectPlatform() {
    try {
      return navigator.userAgentData?.platform || navigator.platform || '';
    } catch {
      return null;
    }
  }

  /**
   * CPU core count — navigator.hardwareConcurrency.
   *
   * Returns the number of logical CPU cores available. This is a hardware
   * characteristic that's difficult to fake without browser-level patching.
   *
   * @returns {number|null}
   */
  function collectHardware() {
    try {
      return navigator.hardwareConcurrency || 0;
    } catch {
      return null;
    }
  }

  /**
   * Touchscreen detection — ontouchstart event or maxTouchPoints API.
   *
   * @returns {boolean|null}
   */
  function collectTouch() {
    try {
      return 'ontouchstart' in window || navigator.maxTouchPoints > 0;
    } catch {
      return null;
    }
  }

  /**
   * Preferred languages — navigator.languages (array) or navigator.language (single).
   *
   * @returns {string[]|null}
   */
  function collectLanguages() {
    try {
      return [...(navigator.languages || [navigator.language])];
    } catch {
      return null;
    }
  }

  /**
   * Collects all fingerprinting signals in parallel and assembles the result.
   *
   * Each collector is wrapped in a try/catch — if one fails (blocked by
   * browser privacy settings, extension, or browser limitation), the
   * remaining signals are still collected.
   *
   * Failed signals are logged in components._errors for debugging.
   *
   * The visitorId is a SHA-256 hash of the sorted components object,
   * producing a stable 64-character hex identifier.
   *
   * @returns {Promise<{ visitorId: string, components: object }>}
   */
  async function collectAll() {
    const errors = [];

    // Wrapper: catches errors per signal without crashing the entire collection
    const wrap = async (name, fn) => {
      try {
        return await fn();
      } catch (e) {
        errors.push({ signal: name, error: e.message });
        return null;
      }
    };

    // Collect hardware-dependent signals in parallel (all async)
    const [canvas, webgl, audio, fonts] = await Promise.all([
      wrap('canvas', collectCanvas),
      wrap('webgl', collectWebGL),
      wrap('audio', collectAudio),
      wrap('fonts', collectFonts),
    ]);

    // Assemble all components
    const components = {
      canvas,
      webgl,
      audio,
      fonts: fonts || [],
      screen: collectScreen(),
      timezone: collectTimezone(),
      plugins: collectPlugins(),
      platform: collectPlatform(),
      hardwareConcurrency: collectHardware(),
      touchSupport: collectTouch(),
      languages: collectLanguages(),
      userAgent: navigator.userAgent,
    };

    // Log any failed collectors for diagnostics
    if (errors.length > 0) {
      components._errors = errors;
    }

    // Sort keys for deterministic hashing (must match server hashComponents)
    const ordered = {};
    Object.keys(components).sort().forEach(k => {
      ordered[k] = components[k];
    });

    // Generate stable visitor ID
    const visitorId = await sha256(JSON.stringify(ordered));

    return { visitorId, components };
  }

  // Public API
  return { collectAll, sha256 };
})();
