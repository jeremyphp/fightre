/*!
 * FightRE client v0.1.0 — environment attestation + proof of work.
 *
 * What it does: collects a fingerprint of the runtime that is executing it,
 * solves the server's proof-of-work challenge, and posts a signed attestation.
 * The attestation proves "a browser-like runtime ran this file just now" — it is
 * a cost, not an identity.  Never treat it as authentication.
 *
 * Embed:  <script src="/fightre.js"></script>
 * API:    FightRE.bootstrap()            -> Promise<{ok, trust}>
 *         FightRE.collect()               -> environment object
 *         FightRE.solve(jti, difficulty)  -> nonce
 */
(function (global) {
  "use strict";

  var VERSION = "0.1.0";
  var CHALLENGE_URL = "/_fightre/challenge";
  var ATTEST_URL = "/_fightre/attest";

  /* ------------------------------------------------------------------ *
   * SHA-256 (synchronous, needed for the tight PoW loop)
   * ------------------------------------------------------------------ */
  var K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];

  function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }

  function sha256Bytes(bytes) {
    var H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
             0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    var l = bytes.length;
    var withPad = ((l + 9 + 63) >> 6) << 6;
    var m = new Uint8Array(withPad);
    m.set(bytes);
    m[l] = 0x80;
    var bitLenHi = Math.floor(l * 8 / 0x100000000);
    var bitLenLo = (l * 8) >>> 0;
    m[withPad - 8] = (bitLenHi >>> 24) & 0xff;
    m[withPad - 7] = (bitLenHi >>> 16) & 0xff;
    m[withPad - 6] = (bitLenHi >>> 8) & 0xff;
    m[withPad - 5] = bitLenHi & 0xff;
    m[withPad - 4] = (bitLenLo >>> 24) & 0xff;
    m[withPad - 3] = (bitLenLo >>> 16) & 0xff;
    m[withPad - 2] = (bitLenLo >>> 8) & 0xff;
    m[withPad - 1] = bitLenLo & 0xff;

    var w = new Uint32Array(64);
    for (var off = 0; off < withPad; off += 64) {
      for (var i = 0; i < 16; i++) {
        w[i] = (m[off + i * 4] << 24) | (m[off + i * 4 + 1] << 16) |
               (m[off + i * 4 + 2] << 8) | m[off + i * 4 + 3];
      }
      for (i = 16; i < 64; i++) {
        var s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
        var s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
      }
      var a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
      for (i = 0; i < 64; i++) {
        var S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        var ch = (e & f) ^ (~e & g);
        var t1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
        var S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        var maj = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (S0 + maj) >>> 0;
        h = g; g = f; f = e; e = (d + t1) >>> 0;
        d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0;
      H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
      H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0;
      H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
    }
    var out = new Uint8Array(32);
    for (i = 0; i < 8; i++) {
      out[i * 4] = (H[i] >>> 24) & 0xff;
      out[i * 4 + 1] = (H[i] >>> 16) & 0xff;
      out[i * 4 + 2] = (H[i] >>> 8) & 0xff;
      out[i * 4 + 3] = H[i] & 0xff;
    }
    return out;
  }

  function asciiBytes(text) {
    var out = new Uint8Array(text.length);
    for (var i = 0; i < text.length; i++) out[i] = text.charCodeAt(i) & 0xff;
    return out;
  }

  function leadingZeroBits(bytes) {
    var total = 0;
    for (var i = 0; i < bytes.length; i++) {
      var b = bytes[i];
      if (b === 0) { total += 8; continue; }
      var mask = 0x80;
      while (mask > 0 && (b & mask) === 0) { total++; mask >>= 1; }
      break;
    }
    return total;
  }

  function solve(jti, difficulty) {
    var budget = 4000000;
    for (var nonce = 0; nonce < budget; nonce++) {
      if (leadingZeroBits(sha256Bytes(asciiBytes(jti + ":" + nonce))) >= difficulty) return nonce;
    }
    return -1;
  }

  /* ------------------------------------------------------------------ *
   * base64url + HMAC
   * ------------------------------------------------------------------ */
  function b64uEncode(bytes) {
    var bin = "";
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function b64uDecode(text) {
    var padded = text.replace(/-/g, "+").replace(/_/g, "/");
    while (padded.length % 4) padded += "=";
    var bin = atob(padded);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  async function hmacSha256(keyBytes, text) {
    if (!global.crypto || !global.crypto.subtle) throw new Error("webcrypto unavailable");
    var key = await global.crypto.subtle.importKey(
      "raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
    );
    var sig = await global.crypto.subtle.sign("HMAC", key, asciiBytes(text));
    return new Uint8Array(sig);
  }

  /* ------------------------------------------------------------------ *
   * environment collection
   * ------------------------------------------------------------------ */
  function safe(fn, fallback) {
    try { var value = fn(); return value === undefined || value === null ? fallback : value; }
    catch (e) { return fallback; }
  }

  function stackLeak() {
    var stack = safe(function () { return new Error().stack || ""; }, "");
    return /pptr:|playwright|puppeteer|__webdriver|__selenium|frida/i.test(stack);
  }

  function webglRenderer() {
    return safe(function () {
      var canvas = document.createElement("canvas");
      var gl = canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
      if (!gl) return "";
      var ext = gl.getExtension("WEBGL_debug_renderer_info");
      if (!ext) return "";
      return String(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || "");
    }, "");
  }

  function nativeClean() {
    return safe(function () {
      var probe = Function.prototype.toString;
      if (probe.call(probe).indexOf("[native code]") === -1) return false;
      if (probe.call(Window.prototype.open).indexOf("[native code]") === -1) return false;
      if (probe.call(Function.prototype.bind).indexOf("[native code]") === -1) return false;
      return true;
    }, true);
  }

  function consistent() {
    return safe(function () {
      var ua = navigator.userAgent;
      var platform = navigator.userAgentData && navigator.userAgentData.platform;
      if (platform) {
        if (/Win/i.test(platform) && !/Windows/i.test(ua)) return false;
        if (/macOS/i.test(platform) && !/Mac OS X/i.test(ua)) return false;
        if (/Android/i.test(platform) && !/Android/i.test(ua)) return false;
      }
      if (navigator.hardwareConcurrency !== undefined && navigator.hardwareConcurrency < 1) return false;
      return true;
    }, true);
  }

  function devtoolsOpen() {
    return safe(function () {
      var widthGap = global.outerWidth - global.innerWidth;
      var heightGap = global.outerHeight - global.innerHeight;
      return widthGap > 160 || heightGap > 200;
    }, false);
  }

  function collect() {
    return {
      v: 1,
      ua: safe(function () { return navigator.userAgent; }, ""),
      webdriver: safe(function () { return navigator.webdriver === true; }, false),
      cdp: stackLeak(),
      native_clean: nativeClean(),
      webgl_renderer: webglRenderer(),
      consistent: consistent(),
      devtools_open: devtoolsOpen(),
      hardware_concurrency: safe(function () { return navigator.hardwareConcurrency || 0; }, 0),
      plugins: safe(function () { return navigator.plugins.length; }, 0),
      languages: safe(function () { return (navigator.languages || []).join(","); }, ""),
      platform: safe(function () { return navigator.platform || ""; }, ""),
      touch: safe(function () { return "ontouchstart" in global; }, false),
      honeypot_filled: safe(function () {
        var field = document.querySelector('input[name="fightre_website"]');
        return !!(field && field.value);
      }, false)
    };
  }

  /* Stable JSON: sorted keys, no whitespace — must match Python's
     json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False). */
  function stableStringify(value) {
    if (value === null || typeof value !== "object") return JSON.stringify(value);
    if (Array.isArray(value)) {
      return "[" + value.map(stableStringify).join(",") + "]";
    }
    var keys = Object.keys(value).sort();
    var parts = [];
    for (var i = 0; i < keys.length; i++) {
      parts.push(JSON.stringify(keys[i]) + ":" + stableStringify(value[keys[i]]));
    }
    return "{" + parts.join(",") + "}";
  }

  /* ------------------------------------------------------------------ *
   * challenge -> work -> attestation
   * ------------------------------------------------------------------ */
  async function bootstrap() {
    var challengeResponse = await fetch(CHALLENGE_URL, {
      method: "GET",
      credentials: "same-origin",
      headers: { "accept": "application/json" }
    });
    if (!challengeResponse.ok) return { ok: false, reason: "challenge-" + challengeResponse.status };
    var body = await challengeResponse.json();
    var challenge = body.challenge || body;
    if (!challenge || !challenge.jti) return { ok: false, reason: "no-challenge" };

    var nonce = solve(challenge.jti, challenge.difficulty);
    if (nonce < 0) return { ok: false, reason: "pow-budget" };

    var env = collect();
    var payload = {
      v: 1,
      jti: challenge.jti,
      ts: Math.round(Date.now() / 1000),
      env: env
    };
    var key = b64uDecode(challenge.attest_key);
    var signature = await hmacSha256(key, stableStringify(payload));
    var attestation = b64uEncode(asciiBytes(stableStringify(payload))) + "." + b64uEncode(signature);

    var attestResponse = await fetch(ATTEST_URL, {
      method: "POST",
      credentials: "same-origin",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token: challenge.token, nonce: nonce, attestation: attestation })
    });
    var result = await attestResponse.json().catch(function () { return {}; });
    if (!attestResponse.ok) return { ok: false, reason: result.error || "attest-failed", detail: result };
    return { ok: true, trust: result.trust, signals: result.signals || [] };
  }

  global.FightRE = {
    version: VERSION,
    collect: collect,
    solve: solve,
    bootstrap: bootstrap,
    stableStringify: stableStringify
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () { bootstrap().catch(function () {}); });
  } else {
    bootstrap().catch(function () {});
  }
})(window);
