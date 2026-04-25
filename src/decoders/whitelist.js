// ════════════════════════════════════════════════════════════════════════════
// whitelist.js — Context-based whitelist predicates for the encoded-content
// detector. Each helper inspects the text region around a
// candidate offset to decide whether the match is benign (data: URI, PEM,
// CSS @font-face, MIME body, GUID, hash literal, PowerShell -EncodedCommand,
// Base32-keyword anchor) and should be skipped before invoking the heavier
// decode + classify pipeline. All methods are pure / side-effect free.
// Mounted via `Object.assign(EncodedContentDetector.prototype, …)` so
// `this._isDataURI(…)` etc. continue to work unchanged.
// ════════════════════════════════════════════════════════════════════════════

Object.assign(EncodedContentDetector.prototype, {
  _isDataURI(text, offset) {
    // Check if the Base64 candidate follows a data: URI scheme
    const lookback = text.substring(Math.max(0, offset - 80), offset);
    return /data:[a-z]+\/[a-z0-9.+\-]+;base64,\s*$/i.test(lookback);
  },

  _isPEMBlock(text, offset) {
    const lookback = text.substring(Math.max(0, offset - 60), offset);
    return /-----BEGIN [A-Z ]+-----\s*$/i.test(lookback);
  },

  _isCSSFontData(text, offset) {
    const lookback = text.substring(Math.max(0, offset - 100), offset);
    return /src:\s*url\(data:(font|application\/x-font)/i.test(lookback);
  },

  _isMIMEBody(text, offset, context) {
    // Skip Base64 blocks that are MIME-encoded attachment bodies (already handled by EmlRenderer)
    if (context.fileType !== 'eml') return false;
    // Check if preceded by Content-Transfer-Encoding: base64 header
    const lookback = text.substring(Math.max(0, offset - 300), offset);
    return /Content-Transfer-Encoding:\s*base64/i.test(lookback);
  },

  _isHashLength(hexStr) {
    const len = hexStr.length;
    return len === 32 || len === 40 || len === 64 || len === 128;
  },

  _isGUID(text, offset) {
    // Check if this is part of a GUID pattern
    const region = text.substring(Math.max(0, offset - 5), offset + 40);
    return /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i.test(region);
  },

  _isPowerShellEncodedCommand(text, offset) {
    const lookback = text.substring(Math.max(0, offset - 60), offset);
    return /-(enc|encodedcommand|ec|EncodedCommand)\s+$/i.test(lookback);
  },

  _hasBase32Context(text, offset) {
    const lookback = text.substring(Math.max(0, offset - 100), offset);
    // Require contextual keywords
    return /(base32|encoded|payload|data|command|parameter|secret)/i.test(lookback) ||
           /['"]$/.test(lookback.trim());
  },
});
