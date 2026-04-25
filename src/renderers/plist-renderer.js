'use strict';
// ════════════════════════════════════════════════════════════════════════════
// plist-renderer.js — macOS Property List (.plist) parser and security analyser
// Supports both XML plist and binary plist (bplist00) formats.
// Depends on: constants.js (IOC, escHtml, fmtBytes)
// ════════════════════════════════════════════════════════════════════════════

class PlistRenderer {

  // ── Suspicious pattern definitions ──────────────────────────────────────
  static SUSPICIOUS_PATTERNS = [
    // Shell execution in ProgramArguments / Program
    { re: /\/bin\/(?:ba)?sh\b/i, label: 'Shell Interpreter in Program', desc: 'ProgramArguments invokes a shell interpreter — common in persistence malware', mitre: 'T1059.004', sev: 'high' },
    { re: /\/usr\/bin\/(?:python[23]?|perl|ruby)\b/i, label: 'Scripting Language Interpreter', desc: 'ProgramArguments uses a scripting language interpreter', mitre: 'T1059', sev: 'medium' },
    { re: /\/usr\/bin\/osascript\b/i, label: 'osascript Execution', desc: 'ProgramArguments invokes osascript — can execute AppleScript/JXA payloads', mitre: 'T1059.002', sev: 'high' },
    { re: /\/usr\/bin\/(?:curl|wget)\b/i, label: 'Download Utility in Program', desc: 'ProgramArguments uses curl/wget — potential payload download', mitre: 'T1105', sev: 'high' },
    { re: /\/usr\/bin\/(?:nc|ncat|netcat)\b/i, label: 'Netcat in Program', desc: 'ProgramArguments uses netcat — potential reverse shell or data exfiltration', mitre: 'T1095', sev: 'critical' },
    { re: /(?:\/tmp\/|\/var\/tmp\/|\/Users\/Shared\/)/i, label: 'User-Writable Path Reference', desc: 'References to temporary or world-writable directories — common malware staging area', mitre: 'T1074.001', sev: 'medium' },
    { re: /(?:LaunchAgents|LaunchDaemons)\/\./i, label: 'Hidden LaunchAgent/Daemon Path', desc: 'Path references a dot-prefixed (hidden) file in LaunchAgents/LaunchDaemons', mitre: 'T1543.004', sev: 'high' },
    { re: /base64/i, label: 'Base64 Reference', desc: 'References to base64 encoding/decoding — potential obfuscation', mitre: 'T1140', sev: 'medium' },
    { re: /chmod\s+[+0-7]*x/i, label: 'chmod Executable', desc: 'Makes a file executable — potential payload staging', mitre: 'T1222.002', sev: 'medium' },
    { re: /(?:open\s+-a|\/Applications\/.*\.app)/i, label: 'Application Launch', desc: 'Launches an application — could be used for execution or masquerading', mitre: 'T1204.002', sev: 'low' },
    { re: /(?:defaults\s+write|PlistBuddy)/i, label: 'Plist Modification Command', desc: 'Modifies property lists via command line — potential persistence or config manipulation', mitre: 'T1647', sev: 'medium' },
    { re: /(?:security\s+(?:add-trusted-cert|delete-certificate|authorizationdb))/i, label: 'Certificate/Auth Manipulation', desc: 'Manipulates system certificates or authorization database', mitre: 'T1553.004', sev: 'high' },
    { re: /(?:pkill|killall|kill\s+-9)/i, label: 'Process Termination', desc: 'Kills processes — could disable security tools', mitre: 'T1489', sev: 'medium' },
    { re: /(?:networksetup|scutil|ifconfig).*(?:proxy|dns)/i, label: 'Network Configuration Change', desc: 'Modifies network settings — potential traffic interception', mitre: 'T1090', sev: 'high' },
  ];

  // ── Security-relevant plist keys ────────────────────────────────────────
  static PERSISTENCE_KEYS = new Set([
    'ProgramArguments', 'Program', 'RunAtLoad', 'KeepAlive', 'StartInterval',
    'StartCalendarInterval', 'WatchPaths', 'QueueDirectories', 'OnDemand',
    'LaunchOnlyOnce', 'AbandonProcessGroup', 'ThrottleInterval',
  ]);

  static IDENTITY_KEYS = new Set([
    'Label', 'BundleIdentifier', 'CFBundleIdentifier', 'CFBundleName',
    'CFBundleDisplayName', 'CFBundleExecutable',
  ]);

  static ENVIRONMENT_KEYS = new Set([
    'EnvironmentVariables', 'PATH', 'DYLD_INSERT_LIBRARIES',
    'DYLD_LIBRARY_PATH', 'DYLD_FRAMEWORK_PATH',
  ]);

  static URL_SCHEME_KEYS = new Set([
    'CFBundleURLTypes', 'CFBundleURLSchemes', 'CFBundleURLName',
  ]);

  static TCC_KEYS = new Set([
    'NSAppleEventsUsageDescription', 'NSCameraUsageDescription',
    'NSMicrophoneUsageDescription', 'NSScreenCaptureUsageDescription',
    'NSAccessibilityUsageDescription', 'NSSystemAdministrationUsageDescription',
    'kTCCServiceAccessibility', 'kTCCServiceScreenCapture',
    'kTCCServiceMicrophone', 'kTCCServiceCamera',
    'com.apple.security.automation.apple-events',
  ]);

  // ══════════════════════════════════════════════════════════════════════════
  //  Helpers
  // ══════════════════════════════════════════════════════════════════════════
  static _esc(s) { return typeof escHtml === 'function' ? escHtml(String(s)) : String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }
  static _fmtBytes(n) { return typeof fmtBytes === 'function' ? fmtBytes(n) : n + ' bytes'; }

  // ══════════════════════════════════════════════════════════════════════════
  //  Format Detection
  // ══════════════════════════════════════════════════════════════════════════

  /** Detect whether buffer is XML plist, binary plist, or unknown */
  static detectFormat(bytes) {
    // Binary plist: starts with "bplist"
    if (bytes.length >= 8 &&
        bytes[0] === 0x62 && bytes[1] === 0x70 && bytes[2] === 0x6C &&
        bytes[3] === 0x69 && bytes[4] === 0x73 && bytes[5] === 0x74) {
      const ver = String.fromCharCode(bytes[6], bytes[7]);
      return { type: 'binary', version: ver };
    }
    // XML plist: check for <?xml or <!DOCTYPE plist or <plist
    const head = new TextDecoder('utf-8', { fatal: false }).decode(bytes.subarray(0, Math.min(512, bytes.length)));
    if (/<plist[\s>]/i.test(head) || /<!DOCTYPE\s+plist/i.test(head)) {
      return { type: 'xml', version: '' };
    }
    // Try UTF-16
    if (bytes.length >= 4 && ((bytes[0] === 0xFF && bytes[1] === 0xFE) || (bytes[0] === 0xFE && bytes[1] === 0xFF))) {
      const encoding = bytes[0] === 0xFF ? 'utf-16le' : 'utf-16be';
      const head16 = new TextDecoder(encoding, { fatal: false }).decode(bytes.subarray(0, Math.min(1024, bytes.length)));
      if (/<plist[\s>]/i.test(head16) || /<!DOCTYPE\s+plist/i.test(head16)) {
        return { type: 'xml', version: '', encoding };
      }
    }
    return { type: 'unknown', version: '' };
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  XML Plist Parser
  // ══════════════════════════════════════════════════════════════════════════

  /** Parse an XML plist from string, returns a JS value */
  _parseXmlPlist(text) {
    const parser = new DOMParser();
    const doc = parser.parseFromString(text, 'application/xml');
    const err = doc.querySelector('parsererror');
    if (err) throw new Error('XML parse error: ' + err.textContent.substring(0, 200));
    const plistEl = doc.querySelector('plist');
    if (!plistEl) throw new Error('No <plist> root element found');
    // The first child element of <plist> is the root value
    for (const child of plistEl.children) {
      return this._parseXmlNode(child, 0);
    }
    return null;
  }

  /**
   * Recursively parse a plist XML node into a JS value with type info.
   * The `depth` argument is bounded by `PARSER_LIMITS.MAX_DEPTH` so a
   * deliberately nested plist (e.g. 10 000 levels of `<array>` inside
   * `<array>`) cannot blow the JS stack.
   */
  _parseXmlNode(node, depth) {
    depth = depth | 0;
    if (depth > PARSER_LIMITS.MAX_DEPTH) {
      return { _type: 'string', _value: '(depth limit reached)' };
    }
    const tag = node.tagName;
    switch (tag) {
      case 'dict': {
        const entries = [];
        const children = Array.from(node.children);
        for (let i = 0; i < children.length; i += 2) {
          if (children[i].tagName !== 'key') continue;
          const key = children[i].textContent;
          const val = i + 1 < children.length ? this._parseXmlNode(children[i + 1], depth + 1) : { _type: 'string', _value: '' };
          entries.push({ key, value: val });
        }
        return { _type: 'dict', _entries: entries };
      }
      case 'array': {
        const items = Array.from(node.children).map(c => this._parseXmlNode(c, depth + 1));
        return { _type: 'array', _items: items };
      }
      case 'string': return { _type: 'string', _value: node.textContent };
      case 'integer': return { _type: 'integer', _value: parseInt(node.textContent, 10) };
      case 'real': return { _type: 'real', _value: parseFloat(node.textContent) };
      case 'true': return { _type: 'boolean', _value: true };
      case 'false': return { _type: 'boolean', _value: false };
      case 'date': return { _type: 'date', _value: node.textContent };
      case 'data': return { _type: 'data', _value: node.textContent.trim() };
      default: return { _type: 'string', _value: node.textContent };
    }
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  Binary Plist Parser (bplist00)
  // ══════════════════════════════════════════════════════════════════════════

  /** Parse a binary plist from Uint8Array, returns a JS value */
  _parseBinaryPlist(bytes) {
    if (bytes.length < 40) throw new Error('Binary plist too short');
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const len = bytes.length;

    // ── Trailer (last 32 bytes) ────────────────────────────────────────
    const trailerOff = len - 32;
    // bytes 0-4 of trailer: unused
    // byte 5: sort version (unused)
    const offsetSize = bytes[trailerOff + 6];     // size of offset table entries
    const objectRefSize = bytes[trailerOff + 7];   // size of object references
    // bytes 8-15: number of objects (64-bit, we use lower 32)
    const numObjects = dv.getUint32(trailerOff + 12);
    // bytes 16-23: top-level object index (64-bit, use lower 32)
    const topObject = dv.getUint32(trailerOff + 20);
    // bytes 24-31: offset table start (64-bit, use lower 32)
    const offsetTableStart = dv.getUint32(trailerOff + 28);

    if (numObjects > 1000000) throw new Error('Binary plist: too many objects (' + numObjects + ')');
    if (offsetSize < 1 || offsetSize > 8) throw new Error('Binary plist: invalid offset size');
    if (objectRefSize < 1 || objectRefSize > 8) throw new Error('Binary plist: invalid object ref size');

    // ── Offset table ───────────────────────────────────────────────────
    const offsets = [];
    for (let i = 0; i < numObjects; i++) {
      offsets.push(this._readSizedInt(bytes, offsetTableStart + i * offsetSize, offsetSize));
    }

    // ── Parse objects ──────────────────────────────────────────────────
    const cache = new Array(numObjects);
    const parseObj = (idx) => {
      if (idx >= numObjects) return { _type: 'string', _value: '(invalid ref)' };
      if (cache[idx] !== undefined) return cache[idx];
      // Guard against cycles
      cache[idx] = { _type: 'string', _value: '(circular ref)' };
      const off = offsets[idx];
      const marker = bytes[off];
      const hi = (marker & 0xF0) >> 4;
      const lo = marker & 0x0F;
      let result;

      switch (hi) {
        case 0x0: // null / bool / fill
          if (lo === 0x00) result = { _type: 'null', _value: null };
          else if (lo === 0x08) result = { _type: 'boolean', _value: false };
          else if (lo === 0x09) result = { _type: 'boolean', _value: true };
          else if (lo === 0x0F) result = { _type: 'null', _value: null }; // fill
          else result = { _type: 'null', _value: null };
          break;

        case 0x1: { // int
          const byteCount = 1 << lo;
          result = { _type: 'integer', _value: this._readSizedInt(bytes, off + 1, byteCount) };
          break;
        }

        case 0x2: { // real
          const byteCount = 1 << lo;
          if (byteCount === 4) result = { _type: 'real', _value: dv.getFloat32(off + 1) };
          else if (byteCount === 8) result = { _type: 'real', _value: dv.getFloat64(off + 1) };
          else result = { _type: 'real', _value: 0 };
          break;
        }

        case 0x3: { // date (always 8-byte float, seconds from 2001-01-01)
          const ts = dv.getFloat64(off + 1);
          const date = new Date(Date.UTC(2001, 0, 1) + ts * 1000);
          result = { _type: 'date', _value: date.toISOString() };
          break;
        }

        case 0x4: { // data
          const { count, dataOff } = this._readCount(bytes, off, lo);
          const b64 = this._bytesToBase64(bytes.subarray(dataOff, dataOff + count));
          result = { _type: 'data', _value: b64, _byteLength: count };
          break;
        }

        case 0x5: { // ASCII string
          const { count, dataOff } = this._readCount(bytes, off, lo);
          const str = String.fromCharCode(...bytes.subarray(dataOff, dataOff + count));
          result = { _type: 'string', _value: str };
          break;
        }

        case 0x6: { // Unicode string (UTF-16BE)
          const { count, dataOff } = this._readCount(bytes, off, lo);
          let str = '';
          for (let i = 0; i < count; i++) {
            str += String.fromCharCode(dv.getUint16(dataOff + i * 2));
          }
          result = { _type: 'string', _value: str };
          break;
        }

        case 0x8: { // UID
          const n = lo + 1;
          result = { _type: 'uid', _value: this._readSizedInt(bytes, off + 1, n) };
          break;
        }

        case 0xA: { // array
          const { count, dataOff } = this._readCount(bytes, off, lo);
          const items = [];
          for (let i = 0; i < count; i++) {
            const ref = this._readSizedInt(bytes, dataOff + i * objectRefSize, objectRefSize);
            items.push(parseObj(ref));
          }
          result = { _type: 'array', _items: items };
          break;
        }

        case 0xC: // set (treat like array)
        {
          const { count, dataOff } = this._readCount(bytes, off, lo);
          const items = [];
          for (let i = 0; i < count; i++) {
            const ref = this._readSizedInt(bytes, dataOff + i * objectRefSize, objectRefSize);
            items.push(parseObj(ref));
          }
          result = { _type: 'array', _items: items };
          break;
        }

        case 0xD: { // dict
          const { count, dataOff } = this._readCount(bytes, off, lo);
          const entries = [];
          const keyStart = dataOff;
          const valStart = dataOff + count * objectRefSize;
          for (let i = 0; i < count; i++) {
            const keyRef = this._readSizedInt(bytes, keyStart + i * objectRefSize, objectRefSize);
            const valRef = this._readSizedInt(bytes, valStart + i * objectRefSize, objectRefSize);
            const keyObj = parseObj(keyRef);
            const keyStr = keyObj._value !== undefined ? String(keyObj._value) : '(unknown)';
            entries.push({ key: keyStr, value: parseObj(valRef) });
          }
          result = { _type: 'dict', _entries: entries };
          break;
        }

        default:
          result = { _type: 'string', _value: `(unknown type 0x${marker.toString(16)})` };
      }

      cache[idx] = result;
      return result;
    };

    return parseObj(topObject);
  }

  /** Read a count from a binary plist object marker. If lo == 0x0F, next byte is int marker for extended count. */
  _readCount(bytes, off, lo) {
    if (lo !== 0x0F) {
      return { count: lo, dataOff: off + 1 };
    }
    // Extended count: next byte is an int marker
    const intMarker = bytes[off + 1];
    const intLen = 1 << (intMarker & 0x0F);
    const count = this._readSizedInt(bytes, off + 2, intLen);
    return { count, dataOff: off + 2 + intLen };
  }

  /** Read an integer of 1/2/4/8 bytes (big-endian) */
  _readSizedInt(bytes, off, size) {
    if (off + size > bytes.length) return 0;
    if (size === 1) return bytes[off];
    if (size === 2) return (bytes[off] << 8) | bytes[off + 1];
    if (size === 4) return ((bytes[off] << 24) | (bytes[off + 1] << 16) | (bytes[off + 2] << 8) | bytes[off + 3]) >>> 0;
    if (size === 8) {
      // JS doesn't do 64-bit ints natively; use Number (safe up to 2^53)
      const hi = ((bytes[off] << 24) | (bytes[off + 1] << 16) | (bytes[off + 2] << 8) | bytes[off + 3]) >>> 0;
      const lo = ((bytes[off + 4] << 24) | (bytes[off + 5] << 16) | (bytes[off + 6] << 8) | bytes[off + 7]) >>> 0;
      return hi * 0x100000000 + lo;
    }
    return 0;
  }

  /** Convert bytes to base64 */
  _bytesToBase64(bytes) {
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    try { return btoa(bin); } catch { return '(binary data, ' + bytes.length + ' bytes)'; }
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  Plist → Text serialiser (for YARA scanning / raw text)
  // ══════════════════════════════════════════════════════════════════════════

  /** Convert parsed plist value to readable text */
  _toText(node, indent) {
    indent = indent || 0;
    const pad = '  '.repeat(indent);
    if (!node) return pad + '(null)';

    switch (node._type) {
      case 'dict': {
        if (!node._entries || node._entries.length === 0) return pad + '{}';
        const lines = [pad + '{'];
        for (const { key, value } of node._entries) {
          lines.push(pad + '  ' + key + ' = ' + this._toText(value, indent + 1).trimStart());
        }
        lines.push(pad + '}');
        return lines.join('\n');
      }
      case 'array': {
        if (!node._items || node._items.length === 0) return pad + '[]';
        const lines = [pad + '['];
        for (const item of node._items) {
          lines.push(this._toText(item, indent + 1));
        }
        lines.push(pad + ']');
        return lines.join('\n');
      }
      case 'data': {
        const preview = String(node._value).substring(0, 80);
        return pad + '<data> ' + preview + (node._value.length > 80 ? '…' : '') + (node._byteLength ? ' (' + node._byteLength + ' bytes)' : '');
      }
      case 'date': return pad + String(node._value);
      case 'boolean': return pad + (node._value ? 'true' : 'false');
      case 'integer':
      case 'real': return pad + String(node._value);
      case 'uid': return pad + 'UID(' + node._value + ')';
      case 'null': return pad + '(null)';
      default: return pad + String(node._value || '');
    }
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  Classify plist purpose
  // ══════════════════════════════════════════════════════════════════════════

  /** Determine the purpose/type of a plist based on keys and filename */
  _classify(root, fileName) {
    if (!root || root._type !== 'dict') return { type: 'generic', label: 'Property List' };
    const keys = new Set(root._entries.map(e => e.key));
    const fn = (fileName || '').toLowerCase();

    // LaunchAgent / LaunchDaemon
    if (keys.has('Label') && (keys.has('ProgramArguments') || keys.has('Program'))) {
      if (fn.includes('launchdaemon') || fn.includes('launchdaemons')) {
        return { type: 'launchdaemon', label: '🔴 LaunchDaemon (root-level persistence)' };
      }
      return { type: 'launchagent', label: '🟡 LaunchAgent (user-level persistence)' };
    }

    // Login Item
    if (keys.has('LSUIElement') || keys.has('LSBackgroundOnly') || fn.includes('loginitem')) {
      return { type: 'loginitem', label: '🟡 Login Item Configuration' };
    }

    // App Info.plist
    if (keys.has('CFBundleIdentifier') && keys.has('CFBundleExecutable')) {
      if (keys.has('CFBundleURLTypes')) return { type: 'app-urlscheme', label: '📱 App Info.plist (with URL schemes)' };
      return { type: 'app-info', label: '📱 App Info.plist' };
    }

    // URL scheme handler
    if (keys.has('CFBundleURLTypes') || keys.has('CFBundleURLSchemes')) {
      return { type: 'urlscheme', label: '🔗 URL Scheme Handler' };
    }

    // Preferences
    if (fn.includes('preferences') || fn.includes('.pref')) {
      return { type: 'preferences', label: '⚙ Preferences Plist' };
    }

    // Entitlements
    if (keys.has('com.apple.security.app-sandbox') || keys.has('com.apple.security.automation.apple-events')) {
      return { type: 'entitlements', label: '🔐 Entitlements Plist' };
    }

    return { type: 'generic', label: '📋 Property List' };
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  Get value from parsed plist by key path
  // ══════════════════════════════════════════════════════════════════════════

  _getValue(root, key) {
    if (!root || root._type !== 'dict') return undefined;
    for (const entry of root._entries) {
      if (entry.key === key) return entry.value;
    }
    return undefined;
  }

  _getStringValue(root, key) {
    const v = this._getValue(root, key);
    if (!v) return '';
    if (v._type === 'string') return v._value;
    if (v._type === 'integer' || v._type === 'real') return String(v._value);
    if (v._type === 'boolean') return v._value ? 'true' : 'false';
    return '';
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  Collect all string values from plist (for scanning)
  // ══════════════════════════════════════════════════════════════════════════

  _collectStrings(node, out, depth) {
    if (!node) return;
    depth = depth | 0;
    if (depth > PARSER_LIMITS.MAX_DEPTH) return;
    if (node._type === 'string' && node._value) out.push(node._value);
    if (node._type === 'dict') {
      for (const e of (node._entries || [])) {
        out.push(e.key);
        this._collectStrings(e.value, out, depth + 1);
      }
    }
    if (node._type === 'array') {
      for (const item of (node._items || [])) this._collectStrings(item, out, depth + 1);
    }
  }

  /** Collect all keys from plist recursively */
  _collectKeys(node, out, depth) {
    if (!node) return;
    depth = depth | 0;
    if (depth > PARSER_LIMITS.MAX_DEPTH) return;
    if (node._type === 'dict') {
      for (const e of (node._entries || [])) {
        out.add(e.key);
        this._collectKeys(e.value, out, depth + 1);
      }
    }
    if (node._type === 'array') {
      for (const item of (node._items || [])) this._collectKeys(item, out, depth + 1);
    }
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  render(buffer, fileName)
  // ══════════════════════════════════════════════════════════════════════════

  render(buffer, fileName) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer || buffer);
    const format = PlistRenderer.detectFormat(bytes);
    const wrap = document.createElement('div');
    wrap.className = 'plist-view';

    // ── Parse ────────────────────────────────────────────────────────────
    let root = null;
    let xmlSource = '';
    let parseError = null;

    try {
      if (format.type === 'binary') {
        root = this._parseBinaryPlist(bytes);
      } else if (format.type === 'xml') {
        const encoding = format.encoding || 'utf-8';
        xmlSource = new TextDecoder(encoding, { fatal: false }).decode(bytes);
        root = this._parseXmlPlist(xmlSource);
      } else {
        // Try XML anyway (best effort)
        xmlSource = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
        root = this._parseXmlPlist(xmlSource);
        format.type = 'xml';
      }
    } catch (e) {
      parseError = e.message;
    }

    // Classify
    const classification = root ? this._classify(root, fileName) : { type: 'unknown', label: 'Unknown Plist' };

    // ── Banner ───────────────────────────────────────────────────────────
    const banner = document.createElement('div');
    banner.className = 'doc-extraction-banner';
    const isLaunchPersistence = classification.type === 'launchagent' || classification.type === 'launchdaemon';
    if (isLaunchPersistence) {
      banner.innerHTML = '<strong>⚠ macOS Persistence Plist</strong> — This property list configures a ' +
        (classification.type === 'launchdaemon' ? 'LaunchDaemon (runs as root)' : 'LaunchAgent (runs as current user)') +
        '. It defines programs that execute automatically on login or system boot, commonly abused for malware persistence.';
    } else {
      banner.innerHTML = '<strong>📋 macOS Property List (.plist)</strong> — Property lists store configuration data for macOS applications and system services. Plist files can define persistence mechanisms, URL handlers, entitlements, and other security-relevant settings.';
    }
    wrap.appendChild(banner);

    // ── Summary info ─────────────────────────────────────────────────────
    const infoDiv = document.createElement('div');
    infoDiv.className = 'plaintext-info';
    const formatLabel = format.type === 'binary' ? 'Binary plist (bplist' + format.version + ')' : 'XML plist';
    const keyCount = root && root._type === 'dict' ? root._entries.length : 0;
    infoDiv.textContent = `${formatLabel}  ·  ${classification.label}  ·  ${keyCount} top-level key${keyCount !== 1 ? 's' : ''}  ·  ${PlistRenderer._fmtBytes(bytes.length)}`;
    wrap.appendChild(infoDiv);

    // ── Parse error ──────────────────────────────────────────────────────
    if (parseError) {
      const errDiv = document.createElement('div');
      errDiv.className = 'zip-warnings';
      const w = document.createElement('div');
      w.className = 'zip-warning zip-warning-high';
      w.textContent = '⚠ Parse error: ' + parseError;
      errDiv.appendChild(w);
      wrap.appendChild(errDiv);
    }

    // ── Security warnings ────────────────────────────────────────────────
    if (root) {
      const warnings = this._generateWarnings(root, fileName);
      if (warnings.length > 0) {
        const warnDiv = document.createElement('div');
        warnDiv.className = 'zip-warnings';
        for (const w of warnings) {
          const d = document.createElement('div');
          d.className = 'zip-warning zip-warning-' + w.sev;
          d.textContent = '⚠ ' + w.label;
          warnDiv.appendChild(d);
        }
        wrap.appendChild(warnDiv);
      }
    }

    // ── Key Properties card (for LaunchAgent/Daemon) ─────────────────────
    if (root && isLaunchPersistence) {
      const card = document.createElement('div');
      card.className = 'plist-persistence-card';

      const cardTitle = document.createElement('div');
      cardTitle.className = 'plist-card-title';
      cardTitle.textContent = classification.type === 'launchdaemon' ? '🔴 LaunchDaemon Properties' : '🟡 LaunchAgent Properties';
      card.appendChild(cardTitle);

      const tbl = document.createElement('table');
      tbl.className = 'lnk-info-table';

      const addRow = (label, value, highlight) => {
        const tr = document.createElement('tr');
        const tdL = document.createElement('td'); tdL.className = 'lnk-lbl'; tdL.textContent = label;
        const tdV = document.createElement('td'); tdV.className = 'lnk-val';
        tdV.textContent = value;
        if (highlight) tdV.style.color = highlight;
        tr.appendChild(tdL); tr.appendChild(tdV);
        tbl.appendChild(tr);
      };

      const label = this._getStringValue(root, 'Label');
      addRow('Label', label || '(not set)', label && label.startsWith('.') ? '#f44' : null);

      const program = this._getStringValue(root, 'Program');
      const progArgs = this._getValue(root, 'ProgramArguments');
      if (program) {
        addRow('Program', program, /\/tmp\/|\/var\/tmp\/|\/Users\/Shared\//.test(program) ? '#f44' : null);
      }
      if (progArgs && progArgs._type === 'array') {
        const argStrings = progArgs._items.map(i => i._value || '').join(' ');
        addRow('ProgramArguments', argStrings, /\/bin\/(?:ba)?sh|curl|wget|osascript|python/.test(argStrings) ? 'var(--risk-high)' : null);
      }

      const runAtLoad = this._getValue(root, 'RunAtLoad');
      if (runAtLoad) addRow('RunAtLoad', runAtLoad._value ? '✅ true' : '❌ false', runAtLoad._value ? 'var(--risk-high)' : null);

      const keepAlive = this._getValue(root, 'KeepAlive');
      if (keepAlive) addRow('KeepAlive', keepAlive._type === 'boolean' ? (keepAlive._value ? '✅ true' : '❌ false') : '(complex)', keepAlive._value ? '#fa0' : null);

      const interval = this._getValue(root, 'StartInterval');
      if (interval) addRow('StartInterval', interval._value + ' seconds', interval._value && interval._value < 300 ? 'var(--risk-high)' : null);

      const watchPaths = this._getValue(root, 'WatchPaths');
      if (watchPaths && watchPaths._type === 'array') {
        addRow('WatchPaths', watchPaths._items.map(i => i._value || '').join(', '));
      }

      const envVars = this._getValue(root, 'EnvironmentVariables');
      if (envVars && envVars._type === 'dict') {
        for (const e of envVars._entries) {
          const isDyld = e.key.startsWith('DYLD_');
          addRow('Env: ' + e.key, e.value._value || '', isDyld ? '#f44' : null);
        }
      }

      card.appendChild(tbl);
      wrap.appendChild(card);
    }

    // ── Tree view ────────────────────────────────────────────────────────
    if (root) {
      const treeH = document.createElement('div');
      treeH.className = 'hta-section-hdr';
      treeH.textContent = '🌳 Property Tree';
      wrap.appendChild(treeH);

      const treeWrap = document.createElement('div');
      treeWrap.className = 'plist-tree';
      treeWrap.appendChild(this._renderNode(root, null, 0, true));
      wrap.appendChild(treeWrap);
    }

    // ── Raw source ───────────────────────────────────────────────────────
    if (format.type === 'xml' && xmlSource) {
      const srcH = document.createElement('div');
      srcH.className = 'hta-section-hdr';
      srcH.textContent = 'XML Source';
      wrap.appendChild(srcH);

      const lines = xmlSource.split('\n');
      const srcInfo = document.createElement('div');
      srcInfo.className = 'plaintext-info';
      srcInfo.textContent = lines.length + ' line' + (lines.length !== 1 ? 's' : '');
      wrap.appendChild(srcInfo);

      const scr = document.createElement('div');
      scr.className = 'plaintext-scroll';
      const table = document.createElement('table');
      table.className = 'plaintext-table';
      const maxLines = RENDER_LIMITS.MAX_TEXT_LINES_SMALL;
      let highlightedLines = null;
      if (typeof hljs !== 'undefined' && xmlSource.length <= 200000) {
        try {
          const result = hljs.highlight(xmlSource, { language: 'xml', ignoreIllegals: true });
          highlightedLines = result.value.split('\n');
        } catch (_) { /* fallback to plain textContent */ }
      }
      for (let i = 0; i < Math.min(lines.length, maxLines); i++) {
        const tr = document.createElement('tr');
        const tdN = document.createElement('td');
        tdN.className = 'plaintext-ln';
        tdN.textContent = i + 1;
        const tdC = document.createElement('td');
        tdC.className = 'plaintext-code';
        if (highlightedLines && highlightedLines[i] !== undefined) {
          tdC.innerHTML = highlightedLines[i] || '';
        } else {
          tdC.textContent = lines[i];
        }
        tr.appendChild(tdN);
        tr.appendChild(tdC);
        table.appendChild(tr);
      }
      if (lines.length > maxLines) {
        const tr = document.createElement('tr');
        const td = document.createElement('td');
        td.colSpan = 2;
        td.style.cssText = 'text-align:center;color:#888;padding:8px;';
        td.textContent = `… ${lines.length - maxLines} more lines truncated …`;
        tr.appendChild(td);
        table.appendChild(tr);
      }
      scr.appendChild(table);
      wrap.appendChild(scr);
    }

    // Store raw text for YARA/IOC scanning.
    // Prefer the actual XML source when available so that match offsets returned
    // by YARA and the IOC extractor line up with the displayed XML source in the
    // plaintext-table. Falling back to the serialised tree would cause clicks
    // on findings to highlight the wrong line (e.g. a URL finding would land on
    // the first string leaf in the serialised tree rather than on the XML line
    // containing the URL). For binary plists there is no xmlSource and no
    // plaintext-table, so the tree serialisation is a harmless fallback.
    wrap._rawText = lfNormalize(xmlSource || (root ? this._toText(root) : ''));
    return wrap;
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  Tree view node renderer
  // ══════════════════════════════════════════════════════════════════════════

  _renderNode(node, keyName, depth, open) {
    if (!node) {
      const sp = document.createElement('span');
      sp.textContent = '(null)';
      return sp;
    }

    const isContainer = node._type === 'dict' || node._type === 'array';
    const isSuspiciousKey = keyName && (
      PlistRenderer.PERSISTENCE_KEYS.has(keyName) ||
      PlistRenderer.ENVIRONMENT_KEYS.has(keyName) ||
      PlistRenderer.TCC_KEYS.has(keyName)
    );
    const isIdentityKey = keyName && PlistRenderer.IDENTITY_KEYS.has(keyName);

    if (isContainer) {
      const det = document.createElement('details');
      det.className = 'plist-node';
      if (open || depth < 1) det.open = true;

      const sum = document.createElement('summary');
      sum.className = 'plist-node-summary';
      if (depth > 0) sum.style.paddingLeft = (depth * 18) + 'px';

      if (keyName !== null) {
        const kSpan = document.createElement('span');
        kSpan.className = 'plist-key' + (isSuspiciousKey ? ' plist-key-suspicious' : '') + (isIdentityKey ? ' plist-key-identity' : '');
        kSpan.textContent = keyName;
        sum.appendChild(kSpan);
        sum.appendChild(document.createTextNode(' '));
      }

      const badge = document.createElement('span');
      badge.className = 'plist-type-badge plist-type-' + node._type;
      const count = node._type === 'dict' ? node._entries.length : node._items.length;
      badge.textContent = node._type + ' (' + count + ')';
      sum.appendChild(badge);
      det.appendChild(sum);

      const content = document.createElement('div');
      content.className = 'plist-node-content';

      if (node._type === 'dict') {
        for (const entry of node._entries) {
          content.appendChild(this._renderNode(entry.value, entry.key, depth + 1, depth < 1));
        }
      } else {
        node._items.forEach((item, idx) => {
          content.appendChild(this._renderNode(item, '[' + idx + ']', depth + 1, depth < 1));
        });
      }

      det.appendChild(content);
      return det;
    }

    // Leaf node
    const row = document.createElement('div');
    row.className = 'plist-leaf';
    if (depth > 0) row.style.paddingLeft = (depth * 18) + 'px';

    if (keyName !== null) {
      const kSpan = document.createElement('span');
      kSpan.className = 'plist-key' + (isSuspiciousKey ? ' plist-key-suspicious' : '') + (isIdentityKey ? ' plist-key-identity' : '');
      kSpan.textContent = keyName;
      row.appendChild(kSpan);
      row.appendChild(document.createTextNode(' '));
    }

    const badge = document.createElement('span');
    badge.className = 'plist-type-badge plist-type-' + node._type;
    badge.textContent = node._type;
    row.appendChild(badge);
    row.appendChild(document.createTextNode(' '));

    const val = document.createElement('span');
    val.className = 'plist-value';
    if (node._type === 'boolean') {
      val.textContent = node._value ? 'true' : 'false';
      val.className += node._value ? ' plist-bool-true' : ' plist-bool-false';
    } else if (node._type === 'data') {
      const preview = String(node._value).substring(0, 80);
      val.textContent = preview + (node._value.length > 80 ? '…' : '');
      if (node._byteLength) val.textContent += ' (' + node._byteLength + ' bytes)';
      val.className += ' plist-value-data';
    } else if (node._type === 'date') {
      val.textContent = node._value;
      val.className += ' plist-value-date';
    } else if (node._type === 'integer' || node._type === 'real') {
      val.textContent = String(node._value);
      val.className += ' plist-value-number';
    } else if (node._type === 'uid') {
      val.textContent = 'UID(' + node._value + ')';
    } else if (node._type === 'null') {
      val.textContent = '(null)';
    } else {
      // string
      const sv = String(node._value);
      val.textContent = sv.length > 500 ? sv.substring(0, 500) + '…' : sv;
      // Highlight suspicious string values
      if (/\/bin\/(?:ba)?sh|curl|wget|osascript|python|perl|\/tmp\/|\/var\/tmp\//.test(sv)) {
        val.className += ' plist-value-suspicious';
      }
    }
    row.appendChild(val);
    return row;
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  Generate security warnings
  // ══════════════════════════════════════════════════════════════════════════

  _generateWarnings(root, fileName) {
    const warnings = [];
    if (!root || root._type !== 'dict') return warnings;
    const allStrings = [];
    this._collectStrings(root, allStrings);
    const allText = allStrings.join('\n');

    const label = this._getStringValue(root, 'Label');
    const runAtLoad = this._getValue(root, 'RunAtLoad');
    const progArgs = this._getValue(root, 'ProgramArguments');
    const program = this._getStringValue(root, 'Program');
    const keepAlive = this._getValue(root, 'KeepAlive');
    const interval = this._getValue(root, 'StartInterval');
    const envVars = this._getValue(root, 'EnvironmentVariables');

    // Hidden label (dot-prefixed)
    if (label && label.startsWith('.')) {
      warnings.push({ sev: 'high', label: 'Hidden LaunchAgent label: "' + label + '" — dot-prefix hides from casual inspection' });
    }

    // RunAtLoad + shell execution
    if (runAtLoad && runAtLoad._value === true) {
      const argText = progArgs && progArgs._type === 'array' ? progArgs._items.map(i => String(i._value || '')).join(' ') : '';
      const execTarget = program || argText;
      if (/\/bin\/(?:ba)?sh\b/.test(execTarget)) {
        warnings.push({ sev: 'critical', label: 'RunAtLoad with shell execution — launches shell on every login/boot' });
      } else if (/osascript/.test(execTarget)) {
        warnings.push({ sev: 'high', label: 'RunAtLoad with osascript — executes AppleScript/JXA on login' });
      } else if (/curl|wget/.test(execTarget)) {
        warnings.push({ sev: 'critical', label: 'RunAtLoad with download utility — fetches payload on every login/boot' });
      } else if (execTarget) {
        warnings.push({ sev: 'medium', label: 'RunAtLoad is enabled — program runs automatically on login/boot' });
      }
    }

    // KeepAlive + RunAtLoad (aggressive persistence)
    if (keepAlive && (keepAlive._value === true || keepAlive._type === 'dict') && runAtLoad && runAtLoad._value === true) {
      warnings.push({ sev: 'high', label: 'KeepAlive + RunAtLoad — aggressive persistence: restarts if killed' });
    }

    // Short StartInterval (potential C2 beacon)
    if (interval && interval._type === 'integer' && interval._value < 300) {
      warnings.push({ sev: 'medium', label: 'Short StartInterval (' + interval._value + 's) — may indicate C2 beacon interval' });
    }

    // Environment variable injection
    if (envVars && envVars._type === 'dict') {
      for (const e of envVars._entries) {
        if (e.key === 'DYLD_INSERT_LIBRARIES') {
          warnings.push({ sev: 'critical', label: 'DYLD_INSERT_LIBRARIES injection — loads malicious dylib into all processes' });
        } else if (e.key.startsWith('DYLD_')) {
          warnings.push({ sev: 'high', label: 'DYLD environment variable: ' + e.key + ' — potential library hijacking' });
        }
      }
    }

    // Suspicious paths in any string values
    if (/\/tmp\/|\/var\/tmp\/|\/Users\/Shared\//.test(allText)) {
      warnings.push({ sev: 'medium', label: 'References to temporary/writable directories — common malware staging area' });
    }

    // Base64 encoded content
    const b64 = allText.match(/[A-Za-z0-9+/=]{60,}/g);
    if (b64 && b64.length) {
      warnings.push({ sev: 'medium', label: 'Large base64-encoded string(s) detected — potential obfuscated payload' });
    }

    return warnings;
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  analyzeForSecurity(buffer, fileName)
  // ══════════════════════════════════════════════════════════════════════════

  analyzeForSecurity(buffer, fileName) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer || buffer);
    const format = PlistRenderer.detectFormat(bytes);

    const findings = {
      risk: 'low',
      hasMacros: false,
      macroSize: 0,
      macroHash: '',
      autoExec: [],
      modules: [],
      externalRefs: [],
      metadata: {},
      signatureMatches: [],
      interestingStrings: [],
    };

    // ── Parse ────────────────────────────────────────────────────────────
    let root = null;
    try {
      if (format.type === 'binary') {
        root = this._parseBinaryPlist(bytes);
        findings.metadata.format = 'Binary Property List (bplist' + format.version + ')';
      } else if (format.type === 'xml') {
        const encoding = format.encoding || 'utf-8';
        const text = new TextDecoder(encoding, { fatal: false }).decode(bytes);
        root = this._parseXmlPlist(text);
        findings.metadata.format = 'XML Property List';
      } else {
        // Try XML as fallback
        const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
        root = this._parseXmlPlist(text);
        findings.metadata.format = 'XML Property List';
      }
    } catch (e) {
      findings.metadata.format = 'Property List (parse error)';
      findings.metadata.parseError = e.message;
      return findings;
    }

    if (!root) return findings;

    // ── Classification ───────────────────────────────────────────────────
    const classification = this._classify(root, fileName);
    findings.metadata.classification = classification.label;
    findings.metadata.topLevelType = root._type;
    if (root._type === 'dict') findings.metadata.keyCount = String(root._entries.length);

    // ── Extract identity info ────────────────────────────────────────────
    const label = this._getStringValue(root, 'Label');
    if (label) findings.metadata.label = label;

    const bundleId = this._getStringValue(root, 'CFBundleIdentifier');
    if (bundleId) findings.metadata.bundleIdentifier = bundleId;

    const bundleName = this._getStringValue(root, 'CFBundleName') || this._getStringValue(root, 'CFBundleDisplayName');
    if (bundleName) findings.metadata.bundleName = bundleName;

    const bundleExec = this._getStringValue(root, 'CFBundleExecutable');
    if (bundleExec) findings.metadata.executable = bundleExec;

    const program = this._getStringValue(root, 'Program');
    if (program) findings.metadata.program = program;

    const progArgs = this._getValue(root, 'ProgramArguments');
    if (progArgs && progArgs._type === 'array') {
      findings.metadata.programArguments = progArgs._items.map(i => String(i._value || '')).join(' ');
    }

    // ── Collect all strings for scanning ─────────────────────────────────
    const allStrings = [];
    this._collectStrings(root, allStrings);
    const allText = allStrings.join('\n');

    // ── Pattern scanning ─────────────────────────────────────────────────
    const matchedLabels = new Set();
    let criticalCount = 0, highCount = 0, mediumCount = 0;

    for (const p of PlistRenderer.SUSPICIOUS_PATTERNS) {
      const re = new RegExp(p.re.source, p.re.flags);
      const matches = [];
      let m;
      while ((m = re.exec(allText)) !== null) {
        matches.push(m[0]);
        if (matches.length >= 20) break;
      }
      if (matches.length > 0 && !matchedLabels.has(p.label)) {
        matchedLabels.add(p.label);
        findings.signatureMatches.push({
          label: p.label,
          description: p.desc,
          mitre: p.mitre,
          severity: p.sev,
          count: matches.length,
          sample: matches[0].substring(0, 120),
          highlight: matches[0],
        });
        if (p.sev === 'critical') criticalCount++;
        else if (p.sev === 'high') highCount++;
        else mediumCount++;
      }
    }

    // ── Persistence-specific checks ──────────────────────────────────────
    const isLaunch = classification.type === 'launchagent' || classification.type === 'launchdaemon';

    if (isLaunch) {
      // Hidden label
      if (label && label.startsWith('.') && !matchedLabels.has('Hidden LaunchAgent Label')) {
        findings.signatureMatches.push({
          label: 'Hidden LaunchAgent Label',
          description: 'Dot-prefixed Label "' + label + '" hides from casual directory listings (ls without -a)',
          mitre: 'T1564.001',
          severity: 'high',
          count: 1,
          sample: label,
          highlight: label,
        });
        highCount++;
      }

      // RunAtLoad + dangerous combo
      const runAtLoad = this._getValue(root, 'RunAtLoad');
      if (runAtLoad && runAtLoad._value === true) {
        const execTarget = program || (findings.metadata.programArguments || '');
        if (/\/bin\/(?:ba)?sh\b/.test(execTarget)) {
          if (!matchedLabels.has('RunAtLoad Shell Execution')) {
            findings.signatureMatches.push({
              label: 'RunAtLoad Shell Execution',
              description: 'RunAtLoad: true with shell interpreter — executes shell commands on every login/boot',
              mitre: 'T1543.004',
              severity: 'critical',
              count: 1,
              sample: execTarget.substring(0, 120),
              highlight: 'RunAtLoad',
            });
            criticalCount++;
          }
        }
      }

      // KeepAlive persistence
      const keepAlive = this._getValue(root, 'KeepAlive');
      if (keepAlive && (keepAlive._value === true || keepAlive._type === 'dict') && runAtLoad && runAtLoad._value === true) {
        findings.signatureMatches.push({
          label: 'Aggressive Persistence',
          description: 'KeepAlive + RunAtLoad combination — process restarts automatically if terminated',
          mitre: 'T1543.004',
          severity: 'high',
          count: 1,
          sample: 'KeepAlive=true, RunAtLoad=true',
          highlight: 'KeepAlive',
        });
        highCount++;
      }

      // Short StartInterval
      const interval = this._getValue(root, 'StartInterval');
      if (interval && interval._type === 'integer' && interval._value < 300) {
        findings.signatureMatches.push({
          label: 'Short Execution Interval',
          description: 'StartInterval of ' + interval._value + ' seconds — may indicate C2 beacon or polling behaviour',
          mitre: 'T1573',
          severity: 'medium',
          count: 1,
          sample: 'StartInterval=' + interval._value,
          highlight: 'StartInterval',
        });
        mediumCount++;
      }
    }

    // ── DYLD injection check ─────────────────────────────────────────────
    const envVars = this._getValue(root, 'EnvironmentVariables');
    if (envVars && envVars._type === 'dict') {
      for (const e of envVars._entries) {
        if (e.key === 'DYLD_INSERT_LIBRARIES') {
          findings.signatureMatches.push({
            label: 'DYLD_INSERT_LIBRARIES Injection',
            description: 'Injects a dynamic library into all child processes — classic macOS code injection technique',
            mitre: 'T1574.006',
            severity: 'critical',
            count: 1,
            sample: e.key + '=' + (e.value._value || '').substring(0, 100),
            highlight: 'DYLD_INSERT_LIBRARIES',
          });
          criticalCount++;
        }
      }
    }

    // ── TCC / accessibility keys ─────────────────────────────────────────
    const allKeys = new Set();
    this._collectKeys(root, allKeys);
    for (const k of allKeys) {
      if (PlistRenderer.TCC_KEYS.has(k) && !matchedLabels.has('TCC: ' + k)) {
        matchedLabels.add('TCC: ' + k);
        findings.signatureMatches.push({
          label: 'TCC/Privacy Key: ' + k,
          description: 'References macOS Transparency, Consent, and Control (TCC) framework — may request or manipulate privacy permissions',
          mitre: 'T1548',
          severity: 'medium',
          count: 1,
          sample: k,
          highlight: k,
        });
        mediumCount++;
      }
    }

    // ── URL scheme detection ─────────────────────────────────────────────
    const urlTypes = this._getValue(root, 'CFBundleURLTypes');
    if (urlTypes && urlTypes._type === 'array') {
      for (const item of urlTypes._items) {
        if (item._type === 'dict') {
          const schemes = this._getValue(item, 'CFBundleURLSchemes');
          if (schemes && schemes._type === 'array') {
            const schemeNames = schemes._items.map(s => s._value || '').filter(Boolean);
            if (schemeNames.length) {
              findings.signatureMatches.push({
                label: 'URL Scheme Registration',
                description: 'Registers custom URL scheme handler(s): ' + schemeNames.join(', '),
                mitre: 'T1071',
                severity: 'low',
                count: schemeNames.length,
                sample: schemeNames.join(', '),
                highlight: schemeNames[0],
              });
            }
          }
        }
      }
    }

    // ── Extract IOCs ─────────────────────────────────────────────────────
    // allText is a concatenation of all string leaves, so regex-index offsets
    // here are offsets into that synthesised string — NOT into the displayed
    // XML source. That's intentional: click-to-focus navigation uses
    // _highlightText (the raw matched text) to find a row in the plaintext
    // table rather than relying on a byte offset.
    let truncatedEmitted = false;
    const emitTruncation = (reason) => {
      if (truncatedEmitted) return;
      truncatedEmitted = true;
      pushIOC(findings, {
        type: IOC.INFO,
        value: `IOC extraction truncated — ${reason}. Additional indicators may be present in the plist.`,
        severity: 'info',
        bucket: 'externalRefs',
      });
    };

    // URLs — pushIOC will auto-emit IOC.DOMAIN / IOC.IP siblings via tldts
    // when the host resolves to a registrable domain or raw IP literal.
    const urlRe = /https?:\/\/[^\s"'<>\])}]{6,200}/gi;
    const seenUrls = new Set();
    let um;
    while ((um = urlRe.exec(allText)) !== null) {
      if (!seenUrls.has(um[0])) {
        seenUrls.add(um[0]);
        pushIOC(findings, {
          type: IOC.URL, value: um[0], severity: 'medium',
          highlightText: um[0],
          bucket: 'externalRefs',
        });
      }
      if (findings.externalRefs.length >= 100) { emitTruncation('URL cap (100) reached'); break; }
    }

    // IPs
    const ipRe = /\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b/g;
    const seenIPs = new Set();
    while ((um = ipRe.exec(allText)) !== null) {
      // Too few digits → likely version string (e.g. 6.0.0.0), not a real IP
      if (um[0].split(':')[0].replace(/\D/g, '').length < 5) continue;
      if (!seenIPs.has(um[0])) {
        seenIPs.add(um[0]);
        pushIOC(findings, {
          type: IOC.IP, value: um[0], severity: 'medium',
          highlightText: um[0],
          bucket: 'externalRefs',
        });
      }
      if (findings.externalRefs.length >= 150) { emitTruncation('IP cap reached'); break; }
    }

    // File paths
    const pathRe = /(?:\/(?:Users|tmp|var|etc|Library|Applications|System|bin|usr|opt|private)\/[^\s"'<>]{4,200})/g;
    const seenPaths = new Set();
    while ((um = pathRe.exec(allText)) !== null) {
      if (!seenPaths.has(um[0])) {
        seenPaths.add(um[0]);
        pushIOC(findings, {
          type: IOC.FILE_PATH, value: um[0], severity: 'info',
          highlightText: um[0],
          bucket: 'externalRefs',
        });
      }
      if (findings.externalRefs.length >= 200) { emitTruncation('file-path cap reached'); break; }
    }

    // Bare domains — emit as HOSTNAME (no scheme, not a full URL).
    const domRe = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|xyz|info|biz|ru|cn|tk|top|cc|pw)\b/gi;
    const seenDomains = new Set();
    while ((um = domRe.exec(allText)) !== null) {
      const d = um[0].toLowerCase();
      if (!seenDomains.has(d)) {
        seenDomains.add(d);
        pushIOC(findings, {
          type: IOC.HOSTNAME, value: d, severity: 'info',
          highlightText: um[0],
          bucket: 'externalRefs',
        });
      }
      if (findings.externalRefs.length >= 250) { emitTruncation('hostname cap reached'); break; }
    }

    // Mirror signatureMatches into externalRefs as IOC.PATTERN so the
    // Summary sidebar and Share view see every detection the viewer
    // surfaces (Detection → IOC parity).
    //
    // Each detection carries a `highlight` string naming the concrete XML
    // token that triggered it (e.g. a matched regex hit, or a key name like
    // "RunAtLoad" / "StartInterval" / "DYLD_INSERT_LIBRARIES"). Threading it
    // through as `highlightText` lets `_navigateToFinding` locate the line
    // in the XML Source pane and flash it — without this, clicking a Pattern
    // row in the sidebar silently no-ops because the mirrored "Label —
    // description" string never literally appears in the rendered source.
    for (const sm of findings.signatureMatches) {
      pushIOC(findings, {
        type: IOC.PATTERN,
        value: `${sm.label} — ${sm.description}`,
        severity: sm.severity || 'medium',
        highlightText: sm.highlight || undefined,
        bucket: 'externalRefs',
      });
    }

    // ── Risk assessment ──────────────────────────────────────────────────
    if (criticalCount >= 1) escalateRisk(findings, 'critical');
    else if (highCount >= 2 || (highCount >= 1 && mediumCount >= 2)) escalateRisk(findings, 'high');
    else if (highCount >= 1 || mediumCount >= 3) escalateRisk(findings, 'medium');
    else if (mediumCount >= 1 || findings.signatureMatches.length > 0) escalateRisk(findings, 'low');

    // Boost risk for LaunchDaemon (runs as root)
    if (classification.type === 'launchdaemon' && findings.risk === 'medium') {
      escalateRisk(findings, 'high');
    }

    // ── Augmented buffer for YARA scanning ───────────────────────────────
    // For XML plists, YARA must scan the *same* bytes that are shown in the
    // "XML Source" viewer (and stored on wrap._rawText). If we scanned a
    // synthesised string-dump instead, the byte offsets YARA reports would
    // not correspond to positions in the XML, and clicking a finding would
    // highlight the wrong line. For binary plists there is no displayed
    // source, so scanning the string-dump of the parsed tree is fine.
    let augBytes;
    if (format.type === 'xml') {
      const encoding = format.encoding || 'utf-8';
      const xml = new TextDecoder(encoding, { fatal: false }).decode(bytes);
      augBytes = new TextEncoder().encode(xml);
    } else {
      let augmented = allText;
      if (findings.externalRefs.length > 0) {
        augmented += '\n=== EXTRACTED PLIST IOCS ===\n';
        for (const ref of findings.externalRefs) {
          augmented += ref.url + '\n';
        }
      }
      augBytes = new TextEncoder().encode(augmented);
    }
    findings.augmentedBuffer = augBytes.buffer;

    return findings;
  }
}
