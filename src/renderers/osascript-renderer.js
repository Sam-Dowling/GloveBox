/* osascript-renderer.js — macOS AppleScript / JXA security analyser
 *
 * Supports:
 *   .scpt       — Compiled AppleScript (FasTX binary, source + string extraction)
 *   .applescript — AppleScript plain-text source
 *   .jxa        — JavaScript for Automation source
 *   .scptd      — Script bundle (directory — flagged as unsupported single-file)
 */

class OsascriptRenderer {

    /* ── Suspicious AppleScript / osascript patterns ────────────────── */

    static APPLESCRIPT_SUSPICIOUS = [
        { re: /do\s+shell\s+script/gi,                          label: 'Shell Execution',              desc: 'Executes arbitrary shell commands via osascript', mitre: 'T1059.002', sev: 'high' },
        { re: /display\s+dialog[\s\S]{0,120}?default\s+answer/gi, label: 'Credential Dialog',          desc: 'Prompts user for text input — credential harvesting vector', mitre: 'T1056.002', sev: 'high' },
        { re: /with\s+hidden\s+answer/gi,                       label: 'Hidden Password Prompt',       desc: 'Password-masked input field in dialog', mitre: 'T1056.002', sev: 'critical' },
        { re: /with\s+administrator\s+privileges/gi,            label: 'Admin Privilege Escalation',   desc: 'Requests admin authentication for shell command', mitre: 'T1548.004', sev: 'high' },
        { re: /system\s+events/gi,                              label: 'System Events Access',         desc: 'UI scripting / keystroke injection via System Events', mitre: 'T1059.002', sev: 'medium' },
        { re: /keystroke\s/gi,                                   label: 'Keystroke Injection',          desc: 'Simulates keyboard input via System Events', mitre: 'T1056.001', sev: 'high' },
        { re: /key\s+code\s/gi,                                  label: 'Key Code Injection',           desc: 'Simulates key presses by virtual key code', mitre: 'T1056.001', sev: 'high' },
        { re: /security\s+(find-generic-password|find-internet-password|delete-keychain|dump-keychain|add-generic-password)/gi, label: 'Keychain Access', desc: 'Interacts with macOS Keychain via security CLI', mitre: 'T1555.001', sev: 'critical' },
        { re: /security\s+authorizationdb/gi,                   label: 'Authorization DB Modification', desc: 'Modifies macOS authorization database', mitre: 'T1548', sev: 'critical' },
        { re: /login\s+item/gi,                                  label: 'Login Item Persistence',       desc: 'Adds or manages login items for persistence', mitre: 'T1547.015', sev: 'high' },
        { re: /LaunchAgent|LaunchDaemon/gi,                      label: 'LaunchAgent/Daemon Persistence', desc: 'References LaunchAgent/Daemon plist persistence', mitre: 'T1543.001', sev: 'high' },
        { re: /Cookies\.binarycookies|Login\s*Data|cookies\.sqlite|Keychain\.db/gi, label: 'Browser Credential Theft', desc: 'Targets browser cookie or credential stores', mitre: 'T1539', sev: 'critical' },
        { re: /(Safari|Google\s*Chrome|Firefox|Brave\s*Browser|Microsoft\s*Edge)[\s\S]{0,40}?(cookie|password|history|login)/gi, label: 'Browser Data Access', desc: 'References browser application data files', mitre: 'T1539', sev: 'high' },
        { re: /the\s+clipboard|set\s+the\s+clipboard|clipboard\s+info/gi, label: 'Clipboard Access', desc: 'Reads or manipulates clipboard content', mitre: 'T1115', sev: 'medium' },
        { re: /curl\s+-|curl\s+"?https?:|wget\s/gi,             label: 'Network Download',             desc: 'Downloads content from a remote server', mitre: 'T1105', sev: 'medium' },
        { re: /run\s+script\s/gi,                                label: 'Dynamic Script Execution',     desc: 'Dynamically compiles and executes script text', mitre: 'T1059.002', sev: 'high' },
        { re: /open\s+location\s/gi,                             label: 'URL Open',                     desc: 'Opens URL in default browser — potential C2 or phishing', mitre: 'T1204.001', sev: 'medium' },
        { re: /screen\s+capture|screen\s+recording/gi,          label: 'Screen Capture',               desc: 'Captures screen content', mitre: 'T1113', sev: 'high' },
        { re: /do\s+JavaScript/gi,                               label: 'Browser JavaScript Injection', desc: 'Executes JavaScript inside a browser via AppleScript', mitre: 'T1059.007', sev: 'high' },
        { re: /osascript\s+-e/gi,                                label: 'Nested osascript Execution',   desc: 'Launches nested osascript process', mitre: 'T1059.002', sev: 'medium' },
        { re: /use\s+framework\s+"Foundation"/gi,                label: 'Foundation Framework Import',  desc: 'Imports Foundation framework — enables ObjC bridge in AppleScript', mitre: 'T1059.002', sev: 'medium' },
        { re: /current\s+application'?s\s+NSTask/gi,            label: 'NSTask Process Execution',     desc: 'Creates subprocess via NSTask from AppleScript-ObjC', mitre: 'T1059', sev: 'high' },
        { re: /ASCII\s+character\s+\d/gi,                        label: 'Character Code Obfuscation',   desc: 'Builds strings from ASCII codes — obfuscation technique', mitre: 'T1027', sev: 'medium' },
        { re: /folder\s+"?Startup\s+Items/gi,                   label: 'Startup Items Persistence',    desc: 'References legacy Startup Items folder', mitre: 'T1547', sev: 'high' },
        { re: /crontab/gi,                                       label: 'Cron Persistence',             desc: 'Installs cron job for scheduled persistence', mitre: 'T1053.003', sev: 'high' },
        { re: /defaults\s+write/gi,                              label: 'Defaults Write',               desc: 'Modifies macOS user/system defaults — may alter security settings', mitre: 'T1562', sev: 'medium' },
    ];

    /* ── JXA-specific Objective-C bridge patterns ──────────────────── */

    static JXA_SUSPICIOUS = [
        { re: /ObjC\.import\s*\(/g,                             label: 'ObjC Bridge Import',           desc: 'Imports Objective-C framework via JXA bridge', mitre: 'T1059.007', sev: 'medium' },
        { re: /\$\.NSTask/g,                                     label: 'NSTask Process Execution',     desc: 'Creates subprocess via NSTask ObjC bridge', mitre: 'T1059', sev: 'high' },
        { re: /\$\.NSAppleScript/g,                              label: 'Nested AppleScript Execution', desc: 'Executes AppleScript from within JXA', mitre: 'T1059.002', sev: 'high' },
        { re: /\$\.NSPipe/g,                                     label: 'NSPipe IPC',                   desc: 'Inter-process communication via pipe', mitre: 'T1559', sev: 'medium' },
        { re: /\$\.NSFileManager/g,                              label: 'File System Access',           desc: 'File operations via ObjC FileManager bridge', mitre: 'T1083', sev: 'medium' },
        { re: /\$\.NSURL(?:Session|Connection|Request|Download)?/g, label: 'Network Operations',       desc: 'URL/network operations via ObjC bridge', mitre: 'T1071', sev: 'high' },
        { re: /\$\.NSData/g,                                     label: 'NSData Binary Operations',     desc: 'Binary data manipulation via ObjC bridge', mitre: 'T1027', sev: 'medium' },
        { re: /\$\.NSString/g,                                   label: 'NSString Operations',          desc: 'String manipulation via ObjC bridge', mitre: 'T1027', sev: 'low' },
        { re: /\$\.NSProcessInfo/g,                              label: 'Process Info Access',          desc: 'Accesses process/environment info', mitre: 'T1082', sev: 'medium' },
        { re: /\$\.NSWorkspace/g,                                label: 'Workspace Access',             desc: 'Opens files/apps, queries running apps', mitre: 'T1057', sev: 'medium' },
        { re: /\$\.NSUserDefaults/g,                             label: 'User Defaults Access',         desc: 'Reads/writes macOS user defaults', mitre: 'T1562', sev: 'medium' },
        { re: /\$\.NSHost/g,                                     label: 'Host Info Gathering',          desc: 'Gathers hostname/network info', mitre: 'T1082', sev: 'medium' },
        { re: /\$\.NSScreen/g,                                   label: 'Screen Info Access',           desc: 'Accesses screen/display information', mitre: 'T1082', sev: 'low' },
        { re: /eval\s*\(|Function\s*\(/g,                       label: 'Dynamic Code Execution',       desc: 'eval() or Function() dynamic execution in JXA', mitre: 'T1059.007', sev: 'high' },
        { re: /atob\s*\(/g,                                      label: 'Base64 Decode',                desc: 'Decodes Base64 string — potential obfuscation', mitre: 'T1140', sev: 'medium' },
    ];

    /* ── Helpers ────────────────────────────────────────────────────── */

    static _esc(s) { return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }

    static _fmtBytes(n) {
        if (n < 1024) return n + ' B';
        if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
        return (n / 1048576).toFixed(1) + ' MB';
    }

    /* ── Compiled AppleScript (.scpt) parsing ──────────────────────── */

    /**
     * Detect compiled AppleScript by FasTX magic.
     * FasTX = 0x46 0x61 0x73 0x54 (first 4 bytes)
     */
    static isCompiledAppleScript(bytes) {
        if (!bytes || bytes.length < 16) return false;
        return bytes[0] === 0x46 && bytes[1] === 0x61 &&
               bytes[2] === 0x73 && bytes[3] === 0x54;
    }

    /**
     * Extract embedded source text and readable strings from compiled .scpt.
     * Compiled AppleScript files often retain the original source text in a
     * resource section. We scan for long runs of printable ASCII/UTF-8.
     */
    _parseCompiledScpt(bytes) {
        const result = { hasSource: false, source: '', strings: [], format: 'Compiled AppleScript' };

        /* Check magic */
        if (!OsascriptRenderer.isCompiledAppleScript(bytes)) {
            result.format = 'Unknown binary (not FasTX)';
            return result;
        }

    /* Scan for long readable ASCII/UTF-8 runs (≥ 8 chars).
     * Include \t (0x09), \n (0x0A), \r (0x0D) so multi-line source
     * blocks are captured intact instead of being split per-line. */
    const strings = [];
    let run = [];
    const MIN_LEN = 8;
    for (let i = 0; i < bytes.length; i++) {
      const b = bytes[i];
      if ((b >= 0x20 && b < 0x7F) || b === 0x09 || b === 0x0A || b === 0x0D) {
        run.push(b);
      } else {
        if (run.length >= MIN_LEN) {
          const s = String.fromCharCode(...run);
          strings.push({ offset: i - run.length, text: s });
        }
        run = [];
      }
    }
    if (run.length >= MIN_LEN) {
      strings.push({ offset: bytes.length - run.length, text: String.fromCharCode(...run) });
    }

        /* Try to identify the embedded source block:
         * The source section is typically a large contiguous text region.
         * Heuristic: the longest string run that contains AppleScript keywords. */
        const asKeywords = /\b(tell|end\s+tell|on\s+run|set\s+|do\s+shell|display\s+dialog|return|if\s+|end\s+if|repeat|end\s+repeat|try|end\s+try|using\s+terms\s+from)\b/i;
        let bestSource = '';
        for (const s of strings) {
            if (s.text.length > bestSource.length && asKeywords.test(s.text)) {
                bestSource = s.text;
            }
        }
        if (bestSource.length > 30) {
            result.hasSource = true;
            result.source = bestSource;
        }

        /* Filter strings: remove duplicates and very short/boring ones.
         * Compare against a trimmed copy of bestSource so that the source
         * block — which frequently has trailing whitespace/padding in the
         * raw printable-run — is not re-emitted as a separate "string"
         * entry. If we compared against the untrimmed bestSource the trim
         * on `t` would make them unequal and the whole source block (URLs
         * and all) would be duplicated in result.strings, leading to
         * triplicate IOC rows once analyzeForSecurity concatenates
         * result.source with result.strings. */
        const bestTrim = bestSource.trim();
        const seen = new Set();
        for (const s of strings) {
            const t = s.text.trim();
            if (t.length >= MIN_LEN && !seen.has(t) && t !== bestTrim) {
                seen.add(t);
                result.strings.push(t);
            }
        }

        return result;
    }

    /* ── Detect script type from filename ──────────────────────────── */

    _scriptType(fileName) {
        const ext = (fileName || '').split('.').pop().toLowerCase();
        if (ext === 'scpt') return 'scpt';
        if (ext === 'scptd') return 'scptd';
        if (ext === 'jxa') return 'jxa';
        return 'applescript'; /* .applescript or fallback */
    }

    /* ── Decode buffer to text (UTF-8 / UTF-16 with BOM) ──────────── */

    _decode(bytes) {
        if (bytes.length >= 3 && bytes[0] === 0xEF && bytes[1] === 0xBB && bytes[2] === 0xBF) {
            return new TextDecoder('utf-8').decode(bytes.subarray(3));
        }
        if (bytes.length >= 2 && bytes[0] === 0xFF && bytes[1] === 0xFE) {
            return new TextDecoder('utf-16le').decode(bytes.subarray(2));
        }
        if (bytes.length >= 2 && bytes[0] === 0xFE && bytes[1] === 0xFF) {
            return new TextDecoder('utf-16be').decode(bytes.subarray(2));
        }
        return new TextDecoder('utf-8').decode(bytes);
    }

    /* ── Format label for UI ───────────────────────────────────────── */

    _formatLabel(type) {
        switch (type) {
            case 'scpt':        return 'Compiled AppleScript (.scpt)';
            case 'scptd':       return 'AppleScript Bundle (.scptd)';
            case 'jxa':         return 'JavaScript for Automation (.jxa)';
            case 'applescript': return 'AppleScript Source (.applescript)';
            default:            return 'macOS Script';
        }
    }

    /* ── Syntax-highlight source code ──────────────────────────────── */

    /**
     * AppleScript keyword set — control flow, scoping, handlers, reference
     * forms. Every entry is a single whitespace-delimited word; multi-word
     * phrases (e.g. "using terms from") are matched separately in
     * APPLESCRIPT_MULTIWORD_KEYWORDS so the tokenizer can swallow them in
     * one pass instead of painting each word with its own span.
     */
    static APPLESCRIPT_KEYWORDS = new Set([
        'tell','end','on','to','of','in','is','as','if','then','else',
        'repeat','while','until','from','by','with','without','set','get',
        'copy','return','exit','continue','try','error','script','property',
        'prop','global','local','my','me','its','it','the','and','or','not',
        'equals','reference','given','into','through','thru','before','after',
        'where','whose','every','each','first','second','third','fourth',
        'fifth','sixth','seventh','eighth','ninth','tenth','last','some',
        'any','considering','ignoring','contains','starts','ends','contain',
        'equal','greater','less','than','does','doesn','aside','application',
        'beginning','middle','front','back','this','that','these','those',
        'entire','contents','item','items','folder','folders','file','files',
        'window','windows','process','processes','document','documents',
        'paragraph','paragraphs','word','words','character','characters',
        'true','false','null'
    ]);

    /**
     * Multi-word keyword phrases. Matched case-insensitively before the
     * single-word keyword pass so the whole phrase becomes one hljs-keyword
     * span. Order longest-first so "a reference to" wins over "reference".
     */
    static APPLESCRIPT_MULTIWORD_KEYWORDS = [
        'using terms from','a reference to','end using terms from',
        'end considering','end ignoring','end repeat','end tell','end try',
        'end if','else if','exit repeat','on error'
    ];

    /** Literal values — coloured like numbers/booleans in most hljs themes. */
    static APPLESCRIPT_LITERALS = new Set([
        'true','false','missing','null','yes','no'
    ]);

    /**
     * Multi-word literal phrases (e.g. "missing value").
     */
    static APPLESCRIPT_MULTIWORD_LITERALS = [
        'missing value'
    ];

    /**
     * Built-in / security-interesting phrases. The list deliberately overlaps
     * the suspicious-pattern catalogue at the top of this file so the things
     * analyzeForSecurity() flags are also the things an analyst's eye is
     * drawn to when reading the source.
     */
    static APPLESCRIPT_MULTIWORD_BUILTINS = [
        'do shell script','display dialog','display notification','display alert',
        'default answer','with hidden answer','with administrator privileges',
        'system events','current application','do JavaScript','open location',
        'run script','mount volume','choose file','choose folder','choose from list',
        'path to','info for','POSIX path','POSIX file','quoted form of',
        'ASCII character','ASCII number','use framework','use scripting additions',
        'launch agent','launch daemon','login item','system info',
        'current date','time to GMT','offset of','count of','length of',
        'text item delimiters','read file','write file','close access'
    ];

    static APPLESCRIPT_BUILTINS = new Set([
        'keystroke','clipboard','osascript','curl','wget','defaults',
        'crontab','security','screen','volume','application','applications',
        'shell','script','dialog','notification','alert','keychain'
    ]);

    /**
     * Tokenise AppleScript source and emit HTML with hljs-* class names so
     * the existing viewers.css palette (light + dark + all themes) colours
     * it correctly. The vendored highlight.min.js ships without an
     * AppleScript grammar, so we do this ourselves — cheap, deterministic,
     * no network fetch, and the class names match every other renderer.
     */
    static _highlightAppleScript(source) {
        const esc = OsascriptRenderer._esc;
        const KW = OsascriptRenderer.APPLESCRIPT_KEYWORDS;
        const LIT = OsascriptRenderer.APPLESCRIPT_LITERALS;
        const BI = OsascriptRenderer.APPLESCRIPT_BUILTINS;
        /* Pre-compile multi-word phrase matchers, longest-first so e.g.
         * "end using terms from" wins over "using terms from" wins over
         * "end". Each entry: [lowercased phrase, regex, cssClass]. */
        const phrases = [];
        const addPhrases = (list, cls) => {
            for (const p of list) {
                /* \b boundaries + runs of whitespace tolerated between words */
                const pattern = p.trim().split(/\s+/).map(w =>
                    w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
                ).join('\\s+');
                phrases.push({
                    re: new RegExp('\\b' + pattern + '\\b', 'i'),
                    cls,
                    len: p.length,
                });
            }
        };
        addPhrases(OsascriptRenderer.APPLESCRIPT_MULTIWORD_BUILTINS, 'hljs-built_in');
        addPhrases(OsascriptRenderer.APPLESCRIPT_MULTIWORD_KEYWORDS, 'hljs-keyword');
        addPhrases(OsascriptRenderer.APPLESCRIPT_MULTIWORD_LITERALS, 'hljs-literal');
        phrases.sort((a, b) => b.len - a.len);

        let out = '';
        let i = 0;
        const n = source.length;

        while (i < n) {
            const ch = source[i];
            const cc = source.charCodeAt(i);

            /* Block comment: (* ... *) — may nest in AppleScript but we treat
             * as non-nesting (matches hljs behaviour). */
            if (ch === '(' && source[i + 1] === '*') {
                const end = source.indexOf('*)', i + 2);
                const stop = end === -1 ? n : end + 2;
                out += `<span class="hljs-comment">${esc(source.slice(i, stop))}</span>`;
                i = stop;
                continue;
            }

            /* Line comment: -- ... or # ... */
            if ((ch === '-' && source[i + 1] === '-') || ch === '#') {
                let j = i;
                while (j < n && source[j] !== '\n') j++;
                out += `<span class="hljs-comment">${esc(source.slice(i, j))}</span>`;
                i = j;
                continue;
            }

            /* String literal: "..." with \" escapes */
            if (ch === '"') {
                let j = i + 1;
                while (j < n) {
                    if (source[j] === '\\' && j + 1 < n) { j += 2; continue; }
                    if (source[j] === '"') { j++; break; }
                    j++;
                }
                out += `<span class="hljs-string">${esc(source.slice(i, j))}</span>`;
                i = j;
                continue;
            }

            /* Number: integer, decimal, or 0xHEX */
            if ((cc >= 48 && cc <= 57) ||
                (ch === '.' && source.charCodeAt(i + 1) >= 48 && source.charCodeAt(i + 1) <= 57)) {
                let j = i;
                if (source[j] === '0' && (source[j + 1] === 'x' || source[j + 1] === 'X')) {
                    j += 2;
                    while (j < n && /[0-9a-fA-F]/.test(source[j])) j++;
                } else {
                    while (j < n && /[0-9]/.test(source[j])) j++;
                    if (source[j] === '.' && /[0-9]/.test(source[j + 1] || '')) {
                        j++;
                        while (j < n && /[0-9]/.test(source[j])) j++;
                    }
                    if (source[j] === 'e' || source[j] === 'E') {
                        j++;
                        if (source[j] === '+' || source[j] === '-') j++;
                        while (j < n && /[0-9]/.test(source[j])) j++;
                    }
                }
                out += `<span class="hljs-number">${esc(source.slice(i, j))}</span>`;
                i = j;
                continue;
            }

            /* Identifier (letters / digits / underscore). AppleScript is
             * case-insensitive for keywords, so we lowercase for lookup. */
            if (/[A-Za-z_]/.test(ch)) {
                /* Try multi-word phrases first */
                let matched = null;
                for (const p of phrases) {
                    p.re.lastIndex = 0;
                    const m = p.re.exec(source.slice(i, i + p.len + 16));
                    if (m && m.index === 0) {
                        matched = { text: m[0], cls: p.cls };
                        break;
                    }
                }
                if (matched) {
                    out += `<span class="${matched.cls}">${esc(matched.text)}</span>`;
                    i += matched.text.length;
                    continue;
                }
                /* Single identifier */
                let j = i;
                while (j < n && /[A-Za-z0-9_]/.test(source[j])) j++;
                const word = source.slice(i, j);
                const lw = word.toLowerCase();
                let cls = null;
                if (LIT.has(lw)) cls = 'hljs-literal';
                else if (KW.has(lw)) cls = 'hljs-keyword';
                else if (BI.has(lw)) cls = 'hljs-built_in';
                if (cls) out += `<span class="${cls}">${esc(word)}</span>`;
                else out += esc(word);
                i = j;
                continue;
            }

            /* Anything else — escape and emit verbatim. */
            out += esc(ch);
            i++;
        }
        return out;
    }

    _highlight(source, lang) {
        /* AppleScript: vendored highlight.min.js has no grammar for it, so
         * use our in-house tokenizer. It emits hljs-* class names, so the
         * existing viewers.css palette applies across every theme. */
        if (lang === 'applescript') {
            try {
                return OsascriptRenderer._highlightAppleScript(source);
            } catch (_) { /* fall through to plain escaping */ }
        }
        /* JXA: JavaScript grammar ships with highlight.min.js. */
        if (typeof hljs !== 'undefined' && lang === 'javascript') {
            try {
                if (hljs.getLanguage('javascript')) {
                    return hljs.highlight(source, { language: 'javascript', ignoreIllegals: true }).value;
                }
            } catch (_) { /* fall through */ }
        }
        return OsascriptRenderer._esc(source);
    }

    /* ── Build line-numbered source view ───────────────────────────── */

    _buildSourceView(source, lang) {
        const lines = source.split('\n');
        const highlighted = this._highlight(source, lang);
        const hLines = highlighted.split('\n');
        let html = '<table class="osascript-source-table plaintext-table"><tbody>';
        for (let i = 0; i < lines.length; i++) {
            html += `<tr><td class="osascript-line-num">${i + 1}</td><td class="osascript-line-code plaintext-code">${hLines[i] || ''}</td></tr>`;
        }
        html += '</tbody></table>';
        return html;
    }

    /* ══════════════════════════════════════════════════════════════════
     *  render(buffer, fileName)
     * ══════════════════════════════════════════════════════════════════ */

    render(buffer, fileName) {
        const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer || buffer);
        const type = this._scriptType(fileName);
        const esc = OsascriptRenderer._esc;
        const wrap = document.createElement('div');
        wrap.className = 'osascript-viewer';

        /* ── .scptd bundle — unsupported ─────────────────────────── */
        if (type === 'scptd') {
            wrap.innerHTML = `
                <div class="osascript-banner osascript-banner-warn">
                    <span class="osascript-icon">⚠️</span>
                    <div class="osascript-banner-text">
                        <strong>${esc(fileName)}</strong> &mdash; AppleScript Bundle (.scptd)<br>
                        <span class="osascript-banner-sub">Script bundles are directory packages. Extract the bundle and open <code>main.scpt</code> individually for analysis.</span>
                    </div>
                </div>`;
            wrap._rawText = lfNormalize('');
            return wrap;
        }

        /* ── Compiled .scpt ──────────────────────────────────────── */
        if (type === 'scpt') {
            const parsed = this._parseCompiledScpt(bytes);
            let html = `
                <div class="osascript-banner">
                    <span class="osascript-icon">🍎</span>
                    <div class="osascript-banner-text">
                        <strong>${esc(fileName)}</strong> &mdash; ${esc(parsed.format)}<br>
                        <span class="osascript-banner-sub">${OsascriptRenderer._fmtBytes(bytes.length)} &bull; FasTX binary &bull; ${parsed.hasSource ? 'Embedded source recovered' : 'No embedded source found'}</span>
                    </div>
                </div>`;

            if (parsed.hasSource) {
                html += `<div class="osascript-section">
                    <div class="osascript-section-title">📝 Embedded Source</div>
                    <div class="osascript-source-wrap">${this._buildSourceView(parsed.source, 'applescript')}</div>
                </div>`;
            }

            if (parsed.strings.length > 0) {
                html += `<div class="osascript-section">
                    <div class="osascript-section-title">🔤 Extracted Strings (${parsed.strings.length})</div>
                    <div class="osascript-strings-wrap"><table class="osascript-strings-table">
                        <thead><tr><th>#</th><th>String</th></tr></thead><tbody>`;
                const limit = Math.min(parsed.strings.length, 500);
                for (let i = 0; i < limit; i++) {
                    html += `<tr><td class="osascript-str-idx">${i + 1}</td><td class="osascript-str-val">${esc(parsed.strings[i])}</td></tr>`;
                }
                if (parsed.strings.length > limit) {
                    html += `<tr><td colspan="2" class="osascript-str-trunc">… ${parsed.strings.length - limit} more strings truncated</td></tr>`;
                }
                html += '</tbody></table></div></div>';
            }

            wrap.innerHTML = html;
            wrap._rawText = lfNormalize(parsed.hasSource ? parsed.source : parsed.strings.join('\n'));
            return wrap;
        }

        /* ── Text-based: .applescript / .jxa ─────────────────────── */
        const source = this._decode(bytes);
        const lang = type === 'jxa' ? 'javascript' : 'applescript';
        const langLabel = type === 'jxa' ? 'JavaScript for Automation (JXA)' : 'AppleScript';

        let html = `
            <div class="osascript-banner">
                <span class="osascript-icon">🍎</span>
                <div class="osascript-banner-text">
                    <strong>${esc(fileName)}</strong> &mdash; ${langLabel}<br>
                    <span class="osascript-banner-sub">${OsascriptRenderer._fmtBytes(bytes.length)} &bull; ${source.split('\n').length} lines</span>
                </div>
            </div>
            <div class="osascript-section">
                <div class="osascript-section-title">📝 Source Code</div>
                <div class="osascript-source-wrap">${this._buildSourceView(source, lang)}</div>
            </div>`;

        wrap.innerHTML = html;
        wrap._rawText = lfNormalize(source);
        return wrap;
    }

    /* ══════════════════════════════════════════════════════════════════
     *  analyzeForSecurity(buffer, fileName)
     * ══════════════════════════════════════════════════════════════════ */

    analyzeForSecurity(buffer, fileName) {
        const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer || buffer);
        const type = this._scriptType(fileName);

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
        };

        /* ── .scptd — minimal analysis ───────────────────────────── */
        if (type === 'scptd') {
            findings.metadata.format = 'AppleScript Bundle (.scptd)';
            findings.metadata.note = 'Directory bundle — extract main.scpt for full analysis';
            return findings;
        }

        /* ── Determine analysable text ───────────────────────────── */
        let analysisText = '';
        let parsedScpt = null;

        if (type === 'scpt') {
            parsedScpt = this._parseCompiledScpt(bytes);
            analysisText = parsedScpt.hasSource ? parsedScpt.source : '';
            /* Also include extracted strings for analysis */
            if (parsedScpt.strings.length > 0) {
                analysisText += '\n' + parsedScpt.strings.join('\n');
            }
            findings.metadata.format = parsedScpt.format;
            findings.metadata.hasEmbeddedSource = parsedScpt.hasSource;
            findings.metadata.extractedStringCount = parsedScpt.strings.length;
        } else {
            analysisText = this._decode(bytes);
            findings.metadata.format = type === 'jxa' ? 'JavaScript for Automation' : 'AppleScript';
            findings.metadata.lineCount = analysisText.split('\n').length;
        }

        findings.metadata.size = bytes.length;

        if (!analysisText.trim()) {
            return findings;
        }

        /* ── Scan AppleScript patterns ───────────────────────────── */
        const matchedLabels = new Set();
        let highCount = 0, criticalCount = 0, mediumCount = 0;

        for (const p of OsascriptRenderer.APPLESCRIPT_SUSPICIOUS) {
            const re = new RegExp(p.re.source, p.re.flags);
            const matches = [];
            let m;
            while ((m = re.exec(analysisText)) !== null) {
                matches.push(m[0]);
                if (matches.length >= 20) break; /* cap per pattern */
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
                    /* Raw first match — used by the IOC.PATTERN mirror below
                     * as _highlightText so clicking the sidebar row scrolls
                     * to the actual offending line in the Source viewer. */
                    _firstMatch: matches[0],
                });
                if (p.sev === 'critical') criticalCount++;
                else if (p.sev === 'high') highCount++;
                else mediumCount++;
            }
        }

        /* ── Scan JXA-specific patterns ──────────────────────────── */
        if (type === 'jxa') {
            for (const p of OsascriptRenderer.JXA_SUSPICIOUS) {
                const re = new RegExp(p.re.source, p.re.flags);
                const matches = [];
                let m;
                while ((m = re.exec(analysisText)) !== null) {
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
                        _firstMatch: matches[0],
                    });
                    if (p.sev === 'critical') criticalCount++;
                    else if (p.sev === 'high') highCount++;
                    else mediumCount++;
                }
            }
        }

        /* ── Auto-exec detection ─────────────────────────────────── */
        /* Each entry records {label, hit} — `hit` is the literal substring
         * that matched in analysisText, carried through to the IOC.PATTERN
         * mirror as _highlightText so sidebar clicks land on the source line. */
        const pushAutoExec = (re, label, haystack = analysisText) => {
            const m = haystack.match(re);
            if (m) findings.autoExec.push({ label, hit: m[0] });
        };
        pushAutoExec(/on\s+run/i, 'on run');
        pushAutoExec(/on\s+open/i, 'on open');
        pushAutoExec(/on\s+idle/i, 'on idle');
        pushAutoExec(/on\s+quit/i, 'on quit');
        pushAutoExec(/on\s+adding\s+folder\s+items/i, 'folder action trigger');
        pushAutoExec(/#![^\n]*/, 'shebang (executable script)', analysisText.substring(0, 80));


        /* ── Extract IOCs ────────────────────────────────────────── */
        /* URLs — dedup like IP/path extractors below so the same URL
         * appearing multiple times in analysisText (embedded source plus
         * FasTX string-table entry, for example) produces exactly one
         * IOC row instead of N. */
        let truncatedEmitted = false;
        const emitTruncation = (reason) => {
            if (truncatedEmitted) return;
            truncatedEmitted = true;
            pushIOC(findings, {
                type: IOC.INFO,
                value: `IOC extraction truncated — ${reason}. Additional indicators may be present in the source.`,
                severity: 'info',
                bucket: 'externalRefs',
            });
        };
        // URLs — pushIOC will auto-emit IOC.DOMAIN / IOC.IP siblings via tldts
        // when the host resolves to a registrable domain or raw IP literal,
        // restoring sidebar domain-pivot for every URL hit.
        const urlRe = /https?:\/\/[^\s"'<>\])}]{6,200}/gi;
        const seenUrls = new Set();
        let um;
        while ((um = urlRe.exec(analysisText)) !== null) {
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
        /* IPs */
        const ipRe = /\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b/g;
        const seenIPs = new Set();
        while ((um = ipRe.exec(analysisText)) !== null) {
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
        /* File paths */
        const pathRe = /(?:\/(?:Users|tmp|var|etc|Library|Applications|System)\/[^\s"'<>]{4,200})/g;
        const seenPaths = new Set();
        while ((um = pathRe.exec(analysisText)) !== null) {
            if (!seenPaths.has(um[0])) {
                seenPaths.add(um[0]);
                pushIOC(findings, {
                    type: IOC.FILE_PATH, value: um[0], severity: 'medium',
                    highlightText: um[0],
                    bucket: 'externalRefs',
                });
            }
            if (findings.externalRefs.length >= 200) { emitTruncation('file-path cap reached'); break; }
        }
        /* Bare domains — loose heuristic. Emit as HOSTNAME (no scheme). */
        const domRe = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|xyz|info|biz|ru|cn|tk|top|cc|pw)\b/gi;
        const seenDomains = new Set();
        while ((um = domRe.exec(analysisText)) !== null) {
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

        /* Mirror signatureMatches into externalRefs as IOC.PATTERN so the
         * Summary sidebar and Share view see every detection the viewer
         * surfaces (Detection → IOC parity).
         *
         * Thread `_firstMatch` through as `highlightText` so clicking the
         * Pattern row in the sidebar locates the concrete offending substring
         * in the Source viewer. Without it the mirrored "Label — description"
         * string never literally appears in the rendered source and the
         * click would silently no-op (see plist-renderer.js for the same
         * pattern with the same explanation). */
        for (const sm of findings.signatureMatches) {
            pushIOC(findings, {
                type: IOC.PATTERN,
                value: `${sm.label} — ${sm.description}`,
                severity: sm.severity || 'medium',
                highlightText: sm._firstMatch || undefined,
                bucket: 'externalRefs',
            });
        }

        /* Mirror auto-exec triggers. Each entry is {label, hit} — thread `hit`
         * through as highlightText so clicking the sidebar row scrolls the
         * Source viewer to the actual trigger token. */
        for (const ae of findings.autoExec) {
            pushIOC(findings, {
                type: IOC.PATTERN,
                value: `Auto-exec trigger: ${ae.label}`,
                severity: 'medium',
                highlightText: ae.hit,
                bucket: 'externalRefs',
            });
        }


        /* ── Obfuscation detection ───────────────────────────────── */
        const b64Chunks = analysisText.match(/[A-Za-z0-9+/=]{60,}/g);
        if (b64Chunks && b64Chunks.length > 0) {
            findings.signatureMatches.push({
                label: 'Base64-encoded Payload',
                description: `${b64Chunks.length} large Base64-encoded string(s) detected — potential obfuscation`,
                mitre: 'T1140',
                severity: 'medium',
                count: b64Chunks.length,
                sample: b64Chunks[0].substring(0, 80) + '…',
            });
            mediumCount++;
        }

        /* ── Risk assessment ─────────────────────────────────────── */
        if (criticalCount >= 1) escalateRisk(findings, 'critical');
        else if (highCount >= 2 || (highCount >= 1 && mediumCount >= 2)) escalateRisk(findings, 'high');
        else if (highCount >= 1 || mediumCount >= 3) escalateRisk(findings, 'medium');
        else if (mediumCount >= 1 || findings.signatureMatches.length > 0) escalateRisk(findings, 'low');

        /* ── Augmented buffer for YARA scanning ──────────────────── */
        let augmented = analysisText;
        if (findings.externalRefs.length > 0) {
            augmented += '\n=== EXTRACTED OSASCRIPT IOCS ===\n';
            for (const ref of findings.externalRefs) {
                augmented += ref.url + '\n';
            }
        }
        const augBytes = new TextEncoder().encode(augmented);
        findings.augmentedBuffer = augBytes.buffer;

        return findings;
    }
}
