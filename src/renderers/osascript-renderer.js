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
        { re: /\bcharacter\s+id\s+\d/gi,                         label: 'Unicode Codepoint Obfuscation',desc: 'Builds strings from Unicode codepoints via `character id` — obfuscation technique', mitre: 'T1027', sev: 'medium' },
        { re: /\bstring\s+id\s+\{\s*\d/gi,                       label: 'Codepoint Array Obfuscation',  desc: 'Builds strings from literal codepoint arrays via `string id {…}` — obfuscation technique rarely seen in benign AppleScript', mitre: 'T1027', sev: 'high' },
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
                    /* safeRegex: builtin */
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

        // INVARIANT — synchronous-only loop. The `APPLESCRIPT_SUSPICIOUS`
        // table is a shared static; we reset `p.re.lastIndex = 0` and iterate
        // the canonical instance instead of cloning via
        // `new RegExp(p.re.source, p.re.flags)` (saves ~10 KB allocation per
        // scan across the full pattern table). This is safe ONLY while the
        // loop body is fully synchronous — adding an `await` here would let
        // a second concurrent `analyzeForSecurity()` reset `lastIndex` mid-
        // iteration and corrupt our walk. If you ever make this async,
        // restore the per-scan clone for every `g`-flagged pattern.
        for (const p of OsascriptRenderer.APPLESCRIPT_SUSPICIOUS) {
            p.re.lastIndex = 0;
            const re = p.re;
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
        // Same synchronous-only invariant as the APPLESCRIPT_SUSPICIOUS
        // loop above — see that comment block before adding any `await`
        // inside this body.
        if (type === 'jxa') {
            for (const p of OsascriptRenderer.JXA_SUSPICIOUS) {
                p.re.lastIndex = 0;
                const re = p.re;
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
            // Version-string suppression — see `looksLikeIpVersionString`
            // (constants.js) for the threshold rationale. Port-bearing
            // matches bypass the filter via the colon-prefix check.
            const ipPart = um[0].split(':')[0];
            const hasPort = um[0].includes(':');
            if (!hasPort && looksLikeIpVersionString(ipPart)) continue;
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

        /* ── Char-code / property-binding reassembly → Detection Patterns
         *
         * Historical context: this pass used to append its output
         * (`-- Binding: _X -> "…"` / `-- Reassembled: do shell script
         * "…"` lines under a `=== DEOBFUSCATED APPLESCRIPT LAYERS ===`
         * sentinel) into `augmentedBuffer` so two YARA rules
         * (`osascript_property_reassembled_shell_sink`,
         * `osascript_property_char_code_dropper`) could match on the
         * synthetic cleartext. That approach broke click-to-scroll:
         * YARA-match offsets pointed into the synthetic suffix, which
         * doesn't exist in the Source viewer, so sidebar click was a
         * silent no-op. It also coupled YARA to Loupe's internal
         * decoder output shape.
         *
         * The two rules were deleted (`src/rules/osascript-threats.yar`).
         * Equivalent detections are emitted here as Detection
         * Patterns with `_firstMatch` / source-offset anchors pointing
         * at the REAL `property _X :` declaration or `do shell script`
         * sink in raw source — so click-to-scroll lands on the actual
         * offending line.
         *
         * The three remaining YARA rules
         * (`osascript_char_code_obfuscation`,
         * `osascript_char_code_admin_shell_reassembly`,
         * `osascript_randomised_property_names`) all match on raw
         * source bytes and continue to fire with correct offsets.
         */
        const bindingTable = OsascriptRenderer._reassembleBindingTable(analysisText);
        if (bindingTable.sinks.length > 0) {
            const first = bindingTable.sinks[0];
            const firstMatch = analysisText.substring(first.sourceOffset, first.sourceOffset + first.sourceLength);
            findings.signatureMatches.push({
                label: 'AppleScript Reassembled Shell Sink',
                description: `do shell script argument reassembled from property bindings — cleartext: "${first.resolved.length > 160 ? first.resolved.slice(0, 157) + '…' : first.resolved}"`,
                mitre: first.isAdmin ? 'T1548.004' : 'T1027.013',
                severity: 'critical',
                count: bindingTable.sinks.length,
                sample: first.resolved.substring(0, 120),
                _firstMatch: firstMatch,
                _sourceOffset: first.sourceOffset,
                _sourceLength: first.sourceLength,
            });
            criticalCount++;
        }
        if (bindingTable.bindings.length >= 3) {
            const first = bindingTable.bindings[0];
            const firstMatch = analysisText.substring(first.sourceOffset, first.sourceOffset + first.sourceLength);
            findings.signatureMatches.push({
                label: 'AppleScript Property Char-Code Dropper',
                description: `${bindingTable.bindings.length} property bindings reassembled from char-code chains — obfuscated dropper shape`,
                mitre: 'T1027.013',
                severity: 'high',
                count: bindingTable.bindings.length,
                sample: `${first.name} -> "${first.resolved.substring(0, 80)}"`,
                _firstMatch: firstMatch,
                _sourceOffset: first.sourceOffset,
                _sourceLength: first.sourceLength,
            });
            highCount++;
        }

        /* Mirror signatureMatches into externalRefs as IOC.PATTERN so the
         * Summary sidebar and Share view see every detection the viewer
         * surfaces (Detection → IOC parity). Runs LAST so every
         * signatureMatch pushed above this line — including the reassembled
         * char-code / binding-table detections — is surfaced in the sidebar.
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

        /* ── Risk assessment ─────────────────────────────────────── */
        if (criticalCount >= 1) escalateRisk(findings, 'critical');
        else if (highCount >= 2 || (highCount >= 1 && mediumCount >= 2)) escalateRisk(findings, 'high');
        else if (highCount >= 1 || mediumCount >= 3) escalateRisk(findings, 'medium');
        else if (mediumCount >= 1 || findings.signatureMatches.length > 0) escalateRisk(findings, 'low');

        /* ── Augmented buffer for YARA scanning ──────────────────────
         *
         * The augmented buffer is raw source + extracted-IOC appendix
         * ONLY. Do not inject synthesised reassembly output here —
         * YARA-match offsets must land inside bytes that exist in the
         * Source viewer so sidebar click-to-scroll works. Reassembled
         * cleartext is surfaced as Detection Patterns (above) with
         * `_sourceOffset` / `_sourceLength` anchors pointing at the
         * real declaration / sink expression in raw source.
         */
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

    /**
     * Synchronous, side-effect-free AppleScript char-code reassembly.
     * Walks every `&`-concatenated chain of codepoint-primitives and
     * emits the resolved cleartext strings. Mirrors the two branches
     * (AS1 `&` chain, AS2 standalone `string id {…}`) of
     * `src/decoders/applescript-obfuscation.js::_findAppleScriptObfuscationCandidates`
     * but WITHOUT the post-decode sensitive-keyword gate and WITHOUT
     * building candidate objects — we only care about the cleartext, so
     * we can feed it to YARA. The decoder still emits findings for the
     * Detections / Deobfuscated Layers sidebar.
     *
     * Cap: 512 emitted strings to bound the YARA-buffer growth on
     * pathological inputs. Returns an array of plain strings; empty
     * array when no chains are present.
     *
     * Static-method so the e2e test harness can exercise it directly
     * without constructing a renderer instance.
     */
    static _reassembleCharCodeChains(text) {
        if (!text || text.length < 12) return [];
        if (!/\b(?:ASCII\s+character|character\s+id|string\s+id\s*\{)/i.test(text)) return [];
        const MAX_CHAINS = 512;
        const MAX_RESOLVED_LEN = 8 * 1024;
        const MAX_STRID_CODES = 4096;
        const MAX_CHAIN_NODES = 2048;

        const out = [];
        const seen = new Set();
        const push = (s) => {
            if (!s || s.length < 3) return;
            if (s.length > MAX_RESOLVED_LEN) s = s.slice(0, MAX_RESOLVED_LEN);
            if (seen.has(s)) return;
            seen.add(s);
            out.push(s);
        };

        const safeCodepoint = (n) => Number.isFinite(n) && n >= 0 && n <= 0x10FFFF;
        const parseCodeList = (body) => {
            const parts = body.split(',');
            if (parts.length < 1 || parts.length > MAX_STRID_CODES) return null;
            const arr = [];
            for (const p of parts) {
                const t = p.trim();
                if (!/^\d{1,6}$/.test(t)) return null;
                const n = parseInt(t, 10);
                if (!safeCodepoint(n)) return null;
                arr.push(n);
            }
            return arr;
        };
        const dequote = (s) => {
            if (s.length < 2 || s[0] !== '"' || s[s.length - 1] !== '"') return null;
            const body = s.slice(1, -1);
            let r = '';
            for (let i = 0; i < body.length; i++) {
                const ch = body[i];
                if (ch !== '\\') { r += ch; continue; }
                if (i + 1 >= body.length) { r += '\\'; break; }
                const nx = body[i + 1];
                if (nx === 'n') { r += '\n'; i++; continue; }
                if (nx === 'r') { r += '\r'; i++; continue; }
                if (nx === 't') { r += '\t'; i++; continue; }
                r += nx; i++;
            }
            return r;
        };

        // AS1: &-concatenation chain.
        /* safeRegex: builtin */
        const chainRe = new RegExp(
            '(?:'
              + '\\(\\s*ASCII\\s+character\\s+\\d{1,6}\\s*\\)'
            + '|'
              + '\\(\\s*character\\s+id\\s+\\d{1,6}\\s*\\)'
            + '|'
              + '\\(?\\s*string\\s+id\\s*\\{[^}]{1,32768}\\}\\s*\\)?'
            + '|'
              + '"(?:[^"\\\\\\r\\n]|\\\\.){0,512}"'
            + ')'
            + '(?:\\s*&\\s*'
            + '(?:'
              + '\\(\\s*ASCII\\s+character\\s+\\d{1,6}\\s*\\)'
            + '|'
              + '\\(\\s*character\\s+id\\s+\\d{1,6}\\s*\\)'
            + '|'
              + '\\(?\\s*string\\s+id\\s*\\{[^}]{1,32768}\\}\\s*\\)?'
            + '|'
              + '"(?:[^"\\\\\\r\\n]|\\\\.){0,512}"'
            + ')'
            + '){1,' + MAX_CHAIN_NODES + '}',
            'gi'
        );
        let m;
        while ((m = chainRe.exec(text)) !== null) {
            if (out.length >= MAX_CHAINS) break;
            // Resolve the chain via the same operand walk the decoder uses.
            const raw = m[0];
            // Only emit when at least one codepoint primitive is present —
            // pure string-concat isn't an obfuscation layer worth writing
            // to the YARA buffer (would just duplicate what's already in
            // analysisText).
            if (!/\b(?:ASCII\s+character|character\s+id|string\s+id)\b/i.test(raw)) continue;
            // Inline operand walk (kept in-sync with
            // `_asResolveChain` in applescript-obfuscation.js).
            let i = 0;
            let resolved = '';
            let ok = true;
            while (i < raw.length && ok) {
                while (i < raw.length && (raw[i] === ' ' || raw[i] === '\t' || raw[i] === '\r' || raw[i] === '\n' || raw[i] === '&')) i++;
                if (i >= raw.length) break;
                const start = i;
                if (raw[i] === '"') {
                    i++;
                    while (i < raw.length) {
                        if (raw[i] === '\\' && i + 1 < raw.length) { i += 2; continue; }
                        if (raw[i] === '"') { i++; break; }
                        i++;
                    }
                    const s = dequote(raw.slice(start, i));
                    if (s === null) { ok = false; break; }
                    resolved += s;
                } else if (raw[i] === '(' || raw[i] === '{') {
                    const openers = { '(': ')', '{': '}' };
                    const stack = [openers[raw[i]]];
                    i++;
                    while (i < raw.length && stack.length > 0) {
                        const c = raw[i];
                        if (c === '"') {
                            i++;
                            while (i < raw.length) {
                                if (raw[i] === '\\' && i + 1 < raw.length) { i += 2; continue; }
                                if (raw[i] === '"') { i++; break; }
                                i++;
                            }
                            continue;
                        }
                        if (c === '(' || c === '{') stack.push(openers[c]);
                        else if (c === stack[stack.length - 1]) stack.pop();
                        i++;
                    }
                    if (stack.length !== 0) { ok = false; break; }
                    let body = raw.slice(start, i);
                    if (body[0] === '(' && body[body.length - 1] === ')') body = body.slice(1, -1).trim();
                    let mm;
                    if ((mm = /^ASCII\s+character\s+(\d{1,6})$/i.exec(body))) {
                        const n = parseInt(mm[1], 10);
                        if (!safeCodepoint(n)) { ok = false; break; }
                        try { resolved += String.fromCodePoint(n); } catch (_) { ok = false; break; }
                    } else if ((mm = /^character\s+id\s+(\d{1,6})$/i.exec(body))) {
                        const n = parseInt(mm[1], 10);
                        if (!safeCodepoint(n)) { ok = false; break; }
                        try { resolved += String.fromCodePoint(n); } catch (_) { ok = false; break; }
                    } else if ((mm = /^string\s+id\s*\{([^}]{1,32768})\}$/i.exec(body))) {
                        const codes = parseCodeList(mm[1]);
                        if (!codes) { ok = false; break; }
                        try { resolved += String.fromCodePoint(...codes); } catch (_) { ok = false; break; }
                    } else {
                        // Unknown primitive — skip this operand.
                    }
                } else if (/[a-zA-Z]/.test(raw[i])) {
                    const slice = raw.slice(i);
                    const stridMatch = /^string\s+id\s*\{([^}]{1,32768})\}/i.exec(slice);
                    if (stridMatch) {
                        const codes = parseCodeList(stridMatch[1]);
                        if (!codes) { ok = false; break; }
                        try { resolved += String.fromCodePoint(...codes); } catch (_) { ok = false; break; }
                        i += stridMatch[0].length;
                    } else {
                        ok = false; break;
                    }
                } else {
                    ok = false; break;
                }
                if (resolved.length > MAX_RESOLVED_LEN) break;
            }
            if (ok) push(resolved);
        }

        // AS2: standalone `string id {…}` — dedup against the chain hits
        // the Set already holds.
        /* safeRegex: builtin */
        const stridRe = /\bstring\s+id\s*\{([^}]{1,32768})\}/gi;
        while ((m = stridRe.exec(text)) !== null) {
            if (out.length >= MAX_CHAINS) break;
            const codes = parseCodeList(m[1]);
            if (!codes || codes.length < 3) continue;
            let resolved;
            try { resolved = String.fromCodePoint(...codes); }
            catch (_) { continue; }
            push(resolved);
        }

        return out;
    }

    /**
     * Produce a structured binding-resolution table for the
     * renderer's Detection-Pattern emission.
     *
     * Scans the file for `property <name> : <rhs>` / `set <name> to
     * <rhs>` / `global <name> : <rhs>` / `local <name> : <rhs>`
     * declarations, resolves their RHS expressions (including cross-
     * references via fixed-point iteration), and walks every
     * `do shell script <expr>` sink substituting resolved bindings.
     *
     * Returns `{ lines, bindings, sinks }`:
     *   • `lines`    — legacy text-view array (`-- Binding: …`,
     *     `-- Reassembled: …`) retained for unit-test shape coverage;
     *     no longer injected into `augmentedBuffer`.
     *   • `bindings` — `Array<{name, kind, resolved, sourceOffset,
     *     sourceLength}>` where offsets anchor at the `property _X :`
     *     / `set _X to` declaration in raw source. Used by
     *     `render()` to emit the `AppleScript Property Char-Code
     *     Dropper` signatureMatch with click-to-scroll.
     *   • `sinks`    — `Array<{resolved, isAdmin, sourceOffset,
     *     sourceLength}>` where offsets anchor at the `do shell
     *     script` keyword in raw source. Used to emit the
     *     `AppleScript Reassembled Shell Sink` signatureMatch.
     *
     * Historical note: this helper used to inject its output into
     * `findings.augmentedBuffer` so YARA rules could match on the
     * synthetic `-- Reassembled: …` / `-- Binding: …` markers. That
     * approach broke click-to-scroll (the markers don't exist in the
     * Source viewer) and coupled YARA to Loupe's decoder output. The
     * two rules (`osascript_property_reassembled_shell_sink` and
     * `osascript_property_char_code_dropper`) were deleted and
     * replaced with in-renderer signatureMatch emitters that anchor
     * to real source offsets.
     *
     * Mirrors the logic of
     * `EncodedContentDetector._findAppleScriptObfuscationCandidates`
     * but runs synchronously and without building findings — we only
     * need the resolved values + source anchors surfaced. The decoder
     * path covers per-binding sidebar emission.
     *
     * Caps mirror the decoder: 512 bindings, 8 KiB per resolved value,
     * 1 MiB aggregate, 8 resolution rounds, 64 shell sinks.
     */
    static _reassembleBindingTable(text) {
        if (!text || text.length < 16) return { lines: [], bindings: [], sinks: [] };
        if (!/\b(?:property\s+_|\bset\s+_|\bdo\s+shell\s+script\b)/i.test(text)) return { lines: [], bindings: [], sinks: [] };

        const MAX_BINDINGS = 512;
        const MAX_RESOLVED_LEN = 8 * 1024;
        const MAX_AGGREGATE = 1024 * 1024;
        const MAX_ROUNDS = 8;
        const MAX_SINKS = 64;
        const MAX_CHAIN_NODES = 2048;
        const MAX_STRID_CODES = 4096;

        const safeCp = (n) => Number.isFinite(n) && n >= 0 && n <= 0x10FFFF;
        const parseCodeList = (body) => {
            const parts = body.split(',');
            if (parts.length < 1 || parts.length > MAX_STRID_CODES) return null;
            const arr = [];
            for (const p of parts) {
                const t = p.trim();
                if (!/^\d{1,6}$/.test(t)) return null;
                const n = parseInt(t, 10);
                if (!safeCp(n)) return null;
                arr.push(n);
            }
            return arr;
        };
        const dequote = (s) => {
            if (typeof s !== 'string' || s.length < 2) return null;
            if (s[0] !== '"' || s[s.length - 1] !== '"') return null;
            const body = s.slice(1, -1);
            let r = '';
            for (let i = 0; i < body.length; i++) {
                const ch = body[i];
                if (ch !== '\\') { r += ch; continue; }
                if (i + 1 >= body.length) { r += '\\'; break; }
                const nx = body[i + 1];
                if (nx === 'n') { r += '\n'; i++; continue; }
                if (nx === 'r') { r += '\r'; i++; continue; }
                if (nx === 't') { r += '\t'; i++; continue; }
                r += nx; i++;
            }
            return r;
        };

        // Classify a `(…)` or `{…}` body as a primitive, or signal
        // that it needs recursive expression tokenisation.
        const classifyBody = (raw) => {
            if (typeof raw !== 'string' || raw.length < 2) return null;
            if (raw[0] === '{' && raw[raw.length - 1] === '}') {
                const codes = parseCodeList(raw.slice(1, -1));
                if (!codes) return null;
                try { return { kind: 'primitive', value: String.fromCodePoint(...codes) }; }
                catch (_) { return null; }
            }
            if (raw[0] !== '(' || raw[raw.length - 1] !== ')') return null;
            const inner = raw.slice(1, -1).trim();
            let mm;
            if ((mm = /^ASCII\s+character\s+(\d{1,6})$/i.exec(inner))) {
                const n = parseInt(mm[1], 10);
                if (!safeCp(n)) return null;
                try { return { kind: 'primitive', value: String.fromCodePoint(n) }; }
                catch (_) { return null; }
            }
            if ((mm = /^character\s+id\s+(\d{1,6})$/i.exec(inner))) {
                const n = parseInt(mm[1], 10);
                if (!safeCp(n)) return null;
                try { return { kind: 'primitive', value: String.fromCodePoint(n) }; }
                catch (_) { return null; }
            }
            if ((mm = /^string\s+id\s*\{([^}]{1,32768})\}$/i.exec(inner))) {
                const codes = parseCodeList(mm[1]);
                if (!codes) return null;
                try { return { kind: 'primitive', value: String.fromCodePoint(...codes) }; }
                catch (_) { return null; }
            }
            return { kind: 'expression' };
        };

        const keywordBlocklist = /^(?:of|to|in|with|without|the|a|an|and|or|not|as|if|then|else|return|set|get|tell|end|on|property|global|local|true|false|it|me|my|where|whose|from|into|ref|through|thru|considering|ignoring|until|while|repeat)$/i;

        const tokenise = (raw) => {
            if (typeof raw !== 'string') return null;
            const operands = [];
            let i = 0;
            const len = raw.length;
            while (i < len) {
                while (i < len && (raw[i] === ' ' || raw[i] === '\t' || raw[i] === '\r' || raw[i] === '\n' || raw[i] === '&')) i++;
                if (i >= len) break;
                if (operands.length >= MAX_CHAIN_NODES) return null;
                const start = i;
                if (raw[i] === '"') {
                    i++;
                    while (i < len) {
                        if (raw[i] === '\\' && i + 1 < len) { i += 2; continue; }
                        if (raw[i] === '"') { i++; break; }
                        i++;
                    }
                    const tok = raw.slice(start, i);
                    const val = dequote(tok);
                    if (val === null) return null;
                    operands.push({ kind: 'literal', value: val });
                    continue;
                }
                if (raw[i] === '(' || raw[i] === '{') {
                    const openers = { '(': ')', '{': '}' };
                    const stack = [openers[raw[i]]];
                    i++;
                    while (i < len && stack.length > 0) {
                        const c = raw[i];
                        if (c === '"') {
                            i++;
                            while (i < len) {
                                if (raw[i] === '\\' && i + 1 < len) { i += 2; continue; }
                                if (raw[i] === '"') { i++; break; }
                                i++;
                            }
                            continue;
                        }
                        if (c === '(' || c === '{') stack.push(openers[c]);
                        else if (c === stack[stack.length - 1]) stack.pop();
                        i++;
                    }
                    if (stack.length !== 0) return null;
                    const tok = raw.slice(start, i);
                    const inner = classifyBody(tok);
                    if (inner && inner.kind === 'primitive') {
                        operands.push({ kind: 'primitive', value: inner.value });
                    } else if (inner && inner.kind === 'expression') {
                        const nested = tokenise(tok.slice(1, -1));
                        if (nested === null) return null;
                        for (const op of nested) {
                            if (operands.length >= MAX_CHAIN_NODES) return null;
                            operands.push(op);
                        }
                    } else {
                        operands.push({ kind: 'unknown' });
                    }
                    continue;
                }
                if (/[A-Za-z_]/.test(raw[i])) {
                    const slice = raw.slice(i);
                    // Multi-token `quoted form of <primary>` unary operator —
                    // POSIX-quotes the operand for shell use. See decoder
                    // for the design rationale; duplicated here so the YARA
                    // buffer sees shell-quoted args instead of three
                    // unresolved-placeholder spans.
                    const qfm = /^quoted\s+form\s+of\s+/i.exec(slice);
                    if (qfm) {
                        const afterKw = i + qfm[0].length;
                        let j = afterKw;
                        let operand = null;
                        if (j < len && (raw[j] === '(' || raw[j] === '{')) {
                            const openers2 = { '(': ')', '{': '}' };
                            const st2 = [openers2[raw[j]]];
                            const opStart = j;
                            j++;
                            while (j < len && st2.length > 0) {
                                const c = raw[j];
                                if (c === '"') {
                                    j++;
                                    while (j < len) {
                                        if (raw[j] === '\\' && j + 1 < len) { j += 2; continue; }
                                        if (raw[j] === '"') { j++; break; }
                                        j++;
                                    }
                                    continue;
                                }
                                if (c === '(' || c === '{') st2.push(openers2[c]);
                                else if (c === st2[st2.length - 1]) st2.pop();
                                j++;
                            }
                            if (st2.length !== 0) return null;
                            const tok = raw.slice(opStart, j);
                            const inner2 = classifyBody(tok);
                            if (inner2 && inner2.kind === 'primitive') {
                                operand = { kind: 'primitive', value: inner2.value };
                            } else if (inner2 && inner2.kind === 'expression') {
                                const nested2 = tokenise(tok.slice(1, -1));
                                if (nested2 === null) return null;
                                operand = { kind: 'group', operands: nested2 };
                            } else {
                                operand = { kind: 'unknown' };
                            }
                        } else if (j < len && raw[j] === '"') {
                            const strStart = j;
                            j++;
                            while (j < len) {
                                if (raw[j] === '\\' && j + 1 < len) { j += 2; continue; }
                                if (raw[j] === '"') { j++; break; }
                                j++;
                            }
                            const tok = raw.slice(strStart, j);
                            const val = dequote(tok);
                            if (val === null) return null;
                            operand = { kind: 'literal', value: val };
                        } else if (j < len && /[A-Za-z_]/.test(raw[j])) {
                            const idMatch2 = /^[_A-Za-z][A-Za-z0-9_]{0,63}/.exec(raw.slice(j));
                            if (idMatch2) {
                                operand = { kind: 'ref', name: idMatch2[0] };
                                j += idMatch2[0].length;
                            }
                        }
                        if (operand) {
                            operands.push({ kind: 'quoted_form_of', operand });
                            i = j;
                            continue;
                        }
                    }
                    let mm;
                    if ((mm = /^string\s+id\s*\{[^}]{1,32768}\}/i.exec(slice))) {
                        const body = /\{([^}]{1,32768})\}/.exec(mm[0])[1];
                        const codes = parseCodeList(body);
                        if (!codes) return null;
                        try { operands.push({ kind: 'primitive', value: String.fromCodePoint(...codes) }); }
                        catch (_) { return null; }
                        i += mm[0].length;
                        continue;
                    }
                    if ((mm = /^ASCII\s+character\s+\d{1,6}/i.exec(slice))) {
                        const n = parseInt(/\d{1,6}/.exec(mm[0])[0], 10);
                        if (!safeCp(n)) return null;
                        try { operands.push({ kind: 'primitive', value: String.fromCodePoint(n) }); }
                        catch (_) { return null; }
                        i += mm[0].length;
                        continue;
                    }
                    if ((mm = /^character\s+id\s+\d{1,6}/i.exec(slice))) {
                        const n = parseInt(/\d{1,6}/.exec(mm[0])[0], 10);
                        if (!safeCp(n)) return null;
                        try { operands.push({ kind: 'primitive', value: String.fromCodePoint(n) }); }
                        catch (_) { return null; }
                        i += mm[0].length;
                        continue;
                    }
                    const idMatch = /^[_A-Za-z][A-Za-z0-9_]{0,63}/.exec(slice);
                    if (idMatch) {
                        const name = idMatch[0];
                        if (keywordBlocklist.test(name)) operands.push({ kind: 'unknown' });
                        else operands.push({ kind: 'ref', name });
                        i += name.length;
                        continue;
                    }
                    let j = i;
                    while (j < len && raw[j] !== '&' && raw[j] !== ' ' && raw[j] !== '\t' && raw[j] !== '\r' && raw[j] !== '\n' && raw[j] !== '(' && raw[j] !== '{' && raw[j] !== '"') j++;
                    operands.push({ kind: 'unknown' });
                    i = j;
                    continue;
                }
                return null;
            }
            return operands;
        };

        const posixQuote = (s) => {
            if (typeof s !== 'string' || s.length === 0) return "''";
            return "'" + s.replace(/'/g, "'\\''") + "'";
        };

        const resolveOps = (operands, bindings, stack) => {
            if (!Array.isArray(operands)) return null;
            let value = '';
            let fully = true;
            for (const op of operands) {
                let piece;
                if (op.kind === 'literal' || op.kind === 'primitive') {
                    piece = op.value;
                } else if (op.kind === 'ref') {
                    if (stack.indexOf(op.name) !== -1) {
                        piece = '\u27E8circular:' + op.name + '\u27E9';
                        fully = false;
                    } else {
                        const t = bindings.get(op.name);
                        if (t && typeof t.value === 'string') {
                            // Accept partially-resolved ref targets —
                            // a value like `"https://⟨unresolved:X⟩/"`
                            // carries the static prefix/suffix which
                            // is useful. Propagate fully=false so the
                            // outer signal still reflects that
                            // resolution is incomplete. Mirror of the
                            // same logic in the decoder's
                            // `_asResolveOperands`.
                            piece = t.value;
                            if (!t.fullyResolved) fully = false;
                        } else {
                            piece = '\u27E8unresolved:' + op.name + '\u27E9';
                            fully = false;
                        }
                    }
                } else if (op.kind === 'quoted_form_of') {
                    const inner = resolveOps([op.operand], bindings, stack);
                    if (inner === null) return null;
                    if (inner.fully) {
                        piece = posixQuote(inner.value);
                    } else {
                        piece = 'quoted form of ' + inner.value;
                        fully = false;
                    }
                } else if (op.kind === 'group') {
                    const inner = resolveOps(op.operands, bindings, stack);
                    if (inner === null) return null;
                    piece = inner.value;
                    if (!inner.fully) fully = false;
                } else {
                    piece = '\u27E8unknown\u27E9';
                    fully = false;
                }
                value += piece;
                if (value.length > MAX_RESOLVED_LEN) return null;
            }
            return { value, fully };
        };

        // Collect bindings.
        const norm = text.replace(/[\u00AC\\][ \t]*\r?\n[ \t]*/g, ' ');

        // Handler-range detection — mirror of decoder's scope classifier.
        // Bindings inside `on NAME() … end NAME` are genuine runtime
        // assignments and must not be treated as file-scope values
        // (see applescript-obfuscation.js for the full rationale).
        const handlerRanges = [];
        {
            /* safeRegex: builtin */
            const onRe = /^[ \t]*on\s+([A-Za-z_][A-Za-z0-9_]{0,63})\b[^\r\n]*$/gim;
            let om;
            while ((om = onRe.exec(norm)) !== null) {
                const hName = om[1];
                if (hName.toLowerCase() === 'error') continue;
                const startOff = om.index + om[0].length;
                /* safeRegex: builtin */
                const endRe = new RegExp(
                    '^[ \\t]*end\\s+' + hName.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\$&') + '\\b[^\\r\\n]*$',
                    'im'
                );
                const endM = endRe.exec(norm.slice(startOff));
                if (endM) {
                    const endOff = startOff + endM.index + endM[0].length;
                    handlerRanges.push([om.index, endOff]);
                    onRe.lastIndex = endOff;
                }
            }
        }
        const insideHandler = (off) => {
            for (const [a, b] of handlerRanges) {
                if (off >= a && off < b) return true;
            }
            return false;
        };

        const bindings = new Map();
        // Runtime-accessor gate — parallel to decoder's
        // `_AS_RUNTIME_ACCESSOR_RE`. Handler-local `set`s whose RHS
        // contains these keywords are refused because the value
        // depends on handler-argument or loop-iterator state we can't
        // know statically.
        const RUNTIME_ACCESSOR_RE =
            /\b(?:contents\s+of|count\s+of|item\s+\d+\s+of|first\s+\w+\s+of|last\s+\w+\s+of|every\s+\w+\s+of|value\s+of|result|return\s+value\s+of|call\s+method|current\s+application|system\s+info|POSIX\s+file|do\s+shell\s+script)\b/i;
        const record = (name, kind, offset, length, rhs) => {
            if (bindings.size >= MAX_BINDINGS) return;
            // Handler-local bindings: admit if RHS is self-contained
            // (no runtime accessors) — parity with decoder path. File-
            // scope bindings (property / global / local + top-level
            // set) admit unconditionally. Records carry a
            // `handlerScoped` flag so the structured output can
            // discriminate if any future consumer needs it.
            const handlerScoped = insideHandler(offset);
            if (handlerScoped && RUNTIME_ACCESSOR_RE.test(rhs)) return;
            if (/^\s*do\s+shell\s+script\b/i.test(rhs)) return;
            const ops = tokenise(rhs.trim());
            if (ops === null) return;
            let hasPrim = false;
            const refs = new Set();
            let isPureEmpty = false;
            for (const op of ops) {
                if (op.kind === 'primitive') hasPrim = true;
                else if (op.kind === 'quoted_form_of') hasPrim = true;
                else if (op.kind === 'group') hasPrim = true;
                else if (op.kind === 'ref') refs.add(op.name);
            }
            if (ops.length === 1 && ops[0].kind === 'literal' && ops[0].value === '') {
                isPureEmpty = true;
            }
            // First-seen-wins with empty-property override. Handler-
            // local bindings never override — mirror of decoder.
            if (bindings.has(name)) {
                const existing = bindings.get(name);
                const existingIsPureEmpty =
                    existing.operands &&
                    existing.operands.length === 1 &&
                    existing.operands[0].kind === 'literal' &&
                    existing.operands[0].value === '';
                if (!existingIsPureEmpty) return;
                if (isPureEmpty) return;
                if (handlerScoped) return;
            }
            bindings.set(name, {
                name, kind, operands: ops,
                value: null, fullyResolved: false,
                refs, hasPrimitive: hasPrim,
                sourceOffset: offset, sourceLength: length,
                handlerScoped,
            });
        };
        /* safeRegex: builtin */
        const propRe = /^[ \t]*(property|global|local)\s+([_A-Za-z][A-Za-z0-9_]{0,63})\s*:\s*(.{1,8192})$/gim;
        /* safeRegex: builtin */
        const setRe = /^[ \t]*set\s+([_A-Za-z][A-Za-z0-9_]{0,63})\s+to\s+(.{1,8192})$/gim;
        let m;
        while ((m = propRe.exec(norm)) !== null) {
            record(m[2], m[1].toLowerCase(), m.index, m[0].length, m[3]);
            if (bindings.size >= MAX_BINDINGS) break;
        }
        while ((m = setRe.exec(norm)) !== null) {
            record(m[1], 'set', m.index, m[0].length, m[2]);
            if (bindings.size >= MAX_BINDINGS) break;
        }

        // Resolve: bootstrap + fixed-point.
        for (const rec of bindings.values()) {
            if (!rec.operands) continue;
            if (rec.refs.size !== 0) continue;
            const r = resolveOps(rec.operands, bindings, [rec.name]);
            if (r === null) continue;
            rec.value = r.value;
            rec.fullyResolved = r.fully;
        }
        for (let round = 0; round < MAX_ROUNDS; round++) {
            let changed = false;
            for (const rec of bindings.values()) {
                if (!rec.operands) continue;
                if (rec.fullyResolved) continue;
                const r = resolveOps(rec.operands, bindings, [rec.name]);
                if (r === null) continue;
                const prev = rec.value;
                rec.value = r.value;
                rec.fullyResolved = r.fully;
                if (prev !== r.value) changed = true;
            }
            if (!changed) break;
        }

        // Emit table lines.
        //
        // Return shape is `{ lines, bindings, sinks }`:
        //   • `lines` — legacy text view (kept for unit-test coverage of
        //     the reassembly format; no longer injected into
        //     augmentedBuffer since the YARA rules that keyed on these
        //     markers were migrated to Detection Patterns).
        //   • `bindings` — structured array of resolved bindings with
        //     their original source-offset anchors so the caller can
        //     emit a `signatureMatch` with click-to-scroll wiring.
        //   • `sinks` — structured array of resolved `do shell script`
        //     expressions with source-offset anchors pointing at the
        //     `do shell script` keyword in the raw file.
        const lines = [];
        const bindingOut = [];
        const sinkOut = [];
        let aggregate = 0;
        for (const rec of bindings.values()) {
            if (typeof rec.value !== 'string') continue;
            if (rec.value.length < 3) continue;
            if (!rec.hasPrimitive && rec.refs.size === 0) continue;
            aggregate += rec.value.length;
            if (aggregate > MAX_AGGREGATE) break;
            const clipped = rec.value.length > MAX_RESOLVED_LEN
                ? rec.value.slice(0, MAX_RESOLVED_LEN) + '…'
                : rec.value;
            // Newlines in resolved values would break YARA rules that
            // match on whole lines — strip them for the table emission.
            const flat = clipped.replace(/[\r\n]+/g, ' ');
            lines.push('-- Binding: ' + rec.name + ' (' + rec.kind + ') -> "' + flat + '"');
            bindingOut.push({
                name: rec.name,
                kind: rec.kind,
                resolved: flat,
                sourceOffset: rec.sourceOffset,
                sourceLength: rec.sourceLength,
                handlerScoped: !!rec.handlerScoped,
            });
        }

        // Walk `do shell script <expr>` sinks.
        /* safeRegex: builtin */
        const sinkRe = /\bdo\s+shell\s+script\s+(.{1,4096}?)(?:\s+(?=with\s+administrator\s+privileges\b|password\b|as\s+\w+|without\b|returning\b)|(?=[\r\n])|$)/gi;
        let sinks = 0;
        while ((m = sinkRe.exec(text)) !== null) {
            if (sinks++ >= MAX_SINKS) break;
            let expr = m[1].trim();
            if (expr.length >= 2 && expr[0] === '(' && expr[expr.length - 1] === ')') {
                expr = expr.slice(1, -1).trim();
            }
            const ops = tokenise(expr);
            if (!ops || ops.length === 0) continue;
            const hasPrim = ops.some(op => op.kind === 'primitive');
            const hasRef = ops.some(op => op.kind === 'ref');
            const hasQf = ops.some(op => op.kind === 'quoted_form_of');
            const hasGroup = ops.some(op => op.kind === 'group');
            if (!hasPrim && !hasRef && !hasQf && !hasGroup) continue;
            const r = resolveOps(ops, bindings, ['__sink']);
            if (!r) continue;
            if (r.value.length < 3) continue;
            const tailStart = m.index + m[0].length;
            const tail = text.substring(tailStart, tailStart + 120);
            const isAdmin = /^\s*with\s+administrator\s+privileges\b/i.test(tail);
            const flat = r.value.replace(/[\r\n]+/g, ' ').slice(0, MAX_RESOLVED_LEN);
            lines.push('-- Reassembled: do shell script "' + flat + '"' + (isAdmin ? ' with administrator privileges' : ''));
            sinkOut.push({
                resolved: flat,
                isAdmin,
                // Anchor at the `do shell script` keyword — that's what
                // an analyst wants to scroll to, not the resolved
                // cleartext which only exists in the sidebar.
                sourceOffset: m.index,
                sourceLength: m[0].length,
            });
        }

        return { lines, bindings: bindingOut, sinks: sinkOut };
    }
}
