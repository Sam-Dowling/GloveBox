'use strict';
// ════════════════════════════════════════════════════════════════════════════
// code-formatter.js — best-efforts code pretty-printer (visual only).
//
// Consumed by `PlainTextRenderer` when the user toggles the "Format" button
// on. Pure function — no DOM, no globals, no IO. Given a source string and
// a highlight.js-style language label, returns a reformatted string whose
// semantics are (at best) unchanged. Formatting is strictly a DISPLAY
// transformation: the caller keeps the original source in `_rawText` so
// sidebar click-to-focus offsets, YARA scan buffers, and IOC extraction
// never see the formatted output. See `plaintext-renderer.js` file header.
//
// Design constraints:
//   • No vendor dependency. Ships as ~250 lines of tokeniser + structural
//     rewriter inside the single-file bundle.
//   • Language-agnostic core. Recognises strings, line/block comments, and
//     (for JS-family) regex literals verbatim, then splits "code" regions
//     on brace/bracket/paren boundaries and re-indents by depth.
//   • Hard-fails CLOSED. On any unexpected condition (over-budget output,
//     unmatched brackets, depth overflow) the formatter returns the
//     original input untouched. A failed format pass is indistinguishable
//     from Format-off, which is exactly the UX the user expects.
//   • No regex with unbounded quantifiers on user input. The tokeniser is
//     a single linear scan over the source string.
//
// Input size caps (independent of the outer rich-render gate — defence in
// depth against a hostile input that somehow slips past):
//
//   • MAX_INPUT_BYTES    — 2 MiB. Above this the formatter is a no-op.
//   • MAX_AMP_FACTOR     — 3×. If the output buffer grows past
//                          `input.length * 3 + 1 KiB` mid-walk, bail.
//   • MAX_DEPTH          — 256 nested brackets. Above → bail.
//
// Language handling:
//   • javascript / typescript / json / jsonl / jsonc / css / scss / less
//     / swift / kotlin / c / cpp / csharp / java / go / rust / php
//     — full tokeniser: `"`/`'`/`` ` ``-strings, `//` and `/* */`
//     comments, regex literals (JS family only, context-gated), `{} []`
//     block/indent.
//   • xml / html — block-tag splitter: insert newlines between `><`
//     adjacent pairs (outside `<!--…-->`, `<![CDATA[…]]>`, and attribute
//     quotes) and indent by open/close-tag depth. No string/regex
//     tokeniser — attribute quotes handled inline.
//   • powershell / bash / dos (batch) — light indent-only pass: re-indent
//     lines by leading-brace depth (`{` / `}`), preserving everything
//     else. Python, Ruby, Perl and other whitespace-significant or
//     brace-less languages fall through to a no-op (return input).
//   • Any other language → no-op.
//
// If the language is unknown or no-op, the formatter returns the input
// string unchanged. `PlainTextRenderer` checks for a non-empty lang before
// offering the Format button, so this path is rare in practice.
// ════════════════════════════════════════════════════════════════════════════

class CodeFormatter {

  static MAX_INPUT_BYTES = 2 * 1024 * 1024;
  static MAX_AMP_FACTOR  = 3;
  static MAX_AMP_OVERHEAD_BYTES = 1024;
  static MAX_DEPTH       = 256;
  static INDENT          = '  ';   // 2 spaces

  /** Languages handled by the brace-family tokeniser. */
  static _BRACE_LANGS = new Set([
    'javascript', 'typescript',
    'json',
    'css', 'scss', 'less',
    'c', 'cpp', 'csharp', 'java',
    'go', 'rust', 'swift', 'kotlin',
    'php',
  ]);

  /** JS-family languages where `/…/` can be a regex literal (context-gated). */
  static _JS_FAMILY = new Set([
    'javascript', 'typescript', 'json',  // json never has regex but tokeniser is shared
  ]);

  /** Languages that support line comments with `//`. */
  static _SLASH_LINE_COMMENT = new Set([
    'javascript', 'typescript',
    'css', 'scss', 'less',
    'c', 'cpp', 'csharp', 'java',
    'go', 'rust', 'swift', 'kotlin',
    'php',
  ]);

  /** Languages that support C-style block comments (slash-star … star-slash). */
  static _BLOCK_COMMENT = new Set([
    'javascript', 'typescript',
    'css', 'scss', 'less',
    'c', 'cpp', 'csharp', 'java',
    'go', 'rust', 'swift', 'kotlin',
    'php',
  ]);

  /** Languages whose line comments start with `#` (shell-style). */
  static _HASH_LINE_COMMENT = new Set([
    'bash', 'powershell',
  ]);

  /** Languages that support template-string backticks. */
  static _BACKTICK_STRINGS = new Set([
    'javascript', 'typescript',
  ]);

  /**
   * Format `input` according to `lang`. On any issue returns `input`
   * unchanged. `lang` is a highlight.js-style label (e.g. 'javascript',
   * 'xml', 'powershell'); unknown labels fall through to a no-op.
   *
   * @param {string} input
   * @param {string} lang
   * @returns {string}
   */
  static format(input, lang) {
    if (typeof input !== 'string' || input.length === 0) return input || '';
    if (input.length > CodeFormatter.MAX_INPUT_BYTES) return input;

    try {
      if (CodeFormatter._BRACE_LANGS.has(lang)) {
        return CodeFormatter._formatBraceLang(input, lang);
      }
      if (lang === 'xml') {
        return CodeFormatter._formatXml(input);
      }
      if (lang === 'powershell' || lang === 'bash' || lang === 'dos') {
        return CodeFormatter._formatIndentOnly(input, lang);
      }
    } catch (_) {
      // Any unexpected throw → return input. No reason to ever surface
      // a formatter exception to the user.
      return input;
    }
    // Unsupported language — treat as no-op.
    return input;
  }

  // ── Brace-family tokeniser / rewriter ─────────────────────────────────

  /**
   * Single-pass formatter for C-style brace languages. Walks the input
   * once, copying strings / comments / regex literals verbatim and
   * rewriting "code" on brace/bracket/paren boundaries.
   *
   * Output rules for "code" characters:
   *   '{' or '[' or '(' → emit, push depth; if followed by a non-close
   *                       character, insert newline + indent.
   *   matching close    → pop depth; insert newline + indent BEFORE if
   *                       the current output line is non-empty, then
   *                       emit the close.
   *   ';'               → emit, then insert newline + indent (only
   *                       outside `(…)` — keeps `for (;;)` on one line).
   *   ','               → emit; if we're inside `{…}` or top-level
   *                       `[…]`, insert newline + indent.
   *   run of whitespace → collapse to single ' ' inside a line; `\n` is
   *                       treated as whitespace and collapsed — the
   *                       structural rules above re-introduce the
   *                       newlines the output needs.
   *
   * The output buffer is checked against the amp cap on every segment
   * append; exceeding it returns the input verbatim.
   */
  static _formatBraceLang(input, lang) {
    const N = input.length;
    const maxOut = N * CodeFormatter.MAX_AMP_FACTOR + CodeFormatter.MAX_AMP_OVERHEAD_BYTES;
    const maxDepth = CodeFormatter.MAX_DEPTH;

    // Output buffered as an array of string pieces; joined once at the end.
    const out = [];
    let outLen = 0;
    // Depth stack — each entry is the character that opened the bracket.
    const stack = [];
    // Are we at the start of a fresh line (only whitespace written since
    // the last '\n' in `out`)? Drives indent insertion.
    let atLineStart = true;
    // Whitespace pending between the last non-space char and the next —
    // collapsed to a single space when we emit a non-space code char.
    let pendingSpace = false;

    const jsFamily = CodeFormatter._JS_FAMILY.has(lang);
    const slashLineComment = CodeFormatter._SLASH_LINE_COMMENT.has(lang);
    const blockComment = CodeFormatter._BLOCK_COMMENT.has(lang);
    const backtickStrings = CodeFormatter._BACKTICK_STRINGS.has(lang);

    const push = (s) => {
      if (!s) return true;
      if (outLen + s.length > maxOut) return false;
      out.push(s);
      outLen += s.length;
      return true;
    };

    const indent = () => CodeFormatter.INDENT.repeat(Math.min(stack.length, maxDepth));

    const newline = () => {
      // Trim trailing spaces on the current line before the '\n'.
      while (out.length > 0) {
        const last = out[out.length - 1];
        if (last === ' ') { out.pop(); outLen -= 1; continue; }
        // Trim trailing spaces inside a concatenated chunk.
        const trimmed = last.replace(/[ \t]+$/, '');
        if (trimmed !== last) {
          outLen -= (last.length - trimmed.length);
          if (trimmed.length === 0) out.pop();
          else out[out.length - 1] = trimmed;
        }
        break;
      }
      if (!push('\n')) return false;
      if (!push(indent())) return false;
      atLineStart = true;
      pendingSpace = false;
      return true;
    };

    const emitCode = (ch) => {
      if (pendingSpace && !atLineStart) {
        if (!push(' ')) return false;
      }
      pendingSpace = false;
      atLineStart = false;
      if (!push(ch)) return false;
      return true;
    };

    // Emit a verbatim-copied span (string / comment / regex). Never
    // introduces structural rewrites; preserves the bytes exactly.
    const emitVerbatim = (span) => {
      if (!span) return true;
      if (pendingSpace && !atLineStart) {
        if (!push(' ')) return false;
      }
      pendingSpace = false;
      if (!push(span)) return false;
      // Update atLineStart based on the last newline in the span. A
      // verbatim that contains a '\n' (e.g. a template literal with
      // embedded newlines) puts us at line start for the next iteration.
      const lastNl = span.lastIndexOf('\n');
      if (lastNl >= 0) {
        const tail = span.slice(lastNl + 1);
        atLineStart = /^[ \t]*$/.test(tail);
      } else {
        atLineStart = false;
      }
      return true;
    };

    // Decide whether a `/` at position `i` is the start of a regex literal.
    // Heuristic: follows a character from the regex-allowed-prefix set, or
    // is at input start / follows only whitespace since a regex-allowed
    // prefix. Conservative — false positives turn an infix `/` into a
    // regex-copy-until-slash which would bail out on EOL mismatch; our
    // walker handles that by surrendering the remaining parse as code.
    const isRegexStart = (i) => {
      if (!jsFamily) return false;
      // Must be at least one more char for the body.
      if (i + 1 >= N) return false;
      const next = input.charAt(i + 1);
      if (next === '/' || next === '*') return false; // comment, not regex
      // Walk back over whitespace.
      let j = i - 1;
      while (j >= 0) {
        const c = input.charCodeAt(j);
        if (c === 0x20 || c === 0x09 || c === 0x0A || c === 0x0D) { j -= 1; continue; }
        break;
      }
      if (j < 0) return true;
      const prev = input.charAt(j);
      // Regex can follow any of these "expects-expression" characters.
      // A bare `)` or `]` or identifier/number means `/` is division.
      return '=,;({[!&|?:+-*%^~<>'.indexOf(prev) >= 0;
    };

    // ── Main walk ──
    let i = 0;
    while (i < N) {
      const ch = input.charAt(i);
      const cc = input.charCodeAt(i);

      // ── Whitespace ──
      if (cc === 0x20 || cc === 0x09) {
        if (!atLineStart) pendingSpace = true;
        i += 1;
        continue;
      }
      if (cc === 0x0A || cc === 0x0D) {
        // Existing newlines in input — collapse into pendingSpace. We
        // emit newlines only where the structural rules say so.
        if (!atLineStart) pendingSpace = true;
        i += 1;
        continue;
      }

      // ── Line comment (`//`) ──
      if (slashLineComment && ch === '/' && i + 1 < N && input.charAt(i + 1) === '/') {
        let j = i + 2;
        while (j < N) {
          const c = input.charCodeAt(j);
          if (c === 0x0A || c === 0x0D) break;
          j += 1;
        }
        const span = input.slice(i, j);
        if (!emitVerbatim(span)) return input;
        if (!newline()) return input;
        i = j;
        // Skip the terminator — newline() already emitted one.
        while (i < N) {
          const c = input.charCodeAt(i);
          if (c === 0x0A || c === 0x0D) { i += 1; continue; }
          break;
        }
        continue;
      }

      // ── Block comment (`/* … */`) ──
      if (blockComment && ch === '/' && i + 1 < N && input.charAt(i + 1) === '*') {
        let j = i + 2;
        while (j + 1 < N) {
          if (input.charAt(j) === '*' && input.charAt(j + 1) === '/') { j += 2; break; }
          j += 1;
        }
        if (j + 1 >= N && !(input.charAt(j - 1) === '/' && input.charAt(j - 2) === '*')) {
          // Unterminated block comment — copy rest of file and stop.
          if (!emitVerbatim(input.slice(i))) return input;
          i = N;
          continue;
        }
        if (!emitVerbatim(input.slice(i, j))) return input;
        i = j;
        continue;
      }

      // ── String literal (`"…"`, `'…'`, `` `…` ``) ──
      if (ch === '"' || ch === "'" || (backtickStrings && ch === '`')) {
        const quote = ch;
        let j = i + 1;
        while (j < N) {
          const c = input.charAt(j);
          if (c === '\\' && j + 1 < N) { j += 2; continue; }
          if (c === quote) { j += 1; break; }
          // Newline in single/double quoted string without continuation
          // → unterminated. Some languages allow this (Python triple
          // quotes, Kotlin raw strings) but our brace-lang set doesn't;
          // still, surrender the rest as verbatim rather than eating
          // the whole file.
          if (quote !== '`' && (c === '\n' || c === '\r')) { break; }
          j += 1;
        }
        if (!emitVerbatim(input.slice(i, j))) return input;
        i = j;
        continue;
      }

      // ── Regex literal (JS family only) ──
      if (ch === '/' && isRegexStart(i)) {
        let j = i + 1;
        let inCharClass = false;
        while (j < N) {
          const c = input.charAt(j);
          if (c === '\\' && j + 1 < N) { j += 2; continue; }
          if (c === '[' && !inCharClass) { inCharClass = true; j += 1; continue; }
          if (c === ']' && inCharClass) { inCharClass = false; j += 1; continue; }
          if (c === '/' && !inCharClass) { j += 1; break; }
          if (c === '\n' || c === '\r') { break; }
          j += 1;
        }
        // Consume flags.
        while (j < N && /[a-z]/i.test(input.charAt(j))) j += 1;
        if (!emitVerbatim(input.slice(i, j))) return input;
        i = j;
        continue;
      }

      // ── Structural characters ──
      if (ch === '{' || ch === '[' || ch === '(') {
        if (stack.length >= maxDepth) return input;
        // For `(` and `[` at a position where we're mid-expression,
        // don't force a newline — that would mangle function calls and
        // array indexing. `{` is always treated as a block/object opener
        // so a newline after it is almost always wanted. This heuristic
        // isn't perfect (JSX / TS generics / object destructuring edge
        // cases exist) but covers the common cases for readability.
        if (!emitCode(ch)) return input;
        stack.push(ch);

        // Peek ahead — skip whitespace — decide whether the opener is
        // immediately followed by a matching closer (empty block).
        let k = i + 1;
        while (k < N) {
          const c = input.charCodeAt(k);
          if (c === 0x20 || c === 0x09 || c === 0x0A || c === 0x0D) { k += 1; continue; }
          break;
        }
        const nextNonWs = k < N ? input.charAt(k) : '';
        const matchingClose = ch === '{' ? '}' : (ch === '[' ? ']' : ')');
        if (nextNonWs === matchingClose) {
          // Empty container — leave as `{}` / `[]` / `()` on one line.
          pendingSpace = false;
          i += 1;
          continue;
        }

        if (ch === '{') {
          if (!newline()) return input;
        } else if (ch === '[' && stack.length >= 2 && stack[stack.length - 2] === '{') {
          // Array value inside an object — newline helps readability.
          if (!newline()) return input;
        }
        // For `(` and top-level `[`, no forced newline: keeps function
        // calls and short arrays compact.
        i += 1;
        continue;
      }

      if (ch === '}' || ch === ']' || ch === ')') {
        const opener = stack.length ? stack[stack.length - 1] : '';
        const expected = opener === '{' ? '}' : (opener === '[' ? ']' : (opener === '(' ? ')' : ''));
        if (ch !== expected) {
          // Mismatched bracket — bail entirely.
          return input;
        }
        stack.pop();
        // Force closer onto its own line for `}` and `]`-inside-object;
        // `)` stays inline to keep call sites tidy.
        if (ch === '}' || (ch === ']' && stack.length >= 1 && stack[stack.length - 1] === '{')) {
          if (!atLineStart) {
            if (!newline()) return input;
          }
        }
        if (!emitCode(ch)) return input;
        i += 1;
        // Line-level context: if the character immediately after is the
        // end of a statement (` ;` / `,`), the semicolon/comma handler
        // below will insert the newline. Otherwise, insert one after
        // `}` of a block / top-level.
        if (ch === '}' && stack.length === 0) {
          if (!newline()) return input;
        }
        continue;
      }

      if (ch === ';') {
        if (!emitCode(ch)) return input;
        i += 1;
        // Inside `(` (e.g. C `for (;;)`) keep statements on one line.
        const topIsParen = stack.length && stack[stack.length - 1] === '(';
        if (!topIsParen) {
          if (!newline()) return input;
        }
        continue;
      }

      if (ch === ',') {
        if (!emitCode(ch)) return input;
        i += 1;
        // Insert newlines after commas at the top level of `{…}` or `[…]`
        // blocks. Keeps function-call arguments / JSON one-liner arrays
        // flowing.
        const top = stack.length ? stack[stack.length - 1] : '';
        if (top === '{' || top === '[') {
          if (!newline()) return input;
        }
        continue;
      }

      if (ch === ':') {
        // Space after `:` in object literals (JSON / JS / TS). Simple
        // rule: emit `:` then a space (unless we're inside `(`, where
        // this could be part of a ternary and spacing is already handled
        // by the operator-spacing pass we don't run).
        if (!emitCode(ch)) return input;
        i += 1;
        const top = stack.length ? stack[stack.length - 1] : '';
        if (top === '{') {
          pendingSpace = true;
        }
        continue;
      }

      // Default: emit code char verbatim.
      if (!emitCode(ch)) return input;
      i += 1;
    }

    // Unterminated context → bail.
    if (stack.length !== 0) return input;

    const result = out.join('');
    // Strip the leading indent / newline the rewriter may have inserted
    // before the first token (common when input begins with `{`).
    return result.replace(/^\n+/, '');
  }

  // ── XML / HTML formatter ─────────────────────────────────────────────

  /**
   * Simple block-tag splitter for XML / HTML. Walks the input once,
   * copying `<!--…-->` / `<![CDATA[…]]>` / `<?…?>` / quoted-attribute
   * spans verbatim, tracking tag depth, and inserting newlines between
   * `>` and `<` when the transition is between different tags (never
   * inside text content).
   */
  static _formatXml(input) {
    const N = input.length;
    const maxOut = N * CodeFormatter.MAX_AMP_FACTOR + CodeFormatter.MAX_AMP_OVERHEAD_BYTES;
    const maxDepth = CodeFormatter.MAX_DEPTH;
    const out = [];
    let outLen = 0;
    let depth = 0;

    const push = (s) => {
      if (!s) return true;
      if (outLen + s.length > maxOut) return false;
      out.push(s);
      outLen += s.length;
      return true;
    };

    const indent = () => CodeFormatter.INDENT.repeat(Math.min(depth, maxDepth));
    const newlineIndent = () => {
      // Trim trailing whitespace on the tail piece, if any.
      if (out.length > 0) {
        const last = out[out.length - 1];
        const trimmed = last.replace(/[ \t]+$/, '');
        if (trimmed !== last) {
          outLen -= (last.length - trimmed.length);
          if (trimmed.length === 0) out.pop();
          else out[out.length - 1] = trimmed;
        }
      }
      return push('\n') && push(indent());
    };

    let i = 0;
    // Skip leading whitespace so we don't emit a blank first line.
    while (i < N) {
      const c = input.charCodeAt(i);
      if (c === 0x20 || c === 0x09 || c === 0x0A || c === 0x0D) { i += 1; continue; }
      break;
    }

    while (i < N) {
      const ch = input.charAt(i);

      // Tag open.
      if (ch === '<') {
        // Determine tag kind.
        //   <!-- … -->          comment
        //   <![CDATA[ … ]]>     cdata
        //   <?…?>               processing instruction (incl. <?xml …?>)
        //   <!DOCTYPE …>        doctype
        //   </tag>              closing
        //   <tag … />           self-closing
        //   <tag …>             opening
        let j = i + 1;
        let verbatim = false;
        let verbatimEnd = -1;
        if (input.substr(i, 4) === '<!--') {
          verbatim = true;
          const end = input.indexOf('-->', i + 4);
          verbatimEnd = end < 0 ? N : end + 3;
        } else if (input.substr(i, 9) === '<![CDATA[') {
          verbatim = true;
          const end = input.indexOf(']]>', i + 9);
          verbatimEnd = end < 0 ? N : end + 3;
        } else if (input.charAt(i + 1) === '?') {
          verbatim = true;
          const end = input.indexOf('?>', i + 2);
          verbatimEnd = end < 0 ? N : end + 2;
        } else if (input.substr(i, 2) === '<!') {
          // Doctype / other bangs — copy to matching `>` (attributes
          // can contain strings; be permissive).
          verbatim = true;
          const end = input.indexOf('>', i + 2);
          verbatimEnd = end < 0 ? N : end + 1;
        }
        if (verbatim) {
          if (!newlineIndent()) return input;
          if (!push(input.slice(i, verbatimEnd))) return input;
          i = verbatimEnd;
          continue;
        }

        // Walk a single tag, respecting quoted attribute values.
        let tagEnd = -1;
        let quote = '';
        let k = j;
        while (k < N) {
          const c = input.charAt(k);
          if (quote) {
            if (c === quote) quote = '';
            k += 1;
            continue;
          }
          if (c === '"' || c === "'") { quote = c; k += 1; continue; }
          if (c === '>') { tagEnd = k + 1; break; }
          k += 1;
        }
        if (tagEnd < 0) {
          // Unterminated tag — surrender the rest verbatim.
          if (!push(input.slice(i))) return input;
          i = N;
          continue;
        }
        const tagText = input.slice(i, tagEnd);
        const isClosing = tagText.charAt(1) === '/';
        const isSelfClosing = tagText.charAt(tagText.length - 2) === '/';

        if (isClosing) {
          depth = Math.max(0, depth - 1);
          if (!newlineIndent()) return input;
          if (!push(tagText)) return input;
        } else {
          if (!newlineIndent()) return input;
          if (!push(tagText)) return input;
          if (!isSelfClosing) {
            if (depth < maxDepth) depth += 1;
          }
        }
        i = tagEnd;
        continue;
      }

      // Text content between tags. Collect until the next `<` and emit
      // as a single chunk (preserving internal whitespace).
      let j = i;
      while (j < N && input.charAt(j) !== '<') j += 1;
      const chunk = input.slice(i, j);
      // Skip chunks that are purely whitespace — the structural
      // newlineIndent handles layout.
      if (chunk.trim().length > 0) {
        if (!newlineIndent()) return input;
        if (!push(chunk.trim())) return input;
      }
      i = j;
    }

    const result = out.join('');
    return result.replace(/^\n+/, '');
  }

  // ── Indent-only formatter (PowerShell / Bash / Batch) ─────────────────

  /**
   * Minimal re-indent pass for brace-delimited shell languages. Preserves
   * line breaks and content; only rewrites leading whitespace per line.
   * A line whose trimmed content starts with `}` decreases depth BEFORE
   * emitting; a line that ends with `{` (outside strings / comments)
   * increases depth AFTER emitting. Strings, comments, and here-docs
   * aren't parsed — the walker is a whole-line heuristic, so complex
   * embedded braces may confuse it. That's acceptable for "best
   * efforts".
   */
  static _formatIndentOnly(input, _lang) {
    const N = input.length;
    if (N === 0) return input;
    const maxOut = N * CodeFormatter.MAX_AMP_FACTOR + CodeFormatter.MAX_AMP_OVERHEAD_BYTES;
    const maxDepth = CodeFormatter.MAX_DEPTH;
    // Normalise line endings locally (caller already LF-normalises but
    // guard anyway).
    const lines = input.replace(/\r\n?/g, '\n').split('\n');
    const out = [];
    let outLen = 0;
    let depth = 0;

    for (let li = 0; li < lines.length; li++) {
      const raw = lines[li];
      const trimmed = raw.replace(/^[ \t]+/, '');
      // Count braces on the trimmed line (coarse — treats all `{` and
      // `}` as structural even inside strings/comments).
      let opens = 0;
      let closes = 0;
      let leadingCloses = 0;
      let seenNonClose = false;
      for (let k = 0; k < trimmed.length; k++) {
        const c = trimmed.charAt(k);
        if (c === '{') { opens += 1; seenNonClose = true; }
        else if (c === '}') {
          closes += 1;
          if (!seenNonClose) leadingCloses += 1;
        } else if (c !== ' ' && c !== '\t') {
          seenNonClose = true;
        }
      }
      // Apply leading `}` dedent BEFORE emitting this line.
      const lineDepth = Math.max(0, Math.min(depth - leadingCloses, maxDepth));
      const indent = CodeFormatter.INDENT.repeat(lineDepth);
      const line = (trimmed.length > 0 ? indent + trimmed : '');
      if (outLen + line.length + 1 > maxOut) return input;
      out.push(line);
      outLen += line.length + 1;
      // Net depth change for next line.
      depth = Math.max(0, Math.min(depth + opens - closes, maxDepth));
    }
    return out.join('\n');
  }
}
