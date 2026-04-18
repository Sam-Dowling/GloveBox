# Browser Extension Samples

Two sample browser extensions for exercising Loupe's `BrowserExtRenderer`
and `browserext-threats.yar` rules.

| File | Format | Risk | What it demonstrates |
|---|---|---|---|
| `benign-firefox.xpi` | Firefox MV2 (`.xpi` = ZIP) | Low | Well-scoped reading-list extension — `storage` / `activeTab` / `contextMenus`, no host permissions, no content scripts. Useful as a "clean" baseline. |
| `suspicious-chrome.crx` | Chrome MV3, CRX v3 envelope | High | Deliberately over-permissioned sample: `<all_urls>` host perms, `nativeMessaging`, `debugger`, `webRequestBlocking`, `cookies`, `'unsafe-eval'` CSP, `externally_connectable` matches `*://*/*`, content script at `document_start` in all frames. Every feature here is legitimate in some real extension; the point is that a single extension claiming *all of them* is the loud pattern `browserext-threats.yar` looks for. |

Both samples are static text — neither performs any real network I/O or
exfiltration, and the native-messaging host name (`com.example.invalid.*`)
is a reserved-invalid TLD that cannot resolve.

The `.crx` envelope is CRX v3 with an empty `CrxFileHeader` protobuf (no
signatures). Chrome would reject this as unsigned; Loupe renders v3 headers
as presence-only (full protobuf parse is deferred, per `CONTRIBUTING.md`).
