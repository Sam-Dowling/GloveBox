// ─── Default YARA Rules ───────────────────────────────────
// Edit or replace these rules, then click "Run Scan"
// Supports: text strings, hex strings {AA BB}, regex /pattern/
// Modifiers: nocase, wide, fullword
// Conditions: any of them, all of them, N of them, $a and $b


// ---------------------------------------------------------------------------
//  SECTION 1: VBA MACRO DETECTION (Office Documents)
// ---------------------------------------------------------------------------

rule Office_Macro_Project_Present
{
    meta:
        description = "Office document contains VBA project streams or references"
        severity    = "info"

    strings:
        $a = "_VBA_PROJECT_CUR" wide
        $b = "VBAProject" wide
        $c = "Attribute VB_"
        $d = "vbaProject.bin"
        $e = "vbaData.xml"

    condition:
        any of them
}

rule VBA_AutoExec_Trigger
{
    meta:
        description = "VBA macro with auto-execution entry point — runs on document open/close"
        severity    = "high"

    strings:
        $a = "AutoOpen" nocase
        $b = "AutoExec" nocase
        $c = "Auto_Open" nocase
        $d = "Document_Open" nocase
        $e = "Workbook_Open" nocase
        $f = "Auto_Close" nocase
        $g = "Document_Close" nocase
        $h = "Workbook_BeforeClose" nocase
        $i = "Document_BeforeSave" nocase

    condition:
        any of them
}

rule VBA_Shell_Execution
{
    meta:
        description = "VBA macro spawns a shell or external process alongside VBA context markers"
        severity    = "critical"

    strings:
        $exec1 = "WScript.Shell" nocase
        $exec2 = "cmd.exe" nocase
        $exec3 = "cmd /c" nocase
        $exec4 = "WinExec" nocase
        $exec5 = "ShellExecute" nocase
        $exec6 = "CreateObject" nocase
        $vba1 = "Sub " nocase
        $vba2 = "Function " nocase
        $vba3 = "Attribute VB_"

    condition:
        ($vba1 or $vba2 or $vba3) and any of ($exec1, $exec2, $exec3, $exec4, $exec5, $exec6)
}

rule VBA_Download_Capability
{
    meta:
        description = "VBA macro uses HTTP objects or download functions to fetch remote content"
        severity    = "critical"

    strings:
        $dl1 = "MSXML2.XMLHTTP" nocase
        $dl2 = "WinHttp.WinHttpRequest" nocase
        $dl3 = "Microsoft.XMLHTTP" nocase
        $dl4 = "MSXML2.ServerXMLHTTP" nocase
        $dl5 = "URLDownloadToFile" nocase
        $dl6 = "DownloadFile" nocase
        $dl7 = "Net.WebClient" nocase
        $dl8 = "InternetExplorer.Application" nocase
        $vba1 = "Sub " nocase
        $vba2 = "Function " nocase

    condition:
        ($vba1 or $vba2) and 2 of ($dl1, $dl2, $dl3, $dl4, $dl5, $dl6, $dl7, $dl8)
}

rule VBA_Obfuscation_Techniques
{
    meta:
        description = "VBA macro uses 3+ obfuscation techniques (string building, encoding, reversal)"
        severity    = "high"

    strings:
        $a = "Chr(" nocase
        $b = "ChrW(" nocase
        $c = "Asc(" nocase
        $d = "StrReverse" nocase
        $e = "Replace(" nocase
        $f = "Join(" nocase
        $g = "Mid(" nocase
        $h = "CallByName" nocase
        $i = "FromBase64String" nocase

    condition:
        3 of them
}

rule VBA_PowerShell_Invocation
{
    meta:
        description = "VBA macro invokes PowerShell — common malware dropper technique"
        severity    = "critical"

    strings:
        $ps = "powershell" nocase
        $a = "Sub " nocase
        $b = "Shell" nocase
        $c = "CreateObject" nocase

    condition:
        $ps and ($a or $b or $c)
}

rule VBA_Environment_Enumeration
{
    meta:
        description = "VBA macro enumerates environment variables or WMI (sandbox evasion / recon)"
        severity    = "medium"

    strings:
        $a = "Environ(" nocase
        $b = "Application.UserName" nocase
        $c = "ComputerName" nocase
        $d = "GetObject(\"winmgmts" nocase
        $e = "Win32_Process" nocase
        $f = "Win32_ComputerSystem" nocase

    condition:
        2 of them
}

rule VBA_File_System_Write
{
    meta:
        description = "VBA macro writes files to disk — potential payload drop"
        severity    = "high"

    strings:
        $fs1 = "Scripting.FileSystemObject" nocase
        $fs2 = "CreateTextFile" nocase
        $fs3 = "SaveToFile" nocase
        $fs4 = "ADODB.Stream" nocase
        $vba1 = "Sub " nocase
        $vba2 = "Function " nocase

    condition:
        ($vba1 or $vba2) and any of ($fs1, $fs2, $fs3, $fs4)
}

rule VBA_Registry_Manipulation
{
    meta:
        description = "VBA macro reads or writes Windows registry keys — persistence or config theft"
        severity    = "high"

    strings:
        $a = "RegRead" nocase
        $b = "RegWrite" nocase
        $c = "RegDelete" nocase
        $d = "HKEY_CURRENT_USER" nocase
        $e = "HKEY_LOCAL_MACHINE" nocase
        $f = "HKCU" nocase
        $g = "HKLM" nocase
        $vba1 = "Sub " nocase
        $vba2 = "Function " nocase

    condition:
        ($vba1 or $vba2) and 2 of ($a, $b, $c, $d, $e, $f, $g)
}

rule VBA_Scheduled_Task_Persistence
{
    meta:
        description = "VBA macro creates scheduled tasks or startup entries for persistence"
        severity    = "critical"

    strings:
        $a = "schtasks" nocase
        $b = "Schedule.Service" nocase
        $c = "CurrentVersion\\Run" nocase
        $d = "Startup" nocase
        $e = "Win32_ScheduledJob" nocase
        $vba1 = "Sub " nocase
        $vba2 = "CreateObject" nocase

    condition:
        ($vba1 or $vba2) and any of ($a, $b, $c, $d, $e)
}

rule VBA_ActiveX_Control
{
    meta:
        description = "VBA macro uses ActiveX controls — can auto-trigger macro execution"
        severity    = "high"

    strings:
        $a = "InkPicture" nocase
        $b = "InkEdit" nocase
        $c = "Forms.CommandButton" nocase
        $d = "MSComctlLib" nocase
        $e = "Painting" nocase

    condition:
        any of them
}

rule VBA_MSHTA_Invocation
{
    meta:
        description = "VBA macro invokes mshta.exe — runs HTA or inline script"
        severity    = "critical"

    strings:
        $a = "mshta" nocase
        $b = "Sub " nocase
        $c = "Shell" nocase

    condition:
        $a and ($b or $c)
}

rule VBA_Certutil_Decode
{
    meta:
        description = "VBA macro uses certutil to decode base64 payloads"
        severity    = "critical"

    strings:
        $a = "certutil" nocase
        $b = "-decode" nocase
        $c = "Sub " nocase

    condition:
        $a and $b and $c
}

rule VBA_Sleep_Delay
{
    meta:
        description = "VBA macro uses sleep or delay — sandbox evasion technique"
        severity    = "medium"

    strings:
        $a = "Sleep" nocase
        $b = "Application.Wait" nocase
        $c = "kernel32" nocase
        $d = "Application.OnTime" nocase

    condition:
        2 of them
}


// ---------------------------------------------------------------------------
//  SECTION 2: OFFICE DDE / OLE / TEMPLATE INJECTION / EXPLOITS
// ---------------------------------------------------------------------------

rule Office_DDE_AutoLink
{
    meta:
        description = "Office document uses DDE or DDEAUTO for code execution"
        severity    = "critical"

    strings:
        $a = "DDEAUTO" nocase
        $b = "DDEAUTO" nocase wide

    condition:
        any of them
}

rule Office_OLE_Embedded_Object
{
    meta:
        description = "Document contains embedded OLE object control words"
        severity    = "high"

    strings:
        $a = "\\object" nocase
        $b = "\\objdata" nocase
        $c = "\\objemb" nocase
        $d = { D0 CF 11 E0 A1 B1 1A E1 }

    condition:
        $d and any of ($a, $b, $c)
}

rule Office_Remote_Template_Injection
{
    meta:
        description = "OOXML document references external template URL (template injection)"
        severity    = "critical"

    strings:
        $a = "attachedTemplate" nocase
        $b = "Target=\"http" nocase
        $c = "Target=\"https" nocase
        $d = "TargetMode=\"External\"" nocase

    condition:
        $a and ($b or $c or $d)
}

rule Office_External_OLE_Link
{
    meta:
        description = "OOXML document contains external OLE link (Follina-style or remote payload)"
        severity    = "critical"

    strings:
        $a = "oleObject" nocase
        $b = "External" nocase
        $c = "http" nocase

    condition:
        all of them
}

rule Office_Follina_MSDT
{
    meta:
        description = "Office document references ms-msdt protocol handler — Follina CVE-2022-30190"
        severity    = "critical"

    strings:
        $a = "ms-msdt:" nocase
        $b = "ms-msdt:/" nocase
        $c = "PCWDiagnostic" nocase
        $d = "IT_BrowseForFile" nocase

    condition:
        any of ($a, $b) or ($c and $d)
}

rule Office_Equation_Editor_CLSID
{
    meta:
        description = "Office document references Equation Editor CLSID — CVE-2017-11882 family"
        severity    = "critical"

    strings:
        $a = "0002CE02-0000-0000-C000-000000000046" nocase
        $b = "0002ce02" nocase
        $c = "Equation.3" nocase

    condition:
        any of them
}

rule Office_External_Relationship
{
    meta:
        description = "OOXML document has external relationship — may fetch remote content on open"
        severity    = "high"

    strings:
        $a = "TargetMode=\"External\"" nocase
        $b = "Target=\"http" nocase
        $c = "Target=\"https" nocase
        $d = "Target=\"file:" nocase
        $e = "Target=\"\\\\" nocase

    condition:
        $a and any of ($b, $c, $d, $e)
}

rule Office_ActiveX_Embedded
{
    meta:
        description = "OOXML document contains ActiveX control — can auto-execute code"
        severity    = "high"

    strings:
        $a = "activeX" nocase
        $b = "activeX1.xml" nocase
        $c = "activeX1.bin" nocase
        $d = "ocx" nocase

    condition:
        2 of them
}

rule Office_XLM_4_Macro
{
    meta:
        description = "Excel document uses XLM 4.0 macros (legacy macros, no VBA project needed)"
        severity    = "critical"

    strings:
        $a = "Excel 4.0 Macros" nocase
        $b = "xl/macrosheets" nocase
        $c = "EXEC(" nocase
        $d = "CALL(" nocase
        $e = "REGISTER(" nocase
        $f = "=ALERT(" nocase
        $g = "=HALT(" nocase
        $h = "Macro1" nocase

    condition:
        2 of them
}

rule Office_ExternalLink_Formula
{
    meta:
        description = "Office document contains external link formula — remote data fetch"
        severity    = "high"

    strings:
        $a = "WEBSERVICE(" nocase
        $b = "IMPORTDATA(" nocase
        $c = "FILTERXML(" nocase
        $d = "ENCODEURL(" nocase
        $e = "externalLink" nocase

    condition:
        any of them
}

rule Office_Encrypted_Content
{
    meta:
        description = "Office document is encrypted — may bypass AV/gateway scanning"
        severity    = "medium"

    strings:
        $a = "EncryptedPackage" wide
        $b = "StrongEncryptionDataSpace" wide
        $c = "EncryptionInfo" wide

    condition:
        any of them
}

rule Office_VBA_Stomping
{
    meta:
        description = "Office document has VBA p-code without matching source — VBA stomping technique"
        severity    = "critical"

    strings:
        $a = "_VBA_PROJECT" wide
        $b = "Attribute VB_"
        $c = "VBA_PROJECT_CUR" wide
        $d = "PROJECT" wide

    condition:
        $a and not $b and ($c or $d)
}


// ---------------------------------------------------------------------------
//  SECTION 3: PDF THREATS
// ---------------------------------------------------------------------------

rule PDF_JavaScript_Execution
{
    meta:
        description = "PDF contains JavaScript references — can be used for exploitation"
        severity    = "high"

    strings:
        $pdf = { 25 50 44 46 }
        $a = "/JavaScript"
        $b = "/JS "
        $c = "/JS("

    condition:
        $pdf and any of ($a, $b, $c)
}

rule PDF_AutoOpen_Action
{
    meta:
        description = "PDF uses OpenAction or Additional Actions to auto-execute on open"
        severity    = "high"

    strings:
        $pdf = { 25 50 44 46 }
        $a = "/OpenAction"
        $b = "/AA"

    condition:
        $pdf and ($a or $b)
}

rule PDF_Launch_Action
{
    meta:
        description = "PDF uses /Launch to execute external programs"
        severity    = "critical"

    strings:
        $pdf = { 25 50 44 46 }
        $a = "/Launch"

    condition:
        $pdf and $a
}

rule PDF_Embedded_File_Attachment
{
    meta:
        description = "PDF contains embedded file attachments — potential payload delivery"
        severity    = "medium"

    strings:
        $pdf = { 25 50 44 46 }
        $a = "/EmbeddedFile"
        $b = "/Filespec"

    condition:
        $pdf and ($a or $b)
}

rule PDF_Obfuscated_Stream
{
    meta:
        description = "PDF uses multiple unusual encoding filters — may hide malicious content"
        severity    = "medium"

    strings:
        $pdf = { 25 50 44 46 }
        $a = "/ASCIIHexDecode"
        $b = "/ASCII85Decode"
        $c = "/LZWDecode"
        $d = "/RunLengthDecode"

    condition:
        $pdf and 2 of ($a, $b, $c, $d)
}

rule PDF_SubmitForm_Action
{
    meta:
        description = "PDF uses /SubmitForm — can exfiltrate form data to external URL"
        severity    = "high"

    strings:
        $pdf = { 25 50 44 46 }
        $a = "/SubmitForm"

    condition:
        $pdf and $a
}

rule PDF_URI_Link
{
    meta:
        description = "PDF contains URI action — may redirect to phishing or malware site"
        severity    = "medium"

    strings:
        $pdf = { 25 50 44 46 }
        $a = "/URI"
        $b = "/S /URI"

    condition:
        $pdf and ($a or $b)
}

rule PDF_GoToR_Remote_Link
{
    meta:
        description = "PDF uses /GoToR to open a remote PDF — can chain to exploit"
        severity    = "high"

    strings:
        $pdf = { 25 50 44 46 }
        $a = "/GoToR"
        $b = "/GoToE"

    condition:
        $pdf and ($a or $b)
}

rule PDF_XFA_Form
{
    meta:
        description = "PDF contains XFA forms — complex attack surface, historically exploited"
        severity    = "high"

    strings:
        $pdf = { 25 50 44 46 }
        $a = "/XFA"
        $b = "xdp:xdp" nocase
        $c = "xfa:data" nocase

    condition:
        $pdf and any of ($a, $b, $c)
}

rule PDF_Encrypted_Content
{
    meta:
        description = "PDF is encrypted — may bypass content scanning by email gateways"
        severity    = "medium"

    strings:
        $pdf = { 25 50 44 46 }
        $a = "/Encrypt"

    condition:
        $pdf and $a
}

rule PDF_Phishing_QR_Code_Indicators
{
    meta:
        description = "PDF likely contains only an image — possible QR code phishing (quishing)"
        severity    = "medium"

    strings:
        $pdf = { 25 50 44 46 }
        $a = "/Image"
        $b = "/XObject"
        $c = "/Subtype /Image"

    condition:
        $pdf and ($a and $b and $c)
}


// ---------------------------------------------------------------------------
//  SECTION 4: RTF EXPLOITS
// ---------------------------------------------------------------------------

rule RTF_Embedded_Object
{
    meta:
        description = "RTF document contains embedded OLE object"
        severity    = "high"

    strings:
        $rtf = "{\\rtf"
        $a = "{\\object"
        $b = "\\objdata"
        $c = "\\objemb"

    condition:
        $rtf and any of ($a, $b, $c)
}

rule RTF_Equation_Editor_Exploit
{
    meta:
        description = "RTF references Equation Editor CLSID — CVE-2017-11882 / CVE-2018-0802"
        severity    = "critical"

    strings:
        $rtf = "{\\rtf"
        $clsid = "0002ce02" nocase

    condition:
        $rtf and $clsid
}

rule RTF_Obfuscated_Header
{
    meta:
        description = "RTF with heavy obfuscation — absurdly long control words or hex escapes"
        severity    = "high"

    strings:
        $rtf = "{\\rtf"
        $junk1 = /\{\\[a-z]{20,}/
        $junk2 = /\\'\w\w\\'\w\w\\'\w\w\\'\w\w/

    condition:
        $rtf and ($junk1 or $junk2)
}

rule RTF_Large_Hex_Blob
{
    meta:
        description = "RTF with very large hex-encoded data blob — likely embedded payload"
        severity    = "high"

    strings:
        $rtf = "{\\rtf"
        $a = "\\objdata"
        $hex = /[0-9a-fA-F]{500,}/

    condition:
        $rtf and $a and $hex
}

rule RTF_Package_Object
{
    meta:
        description = "RTF contains packager shell object — drops files to disk"
        severity    = "critical"

    strings:
        $rtf = "{\\rtf"
        $a = "Package" nocase
        $b = "\\object"
        $c = "OLE2Link" nocase

    condition:
        $rtf and 2 of ($a, $b, $c)
}


// ---------------------------------------------------------------------------
//  SECTION 5: HTA FILES (HTML Application)
// ---------------------------------------------------------------------------

rule HTA_File_With_Script
{
    meta:
        description = "HTA file with script block and execution capability"
        severity    = "critical"

    strings:
        $hta = "<HTA:APPLICATION" nocase
        $script = "<script" nocase
        $vbs = "VBScript" nocase
        $js = "JScript" nocase
        $ps = "powershell" nocase
        $shell = "WScript.Shell" nocase
        $exec = "Run(" nocase

    condition:
        $hta and ($script or $vbs or $js) and ($ps or $shell or $exec)
}

rule HTA_Download_Execute
{
    meta:
        description = "HTA downloads and executes a remote payload"
        severity    = "critical"

    strings:
        $hta = "<HTA:APPLICATION" nocase
        $dl1 = "MSXML2.XMLHTTP" nocase
        $dl2 = "Microsoft.XMLHTTP" nocase
        $dl3 = "WinHttp" nocase
        $dl4 = "URLDownloadToFile" nocase
        $dl5 = "Net.WebClient" nocase
        $save = "SaveToFile" nocase
        $stream = "ADODB.Stream" nocase

    condition:
        $hta and ($dl1 or $dl2 or $dl3 or $dl4 or $dl5 or ($save and $stream))
}

rule HTA_Any_Presence
{
    meta:
        description = "File contains HTA application tag — always suspicious as email attachment"
        severity    = "high"

    strings:
        $a = "<HTA:APPLICATION" nocase

    condition:
        $a
}

rule HTA_MSHTA_Inline_Script
{
    meta:
        description = "HTA invoked with mshta inline vbscript or javascript — fileless delivery"
        severity    = "critical"

    strings:
        $a = "mshta" nocase
        $b = "vbscript:Execute" nocase
        $c = "javascript:" nocase
        $d = "vbscript:Close" nocase

    condition:
        $a and any of ($b, $c, $d)
}


// ---------------------------------------------------------------------------
//  SECTION 6: URL SHORTCUT FILES
// ---------------------------------------------------------------------------

rule URL_Shortcut_Suspicious
{
    meta:
        description = "Windows .url shortcut with SMB reference or remote icon (credential theft)"
        severity    = "high"

    strings:
        $header = "[InternetShortcut]"
        $url = "URL="
        $smb = "file://" nocase
        $icon = "IconFile="

    condition:
        $header and $url and ($smb or $icon)
}

rule URL_Shortcut_UNC_Icon
{
    meta:
        description = "URL shortcut with UNC path icon reference — NTLM hash theft via SMB"
        severity    = "critical"

    strings:
        $header = "[InternetShortcut]"
        $icon = /IconFile=\\\\[^\r\n]+/

    condition:
        $header and $icon
}

rule URL_Shortcut_Any_Presence
{
    meta:
        description = "Any .url internet shortcut file — uncommon as legitimate email attachment"
        severity    = "medium"

    strings:
        $a = "[InternetShortcut]"
        $b = "URL="

    condition:
        $a and $b
}

rule URL_Shortcut_To_Script_Handler
{
    meta:
        description = "URL shortcut pointing to script protocol handler (javascript/vbscript/mshta)"
        severity    = "critical"

    strings:
        $header = "[InternetShortcut]"
        $a = "URL=javascript:" nocase
        $b = "URL=vbscript:" nocase
        $c = "URL=mshta" nocase
        $d = "URL=file:" nocase

    condition:
        $header and any of ($a, $b, $c, $d)
}


// ---------------------------------------------------------------------------
//  SECTION 7: LNK (Windows Shortcut) FILES
// ---------------------------------------------------------------------------

rule LNK_Suspicious_CommandLine
{
    meta:
        description = "LNK shortcut with references to suspicious LOLBins (PowerShell, cmd, mshta, etc.)"
        severity    = "critical"

    strings:
        $lnk = { 4C 00 00 00 }
        $a = "cmd" nocase wide
        $b = "powershell" nocase wide
        $c = "mshta" nocase wide
        $d = "wscript" nocase wide
        $e = "cscript" nocase wide
        $f = "rundll32" nocase wide
        $g = "regsvr32" nocase wide
        $h = "certutil" nocase wide
        $i = "bitsadmin" nocase wide
        $j = "msiexec" nocase wide

    condition:
        $lnk and any of ($a, $b, $c, $d, $e, $f, $g, $h, $i, $j)
}

rule LNK_Double_Extension
{
    meta:
        description = "LNK file containing a double-extension string — file masquerade technique"
        severity    = "high"

    strings:
        $lnk = { 4C 00 00 00 }
        $a = ".pdf.lnk" nocase wide
        $b = ".doc.lnk" nocase wide
        $c = ".xlsx.lnk" nocase wide
        $d = ".jpg.lnk" nocase wide
        $e = ".png.lnk" nocase wide
        $f = ".txt.lnk" nocase wide

    condition:
        $lnk and any of ($a, $b, $c, $d, $e, $f)
}

rule LNK_Extended_LOLBins
{
    meta:
        description = "LNK shortcut references less common LOLBins — forfiles, pcalua, explorer abuse"
        severity    = "critical"

    strings:
        $lnk = { 4C 00 00 00 }
        $a = "forfiles" nocase wide
        $b = "pcalua" nocase wide
        $c = "explorer.exe" nocase wide
        $d = "control.exe" nocase wide
        $e = "msconfig" nocase wide
        $f = "fodhelper" nocase wide
        $g = "SyncAppvPublishingServer" nocase wide
        $h = "InstallUtil" nocase wide
        $i = "MSBuild" nocase wide
        $j = "xwizard" nocase wide

    condition:
        $lnk and any of ($a, $b, $c, $d, $e, $f, $g, $h, $i, $j)
}

rule LNK_Script_Target
{
    meta:
        description = "LNK shortcut targets a script file directly (.js, .vbs, .hta, .bat, .ps1)"
        severity    = "critical"

    strings:
        $lnk = { 4C 00 00 00 }
        $a = ".js" nocase wide
        $b = ".jse" nocase wide
        $c = ".vbs" nocase wide
        $d = ".vbe" nocase wide
        $e = ".hta" nocase wide
        $f = ".bat" nocase wide
        $g = ".cmd" nocase wide
        $h = ".ps1" nocase wide
        $i = ".wsf" nocase wide

    condition:
        $lnk and any of ($a, $b, $c, $d, $e, $f, $g, $h, $i)
}

rule LNK_Environment_Variable_Abuse
{
    meta:
        description = "LNK shortcut uses environment variable paths — evasion of static path analysis"
        severity    = "high"

    strings:
        $lnk = { 4C 00 00 00 }
        $a = "%APPDATA%" nocase wide
        $b = "%TEMP%" nocase wide
        $c = "%USERPROFILE%" nocase wide
        $d = "%PUBLIC%" nocase wide
        $e = "%COMSPEC%" nocase wide
        $f = "%SYSTEMROOT%" nocase wide

    condition:
        $lnk and any of ($a, $b, $c, $d, $e, $f)
}


// ---------------------------------------------------------------------------
//  SECTION 8: JAVASCRIPT / JSCRIPT DROPPERS (.js / .jse)
// ---------------------------------------------------------------------------

rule JS_WSH_Dropper
{
    meta:
        description = "JavaScript uses Windows Script Host objects with execution capability"
        severity    = "critical"

    strings:
        $wsh1 = "WScript.Shell" nocase
        $wsh2 = "WScript.CreateObject" nocase
        $wsh3 = "Scripting.FileSystemObject" nocase
        $wsh4 = "MSXML2.XMLHTTP" nocase
        $wsh5 = "ADODB.Stream" nocase
        $wsh6 = "Shell.Application" nocase
        $wsh7 = "ActiveXObject" nocase
        $act1 = ".Run(" nocase
        $act2 = ".Exec(" nocase
        $act3 = ".ShellExecute" nocase
        $act4 = "SaveToFile" nocase

    condition:
        2 of ($wsh1, $wsh2, $wsh3, $wsh4, $wsh5, $wsh6, $wsh7) and ($act1 or $act2 or $act3 or $act4)
}

rule JS_Obfuscated_Payload
{
    meta:
        description = "Heavily obfuscated JavaScript — charCode loops, eval, or large encoded arrays"
        severity    = "high"

    strings:
        $cc1 = "fromCharCode" nocase
        $cc2 = "String.fromCharCode" nocase
        $cc3 = "charCodeAt" nocase
        $eval = "eval("
        $func = "Function("
        $arr = /\[\d{2,3}(,\d{2,3}){20,}\]/
        $split = /\"[^\"]{50,}\"\.split\(/

    condition:
        (($cc1 or $cc2 or $cc3) and ($eval or $func)) or $arr or $split
}

rule JS_Encoded_Script_JSE
{
    meta:
        description = "JScript.Encode encoded script file (JSE format marker)"
        severity    = "high"

    strings:
        $jse = "#@~^"

    condition:
        $jse
}

rule JS_WMI_Execution
{
    meta:
        description = "JavaScript uses WMI to execute processes — evasion of direct Shell calls"
        severity    = "critical"

    strings:
        $a = "GetObject" nocase
        $b = "winmgmts" nocase
        $c = "Win32_Process" nocase
        $d = "Create(" nocase

    condition:
        $a and $b and ($c or $d)
}

rule JS_Clipboard_Paste_Lure
{
    meta:
        description = "JavaScript or HTML uses clipboard manipulation — paste-jacking attack"
        severity    = "high"

    strings:
        $a = "navigator.clipboard" nocase
        $b = "document.execCommand" nocase
        $c = "clipboardData" nocase
        $d = "writeText" nocase

    condition:
        2 of them
}

rule JS_Deobfuscation_Heavy
{
    meta:
        description = "JavaScript uses multiple layers of encoding — base64, unescape, decode chains"
        severity    = "high"

    strings:
        $a = "atob(" nocase
        $b = "btoa(" nocase
        $c = "unescape(" nocase
        $d = "decodeURIComponent(" nocase
        $e = "String.fromCharCode" nocase
        $f = "eval(" nocase
        $g = "Function(" nocase

    condition:
        3 of them
}


// ---------------------------------------------------------------------------
//  SECTION 9: VBScript DROPPERS (.vbs / .vbe / .wsf)
// ---------------------------------------------------------------------------

rule VBS_Download_Execute
{
    meta:
        description = "VBScript downloads remote content and executes or saves it"
        severity    = "critical"

    strings:
        $http1 = "MSXML2.XMLHTTP" nocase
        $http2 = "WinHttp.WinHttpRequest" nocase
        $http3 = "Microsoft.XMLHTTP" nocase
        $save1 = "ADODB.Stream" nocase
        $save2 = "SaveToFile" nocase
        $save3 = "ResponseBody" nocase
        $exec1 = "WScript.Shell" nocase
        $exec2 = ".Run " nocase

    condition:
        ($http1 or $http2 or $http3) and ($save1 or $save2 or $save3 or $exec1 or $exec2)
}

rule WSF_MultiEngine_Script
{
    meta:
        description = "Windows Script File (.wsf) with embedded script — bypasses script policy"
        severity    = "high"

    strings:
        $a = "<job" nocase
        $b = "<script" nocase
        $c = "language=" nocase
        $d = "WScript" nocase

    condition:
        $a and $b and ($c or $d)
}

rule VBS_Registry_Persistence
{
    meta:
        description = "VBScript writes registry Run keys for persistence"
        severity    = "critical"

    strings:
        $a = "RegWrite" nocase
        $b = "CurrentVersion\\Run" nocase
        $c = "WScript.Shell" nocase

    condition:
        $a and ($b or $c)
}

rule VBS_Scheduled_Task
{
    meta:
        description = "VBScript creates scheduled tasks for persistence or delayed execution"
        severity    = "critical"

    strings:
        $a = "Schedule.Service" nocase
        $b = "schtasks" nocase
        $c = "RegisterTaskDefinition" nocase
        $d = "WScript.Shell" nocase

    condition:
        ($a or $b or $c) and $d
}

rule VBS_Encoded_VBE
{
    meta:
        description = "VBScript.Encode encoded file (VBE format marker)"
        severity    = "high"

    strings:
        $a = "#@~^"
        $b = "VBScript.Encode" nocase

    condition:
        any of them
}

rule VBS_Obfuscation_ChrW
{
    meta:
        description = "VBScript uses heavy ChrW/Chr obfuscation to build strings dynamically"
        severity    = "high"

    strings:
        $a = "ChrW(" nocase
        $b = "Chr(" nocase
        $c = "Execute(" nocase
        $d = "ExecuteGlobal(" nocase

    condition:
        ($a or $b) and ($c or $d)
}


// ---------------------------------------------------------------------------
//  SECTION 10: ZIP / RAR / 7Z ARCHIVES CONTAINING DANGEROUS FILES
// ---------------------------------------------------------------------------

rule ZIP_Contains_Script_File
{
    meta:
        description = "ZIP archive contains scripting files (.js/.vbs/.wsf/.hta/.bat/.cmd/.ps1)"
        severity    = "critical"

    strings:
        $pk = { 50 4B 03 04 }
        $a = ".js" fullword
        $b = ".jse" fullword
        $c = ".vbs" fullword
        $d = ".vbe" fullword
        $e = ".wsf" fullword
        $f = ".hta" fullword
        $g = ".bat" fullword
        $h = ".cmd" fullword
        $i = ".ps1" fullword

    condition:
        $pk and any of ($a, $b, $c, $d, $e, $f, $g, $h, $i)
}

rule ZIP_Contains_LNK
{
    meta:
        description = "ZIP archive contains Windows shortcut (.lnk) — masquerade delivery"
        severity    = "critical"

    strings:
        $pk = { 50 4B 03 04 }
        $a = ".lnk" fullword

    condition:
        $pk and $a
}

rule ZIP_Contains_URL_Shortcut
{
    meta:
        description = "ZIP archive contains .url shortcut file — uncommon, likely phishing"
        severity    = "critical"

    strings:
        $pk = { 50 4B 03 04 }
        $a = ".url" fullword

    condition:
        $pk and $a
}

rule ZIP_Contains_ISO_IMG
{
    meta:
        description = "ZIP archive contains disk image (.iso/.img/.vhd/.vhdx) — MotW bypass nesting"
        severity    = "critical"

    strings:
        $pk = { 50 4B 03 04 }
        $a = ".iso" fullword
        $b = ".img" fullword
        $c = ".vhd" fullword
        $d = ".vhdx" fullword

    condition:
        $pk and any of ($a, $b, $c, $d)
}

rule ZIP_Contains_Office_Macro_File
{
    meta:
        description = "ZIP contains macro-enabled Office document (.docm/.xlsm/.pptm/.xlsb)"
        severity    = "high"

    strings:
        $pk = { 50 4B 03 04 }
        $a = ".docm" fullword
        $b = ".xlsm" fullword
        $c = ".pptm" fullword
        $d = ".xlsb" fullword
        $e = ".dotm" fullword

    condition:
        $pk and any of ($a, $b, $c, $d, $e)
}

rule ZIP_Contains_HTA
{
    meta:
        description = "ZIP archive contains an HTA file — strong phishing indicator"
        severity    = "critical"

    strings:
        $pk = { 50 4B 03 04 }
        $a = ".hta" fullword

    condition:
        $pk and $a
}

rule ZIP_Contains_MSI
{
    meta:
        description = "ZIP archive contains an MSI installer — uncommon as email attachment"
        severity    = "high"

    strings:
        $pk = { 50 4B 03 04 }
        $a = ".msi" fullword

    condition:
        $pk and $a
}

rule RAR_Archive_Header
{
    meta:
        description = "RAR archive detected — commonly used phishing delivery wrapper"
        severity    = "medium"

    strings:
        $rar4 = { 52 61 72 21 1A 07 00 }
        $rar5 = { 52 61 72 21 1A 07 01 00 }

    condition:
        $rar4 or $rar5
}

rule SevenZip_Archive_Header
{
    meta:
        description = "7-Zip archive detected — sometimes used to bypass gateway extension filters"
        severity    = "medium"

    strings:
        $a = { 37 7A BC AF 27 1C }

    condition:
        $a
}

rule Archive_Double_Extension
{
    meta:
        description = "Archive file contains a double-extension filename — masquerade attempt"
        severity    = "critical"

    strings:
        $pk = { 50 4B 03 04 }
        $a = ".pdf.js" nocase
        $b = ".doc.vbs" nocase
        $c = ".xlsx.js" nocase
        $d = ".pdf.bat" nocase
        $e = ".doc.hta" nocase
        $f = ".jpg.js" nocase
        $g = ".pdf.vbs" nocase
        $h = ".doc.bat" nocase
        $i = ".pdf.ps1" nocase
        $j = ".txt.js" nocase
        $k = ".pdf.wsf" nocase
        $l = ".xls.hta" nocase

    condition:
        $pk and any of ($a, $b, $c, $d, $e, $f, $g, $h, $i, $j, $k, $l)
}


// ---------------------------------------------------------------------------
//  SECTION 11: POWERSHELL PAYLOADS
// ---------------------------------------------------------------------------

rule PowerShell_Encoded_Command
{
    meta:
        description = "PowerShell invoked with encoded command flag — hides base64 payload"
        severity    = "critical"

    strings:
        $ps = "powershell" nocase
        $a = "-EncodedCommand" nocase
        $b = "-enc " nocase
        $c = "-ec " nocase

    condition:
        $ps and ($a or $b or $c)
}

rule PowerShell_Download_Cradle
{
    meta:
        description = "PowerShell download cradle — fetches and executes remote code"
        severity    = "critical"

    strings:
        $iex1 = "Invoke-Expression" nocase
        $iex2 = "IEX"
        $iex3 = "iex " nocase
        $dl1 = "DownloadString" nocase
        $dl2 = "DownloadFile" nocase
        $dl3 = "Invoke-WebRequest" nocase
        $dl4 = "Net.WebClient" nocase
        $dl5 = "Start-BitsTransfer" nocase
        $dl6 = "Invoke-RestMethod" nocase

    condition:
        ($iex1 or $iex2 or $iex3) and ($dl1 or $dl2 or $dl3 or $dl4 or $dl5 or $dl6)
}

rule PowerShell_AMSI_Bypass
{
    meta:
        description = "PowerShell attempts to bypass AMSI (Antimalware Scan Interface)"
        severity    = "critical"

    strings:
        $a = "AmsiUtils" nocase
        $b = "amsiInitFailed" nocase
        $c = "AmsiScanBuffer" nocase

    condition:
        any of them
}

rule PowerShell_Reflective_Load
{
    meta:
        description = "PowerShell reflectively loads .NET assembly or PE — fileless attack"
        severity    = "critical"

    strings:
        $a = "Reflection.Assembly" nocase
        $b = "Assembly]::Load" nocase
        $c = "LoadWithPartialName" nocase
        $d = "FromBase64String" nocase
        $e = "MemoryStream" nocase
        $f = "GZipStream" nocase

    condition:
        2 of them
}

rule PowerShell_Execution_Policy_Bypass
{
    meta:
        description = "PowerShell bypasses execution policy — allows unsigned scripts to run"
        severity    = "high"

    strings:
        $a = "-ExecutionPolicy" nocase
        $b = "Bypass" nocase
        $c = "Unrestricted" nocase
        $d = "-ep " nocase
        $e = "Set-ExecutionPolicy" nocase

    condition:
        ($a and ($b or $c)) or ($d and ($b or $c)) or $e
}

rule PowerShell_Hidden_Window
{
    meta:
        description = "PowerShell runs with hidden window — user won't see execution"
        severity    = "high"

    strings:
        $a = "-WindowStyle" nocase
        $b = "Hidden" nocase
        $c = "-w hidden" nocase
        $d = "-win hidden" nocase
        $e = "-nop" nocase

    condition:
        ($a and $b) or $c or $d
}

rule PowerShell_Credential_Theft
{
    meta:
        description = "PowerShell accesses stored credentials or prompts for credentials"
        severity    = "critical"

    strings:
        $a = "Get-Credential" nocase
        $b = "CredentialCache" nocase
        $c = "SecureString" nocase
        $d = "ConvertTo-SecureString" nocase
        $e = "NetworkCredential" nocase

    condition:
        2 of them
}

rule PowerShell_Certutil_Combo
{
    meta:
        description = "PowerShell combined with certutil — decode and execute pattern"
        severity    = "critical"

    strings:
        $a = "certutil" nocase
        $b = "-decode" nocase
        $c = "powershell" nocase

    condition:
        $a and $b and $c
}


// ---------------------------------------------------------------------------
//  SECTION 12: EMBEDDED PE IN NON-EXECUTABLE
// ---------------------------------------------------------------------------

rule Embedded_PE_Header
{
    meta:
        description = "File contains an embedded MZ PE header — hidden executable inside document"
        severity    = "critical"

    strings:
        $mz = { 4D 5A 90 00 }

    condition:
        $mz
}


// ---------------------------------------------------------------------------
//  SECTION 13: ISO / IMG / VHD DISK IMAGES (MotW bypass)
// ---------------------------------------------------------------------------

rule ISO_IMG_Disk_Image
{
    meta:
        description = "ISO 9660 disk image — used to bypass Mark-of-the-Web protections"
        severity    = "high"

    strings:
        $iso = "CD001"

    condition:
        $iso
}

rule VHD_Disk_Image
{
    meta:
        description = "VHD/VHDX virtual disk image — MotW bypass, mounts as drive on double-click"
        severity    = "high"

    strings:
        $a = "conectix"
        $b = "vhdxfile"

    condition:
        any of them
}


// ---------------------------------------------------------------------------
//  SECTION 14: ONENOTE EMBEDDED FILES
// ---------------------------------------------------------------------------

rule OneNote_Embedded_Script
{
    meta:
        description = "OneNote file with embedded script or executable file references"
        severity    = "critical"

    strings:
        $magic = { E4 52 5C 7B 8C D8 A7 4D }
        $a = ".bat" wide
        $b = ".cmd" wide
        $c = ".hta" wide
        $d = ".vbs" wide
        $e = ".js" wide
        $f = ".ps1" wide
        $g = ".exe" wide
        $h = ".wsf" wide

    condition:
        $magic and any of ($a, $b, $c, $d, $e, $f, $g, $h)
}

rule OneNote_Any_Embedded_File
{
    meta:
        description = "OneNote file with any embedded file attachment — review for payloads"
        severity    = "high"

    strings:
        $magic = { E4 52 5C 7B 8C D8 A7 4D }
        $a = { 00 00 00 00 E7 16 E3 BD }

    condition:
        $magic and $a
}


// ---------------------------------------------------------------------------
//  SECTION 15: SVG WITH EMBEDDED SCRIPT
// ---------------------------------------------------------------------------

rule SVG_Embedded_Script
{
    meta:
        description = "SVG image containing embedded JavaScript or event handlers"
        severity    = "high"

    strings:
        $svg = "<svg" nocase
        $a = "<script" nocase
        $b = "onload=" nocase
        $c = "onerror=" nocase
        $d = "onclick=" nocase
        $e = "<foreignObject" nocase

    condition:
        $svg and ($a or $b or $c or $d or $e)
}

rule SVG_Redirect_Phish
{
    meta:
        description = "SVG image with embedded link or meta redirect — phishing lure disguised as image"
        severity    = "high"

    strings:
        $svg = "<svg" nocase
        $a = "<a " nocase
        $b = "href=" nocase
        $c = "xlink:href=" nocase
        $d = "http-equiv=\"refresh\"" nocase

    condition:
        $svg and 2 of ($a, $b, $c, $d)
}

rule SVG_Base64_Embedded_Content
{
    meta:
        description = "SVG with large base64 data URI — may smuggle hidden content"
        severity    = "high"

    strings:
        $svg = "<svg" nocase
        $a = "data:text/html;base64" nocase
        $b = "data:application" nocase
        $c = "data:image/svg+xml;base64" nocase

    condition:
        $svg and any of ($a, $b, $c)
}


// ---------------------------------------------------------------------------
//  SECTION 16: HTML SMUGGLING / PHISHING
// ---------------------------------------------------------------------------

rule HTML_Smuggling
{
    meta:
        description = "HTML file using blob/download smuggling to deliver hidden payload"
        severity    = "critical"

    strings:
        $a = "new Blob" nocase
        $b = "URL.createObjectURL" nocase
        $c = "msSaveOrOpenBlob" nocase
        $d = "download=" nocase
        $e = ".click()"
        $f = "atob("
        $g = "Uint8Array"

    condition:
        3 of them
}

rule HTML_Credential_Phish_Form
{
    meta:
        description = "HTML file with password input and brand impersonation or external form action"
        severity    = "high"

    strings:
        $form = "<form" nocase
        $pwd1 = "type=\"password\"" nocase
        $pwd2 = "type='password'" nocase
        $act1 = "action=\"http" nocase
        $act2 = "action='http" nocase
        $brand1 = "Microsoft" nocase
        $brand2 = "Office 365" nocase
        $brand3 = "SharePoint" nocase
        $brand4 = "OneDrive" nocase
        $brand5 = "Adobe" nocase
        $brand6 = "DocuSign" nocase
        $brand7 = "Google" nocase

    condition:
        $form and ($pwd1 or $pwd2) and ($act1 or $act2 or $brand1 or $brand2 or $brand3 or $brand4 or $brand5 or $brand6 or $brand7)
}

rule HTML_Meta_Redirect_Phish
{
    meta:
        description = "HTML file with meta refresh redirect — used in phishing redirectors"
        severity    = "high"

    strings:
        $a = "http-equiv=\"refresh\"" nocase
        $b = "http-equiv='refresh'" nocase
        $c = "url=" nocase
        $d = "<meta" nocase

    condition:
        ($a or $b) and $c and $d
}

rule HTML_JavaScript_Redirect
{
    meta:
        description = "HTML with JavaScript redirect — common phishing redirector technique"
        severity    = "high"

    strings:
        $a = "window.location" nocase
        $b = "location.href" nocase
        $c = "location.replace" nocase
        $d = "document.location" nocase
        $e = "<script" nocase

    condition:
        $e and any of ($a, $b, $c, $d)
}

rule HTML_Obfuscated_Phish_Page
{
    meta:
        description = "HTML page with heavy obfuscation — typical of advanced phishing kits"
        severity    = "critical"

    strings:
        $a = "atob(" nocase
        $b = "String.fromCharCode" nocase
        $c = "unescape(" nocase
        $d = "document.write(" nocase
        $e = "eval(" nocase
        $f = "type=\"password\"" nocase
        $g = "type='password'" nocase

    condition:
        ($f or $g) and 2 of ($a, $b, $c, $d, $e)
}

rule HTML_Invisible_Iframe
{
    meta:
        description = "HTML page with hidden/invisible iframe — clickjacking or silent redirect"
        severity    = "high"

    strings:
        $a = "<iframe" nocase
        $b = "display:none" nocase
        $c = "visibility:hidden" nocase
        $d = "width=\"0\"" nocase
        $e = "height=\"0\"" nocase
        $f = "width:0" nocase
        $g = "height:0" nocase

    condition:
        $a and any of ($b, $c, $d, $e, $f, $g)
}

rule HTML_Captcha_Phish_Gate
{
    meta:
        description = "HTML phishing page with fake CAPTCHA gate — delays analysis, builds trust"
        severity    = "high"

    strings:
        $a = "captcha" nocase
        $b = "verify" nocase
        $c = "human" nocase
        $d = "type=\"password\"" nocase
        $e = "robot" nocase

    condition:
        3 of them
}

rule HTML_LocalStorage_Exfil
{
    meta:
        description = "HTML phishing page accesses localStorage or sessionStorage — credential caching"
        severity    = "medium"

    strings:
        $a = "localStorage" nocase
        $b = "sessionStorage" nocase
        $c = "setItem" nocase
        $d = "getItem" nocase
        $e = "password" nocase

    condition:
        ($a or $b) and ($c or $d) and $e
}

rule HTML_Data_URI_Payload
{
    meta:
        description = "HTML file uses data URI to embed executable or script content"
        severity    = "high"

    strings:
        $a = "data:text/html;base64" nocase
        $b = "data:application/x-javascript" nocase
        $c = "data:application/octet-stream" nocase
        $d = "data:text/javascript" nocase

    condition:
        any of them
}

rule HTML_WebSocket_Exfil
{
    meta:
        description = "HTML page opens WebSocket connection — potential credential exfiltration channel"
        severity    = "medium"

    strings:
        $a = "new WebSocket" nocase
        $b = "wss://" nocase
        $c = "ws://" nocase
        $d = "password" nocase

    condition:
        ($a or $b or $c) and $d
}


// ---------------------------------------------------------------------------
//  SECTION 17: MSI / MSIX INSTALLERS
// ---------------------------------------------------------------------------

rule MSI_Installer_Suspicious
{
    meta:
        description = "MSI Windows Installer — uncommon as legitimate email attachment"
        severity    = "high"

    strings:
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $a = "SummaryInformation" wide
        $b = "InstallExecuteSequence" wide
        $c = "CustomAction" wide

    condition:
        $ole and any of ($a, $b, $c)
}

rule MSIX_APPX_Installer
{
    meta:
        description = "MSIX/APPX package — abused for sideloading malware via ms-appinstaller"
        severity    = "high"

    strings:
        $pk = { 50 4B 03 04 }
        $a = "AppxManifest.xml" nocase
        $b = "AppxBlockMap.xml" nocase
        $c = "AppxSignature" nocase

    condition:
        $pk and any of ($a, $b, $c)
}


// ---------------------------------------------------------------------------
//  SECTION 18: IQY / SLK / CSV FORMULA INJECTION
// ---------------------------------------------------------------------------

rule IQY_Web_Query_File
{
    meta:
        description = "IQY web query file — fetches remote data into Excel, abused for C2"
        severity    = "critical"

    strings:
        $a = "WEB" nocase
        $b = "http" nocase
        $c = "1"

    condition:
        all of them
}

rule SLK_Symbolic_Link_File
{
    meta:
        description = "SLK (Symbolic Link) spreadsheet file — legacy format that bypasses macro blocks"
        severity    = "high"

    strings:
        $a = "ID;P" nocase

    condition:
        $a
}

rule CSV_Formula_Injection
{
    meta:
        description = "CSV file with formula injection — payloads execute when opened in Excel"
        severity    = "high"

    strings:
        $a = "=CMD(" nocase
        $b = "=EXEC(" nocase
        $c = "=SYSTEM(" nocase
        $d = /^=[A-Z]+\(/ nocase
        $e = "+cmd" nocase
        $f = "-cmd" nocase
        $g = "@SUM(" nocase
        $h = "=HYPERLINK(" nocase

    condition:
        any of ($a, $b, $c, $e, $f) or ($d and ($g or $h))
}


// ---------------------------------------------------------------------------
//  SECTION 19: WINDOWS SCRIPT / BATCH PATTERNS
// ---------------------------------------------------------------------------

rule BAT_Download_Execute
{
    meta:
        description = "Batch file downloads and executes a remote payload"
        severity    = "critical"

    strings:
        $a = "certutil" nocase
        $b = "bitsadmin" nocase
        $c = "powershell" nocase
        $d = "curl " nocase
        $e = "wget " nocase
        $f = "-decode" nocase
        $g = "/transfer" nocase
        $h = "start " nocase
        $i = "call " nocase

    condition:
        any of ($a, $b, $c, $d, $e) and any of ($f, $g, $h, $i)
}

rule BAT_Obfuscated_Variables
{
    meta:
        description = "Batch file uses variable obfuscation — environment variable substring abuse"
        severity    = "high"

    strings:
        $a = /\%[a-zA-Z]+:~\d+,\d+\%/
        $b = "set " nocase
        $c = "call " nocase

    condition:
        $a and ($b or $c)
}

rule BAT_Recursive_Copy_Drop
{
    meta:
        description = "Batch file copies or moves files from temp paths — payload staging"
        severity    = "high"

    strings:
        $a = "copy " nocase
        $b = "move " nocase
        $c = "xcopy" nocase
        $d = "%TEMP%" nocase
        $e = "%APPDATA%" nocase
        $f = "%USERPROFILE%" nocase
        $g = "%PUBLIC%" nocase

    condition:
        any of ($a, $b, $c) and any of ($d, $e, $f, $g)
}

rule BAT_Registry_Persistence
{
    meta:
        description = "Batch file modifies registry Run keys for persistence"
        severity    = "critical"

    strings:
        $a = "reg add" nocase
        $b = "CurrentVersion\\Run" nocase
        $c = "reg.exe" nocase

    condition:
        ($a or $c) and $b
}


// ---------------------------------------------------------------------------
//  SECTION 20: CREDENTIAL HARVESTING / NTLM THEFT PATTERNS
// ---------------------------------------------------------------------------

rule UNC_Path_NTLM_Theft
{
    meta:
        description = "File contains UNC path reference — may trigger NTLM authentication to attacker"
        severity    = "high"

    strings:
        $a = /\\\\[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\\/
        $b = /\\\\[a-zA-Z0-9\-]+\.[a-z]{2,4}\\/

    condition:
        any of them
}

rule WebDAV_Reference
{
    meta:
        description = "File references WebDAV path — can fetch remote payloads or steal NTLM hashes"
        severity    = "high"

    strings:
        $a = "\\\\DavWWWRoot\\" nocase
        $b = "\\DavWWWRoot\\" nocase
        $c = "@SSL\\DavWWWRoot" nocase

    condition:
        any of them
}


// ---------------------------------------------------------------------------
//  SECTION 21: EMAIL ATTACHMENT ANOMALIES (General)
// ---------------------------------------------------------------------------

rule Double_Extension_Any_File
{
    meta:
        description = "File with double extension pattern in its content — masquerade attempt"
        severity    = "high"

    strings:
        $a = ".pdf.hta" nocase
        $b = ".doc.js" nocase
        $c = ".xls.vbs" nocase
        $d = ".jpg.js" nocase
        $e = ".png.bat" nocase
        $f = ".txt.cmd" nocase
        $g = ".pdf.wsf" nocase
        $h = ".doc.cmd" nocase
        $i = ".xls.hta" nocase
        $j = ".jpg.vbs" nocase
        $k = ".pdf.bat" nocase
        $l = ".doc.ps1" nocase

    condition:
        any of them
}

rule Right_To_Left_Override
{
    meta:
        description = "File contains Right-to-Left Override character — filename spoofing technique"
        severity    = "critical"

    strings:
        $a = { E2 80 AE }
        $b = { FE FF 20 2E }

    condition:
        any of them
}

rule CMSTP_INF_Bypass
{
    meta:
        description = "INF file designed for CMSTP.exe bypass — UAC evasion via connection manager"
        severity    = "critical"

    strings:
        $a = "[version]" nocase
        $b = "CMSTP" nocase
        $c = "RegisterOCXSection" nocase
        $d = "UnRegisterOCXSection" nocase
        $e = "RunPreSetupCommandsSection" nocase

    condition:
        $a and ($b or $c or $d or $e)
}

rule AddIn_XLL_File
{
    meta:
        description = "Excel Add-In (XLL) file — executes native code when loaded, bypasses macro policy"
        severity    = "critical"

    strings:
        $mz = { 4D 5A }
        $a = "xlAutoOpen" nocase
        $b = "xlAutoClose" nocase
        $c = "xlAutoAdd" nocase

    condition:
        $mz and any of ($a, $b, $c)
}

rule PPAM_PPTM_AddIn
{
    meta:
        description = "PowerPoint Add-In (.ppam) or macro-enabled file — less scrutinized than docm/xlsm"
        severity    = "high"

    strings:
        $pk = { 50 4B 03 04 }
        $a = "ppt/vbaProject.bin"
        $b = "vbaProject.bin"
        $c = "macroEnabled" nocase

    condition:
        $pk and any of ($a, $b, $c)
}
