// ─── Default YARA Rules ───────────────────────────────────
// Edit or replace these rules, then click "Run Scan"
// Supports: text strings, hex strings {AA BB}, regex /pattern/
// Modifiers: nocase, wide, fullword
// Conditions: any of them, all of them, N of them, $a and $b

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

rule URL_Shortcut_Suspicious
{
    meta:
        description = "Windows .url shortcut with SMB reference or remote icon (credential theft)"
        severity    = "high"

    strings:
        $header = "[InternetShortcut]"
        $url = "URL="
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
        $d = "password" nocase

    condition:
        ($a or $b or $c) and $d
}

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

rule Info_Contains_MachO_Binary
{
    meta:
        description = "File contains a Mach-O binary header (macOS/iOS executable)"
        severity    = "info"

    strings:
        $macho32    = { CE FA ED FE }
        $macho64    = { CF FA ED FE }
        $macho_fat  = { CA FE BA BE }

    condition:
        any of them
}

rule Info_Contains_Java_JAR
{
    meta:
        description = "File contains a Java JAR archive (ZIP with META-INF/MANIFEST.MF)"
        severity    = "info"

    strings:
        $pk       = { 50 4B 03 04 }
        $manifest = "META-INF/MANIFEST.MF"

    condition:
        $pk and $manifest
}

rule Info_Contains_Java_Class
{
    meta:
        description = "File contains a compiled Java .class file (magic bytes CAFEBABE)"
        severity    = "info"

    strings:
        $magic = { CA FE BA BE 00 }

    condition:
        $magic
}

rule Info_Contains_DotNet_Assembly
{
    meta:
        description = "File contains .NET CLR assembly indicators"
        severity    = "info"

    strings:
        $mz       = { 4D 5A }
        $mscoree  = "mscoree.dll" nocase
        $clr      = "_CorExeMain" nocase
        $clr2     = "_CorDllMain" nocase
        $metadata = "#Strings" wide
        $metadata2 = "#GUID" wide

    condition:
        $mz and ($mscoree or $clr or $clr2 or 2 of ($metadata, $metadata2))
}

rule Info_Contains_WebAssembly
{
    meta:
        description = "File contains WebAssembly (WASM) binary module"
        severity    = "info"

    strings:
        $magic = { 00 61 73 6D }

    condition:
        $magic
}

rule Info_Contains_DLL_Export
{
    meta:
        description = "File contains DLL export indicators — may be a disguised dynamic library"
        severity    = "info"

    strings:
        $mz      = { 4D 5A }
        $export1 = "DllRegisterServer" nocase
        $export2 = "DllUnregisterServer" nocase
        $export3 = "DllGetClassObject" nocase
        $export4 = "DllCanUnloadNow" nocase
        $export5 = "ServiceMain" nocase

    condition:
        $mz and any of ($export1, $export2, $export3, $export4, $export5)
}

rule Info_Email_EML_Format
{
    meta:
        description = "File is a raw email message (.eml format with standard headers)"
        severity    = "info"

    strings:
        $from    = "From: " nocase
        $to      = "To: " nocase
        $subject = "Subject: " nocase
        $mime    = "MIME-Version:" nocase
        $recv    = "Received:" nocase

    condition:
        3 of them
}

rule Info_Email_Reply_To_Mismatch_Indicator
{
    meta:
        description = "Email contains both From and Reply-To headers — analyst should verify they match"
        severity    = "info"

    strings:
        $from    = "From:" nocase
        $replyto = "Reply-To:" nocase

    condition:
        $from and $replyto
}

rule Info_Email_SPF_Fail
{
    meta:
        description = "Email headers indicate SPF authentication failure"
        severity    = "info"

    strings:
        $a = "spf=fail" nocase
        $b = "spf=softfail" nocase
        $c = "spf=temperror" nocase
        $d = "spf=permerror" nocase

    condition:
        any of them
}

rule Info_Email_DKIM_Fail
{
    meta:
        description = "Email headers indicate DKIM signature verification failure"
        severity    = "info"

    strings:
        $a = "dkim=fail" nocase
        $b = "dkim=temperror" nocase
        $c = "dkim=permerror" nocase

    condition:
        any of them
}

rule Info_Email_DMARC_Fail
{
    meta:
        description = "Email headers indicate DMARC policy failure"
        severity    = "info"

    strings:
        $a = "dmarc=fail" nocase
        $b = "dmarc=none" nocase

    condition:
        any of them
}

rule Info_Email_X_Originating_IP
{
    meta:
        description = "Email contains X-Originating-IP header — reveals sender's source IP"
        severity    = "info"

    strings:
        $a = "X-Originating-IP:" nocase

    condition:
        $a
}

rule Info_Email_Multiple_Received_Hops
{
    meta:
        description = "Email has multiple Received headers — may indicate forwarding or relay chain"
        severity    = "info"

    strings:
        $recv = "Received:" nocase

    condition:
        #recv > 5
}

rule Info_Email_Bulk_Precedence
{
    meta:
        description = "Email marked as bulk, list, or junk precedence — mass mailing indicator"
        severity    = "info"

    strings:
        $a = "Precedence: bulk" nocase
        $b = "Precedence: junk" nocase
        $c = "Precedence: list" nocase
        $d = "X-Mailer:" nocase

    condition:
        any of ($a, $b, $c)
}

rule Info_Email_Content_Transfer_Encoding
{
    meta:
        description = "Email uses base64 or quoted-printable content transfer encoding"
        severity    = "info"

    strings:
        $a = "Content-Transfer-Encoding: base64" nocase
        $b = "Content-Transfer-Encoding: quoted-printable" nocase

    condition:
        any of them
}

rule Info_Email_Multipart_Mixed
{
    meta:
        description = "Email is multipart/mixed — contains attachments alongside body text"
        severity    = "info"

    strings:
        $a = "Content-Type: multipart/mixed" nocase

    condition:
        $a
}

rule Info_PNG_Appended_Data
{
    meta:
        description = "PNG file with data appended after IEND chunk — possible steganography or payload"
        severity    = "info"

    strings:
        $png_header = { 89 50 4E 47 0D 0A 1A 0A }
        $iend       = { 49 45 4E 44 AE 42 60 82 }

    condition:
        $png_header and $iend and @iend[1] + 8 < filesize
}

rule Info_JPEG_Appended_Data
{
    meta:
        description = "JPEG file with data after the EOI marker — possible hidden payload"
        severity    = "info"

    strings:
        $soi = { FF D8 FF }
        $eoi = { FF D9 }

    condition:
        $soi at 0 and @eoi[#eoi] + 2 < filesize
}

rule Info_Image_Only_HTML_Email
{
    meta:
        description = "HTML content is image-only with no meaningful text — scanner evasion technique"
        severity    = "info"

    strings:
        $html  = "<html" nocase
        $img1  = "<img" nocase
        $img2  = "background-image" nocase
        $no_p  = "<p" nocase
        $no_span = "<span" nocase
        $no_div_text = "<div" nocase

    condition:
        $html and ($img1 or $img2) and not $no_p and not $no_span
}

rule Info_SVG_Image_Present
{
    meta:
        description = "File contains SVG image markup — review for embedded scripts"
        severity    = "info"

    strings:
        $svg = "<svg" nocase
        $xmlns = "xmlns" nocase

    condition:
        $svg and $xmlns
}

rule Info_WMI_Event_Subscription
{
    meta:
        description = "File references WMI event subscription classes — fileless persistence mechanism"
        severity    = "info"

    strings:
        $a = "__EventFilter" nocase
        $b = "__EventConsumer" nocase
        $c = "CommandLineEventConsumer" nocase
        $d = "ActiveScriptEventConsumer" nocase
        $e = "__FilterToConsumerBinding" nocase

    condition:
        any of them
}

rule Suspicious_COM_Hijack_CLSID
{
    meta:
        description = "File references COM object CLSIDs commonly abused for hijacking persistence"
        severity    = "medium"

    strings:
        $clsid_mmcfx   = "{49CBB1C7-97D1-485A-9EC1-A26065633066}" nocase
        $inproc         = "InprocServer32" nocase
        $treatAs        = "TreatAs" nocase
        $clsid_generic  = /CLSID\\{[0-9A-Fa-f\-]{36}}/ nocase

    condition:
        ($inproc or $treatAs) and $clsid_generic
}

rule Info_Service_Installation
{
    meta:
        description = "File references Windows service creation or modification"
        severity    = "info"

    strings:
        $a = "sc create" nocase
        $b = "sc config" nocase
        $c = "New-Service" nocase
        $d = "InstallService" nocase
        $e = "ServiceName" nocase
        $f = "binPath=" nocase

    condition:
        2 of them
}

rule Info_BITSAdmin_Reference
{
    meta:
        description = "File references BITSAdmin — can be abused for stealthy file transfers"
        severity    = "info"

    strings:
        $a = "bitsadmin" nocase
        $b = "/transfer" nocase
        $c = "Start-BitsTransfer" nocase

    condition:
        any of them
}

rule Info_Alternate_Data_Stream
{
    meta:
        description = "File references NTFS Alternate Data Streams — payload hiding technique"
        severity    = "info"

    strings:
        $a = /[a-zA-Z]:\\[^\s:]+:[^\s:]+/ nocase
        $b = "Zone.Identifier" nocase
        $c = ":$DATA" nocase

    condition:
        any of them
}

rule Info_DLL_Sideload_Indicators
{
    meta:
        description = "File references known DLL sideloading targets"
        severity    = "info"

    strings:
        $a = "version.dll" nocase
        $b = "winmm.dll" nocase
        $c = "dbghelp.dll" nocase
        $d = "wer.dll" nocase
        $e = "CRYPTSP.dll" nocase
        $f = "profapi.dll" nocase

    condition:
        2 of them
}

rule Info_Android_APK
{
    meta:
        description = "File is an Android APK package (ZIP with AndroidManifest.xml)"
        severity    = "info"

    strings:
        $pk       = { 50 4B 03 04 }
        $manifest = "AndroidManifest.xml"
        $dex      = "classes.dex"

    condition:
        $pk and ($manifest or $dex)
}

rule Info_iOS_MobileConfig
{
    meta:
        description = "File is an Apple .mobileconfig profile — can install MDM, VPN, or certs silently"
        severity    = "info"

    strings:
        $plist = "<!DOCTYPE plist" nocase
        $a     = "PayloadType" nocase
        $b     = "PayloadIdentifier" nocase
        $c     = "Configuration" nocase
        $d     = "PayloadContent" nocase

    condition:
        $plist and 2 of ($a, $b, $c, $d)
}

rule Info_ICS_Calendar_Invite
{
    meta:
        description = "File is an iCalendar (.ics) invite — check for phishing URLs in event body"
        severity    = "info"

    strings:
        $begin = "BEGIN:VCALENDAR" nocase
        $event = "BEGIN:VEVENT" nocase
        $url   = "URL:" nocase
        $desc  = "DESCRIPTION:" nocase

    condition:
        $begin and $event
}

rule Info_ICS_Calendar_With_URL
{
    meta:
        description = "Calendar invite (.ics) contains URL — common vector for calendar phishing"
        severity    = "info"

    strings:
        $begin = "BEGIN:VCALENDAR" nocase
        $event = "BEGIN:VEVENT" nocase
        $url1  = "URL:http" nocase
        $url2  = "DESCRIPTION:" nocase
        $url3  = "http" nocase

    condition:
        $begin and $event and ($url1 or ($url2 and $url3))
}

rule Info_Apple_Disk_Image_DMG
{
    meta:
        description = "File is an Apple Disk Image (DMG) — can contain macOS malware"
        severity    = "info"

    strings:
        $a = { 78 01 73 0D 62 62 60 }
        $b = "koly" 
        $c = "dmg" nocase

    condition:
        $a or ($b and $c)
}

rule Info_Shortcut_WEBLOC
{
    meta:
        description = "File is a macOS .webloc bookmark — may redirect to phishing URL"
        severity    = "info"

    strings:
        $plist = "<!DOCTYPE plist" nocase
        $url   = "<key>URL</key>" nocase

    condition:
        $plist and $url
}

rule Info_Linux_Desktop_Entry
{
    meta:
        description = "File is a Linux .desktop application entry — can execute arbitrary commands"
        severity    = "info"

    strings:
        $header = "[Desktop Entry]" nocase
        $exec   = "Exec=" nocase
        $type   = "Type=Application" nocase

    condition:
        $header and $exec
}

rule Info_Cloudflare_Workers_URL
{
    meta:
        description = "File references Cloudflare Workers URL — abused for phishing proxies"
        severity    = "info"

    strings:
        $a = ".workers.dev" nocase
        $b = "pages.dev" nocase

    condition:
        any of them
}

rule Info_Azure_Hosting_URL
{
    meta:
        description = "File references Azure hosting domains — sometimes abused for phishing infra"
        severity    = "info"

    strings:
        $a = ".azurewebsites.net" nocase
        $b = ".blob.core.windows.net" nocase
        $c = ".azureedge.net" nocase
        $d = ".azure-api.net" nocase
        $e = ".onmicrosoft.com" nocase

    condition:
        any of them
}

rule Info_AWS_Hosting_URL
{
    meta:
        description = "File references AWS hosting domains — sometimes abused for phishing infra"
        severity    = "info"

    strings:
        $a = ".amazonaws.com" nocase
        $b = ".cloudfront.net" nocase
        $c = ".awsapps.com" nocase
        $d = "s3.amazonaws.com" nocase

    condition:
        any of them
}

rule Info_Google_Cloud_Hosting_URL
{
    meta:
        description = "File references Google Cloud hosting domains"
        severity    = "info"

    strings:
        $a = ".appspot.com" nocase
        $b = ".cloudfunctions.net" nocase
        $c = ".run.app" nocase
        $d = ".web.app" nocase
        $e = ".firebaseapp.com" nocase

    condition:
        any of them
}

rule Info_Firebase_Dynamic_Link
{
    meta:
        description = "File contains Firebase dynamic link — used to create redirect chains"
        severity    = "info"

    strings:
        $a = ".page.link" nocase
        $b = "firebasedynamic" nocase

    condition:
        any of them
}

rule Info_Vercel_Netlify_Hosting
{
    meta:
        description = "File references Vercel or Netlify hosting — abused for disposable phishing sites"
        severity    = "info"

    strings:
        $a = ".vercel.app" nocase
        $b = ".netlify.app" nocase
        $c = ".netlify.com" nocase

    condition:
        any of them
}

rule Info_Heroku_Render_Hosting
{
    meta:
        description = "File references Heroku or Render hosting domains"
        severity    = "info"

    strings:
        $a = ".herokuapp.com" nocase
        $b = ".onrender.com" nocase

    condition:
        any of them
}

rule Info_Tracking_Pixel
{
    meta:
        description = "File contains a 1x1 tracking pixel image — used for open-tracking or canary"
        severity    = "info"

    strings:
        $a = "width=\"1\" height=\"1\"" nocase
        $b = "width='1' height='1'" nocase
        $c = "width:1px;height:1px" nocase
        $d = "width=1 height=1" nocase
        $e = "width=\"1\"" nocase

    condition:
        any of ($a, $b, $c, $d) and ($e)
}

rule Info_External_Image_Load
{
    meta:
        description = "Document or HTML loads an external image — may phone home on open"
        severity    = "info"

    strings:
        $img_http1 = "<img" nocase
        $img_http2 = "src=\"http" nocase
        $img_http3 = "src='http" nocase
        $bg_img    = "background=\"http" nocase
        $css_bg    = "url(http" nocase

    condition:
        ($img_http1 and ($img_http2 or $img_http3)) or $bg_img or $css_bg
}

rule Info_Unique_Token_In_URL
{
    meta:
        description = "File contains URL with long unique token — per-recipient tracking link"
        severity    = "info"

    strings:
        $a = /https?:\/\/[^\s]{10,}[?&][a-zA-Z]+=[-a-zA-Z0-9_]{20,}/

    condition:
        $a
}

rule Info_Web_Beacon_Keywords
{
    meta:
        description = "File contains web beacon or tracking-related keywords"
        severity    = "info"

    strings:
        $a = "web beacon" nocase
        $b = "tracking pixel" nocase
        $c = "open tracking" nocase
        $d = "read receipt" nocase
        $e = "canarytoken" nocase
        $f = "canarytokens.com" nocase

    condition:
        any of them
}

rule Info_UTF7_Encoded_Content
{
    meta:
        description = "File contains UTF-7 encoded sequences — used to bypass XSS and content filters"
        severity    = "info"

    strings:
        $a = "+ADw-script" nocase
        $b = "+ADw-img" nocase
        $c = "+ADw-iframe" nocase
        $d = "+ADw-svg" nocase
        $e = "+ACI-" nocase

    condition:
        any of them
}

rule Info_MIME_Encoded_Words
{
    meta:
        description = "File contains MIME encoded-word syntax — may hide subject or filename"
        severity    = "info"

    strings:
        $b64  = /=\?[A-Za-z0-9\-]+\?B\?[A-Za-z0-9+\/=]+\?=/
        $qp   = /=\?[A-Za-z0-9\-]+\?Q\?[^\?]+\?=/

    condition:
        any of them
}

rule Info_Quoted_Printable_Obfuscation
{
    meta:
        description = "File contains heavy quoted-printable encoding — may obfuscate phishing text"
        severity    = "info"

    strings:
        $qp = /=[0-9A-Fa-f]{2}/

    condition:
        #qp > 50
}

rule Info_HTML_Entity_Obfuscation
{
    meta:
        description = "File uses heavy HTML entity encoding — evasion of text-based content scanning"
        severity    = "info"

    strings:
        $dec = /&#[0-9]{2,4};/
        $hex = /&#x[0-9a-fA-F]{2,4};/

    condition:
        #dec > 20 or #hex > 20
}

rule Info_CSS_Content_Injection
{
    meta:
        description = "HTML uses CSS content property to render text — hides text from parsers"
        severity    = "info"

    strings:
        $a = "content:" nocase
        $b = "::before" nocase
        $c = "::after" nocase
        $d = "attr(" nocase

    condition:
        $a and ($b or $c or $d)
}

rule Info_Zero_Width_Characters
{
    meta:
        description = "File contains zero-width Unicode characters — text obfuscation or fingerprinting"
        severity    = "info"

    strings:
        $zwsp  = { E2 80 8B }
        $zwnj  = { E2 80 8C }
        $zwj   = { E2 80 8D }
        $bom   = { EF BB BF }
        $wj    = { E2 81 A0 }

    condition:
        2 of them
}

rule Info_Punycode_Domain
{
    meta:
        description = "File contains a Punycode-encoded domain (xn--) — possible homograph attack"
        severity    = "info"

    strings:
        $a = "xn--" nocase

    condition:
        $a
}

rule Info_Data_URI_Scheme
{
    meta:
        description = "File contains data: URI scheme — may embed content inline to avoid fetching"
        severity    = "info"

    strings:
        $a = "data:text/html" nocase
        $b = "data:application/" nocase
        $c = "data:image/svg+xml" nocase
        $d = "data:text/javascript" nocase

    condition:
        any of them
}

rule Info_Cobalt_Strike_Indicators
{
    meta:
        description = "File contains strings associated with Cobalt Strike beacons"
        severity    = "info"

    strings:
        $a = "beacon.dll" nocase
        $b = "beacon.exe" nocase
        $c = "%COMSPEC%" nocase
        $d = "IEX (New-Object Net.Webclient).DownloadString" nocase
        $e = "/submit.php?" nocase
        $f = "pipe\\msse-" nocase

    condition:
        2 of them
}

rule Info_Metasploit_Indicators
{
    meta:
        description = "File contains strings commonly seen in Metasploit payloads"
        severity    = "info"

    strings:
        $a = "meterpreter" nocase
        $b = "metasploit" nocase
        $c = "reverse_tcp" nocase
        $d = "reverse_http" nocase
        $e = "shell_bind_tcp" nocase
        $f = "windows/exec" nocase

    condition:
        any of them
}

rule Info_Macro_Builder_Artifacts
{
    meta:
        description = "File contains artifacts from known macro payload builders"
        severity    = "info"

    strings:
        $a = "MacroPack" nocase
        $b = "EvilClippy" nocase
        $c = "Unicorn" nocase
        $d = "LuckyStrike" nocase
        $e = "macro_reverse" nocase

    condition:
        any of them
}

rule Info_Mimikatz_Reference
{
    meta:
        description = "File contains references to Mimikatz credential harvesting tool"
        severity    = "info"

    strings:
        $a = "mimikatz" nocase
        $b = "sekurlsa" nocase
        $c = "kerberos::list" nocase
        $d = "lsadump" nocase
        $e = "gentilkiwi" nocase

    condition:
        any of them
}

rule Info_DNS_Over_HTTPS_Reference
{
    meta:
        description = "File references DNS-over-HTTPS endpoints — can be used for covert C2"
        severity    = "info"

    strings:
        $a = "dns.google/resolve" nocase
        $b = "cloudflare-dns.com/dns-query" nocase
        $c = "dns.quad9.net" nocase
        $d = "doh.opendns.com" nocase
        $e = "application/dns-json" nocase

    condition:
        any of them
}

rule Info_DNS_TXT_Lookup
{
    meta:
        description = "File performs DNS TXT record lookups — can smuggle data or instructions"
        severity    = "info"

    strings:
        $a = "nslookup" nocase
        $b = "-type=TXT" nocase
        $c = "Resolve-DnsName" nocase
        $d = "QueryType TXT" nocase
        $e = "dig " nocase

    condition:
        ($a and $b) or ($c and $d) or $e
}

rule Info_Exfil_HTTP_POST
{
    meta:
        description = "File constructs HTTP POST requests with data — possible exfiltration"
        severity    = "info"

    strings:
        $a = "XMLHttpRequest" nocase
        $b = ".open(\"POST\"" nocase
        $c = ".open('POST'" nocase
        $d = "fetch(" nocase
        $e = "method: 'POST'" nocase
        $f = "method:\"POST\"" nocase
        $g = "Content-Type" nocase

    condition:
        ($a and ($b or $c) and $g) or ($d and ($e or $f))
}

rule Info_Socket_Connection
{
    meta:
        description = "File creates raw socket or TCP connection — possible reverse shell or C2"
        severity    = "info"

    strings:
        $a = "TCPClient" nocase
        $b = "Net.Sockets" nocase
        $c = "socket.connect" nocase
        $d = "new Socket" nocase
        $e = "SOCK_STREAM" nocase
        $f = "WSAStartup" nocase

    condition:
        any of them
}

rule Info_Reverse_Shell_Patterns
{
    meta:
        description = "File contains common reverse shell connection patterns"
        severity    = "info"

    strings:
        $a = "/dev/tcp/" nocase
        $b = "bash -i" nocase
        $c = "nc -e" nocase
        $d = "ncat -e" nocase
        $e = "python -c 'import socket" nocase
        $f = "0>&1" nocase
        $g = "exec 5<>/dev/tcp" nocase

    condition:
        any of them
}

rule Info_Browser_Credential_Paths
{
    meta:
        description = "File references browser credential or cookie store paths"
        severity    = "info"

    strings:
        $a = "Login Data" nocase
        $b = "Cookies" nocase
        $c = "\\Google\\Chrome\\User Data" nocase
        $d = "\\Mozilla\\Firefox\\Profiles" nocase
        $e = "\\Microsoft\\Edge\\User Data" nocase
        $f = "logins.json" nocase
        $g = "signons.sqlite" nocase

    condition:
        2 of them
}

rule Info_Keylogger_Indicators
{
    meta:
        description = "File contains keylogger-related API calls or patterns"
        severity    = "info"

    strings:
        $a = "GetAsyncKeyState" nocase
        $b = "SetWindowsHookEx" nocase
        $c = "GetKeyState" nocase
        $d = "WH_KEYBOARD" nocase
        $e = "keylog" nocase

    condition:
        2 of them
}

rule Info_Screenshot_Capture
{
    meta:
        description = "File contains screen capture API references"
        severity    = "info"

    strings:
        $a = "GetDesktopWindow" nocase
        $b = "BitBlt" nocase
        $c = "CopyFromScreen" nocase
        $d = "Screenshot" nocase
        $e = "PrintWindow" nocase

    condition:
        2 of them
}

rule Info_Webcam_Microphone_Access
{
    meta:
        description = "File references webcam or microphone access APIs"
        severity    = "info"

    strings:
        $a = "getUserMedia" nocase
        $b = "MediaDevices" nocase
        $c = "avicap32" nocase
        $d = "capCreateCaptureWindow" nocase
        $e = "waveInOpen" nocase
        $f = "navigator.mediaDevices" nocase

    condition:
        2 of them
}

rule Info_Sensitive_File_Extensions
{
    meta:
        description = "File references sensitive data file extensions (wallets, databases, keys)"
        severity    = "info"

    strings:
        $a = ".kdbx" nocase
        $b = ".kdb" nocase
        $c = ".wallet" nocase
        $d = ".pfx" nocase
        $e = ".p12" nocase
        $f = ".pem" nocase
        $g = ".rdp" nocase
        $h = ".ovpn" nocase
        $i = ".ppk" nocase

    condition:
        any of them
}

rule Info_Outlook_Credential_Reference
{
    meta:
        description = "File references Outlook profile credentials or PST/OST archives"
        severity    = "info"

    strings:
        $a = ".pst" nocase fullword
        $b = ".ost" nocase fullword
        $c = "Outlook\\Profiles" nocase
        $d = "IMAP Password" nocase
        $e = "POP3 Password" nocase
        $f = "SMTP Password" nocase

    condition:
        2 of them
}

rule Info_VM_Detection_Strings
{
    meta:
        description = "File checks for virtual machine or sandbox environment indicators"
        severity    = "info"

    strings:
        $a = "VMware" nocase
        $b = "VirtualBox" nocase
        $c = "QEMU" nocase
        $d = "Hyper-V" nocase
        $e = "Xen" nocase
        $f = "vboxservice" nocase
        $g = "vmtoolsd" nocase
        $h = "SbieDll" nocase
        $i = "sandboxie" nocase
        $j = "cuckoomon" nocase

    condition:
        2 of them
}

rule Info_Debugger_Detection
{
    meta:
        description = "File checks for debugger presence — anti-analysis technique"
        severity    = "info"

    strings:
        $a = "IsDebuggerPresent" nocase
        $b = "CheckRemoteDebuggerPresent" nocase
        $c = "NtQueryInformationProcess" nocase
        $d = "OutputDebugString" nocase
        $e = "OllyDbg" nocase
        $f = "x64dbg" nocase

    condition:
        2 of them
}

rule Info_Timing_Based_Evasion
{
    meta:
        description = "File uses timing checks — common sandbox evasion to wait out analysis"
        severity    = "info"

    strings:
        $a = "GetTickCount" nocase
        $b = "QueryPerformanceCounter" nocase
        $c = "NtDelayExecution" nocase
        $d = "TimeSpan" nocase
        $e = "Thread.Sleep" nocase
        $f = "time.sleep" nocase

    condition:
        2 of them
}

rule Info_Process_Enumeration
{
    meta:
        description = "File enumerates running processes — recon or AV-detection technique"
        severity    = "info"

    strings:
        $a = "CreateToolhelp32Snapshot" nocase
        $b = "Process32First" nocase
        $c = "Process32Next" nocase
        $d = "EnumProcesses" nocase
        $e = "Get-Process" nocase
        $f = "tasklist" nocase

    condition:
        2 of them
}

rule Info_UAC_Bypass_Indicators
{
    meta:
        description = "File contains references to UAC bypass techniques"
        severity    = "info"

    strings:
        $a = "fodhelper" nocase
        $b = "eventvwr" nocase
        $c = "sdclt" nocase
        $d = "slui" nocase
        $e = "CompMgmtLauncher" nocase
        $f = "ms-settings" nocase

    condition:
        2 of them
}

rule PE_Process_Injection_APIs
{
    meta:
        description = "PE binary imports classic process injection APIs (alloc + write + thread)"
        severity    = "critical"

    strings:
        $mz       = { 4D 5A }
        $alloc    = "VirtualAlloc" nocase
        $allocex  = "VirtualAllocEx" nocase
        $write    = "WriteProcessMemory" nocase
        $thread   = "CreateRemoteThread" nocase
        $protect  = "VirtualProtect" nocase
        $move     = "RtlMoveMemory" nocase

    condition:
        $mz at 0 and (
            ($alloc or $allocex) and ($write or $move) and $thread
        )
}

rule PE_Shellcode_Loader_Pattern
{
    meta:
        description = "PE imports memory manipulation APIs commonly used for shellcode loading"
        severity    = "high"

    strings:
        $mz       = { 4D 5A }
        $alloc    = "VirtualAlloc" nocase
        $protect  = "VirtualProtect" nocase
        $move     = "RtlMoveMemory" nocase
        $load     = "LoadLibraryA" nocase

    condition:
        $mz at 0 and 3 of ($alloc, $protect, $move, $load)
}

rule PE_Download_Execute
{
    meta:
        description = "PE binary downloads remote content and executes it"
        severity    = "critical"

    strings:
        $mz      = { 4D 5A }
        $dl1     = "InternetConnectA" nocase
        $dl2     = "URLDownloadToFile" nocase
        $dl3     = "URLDownloadToFileA" nocase
        $dl4     = "InternetOpenA" nocase
        $dl5     = "InternetReadFile" nocase
        $exec1   = "WinExec" nocase
        $exec2   = "CreateProcessA" nocase
        $exec3   = "CreateProcessW" nocase
        $exec4   = "ShellExecuteA" nocase

    condition:
        $mz at 0 and any of ($dl1, $dl2, $dl3, $dl4, $dl5) and any of ($exec1, $exec2, $exec3, $exec4)
}

rule PE_Suspicious_Imports_Cluster
{
    meta:
        description = "PE binary imports 3+ suspicious APIs (injection, download, execution)"
        severity    = "high"

    strings:
        $mz   = { 4D 5A }
        $a    = "VirtualAlloc" nocase
        $b    = "WriteProcessMemory" nocase
        $c    = "CreateRemoteThread" nocase
        $d    = "InternetConnectA" nocase
        $e    = "URLDownloadToFile" nocase
        $f    = "WinExec" nocase
        $g    = "CreateProcessA" nocase
        $h    = "VirtualProtect" nocase
        $i    = "RtlMoveMemory" nocase
        $j    = "LoadLibraryA" nocase
        $k    = "NtUnmapViewOfSection" nocase

    condition:
        $mz at 0 and 3 of ($a, $b, $c, $d, $e, $f, $g, $h, $i, $j, $k)
}

rule PE_Process_Hollowing
{
    meta:
        description = "PE imports APIs consistent with process hollowing technique"
        severity    = "critical"

    strings:
        $mz     = { 4D 5A }
        $a      = "NtUnmapViewOfSection" nocase
        $b      = "ZwUnmapViewOfSection" nocase
        $c      = "WriteProcessMemory" nocase
        $d      = "CreateProcessA" nocase
        $e      = "CreateProcessW" nocase
        $f      = "ResumeThread" nocase

    condition:
        $mz at 0 and ($a or $b) and $c and ($d or $e) and $f
}

rule JS_DocumentWrite_With_Obfuscation
{
    meta:
        description = "JavaScript uses document.write with encoding/decoding — DOM-based payload injection"
        severity    = "high"

    strings:
        $dw    = "document.write" nocase
        $a     = "unescape" nocase
        $b     = "atob" nocase
        $c     = "fromCharCode" nocase
        $d     = "decodeURIComponent" nocase
        $e     = "eval(" nocase

    condition:
        $dw and any of ($a, $b, $c, $d, $e)
}

rule JS_Location_Redirect_Obfuscated
{
    meta:
        description = "JavaScript redirects via window.location with encoding — phishing redirect"
        severity    = "high"

    strings:
        $loc1  = "window.location" nocase
        $loc2  = "document.location" nocase
        $loc3  = "location.href" nocase
        $loc4  = "location.replace" nocase
        $a     = "atob(" nocase
        $b     = "fromCharCode" nocase
        $c     = "unescape" nocase
        $d     = "decodeURIComponent" nocase

    condition:
        any of ($loc1, $loc2, $loc3, $loc4) and any of ($a, $b, $c, $d)
}

rule JS_ActiveX_With_XMLHttp
{
    meta:
        description = "JavaScript creates ActiveXObject for HTTP requests — classic dropper pattern"
        severity    = "critical"

    strings:
        $ax    = "ActiveXObject" nocase
        $a     = "MSXML2.XMLHTTP" nocase
        $b     = "Microsoft.XMLHTTP" nocase
        $c     = "WScript.Shell" nocase

    condition:
        $ax and any of ($a, $b, $c)
}

rule PowerShell_AddType_Inline_CSharp
{
    meta:
        description = "PowerShell compiles inline C# via Add-Type — used for API access and evasion"
        severity    = "critical"

    strings:
        $a     = "Add-Type" nocase
        $b     = "-TypeDefinition" nocase
        $c     = "-MemberDefinition" nocase
        $d     = "DllImport" nocase
        $e     = "System.Runtime.InteropServices" nocase

    condition:
        $a and any of ($b, $c, $d, $e)
}

rule PowerShell_Invoke_Command_Remote
{
    meta:
        description = "PowerShell uses Invoke-Command for lateral movement"
        severity    = "critical"

    strings:
        $a     = "Invoke-Command" nocase
        $b     = "-ComputerName" nocase
        $c     = "-ScriptBlock" nocase
        $d     = "-Session" nocase

    condition:
        $a and any of ($b, $c, $d)
}

rule PowerShell_Stealth_Flags_Combo
{
    meta:
        description = "PowerShell uses multiple stealth flags together (hidden, noprofile, noninteractive)"
        severity    = "critical"

    strings:
        $ps    = "powershell" nocase
        $a     = "-nop" nocase
        $b     = "-noni" nocase
        $c     = "-w hidden" nocase
        $d     = "-win hidden" nocase
        $e     = "-ep bypass" nocase
        $f     = "-ExecutionPolicy Bypass" nocase

    condition:
        $ps and 2 of ($a, $b, $c, $d, $e, $f)
}

rule PowerShell_Reflection_Assembly_Load
{
    meta:
        description = "PowerShell loads .NET assembly via reflection — fileless PE execution"
        severity    = "critical"

    strings:
        $a     = "System.Reflection.Assembly" nocase
        $b     = "[Reflection.Assembly]::Load" nocase
        $c     = "FromBase64String" nocase
        $d     = "Add-Type" nocase

    condition:
        ($a or $b) and ($c or $d)
}

rule PowerShell_IEX_Env_Variable
{
    meta:
        description = "PowerShell IEX via environment variable — obfuscated execution"
        severity    = "critical"

    strings:
        $a     = "IEX $env:" nocase
        $b     = "iex $env:" nocase
        $c     = "Invoke-Expression $env:" nocase

    condition:
        any of them
}

rule VBA_GetObject_WMI
{
    meta:
        description = "VBA uses GetObject to access WMI or remote resources"
        severity    = "high"

    strings:
        $get   = "GetObject" nocase
        $a     = "winmgmts" nocase
        $b     = "Win32_Process" nocase
        $vba   = "Sub " nocase

    condition:
        $vba and $get and any of ($a, $b, $c)
}

rule VBA_Shell_Application_Abuse
{
    meta:
        description = "VBA creates Shell.Application object — can execute programs and browse namespace"
        severity    = "high"

    strings:
        $a     = "Shell.Application" nocase
        $b     = "ShellExecute" nocase
        $c     = "CreateObject" nocase
        $vba   = "Sub " nocase

    condition:
        $vba and $a and ($b or $c)
}

rule VBA_DDE_Field_Injection
{
    meta:
        description = "VBA or document content uses DDE field codes for code execution"
        severity    = "critical"

    strings:
        $a     = "DDE" nocase fullword
        $b     = "DDEAUTO" nocase
        $c     = "cmd.exe" nocase
        $d     = "powershell" nocase
        $e     = "mshta" nocase

    condition:
        ($a or $b) and any of ($c, $d, $e)
}

rule VBA_NewObject_PowerShell
{
    meta:
        description = "VBA passes New-Object to PowerShell — .NET object instantiation from macro"
        severity    = "critical"

    strings:
        $ps    = "powershell" nocase
        $no    = "New-Object" nocase
        $vba1  = "Sub " nocase
        $vba2  = "Shell" nocase

    condition:
        $ps and $no and ($vba1 or $vba2)
}

rule VBA_WbemDisp_WMI
{
    meta:
        description = "VBA references wbemdisp.dll — WMI scripting library for process creation"
        severity    = "high"

    strings:
        $a     = "wbemdisp.dll" nocase
        $b     = "SWbemLocator" nocase
        $c     = "WbemScripting" nocase
        $vba   = "Sub " nocase

    condition:
        $vba and any of ($a, $b, $c)
}

rule PDF_AcroForm_With_JavaScript
{
    meta:
        description = "PDF has AcroForm combined with JavaScript — interactive form exploitation"
        severity    = "high"

    strings:
        $pdf   = { 25 50 44 46 }
        $acro  = "/AcroForm"
        $js1   = "/JavaScript"
        $js2   = "/JS"

    condition:
        $pdf and $acro and ($js1 or $js2)
}

rule PDF_RichMedia_Content
{
    meta:
        description = "PDF contains RichMedia (Flash/multimedia) — historically exploited attack surface"
        severity    = "high"

    strings:
        $pdf   = { 25 50 44 46 }
        $a     = "/RichMedia"

    condition:
        $pdf and $a
}

rule PDF_ObjectStream_With_Action
{
    meta:
        description = "PDF uses object streams with auto-action — can hide malicious objects"
        severity    = "high"

    strings:
        $pdf   = { 25 50 44 46 }
        $obj   = "/ObjStm"
        $a     = "/OpenAction"
        $b     = "/AA"
        $c     = "/JavaScript"

    condition:
        $pdf and $obj and any of ($a, $b, $c)
}

rule PDF_Eval_Obfuscation
{
    meta:
        description = "PDF contains JavaScript eval or encoding functions — obfuscated exploit code"
        severity    = "critical"

    strings:
        $pdf   = { 25 50 44 46 }
        $js    = "/JavaScript"
        $a     = "eval" nocase
        $b     = "String.fromCharCode" nocase
        $c     = "unescape" nocase
        $d     = "atob" nocase

    condition:
        $pdf and $js and 2 of ($a, $b, $c, $d)
}

rule General_XOR_Decode_Loop
{
    meta:
        description = "File contains XOR decoding patterns — common payload deobfuscation"
        severity    = "medium"

    strings:
        $a     = "xor" nocase fullword
        $b     = "fromCharCode" nocase
        $c     = "charCodeAt" nocase
        $d     = "Chr(" nocase

    condition:
        $a and any of ($b, $c, $d)
}

rule General_Base64_With_Execution
{
    meta:
        description = "File decodes base64 and passes result to execution function"
        severity    = "high"

    strings:
        $b64_1 = "base64" nocase
        $b64_2 = "FromBase64String" nocase
        $b64_3 = "atob(" nocase
        $exec1 = "eval(" nocase
        $exec2 = "Invoke-Expression" nocase
        $exec3 = "iex " nocase
        $exec4 = "Execute(" nocase
        $exec5 = "ExecuteGlobal(" nocase
        $exec6 = "Function(" nocase

    condition:
        any of ($b64_1, $b64_2, $b64_3) and any of ($exec1, $exec2, $exec3, $exec4, $exec5, $exec6)
}

rule General_Hex_Encoded_Shellcode
{
    meta:
        description = "File contains patterns consistent with hex-encoded shellcode blobs"
        severity    = "high"

    strings:
        $hex_prefix = /\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){15,}/
        $hex_comma  = /0x[0-9a-fA-F]{2}(,\s*0x[0-9a-fA-F]{2}){15,}/

    condition:
        any of them
}

rule WMIC_Process_Create
{
    meta:
        description = "WMIC used to create remote processes — lateral movement technique"
        severity    = "critical"

    strings:
        $a     = "wmic" nocase
        $b     = "process" nocase fullword
        $c     = "call" nocase fullword
        $d     = "create" nocase fullword

    condition:
        $a and $b and $c and $d
}

rule BITSAdmin_Download
{
    meta:
        description = "BITSAdmin used for file download — LOLBin download technique"
        severity    = "critical"

    strings:
        $a     = "bitsadmin" nocase
        $b     = "/transfer" nocase
        $c     = "/download" nocase
        $d     = "http" nocase

    condition:
        $a and ($b or $c) and $d
}

rule Regsvr32_Remote_SCT
{
    meta:
        description = "Regsvr32 loads remote scriptlet — Squiblydoo AppLocker bypass"
        severity    = "critical"

    strings:
        $a     = "regsvr32" nocase
        $b     = "/s" nocase
        $c     = "/n" nocase
        $d     = "/u" nocase
        $e     = "/i:http" nocase
        $f     = "scrobj.dll" nocase

    condition:
        $a and ($e or $f)
}

rule MSBuild_Inline_Task
{
    meta:
        description = "MSBuild XML with inline task — bypasses application whitelisting"
        severity    = "critical"

    strings:
        $a     = "<Project" nocase
        $b     = "<UsingTask" nocase
        $c     = "TaskFactory" nocase
        $d     = "CodeTaskFactory" nocase
        $e     = "DllImport" nocase
        $f     = "ProcessStartInfo" nocase

    condition:
        $a and $b and ($c or $d) and ($e or $f)
}

rule CMSTP_INF_Bypass
{
    meta:
        description = "CMSTP.exe INF-based execution — UAC bypass and AppLocker evasion"
        severity    = "critical"

    strings:
        $a     = "cmstp" nocase
        $b     = "/ni" nocase
        $c     = "/s" nocase
        $d     = ".inf" nocase
        $e     = "RunPreSetupCommandsSection" nocase

    condition:
        ($a and ($b or $c) and $d) or $e
}

rule Msiexec_Remote_Install
{
    meta:
        description = "Msiexec loads remote MSI package — payload delivery via Windows Installer"
        severity    = "critical"

    strings:
        $a     = "msiexec" nocase
        $b     = "/i" nocase
        $c     = "/q" nocase
        $d     = "http" nocase

    condition:
        $a and $b and $d
}

rule Rundll32_Script_Proxy
{
    meta:
        description = "Rundll32 used to proxy-execute JavaScript or DLL exports"
        severity    = "critical"

    strings:
        $a     = "rundll32" nocase
        $b     = "javascript:" nocase
        $c     = "mshtml" nocase
        $d     = "advpack.dll" nocase
        $e     = "ieadvpack.dll" nocase
        $f     = "syssetup.dll" nocase
        $g     = "setupapi.dll" nocase

    condition:
        $a and any of ($b, $c, $d, $e, $f, $g)
}

rule PowerShell_WMI_Event_Persistence
{
    meta:
        description = "PowerShell creates WMI event subscription — fileless persistence"
        severity    = "critical"

    strings:
        $a     = "__EventFilter" nocase
        $b     = "CommandLineEventConsumer" nocase
        $c     = "__FilterToConsumerBinding" nocase
        $d     = "Register-WmiEvent" nocase
        $e     = "Set-WmiInstance" nocase

    condition:
        2 of them
}

rule Credential_Dumping_Commands
{
    meta:
        description = "File references credential dumping tools or techniques beyond mimikatz"
        severity    = "critical"

    strings:
        $a     = "procdump" nocase
        $b     = "lsass" nocase
        $c     = "comsvcs.dll" nocase
        $d     = "MiniDump" nocase
        $e     = "ntdsutil" nocase
        $f     = "vssadmin" nocase
        $g     = "ntds.dit" nocase

    condition:
        ($a and $b) or ($c and $d) or ($e and ($f or $g))
}

rule AMSI_ETW_Bypass_Patterns
{
    meta:
        description = "File attempts to patch AMSI or disable ETW tracing"
        severity    = "critical"

    strings:
        $a     = "AmsiScanBuffer" nocase
        $b     = "amsiInitFailed" nocase
        $c     = "EtwEventWrite" nocase
        $d     = "ntdll" nocase
        $e     = { C3 }
        $f     = "VirtualProtect" nocase
        $g     = "patch" nocase

    condition:
        ($a or $b or $c) and ($f or $g)
}

rule Standalone_Script_Shell_Execution
{
    meta:
        description = "Individual script/shell execution indicator (standalone match)"
        severity    = "medium"

    strings:
        $wscript_shell   = "WScript.Shell" nocase
        $create_object   = "CreateObject" nocase
        $get_object      = "GetObject" nocase
        $shell_call      = /\bShell\s*\(/ nocase
        $shell_execute   = "ShellExecute" nocase
        $shell_app       = "Shell.Application" nocase
        $run_call        = /\bRun\s*\(/ nocase
        $exec_call       = /\bExec\s*\(/ nocase

    condition:
        any of them
}

rule Standalone_COM_Objects
{
    meta:
        description = "COM object instantiation or access (standalone match)"
        severity    = "medium"

    strings:
        $fso    = "Scripting.FileSystemObject" nocase
        $adodb  = "ADODB.Stream" nocase
        $activex = "ActiveXObject" nocase
        $clsid  = "clsid:" nocase

    condition:
        any of them
}

rule Standalone_Download_Network_Indicators
{
    meta:
        description = "Individual network/download indicator (standalone match)"
        severity    = "medium"

    strings:
        $dl_file       = "DownloadFile" nocase
        $dl_string     = "DownloadString" nocase
        $webclient     = "Net.WebClient" nocase
        $xmlhttp       = "XMLHTTP" nocase
        $msxml2        = "MSXML2" nocase
        $ms_xmlhttp    = "Microsoft.XMLHTTP" nocase
        $winhttp       = "WinHttp.WinHttpRequest" nocase
        $urldownload   = "URLDownloadToFile" nocase
        $iwr           = "Invoke-WebRequest" nocase
        $irm           = "Invoke-RestMethod" nocase
        $bits_transfer = "Start-BitsTransfer" nocase
        $inet_connect  = "InternetConnectA" nocase
        $ie_app        = "InternetExplorer.Application" nocase
        $xmlhttp_req   = "XMLHttpRequest" nocase
        $msxml2_xmlhttp = "MSXML2.XMLHTTP" nocase

    condition:
        any of them
}

rule Standalone_PowerShell_Indicators
{
    meta:
        description = "Individual PowerShell indicator (standalone match)"
        severity    = "medium"

    strings:
        $iex            = "Invoke-Expression" nocase
        $iex_alias      = /\biex\s/ nocase
        $start_process  = "Start-Process" nocase
        $new_object     = "New-Object" nocase
        $enc_cmd        = "-EncodedCommand" nocase
        $enc_short      = /\s-enc\s/ nocase
        $enc_e          = /\s-e\s/ nocase
        $nop            = "-nop" nocase
        $noni           = "-noni" nocase
        $hidden_win     = "-w hidden" nocase
        $invoke_cmd     = "Invoke-Command" nocase
        $add_type       = "Add-Type" nocase
        $reflection     = "System.Reflection.Assembly" nocase
        $ps_enc_payload = /-[Ee](?:nc|ncodedcommand)\s+[A-Za-z0-9+\/=]{20,}/

    condition:
        any of them
}

rule Standalone_LOLBin_Indicators
{
    meta:
        description = "LOLBin (Living Off The Land Binary) reference — may indicate abuse"
        severity    = "info"

    strings:
        $certutil   = "certutil" nocase fullword
        $bitsadmin  = "bitsadmin" nocase fullword
        $mshta      = "mshta" nocase fullword
        $regsvr32   = "regsvr32" nocase fullword
        $rundll32   = "rundll32" nocase fullword
        $cscript    = "cscript" nocase fullword
        $wscript    = "wscript" nocase fullword
        $msiexec    = "msiexec" nocase fullword
        $cmd_c      = /\bcmd\s*\/[ck]\b/ nocase
        $ps_enc     = /powershell\s+.*-[Ee]nc/ nocase

    condition:
        any of them
}

rule Standalone_HTML_Suspicious_Elements
{
    meta:
        description = "Suspicious HTML element or attribute (standalone match)"
        severity    = "info"

    strings:
        $script_tag     = /<script[\s>]/ nocase
        $event_handler  = /\bon\w+\s*=/ nocase
        $iframe_tag     = /<iframe[\s>]/ nocase
        $object_tag     = /<object[\s>]/ nocase
        $embed_tag      = /<embed[\s>]/ nocase
        $form_tag       = /<form[\s>]/ nocase

    condition:
        2 of them
}

rule Standalone_HTML_Credential_Indicators
{
    meta:
        description = "HTML credential harvesting or redirect indicator"
        severity    = "medium"

    strings:
        $password_input = /type\s*=\s*["']?password/ nocase
        $doc_cookie     = "document.cookie" nocase
        $form_submit    = /\.submit\s*\(/ nocase
        $meta_refresh   = /<meta[^>]+refresh/ nocase
        $base_href      = /<base\s+href/ nocase

    condition:
        2 of them
}

rule Standalone_HTML_Code_Execution
{
    meta:
        description = "HTML/JavaScript code execution or obfuscation (2+ indicators)"
        severity    = "medium"

    strings:
        $eval_call      = /eval\s*\(/ nocase
        $doc_write      = "document.write" nocase
        $atob_call      = /atob\s*\(/ nocase
        $unescape_call  = /unescape\s*\(/ nocase
        $fromcharcode   = "String.fromCharCode" nocase
        $js_uri         = /javascript\s*:/ nocase
        $data_html_uri  = /data\s*:\s*text\/html/ nocase
        $vbscript_uri   = /vbscript\s*:/ nocase

    condition:
        2 of them
}

rule Standalone_HTA_VBScript_Indicators
{
    meta:
        description = "HTA or VBScript execution indicator (standalone match)"
        severity    = "medium"

    strings:
        $hta_tag        = /<HTA:APPLICATION[^>]*>/ nocase
        $exec_global    = "ExecuteGlobal" nocase
        $exec_statement = "ExecuteStatement" nocase
        $execute_call   = /\bExecute\s*\(/ nocase
        $eval_vbs       = /\bEval\s*\(/ nocase
        $getref         = /\bGetRef\s*\(/ nocase
        $chr_obfusc     = /\bChr\s*\(\s*\d/ nocase
        $chrw_obfusc    = /\bChrW\s*\(\s*\d/ nocase
        $strreverse     = "StrReverse" nocase
        $msgbox         = "MsgBox" nocase
        $vbscript_lang  = /language\s*=\s*["']?vbscript/ nocase
        $jscript_lang   = /language\s*=\s*["']?jscript/ nocase

    condition:
        any of them
}

rule Standalone_WSF_Script_Indicators
{
    meta:
        description = "Windows Script File execution indicator (standalone match)"
        severity    = "medium"

    strings:
        $regwrite    = "RegWrite" nocase fullword
        $frombase64  = "FromBase64String" nocase
        $wbemdisp    = "wbemdisp.dll" nocase
        $dde         = "DDE" nocase fullword
        $ddeauto     = "DDEAUTO" nocase fullword

    condition:
        any of them
}

rule Standalone_RTF_OLE_Keywords
{
    meta:
        description = "RTF OLE object control word with RTF context"
        severity    = "high"

    strings:
        $rtf        = "{\\rtf"
        $objdata    = "\\objdata"
        $objocx     = "\\objocx"
        $objemb     = "\\objemb"
        $objautlink = "\\objautlink"
        $objhtml    = "\\objhtml"
        $objlink    = "\\objlink"
        $objupdate  = "\\objupdate"
        $objclass   = "\\objclass"

    condition:
        $rtf and any of ($objdata, $objocx, $objemb, $objautlink, $objhtml, $objlink, $objupdate, $objclass)
}

rule Standalone_RTF_Exploit_Patterns
{
    meta:
        description = "RTF exploit vector or DDE field with RTF context"
        severity    = "high"

    strings:
        $rtf           = "{\\rtf"
        $equation_obj  = /\{\\object\b[^}]*\\objclass\s+Equation/ nocase
        $equation3     = "Equation.3" nocase
        $eq3_clsid     = "0002CE02-0000-0000-C000-000000000046" nocase
        $datafield     = "\\datafield"
        $ddeauto_rtf   = "\\ddeauto"
        $ddeauto_field = /\\field\s*\{[^}]*\\fldinst\s+[^}]*DDEAUTO/ nocase
        $import_field  = /\\field\s*\{[^}]*\\fldinst\s+[^}]*IMPORT/ nocase
        $include_field = /\\field\s*\{[^}]*\\fldinst\s+[^}]*INCLUDETEXT/ nocase

    condition:
        $rtf and any of ($equation_obj, $equation3, $eq3_clsid, $datafield, $ddeauto_rtf, $ddeauto_field, $import_field, $include_field)
}

rule Standalone_RTF_Obfuscation
{
    meta:
        description = "RTF obfuscation technique with RTF context"
        severity    = "medium"

    strings:
        $rtf           = "{\\rtf"
        $obfusc_header = /\{\\rt[^f]/ nocase
        $bin_payload   = /\\bin\d{4,}/

    condition:
        $rtf and ($obfusc_header or $bin_payload)
}

rule Standalone_LNK_Argument_Patterns
{
    meta:
        description = "Suspicious command-line argument patterns (2+ indicators suggest malicious intent)"
        severity    = "high"

    strings:
        $enc_flag     = /-e(nc(odedcommand)?)\b/ nocase
        $noprofile    = /-nop(rofile)?\b/ nocase
        $hidden_win   = /-w(indowstyle)?\s+hidden/ nocase
        $ep_bypass    = /-ep\s+bypass/ nocase
        $frombase64   = "FromBase64String" nocase fullword

    condition:
        2 of them
}

rule Encoded_Base64_PE_Header
{
    meta:
        description = "Base64-encoded PE executable (MZ header = TVqQ/TVpQ/TVro)"
        severity    = "high"

    strings:
        $b64_mz1 = "TVqQ" ascii
        $b64_mz2 = "TVpQ" ascii
        $b64_mz3 = "TVro" ascii

    condition:
        any of them
}

rule Encoded_Base64_Gzip
{
    meta:
        description = "Base64-encoded gzip data (H4sI prefix)"
        severity    = "medium"

    strings:
        $b64_gz = "H4sI" ascii

    condition:
        $b64_gz
}

rule Encoded_Base64_OLE_Document
{
    meta:
        description = "Base64-encoded OLE/CFB compound document (0M8R prefix)"
        severity    = "medium"

    strings:
        $b64_ole = "0M8R" ascii

    condition:
        $b64_ole
}

rule Encoded_Base64_PDF
{
    meta:
        description = "Base64-encoded PDF document (JVBE prefix)"
        severity    = "medium"

    strings:
        $b64_pdf = "JVBE" ascii

    condition:
        $b64_pdf
}

rule Encoded_Base64_ZIP
{
    meta:
        description = "Base64-encoded ZIP archive (UEsD prefix)"
        severity    = "medium"

    strings:
        $b64_zip = "UEsD" ascii

    condition:
        $b64_zip
}

rule PowerShell_EncodedCommand
{
    meta:
        description = "PowerShell -EncodedCommand with Base64 payload"
        severity    = "high"

    strings:
        $enc1 = /-[Ee]nc\s+[A-Za-z0-9+\/]{20,}/
        $enc2 = /-[Ee]ncodedcommand\s+[A-Za-z0-9+\/]{20,}/ nocase
        $enc3 = /-[Ee][Cc]\s+[A-Za-z0-9+\/]{20,}/
        $from = "FromBase64String" nocase fullword

    condition:
        any of them
}

rule Hex_Encoded_PE_Header
{
    meta:
        description = "Hex-encoded PE executable header (4D5A9000)"
        severity    = "high"

    strings:
        $hex_mz_lower = "4d5a9000" ascii
        $hex_mz_upper = "4D5A9000" ascii
        $hex_mz_mixed = "4d5a90" ascii

    condition:
        any of them
}

rule Hex_Shellcode_Pattern
{
    meta:
        description = "Hex-encoded byte array pattern commonly used for shellcode"
        severity    = "medium"

    strings:
        $ps_bytes = /0x[0-9a-fA-F]{2}(,\s*0x[0-9a-fA-F]{2}){15,}/ ascii
        $escaped  = /(\\x[0-9a-fA-F]{2}){16,}/ ascii

    condition:
        any of them
}

rule Stacked_Encoding_Indicators
{
    meta:
        description = "Indicators of multi-layer encoding/obfuscation"
        severity    = "high"

    strings:
        $decompress   = "IO.Compression" nocase
        $memstream    = "IO.MemoryStream" nocase
        $deflate      = "DeflateStream" nocase
        $gzipstream   = "GZipStream" nocase
        $from_b64     = "FromBase64String" nocase
        $convert      = "[Convert]::" nocase
        $iex          = "Invoke-Expression" nocase fullword
        $iex_short    = /\bIEX\b/

    condition:
        3 of them
}

rule Embedded_ZIP_In_Non_Archive
{
    meta:
        description = "ZIP local file header (PK\\x03\\x04) found inside a non-archive file"
        severity    = "medium"

    strings:
        $pk = { 50 4B 03 04 }

    condition:
        #pk > 1
}

rule Embedded_Compressed_Stream
{
    meta:
        description = "Zlib or gzip compressed stream embedded in file"
        severity    = "info"

    strings:
        $zlib_default = { 78 9C }
        $zlib_best    = { 78 DA }
        $gzip_magic   = { 1F 8B 08 }

    condition:
        any of them
}

// ════════════════════════════════════════════════════════════════════════
// REG — Windows Registry File rules
// ════════════════════════════════════════════════════════════════════════

rule REG_Persistence_Run_Key
{
    meta:
        description = "Registry file modifies Run/RunOnce autostart keys (persistence)"
        severity    = "critical"

    strings:
        $header1 = "Windows Registry Editor" nocase
        $header2 = "REGEDIT4"
        $run1 = "CurrentVersion\\Run]" nocase
        $run2 = "CurrentVersion\\RunOnce]" nocase
        $run3 = "CurrentVersion\\RunOnceEx]" nocase
        $run4 = "CurrentVersion\\RunServices]" nocase

    condition:
        ($header1 or $header2) and any of ($run*)
}

rule REG_Persistence_Winlogon
{
    meta:
        description = "Registry file modifies Winlogon keys (persistence/credential theft)"
        severity    = "critical"

    strings:
        $header1 = "Windows Registry Editor" nocase
        $header2 = "REGEDIT4"
        $wl1 = "CurrentVersion\\Winlogon" nocase
        $wl2 = "\"Userinit\"" nocase
        $wl3 = "\"Shell\"" nocase

    condition:
        ($header1 or $header2) and $wl1 and any of ($wl2, $wl3)
}

rule REG_Security_Disable
{
    meta:
        description = "Registry file disables Windows security features"
        severity    = "critical"

    strings:
        $header1 = "Windows Registry Editor" nocase
        $header2 = "REGEDIT4"
        $dis1 = "DisableAntiSpyware" nocase
        $dis2 = "DisableRealtimeMonitoring" nocase
        $dis3 = "DisableBehaviorMonitoring" nocase
        $dis4 = "DisableOnAccessProtection" nocase
        $dis5 = "DisableScanOnRealtimeEnable" nocase
        $dis6 = "DisableAntiVirus" nocase
        $dis7 = "Windows Defender" nocase

    condition:
        ($header1 or $header2) and any of ($dis*)
}

rule REG_IFEO_Debugger
{
    meta:
        description = "Registry file sets Image File Execution Options debugger (process hijack)"
        severity    = "critical"

    strings:
        $header1 = "Windows Registry Editor" nocase
        $header2 = "REGEDIT4"
        $ifeo = "Image File Execution Options" nocase
        $dbg = "\"Debugger\"" nocase

    condition:
        ($header1 or $header2) and $ifeo and $dbg
}

rule REG_Service_Creation
{
    meta:
        description = "Registry file creates or modifies Windows services"
        severity    = "high"

    strings:
        $header1 = "Windows Registry Editor" nocase
        $header2 = "REGEDIT4"
        $svc1 = "\\Services\\" nocase
        $svc2 = "\"ImagePath\"" nocase
        $svc3 = "\"Start\"=dword:" nocase

    condition:
        ($header1 or $header2) and $svc1 and any of ($svc2, $svc3)
}

rule REG_UAC_Disable
{
    meta:
        description = "Registry file disables User Account Control"
        severity    = "critical"

    strings:
        $header1 = "Windows Registry Editor" nocase
        $header2 = "REGEDIT4"
        $uac1 = "EnableLUA" nocase
        $uac2 = "ConsentPromptBehaviorAdmin" nocase
        $uac3 = "PromptOnSecureDesktop" nocase

    condition:
        ($header1 or $header2) and any of ($uac*)
}

rule REG_COM_Hijack
{
    meta:
        description = "Registry file modifies COM class registration (COM hijacking)"
        severity    = "high"

    strings:
        $header1 = "Windows Registry Editor" nocase
        $header2 = "REGEDIT4"
        $com1 = "\\Classes\\CLSID\\" nocase
        $com2 = "InprocServer32" nocase
        $com3 = "\\Classes\\*\\shell" nocase

    condition:
        ($header1 or $header2) and any of ($com*)
}

rule REG_Suspicious_Values
{
    meta:
        description = "Registry file contains suspicious executable references in values"
        severity    = "high"

    strings:
        $header1 = "Windows Registry Editor" nocase
        $header2 = "REGEDIT4"
        $v1 = "powershell" nocase
        $v2 = "cmd.exe" nocase
        $v3 = "mshta" nocase
        $v4 = "regsvr32" nocase
        $v5 = "rundll32" nocase
        $v6 = "certutil" nocase
        $v7 = "bitsadmin" nocase
        $v8 = "wscript" nocase
        $v9 = "cscript" nocase
        $v10 = "-EncodedCommand" nocase
        $v11 = "FromBase64String" nocase
        $v12 = "DownloadString" nocase
        $v13 = "DownloadFile" nocase

    condition:
        ($header1 or $header2) and 2 of ($v*)
}

rule REG_File_Association_Hijack
{
    meta:
        description = "Registry file modifies file associations or shell handlers"
        severity    = "high"

    strings:
        $header1 = "Windows Registry Editor" nocase
        $header2 = "REGEDIT4"
        $fa1 = "\\Classes\\.exe\\" nocase
        $fa2 = "\\Classes\\exefile\\" nocase
        $fa3 = "\\Classes\\htmlfile\\" nocase
        $fa4 = "\\Classes\\http\\" nocase
        $fa5 = "\\shell\\open\\command" nocase

    condition:
        ($header1 or $header2) and any of ($fa*)
}

rule REG_Any_Presence
{
    meta:
        description = "Windows Registry import file detected"
        severity    = "info"

    strings:
        $header1 = "Windows Registry Editor Version 5.00"
        $header2 = "REGEDIT4"

    condition:
        any of them
}

// ════════════════════════════════════════════════════════════════════════
// INF — Windows Setup Information File rules
// ════════════════════════════════════════════════════════════════════════

rule INF_Command_Execution
{
    meta:
        description = "INF file with RunPreSetupCommands or RunPostSetupCommands (command execution)"
        severity    = "critical"

    strings:
        $sec1 = "[RunPreSetupCommands]" nocase
        $sec2 = "[RunPostSetupCommands]" nocase
        $cmd1 = "RunPreSetupCommands" nocase
        $cmd2 = "RunPostSetupCommands" nocase

    condition:
        any of them
}

rule INF_CMSTP_Bypass
{
    meta:
        description = "INF file references CMSTP (UAC bypass technique T1218.003)"
        severity    = "critical"

    strings:
        $cmstp1 = "cmstp" nocase
        $cmstp2 = "CMSTP.EXE" nocase
        $inf1 = "[DefaultInstall" nocase

    condition:
        any of ($cmstp*) and $inf1
}

rule INF_LOLBin_Reference
{
    meta:
        description = "INF file references LOLBins (Living-off-the-Land binaries)"
        severity    = "high"

    strings:
        $inf = "[DefaultInstall" nocase
        $lol1 = "rundll32" nocase
        $lol2 = "regsvr32" nocase
        $lol3 = "mshta" nocase
        $lol4 = "certutil" nocase
        $lol5 = "bitsadmin" nocase
        $lol6 = "scrobj.dll" nocase
        $lol7 = "msiexec" nocase

    condition:
        $inf and any of ($lol*)
}

rule INF_Script_Execution
{
    meta:
        description = "INF file references script interpreters"
        severity    = "high"

    strings:
        $inf = "[DefaultInstall" nocase
        $sc1 = "powershell" nocase
        $sc2 = "cmd.exe" nocase
        $sc3 = "wscript" nocase
        $sc4 = "cscript" nocase
        $sc5 = "cmd /c" nocase
        $sc6 = "cmd /k" nocase

    condition:
        $inf and any of ($sc*)
}

rule INF_Registry_Modification
{
    meta:
        description = "INF file with AddReg/DelReg directives (registry modification)"
        severity    = "medium"

    strings:
        $addreg = "AddReg" nocase
        $delreg = "DelReg" nocase
        $hklm = "HKLM" nocase
        $hkcu = "HKCU" nocase

    condition:
        any of ($addreg, $delreg) and any of ($hklm, $hkcu)
}

rule INF_DLL_Registration
{
    meta:
        description = "INF file registers DLLs or OCX components"
        severity    = "high"

    strings:
        $reg1 = "RegisterDlls" nocase
        $reg2 = "UnRegisterDlls" nocase
        $reg3 = "RegisterOCXs" nocase
        $reg4 = "UnRegisterOCXs" nocase

    condition:
        any of them
}

rule INF_URL_Reference
{
    meta:
        description = "INF file contains URL references"
        severity    = "medium"

    strings:
        $url1 = "http://" nocase
        $url2 = "https://" nocase
        $inf = "[Version]" nocase

    condition:
        $inf and any of ($url*)
}

rule INF_Any_Presence
{
    meta:
        description = "Windows Setup Information file detected"
        severity    = "info"

    strings:
        $ver = "[Version]" nocase
        $sig1 = "Signature=" nocase
        $sig2 = "$Chicago$"
        $sig3 = "$Windows NT$"

    condition:
        $ver and any of ($sig*)
}

// ════════════════════════════════════════════════════════════════════════
// SCT — Windows Script Component (COM Scriptlet) rules
// ════════════════════════════════════════════════════════════════════════

rule SCT_Squiblydoo
{
    meta:
        description = "SCT scriptlet with regsvr32 references (Squiblydoo attack T1218.010)"
        severity    = "critical"

    strings:
        $sct1 = "<scriptlet" nocase
        $sct2 = "<registration" nocase
        $reg1 = "regsvr32" nocase
        $reg2 = "scrobj.dll" nocase

    condition:
        any of ($sct*) and any of ($reg*)
}

rule SCT_Script_Execution
{
    meta:
        description = "SCT scriptlet with embedded script code"
        severity    = "high"

    strings:
        $sct = "<scriptlet" nocase
        $sc1 = "<script" nocase
        $lang1 = "JScript" nocase
        $lang2 = "VBScript" nocase

    condition:
        $sct and $sc1 and any of ($lang*)
}

rule SCT_COM_Object_Creation
{
    meta:
        description = "SCT scriptlet creates COM objects (code execution)"
        severity    = "high"

    strings:
        $sct = "<scriptlet" nocase
        $com1 = "CreateObject" nocase
        $com2 = "GetObject" nocase
        $com3 = "WScript.Shell" nocase
        $com4 = "Shell.Application" nocase
        $com5 = "Scripting.FileSystemObject" nocase

    condition:
        $sct and any of ($com*)
}

rule SCT_Network_Access
{
    meta:
        description = "SCT scriptlet with network access capabilities"
        severity    = "high"

    strings:
        $sct = "<scriptlet" nocase
        $net1 = "XMLHTTP" nocase
        $net2 = "MSXML2" nocase
        $net3 = "WinHttp" nocase
        $net4 = "ADODB.Stream" nocase
        $net5 = "DownloadFile" nocase
        $net6 = "DownloadString" nocase

    condition:
        $sct and any of ($net*)
}

rule SCT_Shell_Command
{
    meta:
        description = "SCT scriptlet executes shell commands"
        severity    = "critical"

    strings:
        $sct = "<scriptlet" nocase
        $cmd1 = "powershell" nocase
        $cmd2 = "cmd.exe" nocase
        $cmd3 = "cmd /c" nocase
        $cmd4 = ".Run" nocase
        $cmd5 = ".Exec" nocase
        $cmd6 = "mshta" nocase

    condition:
        $sct and 2 of ($cmd*)
}

rule SCT_Any_Presence
{
    meta:
        description = "Windows Script Component (SCT/WSC scriptlet) detected"
        severity    = "medium"

    strings:
        $sct1 = "<scriptlet" nocase
        $sct2 = "<registration" nocase
        $sct3 = "classid=" nocase

    condition:
        $sct1 and any of ($sct2, $sct3)
}

// ════════════════════════════════════════════════════════════════════════
// MSI — Windows Installer Package rules
// ════════════════════════════════════════════════════════════════════════

rule MSI_Embedded_PE
{
    meta:
        description = "MSI installer contains embedded PE executable"
        severity    = "critical"

    strings:
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $mz1 = { 4D 5A 90 00 }
        $mz2 = { 4D 5A 50 45 }
        $pe  = "This program cannot be run in DOS mode"

    condition:
        $ole at 0 and (any of ($mz*) or $pe)
}

rule MSI_Embedded_Script
{
    meta:
        description = "MSI installer contains embedded script content"
        severity    = "high"

    strings:
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $sc1 = "WScript.Shell" nocase
        $sc2 = "Scripting.FileSystemObject" nocase
        $sc3 = "CreateObject" nocase
        $sc4 = "powershell" nocase
        $sc5 = "cmd.exe /c" nocase
        $sc6 = "Shell.Application" nocase

    condition:
        $ole at 0 and 2 of ($sc*)
}

rule MSI_Suspicious_CustomAction
{
    meta:
        description = "MSI installer references CustomAction execution patterns"
        severity    = "high"

    strings:
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $ca = "CustomAction" nocase
        $cmd1 = "powershell" nocase
        $cmd2 = "cmd.exe" nocase
        $cmd3 = "mshta" nocase
        $cmd4 = "wscript" nocase
        $cmd5 = "cscript" nocase
        $cmd6 = "certutil" nocase
        $cmd7 = "bitsadmin" nocase
        $cmd8 = "rundll32" nocase

    condition:
        $ole at 0 and $ca and any of ($cmd*)
}

rule MSI_Network_Indicators
{
    meta:
        description = "MSI installer contains network URL references"
        severity    = "medium"

    strings:
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $url1 = "http://" nocase
        $url2 = "https://" nocase
        $url3 = "ftp://" nocase

    condition:
        $ole at 0 and any of ($url*)
}

rule MSI_Encoded_Content
{
    meta:
        description = "MSI installer contains Base64 or encoded command indicators"
        severity    = "high"

    strings:
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $enc1 = "-EncodedCommand" nocase
        $enc2 = "-enc " nocase
        $enc3 = "FromBase64String" nocase
        $enc4 = "Convert]::FromBase64" nocase

    condition:
        $ole at 0 and any of ($enc*)
}

rule MSI_Service_Install
{
    meta:
        description = "MSI installer creates Windows services"
        severity    = "medium"

    strings:
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $svc1 = "ServiceInstall" nocase
        $svc2 = "ServiceControl" nocase

    condition:
        $ole at 0 and any of ($svc*)
}
