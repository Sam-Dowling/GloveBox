// ─── Office Macros ───
// 33 rules

rule Office_Macro_Project_Present
{
    meta:
        description = "Office document contains VBA project streams or references"
        severity    = "info"
        category    = "execution"
        mitre       = "T1059.005"

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
        category    = "execution"
        mitre       = "T1204.002"

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
        category    = "execution"
        mitre       = "T1059.005"

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
        category    = "command-and-control"
        mitre       = "T1105"

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
        category    = "defense-evasion"
        mitre       = "T1027"

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
        category    = "execution"
        mitre       = "T1059.001"

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
        category    = "discovery"
        mitre       = "T1082"

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
        category    = "execution"
        mitre       = "T1059.005"

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
        category    = "persistence"
        mitre       = "T1547.001"

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
        category    = "persistence"
        mitre       = "T1053.005"

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
        category    = "execution"
        mitre       = "T1559.001"

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
        category    = "defense-evasion"
        mitre       = "T1218.005"

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
        category    = "defense-evasion"
        mitre       = "T1140"

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
        category    = "defense-evasion"
        mitre       = "T1497.003"

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
        category    = "execution"
        mitre       = "T1559.002"

    strings:
        $a = "DDE" nocase fullword
        $b = "DDEAUTO" nocase
        $c = "DDEAUTO" nocase wide

    condition:
        any of them
}

rule Office_OLE_Embedded_Object
{
    meta:
        description = "Document contains embedded OLE object control words"
        severity    = "high"
        category    = "execution"
        mitre       = "T1204.002"

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
        category    = "defense-evasion"
        mitre       = "T1221"

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
        category    = "execution"
        mitre       = "T1204.002"

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
        category    = "execution"
        mitre       = "T1203"

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
        category    = "execution"
        mitre       = "T1203"

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
        category    = "defense-evasion"
        mitre       = "T1221"

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
        category    = "execution"
        mitre       = "T1559.001"

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
        category    = "execution"
        mitre       = "T1059.005"

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
        category    = "execution"
        mitre       = "T1559.002"

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
        category    = "defense-evasion"
        mitre       = "T1027"

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
        category    = "defense-evasion"
        mitre       = "T1564.007"

    strings:
        $a = "_VBA_PROJECT" wide
        $b = "Attribute VB_"
        $c = "VBA_PROJECT_CUR" wide
        $d = "PROJECT" wide

    condition:
        $a and not $b and ($c or $d)
}

rule AddIn_XLL_File
{
    meta:
        description = "Excel Add-In (XLL) file — executes native code when loaded, bypasses macro policy"
        severity    = "critical"
        category    = "execution"
        mitre       = "T1137.006"

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
        category    = "execution"
        mitre       = "T1137.006"

    strings:
        $pk = { 50 4B 03 04 }
        $a = "ppt/vbaProject.bin"
        $b = "vbaProject.bin"
        $c = "macroEnabled" nocase

    condition:
        $pk and any of ($a, $b, $c)
}

rule VBA_GetObject_WMI
{
    meta:
        description = "VBA uses GetObject to access WMI or remote resources"
        severity    = "high"
        category    = "execution"
        mitre       = "T1047"

    strings:
        $get   = "GetObject" nocase
        $a     = "winmgmts" nocase
        $b     = "Win32_Process" nocase
        $c     = "Win32_ComputerSystem" nocase
        $vba   = "Sub " nocase

    condition:
        $vba and $get and any of ($a, $b, $c)
}

rule VBA_Shell_Application_Abuse
{
    meta:
        description = "VBA creates Shell.Application object — can execute programs and browse namespace"
        severity    = "high"
        category    = "execution"
        mitre       = "T1059.005"

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
        category    = "execution"
        mitre       = "T1559.002"

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
        category    = "execution"
        mitre       = "T1059.001"

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
        category    = "execution"
        mitre       = "T1047"

    strings:
        $a     = "wbemdisp.dll" nocase
        $b     = "SWbemLocator" nocase
        $c     = "WbemScripting" nocase
        $vba   = "Sub " nocase

    condition:
        $vba and any of ($a, $b, $c)
}

