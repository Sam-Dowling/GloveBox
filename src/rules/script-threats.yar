rule PS_Whitespace_Token_Obfuscation
{
    meta:
        description = "Detects PowerShell token obfuscation via excessive whitespace between characters"
        severity = "medium"
        category = "obfuscation"
        mitre       = "T1027"
        applies_to  = "ps1, plaintext, decoded-payload"
    strings:
        $ws_pattern = /[A-Za-z]\s{2,}[A-Za-z]\s{2,}[A-Za-z]\s{2,}[A-Za-z]\s{2,}[A-Za-z]/ nocase
        $ws_cmdlet = /[Ww]\s{2,}[Rr]\s{2,}[Ii]\s{2,}[Tt]\s{2,}[Ee]/ nocase
        $ws_iex = /[Ii]\s{2,}[Ee]\s{2,}[Xx]/ nocase
    condition:
        any of them
}

rule PS_ScriptBlock_Reflection_Create
{
    meta:
        description = "Detects PowerShell ScriptBlock creation via .NET reflection"
        severity = "high"
        category = "obfuscation"
        mitre       = "T1059.001"
        applies_to  = "ps1, plaintext, decoded-payload"
    strings:
        $sb_reflect = "ScriptBlock].GetMethod" nocase
        $sb_create = /ScriptBlock\].*Create/ nocase
        $invoke = ".Invoke(" nocase
        $automation = "System.Management.Automation" nocase
    condition:
        ($sb_reflect or $sb_create) and ($invoke or $automation)
}

rule Python_Dynamic_Import_Getattr
{
    meta:
        description = "Detects Python dynamic import with getattr/getattribute for obfuscated access"
        severity = "medium"
        category = "obfuscation"
        mitre       = "T1059.006"
        applies_to  = "py, plaintext, decoded-payload"
    strings:
        $import_builtins = "__import__('builtins')" nocase
        $import_os = "__import__('os')" nocase
        $import_sys = "__import__('sys')" nocase
        $import_sub = "__import__('subprocess')" nocase
        $getattr1 = "__getattribute__(" nocase
        $getattr2 = "getattr(" nocase
    condition:
        any of ($import_*) and any of ($getattr*)
}

rule JS_Comment_Injection_Obfuscation
{
    meta:
        description = "Detects JavaScript comment injection between object property access chains"
        severity = "medium"
        category = "obfuscation"
        mitre       = "T1027"
        applies_to  = "js, html, hta, plaintext, decoded-payload"
    strings:
        $comment_dot = /\w+\s*\/\*[^*]*\*\/\s*\.\s*\/\*[^*]*\*\/\s*\w+/ nocase
        $comment_bracket = /\w+\s*\/\*[^*]*\*\/\s*\[\s*\/\*[^*]*\*\/\s*['"]/ nocase
        $comment_call = /\w+\s*\/\*[^*]*\*\/\s*\(\s*\/\*[^*]*\*\/\s*['"]/ nocase
    condition:
        any of them
}

rule JS_WSH_Dropper
{
    meta:
        description = "JavaScript uses Windows Script Host objects with execution capability"
        severity    = "critical"
        category    = "execution"
        mitre       = "T1059.007"
        applies_to  = "js, html, hta, plaintext, decoded-payload"
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
        category    = "defense-evasion"
        mitre       = "T1027"
        applies_to  = "js, html, hta, plaintext, decoded-payload"
    strings:
        $cc1 = "fromCharCode" nocase
        $cc2 = "String.fromCharCode" nocase
        $cc3 = "charCodeAt" nocase
        $eval = "eval("
        $func = "Function("
        $arr = /\[\d{2,3}(,\d{2,3}){20,}\]/
        $split = /\"[^\"]{200,}\"\.split\(/

    condition:
        (($cc1 or $cc2 or $cc3) and ($eval or $func)) or $arr or ($split and ($eval or $func))
}

rule Encoded_Script_File_JSE_VBE
{
    meta:
        description = "File contains Microsoft JScript.Encode or VBScript.Encode markers (JSE/VBE)"
        severity    = "high"
        category    = "defense-evasion"
        mitre       = "T1027.010"
        applies_to  = "js, vbs, plaintext, decoded-payload"
    strings:
        $marker_start = "#@~^" ascii
        $marker_end   = "^#~@" ascii
        $lang1 = "JScript.Encode" nocase
        $lang2 = "VBScript.Encode" nocase

    condition:
        ($marker_start and $marker_end) or any of ($lang*)
}

rule JS_WMI_Execution
{
    meta:
        description = "JavaScript uses WMI to execute processes — evasion of direct Shell calls"
        severity    = "critical"
        category    = "execution"
        mitre       = "T1047"
        applies_to  = "js, html, hta, plaintext, decoded-payload"
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
        category    = "execution"
        mitre       = "T1204.001"
        applies_to  = "js, html, hta, plaintext, decoded-payload"
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
        category    = "defense-evasion"
        mitre       = "T1140"
        applies_to  = "js, html, hta, plaintext, decoded-payload"
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
        category    = "execution"
        mitre       = "T1059.005"
        applies_to  = "vbs, hta, plaintext, decoded-payload"
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

rule VBS_Registry_Persistence
{
    meta:
        description = "VBScript writes registry Run keys for persistence"
        severity    = "critical"
        category    = "persistence"
        mitre       = "T1547.001"
        applies_to  = "vbs, hta, plaintext, decoded-payload"
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
        category    = "persistence"
        mitre       = "T1053.005"
        applies_to  = "vbs, hta, plaintext, decoded-payload"
    strings:
        $a = "Schedule.Service" nocase
        $b = "schtasks" nocase
        $c = "RegisterTaskDefinition" nocase
        $d = "WScript.Shell" nocase

    condition:
        ($a or $b or $c) and $d
}

rule VBS_Obfuscation_ChrW
{
    meta:
        description = "VBScript uses heavy ChrW/Chr obfuscation to build strings dynamically"
        severity    = "high"
        category    = "defense-evasion"
        mitre       = "T1027"
        applies_to  = "vbs, hta, plaintext, decoded-payload"
    strings:
        $a = "ChrW(" nocase
        $b = "Chr(" nocase
        $c = "Execute(" nocase
        $d = "ExecuteGlobal(" nocase

    condition:
        ($a or $b) and ($c or $d)
}

rule PowerShell_Encoded_Command
{
    meta:
        description = "PowerShell invoked with encoded command flag — hides base64 payload"
        severity    = "critical"
        category    = "execution"
        mitre       = "T1059.001"
        applies_to  = "ps1, plaintext, decoded-payload"
    strings:
        $ps  = "powershell" nocase
        $a   = "-EncodedCommand" nocase
        $b   = "-enc " nocase
        $c   = "-ec " nocase
        $enc1 = /-[Ee]nc\s+[A-Za-z0-9+\/]{20,}/
        $enc2 = /-[Ee]ncodedcommand\s+[A-Za-z0-9+\/]{20,}/ nocase
        $enc3 = /-[Ee][Cc]\s+[A-Za-z0-9+\/]{20,}/
        $from = "FromBase64String" nocase fullword

    condition:
        ($ps and ($a or $b or $c or $from)) or any of ($enc*)
}

rule PowerShell_Download_Cradle
{
    meta:
        description = "PowerShell download cradle — fetches and executes remote code"
        severity    = "critical"
        category    = "execution"
        mitre       = "T1059.001"
        applies_to  = "ps1, plaintext, decoded-payload"
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
        category    = "defense-evasion"
        mitre       = "T1562.001"
        applies_to  = "ps1, plaintext, decoded-payload"
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
        category    = "defense-evasion"
        mitre       = "T1620"
        applies_to  = "ps1, plaintext, decoded-payload"
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
        category    = "defense-evasion"
        mitre       = "T1059.001"
        applies_to  = "ps1, plaintext, decoded-payload"
    strings:
        $a = "-ExecutionPolicy" nocase
        $b = "Bypass" nocase
        $c = "Unrestricted" nocase
        $d = "-ep " nocase
        $e = "Set-ExecutionPolicy" nocase

    condition:
        ($a and ($b or $c)) or ($d and ($b or $c)) or ($e and ($b or $c))
}

rule PowerShell_Hidden_Window
{
    meta:
        description = "PowerShell runs with hidden window — user won't see execution"
        severity    = "high"
        category    = "defense-evasion"
        mitre       = "T1059.001"
        applies_to  = "ps1, plaintext, decoded-payload"
    strings:
        $a = "-WindowStyle" nocase
        $b = "Hidden" nocase
        $c = "-w hidden" nocase
        $d = "-win hidden" nocase
        $e = "-nop" nocase

    condition:
        ($a and $b) or ($c and $e) or ($d and $e)
}

rule PowerShell_Credential_Theft
{
    meta:
        description = "PowerShell accesses stored credentials or prompts for credentials"
        severity    = "critical"
        category    = "credential-access"
        mitre       = "T1003"
        applies_to  = "ps1, plaintext, decoded-payload"
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
        category    = "defense-evasion"
        mitre       = "T1140"
        applies_to  = "ps1, plaintext, decoded-payload"
    strings:
        $a = "certutil" nocase
        $b = "-decode" nocase
        $c = "powershell" nocase

    condition:
        $a and $b and $c
}

rule BAT_Download_Execute
{
    meta:
        description = "Batch file downloads and executes a remote payload"
        severity    = "critical"
        category    = "execution"
        mitre       = "T1059.003"
        applies_to  = "bat, plaintext, decoded-payload"
    strings:
        $a = "certutil" nocase
        $b = "bitsadmin" nocase
        $c = "powershell" nocase
        $d = "curl " nocase
        $e = "wget " nocase
        $f = "-decode" nocase
        $g = "/transfer" nocase
        $h = "-urlcache" nocase
        $i = /-[Ee]nc(odedCommand)?\b/

    condition:
        any of ($a, $b, $c, $d, $e) and any of ($f, $g, $h, $i)
}

rule BAT_Obfuscated_Variables
{
    meta:
        description = "Batch file uses variable obfuscation — environment variable substring abuse"
        severity    = "high"
        category    = "defense-evasion"
        mitre       = "T1027"
        applies_to  = "bat, plaintext, decoded-payload"
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
        category    = "execution"
        mitre       = "T1074.001"
        applies_to  = "bat, plaintext, decoded-payload"
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
        category    = "persistence"
        mitre       = "T1547.001"
        applies_to  = "bat, plaintext, decoded-payload"
    strings:
        $a = "reg add" nocase
        $b = "CurrentVersion\\Run" nocase
        $c = "reg.exe" nocase

    condition:
        ($a or $c) and $b
}

rule JS_DocumentWrite_With_Obfuscation
{
    meta:
        description = "JavaScript uses document.write with encoding/decoding — DOM-based payload injection"
        severity    = "high"
        category    = "defense-evasion"
        mitre       = "T1027"
        applies_to  = "js, html, hta, plaintext, decoded-payload"
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
        category    = "initial-access"
        mitre       = "T1566.002"
        applies_to  = "js, html, hta, plaintext, decoded-payload"
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
        category    = "execution"
        mitre       = "T1059.007"
        applies_to  = "js, html, hta, plaintext, decoded-payload"
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
        category    = "execution"
        mitre       = "T1059.001"
        applies_to  = "ps1, plaintext, decoded-payload"
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
        category    = "lateral-movement"
        mitre       = "T1021.006"
        applies_to  = "ps1, plaintext, decoded-payload"
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
        category    = "execution"
        mitre       = "T1059.001"
        applies_to  = "ps1, plaintext, decoded-payload"
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

rule WMIC_Process_Create
{
    meta:
        description = "WMIC used to create remote processes — lateral movement technique"
        severity    = "critical"
        category    = "execution"
        mitre       = "T1047"
        applies_to  = "bat, plaintext, decoded-payload"
    strings:
        $a     = "wmic" nocase
        $b     = "process" nocase fullword
        $c     = "call" nocase fullword
        $d     = "create" nocase fullword

    condition:
        $a and $b and $c and $d
}

rule PowerShell_WMI_Event_Persistence
{
    meta:
        description = "PowerShell creates WMI event subscription — fileless persistence"
        severity    = "critical"
        category    = "persistence"
        mitre       = "T1546.003"
        applies_to  = "ps1, plaintext, decoded-payload"
    strings:
        $a     = "__EventFilter" nocase
        $b     = "CommandLineEventConsumer" nocase
        $c     = "__FilterToConsumerBinding" nocase
        $d     = "Register-WmiEvent" nocase
        $e     = "Set-WmiInstance" nocase

    condition:
        2 of them
}

rule AMSI_ETW_Bypass_Patterns
{
    meta:
        description = "File attempts to patch AMSI or disable ETW tracing"
        severity    = "critical"
        category    = "defense-evasion"
        mitre       = "T1562.001"
        applies_to  = "ps1, bat, plaintext, decoded-payload"
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

rule CMD_Caret_Obfuscation
{
    meta:
        description = "CMD command uses caret (^) insertion to break up keywords and evade detection"
        severity    = "high"
        category    = "defense-evasion"
        mitre       = "T1027"
        applies_to  = "bat, plaintext, decoded-payload"
    strings:
        $c1 = /[pP]\^[oO]\^[wW]\^[eE]\^[rR]\^[sS]\^[hH]\^[eE]\^[lL]\^[lL]/ ascii
        $c2 = /[cC]\^[mM]\^[dD]/ ascii
        $c3 = /[wW]\^[sS]\^[cC]\^[rR]\^[iI]\^[pP]\^[tT]/ ascii
        $c4 = /[nN]\^[eE]\^[tT]\.\^[wW]\^[eE]\^[bB]\^[cC]\^[lL]\^[iI]\^[eE]\^[nN]\^[tT]/ ascii
        $c5 = /[rR]\^[eE]\^[gG]\^[sS]\^[vV]\^[rR]\^3\^2/ ascii
        $c6 = /[mM]\^[sS]\^[hH]\^[tT]\^[aA]/ ascii
        $c7 = /[bB]\^[iI]\^[tT]\^[sS]\^[aA]\^[dD]\^[mM]\^[iI]\^[nN]/ ascii
        $c8 = /[cC]\^[eE]\^[rR]\^[tT]\^[uU]\^[tT]\^[iI]\^[lL]/ ascii
        $generic = /\w\^\w\^\w\^\w\^\w\^\w/ ascii

    condition:
        any of them
}

rule CMD_Set_Variable_Obfuscation
{
    meta:
        description = "CMD script uses SET variable concatenation to build commands from fragments"
        severity    = "high"
        category    = "defense-evasion"
        mitre       = "T1027"
        applies_to  = "bat, plaintext, decoded-payload"
    strings:
        $set_pattern = /[sS][eE][tT]\s+\w{1,3}=\S{1,20}/ ascii
        $concat = /(%\w{1,3}%){3,}/ ascii
        $call = /[cC][aA][lL][lL]\s+(%\w{1,3}%){2,}/ ascii

    condition:
        (#set_pattern > 3 and $concat) or $call
}

rule CMD_Environment_Substring_Abuse
{
    meta:
        description = "CMD script extracts substrings from environment variables to build commands"
        severity    = "high"
        category    = "defense-evasion"
        mitre       = "T1027"
        applies_to  = "bat, plaintext, decoded-payload"
    strings:
        $substr = /(%\w+:~\d{1,3},\d{1,3}%){3,}/ ascii
        $comspec = "%comspec:~" nocase
        $path_sub = "%path:~" nocase

    condition:
        $substr or (#comspec > 2) or (#path_sub > 2)
}

rule PS_String_Concatenation_Obfuscation
{
    meta:
        description = "PowerShell uses excessive string concatenation to evade keyword detection"
        severity    = "medium"
        category    = "defense-evasion"
        mitre       = "T1027"
        applies_to  = "ps1, plaintext, decoded-payload"
    strings:
        $concat_single = /('[a-zA-Z]{1,4}'\s*\+\s*){4,}'[a-zA-Z]{1,4}'/ ascii
        $concat_double = /("[a-zA-Z]{1,4}"\s*\+\s*){4,}"[a-zA-Z]{1,4}"/ ascii
        $iex_concat = /[iI][eE][xX]\s*\(\s*['"][a-zA-Z]{1,3}['"]\s*\+/ ascii

    condition:
        any of them
}

rule PS_Backtick_Obfuscation
{
    meta:
        description = "PowerShell uses backtick escape characters to break up keywords"
        severity    = "medium"
        category    = "defense-evasion"
        mitre       = "T1027"
        applies_to  = "ps1, plaintext, decoded-payload"
    strings:
        $bt1 = "In`v`o`k`e" ascii
        $bt2 = "Ne`w`-O`b`j" ascii
        $bt3 = "Do`wn`lo`ad" ascii
        $bt4 = "We`b`Cl`ie`nt" ascii
        $bt5 = "Sy`st`em" ascii
        $bt6 = "Ne`t." ascii
        $bt7 = /\w`\w`\w`\w`\w`\w/ ascii

    condition:
        any of them
}

rule PS_Format_Operator_Obfuscation
{
    meta:
        description = "PowerShell uses -f format operator to reconstruct strings from fragments"
        severity    = "medium"
        category    = "defense-evasion"
        mitre       = "T1027"
        applies_to  = "ps1, plaintext, decoded-payload"
    strings:
        $fmt = /'\{0\}\{1\}\{2\}(\{3\})?(\{4\})?(\{5\})?' *-[fF] *'[^']{1,12}',\s*'[^']{1,12}',\s*'[^']{1,12}'/ ascii

    condition:
        $fmt
}

rule PS_Char_Casting_Obfuscation
{
    meta:
        description = "PowerShell uses [char] type casting to build strings from ASCII codes"
        severity    = "high"
        category    = "defense-evasion"
        mitre       = "T1027"
        applies_to  = "ps1, plaintext, decoded-payload"
    strings:
        $char = /(\[char\]\d{2,3}\s*\+\s*){4,}/ nocase
        $char_join = /\-join\s*\(\s*(\d{2,3}\s*,\s*){4,}/ nocase
        $char_arr = /\[char\[\]\]\s*\(\s*(\d{2,3}\s*,\s*){4,}/ nocase

    condition:
        any of them
}

rule PS_String_Reversal_Obfuscation
{
    meta:
        description = "PowerShell reverses strings to hide commands"
        severity    = "medium"
        category    = "defense-evasion"
        mitre       = "T1027"
        applies_to  = "ps1, plaintext, decoded-payload"
    strings:
        $rev1 = /\[array\]::reverse\s*\(/ nocase
        $rev2 = /-join\s*\[regex\]::matches\([^)]+,\s*'\.'\s*,\s*'RightToLeft'\)/ nocase
        $rev3 = /\$[a-zA-Z]+\[-1\.\.-?\d+\]/ ascii

    condition:
        any of them
}

rule PS_Replace_Chain_Obfuscation
{
    meta:
        description = "PowerShell uses chained -replace operators to transform encoded strings"
        severity    = "medium"
        category    = "defense-evasion"
        mitre       = "T1027"
        applies_to  = "ps1, plaintext, decoded-payload"
    strings:
        $rep = /(-replace\s*'[^']{1,20}'\s*,\s*'[^']{0,20}'\s*){3,}/ nocase
        $creplace = /(\.\s*replace\s*\(\s*'[^']{1,20}'\s*,\s*'[^']{0,20}'\s*\)\s*){3,}/ nocase

    condition:
        any of them
}

rule VBScript_Chr_Concatenation
{
    meta:
        description = "VBScript uses Chr() function concatenation to build strings"
        severity    = "high"
        category    = "defense-evasion"
        mitre       = "T1027"
        applies_to  = "vbs, hta, plaintext, decoded-payload"
    strings:
        $chr = /([Cc][Hh][Rr]\s*\(\s*\d{2,3}\s*\)\s*(&|&amp;)\s*){5,}/ ascii
        $chrw = /([Cc][Hh][Rr][Ww]\s*\(\s*\d{2,5}\s*\)\s*(&|&amp;)\s*){5,}/ ascii

    condition:
        any of them
}

rule Python_Exec_Base64_Obfuscation
{
    meta:
        description = "Detects Python code using exec() with base64-decoded payloads"
        severity = "high"
        category = "obfuscation"
        mitre       = "T1059.006"
        reference = "Python exec + base64 payload delivery"
        applies_to  = "py, plaintext, decoded-payload"
    strings:
        $exec_b64_1 = "exec(base64.b64decode(" nocase
        $exec_b64_2 = "exec(__import__('base64').b64decode(" nocase
        $exec_b64_3 = "exec(compile(base64" nocase
        $exec_b64_4 = "exec(marshal.loads(" nocase
        $exec_b64_5 = "exec(zlib.decompress(base64" nocase
        $import_os = "__import__('os')" nocase
        $import_subprocess = "__import__('subprocess')" nocase
        $import_socket = "__import__('socket')" nocase
        $exec_compile = "exec(compile(" nocase

    condition:
        any of ($exec_b64_*) or ($exec_compile and any of ($import_*))
}

rule Python_Eval_Codec_Obfuscation
{
    meta:
        description = "Detects Python eval/exec with codec or marshal-based obfuscation"
        severity = "high"
        category = "obfuscation"
        mitre       = "T1059.006"
        reference = "Python eval with codec/zlib/marshal deobfuscation"
        applies_to  = "py, plaintext, decoded-payload"
    strings:
        $eval = "eval(" nocase
        $exec = "exec(" nocase
        $codecs_decode = "codecs.decode(" nocase
        $rot13 = "'rot_13'" nocase
        $rot13b = "'rot13'" nocase
        $zlib_decompress = "zlib.decompress(" nocase
        $marshal_loads = "marshal.loads(" nocase
        $bytearray = "bytearray(" nocase
        $chr_join = /chr\s*\(\s*\w+\s*\)\s*for\s+\w+\s+in/

    condition:
        ($eval or $exec) and (any of ($codecs_decode, $rot13, $rot13b, $zlib_decompress, $marshal_loads) or ($bytearray and $chr_join))
}

rule Python_Char_Construction
{
    meta:
        description = "Detects Python string construction via chr() calls to evade static analysis"
        severity = "medium"
        category = "obfuscation"
        mitre       = "T1027"
        reference = "Python chr() string building"
        applies_to  = "py, plaintext, decoded-payload"
    strings:
        $chr_chain = /chr\(\d+\)\s*\+\s*chr\(\d+\)\s*\+\s*chr\(\d+\)/
        $chr_join = /join\s*\(\s*\[?\s*chr\s*\(\s*\d+\s*\)/ nocase
        $chr_map = /map\s*\(\s*chr\s*,\s*\[/ nocase
        $exec = "exec(" nocase
        $eval = "eval(" nocase

    condition:
        any of ($chr_chain, $chr_join, $chr_map) and ($exec or $eval)
}

rule JS_ROT13_Cipher_Implementation
{
    meta:
        description = "Detects JavaScript ROT13/Caesar cipher implementations used for obfuscation"
        severity = "medium"
        category = "obfuscation"
        mitre       = "T1027"
        reference = "ROT13 character rotation in JavaScript"
        applies_to  = "js, html, hta, plaintext, decoded-payload"
    strings:
        $charcode_13 = /charCodeAt\s*\(\s*\w*\s*\)\s*[\+\-]\s*13/ nocase
        $replace_alpha = /replace\s*\(\s*\/\[a-zA-Z\]\// nocase
        $fromcharcode_shift = /String\.fromCharCode\s*\([^)]*[\+\-]\s*13\s*\)/ nocase
        $rot13_func = /function\s+rot13\s*\(/ nocase
        $rot13_name = "rot13" nocase
        $caesar_shift = /charCodeAt\s*\([^)]*\)\s*[\+\-]\s*\d{1,2}\s*\)\s*%\s*26/ nocase

    condition:
        ($charcode_13 and $replace_alpha) or $fromcharcode_shift or ($rot13_func) or $caesar_shift
}

rule PS_Call_Operator_Obfuscation
{
    meta:
        description = "Detects PowerShell call operator (&) with string concatenation to invoke commands dynamically"
        severity = "high"
        category = "obfuscation"
        mitre       = "T1027"
        reference = "PowerShell & operator with dynamic command construction"
        applies_to  = "ps1, plaintext, decoded-payload"
    strings:
        $call_concat_1 = /&\s*\(\s*['"][a-zA-Z]+['"]\s*\+\s*['"][a-zA-Z]+['"]/ nocase
        $call_concat_2 = /&\s*\(\s*\$[a-zA-Z]+\s*\+\s*\$[a-zA-Z]+\s*\)/ nocase
        $call_iex = /&\s*\(\s*['"]i['"\s]*\+\s*['"]e['"\s]*\+\s*['"]x['"]\s*\)/ nocase
        $dot_invoke = /\.\s*\(\s*['"][a-zA-Z]+['"]\s*\+/ nocase

    condition:
        any of them
}

rule PS_EnvVar_Payload_Execution
{
    meta:
        description = "Detects PowerShell using environment variables as payload containers with IEX"
        severity = "high"
        category = "obfuscation"
        mitre       = "T1027"
        reference = "PowerShell $env: variable payload + IEX execution"
        applies_to  = "ps1, plaintext, decoded-payload"
    strings:
        $env_set = /\$env:\w+\s*=\s*['"]/ nocase
        $env_set2 = /\[Environment\]::SetEnvironmentVariable\s*\(/ nocase
        $env_get = /\$env:\w+/ nocase
        $iex = "iex" nocase
        $invoke_expr = "Invoke-Expression" nocase
        $env_iex_combo = /iex\s*\(?\s*\$env:\w+/ nocase
        $env_iex_combo2 = /Invoke-Expression\s*\(?\s*\$env:\w+/ nocase

    condition:
        any of ($env_iex_combo*) or (any of ($env_set*) and any of ($iex, $invoke_expr) and $env_get)
}

rule PS_Split_Join_Reassembly
{
    meta:
        description = "Detects PowerShell -split/-join operators used for string reassembly obfuscation"
        severity = "medium"
        category = "obfuscation"
        mitre       = "T1027"
        reference = "PowerShell -split + -join pattern for payload reassembly"
        applies_to  = "ps1, plaintext, decoded-payload"
    strings:
        $split_join_1 = /\-split\s*['"][^'"]+['"]\s*\-join\s*['"][^'"]*['"]/ nocase
        $split_join_2 = /\.Split\s*\(\s*['"][^'"]+['"]\s*\)\s*[-\.]join/ nocase
        $string_join = /\[string\]::Join\s*\(/ nocase
        $split_iex = /\-split\s*['"][^'"]+['"].*iex/ nocase
        $join_iex = /\-join\s*['"][^'"]*['"].*iex/ nocase
        $split_invoke = /\-split\s*['"][^'"]+['"].*Invoke-Expression/ nocase
        $iex = /\b[iI][eE][xX]\b/
        $invoke_expr = "Invoke-Expression" nocase

    condition:
        $split_join_1 or $split_join_2 or $split_iex or $join_iex or $split_invoke or ($string_join and ($iex or $invoke_expr))
}

rule PS_Hashtable_Command_Construction
{
    meta:
        description = "Detects PowerShell hashtable-based command construction and invocation"
        severity = "medium"
        category = "obfuscation"
        mitre       = "T1027"
        reference = "PowerShell @{} hashtable with call operator execution"
        applies_to  = "ps1, plaintext, decoded-payload"
    strings:
        $hashtable = /\$\w+\s*=\s*@\{/ nocase
        $call_key = /&\s*\(?\s*\$\w+\.\w+\s*\)?/ nocase
        $call_index = /&\s*\(?\s*\$\w+\[\s*['"]/ nocase
        $dot_key = /\.\s*\(?\s*\$\w+\.\w+\s*\)?/ nocase

    condition:
        $hashtable and any of ($call_key, $call_index, $dot_key)
}

rule JS_Split_Join_Deobfuscation
{
    meta:
        description = "Detects JavaScript split/join pattern used for character removal deobfuscation"
        severity = "medium"
        category = "obfuscation"
        mitre       = "T1027"
        reference = "JavaScript .split('x').join('') character stripping"
        applies_to  = "js, html, hta, plaintext, decoded-payload"
    strings:
        $split_join_empty = /\.split\s*\(\s*['"][^'"]+['"]\s*\)\s*\.join\s*\(\s*['"]['"]/ nocase
        $split_join_replace = /\.split\s*\(\s*['"][^'"]+['"]\s*\)\s*\.join\s*\(\s*['"][^'"]+['"]/ nocase
        $eval = "eval(" nocase
        $func = "Function(" nocase
        $document_write = "document.write(" nocase
        $innerhtml = "innerHTML" nocase

    condition:
        any of ($split_join_*) and any of ($eval, $func, $document_write, $innerhtml)
}

rule JS_Proxy_Function_Hiding
{
    meta:
        description = "Detects JavaScript Proxy objects used to wrap or hide function calls"
        severity = "medium"
        category = "obfuscation"
        mitre       = "T1027"
        reference = "JavaScript Proxy handler wrapping suspicious invocations"
        applies_to  = "js, html, hta, plaintext, decoded-payload"
    strings:
        $proxy = "new Proxy(" nocase
        $handler_apply = /handler\s*[=:]\s*\{[^}]*apply\s*:/ nocase
        $handler_get = /handler\s*[=:]\s*\{[^}]*get\s*:/ nocase
        $inline_get = /\{\s*get\s*\(\s*\w+\s*,\s*\w+\s*\)\s*\{/ nocase
        $inline_apply = /\{\s*apply\s*\(\s*\w+/ nocase

    condition:
        $proxy and any of ($handler_apply, $handler_get, $inline_get, $inline_apply)
}

rule JS_Bracket_Hex_Property_Execution
{
    meta:
        description = "Detects JavaScript bracket notation with hex/unicode escapes to invoke functions"
        severity = "high"
        category = "obfuscation"
        mitre       = "T1027"
        reference = "window['\\x65\\x76\\x61\\x6c'] style property access"
        applies_to  = "js, html, hta, plaintext, decoded-payload"
    strings:
        $hex_bracket_1 = /\w+\s*\[\s*['"]\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2})+['"]\s*\]/ nocase
        $hex_bracket_2 = /\w+\s*\[\s*['"]\\u[0-9a-fA-F]{4}(\\u[0-9a-fA-F]{4})+['"]\s*\]/ nocase
        $window_hex = /window\s*\[\s*['"]\\[xu]/ nocase
        $document_hex = /document\s*\[\s*['"]\\[xu]/ nocase
        $this_hex = /this\s*\[\s*['"]\\[xu]/ nocase
        $global_hex = /globalThis\s*\[\s*['"]\\[xu]/ nocase

    condition:
        any of them
}

rule Bash_Base64_Execution
{
    meta:
        description = "Detects bash/shell commands that decode and execute base64-encoded payloads"
        severity = "high"
        category = "obfuscation"
        mitre       = "T1059.004"
        reference = "eval $(echo ... | base64 -d) and similar patterns"
        applies_to  = "bash, plaintext, decoded-payload"
    strings:
        $eval_b64_1 = /eval\s+\$\(\s*echo\s+[A-Za-z0-9\+\/=]+\s*\|\s*base64\s+-(d|decode)\s*\)/ nocase
        $eval_b64_2 = /eval\s+['"`]\$\(\s*base64\s+-(d|decode)/ nocase
        $bash_b64_1 = /bash\s+-(c|i)\s+['"]*\$\(\s*echo\s+[^\)]*base64\s+-(d|decode)/ nocase
        $bash_b64_2 = /bash\s+-(c|i)\s+['"]*\$\(\s*base64\s+-(d|decode)/ nocase
        $sh_b64 = /\/bin\/sh\s+-(c|i)\s+['"]*\$\(\s*.*base64\s+-(d|decode)/ nocase
        $pipe_b64_bash = /base64\s+-(d|decode)\s*\|\s*(ba)?sh/ nocase
        $printf_eval = /eval\s+\$\(\s*printf\s+/ nocase

    condition:
        any of them
}

rule Bash_Variable_Obfuscation
{
    meta:
        description = "Detects bash variable expansion and string manipulation obfuscation techniques"
        severity = "medium"
        category = "obfuscation"
        mitre       = "T1027"
        reference = "Bash ${var} abuse, IFS manipulation, and heredoc payloads"
        applies_to  = "bash, plaintext, decoded-payload"
    strings:
        $ifs_manip = /IFS\s*=\s*['"][^'"]*['"]\s*;/ nocase
        $var_concat = /\$\{?\w+\}?\$\{?\w+\}?\$\{?\w+\}?/ nocase
        $eval_var = /eval\s+['"]*\$\{?\w+\}?/ nocase
        $heredoc_exec = /<<\s*['"]*\w+['"]*\s*\n.*\n\s*\w+/
        $rev_pipe = /rev\s*<<<\s*['"]/ nocase
        $xxd_pipe = /xxd\s+-(r|revert)\s*.*\|\s*(ba)?sh/ nocase
        $printf_slash = /\$\(printf\s+['"]\\[0-9x]/ nocase
        $bracket_cmd = /\$\{\w+:[\d]+:[\d]+\}/ nocase

    condition:
        any of ($ifs_manip, $rev_pipe, $xxd_pipe) or ($eval_var and any of ($var_concat, $printf_slash, $bracket_cmd)) or ($heredoc_exec and $eval_var)
}

rule Shell_Curl_Wget_Pipe_Exec
{
    meta:
        description = "Detects shell commands that download and directly execute scripts via pipe"
        severity = "high"
        category = "obfuscation"
        mitre       = "T1059.004"
        reference = "curl/wget piped to bash/sh for remote code execution"
        applies_to  = "bash, plaintext, decoded-payload"
    strings:
        $curl_bash = /curl\s+[^\|]*\|\s*(ba)?sh/ nocase
        $wget_bash = /wget\s+[^\|]*\|\s*(ba)?sh/ nocase
        $curl_eval = /eval\s+\$\(\s*curl\s+/ nocase
        $wget_eval = /eval\s+\$\(\s*wget\s+/ nocase
        $curl_source = /source\s+<\(\s*curl\s+/ nocase
        $wget_source = /source\s+<\(\s*wget\s+/ nocase

    condition:
        any of them
}

rule Python_Reverse_Shell
{
    meta:
        description = "Detects Python reverse shell patterns — socket connect with subprocess/pty"
        severity = "critical"
        category = "execution"
        mitre       = "T1059.006"
        applies_to  = "py, plaintext, decoded-payload"
    strings:
        $socket_import = "import socket" nocase
        $subprocess    = "import subprocess" nocase
        $pty           = "import pty" nocase
        $os_dup2       = "os.dup2(" nocase
        $connect       = ".connect((" nocase
        $popen         = "subprocess.Popen(" nocase
        $call          = "subprocess.call(" nocase
        $pty_spawn     = "pty.spawn(" nocase
        $bin_sh        = "/bin/sh" nocase
        $bin_bash      = "/bin/bash" nocase

    condition:
        $socket_import and $connect and ($subprocess or $pty) and ($os_dup2 or $popen or $call or $pty_spawn or $bin_sh or $bin_bash)
}

rule NodeJS_Child_Process_Execution
{
    meta:
        description = "Detects Node.js child_process module usage for command execution"
        severity = "high"
        category = "execution"
        mitre       = "T1059.007"
        applies_to  = "js, plaintext, decoded-payload"
    strings:
        $require_cp = "require('child_process')" nocase
        $require_cp2 = "require(\"child_process\")" nocase
        $import_cp = "from 'child_process'" nocase
        $import_cp2 = "from \"child_process\"" nocase
        $exec       = ".exec(" nocase
        $execSync   = ".execSync(" nocase
        $spawn      = ".spawn(" nocase
        $spawnSync  = ".spawnSync(" nocase
        $execFile   = ".execFile(" nocase
        $cmd        = "cmd" nocase
        $powershell = "powershell" nocase
        $bash       = "/bin/sh" nocase

    condition:
        any of ($require_cp*,$import_cp*) and any of ($exec,$execSync,$spawn,$spawnSync,$execFile) and any of ($cmd,$powershell,$bash)
}
