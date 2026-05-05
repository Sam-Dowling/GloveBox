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
        $comment_dot     = /\b[A-Za-z_$][\w$]{0,63}\s{0,8}\/\*[^*]{0,512}\*\/\s{0,8}\.\s{0,8}\/\*[^*]{0,512}\*\/\s{0,8}[A-Za-z_$][\w$]{0,63}/ nocase
        $comment_bracket = /\b[A-Za-z_$][\w$]{0,63}\s{0,8}\/\*[^*]{0,512}\*\/\s{0,8}\[\s{0,8}\/\*[^*]{0,512}\*\/\s{0,8}['"]/ nocase
        $comment_call    = /\b[A-Za-z_$][\w$]{0,63}\s{0,8}\/\*[^*]{0,512}\*\/\s{0,8}\(\s{0,8}\/\*[^*]{0,512}\*\/\s{0,8}['"]/ nocase
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
        applies_to  = "js, html, hta, plaintext, decoded-payload"
    strings:
        $hex_bracket_1 = /\b[A-Za-z_$][\w$]{0,63}\[\s{0,8}['"](?:\\x[0-9a-fA-F]{2}){2,}['"]\s{0,8}\]/ nocase
        $hex_bracket_2 = /\b[A-Za-z_$][\w$]{0,63}\[\s{0,8}['"](?:\\u[0-9a-fA-F]{4}){2,}['"]\s{0,8}\]/ nocase
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

rule ReverseShell_Perl_OneLiner
{
    meta:
        description = "Perl reverse-shell one-liner — Socket + getprotobyname + inet_aton + sockaddr_in (3+ of 4 canonical tokens)"
        severity    = "critical"
        category    = "execution"
        mitre       = "T1059.006"
        applies_to  = "text_like, decoded-payload"

    strings:
        $a = "use Socket" nocase
        $b = "getprotobyname(\"tcp\")" nocase
        $c = "inet_aton" nocase
        $d = "sockaddr_in" nocase
        $e = "socket(S,PF_INET" nocase
        $f = "exec \"/bin/sh -i\"" nocase
        $g = "exec \"/bin/bash -i\"" nocase
        $perl_e = /\bperl\s+-e\s+["']/ nocase

    condition:
        3 of ($a, $b, $c, $d, $e) or ($perl_e and 1 of ($a, $b, $c, $d, $f, $g))
}

rule ReverseShell_Ruby_OneLiner
{
    meta:
        description = "Ruby reverse-shell one-liner — require 'socket' + TCPSocket.new + exec/IO.popen/%x{}"
        severity    = "critical"
        category    = "execution"
        mitre       = "T1059.006"
        applies_to  = "text_like, decoded-payload"

    strings:
        $req   = "require 'socket'" nocase
        $req2  = "require \"socket\"" nocase
        $tcps  = "TCPSocket.new" nocase
        $exec  = /exec\s*\(?\s*['"]\/bin\/(ba)?sh/ nocase
        $popen = "IO.popen" nocase
        $pct_x = /%x\s*\{[^}]{0,80}\/bin\/(ba)?sh/ nocase
        $ruby_e = /\bruby\s+-rsocket\b/ nocase

    condition:
        ($req or $req2 or $ruby_e) and $tcps and ($exec or $popen or $pct_x)
}

rule ReverseShell_PHP_OneLiner
{
    meta:
        description = "PHP reverse-shell primitives — fsockopen/stream_socket_client + exec/passthru/proc_open/shell_exec, often via `php -r`"
        severity    = "critical"
        category    = "execution"
        mitre       = "T1059"
        applies_to  = "text_like, decoded-payload"

    strings:
        $fsock = "fsockopen(" nocase
        $ssock = "stream_socket_client(" nocase
        $proc  = "proc_open(" nocase
        $exec  = /\bexec\s*\(\s*["']\/bin\/(ba)?sh/ nocase
        $pass  = "passthru(" nocase
        $shex  = "shell_exec(" nocase
        $sys   = /\bsystem\s*\(\s*["'][^"']{0,80}\/bin\/(ba)?sh/ nocase
        $php_r = /\bphp\s+-r\s+["']/ nocase
        $bash_path = "/bin/sh -i" nocase

    condition:
        ($fsock or $ssock) and ($proc or $exec or $pass or $shex or $sys or $bash_path) and ($php_r or $fsock or $ssock)
}

rule ReverseShell_Lua_Tcl_AWK
{
    meta:
        description = "Lua / Tcl / awk reverse-shell one-liners — luasocket TCP shell, expect spawn sh, awk BEGIN{system()} with /inet/tcp/"
        severity    = "high"
        category    = "execution"
        mitre       = "T1059"
        applies_to  = "text_like, decoded-payload"

    strings:
        $lua_sock = "require(\"socket\")" nocase
        $lua_sock2 = "require('socket')" nocase
        $lua_exec = /os\.execute\s*\(\s*["']\/bin\/(ba)?sh/ nocase
        $tcl_spawn = "spawn sh" nocase
        $tcl_exp   = "package require Tcl" nocase
        $awk_inet  = /awk\s+['"]BEGIN\s*\{[^}]{0,200}\/inet\/tcp\// nocase
        $awk_sys   = /awk\s+['"]BEGIN\s*\{[^}]{0,200}system\s*\(/ nocase
        $expect_spawn = /expect[^\r\n]{0,80}spawn\s+sh/ nocase

    condition:
        ($lua_sock or $lua_sock2) and $lua_exec or
        ($tcl_exp and $tcl_spawn) or
        $awk_inet or $awk_sys or
        $expect_spawn
}

rule ReverseShell_NamedPipe
{
    meta:
        description = "Named-pipe reverse shell — `mkfifo` co-located with nc/ncat/netcat/telnet and a shell pathname"
        severity    = "critical"
        category    = "execution"
        mitre       = "T1059.004"
        applies_to  = "text_like, decoded-payload"

    strings:
        $mkfifo = /\bmkfifo\s+\/(tmp|var|dev)\/[\w\.]+/ nocase
        $mknod  = /\bmknod\s+\/(tmp|var|dev)\/[\w\.]+\s+p\b/ nocase
        $nc     = /\b(n(et)?c(at)?)\s+[a-z0-9\.\-]{1,80}\s+\d+/ nocase
        $tel    = /\btelnet\s+[a-z0-9\.\-]{1,80}\s+\d+/ nocase
        $sh     = "/bin/sh" nocase
        $bash   = "/bin/bash" nocase

    condition:
        ($mkfifo or $mknod) and ($nc or $tel) and ($sh or $bash)
}

rule ReverseShell_Socat
{
    meta:
        description = "Socat reverse / bind shell — tcp-listen|tcp-connect|openssl-listen with exec:bash|sh"
        severity    = "critical"
        category    = "execution"
        mitre       = "T1059.004"
        applies_to  = "text_like, decoded-payload"

    strings:
        $a = /\bsocat\s+(tcp|tcp4|tcp6|openssl)-listen:\d+[^\r\n]{0,120}exec:\s*["']?\/?(bin\/)?(ba)?sh/ nocase
        $b = /\bsocat\s+(tcp|tcp4|tcp6|openssl)-connect:[a-z0-9\.\-]+:\d+[^\r\n]{0,120}exec:/ nocase
        $c = /\bsocat\s+exec:[\"']?\/?(bin\/)?(ba)?sh[^\r\n]{0,120}(tcp|openssl)/ nocase

    condition:
        any of them
}

rule PowerShell_TCPClient_RevShell
{
    meta:
        description = "PowerShell TCPClient reverse-shell pattern (Nishang-style Invoke-PowerShellTcp) — System.Net.Sockets.TCPClient + GetStream + IEX/Invoke-Expression + StreamReader/Writer"
        severity    = "critical"
        category    = "execution"
        mitre       = "T1059.001"
        applies_to  = "text_like, decoded-payload"

    strings:
        $tcp     = "System.Net.Sockets.TCPClient" nocase
        $getstream = "GetStream()" nocase
        $iex     = "Invoke-Expression" nocase
        $iex2    = /\biex\b/ nocase
        $sw      = "StreamWriter" nocase
        $sr      = "StreamReader" nocase
        $bw      = "BinaryWriter" nocase

    condition:
        $tcp and $getstream and ($iex or $iex2) and ($sw or $sr or $bw)
}

rule GTFOBin_Exec_Primitive
{
    meta:
        description = "GTFOBin-style command-execution primitive — find -exec, vim/less/tar/awk/gawk/gdb/git/xargs/env/script/flock used as arbitrary-shell launcher"
        severity    = "high"
        category    = "execution"
        mitre       = "T1059.004"
        applies_to  = "text_like, decoded-payload"

    strings:
        $find_exec   = /\bfind\s+[^\r\n]{0,120}-exec\s+\/?(bin\/)?(ba)?sh\b/ nocase
        $find_exec2  = /\bfind\s+[^\r\n]{0,120}-exec\s+[^\s]+\s+-i\b/ nocase
        $vim_cmd     = /\bvim?\s+-c\s+['":]?\!\/?(bin\/)?(ba)?sh/ nocase
        $vim_py      = /\bvim?\s+-c\s+['":]?py(thon)?\s+import\s+os/ nocase
        $less_bang   = /\bless\s+[^\r\n]{0,80}!\/?(bin\/)?(ba)?sh/ nocase
        $tar_cp      = /tar\s+[^\r\n]{0,120}--checkpoint=\d+\s+--checkpoint-action=exec/ nocase
        $awk_system  = /(g?awk|mawk)\s+['"]BEGIN\s*\{\s*system\s*\(/ nocase
        $gdb_python  = /\bgdb\s+-batch\s+-ex\s+['"]python\s+/ nocase
        $git_ssh     = /git\s+-c\s+core\.sshCommand=/ nocase
        $git_pager   = /git\s+-c\s+core\.pager=/ nocase
        $xargs_sh    = /\bxargs\s+-I\s*\S+\s+\/?(bin\/)?(ba)?sh\s+-c/ nocase
        $env_isolate = /\benv\s+-i\s+\/?(bin\/)?(ba)?sh\b/ nocase
        $script_term = /\bscript\s+(-q\s+)?-c\s+['"]\/?(bin\/)?(ba)?sh/ nocase
        $script_dev  = /\bscript\s+[^\r\n]{0,40}\/dev\/null/ nocase
        $flock_cmd   = /\bflock\s+(-u\s+)?[\/-]\s+-c\s+['"]/ nocase
        $ed_bang     = /\bed\s*\n[^\r\n]*\n!\/?(bin\/)?(ba)?sh/ nocase
        $rsync_e     = /\brsync\s+-e\s+['"]?\/?(bin\/)?(ba)?sh/ nocase
        $man_bang    = /\bman\s+[^\r\n]{0,40}!\/?(bin\/)?(ba)?sh/ nocase
        $sed_e       = /\bsed\s+-e\s+['"]\d*e\b/ nocase
        $nice_sh     = /\bnice\s+\/?(bin\/)?(ba)?sh\b/ nocase
        $stdbuf_sh   = /\bstdbuf\s+-[ioe]\s*0?\s+\/?(bin\/)?(ba)?sh/ nocase
        $timeout_sh  = /\btimeout\s+--preserve-status\s+\d+\s+\/?(bin\/)?(ba)?sh/ nocase

    condition:
        any of them
}

rule Linux_SUID_Discovery
{
    meta:
        description = "SUID / file-capability discovery primitive — `find / -perm -u=s|-4000`, `getcap -r`, `getfacl -R` — privilege-escalation reconnaissance"
        severity    = "low"
        category    = "discovery"
        mitre       = "T1083"
        applies_to  = "text_like, decoded-payload"

    strings:
        $a = /find\s+\/[^\r\n]{0,120}-perm\s+-?u=s/ nocase
        $b = /find\s+\/[^\r\n]{0,120}-perm\s+-?4000/ nocase
        $c = /find\s+\/[^\r\n]{0,120}-perm\s+-?2000/ nocase
        $d = /find\s+\/[^\r\n]{0,120}-perm\s+-?6000/ nocase
        $e = "getcap -r /" nocase
        $f = /\bgetcap\s+-r\b/ nocase
        $g = /\bgetfacl\s+-R\b/ nocase

    condition:
        any of them
}

rule Linux_Persist_Add_User
{
    meta:
        description = "Add backdoor account / privileged-group escalation — usermod/useradd/gpasswd into sudo|wheel|admin, or direct /etc/passwd append with UID 0"
        severity    = "high"
        category    = "persistence"
        mitre       = "T1136.001"
        applies_to  = "text_like, decoded-payload"

    strings:
        $a = /\busermod\s+-aG\s+(sudo|wheel|admin|root)\b/ nocase
        $b = /\buseradd\s+[^\r\n]{0,80}-G\s+(sudo|wheel|admin|root)\b/ nocase
        $c = /\buseradd\s+[^\r\n]{0,80}-u\s*0\b/ nocase
        $d = /\bgpasswd\s+-a\s+\w+\s+(sudo|wheel|admin|root)\b/ nocase
        $e = /\badduser\s+\w+\s+(sudo|wheel|admin|root)\b/ nocase
        $f = /echo\s+["']?[^\r\n]{0,80}:::?0:0/ nocase
        $g = />>\s*\/etc\/passwd/ nocase
        $h = />>\s*\/etc\/sudoers/ nocase
        $i = "NOPASSWD:ALL" nocase

    condition:
        any of them
}

rule PasswordManager_DB_Reference
{
    meta:
        description = "Reference to a password-manager / secret-vault database file by name (Bitwarden data.json, 1Password .opvault, KeePass .kdbx, LastPass lp.sqlite, Enpass vault.json, NordPass, Dashlane, RoboForm, pass / password-store)"
        severity    = "high"
        category    = "credential-access"
        mitre       = "T1555.005"
        applies_to  = "any, decoded-payload"

    strings:
        $bw_data    = "Bitwarden\\data.json" nocase
        $bw_data2   = "/Bitwarden/data.json" nocase
        $op_vault   = ".opvault" nocase
        $op_sqlite  = "1Password.sqlite" nocase
        $op_4       = "OnePassword4.sqlite" nocase
        $kp_kdbx    = ".kdbx" nocase
        $kp_kdb     = ".kdb" nocase
        $lp_sqlite  = "lp.sqlite" nocase
        $enpass     = "vault.enpassdb" nocase
        $enpass2    = "Enpass\\vault.json" nocase
        $nordpass   = "NordPass" ascii wide nocase
        $dashlane   = "Dashlane" ascii wide nocase
        $roboform   = "RoboForm" ascii wide nocase
        $stickyp    = "StickyPassword" ascii wide nocase
        $passstore  = "/.password-store/" nocase
        $keepassxc  = "KeePassXC" ascii wide nocase
        $keeper     = /\bkeeper(security)?\b/ nocase

    condition:
        any of them
}

rule Browser_NSS_Cred_Reference
{
    meta:
        description = "Reference to Mozilla NSS / Firefox credential-store internals — key3.db / key4.db / logins.json with profile context, nss3.dll, pk11sdr_decrypt"
        severity    = "high"
        category    = "credential-access"
        mitre       = "T1555.003"
        applies_to  = "any, decoded-payload"

    strings:
        $k3 = "key3.db" nocase
        $k4 = "key4.db" nocase
        $logins = "logins.json" nocase
        $signons = "signons.sqlite" nocase
        $nss = "nss3.dll" nocase
        $pk11 = "PK11SDR_Decrypt" nocase
        $pk11b = "pk11sdr_decrypt" nocase
        $profile = /Mozilla[\\\/]Firefox[\\\/]Profiles[\\\/]/ nocase
        $profile2 = /\.mozilla[\\\/]firefox[\\\/]/ nocase
        $thunder = /Thunderbird[\\\/]Profiles/ nocase

    condition:
        ($nss or $pk11 or $pk11b) or
        (($k3 or $k4 or $logins or $signons) and ($profile or $profile2 or $thunder or $nss))
}

rule CredFile_Walk_CrossOS
{
    meta:
        description = "Walk of cross-OS credential / config files — .git-credentials, .netrc, .pypirc, kubeconfig, gh hosts.yml, .azure, gcloud, service-account JSON, GNOME keyring, KWallet, SSH agent socket"
        severity    = "high"
        category    = "credential-access"
        mitre       = "T1552.001"
        applies_to  = "text_like, decoded-payload"

    strings:
        $git_creds  = ".git-credentials" nocase
        $netrc      = /\b\.netrc\b/ nocase
        $netrc2     = /[\\\/]_netrc\b/ nocase
        $pypirc     = ".pypirc" nocase
        $kubeconfig = /\.kube[\\\/]config\b/ nocase
        $gh_hosts   = /gh[\\\/]hosts\.yml\b/ nocase
        $azure_cfg  = /[\\\/]\.azure[\\\/]/ nocase
        $gcloud_cfg = /\.config[\\\/]gcloud[\\\/]/ nocase
        $svc_acct   = "service-account.json" nocase
        $gae_creds  = "GOOGLE_APPLICATION_CREDENTIALS" nocase
        $aws_creds  = /\.aws[\\\/]credentials\b/ nocase
        $aws_cfg    = /\.aws[\\\/]config\b/ nocase
        $docker_cfg = /\.docker[\\\/]config\.json\b/ nocase
        $gnome_kr   = "login.keyring" nocase
        $kwallet    = "kdewallet.kwl" nocase
        $secret_tool = /\bsecret-tool\s+lookup\b/ nocase
        $ssh_sock   = "SSH_AUTH_SOCK" nocase
        $ssh_id_rsa = /\.ssh[\\\/]id_(rsa|ed25519|ecdsa|dsa)\b/ nocase
        $ssh_authk  = /\.ssh[\\\/]authorized_keys\b/ nocase
        $vault_token = /\.vault-token\b/ nocase
        $npm_rc     = /\b\.npmrc\b/ nocase

    condition:
        3 of them
}

rule Bash_DevTcp_Reverse_Shell
{
    meta:
        description = "Detects bash /dev/tcp reverse-shell — bash -i with stdio redirected to attacker via /dev/tcp/<host>/<port>"
        severity = "critical"
        category = "execution"
        mitre = "T1059.004"
        applies_to = "bash, plaintext, decoded-payload"
    strings:
        $devtcp_redirect_1 = /bash\s+-i\b[^\r\n]{0,200}>\s*&?\s*\/dev\/tcp\// nocase
        $devtcp_redirect_2 = /sh\s+-i\b[^\r\n]{0,200}>\s*&?\s*\/dev\/tcp\// nocase
        $devtcp_dup_1 = /\/dev\/tcp\/[\w.\-]+\/\d{1,5}\b[^\r\n]{0,200}\b0<&\d/ nocase
        $devtcp_dup_2 = /\/dev\/tcp\/[\w.\-]+\/\d{1,5}\b[^\r\n]{0,200}\b>&\d/ nocase
        $exec_devtcp = /exec\s+\d+<>\s*\/dev\/tcp\// nocase
    condition:
        any of them
}

rule Bash_Bashrc_Persistence
{
    meta:
        description = "Detects bash persistence via ~/.bashrc / ~/.bash_profile / /etc/profile.d injection — write-and-redirect into a shell-startup file"
        severity = "high"
        category = "persistence"
        mitre = "T1546.004"
        applies_to = "bash, plaintext, decoded-payload"
    strings:
        $bashrc_append_1 = /(?:echo|printf|cat\s+>>?)[^\r\n]{0,200}>>?\s*['"]?\$?HOME?[\\\/]\.bashrc\b/ nocase
        $bashrc_append_2 = /(?:echo|printf|cat\s+>>?)[^\r\n]{0,200}>>?\s*['"]?[\\\/]?\.bash_profile\b/ nocase
        $bashrc_append_3 = /(?:echo|printf|cat\s+>>?)[^\r\n]{0,200}>>?\s*['"]?[\\\/]?\.profile\b/ nocase
        $profiled = /\/etc\/profile\.d\/[^\r\n]{1,80}\.sh\b/ nocase
        $bashrc_tee = /tee\s+-a\s+[^\r\n]{0,80}\.(?:bashrc|bash_profile|profile|zshrc)\b/ nocase
    condition:
        any of them
}

rule Bash_Sudoers_Tampering
{
    meta:
        description = "Detects /etc/sudoers tampering — appending NOPASSWD or ALL=(ALL) entries to grant unattended root"
        severity = "critical"
        category = "privilege-escalation"
        mitre = "T1548.003"
        applies_to = "bash, plaintext, decoded-payload"
    strings:
        $nopasswd_append_1 = /(?:echo|printf|cat\s+>>?)[^\r\n]{0,200}NOPASSWD[^\r\n]{0,80}>>?\s*\/etc\/sudoers\b/ nocase
        $nopasswd_append_2 = /(?:echo|printf)[^\r\n]{0,200}>>?\s*\/etc\/sudoers\.d\// nocase
        $visudo_pipe = /\bvisudo\b[^\r\n]{0,80}\bNOPASSWD\b/ nocase
        $sudoers_tee = /tee\s+-a\s+\/etc\/sudoers/ nocase
        $passwd_root = /(?:echo|printf)[^\r\n]{0,200}>>?\s*\/etc\/passwd\b/ nocase
    condition:
        any of them
}

rule Bash_Cron_Persistence
{
    meta:
        description = "Detects cron-job persistence — installing entries via crontab(1) -, /etc/cron.* drop, or systemd timer drop"
        severity = "high"
        category = "persistence"
        mitre = "T1053.003"
        applies_to = "bash, plaintext, decoded-payload"
    strings:
        $crontab_pipe_1 = /\(crontab\s+-l[^\r\n]{0,40}\|[^\r\n]{0,200}\)\s*\|\s*crontab\s+-/ nocase
        $crontab_pipe_2 = /(?:echo|printf)[^\r\n]{0,200}\|\s*crontab\s+-/ nocase
        $cron_dir_1 = /(?:cp|mv|tee|>>?)[^\r\n]{0,200}\/etc\/cron\.(?:d|hourly|daily|weekly|monthly)\// nocase
        $cron_at = /\bat\s+(?:now|\+\d+\s*(?:min|hour|day))[^\r\n]{0,200}<<</ nocase
        $systemd_timer = /\.timer\b[\s\S]{0,500}OnBootSec\s*=/ nocase
    condition:
        any of them
}

rule Bash_SSH_Key_Injection
{
    meta:
        description = "Detects SSH authorized_keys injection — appending an attacker pubkey to grant persistent passwordless login"
        severity = "critical"
        category = "persistence"
        mitre = "T1098.004"
        applies_to = "bash, plaintext, decoded-payload"
    strings:
        $authkeys_append_1 = /(?:echo|printf|cat\s+>>?)[^\r\n]{0,400}>>?\s*[^\r\n]{0,80}\.ssh\/authorized_keys\b/ nocase
        $authkeys_append_2 = /tee\s+-a\s+[^\r\n]{0,80}\.ssh\/authorized_keys\b/ nocase
        $mkdir_ssh = /mkdir\s+-p\s+[^\r\n]{0,80}\.ssh[^\r\n]{0,200}chmod\s+(?:700|600)/ nocase
        $ssh_keygen = /ssh-keygen\s+-(?:t|f)\s+\w+[^\r\n]{0,200}-N\s+['"]['"]?/ nocase
        $rsa_pubkey = /ssh-(?:rsa|ed25519|ecdsa-sha2-nistp\d+)\s+[A-Za-z0-9+\/=]{200,}/
    condition:
        ($authkeys_append_1 or $authkeys_append_2 or $mkdir_ssh) and ($rsa_pubkey or $authkeys_append_1)
}

rule Bash_IFS_Reassembly
{
    meta:
        description = "Detects IFS-reassembly obfuscation — IFS reassigned to a separator char, command split into tokens reassembled at exec time via eval/exec/$cmd"
        severity = "high"
        category = "obfuscation"
        mitre = "T1027"
        applies_to = "bash, plaintext, decoded-payload"
    strings:
        $ifs_ansi_eval = /\bIFS\s*=\s*\$'(?:[^'\\]|\\.){1,40}'[\s\S]{0,400}?\b(?:eval|exec)\s+\$\{?\w+\}?/ nocase
        $ifs_quoted_eval = /\bIFS\s*=\s*['"][^'"\r\n]{1,40}['"][\s\S]{0,400}?\b(?:eval|exec)\s+\$\{?\w+\}?/ nocase
        $ifs_brace_concat = /\bIFS\s*=[\s\S]{0,400}?\$\{?\w+\}?\$\{?\w+\}?\$\{?\w+\}?/ nocase
    condition:
        any of them
}

rule Bash_Heredoc_Exec
{
    meta:
        description = "Detects bash here-document execution — script body delivered inline via <<EOF then piped to sh / bash / interpreter"
        severity = "medium"
        category = "execution"
        mitre = "T1059.004"
        applies_to = "bash, plaintext, decoded-payload"
    strings:
        $heredoc_sh = /<<-?\s*['"]?\w+['"]?[\s\S]{20,4096}?\b\w+\s*\|\s*(?:ba)?sh\b/ nocase
        $heredoc_python = /<<-?\s*['"]?\w+['"]?[\s\S]{20,4096}?\bpython\d?\s+-/ nocase
        $heredoc_perl = /<<-?\s*['"]?\w+['"]?[\s\S]{20,4096}?\bperl\s+-e\s+/ nocase
        $heredoc_curl = /<<-?\s*['"]?\w+['"]?[\s\S]{20,4096}?\bcurl\s+-d\s+@-/ nocase
    condition:
        any of them
}

rule Bash_DD_Pipe_Shell
{
    meta:
        description = "Detects dd pipe-to-shell — dd extracts an embedded payload from a host file (offset/skip) and pipes it to a shell"
        severity = "high"
        category = "execution"
        mitre = "T1059.004"
        applies_to = "bash, plaintext, decoded-payload"
    strings:
        $dd_skip_pipe = /\bdd\s+if=[^\r\n]{1,200}skip=\d+[^\r\n]{0,200}\|\s*(?:ba)?sh\b/ nocase
        $dd_bs_pipe = /\bdd\s+if=[^\r\n]{1,200}\bbs=\d+[^\r\n]{0,200}\|\s*(?:ba)?sh\b/ nocase
        $tail_byte_pipe = /\btail\s+-c\s+[+\-]?\d+[^\r\n]{0,200}\|\s*(?:ba)?sh\b/ nocase
        $head_byte_pipe = /\bhead\s+-c\s+\d+[^\r\n]{0,200}\|\s*(?:ba)?sh\b/ nocase
    condition:
        any of them
}

rule Bash_Command_Not_Found_Hijack
{
    meta:
        description = "Detects command_not_found_handle hijack — overriding the handler to silently exec arbitrary commands when an unknown name is typed"
        severity = "high"
        category = "persistence"
        mitre = "T1546"
        applies_to = "bash, plaintext, decoded-payload"
    strings:
        $cnf_handle_def = /\bcommand_not_found_handle\s*\(\s*\)\s*\{/ nocase
        $cnf_handler_def = /\bcommand_not_found_handler\s*\(\s*\)\s*\{/ nocase
        $cnf_export = /\bexport\s+-f\s+command_not_found_handle/ nocase
    condition:
        any of them
}

rule Bash_Env_I_Masking
{
    meta:
        description = "Detects env -i masking — wiping the environment before launching a shell to bypass auditd/HISTFILE/PROMPT_COMMAND telemetry"
        severity = "medium"
        category = "defense-evasion"
        mitre = "T1562.003"
        applies_to = "bash, plaintext, decoded-payload"
    strings:
        $env_i_bash = /\benv\s+-i\b[^\r\n]{0,200}\b(?:ba)?sh\b/ nocase
        $unset_history = /\bunset\s+(?:HISTFILE|HISTSIZE|HISTFILESIZE|PROMPT_COMMAND)\b/ nocase
        $histfile_devnull = /\bHISTFILE\s*=\s*\/dev\/null\b/ nocase
        $set_no_history = /\bset\s+\+o\s+history\b/ nocase
    condition:
        any of them
}

rule PHP_Webshell_Decoder_Onion
{
    meta:
        description = "Detects PHP webshell decoder onion — eval/assert wrapping nested base64_decode/gzinflate/gzuncompress/str_rot13 chains (b374k / WSO / r57 family)"
        severity = "critical"
        category = "execution"
        mitre = "T1059"
        applies_to = "php, plaintext, decoded-payload"
    strings:
        $eval_b64 = /(?:eval|assert)\s*\(\s*base64_decode\s*\(\s*['"][A-Za-z0-9+\/=]{16,}['"]\s*\)\s*\)/ nocase
        $eval_gz_b64 = /(?:eval|assert)\s*\(\s*gzinflate\s*\(\s*base64_decode\s*\(/ nocase
        $eval_rot_gz = /(?:eval|assert)\s*\(\s*str_rot13\s*\(\s*gzinflate\s*\(\s*base64_decode\s*\(/ nocase
        $eval_gzuncompress = /(?:eval|assert)\s*\(\s*gzuncompress\s*\(\s*base64_decode\s*\(/ nocase
        $eval_gzdecode = /(?:eval|assert)\s*\(\s*gzdecode\s*\(\s*base64_decode\s*\(/ nocase
        $create_function_b64 = /create_function\s*\(\s*['"]['"]?\s*,\s*base64_decode\s*\(/ nocase
    condition:
        any of them
}

rule PHP_Eval_Superglobal
{
    meta:
        description = "Detects PHP one-line shell — eval/system/shell_exec called with $_GET / $_POST / $_REQUEST / $_COOKIE / $_SERVER / $_FILES user-controlled data, with up to 3 levels of sanitiser/decoder wrappers (escapeshellarg, urldecode, base64_decode, ...)"
        severity = "critical"
        category = "execution"
        mitre = "T1059"
        applies_to = "php, plaintext, decoded-payload"
    strings:
        $eval_get = /\beval\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\s*\[/ nocase
        $assert_get = /\bassert\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\s*\[/ nocase
        $system_get = /\b(?:system|shell_exec|passthru|exec|popen|proc_open)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\s*\[/ nocase
        $system_wrapped_sg = /\b(?:eval|assert|system|shell_exec|passthru|exec|popen|proc_open)\s*\(\s*(?:[A-Za-z_][A-Za-z_0-9]{2,30}\s*\(\s*){1,3}\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\s*\[/ nocase
        $superglobal_call = /\$_(?:GET|POST|REQUEST|COOKIE)\s*\[\s*['"]?[^\]'"\r\n]{1,40}['"]?\s*\]\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/ nocase
        $callback_filter = /\b(?:array_filter|array_map|usort|preg_replace_callback)\s*\([^)]{0,200}\$_(?:GET|POST|REQUEST|COOKIE)/ nocase
    condition:
        any of them
}

rule PHP_Webshell_Escapeshell_Taint
{
    meta:
        description = "Detects PHP webshell anti-pattern where a sink function (shell_exec / system / passthru / exec / popen / proc_open) is called with escapeshellarg() or escapeshellcmd() wrapping a superglobal — these escapers protect shell-argument tokenisation but still permit option-injection attacks (CVE-2024-4577 / ssh -oProxyCommand class), so the developer's mitigation is ineffective"
        severity = "critical"
        category = "execution"
        mitre = "T1059"
        applies_to = "php, plaintext, decoded-payload"
    strings:
        $esc_arg = /\b(?:system|shell_exec|passthru|exec|popen|proc_open)\s*\(\s*escapeshellarg\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\s*\[/ nocase
        $esc_cmd = /\b(?:system|shell_exec|passthru|exec|popen|proc_open)\s*\(\s*escapeshellcmd\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\s*\[/ nocase
    condition:
        any of them
}

rule PHP_Preg_Replace_E_Modifier
{
    meta:
        description = "Detects deprecated preg_replace /e modifier — the replacement string is evaluated as PHP code (RCE primitive on PHP < 7.0; legacy webshell shape)"
        severity = "high"
        category = "execution"
        mitre = "T1059"
        applies_to = "php, plaintext, decoded-payload"
    strings:
        $preg_e_1 = /preg_replace(?:_callback)?\s*\(\s*['"]\/[^'"\r\n]{1,200}\/[a-zA-Z]{0,12}e[a-zA-Z]{0,12}['"]/ nocase
        $preg_e_2 = /preg_replace(?:_callback)?\s*\(\s*['"]#[^'"\r\n]{1,200}#[a-zA-Z]{0,12}e[a-zA-Z]{0,12}['"]/ nocase
        $preg_e_3 = /preg_replace(?:_callback)?\s*\(\s*['"]~[^'"\r\n]{1,200}~[a-zA-Z]{0,12}e[a-zA-Z]{0,12}['"]/ nocase
    condition:
        any of them
}

rule PHP_Variable_Variable_Obfuscation
{
    meta:
        description = "Detects PHP variable-variables obfuscation — $$x or ${'a'.'b'.'c'}() calling a string-concat-resolved function name (system / eval / shell_exec)"
        severity = "high"
        category = "obfuscation"
        mitre = "T1027"
        applies_to = "php, plaintext, decoded-payload"
    strings:
        $double_dollar_call = /\$\$\w+\s*\(/ nocase
        $brace_concat_call = /\$\{\s*['"][^'"\r\n]{1,40}['"](?:\s*\.\s*['"][^'"\r\n]{1,40}['"]){1,12}\s*\}\s*\(/ nocase
        $assign_concat = /\$\w+\s*=\s*['"][a-z]{2,8}['"](?:\s*\.\s*['"][a-z]{1,8}['"]){1,8}\s*;/ nocase
        $chr_concat_dangerous = /chr\s*\(\s*\d{1,3}\s*\)(?:\s*\.\s*chr\s*\(\s*\d{1,3}\s*\)){2,32}/ nocase
        $pack_h_dangerous = /pack\s*\(\s*['"]H\*['"]\s*,\s*['"][0-9a-fA-F]{6,200}['"]\s*\)/ nocase
    condition:
        ($double_dollar_call or $brace_concat_call) and ($assign_concat or $chr_concat_dangerous or $pack_h_dangerous)
        or 2 of ($chr_concat_dangerous, $pack_h_dangerous, $double_dollar_call, $brace_concat_call)
}

rule PHP_Superglobal_Taint_LocalVar
{
    meta:
        description = "Detects PHP second-order taint where a local variable is assigned from a superglobal ($_GET / $_POST / $_REQUEST / $_COOKIE / $_SERVER / $_FILES) and subsequently passed to a sink function (eval / system / shell_exec / passthru / exec / popen / proc_open) — regex-over-single-line scanners miss this assignment-then-sink shape"
        severity = "high"
        category = "execution"
        mitre = "T1059"
        applies_to = "php, plaintext, decoded-payload"
    strings:
        $assign_sg = /\$[A-Za-z_]\w{0,63}\s*=\s*[^;\r\n]{0,200}\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\s*\[[^\]\r\n]{0,80}\]/ nocase
        $sink_var_1 = /\b(?:eval|assert|system|shell_exec|passthru|exec|popen|proc_open)\s*\(\s*\$[A-Za-z_]\w{0,63}\s*\)/ nocase
        $sink_var_2 = /\b(?:eval|assert|system|shell_exec|passthru|exec|popen|proc_open)\s*\(\s*(?:escapeshellarg|escapeshellcmd|trim|urldecode|stripslashes|strtolower)\s*\(\s*\$[A-Za-z_]\w{0,63}\s*\)/ nocase
    condition:
        $assign_sg and ($sink_var_1 or $sink_var_2)
}

rule Bash_Live_Fetch_Pipe_Shell
{
    meta:
        description = "Detects bash live-fetch pipe-to-shell — curl / wget / fetch output piped directly (or via base64 / xxd / rev) into sh / bash. Canonical T1105 payload-delivery primitive; the upstream URL is the actionable artefact"
        severity = "critical"
        category = "execution"
        mitre = "T1105"
        applies_to = "bash, plaintext, decoded-payload"
    strings:
        $curl_pipe_sh = /\bcurl\b[^\r\n|]{0,400}\|\s*(?:ba)?sh\b/ nocase
        $wget_pipe_sh = /\bwget\b[^\r\n|]{0,400}\|\s*(?:ba)?sh\b/ nocase
        $curl_b64_sh = /\bcurl\b[^\r\n|]{0,400}\|\s*base64\s+-(?:d|decode)\s*\|\s*(?:ba)?sh\b/ nocase
        $wget_b64_sh = /\bwget\b[^\r\n|]{0,400}\|\s*base64\s+-(?:d|decode)\s*\|\s*(?:ba)?sh\b/ nocase
        $curl_xxd_sh = /\bcurl\b[^\r\n|]{0,400}\|\s*xxd\s+-r(?:\s+-p)?\s*\|\s*(?:ba)?sh\b/ nocase
        $eval_subshell_curl = /\beval\s*\$\(\s*(?:curl|wget)\b/ nocase
        $bash_subshell_curl = /\bbash\s+<\(\s*(?:curl|wget)\b/ nocase
        $source_subshell_curl = /\bsource\s+<\(\s*(?:curl|wget)\b/ nocase
    condition:
        any of them
}

rule JS_Aaencode_Kaomoji_Carrier
{
    meta:
        description = "Detects Yosuke Hasegawa's aaencode JS obfuscator — encodes arbitrary JavaScript into a dense burst of kaomoji-style symbols from the Katakana / Halfwidth / Greek / Cyrillic ranges followed by signature (ﾟДﾟ) token calls. Statically opaque; recovery requires JS-engine execution in a sandbox"
        severity = "high"
        category = "obfuscation"
        mitre = "T1027.010"
        applies_to = "javascript, html, plaintext, decoded-payload"
    strings:
        $aa_opener_1 = "ﾟωﾟﾉ" ascii
        $aa_opener_2 = "(ﾟДﾟ)" ascii
        $aa_opener_3 = "ﾟΘﾟ" ascii
        $aa_opener_4 = "ﾟｰﾟ" ascii
        $aa_sig = /\(\s*[\x{30A0}-\x{30FF}\x{FF00}-\x{FFEF}\x{0370}-\x{03FF}\x{0400}-\x{04FF}]{2,}\s*\)/
    condition:
        (2 of ($aa_opener_*)) or ($aa_sig and #aa_sig > 5)
}

rule JS_Jjencode_Symbol_Carrier
{
    meta:
        description = "Detects Yosuke Hasegawa's jjencode JS obfuscator — encodes arbitrary JavaScript into ASCII-only symbol soup using the alphabet [ ] { } ( ) + ! _ / $ . \\ . Opens with the canonical NAME=~[]; NAME={...} destructor assignment shape. Statically opaque; recovery requires JS-engine execution in a sandbox"
        severity = "high"
        category = "obfuscation"
        mitre = "T1027.010"
        applies_to = "javascript, html, plaintext, decoded-payload"
    strings:
        $jj_opener = /[A-Za-z_$][A-Za-z0-9_$]{0,40}\s*=\s*~\s*\[\s*\]\s*;\s*[A-Za-z_$][A-Za-z0-9_$]{0,40}\s*=\s*\{/
        $jj_toString = "\"constructor\"][\"constructor\"]" ascii
        $jj_alphabet = /[\$_]{3,}(?:\+[\$_]{1,}){8,}/
    condition:
        $jj_opener and ($jj_toString or $jj_alphabet)
}

rule Python_Socket_Revshell_Primitive
{
    meta:
        description = "Detects Python reverse-shell primitive — socket.socket() + connect((host, port)) paired with os.dup2() / pty.spawn() / subprocess.call() within a small proximity. The canonical pentester / dropper shape for Linux-target Python stagers"
        severity = "critical"
        category = "execution"
        mitre = "T1059.006"
        applies_to = "python, plaintext, decoded-payload"
    strings:
        $sock_create = /socket\s*\.\s*socket\s*\(/ nocase
        $sock_connect = /\.\s*connect\s*\(\s*\(\s*['"]?[\w.\-]{3,80}['"]?\s*,\s*\d{1,5}\s*\)/ nocase
        $os_dup2 = /os\s*\.\s*dup2\s*\(/ nocase
        $pty_spawn = /pty\s*\.\s*spawn\s*\(/ nocase
        $subprocess_call = /subprocess\s*\.\s*(?:call|Popen|run)\s*\(/ nocase
    condition:
        $sock_create and $sock_connect and any of ($os_dup2, $pty_spawn, $subprocess_call)
}
