// ─── Encoding Threats ───
// 28 rules

rule Double_Extension_Any_File
{
    meta:
        description = "File with double extension pattern in its content — masquerade attempt"
        severity    = "high"
        category    = "defense-evasion"
        mitre       = "T1036.007"

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
        category    = "defense-evasion"
        mitre       = "T1036.002"

    strings:
        $a = { E2 80 AE }
        $b = { FE FF 20 2E }

    condition:
        any of them
}

rule Standalone_Script_Shell_Execution
{
    meta:
        description = "Individual script/shell execution indicator (standalone match)"
        severity    = "medium"
        category    = "execution"
        mitre       = "T1059"

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
        category    = "execution"
        mitre       = "T1559.001"

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
        category    = "command-and-control"
        mitre       = "T1105"

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
        category    = "execution"
        mitre       = "T1059.001"

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
        category    = "defense-evasion"
        mitre       = "T1218"

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
        category    = "execution"
        mitre       = "T1059.007"

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
        category    = "credential-access"
        mitre       = "T1056.003"

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
        category    = "execution"
        mitre       = "T1059.007"

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
        category    = "execution"
        mitre       = "T1059.005"

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
        category    = "execution"
        mitre       = "T1059"

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
        category    = "initial-access"
        mitre       = "T1204.002"

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
        category    = "initial-access"
        mitre       = "T1203"

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
        category    = "defense-evasion"
        mitre       = "T1027"

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
        category    = "execution"
        mitre       = "T1204.002"

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
        category    = "defense-evasion"
        mitre       = "T1027"

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
        category    = "defense-evasion"
        mitre       = "T1027"

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
        category    = "defense-evasion"
        mitre       = "T1027"

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
        category    = "defense-evasion"
        mitre       = "T1027"

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
        category    = "defense-evasion"
        mitre       = "T1027"

    strings:
        $b64_zip = "UEsD" ascii

    condition:
        $b64_zip
}

rule Hex_Encoded_PE_Header
{
    meta:
        description = "Hex-encoded PE executable header (4D5A9000)"
        severity    = "high"
        category    = "defense-evasion"
        mitre       = "T1027"

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
        category    = "defense-evasion"
        mitre       = "T1027"

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
        category    = "defense-evasion"
        mitre       = "T1140"

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

rule Unicode_Escape_Obfuscation
{
    meta:
        description = "File uses Unicode escape sequences to hide content"
        severity    = "medium"
        category    = "defense-evasion"
        mitre       = "T1027"

    strings:
        $uesc = /(\\u[0-9a-fA-F]{4}){8,}/ ascii

    condition:
        $uesc
}

rule Obfuscated_IEX_Invocation
{
    meta:
        description = "PowerShell uses obfuscated Invoke-Expression (IEX) patterns"
        severity    = "high"
        category    = "execution"
        mitre       = "T1059.001"

    strings:
        $iex1 = /\.\s*\(\s*\$[a-zA-Z]*[eE][nN][vV]:[a-zA-Z]+\[/ ascii
        $iex2 = /[iI][eE][xX]\s*\(/ ascii
        $iex3 = /[Ii]nvoke-[Ee]xpression/ ascii
        $iex4 = /\.\(\s*'[iI]'\s*\+\s*'[eE]'\s*\+\s*'[xX]'\s*\)/ ascii
        $iex5 = /\$\w+\s*=\s*\[type\]\s*\(\s*'[^']+'\s*\)/ ascii
        $sal = /[sS][aA][lL]\s+\w{1,5}\s+[iI][eE][xX]/ ascii

    condition:
        any of them
}

rule Obfuscated_Download_Cradle
{
    meta:
        description = "File contains obfuscated download cradle patterns"
        severity    = "high"
        category    = "execution"
        mitre       = "T1059.001"

    strings:
        $dl1 = "DownloadString" nocase
        $dl2 = "DownloadFile" nocase
        $dl3 = "DownloadData" nocase
        $dl4 = "Invoke-WebRequest" nocase
        $dl5 = "Start-BitsTransfer" nocase
        $dl6 = "Net.WebClient" nocase
        $dl7 = "wget " nocase
        $dl8 = "curl " nocase
        $obf1 = "FromBase64String" nocase
        $obf2 = "-EncodedCommand" nocase
        $obf3 = "-enc " nocase
        $obf4 = "hidden" nocase
        $obf5 = "-w hidden" nocase
        $obf6 = "-nop" nocase

    condition:
        any of ($dl*) and any of ($obf*)
}

// ============================================================================
// Python Obfuscation Rules
// ============================================================================

rule Space_Delimited_Hex_Payload
{
    meta:
        description = "Detects space, colon, or dash delimited hex byte strings that may encode payloads"
        severity = "medium"
        category = "obfuscation"
        mitre       = "T1027"
        reference = "Hex bytes like '4d 5a 90 00' or '4d:5a:90:00' encoding executables or scripts"

    strings:
        $hex_space = /([0-9a-fA-F]{2}\s){15,}[0-9a-fA-F]{2}/
        $hex_colon = /([0-9a-fA-F]{2}:){15,}[0-9a-fA-F]{2}/
        $hex_dash = /([0-9a-fA-F]{2}-){15,}[0-9a-fA-F]{2}/

    condition:
        any of them
}

// ============================================================================
// Bash / Shell Obfuscation Rules
// ============================================================================

