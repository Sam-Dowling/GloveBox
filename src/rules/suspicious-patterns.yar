// ─── Suspicious Patterns ───
// 7 rules

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
// Crypto Miner Indicators
// ════════════════════════════════════════════════════════════════════════

rule Crypto_Miner_Indicators
{
    meta:
        description = "File contains cryptocurrency mining indicators — pool addresses, miner tools"
        severity    = "high"

    strings:
        $pool1  = "stratum+tcp://" nocase
        $pool2  = "stratum+ssl://" nocase
        $pool3  = "pool.minexmr.com" nocase
        $pool4  = "xmrpool.eu" nocase
        $pool5  = "nanopool.org" nocase
        $pool6  = "hashvault.pro" nocase
        $miner1 = "xmrig" nocase
        $miner2 = "cpuminer" nocase
        $miner3 = "cgminer" nocase
        $miner4 = "bfgminer" nocase
        $miner5 = "CoinHive" nocase
        $wallet = /[14][a-km-zA-HJ-NP-Z1-9]{25,34}/ ascii
        $monero = /4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}/ ascii

    condition:
        any of ($pool*) or any of ($miner*) or ($wallet and any of ($pool*, $miner*)) or ($monero and any of ($pool*, $miner*))
}

// ════════════════════════════════════════════════════════════════════════
// OLE10Native Embedded Object Abuse
// ════════════════════════════════════════════════════════════════════════

rule OLE10Native_Embedded_Executable
{
    meta:
        description = "OLE document contains OLE10Native stream with executable — drops file on activation"
        severity    = "critical"

    strings:
        $ole    = { D0 CF 11 E0 A1 B1 1A E1 }
        $native = "\x01Ole10Native" wide
        $exe    = ".exe" nocase
        $cmd    = ".cmd" nocase
        $bat    = ".bat" nocase
        $scr    = ".scr" nocase
        $pif    = ".pif" nocase
        $ps1    = ".ps1" nocase

    condition:
        $ole and $native and any of ($exe, $cmd, $bat, $scr, $pif, $ps1)
}

// ════════════════════════════════════════════════════════════════════════
// Suspicious String Entropy / Padding
// ════════════════════════════════════════════════════════════════════════

rule Suspicious_Null_Byte_Padding
{
    meta:
        description = "File contains suspicious null byte padding patterns — payload alignment or evasion"
        severity    = "medium"

    strings:
        $nop_sled = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
        $null_pad = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        $nop_sled or (#null_pad > 10)
}

// ════════════════════════════════════════════════════════════════════════
// REG — Windows Registry File rules
// ════════════════════════════════════════════════════════════════════════

