rule Embedded_PE_Header
{
    meta:
        description = "File contains an embedded MZ PE header (4D5A9000) — hidden executable inside non-PE file"
        severity    = "critical"
        category    = "defense-evasion"
        mitre       = "T1027.009"
        applies_to  = "any"

    strings:
        $mz = { 4D 5A 90 00 }

    condition:
        not ($mz at 0) and $mz
}

rule Suspicious_COM_Hijack_CLSID
{
    meta:
        description = "File references COM object CLSIDs commonly abused for hijacking persistence"
        severity    = "medium"
        category    = "persistence"
        mitre       = "T1546.015"
        applies_to  = "text_like, decoded-payload"

    strings:
        $clsid_mmcfx   = "{49CBB1C7-97D1-485A-9EC1-A26065633066}" nocase
        $inproc         = "InprocServer32" nocase
        $treatAs        = "TreatAs" nocase
        $clsid_generic  = /CLSID\\{[0-9A-Fa-f\-]{36}}/ nocase

    condition:
        ($inproc or $treatAs) and $clsid_generic
}

rule General_Hex_Encoded_Shellcode
{
    meta:
        description = "File contains patterns consistent with hex-encoded shellcode blobs"
        severity    = "high"
        category    = "defense-evasion"
        mitre       = "T1027"
        applies_to  = "text_like, decoded-payload"

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
        category    = "defense-evasion"
        mitre       = "T1027.009"
        applies_to  = "any"

    strings:
        $pk = { 50 4B 03 04 }

    condition:
        not ($pk at 0) and #pk > 0
}

rule Embedded_Compressed_Stream
{
    meta:
        description = "Zlib or gzip compressed stream embedded in file"
        severity    = "info"
        category    = "file-type"
        mitre       = ""
        applies_to  = "any"

    strings:
        $zlib_default = { 78 9C }
        $zlib_best    = { 78 DA }
        $gzip_magic   = { 1F 8B 08 }

    condition:
        any of them
}

rule Crypto_Miner_Indicators
{
    meta:
        description = "File contains cryptocurrency mining indicators — pool addresses, miner tools"
        severity    = "high"
        category    = "impact"
        mitre       = "T1496"
        applies_to  = "text_like, decoded-payload"

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

rule OLE10Native_Embedded_Executable
{
    meta:
        description = "OLE document contains OLE10Native stream with executable — drops file on activation"
        severity    = "critical"
        category    = "execution"
        mitre       = "T1204.002"
        applies_to  = "is_office, rtf"

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
