rule ZIP_Contains_Script_File
{
    meta:
        description = "ZIP archive contains two or more script-file types (.js/.vbs/.wsf/.hta/.bat/.cmd/.ps1) — dropper-style bundle"
        severity    = "critical"
        category    = "delivery"
        mitre       = "T1566.001"

    strings:
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
        uint32(0) == 0x04034B50 and 2 of ($a, $b, $c, $d, $e, $f, $g, $h, $i)
}

rule ZIP_Contains_LNK
{
    meta:
        description = "ZIP archive contains Windows shortcut (.lnk) — masquerade delivery"
        severity    = "critical"
        category    = "delivery"
        mitre       = "T1204.002"

    strings:
        $a = ".lnk" fullword

    condition:
        uint32(0) == 0x04034B50 and $a
}

rule ZIP_Contains_URL_Shortcut
{
    meta:
        description = "ZIP archive contains .url shortcut file — uncommon, likely phishing"
        severity    = "critical"
        category    = "delivery"
        mitre       = "T1204.002"

    strings:
        $a = ".url" fullword

    condition:
        uint32(0) == 0x04034B50 and $a
}

rule ZIP_Contains_ISO_IMG
{
    meta:
        description = "ZIP archive contains disk image (.iso/.img/.vhd/.vhdx) — MotW bypass nesting"
        severity    = "critical"
        category    = "defense-evasion"
        mitre       = "T1553.005"

    strings:
        $a = ".iso" fullword
        $b = ".img" fullword
        $c = ".vhd" fullword
        $d = ".vhdx" fullword

    condition:
        uint32(0) == 0x04034B50 and any of ($a, $b, $c, $d)
}

rule ZIP_Contains_Office_Macro_File
{
    meta:
        description = "ZIP contains macro-enabled Office document (.docm/.xlsm/.pptm/.xlsb)"
        severity    = "high"
        category    = "delivery"
        mitre       = "T1566.001"

    strings:
        $a = ".docm" fullword
        $b = ".xlsm" fullword
        $c = ".pptm" fullword
        $d = ".xlsb" fullword
        $e = ".dotm" fullword

    condition:
        uint32(0) == 0x04034B50 and any of ($a, $b, $c, $d, $e)
}

rule ZIP_Contains_MSI
{
    meta:
        description = "ZIP archive contains an MSI installer — uncommon as email attachment"
        severity    = "high"
        category    = "delivery"
        mitre       = "T1218.007"

    strings:
        $a = ".msi" fullword

    condition:
        uint32(0) == 0x04034B50 and $a
}

rule RAR_Archive_Header
{
    meta:
        description = "RAR archive detected — commonly used phishing delivery wrapper"
        severity    = "info"
        category    = "file-type"
        mitre       = "T1566.001"

    strings:
        $rar4 = { 52 61 72 21 1A 07 00 }
        $rar5 = { 52 61 72 21 1A 07 01 00 }

    condition:
        $rar4 at 0 or $rar5 at 0
}

rule SevenZip_Archive_Header
{
    meta:
        description = "7-Zip archive detected — sometimes used to bypass gateway extension filters"
        severity    = "info"
        category    = "file-type"
        mitre       = "T1566.001"

    strings:
        $magic = { 37 7A BC AF 27 1C }

    condition:
        $magic at 0
}

rule Archive_Double_Extension
{
    meta:
        description = "Archive file contains a double-extension filename — masquerade attempt"
        severity    = "critical"
        category    = "defense-evasion"
        mitre       = "T1036.007"

    strings:
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
        uint32(0) == 0x04034B50 and any of ($a, $b, $c, $d, $e, $f, $g, $h, $i, $j, $k, $l)
}

rule ISO_IMG_Disk_Image
{
    meta:
        description = "ISO 9660 disk image — used to bypass Mark-of-the-Web protections"
        severity    = "high"
        category    = "defense-evasion"
        mitre       = "T1553.005"

    strings:
        $iso = "CD001" ascii

    condition:
        $iso at 32769 or $iso at 34817
}
