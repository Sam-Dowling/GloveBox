rule PKG_Xar_Archive {
    meta:
        description = "macOS flat Installer Package (xar archive) — scripts execute with root privileges during install"
        category    = "suspicious"
        mitre       = "T1546"
        severity    = "info"
    strings:
        $xar = { 78 61 72 21 }
    condition:
        $xar at 0
}

rule DMG_UDIF_Disk_Image {
    meta:
        description = "Apple Disk Image (UDIF) — bypasses macOS Mark-of-the-Web quarantine attribute once mounted"
        category    = "defense-evasion"
        mitre       = "T1553.005"
        severity    = "info"
    strings:
        $koly = { 6B 6F 6C 79 }
    condition:
        $koly in (filesize - 512 .. filesize)
}

rule DMG_Encrypted {
    meta:
        description = "Encrypted Apple Disk Image — contents cannot be statically inspected without the passphrase (common malware packaging)"
        category    = "defense-evasion"
        mitre       = "T1027.013"
        severity    = "high"
    strings:
        $aea      = { 41 45 41 31 }
        $encrcdsa = "encrcdsa" ascii
        $cdsaencr = "cdsaencr" ascii
    condition:
        $aea at 0 or $encrcdsa at 0 or $cdsaencr at 0
}

rule DMG_Contains_App_Launcher {
    meta:
        description = "DMG contains both an Applications symlink and a .app bundle — classic drag-to-install social-engineering layout used by AdLoad / AMOS / Atomic Stealer"
        category    = "initial-access"
        mitre       = "T1204.002"
        severity    = "high"
    strings:
        $koly     = { 6B 6F 6C 79 }
        $apps_sym = "Applications" ascii
        $app_bun  = ".app" ascii
    condition:
        $koly in (filesize - 512 .. filesize)
        and $apps_sym and #app_bun >= 2
}

rule DMG_Contains_Hidden_App {
    meta:
        description = "DMG contains a hidden .app bundle (leading dot) — used to obscure the real payload behind a visible decoy"
        category    = "defense-evasion"
        mitre       = "T1564.001"
        severity    = "high"
    strings:
        $koly       = { 6B 6F 6C 79 }
        $hidden1    = "/.app" ascii
        $hidden2    = /\/\.[A-Za-z0-9_\- ]{1,40}\.app/
    condition:
        $koly in (filesize - 512 .. filesize) and ($hidden1 or $hidden2)
}
