rule ClickOnce_AppDomainManager_Override {
    meta:
        description = "ClickOnce manifest overrides AppDomainManager — hijack/side-load vector (GhostPack / DoppelGate)"
        category    = "defense-evasion"
        mitre       = "T1574.014"
        severity    = "high"
    strings:
        $asm    = "<assembly" ascii wide nocase
        $adma   = "appDomainManagerAssembly" ascii wide nocase
        $admt   = "appDomainManagerType" ascii wide nocase
        $config = "configurationFile" ascii wide nocase
    condition:
        $asm and ($adma or $admt or $config)
}

rule ClickOnce_HTTP_Deployment {
    meta:
        description = "ClickOnce deployment manifest uses plain HTTP codebase (no TLS) — MITM/downgrade risk"
        category    = "command-and-control"
        mitre       = "T1105"
        severity    = "medium"
    strings:
        $dep    = "<deployment" ascii wide nocase
        $cb     = "codebase=\"http://" ascii wide nocase
        $dp     = "deploymentProvider=\"http://" ascii wide nocase
    condition:
        $dep and ($cb or $dp)
}

rule ClickOnce_FullTrust_Requested {
    meta:
        description = "ClickOnce application requests FullTrust permission set (runs unsandboxed)"
        category    = "privilege-escalation"
        mitre       = "T1059"
        severity    = "high"
    strings:
        $asm   = "<assembly" ascii wide nocase
        $ts    = "<trustInfo" ascii wide nocase
        $pset  = "<PermissionSet" ascii wide nocase
        $ft1   = "Unrestricted=\"true\"" ascii wide nocase
        $ft3   = "ID=\"FullTrust\"" ascii wide nocase
    condition:
        $asm and $ts and $pset and ($ft1 or $ft3)
}

rule ClickOnce_Suspicious_Codebase_TLD {
    meta:
        description = "ClickOnce deployment codebase points to suspicious/disposable hosting (free-TLD, tunneling, paste sites)"
        category    = "command-and-control"
        mitre       = "T1608.001"
        severity    = "high"
    strings:
        $dep   = "<deployment" ascii wide nocase
        $cb    = "codebase=" ascii wide nocase
        $tld1  = ".trycloudflare.com" ascii wide nocase
        $tld2  = ".ngrok.io" ascii wide nocase
        $tld3  = ".ngrok-free.app" ascii wide nocase
        $tld4  = ".serveo.net" ascii wide nocase
        $tld5  = ".loca.lt" ascii wide nocase
        $tld6  = ".duckdns.org" ascii wide nocase
        $tld7  = ".sytes.net" ascii wide nocase
        $tld8  = ".zapto.org" ascii wide nocase
        $tld9  = ".hopto.org" ascii wide nocase
        $tld10 = ".serveftp.com" ascii wide nocase
        $tld11 = "pastebin.com" ascii wide nocase
        $tld12 = "transfer.sh" ascii wide nocase
    condition:
        $dep and $cb and 1 of ($tld*)
}
