rule PCAP_Cobalt_Strike_Malleable_C2 {
    meta:
        description = "Cobalt Strike default Malleable C2 profile artefacts in HTTP traffic"
        severity    = "critical"
        category    = "c2"
        mitre       = "T1071.001"
    strings:
        $ua_jquery   = "User-Agent: Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; Trident/6.0)" ascii
        $cs_jquery   = "/jquery-3.3.1.min.js" ascii
        $cs_jquery2  = "/jquery-3.3.2.min.js" ascii
        $cs_amazon   = "/s/ref=nb_sb_noss_1/" ascii
        $cs_session  = "__cfduid=" ascii
        $cs_beacon   = "MZARUH" ascii
    condition:
        2 of them
}

rule PCAP_Empire_HTTP_Listener {
    meta:
        description = "Empire / Starkiller default HTTP listener URI patterns"
        severity    = "critical"
        category    = "c2"
        mitre       = "T1071.001"
    strings:
        $u1 = "/admin/get.php" ascii
        $u2 = "/news.php" ascii
        $u3 = "/login/process.php" ascii
        $session = "session=" ascii
        $stager = "powershell -nop -w hidden -enc " ascii
    condition:
        2 of ($u*) or $stager
}

rule PCAP_Metasploit_Meterpreter_Default {
    meta:
        description = "Metasploit reverse_https / meterpreter default URI shape"
        severity    = "high"
        category    = "c2"
        mitre       = "T1071.001"
    strings:
        $msf1 = "/INITM" ascii
        $msf2 = "/INITJM" ascii
        $msf3 = "/A_2/x/" ascii
        $stage = "x86/shikata_ga_nai" ascii
    condition:
        any of them
}

rule PCAP_Mythic_HTTP_Profile {
    meta:
        description = "Mythic C2 default HTTP profile callback URI"
        severity    = "high"
        category    = "c2"
        mitre       = "T1071.001"
    strings:
        $u1 = "/api/v1.4/agent_message" ascii
        $u2 = "X-Mythic" ascii nocase
    condition:
        any of them
}

rule PCAP_Sliver_HTTP_Profile {
    meta:
        description = "Sliver C2 default HTTP transport URI shape"
        severity    = "high"
        category    = "c2"
        mitre       = "T1071.001"
    strings:
        $u1 = "/admin/login.html?id=" ascii
        $u2 = "/api/v1/info" ascii
        $sess = "PHPSESSID=" ascii
        $cookie = "cf_clearance=" ascii
    condition:
        2 of them
}

rule PCAP_DNS_Tunneling_Long_Subdomain {
    meta:
        description = "DNS query with abnormally long base32/base64-shaped subdomain — possible DNS tunnel (iodine / dnscat2)"
        severity    = "high"
        category    = "tunnel"
        mitre       = "T1071.004"
    strings:
        $tun_marker = "dnscat" ascii nocase
        $iodine     = ".iodine." ascii nocase
        $long_b32   = /[A-Z2-7]{40,}\.[a-z0-9.-]+/ ascii nocase
    condition:
        any of them
}

rule PCAP_Plaintext_Credentials_HTTP {
    meta:
        description = "HTTP request with plaintext password / token in form body or query string"
        severity    = "high"
        category    = "credential"
        mitre       = "T1040"
    strings:
        $authz = "Authorization: Basic " ascii
        $form_pass1 = "&password=" ascii nocase
        $form_pass2 = "?password=" ascii nocase
        $form_pass3 = "&passwd=" ascii nocase
        $form_pass4 = "&pwd=" ascii nocase
        $form_token = "&access_token=" ascii nocase
    condition:
        any of them
}

rule PCAP_TLS_JA3_SelfSigned_Indicator {
    meta:
        description = "TLS handshake bytes with default Cobalt Strike / Mimikatz self-signed certificate indicators (CN=Major Cobalt Strike)"
        severity    = "critical"
        category    = "c2"
        mitre       = "T1573.002"
    strings:
        $cn1 = "CN=Major Cobalt Strike" ascii
        $cn2 = "kaboom" ascii fullword
        $cn3 = "CN=AnyConnect VPN" ascii
        $cn4 = "CN=Burp Suite" ascii
    condition:
        any of them
}

rule PCAP_Mirai_Telnet_Bruteforce {
    meta:
        description = "Mirai-style Telnet bruteforce — common default-credential strings in TCP/23 traffic"
        severity    = "high"
        category    = "exploit"
        mitre       = "T1110.001"
    strings:
        $login1 = "Login: root" ascii
        $login2 = "username: admin" ascii nocase
        $cred1  = "xc3511" ascii
        $cred2  = "vizxv" ascii
        $cred3  = "klv1234" ascii
        $cred4  = "Zte521" ascii
        $busybox = "BusyBox" ascii
    condition:
        2 of ($cred*) or ($busybox and 1 of ($login*))
}

rule PCAP_PowerShell_Download_Cradle {
    meta:
        description = "PowerShell download cradle observed in HTTP body (T1059.001 + T1105)"
        severity    = "high"
        category    = "exec"
        mitre       = "T1059.001"
    strings:
        $iex = "IEX(New-Object Net.WebClient).DownloadString" ascii nocase
        $iex2 = "Invoke-Expression(New-Object Net.WebClient).DownloadString" ascii nocase
        $b64 = "powershell -e " ascii nocase
        $b64b = "powershell.exe -nop -w hidden -enc " ascii nocase
    condition:
        any of them
}

rule PCAP_SMB_Lateral_Movement {
    meta:
        description = "SMB tree-connect to ADMIN$ / C$ / IPC$ — administrative share access (T1021.002)"
        severity    = "medium"
        category    = "lateral"
        mitre       = "T1021.002"
    strings:
        $smb_signature = { FF 53 4D 42 }
        $smb2_signature = { FE 53 4D 42 }
        $admin = "ADMIN$" wide
        $c     = "C$" wide
        $ipc   = "IPC$" wide
    condition:
        ($smb_signature or $smb2_signature) and any of ($admin, $c, $ipc)
}

rule PCAP_Suspicious_HTTP_UserAgent {
    meta:
        description = "HTTP User-Agent strings that are common malware defaults (curl/wget/python/empty)"
        severity    = "medium"
        category    = "c2"
        mitre       = "T1071.001"
    strings:
        $ua1 = "User-Agent: python-requests/" ascii
        $ua2 = "User-Agent: curl/" ascii
        $ua3 = "User-Agent: Wget/" ascii
        $ua4 = "User-Agent: Go-http-client" ascii
        $ua5 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)" ascii
        $ua6 = "User-Agent: \r\n" ascii
    condition:
        any of them
}
