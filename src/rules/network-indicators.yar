rule UNC_Path_NTLM_Theft
{
    meta:
        description = "File contains UNC path reference — may trigger NTLM authentication to attacker"
        severity    = "high"
        category    = "credential-access"
        mitre       = "T1187"
        applies_to  = "text_like, decoded-payload"

    strings:
        $a = /\\\\[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\\/
        $b = /\\\\[a-zA-Z0-9\-]+\.[a-z]{2,4}\\/

    condition:
        any of them
}

rule WebDAV_Reference
{
    meta:
        description = "File references WebDAV path — can fetch remote payloads or steal NTLM hashes"
        severity    = "high"
        category    = "credential-access"
        mitre       = "T1187"
        applies_to  = "text_like, decoded-payload"

    strings:
        $a = "\\\\DavWWWRoot\\" nocase
        $b = "\\DavWWWRoot\\" nocase
        $c = "@SSL\\DavWWWRoot" nocase

    condition:
        any of them
}

rule Credential_Dumping_Commands
{
    meta:
        description = "File references credential dumping tools or techniques (procdump+lsass, comsvcs MiniDump, ntdsutil)"
        severity    = "high"
        category    = "credential-access"
        mitre       = "T1003"
        applies_to  = "text_like, decoded-payload"

    strings:
        $a     = "procdump" nocase
        $b     = "lsass" nocase
        $c     = "comsvcs.dll" nocase
        $d     = "MiniDump" nocase
        $e     = "ntdsutil" nocase
        $f     = "vssadmin" nocase
        $g     = "ntds.dit" nocase

    condition:
        ($a and $b) or ($c and $d) or ($e and ($f or $g))
}

rule Exfil_Telegram_Bot_API
{
    meta:
        description = "References to Telegram Bot API for data exfiltration or C2"
        severity    = "medium"
        category    = "exfiltration"
        mitre       = "T1567"
        applies_to  = "text_like, decoded-payload"

    strings:
        $api1 = "api.telegram.org" nocase
        $api2 = "/sendMessage" nocase
        $api3 = "/sendDocument" nocase
        $bot  = "bot_token" nocase
        $chat = "chat_id" nocase

    condition:
        $api1 or ($api2 and ($bot or $chat)) or ($api3 and ($bot or $chat))
}

rule Exfil_Discord_Webhook
{
    meta:
        description = "File references Discord webhook URL — used for data exfiltration"
        severity    = "high"
        category    = "exfiltration"
        mitre       = "T1567"
        applies_to  = "text_like, decoded-payload"

    strings:
        $webhook = "discord.com/api/webhooks/" nocase
        $discordapp = "discordapp.com/api/webhooks/" nocase

    condition:
        $webhook or $discordapp
}

rule Exfil_Slack_Webhook
{
    meta:
        description = "File references Slack webhook — potential data exfiltration channel"
        severity    = "high"
        category    = "exfiltration"
        mitre       = "T1567"
        applies_to  = "text_like, decoded-payload"

    strings:
        $hook = "hooks.slack.com/services/" nocase
        $api  = "slack.com/api/" nocase

    condition:
        any of them
}

rule SSH_Private_Key_Reference
{
    meta:
        description = "Reference to SSH private key file or content"
        severity    = "medium"
        category    = "credential-access"
        mitre       = "T1552.004"
        applies_to  = "any"

    strings:
        $rsa     = "-----BEGIN RSA PRIVATE KEY-----"
        $openssh = "-----BEGIN OPENSSH PRIVATE KEY-----"
        $ec      = "-----BEGIN EC PRIVATE KEY-----"
        $dsa     = "-----BEGIN DSA PRIVATE KEY-----"
        $pgp     = "-----BEGIN PGP PRIVATE KEY BLOCK-----"
        $generic = "-----BEGIN PRIVATE KEY-----"
        $ppk     = "PuTTY-User-Key-File" nocase

    condition:
        any of them
}

rule Exfil_Pastebin_Reference
{
    meta:
        description = "References to Pastebin or paste-site URLs (commonly used for malware staging)"
        severity    = "info"
        category    = "exfiltration"
        mitre       = "T1567.002"
        applies_to  = "text_like, decoded-payload"

    strings:
        $pb1 = "pastebin.com" nocase
        $pb2 = "hastebin.com" nocase
        $pb3 = "paste.ee" nocase
        $pb4 = "ghostbin.co" nocase
        $pb5 = "dpaste.org" nocase
        $pb6 = "transfer.sh" nocase

    condition:
        any of them
}

rule Punycode_IDN_Homograph
{
    meta:
        description = "File contains punycode/xn-- domain — possible IDN homograph or lookalike-domain phishing"
        severity    = "medium"
        category    = "phishing"
        mitre       = "T1036"
        applies_to  = "text_like, decoded-payload"

    strings:
        $a = /https?:\/\/[a-zA-Z0-9\-\.]{0,253}xn--[a-z0-9\-]{2,63}/
        $b = /\bxn--[a-z0-9\-]{2,63}\.[a-z]{2,24}\b/

    condition:
        any of them
}

rule Abuse_TLD_DDNS_Tunnel
{
    meta:
        description = "File references a domain on a high-abuse dynamic-DNS or tunnelling provider (ngrok, trycloudflare, duckdns, serveo, cloudflare workers/pages)"
        severity    = "medium"
        category    = "command-and-control"
        mitre       = "T1568.002"
        applies_to  = "text_like, decoded-payload"

    strings:
        $a = ".ngrok.io" nocase
        $b = ".ngrok-free.app" nocase
        $c = ".trycloudflare.com" nocase
        $d = ".loca.lt" nocase
        $e = ".serveo.net" nocase
        $f = ".duckdns.org" nocase
        $g = ".no-ip.com" nocase
        $h = ".hopto.org" nocase
        $i = ".zapto.org" nocase
        $j = ".dynu.net" nocase
        $k = ".workers.dev" nocase
        $l = ".pages.dev" nocase

    condition:
        any of them
}

rule Tunneling_Tool_Reference
{
    meta:
        description = "Reference to a known tunneling / pivoting tool by binary or project name — chisel, ligolo-ng, frpc/frps, gost, socat, plink, sshuttle, cloudflared, stunnel, iodine, dnscat2, nps/npc, revsocks, rathole, gotunnel"
        severity    = "high"
        category    = "command-and-control"
        mitre       = "T1572"
        applies_to  = "text_like, decoded-payload"

    strings:
        $chisel       = /\bchisel(\.exe)?\s+(client|server)\b/ nocase
        $chisel2      = "github.com/jpillora/chisel" nocase
        $ligolo       = /\bligolo(-ng)?(\.exe)?\b/ nocase
        $ligolo_proj  = "ligolo-ng" nocase
        $frpc         = /\bfrpc(\.exe)?\s+-c\b/ nocase
        $frps         = /\bfrps(\.exe)?\s+-c\b/ nocase
        $frpc_toml    = "[common]\nserver_addr" nocase
        $gost         = /\bgost(\.exe)?\s+-L\b/ nocase
        $socat_tun    = /\bsocat\s+(tcp|tcp4|tcp6|openssl)-listen:[0-9]+/ nocase
        $socat_exec   = /\bsocat[^\r\n]{0,80}exec:[\"']?(\/bin\/(ba)?sh|cmd)/ nocase
        $plink        = /\bplink(\.exe)?\s+-(R|L|D)\s+\d+/ nocase
        $sshuttle     = /\bsshuttle\s+-r\b/ nocase
        $cloudflared  = /\bcloudflared(\.exe)?\s+(tunnel|access)\b/ nocase
        $stunnel      = /\bstunnel(4|\.exe)?\s+/ nocase
        $iodine       = /\biodine(d)?\s+/ nocase
        $dnscat2      = /\bdnscat2?(\.exe)?\b/ nocase
        $nps          = /\bnps(\.exe)?\s+(install|start)\b/ nocase
        $npc          = /\bnpc(\.exe)?\s+-server\s/ nocase
        $revsocks     = /\brevsocks(\.exe)?\b/ nocase
        $rathole      = /\brathole(\.exe)?\s+/ nocase
        $gotunnel     = "gotunnel" nocase
        $powercat     = "Invoke-PowerCat" nocase
        $tcp_tunnel   = "github.com/sensepost/godoh" nocase

    condition:
        any of them
}

rule Exfil_File_Drop_Hosts
{
    meta:
        description = "Reference to public anonymous-upload / file-drop / large-file-share host commonly abused for exfiltration (mega, mediafire, sendspace, wetransfer, file.io, anonfiles, gofile, catbox.moe, 0x0.st, temp.sh, bashupload, oshi.at, filebin)"
        severity    = "medium"
        category    = "exfiltration"
        mitre       = "T1567.002"
        applies_to  = "text_like, decoded-payload"

    strings:
        $mega       = "mega.nz" nocase
        $mega2      = "mega.co.nz" nocase
        $mediafire  = "mediafire.com" nocase
        $sendspace  = "sendspace.com" nocase
        $wetransfer = "wetransfer.com" nocase
        $fileio     = /\bfile\.io\b/ nocase
        $anonfiles  = "anonfiles.com" nocase
        $gofile     = "gofile.io" nocase
        $catbox     = "catbox.moe" nocase
        $litterbox  = "litterbox.catbox.moe" nocase
        $oxost      = /\b0x0\.st\b/ nocase
        $tempsh     = /\btemp\.sh\b/ nocase
        $bashupload = "bashupload.com" nocase
        $oshi       = /\boshi\.at\b/ nocase
        $filebin    = "filebin.net" nocase
        $transfer   = "transfer.archivete.am" nocase
        $dbox_share = "dropbox.com/s/" nocase
        $dbox_share2 = "dropbox.com/scl/fi/" nocase
        $gdrive_dl  = /drive\.google\.com\/uc\?[^\r\n]{0,80}id=/ nocase
        $gdocs_exp  = "docs.google.com/document/" nocase
        $onedrv_dl  = "1drv.ms" nocase
        $onedrv_dl2 = "onedrive.live.com/download" nocase
        $tmpfiles   = "tmpfiles.org" nocase
        $putio      = /\bput\.re\b/ nocase

    condition:
        any of them
}

rule Exfil_OAST_Collaborator
{
    meta:
        description = "Reference to OAST / OOB-collaborator domain (interactsh, oast.*, dnslog.cn, burpcollaborator, ceye.io) — out-of-band exfil / blind-injection callback channel"
        severity    = "high"
        category    = "exfiltration"
        mitre       = "T1071.004"
        applies_to  = "text_like, decoded-payload"

    strings:
        $interactsh   = "interactsh-server" nocase
        $oast_fun     = ".oast.fun" nocase
        $oast_live    = ".oast.live" nocase
        $oast_pro     = ".oast.pro" nocase
        $oast_me      = ".oast.me" nocase
        $oast_online  = ".oast.online" nocase
        $oast_site    = ".oast.site" nocase
        $dnslog_cn    = "dnslog.cn" nocase
        $burp         = "burpcollaborator.net" nocase
        $ceye         = ".ceye.io" nocase
        $pingb        = ".pingb.in" nocase

    condition:
        any of them
}

rule Cloud_CLI_Exfil
{
    meta:
        description = "Cloud-storage CLI write/sync verb paired with non-tenant URL or remote alias (aws s3 cp/sync, gsutil/gcloud cp, az storage blob upload, rclone copy/sync, b2 upload-file, mc cp) — bring-your-own-bucket exfiltration"
        severity    = "medium"
        category    = "exfiltration"
        mitre       = "T1567"
        applies_to  = "text_like, decoded-payload"

    strings:
        $aws_cp    = /\baws\s+s3\s+(cp|sync|mv)\s+/ nocase
        $aws_make  = /\baws\s+s3\s+mb\s+s3:/ nocase
        $gsutil    = /\bgsutil\s+(cp|mv|rsync)\s+/ nocase
        $gcloud_cp = /\bgcloud\s+storage\s+(cp|mv|rsync)\s+/ nocase
        $az_up     = /\baz\s+storage\s+blob\s+(upload|upload-batch|copy)\s+/ nocase
        $rclone    = /\brclone\s+(copy|sync|move|copyto|moveto)\s+/ nocase
        $b2_up     = /\bb2\s+upload-file\s+/ nocase
        $mc_cp     = /\bmc\s+(cp|mirror|mv)\s+/ nocase
        $oci_up    = /\boci\s+os\s+object\s+put\s+/ nocase
        $s3_url    = /s3:\/\/[a-z0-9\-\.]{2,}/ nocase

    condition:
        any of them
}
