// ─── Network Indicators ───
// 3 rules

rule UNC_Path_NTLM_Theft
{
    meta:
        description = "File contains UNC path reference — may trigger NTLM authentication to attacker"
        severity    = "high"

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
        description = "File references credential dumping tools or techniques beyond mimikatz"
        severity    = "critical"

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

// ════════════════════════════════════════════════════════════════════════
// C2 / Exfiltration Channel Detection
// ════════════════════════════════════════════════════════════════════════

rule Exfil_Telegram_Bot_API
{
    meta:
        description = "File references Telegram Bot API — common exfiltration and C2 channel"
        severity    = "high"

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

    strings:
        $webhook = "discord.com/api/webhooks/" nocase
        $discordapp = "discordapp.com/api/webhooks/" nocase
        $content = "\"content\"" nocase
        $embed = "\"embeds\"" nocase

    condition:
        ($webhook or $discordapp) or (($content or $embed) and ($webhook or $discordapp))
}

rule Exfil_Slack_Webhook
{
    meta:
        description = "File references Slack webhook — potential data exfiltration channel"
        severity    = "high"

    strings:
        $hook = "hooks.slack.com/services/" nocase
        $api  = "slack.com/api/" nocase

    condition:
        any of them
}

rule SSH_Private_Key_Reference
{
    meta:
        description = "File contains or references SSH/PGP private key material"
        severity    = "critical"

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
        description = "File references Pastebin or paste-like services — dead-drop exfiltration"
        severity    = "medium"

    strings:
        $pb1 = "pastebin.com" nocase
        $pb2 = "hastebin.com" nocase
        $pb3 = "paste.ee" nocase
        $pb4 = "ghostbin.co" nocase
        $pb5 = "dpaste.org" nocase
        $pb6 = "transfer.sh" nocase
        $pb7 = "file.io" nocase

    condition:
        any of them
}

