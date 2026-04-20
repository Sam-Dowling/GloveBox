rule Npm_Lifecycle_Hook_Download {
    meta:
        description = "npm lifecycle hook (preinstall/postinstall/install) shells out to curl or wget to fetch and run a remote payload"
        category    = "execution"
        mitre       = "T1105"
        severity    = "critical"
    strings:
        $h1    = "\"preinstall\"" ascii wide nocase
        $h2    = "\"postinstall\"" ascii wide nocase
        $h3    = "\"install\"" ascii wide nocase
        $c1    = "curl " ascii wide nocase
        $c2    = "wget " ascii wide nocase
        $c3    = "| sh" ascii wide nocase
        $c4    = "| bash" ascii wide nocase
        $c5    = "iwr " ascii wide nocase
        $c6    = "Invoke-WebRequest" ascii wide nocase
    condition:
        1 of ($h*) and 2 of ($c*)
}

rule Npm_Lifecycle_Hook_Eval_Chain {
    meta:
        description = "npm lifecycle hook composes eval / new Function / Buffer.from(…'base64') to decode and execute a runtime-assembled payload"
        category    = "defense-evasion"
        mitre       = "T1027"
        severity    = "high"
    strings:
        $h1    = "\"preinstall\"" ascii wide nocase
        $h2    = "\"postinstall\"" ascii wide nocase
        $h3    = "\"install\"" ascii wide nocase
        $e1    = "eval(" ascii wide nocase
        $e2    = "new Function(" ascii wide nocase
        $e3    = "Buffer.from(" ascii wide nocase
        $e4    = "'base64'" ascii wide nocase
        $e5    = "\"base64\"" ascii wide nocase
        $e6    = "require('child_process')" ascii wide nocase
        $e7    = "child_process.exec" ascii wide nocase
    condition:
        1 of ($h*) and 2 of ($e*)
}

rule Npm_ShaiHulud_Workflow {
    meta:
        description = "Package bundles a GitHub Actions workflow named shai-hulud.yml — hallmark of the Shai-Hulud npm worm which re-publishes victim repos as public"
        category    = "persistence"
        mitre       = "T1546"
        severity    = "critical"
    strings:
        $w1    = "shai-hulud.yml" ascii wide nocase
        $w2    = "shai-hulud.yaml" ascii wide nocase
        $w3    = ".github/workflows/shai-hulud" ascii wide nocase
        $w4    = "Shai-Hulud" ascii wide
    condition:
        any of ($w*)
}

rule Npm_ShaiHulud_Repo_Exfil {
    meta:
        description = "Package script creates a public GitHub repo named Shai-Hulud and pushes harvested secrets to it via the GitHub API"
        category    = "exfiltration"
        mitre       = "T1567"
        severity    = "critical"
    strings:
        $n1    = "Shai-Hulud" ascii wide
        $n2    = "shai-hulud" ascii wide nocase
        $api1  = "api.github.com/user/repos" ascii wide nocase
        $api2  = "api.github.com/repos/" ascii wide nocase
        $mk    = "\"private\":false" ascii wide nocase
        $mk2   = "\"private\": false" ascii wide nocase
    condition:
        1 of ($n*) and 1 of ($api*) and 1 of ($mk*)
}

rule Npm_ShaiHulud_Bundle_Stealer {
    meta:
        description = "Package ships a large bundle.js that imports TruffleHog / cloud-metadata endpoints — the credential-harvesting payload shape seen in Shai-Hulud 1.0 and 2.0"
        category    = "credential-access"
        mitre       = "T1552"
        severity    = "critical"
    strings:
        $bn1   = "bundle.js" ascii wide nocase
        $bn2   = "dist/index.js" ascii wide nocase
        $tf1   = "trufflehog" ascii wide nocase
        $tf2   = "TruffleHog" ascii wide
        $aws   = "169.254.169.254" ascii wide
        $gcp   = "metadata.google.internal" ascii wide nocase
        $az    = "169.254.169.254/metadata" ascii wide nocase
        $imds  = "instance-identity" ascii wide nocase
    condition:
        1 of ($bn*) and 2 of ($tf*, $aws, $gcp, $az, $imds)
}

rule Npm_Npmrc_Token_Exfil {
    meta:
        description = "Package script reads .npmrc / NPM_TOKEN and writes it back out over the network — classic npm-publish-token hijack for downstream supply-chain pivots"
        category    = "credential-access"
        mitre       = "T1552.001"
        severity    = "high"
    strings:
        $rc1   = ".npmrc" ascii wide nocase
        $rc2   = "NPM_TOKEN" ascii wide
        $rc3   = "_authToken" ascii wide nocase
        $net1  = "fetch(" ascii wide nocase
        $net2  = "https.request" ascii wide nocase
        $net3  = "http.request" ascii wide nocase
        $net4  = "axios." ascii wide nocase
        $net5  = "XMLHttpRequest" ascii wide
    condition:
        2 of ($rc*) and 1 of ($net*)
}

rule Npm_Env_Harvest {
    meta:
        description = "Package script enumerates process.env and POSTs it off-box — common first-stage credential-harvest pattern in malicious npm packages"
        category    = "credential-access"
        mitre       = "T1552.001"
        severity    = "high"
    strings:
        $e1    = "process.env" ascii wide
        $e2    = "Object.keys(process.env)" ascii wide
        $e3    = "JSON.stringify(process.env)" ascii wide
        $net1  = "fetch(" ascii wide nocase
        $net2  = "https.request" ascii wide nocase
        $net3  = "http.request" ascii wide nocase
        $net4  = "axios." ascii wide nocase
        $sec1  = "AWS_SECRET" ascii wide
        $sec2  = "GITHUB_TOKEN" ascii wide
        $sec3  = "GH_TOKEN" ascii wide
        $sec4  = "SLACK_TOKEN" ascii wide
        $sec5  = "DISCORD_TOKEN" ascii wide
        $sec6  = "DATABASE_URL" ascii wide
    condition:
        $e1 and 1 of ($net*) and 1 of ($sec*)
}

rule Npm_Wallet_Scanner {
    meta:
        description = "Package script walks home-directory paths of browser wallet extensions (MetaMask, Phantom, Trust, Exodus) to lift seed vaults"
        category    = "credential-access"
        mitre       = "T1555"
        severity    = "critical"
    strings:
        $w1    = "MetaMask" ascii wide
        $w2    = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii wide nocase
        $w3    = "Phantom" ascii wide
        $w4    = "Exodus" ascii wide
        $w5    = "Trust Wallet" ascii wide
        $w6    = "Ledger Live" ascii wide
        $w7    = "wallet.dat" ascii wide nocase
        $w8    = "keystore" ascii wide nocase
        $fs1   = "readFileSync" ascii wide
        $fs2   = "readdirSync" ascii wide
        $fs3   = "os.homedir" ascii wide
    condition:
        2 of ($w*) and 1 of ($fs*)
}

rule Npm_Clipboard_Wallet_Swap {
    meta:
        description = "Package hooks the clipboard and rewrites BTC / ETH / SOL addresses on copy-paste — clipper shape used in npm supply-chain drops"
        category    = "impact"
        mitre       = "T1115"
        severity    = "high"
    strings:
        $cb1   = "clipboardy" ascii wide nocase
        $cb2   = "clipboard-event" ascii wide nocase
        $cb3   = "navigator.clipboard" ascii wide
        $re1   = "0x[a-fA-F0-9]{40}" ascii wide
        $re2   = "bc1[a-z0-9]{20" ascii wide
        $re3   = "[13][a-km-zA-HJ-NP-Z1-9]{25" ascii wide
    condition:
        1 of ($cb*) and 1 of ($re*)
}

rule Npm_Webhook_Beacon {
    meta:
        description = "Package script beacons to Discord / Telegram / Slack webhooks or a pastebin-like relay — common low-effort exfil channel in malicious npm drops"
        category    = "exfiltration"
        mitre       = "T1567.002"
        severity    = "high"
    strings:
        $d1    = "discord.com/api/webhooks" ascii wide nocase
        $d2    = "discordapp.com/api/webhooks" ascii wide nocase
        $t1    = "api.telegram.org/bot" ascii wide nocase
        $s1    = "hooks.slack.com/services" ascii wide nocase
        $p1    = "pastebin.com/api" ascii wide nocase
        $n1    = ".ngrok.io" ascii wide nocase
        $n2    = ".ngrok-free.app" ascii wide nocase
        $n3    = ".trycloudflare.com" ascii wide nocase
        $n4    = "requestbin." ascii wide nocase
        $n5    = "webhook.site" ascii wide nocase
    condition:
        any of them
}

rule Npm_Obfuscator_IO {
    meta:
        description = "Bundled script shows javascript-obfuscator.io fingerprints — array-rotate / string-array / hex-heavy identifiers typical of obfuscated npm droppers"
        category    = "defense-evasion"
        mitre       = "T1027"
        severity    = "medium"
    strings:
        $o1    = "_0x" ascii wide
        $o2    = "['push']['apply']" ascii wide
        $o3    = "['shift']()" ascii wide
        $o4    = "parseInt(_0x" ascii wide
        $o5    = "String['fromCharCode']" ascii wide
    condition:
        #o1 > 15 and 1 of ($o2, $o3, $o4, $o5)
}

rule Npm_Native_Binary_Dropper {
    meta:
        description = "Package ships a raw native binary (PE / ELF / Mach-O) alongside a postinstall hook that chmod +x's it and runs it"
        category    = "execution"
        mitre       = "T1204.002"
        severity    = "high"
    strings:
        $h1    = "\"postinstall\"" ascii wide nocase
        $h2    = "\"install\"" ascii wide nocase
        $c1    = "chmod +x" ascii wide
        $c2    = "child_process" ascii wide nocase
        $c3    = "spawn(" ascii wide
        $c4    = "execFile(" ascii wide
        $mz    = "MZ"
        $elf   = { 7F 45 4C 46 }
        $mh1   = { FE ED FA CE }
        $mh2   = { FE ED FA CF }
        $mh3   = { CA FE BA BE }
    condition:
        1 of ($h*) and 1 of ($c*) and 1 of ($mz, $elf, $mh1, $mh2, $mh3)
}

rule Npm_Typosquat_Lookalike {
    meta:
        description = "Package name matches a known typosquat of a popular npm package (e.g. crossenv, babelcli, jquery.js, noblox.js-proxied)"
        category    = "initial-access"
        mitre       = "T1195.002"
        severity    = "medium"
    strings:
        $n1    = "\"name\": \"crossenv\"" ascii wide nocase
        $n2    = "\"name\":\"crossenv\"" ascii wide nocase
        $n3    = "\"name\": \"babelcli\"" ascii wide nocase
        $n4    = "\"name\":\"babelcli\"" ascii wide nocase
        $n5    = "\"name\": \"jquery.js\"" ascii wide nocase
        $n6    = "\"name\":\"jquery.js\"" ascii wide nocase
        $n7    = "\"name\": \"noblox.js-proxy\"" ascii wide nocase
        $n8    = "\"name\":\"noblox.js-proxy\"" ascii wide nocase
        $n9    = "\"name\": \"discord.dll\"" ascii wide nocase
        $n10   = "\"name\":\"discord.dll\"" ascii wide nocase
        $n11   = "\"name\": \"electorn\"" ascii wide nocase
        $n12   = "\"name\": \"loadyaml\"" ascii wide nocase
    condition:
        any of them
}

rule Npm_Bin_Shell_Wrapper {
    meta:
        description = "Package 'bin' entry points at a .sh / .bat / .cmd wrapper — installing the package drops a shell script onto the user's PATH"
        category    = "persistence"
        mitre       = "T1546"
        severity    = "medium"
    strings:
        $b      = "\"bin\"" ascii wide nocase
        $s1     = ".sh\"" ascii wide nocase
        $s2     = ".bat\"" ascii wide nocase
        $s3     = ".cmd\"" ascii wide nocase
        $s4     = ".ps1\"" ascii wide nocase
    condition:
        $b and 1 of ($s*)
}

rule Npm_Lockfile_Nonregistry_Resolved {
    meta:
        description = "package-lock.json resolves a dependency from a non-registry URL (raw git / tarball / local path) — bypasses the public npm registry integrity gate"
        category    = "supply-chain"
        mitre       = "T1195.001"
        severity    = "medium"
    strings:
        $lv    = "\"lockfileVersion\"" ascii wide
        $r1    = "\"resolved\": \"git+" ascii wide nocase
        $r2    = "\"resolved\":\"git+" ascii wide nocase
        $r3    = "\"resolved\": \"file:" ascii wide nocase
        $r4    = "\"resolved\":\"file:" ascii wide nocase
        $r5    = "\"resolved\": \"http://" ascii wide nocase
        $r6    = "\"resolved\":\"http://" ascii wide nocase
        $r7    = "github.com/" ascii wide nocase
        $r8    = "codeload.github.com" ascii wide nocase
    condition:
        $lv and 1 of ($r1, $r2, $r3, $r4, $r5, $r6) and $r7
}
