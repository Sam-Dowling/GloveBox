/* ──────────────────────────────────────────────────────────────────────
 *  osascript-threats.yar — AppleScript & JXA threat detection rules
 *
 *  Targets: .applescript, .scpt (compiled), .jxa (JavaScript for Automation)
 *  These are text-based rules — no magic byte anchoring (compiled .scpt
 *  strings are extracted to an augmented buffer before YARA scanning).
 * ────────────────────────────────────────────────────────────────────── */


rule osascript_credential_dialog_hidden
{
    meta:
        description = "AppleScript credential harvesting with hidden password dialog"
        severity    = "critical"
        category    = "credential-theft"
        mitre       = "T1056.002"
    strings:
        $dialog   = "display dialog" ascii nocase
        $default  = "default answer" ascii nocase
        $hidden   = "hidden answer" ascii nocase
    condition:
        $dialog and $default and $hidden
}

rule osascript_credential_dialog_social_engineering
{
    meta:
        description = "AppleScript dialog impersonating system prompt for credential theft"
        severity    = "high"
        category    = "credential-theft"
        mitre       = "T1056.002"
    strings:
        $dialog  = "display dialog" ascii nocase
        $answer  = "default answer" ascii nocase
        $se1     = "password" ascii nocase
        $se2     = "update" ascii nocase
        $se3     = "verify" ascii nocase
        $se4     = "authenticate" ascii nocase
        $se5     = "credentials" ascii nocase
        $se6     = "macOS requires" ascii nocase
        $se7     = "System Preferences" ascii nocase
        $icon    = "with icon" ascii nocase
    condition:
        $dialog and $answer and $icon and 1 of ($se*)
}

rule osascript_admin_shell_execution
{
    meta:
        description = "AppleScript executes shell commands with administrator privileges"
        severity    = "high"
        category    = "execution"
        mitre       = "T1548.004"
    strings:
        $shell  = "do shell script" ascii nocase
        $admin  = "administrator privileges" ascii nocase
    condition:
        $shell and $admin
}

rule osascript_shell_with_download
{
    meta:
        description = "AppleScript shell execution with network download (curl/wget)"
        severity    = "high"
        category    = "execution"
        mitre       = "T1105"
    strings:
        $shell  = "do shell script" ascii nocase
        $curl   = "curl " ascii nocase
        $wget   = "wget " ascii nocase
        $fetch  = "/usr/bin/curl" ascii nocase
    condition:
        $shell and 1 of ($curl, $wget, $fetch)
}

rule osascript_keychain_theft
{
    meta:
        description = "AppleScript accessing macOS Keychain credentials via security CLI"
        severity    = "critical"
        category    = "credential-theft"
        mitre       = "T1555.001"
    strings:
        $sec1 = "security find-generic-password" ascii nocase
        $sec2 = "security find-internet-password" ascii nocase
        $sec3 = "security dump-keychain" ascii nocase
        $sec4 = "security delete-keychain" ascii nocase
        $sec5 = "security export" ascii nocase
    condition:
        any of them
}

rule osascript_browser_credential_theft
{
    meta:
        description = "AppleScript targeting browser credential or cookie stores"
        severity    = "critical"
        category    = "credential-theft"
        mitre       = "T1539"
    strings:
        $cook1 = "Cookies.binarycookies" ascii
        $cook2 = "cookies.sqlite" ascii
        $login = "Login Data" ascii
        $keyc  = "Keychain.db" ascii
        $safe  = "Safe Storage" ascii
        $chp   = "Chrome/Default" ascii
        $ffp   = "Firefox/Profiles" ascii
    condition:
        any of them
}

rule osascript_launchagent_persistence
{
    meta:
        description = "AppleScript creating LaunchAgent or LaunchDaemon for persistence"
        severity    = "high"
        category    = "persistence"
        mitre       = "T1543.001"
    strings:
        $la  = "LaunchAgents" ascii
        $ld  = "LaunchDaemons" ascii
        $xml = "<?xml" ascii
        $pba = "ProgramArguments" ascii
        $ral = "RunAtLoad" ascii
        $wrt = "write" ascii nocase
        $cp  = "/bin/cp" ascii
        $mv  = "/bin/mv" ascii
    condition:
        1 of ($la, $ld) and (1 of ($xml, $pba, $ral) or 1 of ($wrt, $cp, $mv))
}

rule osascript_login_item_persistence
{
    meta:
        description = "AppleScript adding login items for persistence"
        severity    = "high"
        category    = "persistence"
        mitre       = "T1547.015"
    strings:
        $li1 = "login item" ascii nocase
        $li2 = "make new login item" ascii nocase
        $li3 = "Startup Items" ascii nocase
    condition:
        any of them
}

rule osascript_keystroke_injection
{
    meta:
        description = "AppleScript injecting keystrokes via System Events (UI scripting)"
        severity    = "high"
        category    = "execution"
        mitre       = "T1056.001"
    strings:
        $sysev = "System Events" ascii nocase
        $key1  = "keystroke" ascii nocase
        $key2  = "key code" ascii nocase
    condition:
        $sysev and 1 of ($key1, $key2)
}

rule osascript_screen_capture
{
    meta:
        description = "AppleScript performing screen capture or recording"
        severity    = "high"
        category    = "collection"
        mitre       = "T1113"
    strings:
        $sc1 = "screencapture" ascii
        $sc2 = "screen capture" ascii nocase
        $sc3 = "CGDisplayCreateImage" ascii
        $sc4 = "do shell script" ascii nocase
        $sc5 = "/usr/sbin/screencapture" ascii
    condition:
        2 of them
}

rule osascript_browser_js_injection
{
    meta:
        description = "AppleScript injecting JavaScript into browser (Safari/Chrome)"
        severity    = "high"
        category    = "execution"
        mitre       = "T1059.007"
    strings:
        $dojs   = "do JavaScript" ascii nocase
        $safari = "Safari" ascii
        $chrome = "Google Chrome" ascii
        $tab    = "current tab" ascii nocase
        $doc    = "document." ascii
    condition:
        $dojs and 1 of ($safari, $chrome) and 1 of ($tab, $doc)
}

rule osascript_base64_obfuscation
{
    meta:
        description = "AppleScript or JXA using Base64 decoding for obfuscation"
        severity    = "high"
        category    = "defense-evasion"
        mitre       = "T1140"
    strings:
        $shell  = "do shell script" ascii nocase
        $b64d1  = "base64 -D" ascii
        $b64d2  = "base64 --decode" ascii
        $b64d3  = "openssl base64 -d" ascii
        $atob   = "atob(" ascii
    condition:
        ($shell and 1 of ($b64d1, $b64d2, $b64d3)) or $atob
}

rule osascript_cron_persistence
{
    meta:
        description = "AppleScript installing cron job for persistence"
        severity    = "high"
        category    = "persistence"
        mitre       = "T1053.003"
    strings:
        $shell = "do shell script" ascii nocase
        $cron1 = "crontab" ascii
        $cron2 = "/var/at/tabs" ascii
    condition:
        $shell and 1 of ($cron1, $cron2)
}

rule jxa_objc_process_execution
{
    meta:
        description = "JXA using Objective-C bridge to execute processes via NSTask"
        severity    = "high"
        category    = "execution"
        mitre       = "T1059.007"
    strings:
        $import = "ObjC.import" ascii
        $task1  = "$.NSTask" ascii
        $task2  = "NSTask.alloc" ascii
        $pipe   = "$.NSPipe" ascii
        $launch = ".launch()" ascii
    condition:
        $import and 1 of ($task1, $task2) and 1 of ($pipe, $launch)
}

rule jxa_objc_network_operations
{
    meta:
        description = "JXA performing network operations via Objective-C bridge"
        severity    = "high"
        category    = "command-and-control"
        mitre       = "T1071"
    strings:
        $import  = "ObjC.import" ascii
        $url1    = "$.NSURL" ascii
        $sess1   = "$.NSURLSession" ascii
        $conn1   = "$.NSURLConnection" ascii
        $req1    = "$.NSURLRequest" ascii
        $dl1     = "$.NSURLDownload" ascii
        $data    = "$.NSData" ascii
        $fetch   = "dataWithContentsOfURL" ascii
    condition:
        $import and 2 of ($url1, $sess1, $conn1, $req1, $dl1, $data, $fetch)
}

rule jxa_eval_dynamic_execution
{
    meta:
        description = "JXA using eval() or Function() for dynamic code execution"
        severity    = "high"
        category    = "defense-evasion"
        mitre       = "T1059.007"
    strings:
        $eval1 = /eval\s*\(/ ascii
        $func1 = /Function\s*\(/ ascii
        $objc  = "ObjC" ascii
        $app   = "Application(" ascii
    condition:
        1 of ($eval1, $func1) and 1 of ($objc, $app)
}

rule osascript_atomic_stealer_indicators
{
    meta:
        description = "Indicators associated with Atomic Stealer / AMOS macOS infostealer"
        severity    = "critical"
        category    = "malware"
        mitre       = "T1555.001"
    strings:
        $dialog = "display dialog" ascii nocase
        $hidden = "hidden answer" ascii nocase
        $kc1    = "find-generic-password" ascii
        $kc2    = "dump-keychain" ascii
        $brw1   = "Cookies.binarycookies" ascii
        $brw2   = "Login Data" ascii
        $brw3   = "Chrome" ascii
        $zip    = "zip " ascii
        $curl   = "curl " ascii
        $tmp    = "/tmp/" ascii
    condition:
        $dialog and $hidden and 2 of ($kc1, $kc2, $brw1, $brw2, $brw3) and 1 of ($zip, $curl, $tmp)
}

rule osascript_multi_technique_attack
{
    meta:
        description = "AppleScript combining credential theft, execution, and persistence — likely malware"
        severity    = "critical"
        category    = "malware"
        mitre       = "T1059.002"
    strings:
        $shell   = "do shell script" ascii nocase
        $dialog  = "display dialog" ascii nocase
        $admin   = "administrator privileges" ascii nocase
        $persist1 = "LaunchAgent" ascii
        $persist2 = "login item" ascii nocase
        $persist3 = "crontab" ascii
        $cred1   = "security find" ascii nocase
        $cred2   = "hidden answer" ascii nocase
        $dl1     = "curl " ascii
        $dl2     = "wget " ascii
    condition:
        $shell and 1 of ($dialog, $admin) and 1 of ($persist1, $persist2, $persist3) and (1 of ($cred1, $cred2) or 1 of ($dl1, $dl2))
}
