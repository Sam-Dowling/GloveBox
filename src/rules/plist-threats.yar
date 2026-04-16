/* ──────────────────────────────────────────────────────────────────────
 *  plist-threats.yar — macOS Property List threat detection rules
 *
 *  Targets: .plist (XML and binary formats)
 *  Detects: LaunchAgent/LaunchDaemon persistence, suspicious program
 *  arguments, hidden agents, DYLD injection, environment manipulation,
 *  and other macOS-specific abuse patterns.
 * ────────────────────────────────────────────────────────────────────── */


rule plist_launchagent_shell_execution
{
    meta:
        description = "LaunchAgent/Daemon executes a shell interpreter via ProgramArguments"
        severity    = "critical"
        category    = "persistence"
        mitre       = "T1543.004"
    strings:
        $label   = "Label" ascii nocase
        $prog    = "ProgramArguments" ascii nocase
        $sh1     = "/bin/sh" ascii nocase
        $sh2     = "/bin/bash" ascii nocase
        $sh3     = "/bin/zsh" ascii nocase
    condition:
        $label and $prog and any of ($sh*)
}

rule plist_launchagent_runatload_shell
{
    meta:
        description = "LaunchAgent with RunAtLoad and shell command — persistence on every login"
        severity    = "critical"
        category    = "persistence"
        mitre       = "T1543.004"
    strings:
        $runatload = "RunAtLoad" ascii nocase
        $true_xml  = "<true/>" ascii nocase
        $prog      = "ProgramArguments" ascii nocase
        $sh1       = "/bin/sh" ascii
        $sh2       = "/bin/bash" ascii
        $sh3       = "/bin/zsh" ascii
    condition:
        $runatload and $true_xml and $prog and any of ($sh*)
}

rule plist_hidden_label
{
    meta:
        description = "LaunchAgent/Daemon with dot-prefixed hidden Label"
        severity    = "high"
        category    = "defense-evasion"
        mitre       = "T1564.001"
    strings:
        $key     = "<key>Label</key>" ascii nocase
        $hidden1 = "<string>." ascii
    condition:
        $key and $hidden1
}

rule plist_suspicious_program_path_tmp
{
    meta:
        description = "Plist references program in /tmp or other user-writable staging directory"
        severity    = "high"
        category    = "execution"
        mitre       = "T1074.001"
    strings:
        $prog  = "ProgramArguments" ascii nocase
        $tmp1  = "/tmp/" ascii
        $tmp2  = "/var/tmp/" ascii
        $tmp3  = "/Users/Shared/" ascii
        $tmp4  = "/private/tmp/" ascii
    condition:
        $prog and any of ($tmp*)
}

rule plist_curl_wget_download
{
    meta:
        description = "Plist ProgramArguments uses curl or wget for payload download"
        severity    = "high"
        category    = "command-and-control"
        mitre       = "T1105"
    strings:
        $prog  = "ProgramArguments" ascii nocase
        $dl1   = "/usr/bin/curl" ascii
        $dl2   = "/usr/bin/wget" ascii
        $dl3   = "curl " ascii nocase
        $dl4   = "curl\t" ascii nocase
    condition:
        $prog and any of ($dl*)
}

rule plist_osascript_execution
{
    meta:
        description = "Plist executes osascript (AppleScript/JXA) — potential social engineering or payload execution"
        severity    = "high"
        category    = "execution"
        mitre       = "T1059.002"
    strings:
        $prog  = "ProgramArguments" ascii nocase
        $osa1  = "/usr/bin/osascript" ascii
        $osa2  = "osascript" ascii nocase
    condition:
        $prog and any of ($osa*)
}

rule plist_python_perl_execution
{
    meta:
        description = "Plist uses scripting language interpreter (Python/Perl/Ruby)"
        severity    = "medium"
        category    = "execution"
        mitre       = "T1059.006"
    strings:
        $prog  = "ProgramArguments" ascii nocase
        $py1   = "/usr/bin/python" ascii
        $py2   = "/usr/local/bin/python" ascii
        $pl1   = "/usr/bin/perl" ascii
        $rb1   = "/usr/bin/ruby" ascii
    condition:
        $prog and any of ($py*, $pl*, $rb*)
}

rule plist_environment_variable_manipulation
{
    meta:
        description = "Plist sets EnvironmentVariables — may modify child process execution environment"
        severity    = "medium"
        category    = "defense-evasion"
        mitre       = "T1574.007"
    strings:
        $env = "EnvironmentVariables" ascii nocase
    condition:
        $env
}

rule plist_dyld_insert_libraries
{
    meta:
        description = "DYLD_INSERT_LIBRARIES in plist — dynamic library injection into all child processes"
        severity    = "critical"
        category    = "privilege-escalation"
        mitre       = "T1574.006"
    strings:
        $dyld = "DYLD_INSERT_LIBRARIES" ascii
    condition:
        $dyld
}

rule plist_dyld_environment
{
    meta:
        description = "DYLD environment variable in plist — potential library path hijacking"
        severity    = "high"
        category    = "privilege-escalation"
        mitre       = "T1574.006"
    strings:
        $dyld1 = "DYLD_LIBRARY_PATH" ascii
        $dyld2 = "DYLD_FRAMEWORK_PATH" ascii
        $dyld3 = "DYLD_FALLBACK" ascii
    condition:
        any of them
}

rule plist_keepalive_persistence
{
    meta:
        description = "KeepAlive + RunAtLoad — aggressive persistence that restarts process if killed"
        severity    = "high"
        category    = "persistence"
        mitre       = "T1543.004"
    strings:
        $keep  = "KeepAlive" ascii nocase
        $run   = "RunAtLoad" ascii nocase
        $true  = "<true/>" ascii nocase
    condition:
        $keep and $run and $true
}

rule plist_short_startinterval
{
    meta:
        description = "Short StartInterval in LaunchAgent — may indicate C2 beacon or polling behaviour"
        severity    = "medium"
        category    = "command-and-control"
        mitre       = "T1573"
    strings:
        $key  = "StartInterval" ascii nocase
        $val1 = "<integer>1</integer>" ascii nocase
        $val2 = "<integer>5</integer>" ascii nocase
        $val3 = "<integer>10</integer>" ascii nocase
        $val4 = "<integer>15</integer>" ascii nocase
        $val5 = "<integer>30</integer>" ascii nocase
        $val6 = "<integer>60</integer>" ascii nocase
        $val7 = "<integer>120</integer>" ascii nocase
    condition:
        $key and any of ($val*)
}

rule plist_watchpaths_monitoring
{
    meta:
        description = "WatchPaths configured — triggers execution when monitored paths change"
        severity    = "low"
        category    = "persistence"
        mitre       = "T1543.004"
    strings:
        $watch = "WatchPaths" ascii nocase
    condition:
        $watch
}

rule plist_url_scheme_handler
{
    meta:
        description = "Custom URL scheme handler registration — could intercept protocol handlers"
        severity    = "medium"
        category    = "persistence"
        mitre       = "T1071"
    strings:
        $url_types   = "CFBundleURLTypes" ascii
        $url_schemes = "CFBundleURLSchemes" ascii
    condition:
        $url_types and $url_schemes
}

rule plist_login_item_hidden
{
    meta:
        description = "LSUIElement or LSBackgroundOnly — app runs without dock icon (hidden login item)"
        severity    = "medium"
        category    = "defense-evasion"
        mitre       = "T1564.001"
    strings:
        $ui1 = "LSUIElement" ascii
        $ui2 = "LSBackgroundOnly" ascii
    condition:
        any of them
}

rule plist_base64_encoded_args
{
    meta:
        description = "Base64 reference in ProgramArguments — potential obfuscated payload"
        severity    = "high"
        category    = "defense-evasion"
        mitre       = "T1140"
    strings:
        $prog   = "ProgramArguments" ascii nocase
        $b64_1  = "base64" ascii nocase
        $b64_2  = "-decode" ascii nocase
        $b64_3  = "--decode" ascii nocase
    condition:
        $prog and any of ($b64*)
}

rule plist_netcat_reverse_shell
{
    meta:
        description = "Netcat in ProgramArguments — potential reverse shell"
        severity    = "critical"
        category    = "execution"
        mitre       = "T1059.004"
    strings:
        $prog  = "ProgramArguments" ascii nocase
        $nc1   = "/usr/bin/nc" ascii
        $nc2   = "netcat" ascii nocase
        $nc3   = "ncat" ascii nocase
    condition:
        $prog and any of ($nc*)
}

rule plist_tcc_bypass_indicator
{
    meta:
        description = "TCC privacy framework references — may attempt to access protected resources"
        severity    = "medium"
        category    = "privilege-escalation"
        mitre       = "T1548"
    strings:
        $tcc1 = "kTCCServiceAccessibility" ascii
        $tcc2 = "kTCCServiceScreenCapture" ascii
        $tcc3 = "kTCCServiceMicrophone" ascii
        $tcc4 = "kTCCServiceCamera" ascii
        $tcc5 = "com.apple.security.automation.apple-events" ascii
    condition:
        any of them
}

rule plist_binary_format
{
    meta:
        description = "Binary property list format detected (bplist00)"
        severity    = "info"
        category    = "file-type"
        mitre       = ""
    strings:
        $magic = "bplist00" ascii
    condition:
        $magic at 0
}

rule plist_certificate_manipulation
{
    meta:
        description = "Certificate or authorization database manipulation commands in plist"
        severity    = "high"
        category    = "defense-evasion"
        mitre       = "T1553.004"
    strings:
        $prog  = "ProgramArguments" ascii nocase
        $cert1 = "add-trusted-cert" ascii
        $cert2 = "delete-certificate" ascii
        $cert3 = "authorizationdb" ascii
    condition:
        $prog and any of ($cert*)
}

rule plist_network_config_change
{
    meta:
        description = "Network configuration modification commands in plist"
        severity    = "high"
        category    = "command-and-control"
        mitre       = "T1090"
    strings:
        $prog  = "ProgramArguments" ascii nocase
        $net1  = "networksetup" ascii
        $net2  = "scutil" ascii
        $proxy = "proxy" ascii nocase
        $dns   = "dns" ascii nocase
    condition:
        $prog and any of ($net*) and any of ($proxy, $dns)
}
