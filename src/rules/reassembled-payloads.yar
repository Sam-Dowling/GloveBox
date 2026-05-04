rule Reassembled_IEX_Invocation
{
    meta:
        description = "PowerShell Invoke-Expression paired with a download primitive in a reassembled script — parallel-obfuscation droppers whose iex line and URL atom were split across multiple encoded spans"
        severity    = "high"
        category    = "execution"
        mitre       = "T1059.001"
        applies_to  = "decoded-payload"

    strings:
        $iex_short     = /\biex\b/ nocase
        $iex_long      = "Invoke-Expression" ascii wide nocase
        $iex_alias     = "IEX " ascii wide nocase

        $dl_string     = "DownloadString" ascii wide nocase
        $dl_file       = "DownloadFile" ascii wide nocase
        $dl_data       = "DownloadData" ascii wide nocase
        $net_webclient = "Net.WebClient" ascii wide nocase
        $new_object    = "New-Object" ascii wide nocase
        $invoke_wr     = "Invoke-WebRequest" ascii wide nocase
        $invoke_restm  = "Invoke-RestMethod" ascii wide nocase
        $frombase64    = "FromBase64String" ascii wide nocase
        $bitstransfer  = "Start-BitsTransfer" ascii wide nocase

        $url_http      = /https?:\/\/[A-Za-z0-9.\-]{3,}/

    condition:
        (any of ($iex_short, $iex_long, $iex_alias))
        and (any of ($dl_string, $dl_file, $dl_data, $net_webclient, $new_object, $invoke_wr, $invoke_restm, $frombase64, $bitstransfer))
        and $url_http
}

rule Reassembled_DownloadExec_Chain
{
    meta:
        description = "Classic download-and-execute chain observable only after reassembling parallel obfuscation spans — a download primitive plus an execution primitive plus a URL in one stitched buffer"
        severity    = "critical"
        category    = "execution"
        mitre       = "T1105"
        applies_to  = "decoded-payload"

    strings:
        $dl_ps_webclient = "Net.WebClient" ascii wide nocase
        $dl_ps_dlstring  = "DownloadString" ascii wide nocase
        $dl_ps_dlfile    = "DownloadFile" ascii wide nocase
        $dl_ps_iwr       = "Invoke-WebRequest" ascii wide nocase
        $dl_ps_irm       = "Invoke-RestMethod" ascii wide nocase
        $dl_cmd_curl     = /\bcurl(?:\.exe)?\b/ nocase
        $dl_cmd_wget     = /\bwget(?:\.exe)?\b/ nocase
        $dl_cmd_certutil = "certutil" ascii wide nocase
        $dl_cmd_bitsadmin = "bitsadmin" ascii wide nocase

        $exec_iex        = /\biex\b/ nocase
        $exec_invoke_exp = "Invoke-Expression" ascii wide nocase
        $exec_start_proc = "Start-Process" ascii wide nocase
        $exec_cmd_exe    = /\bcmd(?:\.exe)?\s+\/c\b/ nocase
        $exec_powershell = /\bpowershell(?:\.exe)?\b/ nocase
        $exec_mshta      = "mshta" ascii wide nocase
        $exec_rundll32   = "rundll32" ascii wide nocase
        $exec_regsvr32   = "regsvr32" ascii wide nocase
        $exec_wmic       = "wmic" ascii wide nocase
        $exec_shell_call = "ShellExecute" ascii wide nocase
        $exec_dev_tcp    = "/dev/tcp/" nocase
        $exec_bash_dash_c = /\bbash\s+-c\b/ nocase
        $exec_sh_dash_c  = /\bsh\s+-c\b/ nocase
        $exec_system     = /\bsystem\s*\(/ nocase
        $exec_popen      = /\bpopen\s*\(/ nocase
        $exec_subprocess = "subprocess" ascii wide nocase
        $exec_os_system  = "os.system" ascii wide nocase

        $url             = /https?:\/\/[A-Za-z0-9.\-]{3,}/

    condition:
        (any of ($dl_ps_webclient, $dl_ps_dlstring, $dl_ps_dlfile, $dl_ps_iwr, $dl_ps_irm, $dl_cmd_curl, $dl_cmd_wget, $dl_cmd_certutil, $dl_cmd_bitsadmin))
        and (any of ($exec_iex, $exec_invoke_exp, $exec_start_proc, $exec_cmd_exe, $exec_powershell, $exec_mshta, $exec_rundll32, $exec_regsvr32, $exec_wmic, $exec_shell_call, $exec_dev_tcp, $exec_bash_dash_c, $exec_sh_dash_c, $exec_system, $exec_popen, $exec_subprocess, $exec_os_system))
        and $url
}

rule Reassembled_Reverse_Shell_Indicator
{
    meta:
        description = "Reverse-shell primitive observed in a reassembled script body — shell redirection to a TCP socket or interactive shell bootstrap across /dev/tcp, netcat, or a language-native socket API"
        severity    = "critical"
        category    = "c2"
        mitre       = "T1071.001"
        applies_to  = "decoded-payload"

    strings:
        $dev_tcp        = "/dev/tcp/" nocase
        $dev_udp        = "/dev/udp/" nocase
        $bash_i         = /bash\s+-i\b/ nocase
        $nc_e           = /\bnc(?:at)?\s+(?:[^\n]{0,40})-e\b/ nocase
        $ncat_exec      = /\bncat\s+(?:[^\n]{0,40})--exec\b/ nocase
        $python_pty     = "pty.spawn" ascii nocase
        $python_socket  = "socket.socket" ascii nocase
        $php_fsockopen  = "fsockopen" ascii nocase
        $perl_socket    = "IO::Socket::INET" ascii nocase
        $ps_tcpclient   = "TcpClient" ascii wide nocase

    condition:
        any of them
}

rule Reassembled_Staged_PowerShell_Loader
{
    meta:
        description = "Reassembled PowerShell script that reconstructs and executes encoded bytes — FromBase64String or [System.Reflection.Assembly]::Load paired with iex/invoke"
        severity    = "high"
        category    = "execution"
        mitre       = "T1027"
        applies_to  = "decoded-payload"

    strings:
        $base64_decode  = "FromBase64String" ascii wide nocase
        $convert_bytes  = "Convert]::FromBase64String" ascii wide nocase
        $assembly_load  = "Assembly]::Load" ascii wide nocase
        $scriptblock    = "scriptblock]::Create" ascii wide nocase
        $reflection     = "System.Reflection.Assembly" ascii wide nocase
        $decompress_gz  = "System.IO.Compression.GZipStream" ascii wide nocase
        $decompress_defl = "System.IO.Compression.DeflateStream" ascii wide nocase

        $exec_iex       = /\biex\b/ nocase
        $exec_invoke    = "Invoke-Expression" ascii wide nocase
        $exec_invoke2   = "Invoke-Command" ascii wide nocase
        $entrypoint_invoke = ".Invoke(" ascii wide nocase

    condition:
        (any of ($base64_decode, $convert_bytes, $assembly_load, $scriptblock, $reflection, $decompress_gz, $decompress_defl))
        and (any of ($exec_iex, $exec_invoke, $exec_invoke2, $entrypoint_invoke))
}
