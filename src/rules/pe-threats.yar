// ════════════════════════════════════════════════════════════════
// PE / Executable threats — packer detection, suspicious patterns,
// known malware indicators, and anomaly detection for PE files
// ════════════════════════════════════════════════════════════════

rule PE_UPX_Packed {
    meta:
        description = "UPX packed executable"
        category = "packer"
        mitre       = "T1027.002"
        severity = "medium"
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upx2 = "UPX!" ascii
        $upx3 = "UPX2" ascii
    condition:
        uint16(0) == 0x5A4D and ($upx0 or $upx1 or $upx2 or $upx3)
}

rule PE_Themida_Packed {
    meta:
        description = "Themida/WinLicense protected executable"
        category = "packer"
        mitre       = "T1027.002"
        severity = "high"
    strings:
        $s1 = ".themida" ascii
        $s2 = ".Themida" ascii
        $s3 = "WinLicen" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule PE_VMProtect_Packed {
    meta:
        description = "VMProtect packed executable"
        category = "packer"
        mitre       = "T1027.002"
        severity = "high"
    strings:
        $s1 = ".vmp0" ascii
        $s2 = ".vmp1" ascii
        $s3 = ".vmp2" ascii
        $s4 = "VMProtect" ascii wide
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule PE_ASPack_Packed {
    meta:
        description = "ASPack packed executable"
        category = "packer"
        mitre       = "T1027.002"
        severity = "medium"
    strings:
        $s1 = ".aspack" ascii
        $s2 = ".adata" ascii
        $s3 = "ASPack" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule PE_MPRESS_Packed {
    meta:
        description = "MPRESS packed executable"
        category = "packer"
        mitre       = "T1027.002"
        severity = "medium"
    strings:
        $s1 = ".MPRESS1" ascii
        $s2 = ".MPRESS2" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule PE_Enigma_Packed {
    meta:
        description = "Enigma Protector packed executable"
        category = "packer"
        mitre       = "T1027.002"
        severity = "high"
    strings:
        $s1 = ".enigma1" ascii
        $s2 = ".enigma2" ascii
        $s3 = "Enigma protector" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule PE_PECompact_Packed {
    meta:
        description = "PECompact packed executable"
        category = "packer"
        mitre       = "T1027.002"
        severity = "medium"
    strings:
        $s1 = "PEC2" ascii
        $s2 = ".pec2" ascii
        $s3 = "PECompact2" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule PE_Process_Injection_APIs {
    meta:
        description = "PE imports process injection API combination"
        category = "suspicious_api"
        mitre       = "T1055"
        severity = "high"
    strings:
        $alloc = "VirtualAllocEx" ascii
        $write = "WriteProcessMemory" ascii
        $thread = "CreateRemoteThread" ascii
        $hollow = "NtUnmapViewOfSection" ascii
        $ctx = "SetThreadContext" ascii
    condition:
        uint16(0) == 0x5A4D and (($alloc and $write) or ($alloc and $thread) or $hollow or ($ctx and $thread))
}

rule PE_Process_Hollowing {
    meta:
        description = "PE shows signs of process hollowing technique"
        category = "suspicious_api"
        mitre       = "T1055.012"
        severity = "critical"
    strings:
        $create = "CreateProcessA" ascii
        $createw = "CreateProcessW" ascii
        $unmap = "NtUnmapViewOfSection" ascii
        $write = "WriteProcessMemory" ascii
        $ctx = "SetThreadContext" ascii
        $resume = "ResumeThread" ascii
    condition:
        uint16(0) == 0x5A4D and ($create or $createw) and $unmap and ($write or $ctx) and $resume
}

rule PE_Anti_Debug_Techniques {
    meta:
        description = "PE uses multiple anti-debugging techniques"
        category = "evasion"
        mitre       = "T1497.001"
        severity = "medium"
    strings:
        $dbg1 = "IsDebuggerPresent" ascii
        $dbg2 = "CheckRemoteDebuggerPresent" ascii
        $dbg3 = "NtQueryInformationProcess" ascii
        $dbg4 = "OutputDebugStringA" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule PE_Credential_Theft_APIs {
    meta:
        description = "PE imports credential theft APIs"
        category = "suspicious_api"
        mitre       = "T1003"
        severity = "critical"
    strings:
        $cred1 = "CredEnumerate" ascii
        $cred2 = "LsaRetrievePrivateData" ascii
        $cred3 = "SamConnect" ascii
        $cred4 = "CryptUnprotectData" ascii
        $cred5 = "CredRead" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule PE_Ransomware_APIs {
    meta:
        description = "PE imports encryption APIs combined with file operations (ransomware indicator)"
        category = "suspicious_api"
        mitre       = "T1486"
        severity = "critical"
    strings:
        $enc1 = "CryptEncrypt" ascii
        $enc2 = "BCryptEncrypt" ascii
        $enc3 = "CryptGenKey" ascii
        $file1 = "FindFirstFileA" ascii
        $file1w = "FindFirstFileW" ascii
        $file2 = "FindNextFileA" ascii
        $file2w = "FindNextFileW" ascii
        $del1 = "DeleteFileA" ascii
        $del1w = "DeleteFileW" ascii
    condition:
        uint16(0) == 0x5A4D and ($enc1 or $enc2 or $enc3) and ($file1 or $file1w) and ($file2 or $file2w)
}

rule PE_Download_Capability {
    meta:
        description = "PE has download/C2 capability via URLDownloadToFile or WinHTTP"
        category = "suspicious_api"
        mitre       = "T1105"
        severity = "high"
    strings:
        $dl1 = "URLDownloadToFileA" ascii
        $dl2 = "URLDownloadToFileW" ascii
        $dl3 = "URLDownloadToCacheFile" ascii
        $http1 = "HttpSendRequestA" ascii
        $http2 = "HttpSendRequestW" ascii
        $inet1 = "InternetOpenUrlA" ascii
        $inet2 = "InternetOpenUrlW" ascii
        $winhttp = "WinHttpSendRequest" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule PE_Dynamic_API_Resolution {
    meta:
        description = "PE uses dynamic API resolution (common in malware to hide imports)"
        category = "evasion"
        mitre       = "T1027.007"
        severity = "medium"
    strings:
        $gpa = "GetProcAddress" ascii
        $lla = "LoadLibraryA" ascii
        $llw = "LoadLibraryW" ascii
        $ldr = "LdrLoadDll" ascii
        $ldr2 = "LdrGetProcedureAddress" ascii
    condition:
        uint16(0) == 0x5A4D and $gpa and ($lla or $llw or $ldr or $ldr2)
}

rule PE_Service_Persistence {
    meta:
        description = "PE creates Windows services (persistence mechanism)"
        category = "suspicious_api"
        mitre       = "T1543.003"
        severity = "high"
    strings:
        $cs1 = "CreateServiceA" ascii
        $cs2 = "CreateServiceW" ascii
        $osc1 = "OpenSCManagerA" ascii
        $osc2 = "OpenSCManagerW" ascii
    condition:
        uint16(0) == 0x5A4D and ($cs1 or $cs2) and ($osc1 or $osc2)
}

rule PE_Registry_Persistence {
    meta:
        description = "PE writes to common persistence registry keys"
        category = "suspicious"
        mitre       = "T1547.001"
        severity = "medium"
    strings:
        $reg1 = "RegSetValueExA" ascii
        $reg2 = "RegSetValueExW" ascii
        $run1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $run2 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide nocase
        $run3 = "CurrentVersion\\Explorer\\Shell Folders" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and ($reg1 or $reg2) and any of ($run*)
}

rule PE_Suspicious_Section_Name {
    meta:
        description = "PE has unusual section names indicating modification or packing"
        category = "anomaly"
        mitre       = "T1027.002"
        severity = "medium"
    strings:
        $s1 = ".rmnet" ascii
        $s2 = ".petite" ascii
        $s3 = ".perplex" ascii
        $s4 = ".nsp0" ascii
        $s5 = ".nsp1" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule PE_Dot_NET_Assembly {
    meta:
        description = "PE is a .NET assembly (CLR executable)"
        category = "info"
        mitre       = ""
        severity = "info"
    strings:
        $clr1 = "_CorExeMain" ascii
        $clr2 = "_CorDllMain" ascii
        $clr3 = "mscoree.dll" ascii nocase
        $clr4 = "mscorlib" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule PE_AutoIT_Compiled {
    meta:
        description = "AutoIT compiled executable (common in commodity malware)"
        category = "suspicious"
        mitre       = "T1059"
        severity = "high"
    strings:
        $au3_1 = "AU3!" ascii
        $au3_2 = "AutoIt" ascii wide
        $au3_3 = "AutoIt3" ascii wide
        $au3_4 = "#AutoIt3Wrapper" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule PE_PyInstaller_Packed {
    meta:
        description = "PyInstaller packed Python executable"
        category = "packer"
        mitre       = "T1027.002"
        severity = "medium"
    strings:
        $py1 = "PyInstaller" ascii wide
        $py2 = "pyi_rth_" ascii
        $py3 = "_MEIPASS" ascii wide
        $py4 = "PYZ-00.pyz" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule PE_NSIS_Installer {
    meta:
        description = "NSIS (Nullsoft Scriptable Install System) installer"
        category = "info"
        mitre       = ""
        severity = "info"
    strings:
        $nsis1 = "Nullsoft" ascii wide
        $nsis2 = "NSIS" ascii
        $nsis3 = "NullsoftInst" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule PE_Embedded_PE {
    meta:
        description = "PE file contains another embedded PE file"
        category = "suspicious"
        mitre       = "T1027.009"
        severity = "high"
    strings:
        $mz = "MZ" ascii
        $pe = "PE\x00\x00" ascii
    condition:
        uint16(0) == 0x5A4D and #mz > 1 and #pe > 1
}

rule PE_Suspicious_Strings_CnC {
    meta:
        description = "PE contains strings suggesting C2 communication"
        category = "suspicious"
        mitre       = "T1071"
        severity = "high"
    strings:
        $s1 = "cmd.exe /c" ascii wide nocase
        $s2 = "powershell" ascii wide nocase
        $s3 = "/c whoami" ascii wide nocase
        $s4 = "User-Agent:" ascii wide
        $s5 = "POST /" ascii
        $s6 = "GET /" ascii
        $s7 = "Mozilla/5.0" ascii
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule PE_Cobalt_Strike_Indicators {
    meta:
        description = "PE shows indicators of Cobalt Strike beacon"
        category = "malware"
        mitre       = "T1071.001"
        severity = "critical"
    strings:
        $cs1 = "%02d/%02d/%02d %02d:%02d:%02d" ascii
        $cs2 = "beacon.dll" ascii wide
        $cs3 = "beacon.x64.dll" ascii wide
        $cs4 = "%s (admin)" ascii
        $cs5 = "ReflectiveLoader" ascii
        $cs6 = "%%POSTEX" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule PE_Mimikatz_Indicators {
    meta:
        description = "PE contains Mimikatz-related strings"
        category = "malware"
        mitre       = "T1003.001"
        severity = "critical"
    strings:
        $m1 = "mimikatz" ascii wide nocase
        $m2 = "sekurlsa::" ascii wide
        $m3 = "kerberos::" ascii wide
        $m4 = "gentilkiwi" ascii wide
        $m5 = "wdigest" ascii wide
        $m6 = "lsadump::" ascii wide
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule PE_Metasploit_Payload {
    meta:
        description = "PE shows indicators of Metasploit payload"
        category = "malware"
        mitre       = "T1059"
        severity = "critical"
    strings:
        $msf1 = "metsrv" ascii wide
        $msf2 = "meterpreter" ascii wide nocase
        $msf3 = "Meterpreter" ascii wide
        $msf4 = "reverse_tcp" ascii wide
        $msf5 = "reverse_http" ascii wide
    condition:
        uint16(0) == 0x5A4D and any of them
}
