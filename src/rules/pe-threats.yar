rule PE_UPX_Packed {
    meta:
        description = "UPX packed executable: UPX0 + UPX1 section names indicate genuine UPX layout (lone UPX! string occurs randomly in any large binary)"
        severity = "medium"
        category = "packer"
        mitre       = "T1027.002"
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
    condition:
        uint16(0) == 0x5A4D and $upx0 and $upx1
}

rule PE_Themida_Packed {
    meta:
        description = "Themida/WinLicense protected executable"
        severity = "high"
        category = "packer"
        mitre       = "T1027.002"
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
        severity = "high"
        category = "packer"
        mitre       = "T1027.002"
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
        severity = "medium"
        category = "packer"
        mitre       = "T1027.002"
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
        severity = "medium"
        category = "packer"
        mitre       = "T1027.002"
    strings:
        $s1 = ".MPRESS1" ascii
        $s2 = ".MPRESS2" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule PE_Enigma_Packed {
    meta:
        description = "Enigma Protector packed executable"
        severity = "high"
        category = "packer"
        mitre       = "T1027.002"
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
        severity = "medium"
        category = "packer"
        mitre       = "T1027.002"
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
        severity = "high"
        category = "suspicious_api"
        mitre       = "T1055"
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
        severity = "critical"
        category = "suspicious_api"
        mitre       = "T1055.012"
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
        description = "PE uses anti-debug API quorum that includes at least one strong signal (CheckRemoteDebuggerPresent or NtQueryInformationProcess) plus another debug-detection probe — IsDebuggerPresent + OutputDebugStringA alone are normal Win32 noise"
        severity = "medium"
        category = "evasion"
        mitre       = "T1497.001"
    strings:
        $dbg1 = "IsDebuggerPresent" ascii
        $dbg2 = "CheckRemoteDebuggerPresent" ascii
        $dbg3 = "NtQueryInformationProcess" ascii
        $dbg4 = "OutputDebugStringA" ascii
    condition:
        uint16(0) == 0x5A4D and ($dbg2 or $dbg3) and 2 of them
}

rule PE_Credential_Theft_APIs {
    meta:
        description = "PE imports credential theft APIs"
        severity = "critical"
        category = "suspicious_api"
        mitre       = "T1003"
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
        severity = "critical"
        category = "suspicious_api"
        mitre       = "T1486"
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
        description = "PE has download/C2 capability via URLDownloadToFile (always-suspicious) or 2+ HTTP transport APIs in the same image — bare InternetOpenUrl alone is too common in legitimate signed binaries"
        severity = "high"
        category = "suspicious_api"
        mitre       = "T1105"
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
        uint16(0) == 0x5A4D and (any of ($dl*) or 2 of ($http1, $http2, $inet1, $inet2, $winhttp))
}

rule PE_Dynamic_API_Resolution {
    meta:
        description = "PE uses dynamic API resolution (LdrLoadDll / LdrGetProcedureAddress or multiple LoadLibrary variants alongside GetProcAddress)"
        severity = "medium"
        category = "evasion"
        mitre       = "T1027.007"
    strings:
        $gpa = "GetProcAddress" ascii
        $lla = "LoadLibraryA" ascii
        $llw = "LoadLibraryW" ascii
        $ldr = "LdrLoadDll" ascii
        $ldr2 = "LdrGetProcedureAddress" ascii
    condition:
        uint16(0) == 0x5A4D and
        ($ldr or $ldr2 or ($gpa and $lla and $llw))
}

rule PE_Service_Persistence {
    meta:
        description = "PE creates Windows services with matched A or W variants of CreateService + OpenSCManager — most legitimate service-control code uses only one ANSI/Wide flavour, persistence droppers tend to ship full"
        severity = "high"
        category = "suspicious_api"
        mitre       = "T1543.003"
    strings:
        $cs1 = "CreateServiceA" ascii
        $cs2 = "CreateServiceW" ascii
        $osc1 = "OpenSCManagerA" ascii
        $osc2 = "OpenSCManagerW" ascii
    condition:
        uint16(0) == 0x5A4D and (($cs1 and $osc1) or ($cs2 and $osc2))
}

rule PE_Registry_Persistence {
    meta:
        description = "PE writes to common persistence registry keys"
        severity = "medium"
        category = "persistence"
        mitre       = "T1547.001"
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
        severity = "medium"
        category = "anomaly"
        mitre       = "T1027.002"
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
        severity = "info"
        category = "info"
        mitre       = ""
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
        severity = "high"
        category = "execution"
        mitre       = "T1059"
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
        severity = "medium"
        category = "packer"
        mitre       = "T1027.002"
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
        severity = "info"
        category = "info"
        mitre       = ""
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
        severity = "high"
        category = "defense-evasion"
        mitre       = "T1027.009"
    strings:
        $mz = "MZ" ascii
        $pe = "PE\x00\x00" ascii
    condition:
        uint16(0) == 0x5A4D and #mz > 1 and #pe > 1
}

rule PE_Suspicious_Strings_CnC {
    meta:
        description = "PE contains strings suggesting C2 communication"
        severity = "high"
        category = "command-and-control"
        mitre       = "T1071"
    strings:
        $s1 = "cmd.exe /c" ascii wide nocase
        $s2 = "powershell" ascii wide nocase
        $s3 = "/c whoami" ascii wide nocase
        $s4 = "User-Agent:" ascii wide
        $s5 = "POST /" ascii wide
        $s6 = "GET /" ascii wide
        $s7 = "Mozilla/5.0" ascii wide
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule PE_Cobalt_Strike_Indicators {
    meta:
        description = "PE shows indicators of Cobalt Strike beacon"
        severity = "critical"
        category = "malware"
        mitre       = "T1071.001"
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
        severity = "critical"
        category = "malware"
        mitre       = "T1003.001"
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
        severity = "critical"
        category = "malware"
        mitre       = "T1059"
    strings:
        $msf1 = "metsrv" ascii wide
        $msf2 = "meterpreter" ascii wide nocase
        $msf3 = "Meterpreter" ascii wide
        $msf4 = "reverse_tcp" ascii wide
        $msf5 = "reverse_http" ascii wide
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule PE_XLL_Excel_AddIn {
    meta:
        description = "Excel XLL add-in (DLL that auto-loads into Excel on open)"
        severity = "high"
        category = "execution"
        mitre       = "T1137.006"
    strings:
        $x1 = "xlAutoOpen" ascii
        $x2 = "xlAutoClose" ascii
        $x3 = "xlAutoAdd" ascii
        $x4 = "xlAutoRemove" ascii
        $x5 = "xlAutoRegister" ascii
        $x6 = "xlAutoFree" ascii
        $x7 = "xlAddInManagerInfo" ascii
    condition:
        uint16(0) == 0x5A4D and $x1 and 1 of ($x2, $x3, $x4, $x5, $x6, $x7)
}

rule PE_XLL_ExcelDNA_Managed {
    meta:
        description = "Excel-DNA managed-code XLL (.NET-authored Excel add-in)"
        severity = "high"
        category = "execution"
        mitre       = "T1137.006"
    strings:
        $x1 = "xlAutoOpen" ascii
        $dna1 = "ExcelDna" ascii wide
        $dna2 = "EXCELDNA" ascii wide
        $dna3 = "DNA_LIBRARY" ascii wide
        $dna4 = "ExcelDna.Integration" ascii wide
        $dna5 = "__MAIN__" ascii
    condition:
        uint16(0) == 0x5A4D and $x1 and 1 of ($dna*)
}

rule PE_Compiled_AutoHotkey {
    meta:
        description = "Compiled AutoHotkey script (common in commodity malware droppers)"
        severity = "high"
        category = "execution"
        mitre       = "T1059"
    strings:
        $ahk1 = ">AUTOHOTKEY SCRIPT<" ascii wide
        $ahk2 = ">AHK WITH ICON<" ascii wide
        $ahk3 = "AutoHotkey" ascii wide
        $ahk4 = "#NoTrayIcon" ascii wide
        $ahk5 = "#SingleInstance" ascii wide
        $ahk6 = "AutoHotkey.exe" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        ($ahk1 or $ahk2 or ($ahk3 and 1 of ($ahk4, $ahk5, $ahk6)))
}

rule PE_Go_Binary {
    meta:
        description = "Go-compiled PE binary (static, large, commonly abused by malware families)"
        severity = "info"
        category = "info"
        mitre       = ""
    strings:
        $g1 = "Go build ID:" ascii
        $g2 = "go.buildinfo" ascii
        $g3 = "runtime.goexit" ascii
        $g4 = "runtime.main" ascii
        $g5 = "\xff Go buildinf:" ascii
        $g6 = "golang.org" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule PE_Installer_InnoSetup {
    meta:
        description = "Inno Setup installer (bundles scripts and payloads; commonly abused)"
        severity = "info"
        category = "info"
        mitre       = ""
    strings:
        $i1 = "Inno Setup" ascii wide
        $i2 = "InnoSetupLdr" ascii
        $i3 = "Inno Setup Setup Data" ascii
        $i4 = "JR.Inno.Setup" ascii wide
    condition:
        uint16(0) == 0x5A4D and any of them
}
