rule PE_Shellcode_Loader_Pattern
{
    meta:
        description = "PE imports memory manipulation APIs commonly used for shellcode loading"
        severity    = "high"
        category    = "execution"
        mitre       = "T1055"

    strings:
        $alloc    = "VirtualAlloc" nocase
        $protect  = "VirtualProtect" nocase
        $move     = "RtlMoveMemory" nocase
        $load     = "LoadLibraryA" nocase

    condition:
        uint16(0) == 0x5A4D and 3 of ($alloc, $protect, $move, $load)
}

rule PE_Download_Execute
{
    meta:
        description = "PE binary downloads remote content and executes it"
        severity    = "critical"
        category    = "execution"
        mitre       = "T1105"

    strings:
        $dl1     = "InternetConnectA" nocase
        $dl2     = "URLDownloadToFile" nocase
        $dl3     = "URLDownloadToFileA" nocase
        $dl4     = "InternetOpenA" nocase
        $dl5     = "InternetReadFile" nocase
        $exec1   = "WinExec" nocase
        $exec2   = "CreateProcessA" nocase
        $exec3   = "CreateProcessW" nocase
        $exec4   = "ShellExecuteA" nocase

    condition:
        uint16(0) == 0x5A4D and any of ($dl1, $dl2, $dl3, $dl4, $dl5) and any of ($exec1, $exec2, $exec3, $exec4)
}

rule PE_Suspicious_Imports_Cluster
{
    meta:
        description = "PE binary imports 3+ suspicious APIs spanning injection, download, and execution categories"
        severity    = "high"
        category    = "execution"
        mitre       = "T1055"

    strings:
        $a    = "VirtualAllocEx" nocase
        $b    = "WriteProcessMemory" nocase
        $c    = "CreateRemoteThread" nocase
        $d    = "InternetConnectA" nocase
        $e    = "URLDownloadToFile" nocase
        $f    = "WinExec" nocase
        $g    = "CreateProcessA" nocase
        $h    = "NtUnmapViewOfSection" nocase
        $i    = "OpenProcess" nocase
        $j    = "NtWriteVirtualMemory" nocase
        $k    = "QueueUserAPC" nocase

    condition:
        uint16(0) == 0x5A4D and 3 of ($a, $b, $c, $d, $e, $f, $g, $h, $i, $j, $k)
}
