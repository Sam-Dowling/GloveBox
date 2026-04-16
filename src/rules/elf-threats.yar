// ════════════════════════════════════════════════════════════════
// ELF / Linux binary threats — packer detection, malware families,
// rootkit indicators, reverse shells, cryptominers, and IoT malware
// ════════════════════════════════════════════════════════════════

rule ELF_UPX_Packed {
    meta:
        description = "UPX packed ELF binary"
        category = "packer"
        mitre       = "T1027.002"
        severity = "medium"
    strings:
        $upx0 = "UPX!" ascii
        $upx1 = "UPX0" ascii
        $upx2 = "UPX1" ascii
        $info = "$Info: This file is packed with the UPX" ascii
    condition:
        uint32(0) == 0x464C457F and any of them
}

rule ELF_Generic_Packer {
    meta:
        description = "Possible packed/encrypted ELF binary (modified section names)"
        category = "packer"
        mitre       = "T1027.002"
        severity = "medium"
    strings:
        $s1 = ".packed" ascii
        $s2 = ".crypted" ascii
        $s3 = ".obfusc" ascii
        $s4 = ".protect" ascii
        $s5 = "MPRESS" ascii
    condition:
        uint32(0) == 0x464C457F and any of them
}

rule ELF_Mirai_Strings {
    meta:
        description = "Mirai botnet variant indicators"
        category = "malware"
        mitre       = "T1583.005"
        severity = "critical"
    strings:
        $s1 = "/proc/self/exe" ascii
        $s2 = "/proc/net/tcp" ascii
        $s3 = "POST /cdn-cgi/" ascii
        $s4 = "/bin/busybox" ascii
        $telnet1 = "telnet" ascii
        $telnet2 = "telnetd" ascii
        $scan1 = "scanner_init" ascii
        $scan2 = "scanner_kill" ascii
        $kill1 = "killer_init" ascii
        $kill2 = "killer_kill" ascii
        $atk1 = "attack_init" ascii
        $atk2 = "attack_parse" ascii
        $cred1 = "admin" ascii
        $cred2 = "root" ascii
        $cred3 = "default" ascii
        $cred4 = "password" ascii
    condition:
        uint32(0) == 0x464C457F and
        (($scan1 and $scan2) or ($kill1 and $kill2) or ($atk1 and $atk2)) and
        2 of ($telnet*, $s*, $cred*)
}

rule ELF_Mirai_Config {
    meta:
        description = "Mirai botnet configuration/CNC patterns"
        category = "malware"
        mitre       = "T1583.005"
        severity = "critical"
    strings:
        $cnc1 = "CNC_ADDR" ascii
        $cnc2 = "cnc_addr" ascii
        $table_init = "table_init" ascii
        $table_lock = "table_lock_val" ascii
        $table_unlock = "table_unlock_val" ascii
        $arch1 = ".arc" ascii
        $arch2 = ".arm" ascii
        $arch3 = ".mips" ascii
        $arch4 = ".x86" ascii
        $arch5 = ".spc" ascii
        $arch6 = ".m68k" ascii
    condition:
        uint32(0) == 0x464C457F and
        ($table_init or ($cnc1 or $cnc2)) and 2 of ($arch*)
}

rule ELF_Cryptominer_XMRig {
    meta:
        description = "XMRig cryptocurrency miner"
        category = "cryptominer"
        mitre       = "T1496"
        severity = "high"
    strings:
        $s1 = "xmrig" ascii nocase
        $s2 = "XMRig" ascii
        $s3 = "stratum+tcp://" ascii
        $s4 = "stratum+ssl://" ascii
        $s5 = "stratum+tls://" ascii
        $s6 = "pool.minexmr.com" ascii
        $s7 = "mine.xmrpool.net" ascii
        $s8 = "randomx" ascii nocase
        $s9 = "cryptonight" ascii nocase
        $s10 = "--coin=" ascii
        $s11 = "--donate-level" ascii
    condition:
        uint32(0) == 0x464C457F and 2 of them
}

rule ELF_Cryptominer_Generic {
    meta:
        description = "Generic cryptocurrency mining indicators"
        category = "cryptominer"
        mitre       = "T1496"
        severity = "high"
    strings:
        $pool1 = "mining.pool" ascii
        $pool2 = "pool.hashvault.pro" ascii
        $pool3 = "nanopool.org" ascii
        $pool4 = "minergate.com" ascii
        $pool5 = "supportxmr.com" ascii
        $proto1 = "stratum://" ascii
        $proto2 = "\"jsonrpc\"" ascii
        $proto3 = "mining.subscribe" ascii
        $proto4 = "mining.authorize" ascii
        $hash1 = "ethash" ascii nocase
        $hash2 = "equihash" ascii nocase
        $hash3 = "kawpow" ascii nocase
    condition:
        uint32(0) == 0x464C457F and 2 of them
}

rule ELF_ESXi_Ransomware {
    meta:
        description = "ESXi/VMware ransomware indicators"
        category = "ransomware"
        mitre       = "T1486"
        severity = "critical"
    strings:
        $esxi1 = "esxcli" ascii
        $esxi2 = "vim-cmd" ascii
        $esxi3 = "/vmfs/volumes" ascii
        $esxi4 = "esxcli vm process kill" ascii
        $vm1 = ".vmdk" ascii
        $vm2 = ".vmx" ascii
        $vm3 = ".vmxf" ascii
        $vm4 = ".vmsd" ascii
        $vm5 = ".vmsn" ascii
        $vm6 = ".vswp" ascii
        $vm7 = ".vmem" ascii
        $enc1 = "encrypt" ascii nocase
        $enc2 = "openssl" ascii
        $enc3 = "ransom" ascii nocase
        $enc4 = ".locked" ascii
        $enc5 = ".encrypted" ascii
        $note1 = "README" ascii
        $note2 = "RECOVER" ascii
        $note3 = "RESTORE" ascii
        $note4 = "bitcoin" ascii nocase
    condition:
        uint32(0) == 0x464C457F and
        1 of ($esxi*) and 2 of ($vm*) and (1 of ($enc*) or 1 of ($note*))
}

rule ELF_Reverse_Shell {
    meta:
        description = "Reverse shell indicators"
        category = "backdoor"
        mitre       = "T1059.004"
        severity = "high"
    strings:
        $sh1 = "/bin/sh" ascii
        $sh2 = "/bin/bash" ascii
        $sh3 = "/bin/dash" ascii
        $net1 = "/dev/tcp/" ascii
        $net2 = "/dev/udp/" ascii
        $net3 = "SOCK_STREAM" ascii
        $cmd1 = "dup2" ascii
        $cmd2 = "execve" ascii
        $cmd3 = "socket" ascii
        $cmd4 = "connect" ascii
        $py1 = "import socket" ascii
        $py2 = "subprocess" ascii
        $perl1 = "IO::Socket" ascii
    condition:
        uint32(0) == 0x464C457F and
        (($cmd3 and $cmd1 and ($cmd2 or 1 of ($sh*))) or
         ($py1 and $py2) or
         ($perl1 and 1 of ($sh*)) or
         1 of ($net1, $net2))
}

rule ELF_LD_PRELOAD_Hijack {
    meta:
        description = "LD_PRELOAD library hijacking / userland rootkit"
        category = "rootkit"
        mitre       = "T1574.006"
        severity = "high"
    strings:
        $s1 = "LD_PRELOAD" ascii
        $s2 = "/etc/ld.so.preload" ascii
        $hook1 = "readdir" ascii
        $hook2 = "readdir64" ascii
        $hook3 = "fopen" ascii
        $hook4 = "fopen64" ascii
        $hook5 = "open" ascii
        $hook6 = "stat" ascii
        $hook7 = "lstat" ascii
        $hook8 = "accept" ascii
        $dlsym = "dlsym" ascii
        $rtld = "RTLD_NEXT" ascii
    condition:
        uint32(0) == 0x464C457F and
        1 of ($s*) and $dlsym and $rtld and 2 of ($hook*)
}

rule ELF_Proc_Hiding {
    meta:
        description = "Process/file hiding via /proc manipulation"
        category = "rootkit"
        mitre       = "T1564.001"
        severity = "high"
    strings:
        $proc1 = "/proc/self/maps" ascii
        $proc2 = "/proc/self/status" ascii
        $proc3 = "/proc/self/fd" ascii
        $proc4 = "/proc/%d" ascii
        $proc5 = "/proc/self/exe" ascii
        $hide1 = "readdir" ascii
        $hide2 = "getdents" ascii
        $hide3 = "getdents64" ascii
        $unlink1 = "unlink" ascii
        $unlink2 = "/proc/self/exe" ascii
    condition:
        uint32(0) == 0x464C457F and
        3 of ($proc*) and (1 of ($hide*) or ($unlink1 and $unlink2))
}

rule ELF_Ptrace_AntiDebug {
    meta:
        description = "Anti-debugging via ptrace"
        category = "evasion"
        mitre       = "T1497.001"
        severity = "medium"
    strings:
        $s1 = "PTRACE_TRACEME" ascii
        $s2 = "ptrace" ascii
        $s3 = "TracerPid" ascii
        $s4 = "/proc/self/status" ascii
    condition:
        uint32(0) == 0x464C457F and
        ($s1 or ($s2 and ($s3 or $s4)))
}

rule ELF_Self_Deletion {
    meta:
        description = "Self-deleting binary (anti-forensics)"
        category = "evasion"
        mitre       = "T1070.004"
        severity = "medium"
    strings:
        $s1 = "/proc/self/exe" ascii
        $s2 = "unlink" ascii
        $s3 = "unlinkat" ascii
        $s4 = "remove" ascii
        $s5 = "shred" ascii
        $argv0 = "argv[0]" ascii
    condition:
        uint32(0) == 0x464C457F and
        $s1 and 1 of ($s2, $s3, $s4, $s5)
}

rule ELF_Kernel_Module_Rootkit {
    meta:
        description = "Kernel module / LKM rootkit indicators"
        category = "rootkit"
        mitre       = "T1547.006"
        severity = "critical"
    strings:
        $s1 = "init_module" ascii
        $s2 = "finit_module" ascii
        $s3 = "delete_module" ascii
        $s4 = "insmod" ascii
        $s5 = "modprobe" ascii
        $hook1 = "sys_call_table" ascii
        $hook2 = "kallsyms_lookup_name" ascii
        $hook3 = "register_kprobe" ascii
        $hide1 = "list_del" ascii
        $hide2 = "__this_module" ascii
    condition:
        uint32(0) == 0x464C457F and
        1 of ($s*) and (1 of ($hook*) or 1 of ($hide*))
}

rule ELF_Credential_Access {
    meta:
        description = "Credential file access patterns"
        category = "credential_theft"
        mitre       = "T1552.001"
        severity = "high"
    strings:
        $s1 = "/etc/passwd" ascii
        $s2 = "/etc/shadow" ascii
        $s3 = "/etc/sudoers" ascii
        $s4 = ".ssh/id_rsa" ascii
        $s5 = ".ssh/authorized_keys" ascii
        $s6 = ".bash_history" ascii
        $s7 = ".gnupg" ascii
        $s8 = "/tmp/krb5cc_" ascii
        $s9 = "/.aws/credentials" ascii
        $s10 = "/.docker/config.json" ascii
    condition:
        uint32(0) == 0x464C457F and 3 of them
}

rule ELF_Persistence_Mechanism {
    meta:
        description = "Linux persistence mechanism indicators"
        category = "persistence"
        mitre       = "T1053.003"
        severity = "high"
    strings:
        $cron1 = "/etc/crontab" ascii
        $cron2 = "/var/spool/cron" ascii
        $cron3 = "crontab" ascii
        $svc1 = "/etc/systemd/system" ascii
        $svc2 = "/lib/systemd/system" ascii
        $svc3 = "systemctl enable" ascii
        $svc4 = "systemctl start" ascii
        $rc1 = "/etc/rc.local" ascii
        $rc2 = "/etc/init.d/" ascii
        $rc3 = "update-rc.d" ascii
        $prof1 = ".bashrc" ascii
        $prof2 = ".profile" ascii
        $prof3 = "/etc/profile.d/" ascii
        $auth1 = "authorized_keys" ascii
    condition:
        uint32(0) == 0x464C457F and 3 of them
}

rule ELF_Container_Escape {
    meta:
        description = "Container escape / breakout indicators"
        category = "container_escape"
        mitre       = "T1611"
        severity = "critical"
    strings:
        $s1 = "/.dockerenv" ascii
        $s2 = "/proc/1/cgroup" ascii
        $s3 = "docker" ascii
        $s4 = "kubelet" ascii
        $s5 = "kubernetes" ascii
        $esc1 = "nsenter" ascii
        $esc2 = "mount" ascii
        $esc3 = "chroot" ascii
        $esc4 = "/proc/sysrq-trigger" ascii
        $esc5 = "CAP_SYS_ADMIN" ascii
        $esc6 = "release_agent" ascii
    condition:
        uint32(0) == 0x464C457F and
        2 of ($s*) and 2 of ($esc*)
}

rule ELF_BPF_Rootkit {
    meta:
        description = "eBPF-based rootkit indicators"
        category = "rootkit"
        mitre       = "T1014"
        severity = "high"
    strings:
        $s1 = "bpf_probe_read" ascii
        $s2 = "bpf_map_update_elem" ascii
        $s3 = "bpf_override_return" ascii
        $s4 = "BPF_PROG_LOAD" ascii
        $s5 = "BPF_MAP_CREATE" ascii
        $s6 = "tracepoint" ascii
        $s7 = "kprobe" ascii
    condition:
        uint32(0) == 0x464C457F and 3 of them
}
