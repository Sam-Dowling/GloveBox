// ════════════════════════════════════════════════════════════════
// Mach-O threat detection rules
// Targets: macOS malware, infostealers, reverse shells, persistence,
//          privilege escalation, anti-analysis, packed binaries
// ════════════════════════════════════════════════════════════════

rule MachO_Atomic_Stealer_Keychain {
  meta:
    description = "Atomic Stealer / AMOS infostealer — Keychain credential theft patterns"
    category    = "malware"
    severity    = "critical"
  strings:
    $magic1 = { CF FA ED FE }
    $magic2 = { CE FA ED FE }
    $magic3 = { CA FE BA BE }
    $kc1 = "SecKeychainFindGenericPassword" ascii
    $kc2 = "SecKeychainFindInternetPassword" ascii
    $kc3 = "SecItemCopyMatching" ascii
    $kc4 = "SecKeychainItemCopyContent" ascii
    $kc5 = "login.keychain" ascii
    $browser1 = "Login Data" ascii
    $browser2 = "Chrome" ascii
    $browser3 = "Firefox" ascii
    $browser4 = "Cookies" ascii
  condition:
    ($magic1 at 0 or $magic2 at 0 or $magic3 at 0) and
    (2 of ($kc*)) and (1 of ($browser*))
}

rule MachO_AMOS_Credential_Prompt {
  meta:
    description = "AMOS-style credential harvesting via osascript dialog"
    category    = "malware"
    severity    = "critical"
  strings:
    $magic1 = { CF FA ED FE }
    $magic2 = { CE FA ED FE }
    $magic3 = { CA FE BA BE }
    $osa1 = "osascript" ascii
    $osa2 = "/usr/bin/osascript" ascii
    $dialog1 = "display dialog" ascii
    $dialog2 = "hidden answer" ascii
    $dialog3 = "password" ascii nocase
    $dialog4 = "with icon" ascii
  condition:
    ($magic1 at 0 or $magic2 at 0 or $magic3 at 0) and
    (1 of ($osa*)) and (2 of ($dialog*))
}

rule MachO_Reverse_Shell {
  meta:
    description = "Reverse shell pattern — socket + dup2 + exec combination"
    category    = "malware"
    severity    = "critical"
  strings:
    $magic1 = { CF FA ED FE }
    $magic2 = { CE FA ED FE }
    $magic3 = { CA FE BA BE }
    $s1 = "_socket" ascii
    $s2 = "_connect" ascii
    $s3 = "_dup2" ascii
    $s4 = "_execve" ascii
    $s5 = "_execvp" ascii
    $s6 = "/bin/sh" ascii
    $s7 = "/bin/bash" ascii
    $s8 = "/bin/zsh" ascii
  condition:
    ($magic1 at 0 or $magic2 at 0 or $magic3 at 0) and
    $s1 and $s3 and (1 of ($s4, $s5)) and (1 of ($s6, $s7, $s8))
}

rule MachO_RAT_Surveillance {
  meta:
    description = "Remote access tool — screen capture and keylogging capabilities"
    category    = "malware"
    severity    = "high"
  strings:
    $magic1 = { CF FA ED FE }
    $magic2 = { CE FA ED FE }
    $magic3 = { CA FE BA BE }
    $sc1 = "CGDisplayCreateImage" ascii
    $sc2 = "CGWindowListCreateImage" ascii
    $sc3 = "CGEventTapCreate" ascii
    $sc4 = "AVCaptureDevice" ascii
    $sc5 = "CGEventGetIntegerValueField" ascii
    $net1 = "_socket" ascii
    $net2 = "_connect" ascii
    $net3 = "_send" ascii
  condition:
    ($magic1 at 0 or $magic2 at 0 or $magic3 at 0) and
    (2 of ($sc*)) and (1 of ($net*))
}

rule MachO_Privilege_Escalation {
  meta:
    description = "Privilege escalation via AuthorizationExecuteWithPrivileges or osascript admin prompt"
    category    = "exploit"
    severity    = "high"
  strings:
    $magic1 = { CF FA ED FE }
    $magic2 = { CE FA ED FE }
    $magic3 = { CA FE BA BE }
    $pe1 = "AuthorizationExecuteWithPrivileges" ascii
    $pe2 = "AuthorizationCreate" ascii
    $pe3 = "with administrator privileges" ascii
    $pe4 = "do shell script" ascii
    $pe5 = "sudo" ascii
  condition:
    ($magic1 at 0 or $magic2 at 0 or $magic3 at 0) and
    ($pe1 or ($pe2 and $pe1) or ($pe3 and $pe4) or ($pe4 and $pe5))
}

rule MachO_Persistence_LaunchAgent {
  meta:
    description = "Persistence via LaunchAgent/LaunchDaemon plist installation"
    category    = "persistence"
    severity    = "high"
  strings:
    $magic1 = { CF FA ED FE }
    $magic2 = { CE FA ED FE }
    $magic3 = { CA FE BA BE }
    $la1 = "LaunchAgents" ascii
    $la2 = "LaunchDaemons" ascii
    $la3 = "/Library/LaunchAgents" ascii
    $la4 = "/Library/LaunchDaemons" ascii
    $la5 = "~/Library/LaunchAgents" ascii
    $plist1 = "RunAtLoad" ascii
    $plist2 = "KeepAlive" ascii
    $plist3 = "ProgramArguments" ascii
    $plist4 = ".plist" ascii
  condition:
    ($magic1 at 0 or $magic2 at 0 or $magic3 at 0) and
    (1 of ($la*)) and (1 of ($plist*))
}

rule MachO_Persistence_LoginItem {
  meta:
    description = "Persistence via login items API"
    category    = "persistence"
    severity    = "medium"
  strings:
    $magic1 = { CF FA ED FE }
    $magic2 = { CE FA ED FE }
    $magic3 = { CA FE BA BE }
    $li1 = "SMLoginItemSetEnabled" ascii
    $li2 = "LSSharedFileListInsertItemURL" ascii
    $li3 = "LSSharedFileListCreate" ascii
    $li4 = "kLSSharedFileListSessionLoginItems" ascii
    $li5 = "com.apple.loginitems" ascii
  condition:
    ($magic1 at 0 or $magic2 at 0 or $magic3 at 0) and
    (1 of ($li*))
}

rule MachO_Anti_Debug {
  meta:
    description = "Anti-debugging via ptrace PT_DENY_ATTACH or sysctl anti-debug"
    category    = "evasion"
    severity    = "high"
  strings:
    $magic1 = { CF FA ED FE }
    $magic2 = { CE FA ED FE }
    $magic3 = { CA FE BA BE }
    $ad1 = "_ptrace" ascii
    $ad2 = "PT_DENY_ATTACH" ascii
    $ad3 = { 1F 00 00 00 }
    $sc1 = "_sysctl" ascii
    $sc2 = "kern.proc.pid" ascii
    $sc3 = "P_TRACED" ascii
    $sc4 = "_isatty" ascii
  condition:
    ($magic1 at 0 or $magic2 at 0 or $magic3 at 0) and
    (($ad1 and ($ad2 or $ad3)) or ($sc1 and ($sc2 or $sc3)) or ($ad1 and $sc4))
}

rule MachO_VM_Detection {
  meta:
    description = "Virtual machine detection — VMware, VirtualBox, Parallels checks"
    category    = "evasion"
    severity    = "medium"
  strings:
    $magic1 = { CF FA ED FE }
    $magic2 = { CE FA ED FE }
    $magic3 = { CA FE BA BE }
    $vm1 = "VMware" ascii nocase
    $vm2 = "VirtualBox" ascii nocase
    $vm3 = "Parallels" ascii nocase
    $vm4 = "QEMU" ascii nocase
    $vm5 = "hw.model" ascii
    $vm6 = "kern.hv_vmm_present" ascii
    $vm7 = "sysctl.proc_translated" ascii
    $sc1 = "_sysctl" ascii
    $sc2 = "IOServiceMatching" ascii
  condition:
    ($magic1 at 0 or $magic2 at 0 or $magic3 at 0) and
    (2 of ($vm*)) and (1 of ($sc*))
}

rule MachO_Packed_UPX {
  meta:
    description = "UPX packed Mach-O binary"
    category    = "packer"
    severity    = "medium"
  strings:
    $magic1 = { CF FA ED FE }
    $magic2 = { CE FA ED FE }
    $magic3 = { CA FE BA BE }
    $upx1 = "UPX!" ascii
    $upx2 = "UPX0" ascii
    $upx3 = "$Info: This file is packed with the UPX" ascii
  condition:
    ($magic1 at 0 or $magic2 at 0 or $magic3 at 0) and
    (1 of ($upx*))
}

rule MachO_Encrypted_Binary {
  meta:
    description = "Encrypted Mach-O binary — LC_ENCRYPTION_INFO with active encryption"
    category    = "packer"
    severity    = "high"
  strings:
    $magic1 = { CF FA ED FE }
    $magic2 = { CE FA ED FE }
    $lc_enc32 = { 21 00 00 00 14 00 00 00 }
    $lc_enc64 = { 2C 00 00 00 18 00 00 00 }
  condition:
    ($magic1 at 0 or $magic2 at 0) and
    (($lc_enc32 in (0..4096)) or ($lc_enc64 in (0..4096)))
}

rule MachO_Cryptominer {
  meta:
    description = "Cryptocurrency mining indicators in Mach-O binary"
    category    = "cryptominer"
    severity    = "high"
  strings:
    $magic1 = { CF FA ED FE }
    $magic2 = { CE FA ED FE }
    $magic3 = { CA FE BA BE }
    $m1 = "stratum+tcp://" ascii
    $m2 = "stratum+ssl://" ascii
    $m3 = "mining.pool" ascii nocase
    $m4 = "xmrig" ascii nocase
    $m5 = "cryptonight" ascii nocase
    $m6 = "randomx" ascii nocase
    $m7 = "hashrate" ascii nocase
    $m8 = "pool_address" ascii nocase
    $wallet = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ ascii
  condition:
    ($magic1 at 0 or $magic2 at 0 or $magic3 at 0) and
    (2 of ($m*) or ($wallet and 1 of ($m*)))
}

rule MachO_Dylib_Hijack {
  meta:
    description = "DYLD injection / dylib hijacking indicators"
    category    = "exploit"
    severity    = "high"
  strings:
    $magic1 = { CF FA ED FE }
    $magic2 = { CE FA ED FE }
    $magic3 = { CA FE BA BE }
    $dh1 = "DYLD_INSERT_LIBRARIES" ascii
    $dh2 = "DYLD_LIBRARY_PATH" ascii
    $dh3 = "DYLD_FRAMEWORK_PATH" ascii
    $dh4 = "@rpath" ascii
    $dh5 = "@loader_path/../Frameworks" ascii
    $dh6 = "NSCreateObjectFileImageFromMemory" ascii
    $dh7 = "_dlopen" ascii
    $dh8 = "DYLD_PRINT_LIBRARIES" ascii
  condition:
    ($magic1 at 0 or $magic2 at 0 or $magic3 at 0) and
    (($dh1 or $dh2 or $dh3) or ($dh6 and $dh7) or (2 of ($dh4, $dh5, $dh8)))
}

rule MachO_Camera_Microphone {
  meta:
    description = "Camera/microphone access — potential surveillance malware"
    category    = "malware"
    severity    = "high"
  strings:
    $magic1 = { CF FA ED FE }
    $magic2 = { CE FA ED FE }
    $magic3 = { CA FE BA BE }
    $cam1 = "AVCaptureDevice" ascii
    $cam2 = "AVCaptureSession" ascii
    $cam3 = "AVCaptureVideoDataOutput" ascii
    $cam4 = "AVCaptureAudioDataOutput" ascii
    $cam5 = "kTCCServiceCamera" ascii
    $cam6 = "kTCCServiceMicrophone" ascii
    $tcc1 = "com.apple.TCC" ascii
    $tcc2 = "tcc.db" ascii
  condition:
    ($magic1 at 0 or $magic2 at 0 or $magic3 at 0) and
    ((2 of ($cam*)) or (1 of ($tcc*) and 1 of ($cam*)))
}

rule MachO_Suspicious_Entitlements {
  meta:
    description = "Suspicious code signing entitlements that weaken security"
    category    = "evasion"
    severity    = "medium"
  strings:
    $magic1 = { CF FA ED FE }
    $magic2 = { CE FA ED FE }
    $magic3 = { CA FE BA BE }
    $ent1 = "com.apple.security.cs.disable-library-validation" ascii
    $ent2 = "com.apple.security.cs.allow-unsigned-executable-memory" ascii
    $ent3 = "com.apple.security.cs.disable-executable-page-protection" ascii
    $ent4 = "com.apple.security.get-task-allow" ascii
    $ent5 = "com.apple.security.cs.allow-jit" ascii
  condition:
    ($magic1 at 0 or $magic2 at 0 or $magic3 at 0) and
    (2 of ($ent*))
}

rule MachO_Adware_Installer {
  meta:
    description = "Adware/bundleware installer patterns — system modification indicators"
    category    = "adware"
    severity    = "medium"
  strings:
    $magic1 = { CF FA ED FE }
    $magic2 = { CE FA ED FE }
    $magic3 = { CA FE BA BE }
    $ad1 = "SystemConfiguration" ascii
    $ad2 = "SCDynamicStore" ascii
    $ad3 = "networksetup" ascii
    $ad4 = "scutil" ascii
    $ad5 = "dscl" ascii
    $proxy1 = "autoproxy" ascii nocase
    $proxy2 = "webproxy" ascii nocase
    $proxy3 = "socksproxy" ascii nocase
    $dns1 = "setdnsservers" ascii nocase
    $dns2 = "/etc/hosts" ascii
  condition:
    ($magic1 at 0 or $magic2 at 0 or $magic3 at 0) and
    (2 of ($ad*) and (1 of ($proxy*) or 1 of ($dns*)))
}

rule MachO_Fileless_Execution {
  meta:
    description = "Fileless Mach-O execution via NSCreateObjectFileImageFromMemory"
    category    = "exploit"
    severity    = "critical"
  strings:
    $magic1 = { CF FA ED FE }
    $magic2 = { CE FA ED FE }
    $magic3 = { CA FE BA BE }
    $fl1 = "NSCreateObjectFileImageFromMemory" ascii
    $fl2 = "NSLinkModule" ascii
    $fl3 = "NSLookupSymbolInModule" ascii
    $fl4 = "NSAddressOfSymbol" ascii
  condition:
    ($magic1 at 0 or $magic2 at 0 or $magic3 at 0) and
    ($fl1 and $fl2)
}
