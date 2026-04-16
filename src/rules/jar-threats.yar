// ─── JAR / Java Class Threat Detection Rules ────────────────────────────────
// Targets: .jar, .war, .ear, .class files
// Focus: Deserialization gadgets, JNDI injection, classloader abuse,
//        command execution, reverse shells, obfuscation, Java agents

rule Java_Deserialization_CommonsCollections {
    meta:
        description = "Apache Commons Collections deserialization gadget chain"
        severity = "critical"
        category = "deserialization"
        mitre = "T1059"
    strings:
        $cc1 = "InvokerTransformer" ascii
        $cc2 = "ChainedTransformer" ascii
        $cc3 = "ConstantTransformer" ascii
        $cc4 = "InstantiateTransformer" ascii
        $cc5 = "commons/collections" ascii nocase
        $cc6 = "commons.collections.functors" ascii
    condition:
        any of ($cc1, $cc2, $cc3, $cc4) and any of ($cc5, $cc6)
}

rule Java_Deserialization_Gadgets {
    meta:
        description = "Known Java deserialization gadget classes"
        severity = "critical"
        category = "deserialization"
        mitre = "T1059"
    strings:
        $g1 = "TemplatesImpl" ascii
        $g2 = "BeanComparator" ascii
        $g3 = "ConvertedClosure" ascii
        $g4 = "bsh/Interpreter" ascii
        $g5 = "c3p0/WrapperConnectionPoolDataSource" ascii
        $g6 = "BasicPropertyAccessor" ascii
        $g7 = "DiskFileItem" ascii
        $g8 = "InterceptorMethodHandler" ascii
        $g9 = "NativeJavaObject" ascii
        $g10 = "com/alibaba/fastjson" ascii
        $context1 = "ObjectInputStream" ascii
        $context2 = "readObject" ascii
        $context3 = "Serializable" ascii
    condition:
        2 of ($g1, $g2, $g3, $g4, $g5, $g6, $g7, $g8, $g9, $g10) or
        (any of ($g1, $g2, $g3, $g4, $g5, $g6, $g7, $g8, $g9, $g10) and any of ($context1, $context2, $context3))
}

rule Java_JNDI_Injection {
    meta:
        description = "JNDI injection / Log4Shell style attack patterns"
        severity = "critical"
        category = "injection"
        mitre = "T1190"
    strings:
        $jndi1 = "jndi:ldap://" ascii nocase
        $jndi2 = "jndi:rmi://" ascii nocase
        $jndi3 = "jndi:dns://" ascii nocase
        $jndi4 = "jndi:iiop://" ascii nocase
        $jndi5 = "jndi:corba://" ascii nocase
        $jndi6 = "${jndi:" ascii nocase
        $ctx1 = "InitialContext" ascii
        $ctx2 = "NamingManager" ascii
        $ctx3 = "javax/naming" ascii
    condition:
        any of ($jndi1, $jndi2, $jndi3, $jndi4, $jndi5, $jndi6) or
        (2 of ($ctx1, $ctx2, $ctx3) and any of ($jndi1, $jndi2, $jndi3, $jndi4, $jndi5, $jndi6))
}

rule Java_Remote_ClassLoader {
    meta:
        description = "Remote class loading via URLClassLoader or similar"
        severity = "high"
        category = "classloader"
        mitre = "T1105"
    strings:
        $cl1 = "URLClassLoader" ascii
        $cl2 = "defineClass" ascii
        $cl3 = "findClass" ascii
        $cl4 = "loadClass" ascii
        $cl5 = "forName" ascii
        $net1 = "http://" ascii
        $net2 = "https://" ascii
        $net3 = "URL" ascii
        $net4 = "openConnection" ascii
    condition:
        any of ($cl1, $cl2) and any of ($net1, $net2, $net3, $net4)
}

rule Java_Command_Execution {
    meta:
        description = "OS command execution via Runtime.exec or ProcessBuilder"
        severity = "high"
        category = "execution"
        mitre = "T1059"
    strings:
        $exec1 = "Runtime" ascii
        $exec2 = "getRuntime" ascii
        $exec3 = "exec" ascii
        $exec4 = "ProcessBuilder" ascii
        $exec5 = "ProcessImpl" ascii
        $cmd1 = "/bin/sh" ascii
        $cmd2 = "/bin/bash" ascii
        $cmd3 = "cmd.exe" ascii
        $cmd4 = "powershell" ascii nocase
        $cmd5 = "cmd /c" ascii nocase
    condition:
        (($exec1 and $exec2 and $exec3) or $exec4 or $exec5) and any of ($cmd1, $cmd2, $cmd3, $cmd4, $cmd5)
}

rule Java_Reverse_Shell {
    meta:
        description = "Java reverse shell pattern (Socket + exec + IO streams)"
        severity = "critical"
        category = "backdoor"
        mitre = "T1059"
    strings:
        $sock = "Socket" ascii
        $exec1 = "Runtime" ascii
        $exec2 = "getRuntime" ascii
        $exec3 = "exec" ascii
        $exec4 = "ProcessBuilder" ascii
        $io1 = "getInputStream" ascii
        $io2 = "getOutputStream" ascii
        $io3 = "InputStream" ascii
        $io4 = "OutputStream" ascii
        $shell1 = "/bin/sh" ascii
        $shell2 = "/bin/bash" ascii
        $shell3 = "cmd.exe" ascii
    condition:
        $sock and any of ($exec1, $exec4) and any of ($io1, $io2, $io3, $io4) and any of ($shell1, $shell2, $shell3)
}

rule Java_Script_Engine {
    meta:
        description = "JavaScript/script engine usage for code execution"
        severity = "high"
        category = "execution"
        mitre = "T1059.007"
    strings:
        $se1 = "ScriptEngineManager" ascii
        $se2 = "ScriptEngine" ascii
        $se3 = "Nashorn" ascii
        $se4 = "javax/script" ascii
        $se5 = "getEngineByName" ascii
        $eval1 = "eval" ascii
        $eval2 = "compile" ascii
    condition:
        any of ($se1, $se2, $se3, $se4) and ($se5 or any of ($eval1, $eval2))
}

rule Java_Agent_Instrumentation {
    meta:
        description = "Java agent / bytecode instrumentation capabilities"
        severity = "high"
        category = "agent"
        mitre = "T1055"
    strings:
        $agent1 = "Premain-Class" ascii
        $agent2 = "Agent-Class" ascii
        $agent3 = "premain" ascii
        $agent4 = "agentmain" ascii
        $inst1 = "java/lang/instrument" ascii
        $inst2 = "Instrumentation" ascii
        $inst3 = "redefineClasses" ascii
        $inst4 = "retransformClasses" ascii
        $inst5 = "Can-Retransform-Classes" ascii
        $inst6 = "Can-Redefine-Classes" ascii
    condition:
        any of ($agent1, $agent2, $agent3, $agent4) and any of ($inst1, $inst2, $inst3, $inst4, $inst5, $inst6)
}

rule Java_Native_Library_Loading {
    meta:
        description = "Native library loading via JNI"
        severity = "high"
        category = "native"
        mitre = "T1055"
    strings:
        $load1 = "System.loadLibrary" ascii
        $load2 = "System.load" ascii
        $load3 = "Runtime.load" ascii
        $load4 = "Runtime.loadLibrary" ascii
        $jni1 = "native" ascii
        $jni2 = "JNI_OnLoad" ascii
        $jni3 = "Java_" ascii
    condition:
        any of ($load1, $load2, $load3, $load4) or ($jni2 and $jni3)
}

rule Java_Network_RAT {
    meta:
        description = "Remote access trojan patterns (keylogger, screen capture, webcam)"
        severity = "critical"
        category = "rat"
        mitre = "T1219"
    strings:
        $rat1 = "Robot" ascii
        $rat2 = "createScreenCapture" ascii
        $rat3 = "KeyListener" ascii
        $rat4 = "keyPressed" ascii
        $rat5 = "keyReleased" ascii
        $rat6 = "getDefaultToolkit" ascii
        $rat7 = "Clipboard" ascii
        $rat8 = "Webcam" ascii
        $net1 = "ServerSocket" ascii
        $net2 = "Socket" ascii
        $net3 = "DatagramSocket" ascii
    condition:
        2 of ($rat1, $rat2, $rat3, $rat4, $rat5, $rat6, $rat7, $rat8) and any of ($net1, $net2, $net3)
}

rule Java_Cryptominer {
    meta:
        description = "Cryptocurrency mining indicators in Java"
        severity = "high"
        category = "cryptominer"
        mitre = "T1496"
    strings:
        $pool1 = "stratum+tcp://" ascii nocase
        $pool2 = "stratum+ssl://" ascii nocase
        $pool3 = "pool.minergate" ascii nocase
        $pool4 = "xmrpool" ascii nocase
        $pool5 = "nanopool" ascii nocase
        $pool6 = "nicehash" ascii nocase
        $mine1 = "cryptonight" ascii nocase
        $mine2 = "hashrate" ascii nocase
        $mine3 = "mining" ascii nocase
        $mine4 = "monero" ascii nocase
        $wallet = /[48][0-9AB][0-9a-zA-Z]{93}/ ascii
    condition:
        any of ($pool1, $pool2, $pool3, $pool4, $pool5, $pool6) or
        (2 of ($mine1, $mine2, $mine3, $mine4) and $wallet)
}

rule Java_Obfuscation_Allatori {
    meta:
        description = "Allatori Java obfuscator signatures"
        severity = "medium"
        category = "obfuscation"
        mitre = "T1027"
    strings:
        $a1 = "Allatori" ascii nocase
        $a2 = "ALLATORIxDEMO" ascii
        $a3 = "com/allatori" ascii nocase
    condition:
        any of them
}

rule Java_Obfuscation_ZKM {
    meta:
        description = "Zelix KlassMaster obfuscator signatures"
        severity = "medium"
        category = "obfuscation"
        mitre = "T1027"
    strings:
        $z1 = "ZKM" ascii
        $z2 = "zelix" ascii nocase
        $z3 = "KlassMaster" ascii
    condition:
        any of them
}

rule Java_Security_Manager_Bypass {
    meta:
        description = "Security manager manipulation or bypass"
        severity = "high"
        category = "defense-evasion"
        mitre = "T1562"
    strings:
        $sm1 = "setSecurityManager" ascii
        $sm2 = "SecurityManager" ascii
        $sm3 = "checkPermission" ascii
        $sm4 = "AccessController" ascii
        $sm5 = "doPrivileged" ascii
        $sm6 = "ProtectionDomain" ascii
        $null = "null" ascii
    condition:
        ($sm1 and $null) or ($sm2 and $sm5) or (3 of ($sm1, $sm2, $sm3, $sm4, $sm5, $sm6))
}

rule Java_Credential_Theft {
    meta:
        description = "Credential harvesting via keystore, LDAP bind, or password interception"
        severity = "high"
        category = "credential-theft"
        mitre = "T1552"
    strings:
        $ks1 = "KeyStore" ascii
        $ks2 = "keystore" ascii nocase
        $ks3 = "PasswordCallback" ascii
        $ks4 = "getPassword" ascii
        $ldap1 = "LdapContext" ascii
        $ldap2 = "SECURITY_CREDENTIALS" ascii
        $ldap3 = "SECURITY_PRINCIPAL" ascii
        $cred1 = "password" ascii nocase
        $cred2 = "credential" ascii nocase
        $cred3 = "passwd" ascii nocase
    condition:
        (any of ($ks1, $ks2) and any of ($ks3, $ks4)) or
        ($ldap1 and any of ($ldap2, $ldap3)) or
        (2 of ($cred1, $cred2, $cred3) and any of ($ks1, $ks2, $ks3, $ks4, $ldap1))
}

rule Java_File_Encryption_Ransomware {
    meta:
        description = "File encryption patterns consistent with ransomware"
        severity = "critical"
        category = "ransomware"
        mitre = "T1486"
    strings:
        $crypto1 = "javax/crypto/Cipher" ascii
        $crypto2 = "AES" ascii
        $crypto3 = "RSA" ascii
        $crypto4 = "SecretKeySpec" ascii
        $file1 = "FileInputStream" ascii
        $file2 = "FileOutputStream" ascii
        $file3 = "listFiles" ascii
        $file4 = "isDirectory" ascii
        $ransom1 = "ransom" ascii nocase
        $ransom2 = "decrypt" ascii nocase
        $ransom3 = "encrypted" ascii nocase
        $ransom4 = "bitcoin" ascii nocase
        $ransom5 = ".locked" ascii
        $ransom6 = ".encrypted" ascii
        $ransom7 = "README" ascii
    condition:
        (2 of ($crypto1, $crypto2, $crypto3, $crypto4)) and
        (2 of ($file1, $file2, $file3, $file4)) and
        any of ($ransom1, $ransom2, $ransom3, $ransom4, $ransom5, $ransom6, $ransom7)
}

rule Java_Data_Exfiltration {
    meta:
        description = "Data collection and exfiltration patterns"
        severity = "high"
        category = "exfiltration"
        mitre = "T1041"
    strings:
        $collect1 = "getProperty" ascii
        $collect2 = "user.home" ascii
        $collect3 = "user.name" ascii
        $collect4 = "os.name" ascii
        $collect5 = "getHostName" ascii
        $collect6 = "getHostAddress" ascii
        $collect7 = "InetAddress" ascii
        $exfil1 = "HttpURLConnection" ascii
        $exfil2 = "openConnection" ascii
        $exfil3 = "POST" ascii
        $exfil4 = "setDoOutput" ascii
        $exfil5 = "getOutputStream" ascii
    condition:
        3 of ($collect1, $collect2, $collect3, $collect4, $collect5, $collect6, $collect7) and
        2 of ($exfil1, $exfil2, $exfil3, $exfil4, $exfil5)
}
