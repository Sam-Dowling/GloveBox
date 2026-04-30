rule Info_Contains_WebAssembly {
    meta:
        description = "File contains WebAssembly (WASM) binary module"
        severity    = "info"
        category    = "file-type"
        mitre       = ""
    strings:
        $magic = { 00 61 73 6D }
    condition:
        $magic
}

rule WASM_Cryptominer_Imports {
    meta:
        description = "WebAssembly cryptominer (CryptoNight / Argon2 / RandomX symbols in imports or exports)"
        severity    = "critical"
        category    = "malware"
        mitre       = "T1496"
        applies_to  = "wasm"
    strings:
        $cn1     = "cryptonight" ascii nocase
        $cn2     = "cryptonight_hash" ascii nocase
        $argon   = "argon2" ascii nocase
        $randomx = "randomx" ascii nocase
        $coinhive = "coinhive" ascii nocase
        $hashvert = "hashvert" ascii nocase
        $monero  = "xmrig" ascii nocase
    condition:
        any of them
}

rule WASM_Network_Bridge_Imports {
    meta:
        description = "WebAssembly imports a JS network bridge (fetch / XHR / WebSocket) — possible C2 over WASM"
        severity    = "high"
        category    = "network"
        mitre       = "T1071.001"
        applies_to  = "wasm"
    strings:
        $f1 = "__wbg_fetch" ascii
        $f2 = "__wbg_send_with" ascii
        $f3 = "__wbg_newwithstr" ascii
        $f4 = "__wbg_websocket" ascii nocase
        $f5 = "__wbg_xmlhttprequest" ascii nocase
        $f6 = "emscripten_fetch" ascii
    condition:
        any of them
}

rule WASM_Eval_Bridge_Imports {
    meta:
        description = "WebAssembly imports a JS evaluation bridge (Function ctor / eval / emscripten_run_script) — sandbox escape vector"
        severity    = "critical"
        category    = "exec"
        mitre       = "T1059.007"
        applies_to  = "wasm"
    strings:
        $e1 = "emscripten_run_script" ascii
        $e2 = "__wbindgen_eval" ascii
        $e3 = "__wbg_eval" ascii nocase
        $e4 = "__wbg_function_new" ascii nocase
    condition:
        any of them
}

rule WASM_WASI_Process_Spawn {
    meta:
        description = "WebAssembly WASI proc_exec / proc_raise / sock_open imports — out-of-sandbox capability surface"
        severity    = "high"
        category    = "exec"
        mitre       = "T1106"
        applies_to  = "wasm"
    strings:
        $w1 = "proc_exec" ascii
        $w2 = "proc_raise" ascii
        $w3 = "sock_open" ascii
        $w4 = "sock_connect" ascii
        $wasi = "wasi_snapshot_preview1" ascii
    condition:
        $wasi and any of ($w1, $w2, $w3, $w4)
}

rule WASM_Keylogger_Stealer_Exports {
    meta:
        description = "WebAssembly exports keylogger / clipboard-stealer / credential-stealer entry points"
        severity    = "critical"
        category    = "malware"
        mitre       = "T1056.001"
        applies_to  = "wasm"
    strings:
        $k1 = "keylogger" ascii nocase
        $k2 = "key_capture" ascii nocase
        $k3 = "clipboard_steal" ascii nocase
        $k4 = "stealer_init" ascii nocase
        $k5 = "exfil_credentials" ascii nocase
    condition:
        any of them
}

rule WASM_Anti_Debug_Strings {
    meta:
        description = "WebAssembly anti-analysis strings (debugger detection / DevTools fingerprinting)"
        severity    = "medium"
        category    = "anti-analysis"
        mitre       = "T1622"
        applies_to  = "wasm"
    strings:
        $a1 = "debugger;" ascii
        $a2 = "DevTools" ascii
        $a3 = "is_debugger_attached" ascii nocase
        $a4 = "anti_debug" ascii nocase
    condition:
        2 of them
}

rule WASM_Embedded_Shellcode_Hint {
    meta:
        description = "WebAssembly module embeds long runs of x86/x64 NOP-sled bytes — possible stage-2 shellcode payload"
        severity    = "high"
        category    = "shellcode"
        mitre       = "T1027"
        applies_to  = "wasm"
    strings:
        $nop_sled = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
        $int3_sled = { CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC }
    condition:
        #nop_sled > 1 or #int3_sled > 1
}

rule WASM_Source_Map_Reference {
    meta:
        description = "WebAssembly references an external sourceMappingURL — analyst pivot for original-source recovery"
        severity    = "info"
        category    = "metadata"
        mitre       = ""
        applies_to  = "wasm"
    strings:
        $smu = "sourceMappingURL" ascii
        $http = "http" ascii
    condition:
        $smu and $http
}
