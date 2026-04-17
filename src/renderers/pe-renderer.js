'use strict';
// ════════════════════════════════════════════════════════════════════════════
// pe-renderer.js — Windows PE (EXE/DLL/SYS) binary parser + analysis view
// Parses PE32/PE32+ headers, sections, imports, exports, resources, Rich
// header, and security features entirely in the browser.
// Depends on: constants.js (IOC)
// ════════════════════════════════════════════════════════════════════════════

class PeRenderer {

  // ── Machine type constants ───────────────────────────────────────────────
  static MACHINE = {
    0x0000: 'Unknown', 0x014C: 'i386 (x86)', 0x0166: 'MIPS R4000',
    0x0169: 'MIPS WCE v2', 0x01A2: 'Hitachi SH3', 0x01A3: 'Hitachi SH3 DSP',
    0x01A6: 'Hitachi SH4', 0x01A8: 'Hitachi SH5', 0x01C0: 'ARM',
    0x01C2: 'ARM Thumb', 0x01C4: 'ARM Thumb-2 (ARMv7)', 0x01D3: 'AM33',
    0x8664: 'AMD64 (x64)', 0xAA64: 'ARM64', 0x5032: 'RISC-V 32',
    0x5064: 'RISC-V 64', 0x0200: 'IA-64 (Itanium)',
  };

  // ── Subsystem constants ──────────────────────────────────────────────────
  static SUBSYSTEM = {
    0: 'Unknown', 1: 'Native', 2: 'Windows GUI', 3: 'Windows Console',
    5: 'OS/2 Console', 7: 'POSIX Console', 9: 'Windows CE GUI',
    10: 'EFI Application', 11: 'EFI Boot Driver', 12: 'EFI Runtime Driver',
    13: 'EFI ROM', 14: 'Xbox', 16: 'Windows Boot App',
  };

  // ── DLL Characteristics flags ────────────────────────────────────────────
  static DLL_CHARS = {
    0x0020: 'HIGH_ENTROPY_VA', 0x0040: 'DYNAMIC_BASE (ASLR)',
    0x0080: 'FORCE_INTEGRITY', 0x0100: 'NX_COMPAT (DEP)',
    0x0200: 'NO_ISOLATION', 0x0400: 'NO_SEH', 0x0800: 'NO_BIND',
    0x1000: 'APPCONTAINER', 0x2000: 'WDM_DRIVER',
    0x4000: 'GUARD_CF (CFG)', 0x8000: 'TERMINAL_SERVER_AWARE',
  };

  // ── COFF Characteristics flags ───────────────────────────────────────────
  static COFF_CHARS = {
    0x0001: 'RELOCS_STRIPPED', 0x0002: 'EXECUTABLE_IMAGE',
    0x0004: 'LINE_NUMS_STRIPPED', 0x0008: 'LOCAL_SYMS_STRIPPED',
    0x0010: 'AGGRESSIVE_WS_TRIM', 0x0020: 'LARGE_ADDRESS_AWARE',
    0x0080: 'BYTES_REVERSED_LO', 0x0100: '32BIT_MACHINE',
    0x0200: 'DEBUG_STRIPPED', 0x0400: 'REMOVABLE_RUN_FROM_SWAP',
    0x0800: 'NET_RUN_FROM_SWAP', 0x1000: 'SYSTEM (driver)',
    0x2000: 'DLL', 0x4000: 'UP_SYSTEM_ONLY',
    0x8000: 'BYTES_REVERSED_HI',
  };

  // ── Section Characteristics flags ────────────────────────────────────────
  static SEC_CHARS = {
    0x00000020: 'CODE', 0x00000040: 'INITIALIZED_DATA',
    0x00000080: 'UNINITIALIZED_DATA', 0x02000000: 'DISCARDABLE',
    0x04000000: 'NOT_CACHED', 0x08000000: 'NOT_PAGED',
    0x10000000: 'SHARED', 0x20000000: 'EXECUTE',
    0x40000000: 'READ', 0x80000000: 'WRITE',
  };

  // ── Resource type constants ──────────────────────────────────────────────
  static RES_TYPE = {
    1: 'Cursor', 2: 'Bitmap', 3: 'Icon', 4: 'Menu', 5: 'Dialog',
    6: 'String Table', 7: 'Font Directory', 8: 'Font', 9: 'Accelerator',
    10: 'RC Data', 11: 'Message Table', 12: 'Group Cursor', 14: 'Group Icon',
    16: 'Version Info', 17: 'DlgInclude', 19: 'Plug & Play',
    20: 'VXD', 21: 'Animated Cursor', 22: 'Animated Icon',
    23: 'HTML', 24: 'Manifest',
  };

  // ── Detailed API info (description, context, MITRE ATT&CK) ──────────────
  static SUSPICIOUS_APIS_DETAIL = {
    VirtualAlloc: {
      desc: 'Allocates or reserves memory pages in the calling process.',
      context: 'Commonly used to allocate RWX memory for shellcode or unpacked payloads.',
      mitre: 'T1055 — Process Injection',
    },
    VirtualAllocEx: {
      desc: 'Allocates memory in another process\'s address space.',
      context: 'Key step in remote process injection — prepares a code cave in the target process for shellcode.',
      mitre: 'T1055.001 — DLL Injection',
    },
    VirtualProtect: {
      desc: 'Changes the access protection on a region of committed pages in the calling process.',
      context: 'Used by packers to mark data as executable at runtime, or by injectors to make writable code pages.',
      mitre: 'T1055 — Process Injection',
    },
    VirtualProtectEx: {
      desc: 'Changes memory protection in a remote process.',
      context: 'Enables write+execute on remote process memory to facilitate code injection.',
      mitre: 'T1055 — Process Injection',
    },
    WriteProcessMemory: {
      desc: 'Writes data to an area of memory in the address space of another process.',
      context: 'Classic injection primitive — writes shellcode or a DLL path into a remote process before triggering execution.',
      mitre: 'T1055.001 — DLL Injection',
    },
    CreateRemoteThread: {
      desc: 'Creates a thread that runs in the virtual address space of another process.',
      context: 'Executes injected code in a remote process. Combined with VirtualAllocEx + WriteProcessMemory this forms the classic injection triad.',
      mitre: 'T1055.001 — DLL Injection',
    },
    CreateRemoteThreadEx: {
      desc: 'Extended version of CreateRemoteThread with additional parameters.',
      context: 'Same injection purpose as CreateRemoteThread with more control over thread attributes.',
      mitre: 'T1055.001 — DLL Injection',
    },
    NtUnmapViewOfSection: {
      desc: 'Unmaps a view of a section from the virtual address space of a process.',
      context: 'Used in process hollowing to carve out the legitimate image before replacing it with malicious code.',
      mitre: 'T1055.012 — Process Hollowing',
    },
    QueueUserAPC: {
      desc: 'Adds a user-mode APC (Asynchronous Procedure Call) to a thread\'s APC queue.',
      context: 'Used in "Early Bird" injection — queues malicious code before the main thread starts, evading hooks.',
      mitre: 'T1055.004 — APC Injection',
    },
    SetThreadContext: {
      desc: 'Sets the context (register state) of a thread.',
      context: 'Used in process hollowing to redirect execution to injected code by modifying the instruction pointer.',
      mitre: 'T1055.012 — Process Hollowing',
    },
    ResumeThread: {
      desc: 'Resumes a suspended thread.',
      context: 'Final step in many injection chains — resumes a thread after modifying its context or injecting code.',
      mitre: 'T1055 — Process Injection',
    },
    IsDebuggerPresent: {
      desc: 'Determines whether the calling process is being debugged.',
      context: 'Basic anti-analysis check. Malware uses this to alter behavior or terminate when a debugger is detected.',
      mitre: 'T1622 — Debugger Evasion',
    },
    CheckRemoteDebuggerPresent: {
      desc: 'Determines whether a remote debugger is debugging the specified process.',
      context: 'Anti-debugging technique that detects both user-mode and kernel-mode debuggers.',
      mitre: 'T1622 — Debugger Evasion',
    },
    NtQueryInformationProcess: {
      desc: 'Retrieves information about the specified process (ntdll).',
      context: 'Used to query ProcessDebugPort, ProcessDebugFlags, etc. for anti-debug, or to detect sandbox/VM environments.',
      mitre: 'T1622 — Debugger Evasion',
    },
    GetTickCount: {
      desc: 'Returns the number of milliseconds since system boot.',
      context: 'Used for timing-based anti-analysis — detects single-stepping in debuggers or fast-forwarding in sandboxes.',
      mitre: 'T1497.003 — Time Based Evasion',
    },
    QueryPerformanceCounter: {
      desc: 'Returns a high-resolution timestamp.',
      context: 'Precision timing check to detect debugger-induced delays or sandbox acceleration.',
      mitre: 'T1497.003 — Time Based Evasion',
    },
    CredEnumerateA: {
      desc: 'Enumerates credentials stored in the Windows Credential Manager.',
      context: 'Allows malware to harvest saved passwords, tokens, and certificates from the credential store.',
      mitre: 'T1555.004 — Windows Credential Manager',
    },
    CryptUnprotectData: {
      desc: 'Decrypts data previously encrypted with CryptProtectData (DPAPI).',
      context: 'Used to decrypt browser passwords, cookies, and other DPAPI-protected secrets.',
      mitre: 'T1555.003 — Credentials from Web Browsers',
    },
    CreateProcessA: {
      desc: 'Creates a new process and its primary thread (ANSI).',
      context: 'Can launch child processes — often used with CREATE_SUSPENDED flag as part of process injection chains.',
      mitre: 'T1106 — Native API',
    },
    CreateProcessW: {
      desc: 'Creates a new process and its primary thread (Unicode).',
      context: 'Can launch child processes — often used with CREATE_SUSPENDED flag as part of process injection chains.',
      mitre: 'T1106 — Native API',
    },
    ShellExecuteA: {
      desc: 'Performs an operation on a specified file (open, print, run).',
      context: 'Can launch executables, open documents, or run scripts through shell verb associations.',
      mitre: 'T1204.002 — Malicious File',
    },
    URLDownloadToFileA: {
      desc: 'Downloads a resource from the Internet and saves it to a local file.',
      context: 'Simple one-call download primitive frequently used by droppers and downloaders to stage payloads.',
      mitre: 'T1105 — Ingress Tool Transfer',
    },
    URLDownloadToFileW: {
      desc: 'Downloads a resource from the Internet and saves it to a local file (Unicode).',
      context: 'Simple one-call download primitive frequently used by droppers and downloaders to stage payloads.',
      mitre: 'T1105 — Ingress Tool Transfer',
    },
    InternetOpenA: {
      desc: 'Initializes WinINet for HTTP/FTP requests.',
      context: 'First call in WinINet networking chain — establishes user agent and proxy configuration for C2.',
      mitre: 'T1071.001 — Web Protocols',
    },
    InternetOpenUrlA: {
      desc: 'Opens a URL for reading via HTTP, HTTPS, or FTP.',
      context: 'Used to download payloads or communicate with command-and-control servers.',
      mitre: 'T1071.001 — Web Protocols',
    },
    WSAStartup: {
      desc: 'Initializes Winsock for raw socket networking.',
      context: 'Required before any raw socket calls — indicates custom network protocol or C2 channel.',
      mitre: 'T1095 — Non-Application Layer Protocol',
    },
    CryptEncrypt: {
      desc: 'Encrypts data using a symmetric or asymmetric key.',
      context: 'Used by ransomware to encrypt victim files. Also used legitimately for data protection.',
      mitre: 'T1486 — Data Encrypted for Impact',
    },
    BCryptEncrypt: {
      desc: 'Encrypts data using the BCrypt (CNG) API.',
      context: 'Modern crypto API used by ransomware for file encryption or by malware for encrypted C2.',
      mitre: 'T1486 — Data Encrypted for Impact',
    },
    RegSetValueExA: {
      desc: 'Sets the data and type of a specified registry value.',
      context: 'Registry writes enable persistence (Run keys), defense evasion, and configuration storage.',
      mitre: 'T1547.001 — Registry Run Keys',
    },
    RegSetValueExW: {
      desc: 'Sets the data and type of a specified registry value (Unicode).',
      context: 'Registry writes enable persistence (Run keys), defense evasion, and configuration storage.',
      mitre: 'T1547.001 — Registry Run Keys',
    },
    CreateServiceA: {
      desc: 'Creates a Windows service object.',
      context: 'Installing a service provides persistent execution at SYSTEM privilege level.',
      mitre: 'T1543.003 — Windows Service',
    },
    LoadLibraryA: {
      desc: 'Loads a DLL module into the calling process.',
      context: 'Dynamic DLL loading is used by packers and malware to resolve functionality at runtime, avoiding static import detection.',
      mitre: 'T1129 — Shared Modules',
    },
    GetProcAddress: {
      desc: 'Retrieves the address of an exported function from a DLL.',
      context: 'Combined with LoadLibrary, enables API-hiding — resolves functions at runtime to evade import table analysis.',
      mitre: 'T1106 — Native API',
    },
    LdrLoadDll: {
      desc: 'Low-level ntdll function that loads a DLL.',
      context: 'Bypasses LoadLibrary hooks placed by security products for DLL load monitoring.',
      mitre: 'T1129 — Shared Modules',
    },
  };

  // ── Suspicious import APIs ───────────────────────────────────────────────
  static SUSPICIOUS_APIS = {
    // Process injection
    VirtualAlloc: 'Memory allocation (common in injection)',
    VirtualAllocEx: 'Remote memory allocation → process injection',
    VirtualProtect: 'Memory permission change → code injection / unpacking',
    VirtualProtectEx: 'Remote memory permission change → injection',
    WriteProcessMemory: 'Write to remote process → process injection',
    CreateRemoteThread: 'Remote thread creation → process injection',
    CreateRemoteThreadEx: 'Remote thread creation → process injection',
    NtUnmapViewOfSection: 'Unmap section → process hollowing',
    NtWriteVirtualMemory: 'Write to process memory → injection',
    NtCreateThreadEx: 'Create thread → injection',
    QueueUserAPC: 'APC injection → early bird injection',
    SetThreadContext: 'Thread hijacking → process hollowing',
    ResumeThread: 'Resume suspended thread → injection chain',
    RtlCreateUserThread: 'Create thread (ntdll) → injection',
    NtQueueApcThread: 'APC queue → injection',

    // Anti-debugging / evasion
    IsDebuggerPresent: 'Debugger detection → anti-analysis',
    CheckRemoteDebuggerPresent: 'Remote debugger detection → anti-analysis',
    NtQueryInformationProcess: 'Process info query → anti-debug / sandbox detect',
    GetTickCount: 'Timing check → sandbox / debugger evasion',
    QueryPerformanceCounter: 'Timing check → sandbox evasion',
    OutputDebugStringA: 'Debug string → anti-debug technique',
    GetSystemInfo: 'System info → sandbox / VM detection',
    EnumSystemFirmwareTables: 'Firmware tables → VM detection',

    // Credential theft
    CredEnumerateA: 'Credential enumeration → credential theft',
    CredEnumerateW: 'Credential enumeration → credential theft',
    LsaRetrievePrivateData: 'LSA secrets → credential theft',
    SamConnect: 'SAM database access → credential dumping',
    CryptUnprotectData: 'DPAPI decryption → credential / data theft',

    // Execution
    CreateProcessA: 'Process creation',
    CreateProcessW: 'Process creation',
    CreateProcessInternalW: 'Internal process creation → stealth',
    ShellExecuteA: 'Shell command execution',
    ShellExecuteW: 'Shell command execution',
    ShellExecuteExA: 'Shell command execution',
    ShellExecuteExW: 'Shell command execution',
    WinExec: 'Command execution (legacy)',

    // Networking
    InternetOpenA: 'Internet connection → C2 / download',
    InternetOpenW: 'Internet connection → C2 / download',
    InternetOpenUrlA: 'URL request → C2 / download',
    InternetOpenUrlW: 'URL request → C2 / download',
    HttpSendRequestA: 'HTTP request → C2',
    HttpSendRequestW: 'HTTP request → C2',
    URLDownloadToFileA: 'File download → payload staging',
    URLDownloadToFileW: 'File download → payload staging',
    WSAStartup: 'Winsock init → raw networking',

    // Crypto (ransomware indicators)
    CryptEncrypt: 'Encryption → potential ransomware',
    CryptDecrypt: 'Decryption → potential data theft',
    CryptGenKey: 'Key generation → crypto operations',
    CryptDeriveKey: 'Key derivation → crypto operations',
    CryptAcquireContextA: 'Crypto provider → encryption operations',
    CryptAcquireContextW: 'Crypto provider → encryption operations',
    BCryptEncrypt: 'BCrypt encryption → potential ransomware',

    // Persistence
    RegSetValueExA: 'Registry write → persistence / config',
    RegSetValueExW: 'Registry write → persistence / config',
    RegCreateKeyExA: 'Registry key creation → persistence',
    RegCreateKeyExW: 'Registry key creation → persistence',

    // Service manipulation
    CreateServiceA: 'Service creation → persistence / privilege escalation',
    CreateServiceW: 'Service creation → persistence / privilege escalation',
    StartServiceA: 'Service start → execution',
    StartServiceW: 'Service start → execution',

    // Dynamic loading (used by packers / evaders)
    LoadLibraryA: 'Dynamic DLL loading',
    LoadLibraryW: 'Dynamic DLL loading',
    LoadLibraryExA: 'Dynamic DLL loading',
    GetProcAddress: 'Dynamic API resolution → API hiding',
    LdrLoadDll: 'Low-level DLL loading → stealth',
  };

  // ── Known packer section names ───────────────────────────────────────────
  static PACKER_SECTIONS = {
    'UPX0': 'UPX Packer', 'UPX1': 'UPX Packer', 'UPX2': 'UPX Packer',
    '.aspack': 'ASPack', '.adata': 'ASPack', 'ASPack': 'ASPack',
    '.nsp0': 'NsPack', '.nsp1': 'NsPack', '.nsp2': 'NsPack',
    '.themida': 'Themida', '.Themida': 'Themida',
    '.vmp0': 'VMProtect', '.vmp1': 'VMProtect', '.vmp2': 'VMProtect',
    '.petite': 'Petite', '.pec2': 'PECompact', 'PEC2': 'PECompact',
    '.MPRESS1': 'MPRESS', '.MPRESS2': 'MPRESS',
    '.enigma1': 'Enigma Protector', '.enigma2': 'Enigma Protector',
    '.perplex': 'Perplex PE-Protector',
    '.rmnet': 'Ramnit virus', '.rsrc1': 'Possibly packed/patched',
  };

  // ── Data directory index names ───────────────────────────────────────────
  static DATA_DIR_NAMES = [
    'Export Table', 'Import Table', 'Resource Table', 'Exception Table',
    'Certificate Table', 'Base Relocation Table', 'Debug', 'Architecture',
    'Global Ptr', 'TLS Table', 'Load Config', 'Bound Import',
    'Import Address Table (IAT)', 'Delay Import', 'CLR Runtime Header', 'Reserved',
  ];

  // ═══════════════════════════════════════════════════════════════════════
  //  Binary read helpers
  // ═══════════════════════════════════════════════════════════════════════

  _u8(bytes, off) { return bytes[off]; }
  _u16(bytes, off) { return bytes[off] | (bytes[off + 1] << 8); }
  _u32(bytes, off) { return (bytes[off] | (bytes[off + 1] << 8) | (bytes[off + 2] << 16) | (bytes[off + 3] << 24)) >>> 0; }
  _u64(bytes, off) {
    const lo = this._u32(bytes, off), hi = this._u32(bytes, off + 4);
    // Return as a Number (safe up to 2^53)
    return hi * 0x100000000 + lo;
  }

  _str(bytes, off, len) {
    let s = '';
    for (let i = 0; i < len && bytes[off + i] !== 0; i++) s += String.fromCharCode(bytes[off + i]);
    return s;
  }

  _hex(v, digits) { return '0x' + v.toString(16).toUpperCase().padStart(digits || 0, '0'); }

  _entropy(bytes, off, len) {
    if (!len || off + len > bytes.length) return 0;
    const freq = new Uint32Array(256);
    const end = Math.min(off + len, bytes.length);
    const actual = end - off;
    for (let i = off; i < end; i++) freq[bytes[i]]++;
    let ent = 0;
    for (let i = 0; i < 256; i++) {
      if (freq[i] === 0) continue;
      const p = freq[i] / actual;
      ent -= p * Math.log2(p);
    }
    return Math.round(ent * 1000) / 1000;
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  RVA → file offset conversion
  // ═══════════════════════════════════════════════════════════════════════

  _rvaToOffset(rva, sections) {
    for (const s of sections) {
      if (rva >= s.virtualAddress && rva < s.virtualAddress + s.virtualSize) {
        return rva - s.virtualAddress + s.rawDataOffset;
      }
    }
    return rva; // If not found, return as-is (may be header-relative)
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Core PE parser
  // ═══════════════════════════════════════════════════════════════════════

  _parse(bytes) {
    const pe = {};

    // ── DOS Header ─────────────────────────────────────────────────────
    if (bytes.length < 64 || this._u16(bytes, 0) !== 0x5A4D)
      throw new Error('Not a valid PE file (missing MZ signature)');

    pe.dosHeader = {
      e_magic: 'MZ',
      e_lfanew: this._u32(bytes, 0x3C),
    };

    const peOff = pe.dosHeader.e_lfanew;
    if (peOff + 4 > bytes.length)
      throw new Error('Invalid PE: e_lfanew points beyond file');

    // ── Rich Header (between DOS stub and PE signature) ────────────────
    pe.richHeader = this._parseRichHeader(bytes, peOff);

    // ── PE Signature ───────────────────────────────────────────────────
    if (this._u32(bytes, peOff) !== 0x00004550)
      throw new Error('Invalid PE signature (expected PE\\0\\0)');

    // ── COFF Header ────────────────────────────────────────────────────
    const coffOff = peOff + 4;
    if (coffOff + 20 > bytes.length)
      throw new Error('File too small for COFF header');

    const machine = this._u16(bytes, coffOff);
    const numSections = this._u16(bytes, coffOff + 2);
    const timestamp = this._u32(bytes, coffOff + 4);
    const optHeaderSize = this._u16(bytes, coffOff + 16);
    const characteristics = this._u16(bytes, coffOff + 18);

    pe.coff = {
      machine, machineStr: PeRenderer.MACHINE[machine] || this._hex(machine, 4),
      numSections, timestamp,
      timestampStr: timestamp === 0 ? 'Epoch (0)' :
        timestamp === 0xFFFFFFFF ? 'Invalid (0xFFFFFFFF)' :
        new Date(timestamp * 1000).toISOString().replace('T', ' ').replace(/\.\d+Z/, ' UTC'),
      optHeaderSize, characteristics,
      characteristicsFlags: this._decodeFlags(characteristics, PeRenderer.COFF_CHARS),
      isDLL: !!(characteristics & 0x2000),
      isSystem: !!(characteristics & 0x1000),
    };

    // ── Optional Header ────────────────────────────────────────────────
    const optOff = coffOff + 20;
    if (optOff + 2 > bytes.length)
      throw new Error('File too small for Optional Header');

    const optMagic = this._u16(bytes, optOff);
    const is64 = optMagic === 0x020B;
    pe.is64 = is64;

    if (optMagic !== 0x010B && optMagic !== 0x020B)
      throw new Error('Unknown Optional Header magic: ' + this._hex(optMagic, 4));

    pe.optional = {
      magic: optMagic, magicStr: is64 ? 'PE32+ (64-bit)' : 'PE32 (32-bit)',
      majorLinkerVer: this._u8(bytes, optOff + 2),
      minorLinkerVer: this._u8(bytes, optOff + 3),
      sizeOfCode: this._u32(bytes, optOff + 4),
      sizeOfInitializedData: this._u32(bytes, optOff + 8),
      sizeOfUninitializedData: this._u32(bytes, optOff + 12),
      entryPoint: this._u32(bytes, optOff + 16),
      baseOfCode: this._u32(bytes, optOff + 20),
    };

    if (is64) {
      pe.optional.imageBase = this._u64(bytes, optOff + 24);
      pe.optional.sectionAlignment = this._u32(bytes, optOff + 32);
      pe.optional.fileAlignment = this._u32(bytes, optOff + 36);
      pe.optional.majorOSVer = this._u16(bytes, optOff + 40);
      pe.optional.minorOSVer = this._u16(bytes, optOff + 42);
      pe.optional.majorImageVer = this._u16(bytes, optOff + 44);
      pe.optional.minorImageVer = this._u16(bytes, optOff + 46);
      pe.optional.majorSubsysVer = this._u16(bytes, optOff + 48);
      pe.optional.minorSubsysVer = this._u16(bytes, optOff + 50);
      pe.optional.sizeOfImage = this._u32(bytes, optOff + 56);
      pe.optional.sizeOfHeaders = this._u32(bytes, optOff + 60);
      pe.optional.checksum = this._u32(bytes, optOff + 64);
      pe.optional.subsystem = this._u16(bytes, optOff + 68);
      pe.optional.dllCharacteristics = this._u16(bytes, optOff + 70);
      pe.optional.numberOfRvaAndSizes = this._u32(bytes, optOff + 108);
    } else {
      pe.optional.baseOfData = this._u32(bytes, optOff + 24);
      pe.optional.imageBase = this._u32(bytes, optOff + 28);
      pe.optional.sectionAlignment = this._u32(bytes, optOff + 32);
      pe.optional.fileAlignment = this._u32(bytes, optOff + 36);
      pe.optional.majorOSVer = this._u16(bytes, optOff + 40);
      pe.optional.minorOSVer = this._u16(bytes, optOff + 42);
      pe.optional.majorImageVer = this._u16(bytes, optOff + 44);
      pe.optional.minorImageVer = this._u16(bytes, optOff + 46);
      pe.optional.majorSubsysVer = this._u16(bytes, optOff + 48);
      pe.optional.minorSubsysVer = this._u16(bytes, optOff + 50);
      pe.optional.sizeOfImage = this._u32(bytes, optOff + 56);
      pe.optional.sizeOfHeaders = this._u32(bytes, optOff + 60);
      pe.optional.checksum = this._u32(bytes, optOff + 64);
      pe.optional.subsystem = this._u16(bytes, optOff + 68);
      pe.optional.dllCharacteristics = this._u16(bytes, optOff + 70);
      pe.optional.numberOfRvaAndSizes = this._u32(bytes, optOff + 92);
    }

    pe.optional.subsystemStr = PeRenderer.SUBSYSTEM[pe.optional.subsystem] || 'Unknown (' + pe.optional.subsystem + ')';
    pe.optional.dllCharFlags = this._decodeFlags(pe.optional.dllCharacteristics, PeRenderer.DLL_CHARS);
    pe.optional.linkerStr = pe.optional.majorLinkerVer + '.' + pe.optional.minorLinkerVer;

    // Security features from DllCharacteristics
    const dc = pe.optional.dllCharacteristics;
    pe.security = {
      aslr: !!(dc & 0x0040),
      highEntropyAslr: !!(dc & 0x0020),
      dep: !!(dc & 0x0100),
      cfg: !!(dc & 0x4000),
      noSeh: !!(dc & 0x0400),
      forceIntegrity: !!(dc & 0x0080),
      appContainer: !!(dc & 0x1000),
    };

    // ── Data Directories ───────────────────────────────────────────────
    const ddOff = is64 ? optOff + 112 : optOff + 96;
    const numDD = Math.min(pe.optional.numberOfRvaAndSizes || 0, 16);
    pe.dataDirectories = [];
    for (let i = 0; i < numDD; i++) {
      const off = ddOff + i * 8;
      if (off + 8 > bytes.length) break;
      pe.dataDirectories.push({
        name: PeRenderer.DATA_DIR_NAMES[i] || 'Directory ' + i,
        rva: this._u32(bytes, off),
        size: this._u32(bytes, off + 4),
      });
    }

    // ── Section Table ──────────────────────────────────────────────────
    const secOff = optOff + optHeaderSize;
    pe.sections = [];
    for (let i = 0; i < numSections; i++) {
      const so = secOff + i * 40;
      if (so + 40 > bytes.length) break;
      const name = this._str(bytes, so, 8);
      const virtualSize = this._u32(bytes, so + 8);
      const virtualAddress = this._u32(bytes, so + 12);
      const rawDataSize = this._u32(bytes, so + 16);
      const rawDataOffset = this._u32(bytes, so + 20);
      const chars = this._u32(bytes, so + 36);
      const entropy = this._entropy(bytes, rawDataOffset, rawDataSize);

      pe.sections.push({
        name, virtualSize, virtualAddress, rawDataSize, rawDataOffset,
        characteristics: chars,
        charFlags: this._decodeFlags(chars, PeRenderer.SEC_CHARS),
        entropy,
        isExecutable: !!(chars & 0x20000000),
        isWritable: !!(chars & 0x80000000),
        isReadable: !!(chars & 0x40000000),
        packerMatch: PeRenderer.PACKER_SECTIONS[name] || null,
      });
    }

    // ── Import Table ───────────────────────────────────────────────────
    pe.imports = this._parseImports(bytes, pe.dataDirectories, pe.sections, is64);

    // ── Export Table ───────────────────────────────────────────────────
    pe.exports = this._parseExports(bytes, pe.dataDirectories, pe.sections);

    // ── Resources ──────────────────────────────────────────────────────
    pe.resources = this._parseResources(bytes, pe.dataDirectories, pe.sections);

    // ── Strings ────────────────────────────────────────────────────────
    pe.strings = this._extractStrings(bytes, 6);

    // ── Debug directory (PDB path) ──────────────────────────────────
    pe.debugInfo = this._parseDebugDirectory(bytes, pe.dataDirectories, pe.sections);

    // ── Version Info (OriginalFilename, ProductName, etc.) ──────────
    pe.versionInfo = this._parseVersionInfo(bytes, pe.dataDirectories, pe.sections);

    // ── Import hash (Imphash) ───────────────────────────────────────
    pe.imphash = this._computeImphash(pe.imports);

    // ── Authenticode Certificates (from Certificate Table data dir) ─
    pe.certificates = [];
    try {
      const certDD = pe.dataDirectories[4];
      if (certDD && certDD.rva > 0 && certDD.size > 0) {
        // Note: Certificate Table "RVA" is actually a raw file offset
        const certOff = certDD.rva;
        if (certOff + 8 <= bytes.length) {
          const dwLength = this._u32(bytes, certOff);
          const wCertType = this._u16(bytes, certOff + 6);
          // WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002
          if (wCertType === 0x0002 && dwLength > 8 && certOff + dwLength <= bytes.length) {
            const pkcs7 = bytes.subarray(certOff + 8, certOff + dwLength);
            const result = X509Renderer.parseCertificatesFromCMS(pkcs7);
            if (result.certs.length) pe.certificates = result.certs;
          }
        }
      }
    } catch (_) { /* cert parsing is best-effort */ }

    return pe;
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Rich Header parser
  // ═══════════════════════════════════════════════════════════════════════

  _parseRichHeader(bytes, peOffset) {
    // Search for "Rich" marker backwards from PE header
    let richOff = -1;
    for (let i = peOffset - 4; i >= 0x80; i -= 4) {
      if (bytes[i] === 0x52 && bytes[i + 1] === 0x69 && bytes[i + 2] === 0x63 && bytes[i + 3] === 0x68) {
        richOff = i;
        break;
      }
    }
    if (richOff < 0) return null;

    const key = this._u32(bytes, richOff + 4);

    // Find "DanS" signature by XOR-decoding backwards
    let danSOff = -1;
    for (let i = richOff - 4; i >= 0; i -= 4) {
      if ((this._u32(bytes, i) ^ key) === 0x536E6144) { // "DanS"
        danSOff = i;
        break;
      }
    }
    if (danSOff < 0) return null;

    // Decode entries (skip first 4 DWORDs: DanS + 3 padding)
    const entries = [];
    for (let i = danSOff + 16; i < richOff; i += 8) {
      const val1 = this._u32(bytes, i) ^ key;
      const val2 = this._u32(bytes, i + 4) ^ key;
      const compId = val1 >> 16;
      const buildId = val1 & 0xFFFF;
      const count = val2;
      if (compId === 0 && buildId === 0 && count === 0) continue;
      entries.push({ compId, buildId, count });
    }

    return { xorKey: key, entries };
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Import Table parser
  // ═══════════════════════════════════════════════════════════════════════

  _parseImports(bytes, dataDirs, sections, is64) {
    if (!dataDirs[1] || dataDirs[1].rva === 0 || dataDirs[1].size === 0) return [];

    const impOff = this._rvaToOffset(dataDirs[1].rva, sections);
    if (impOff + 20 > bytes.length) return [];

    const imports = [];
    const maxDlls = 256; // Safety limit
    let descOff = impOff;

    for (let d = 0; d < maxDlls; d++) {
      if (descOff + 20 > bytes.length) break;

      const iltRva = this._u32(bytes, descOff);
      const nameRva = this._u32(bytes, descOff + 12);
      const iatRva = this._u32(bytes, descOff + 16);

      // End of import descriptors (all zeros)
      if (iltRva === 0 && nameRva === 0 && iatRva === 0) break;

      // Read DLL name
      const nameOff = this._rvaToOffset(nameRva, sections);
      const dllName = (nameOff < bytes.length) ? this._str(bytes, nameOff, 256) : '(unknown)';

      // Read imported functions from ILT (or IAT if ILT is 0)
      const lookupRva = iltRva || iatRva;
      const lookupOff = this._rvaToOffset(lookupRva, sections);
      const functions = [];
      const maxFuncs = 4096; // Safety limit

      if (lookupOff < bytes.length) {
        const entrySize = is64 ? 8 : 4;
        const ordFlag = is64 ? 0x8000000000000000 : 0x80000000;

        for (let f = 0; f < maxFuncs; f++) {
          const fOff = lookupOff + f * entrySize;
          if (fOff + entrySize > bytes.length) break;

          let entry;
          if (is64) {
            entry = this._u64(bytes, fOff);
          } else {
            entry = this._u32(bytes, fOff);
          }
          if (entry === 0) break;

          if (is64 ? (entry >= ordFlag) : (entry & ordFlag)) {
            // Import by ordinal
            const ordinal = entry & 0xFFFF;
            functions.push({ name: `Ordinal #${ordinal}`, ordinal, isSuspicious: false });
          } else {
            // Import by name
            const hintRva = is64 ? (entry & 0x7FFFFFFF) : (entry & 0x7FFFFFFF);
            const hintOff = this._rvaToOffset(hintRva, sections);
            if (hintOff + 2 < bytes.length) {
              const funcName = this._str(bytes, hintOff + 2, 256);
              const suspiciousInfo = PeRenderer.SUSPICIOUS_APIS[funcName] || null;
              functions.push({ name: funcName, isSuspicious: !!suspiciousInfo, suspiciousInfo });
            }
          }
        }
      }

      imports.push({ dllName, functions });
      descOff += 20;
    }

    return imports;
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Export Table parser
  // ═══════════════════════════════════════════════════════════════════════

  _parseExports(bytes, dataDirs, sections) {
    if (!dataDirs[0] || dataDirs[0].rva === 0 || dataDirs[0].size === 0) return null;

    const expOff = this._rvaToOffset(dataDirs[0].rva, sections);
    if (expOff + 40 > bytes.length) return null;

    const nameRva = this._u32(bytes, expOff + 12);
    const ordinalBase = this._u32(bytes, expOff + 16);
    const numFunctions = this._u32(bytes, expOff + 20);
    const numNames = this._u32(bytes, expOff + 24);
    const funcRva = this._u32(bytes, expOff + 28);
    const nameRvaTable = this._u32(bytes, expOff + 32);
    const ordinalRvaTable = this._u32(bytes, expOff + 36);

    const nameOff = this._rvaToOffset(nameRva, sections);
    const dllName = (nameOff < bytes.length) ? this._str(bytes, nameOff, 256) : '(unknown)';

    const names = [];
    const namesOff = this._rvaToOffset(nameRvaTable, sections);
    const ordinalsOff = this._rvaToOffset(ordinalRvaTable, sections);

    const maxNames = Math.min(numNames, 4096);
    for (let i = 0; i < maxNames; i++) {
      const nOff = namesOff + i * 4;
      if (nOff + 4 > bytes.length) break;
      const nRva = this._u32(bytes, nOff);
      const nFileOff = this._rvaToOffset(nRva, sections);
      const funcName = (nFileOff < bytes.length) ? this._str(bytes, nFileOff, 256) : '';

      let ordinal = ordinalBase;
      const oOff = ordinalsOff + i * 2;
      if (oOff + 2 <= bytes.length) {
        ordinal = this._u16(bytes, oOff) + ordinalBase;
      }

      names.push({ name: funcName, ordinal });
    }

    return { dllName, ordinalBase, numFunctions, numNames, names };
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Resource Directory parser (top-level enumeration)
  // ═══════════════════════════════════════════════════════════════════════

  _parseResources(bytes, dataDirs, sections) {
    if (!dataDirs[2] || dataDirs[2].rva === 0 || dataDirs[2].size === 0) return [];

    const resOff = this._rvaToOffset(dataDirs[2].rva, sections);
    if (resOff + 16 > bytes.length) return [];

    const resources = [];
    try {
      const numNamed = this._u16(bytes, resOff + 12);
      const numId = this._u16(bytes, resOff + 14);
      const total = numNamed + numId;

      for (let i = 0; i < total && i < 64; i++) {
        const entryOff = resOff + 16 + i * 8;
        if (entryOff + 8 > bytes.length) break;

        const id = this._u32(bytes, entryOff);
        const dataOrDir = this._u32(bytes, entryOff + 4);
        const isDir = !!(dataOrDir & 0x80000000);

        let typeName;
        if (id & 0x80000000) {
          // Named resource — read name string
          const nameOff = resOff + (id & 0x7FFFFFFF);
          if (nameOff + 2 < bytes.length) {
            const nameLen = this._u16(bytes, nameOff);
            typeName = '';
            for (let c = 0; c < nameLen && nameOff + 2 + c * 2 + 1 < bytes.length; c++) {
              typeName += String.fromCharCode(this._u16(bytes, nameOff + 2 + c * 2));
            }
          } else {
            typeName = 'Named(' + (id & 0x7FFFFFFF) + ')';
          }
        } else {
          typeName = PeRenderer.RES_TYPE[id] || 'Type ' + id;
        }

        // Count sub-entries if this is a directory
        let count = 0;
        if (isDir) {
          const subDirOff = resOff + (dataOrDir & 0x7FFFFFFF);
          if (subDirOff + 16 <= bytes.length) {
            count = this._u16(bytes, subDirOff + 12) + this._u16(bytes, subDirOff + 14);
          }
        }

        resources.push({ id: id & 0x7FFFFFFF, typeName, isDir, count });
      }
    } catch (e) { /* resource parsing is best-effort */ }

    return resources;
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  String extraction (ASCII + Unicode)
  // ═══════════════════════════════════════════════════════════════════════

  _extractStrings(bytes, minLen) {
    const strings = { ascii: [], unicode: [] };
    const maxStrings = 10000;
    const maxScan = Math.min(bytes.length, 8 * 1024 * 1024); // Cap at 8MB scan

    // ASCII strings
    let current = '';
    for (let i = 0; i < maxScan && strings.ascii.length < maxStrings; i++) {
      const b = bytes[i];
      if (b >= 0x20 && b < 0x7F) {
        current += String.fromCharCode(b);
      } else {
        if (current.length >= minLen) strings.ascii.push(current);
        current = '';
      }
    }
    if (current.length >= minLen && strings.ascii.length < maxStrings) strings.ascii.push(current);

    // Unicode (UTF-16LE) strings
    let ucurrent = '';
    for (let i = 0; i < maxScan - 1 && strings.unicode.length < maxStrings; i += 2) {
      const c = bytes[i] | (bytes[i + 1] << 8);
      if (c >= 0x20 && c < 0x7F) {
        ucurrent += String.fromCharCode(c);
      } else {
        if (ucurrent.length >= minLen && !strings.ascii.includes(ucurrent)) {
          strings.unicode.push(ucurrent);
        }
        ucurrent = '';
      }
    }
    if (ucurrent.length >= minLen && !strings.ascii.includes(ucurrent) && strings.unicode.length < maxStrings) {
      strings.unicode.push(ucurrent);
    }

    return strings;
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Debug Directory parser (PDB path extraction)
  // ═══════════════════════════════════════════════════════════════════════

  _parseDebugDirectory(bytes, dataDirs, sections) {
    if (!dataDirs[6] || dataDirs[6].rva === 0 || dataDirs[6].size === 0) return null;
    try {
      const off = this._rvaToOffset(dataDirs[6].rva, sections);
      const numEntries = Math.floor(dataDirs[6].size / 28);

      for (let i = 0; i < numEntries && i < 16; i++) {
        const eo = off + i * 28;
        if (eo + 28 > bytes.length) break;
        const type = this._u32(bytes, eo + 12);
        if (type !== 2) continue; // IMAGE_DEBUG_TYPE_CODEVIEW only

        const dataSize = this._u32(bytes, eo + 16);
        const dataOff = this._u32(bytes, eo + 24); // PointerToRawData (file offset)
        if (dataOff + 4 > bytes.length || dataSize < 24) continue;

        const sig = this._u32(bytes, dataOff);
        if (sig === 0x53445352) { // "RSDS" — PDB 7.0
          const go = dataOff + 4;
          const d1 = this._u32(bytes, go).toString(16).padStart(8, '0');
          const d2 = this._u16(bytes, go + 4).toString(16).padStart(4, '0');
          const d3 = this._u16(bytes, go + 6).toString(16).padStart(4, '0');
          let d4 = '';
          for (let j = 0; j < 2; j++) d4 += bytes[go + 8 + j].toString(16).padStart(2, '0');
          let d5 = '';
          for (let j = 2; j < 8; j++) d5 += bytes[go + 8 + j].toString(16).padStart(2, '0');
          const guid = (d1 + '-' + d2 + '-' + d3 + '-' + d4 + '-' + d5).toUpperCase();
          const age = this._u32(bytes, dataOff + 20);
          const pdbPath = this._str(bytes, dataOff + 24, Math.min(dataSize - 24, 260));
          return { pdbPath, guid, age };
        }
        if (sig === 0x3031424E) { // "NB10" — PDB 2.0
          const pdbPath = this._str(bytes, dataOff + 16, Math.min(dataSize - 16, 260));
          return { pdbPath, guid: null, age: this._u32(bytes, dataOff + 8) };
        }
      }
    } catch (e) { /* best-effort */ }
    return null;
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Version Info parser (OriginalFilename, ProductName, etc.)
  // ═══════════════════════════════════════════════════════════════════════

  _parseVersionInfo(bytes, dataDirs, sections) {
    if (!dataDirs[2] || dataDirs[2].rva === 0) return null;
    try {
      const resBase = this._rvaToOffset(dataDirs[2].rva, sections);
      if (resBase + 16 > bytes.length) return null;

      // Level 1: find RT_VERSION (type 16)
      const l1Named = this._u16(bytes, resBase + 12);
      const l1Id = this._u16(bytes, resBase + 14);
      let vDirOff = -1;
      for (let i = 0; i < l1Named + l1Id && i < 64; i++) {
        const eo = resBase + 16 + i * 8;
        if (eo + 8 > bytes.length) break;
        const id = this._u32(bytes, eo) & 0x7FFFFFFF;
        const data = this._u32(bytes, eo + 4);
        if (id === 16 && (data & 0x80000000)) { vDirOff = resBase + (data & 0x7FFFFFFF); break; }
      }
      if (vDirOff < 0 || vDirOff + 16 > bytes.length) return null;

      // Navigate level 2 → level 3 → data entry
      const walkToLeaf = (dirOff) => {
        if (dirOff + 16 > bytes.length) return null;
        const n = this._u16(bytes, dirOff + 12) + this._u16(bytes, dirOff + 14);
        if (n === 0) return null;
        const d = this._u32(bytes, dirOff + 16 + 4);
        if (d & 0x80000000) return walkToLeaf(resBase + (d & 0x7FFFFFFF));
        // Data entry: RVA(4) + Size(4) + CodePage(4) + Reserved(4)
        const deOff = resBase + d;
        if (deOff + 16 > bytes.length) return null;
        return { rva: this._u32(bytes, deOff), size: this._u32(bytes, deOff + 4) };
      };

      const leaf = walkToLeaf(vDirOff);
      if (!leaf) return null;
      const dataOff = this._rvaToOffset(leaf.rva, sections);
      return this._parseVsVersionStrings(bytes, dataOff, Math.min(leaf.size, 8192));
    } catch (e) { return null; }
  }

  _parseVsVersionStrings(bytes, off, size) {
    if (off + 6 > bytes.length) return null;
    const end = Math.min(off + size, bytes.length);
    const result = {};
    const props = [
      'CompanyName', 'FileDescription', 'FileVersion', 'InternalName',
      'LegalCopyright', 'OriginalFilename', 'ProductName', 'ProductVersion',
    ];
    for (const prop of props) {
      const val = this._findVersionString(bytes, off, end, prop);
      if (val) result[prop] = val;
    }
    return Object.keys(result).length > 0 ? result : null;
  }

  _findVersionString(bytes, start, end, name) {
    // Build UTF-16LE search needle for the property name
    const needle = new Uint8Array(name.length * 2 + 2);
    for (let i = 0; i < name.length; i++) { needle[i * 2] = name.charCodeAt(i); needle[i * 2 + 1] = 0; }
    // null terminator already zero-filled

    for (let i = start; i < end - needle.length; i++) {
      let match = true;
      for (let j = 0; j < needle.length; j++) {
        if (bytes[i + j] !== needle[j]) { match = false; break; }
      }
      if (!match) continue;

      // Found name — skip past it + null terminator, align to DWORD
      let vo = i + needle.length;
      if (vo % 4 !== 0) vo += 4 - (vo % 4);
      if (vo >= end) return null;

      // Read UTF-16LE value
      let val = '';
      for (let k = vo; k < end - 1 && val.length < 512; k += 2) {
        const c = bytes[k] | (bytes[k + 1] << 8);
        if (c === 0) break;
        if (c >= 0x20 && c < 0xFFFE) val += String.fromCharCode(c);
      }
      return val.trim() || null;
    }
    return null;
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Import Hash (Imphash) computation
  // ═══════════════════════════════════════════════════════════════════════

  _computeImphash(imports) {
    if (!imports || imports.length === 0) return null;
    const parts = [];
    for (const imp of imports) {
      const dll = imp.dllName.toLowerCase().replace(/\.(dll|ocx|sys)$/i, '');
      for (const fn of imp.functions) {
        if (fn.ordinal !== undefined && fn.name.startsWith('Ordinal #')) {
          parts.push(dll + '.ord' + fn.ordinal);
        } else {
          parts.push(dll + '.' + fn.name.toLowerCase());
        }
      }
    }
    if (parts.length === 0) return null;
    return this._md5(parts.join(','));
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  MD5 (for imphash — compact RFC 1321 implementation)
  // ═══════════════════════════════════════════════════════════════════════

  _md5(str) {
    const cmn = (q, a, b, x, s, t) => { a = (a + q + x + t) | 0; return (((a << s) | (a >>> (32 - s))) + b) | 0; };
    const ff = (a, b, c, d, x, s, t) => cmn((b & c) | (~b & d), a, b, x, s, t);
    const gg = (a, b, c, d, x, s, t) => cmn((b & d) | (c & ~d), a, b, x, s, t);
    const hh = (a, b, c, d, x, s, t) => cmn(b ^ c ^ d, a, b, x, s, t);
    const ii = (a, b, c, d, x, s, t) => cmn(c ^ (b | ~d), a, b, x, s, t);

    // Convert to bytes (ASCII-safe for imphash input)
    const n = str.length;
    const buf = new Uint8Array(((n + 72) >>> 6) << 6); // padded to 64-byte blocks
    for (let i = 0; i < n; i++) buf[i] = str.charCodeAt(i) & 0xFF;
    buf[n] = 0x80;
    const bits = n * 8;
    const lenOff = buf.length - 8;
    buf[lenOff] = bits & 0xFF; buf[lenOff + 1] = (bits >>> 8) & 0xFF;
    buf[lenOff + 2] = (bits >>> 16) & 0xFF; buf[lenOff + 3] = (bits >>> 24) & 0xFF;
    // High 32 bits of length stay 0 (fine for strings < 512 MB)

    let a0 = 0x67452301, b0 = 0xEFCDAB89 | 0, c0 = 0x98BADCFE | 0, d0 = 0x10325476;

    for (let i = 0; i < buf.length; i += 64) {
      const w = new Int32Array(16);
      for (let j = 0; j < 16; j++) w[j] = buf[i+j*4] | (buf[i+j*4+1]<<8) | (buf[i+j*4+2]<<16) | (buf[i+j*4+3]<<24);
      let a = a0, b = b0, c = c0, d = d0;
      a=ff(a,b,c,d,w[0],7,-680876936);d=ff(d,a,b,c,w[1],12,-389564586);
      c=ff(c,d,a,b,w[2],17,606105819);b=ff(b,c,d,a,w[3],22,-1044525330);
      a=ff(a,b,c,d,w[4],7,-176418897);d=ff(d,a,b,c,w[5],12,1200080426);
      c=ff(c,d,a,b,w[6],17,-1473231341);b=ff(b,c,d,a,w[7],22,-45705983);
      a=ff(a,b,c,d,w[8],7,1770035416);d=ff(d,a,b,c,w[9],12,-1958414417);
      c=ff(c,d,a,b,w[10],17,-42063);b=ff(b,c,d,a,w[11],22,-1990404162);
      a=ff(a,b,c,d,w[12],7,1804603682);d=ff(d,a,b,c,w[13],12,-40341101);
      c=ff(c,d,a,b,w[14],17,-1502002290);b=ff(b,c,d,a,w[15],22,1236535329);
      a=gg(a,b,c,d,w[1],5,-165796510);d=gg(d,a,b,c,w[6],9,-1069501632);
      c=gg(c,d,a,b,w[11],14,643717713);b=gg(b,c,d,a,w[0],20,-373897302);
      a=gg(a,b,c,d,w[5],5,-701558691);d=gg(d,a,b,c,w[10],9,38016083);
      c=gg(c,d,a,b,w[15],14,-660478335);b=gg(b,c,d,a,w[4],20,-405537848);
      a=gg(a,b,c,d,w[9],5,568446438);d=gg(d,a,b,c,w[14],9,-1019803690);
      c=gg(c,d,a,b,w[3],14,-187363961);b=gg(b,c,d,a,w[8],20,1163531501);
      a=gg(a,b,c,d,w[13],5,-1444681467);d=gg(d,a,b,c,w[2],9,-51403784);
      c=gg(c,d,a,b,w[7],14,1735328473);b=gg(b,c,d,a,w[12],20,-1926607734);
      a=hh(a,b,c,d,w[5],4,-378558);d=hh(d,a,b,c,w[8],11,-2022574463);
      c=hh(c,d,a,b,w[11],16,1839030562);b=hh(b,c,d,a,w[14],23,-35309556);
      a=hh(a,b,c,d,w[1],4,-1530992060);d=hh(d,a,b,c,w[4],11,1272893353);
      c=hh(c,d,a,b,w[7],16,-155497632);b=hh(b,c,d,a,w[10],23,-1094730640);
      a=hh(a,b,c,d,w[13],4,681279174);d=hh(d,a,b,c,w[0],11,-358537222);
      c=hh(c,d,a,b,w[3],16,-722521979);b=hh(b,c,d,a,w[6],23,76029189);
      a=hh(a,b,c,d,w[9],4,-640364487);d=hh(d,a,b,c,w[12],11,-421815835);
      c=hh(c,d,a,b,w[15],16,530742520);b=hh(b,c,d,a,w[2],23,-995338651);
      a=ii(a,b,c,d,w[0],6,-198630844);d=ii(d,a,b,c,w[7],10,1126891415);
      c=ii(c,d,a,b,w[14],15,-1416354905);b=ii(b,c,d,a,w[5],21,-57434055);
      a=ii(a,b,c,d,w[12],6,1700485571);d=ii(d,a,b,c,w[3],10,-1894986606);
      c=ii(c,d,a,b,w[10],15,-1051523);b=ii(b,c,d,a,w[1],21,-2054922799);
      a=ii(a,b,c,d,w[8],6,1873313359);d=ii(d,a,b,c,w[15],10,-30611744);
      c=ii(c,d,a,b,w[6],15,-1560198380);b=ii(b,c,d,a,w[13],21,1309151649);
      a=ii(a,b,c,d,w[4],6,-145523070);d=ii(d,a,b,c,w[11],10,-1120210379);
      c=ii(c,d,a,b,w[2],15,718787259);b=ii(b,c,d,a,w[9],21,-343485551);
      a0 = (a0+a)|0; b0 = (b0+b)|0; c0 = (c0+c)|0; d0 = (d0+d)|0;
    }

    const hex = v => { let s=''; for(let i=0;i<4;i++) s+=((v>>>(i*8))&0xFF).toString(16).padStart(2,'0'); return s; };
    return hex(a0) + hex(b0) + hex(c0) + hex(d0);
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Flag decoder helper
  // ═══════════════════════════════════════════════════════════════════════

  _decodeFlags(value, flagMap) {
    const flags = [];
    for (const [bit, label] of Object.entries(flagMap)) {
      if (value & Number(bit)) flags.push(label);
    }
    return flags;
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  DOM render
  // ═══════════════════════════════════════════════════════════════════════

  render(buffer, fileName) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    this._bytes = bytes;
    const wrap = document.createElement('div');
    wrap.className = 'pe-view';

    try {
      const pe = this._parse(bytes);
      this._lastStrings = [...pe.strings.ascii, ...pe.strings.unicode];

      // ── Banner ─────────────────────────────────────────────────────
      const banner = document.createElement('div');
      banner.className = 'doc-extraction-banner';
      const bType = pe.coff.isDLL ? 'DLL' : pe.coff.isSystem ? 'System Driver' : 'Executable';
      const bArch = pe.optional.magicStr;
      banner.innerHTML = `<strong>PE Analysis — ${this._esc(bType)}</strong> ` +
        `<span class="doc-meta-tag">${this._esc(bArch)}</span> ` +
        `<span class="doc-meta-tag">${this._esc(pe.coff.machineStr)}</span> ` +
        `<span class="doc-meta-tag">${pe.sections.length} sections</span> ` +
        `<span class="doc-meta-tag">${pe.imports.length} imported DLLs</span>` +
        (pe.exports ? ` <span class="doc-meta-tag">${pe.exports.numNames} exports</span>` : '');
      wrap.appendChild(banner);

      // ── File Headers ───────────────────────────────────────────────
      wrap.appendChild(this._renderSection('📋 PE Headers', this._renderHeaders(pe)));

      // ── Security Features ──────────────────────────────────────────
      wrap.appendChild(this._renderSection('🛡 Security Features', this._renderSecurity(pe)));

      // ── Section Table ──────────────────────────────────────────────
      wrap.appendChild(this._renderSection('📦 Sections (' + pe.sections.length + ')', this._renderSections(pe)));

      // ── Imports ────────────────────────────────────────────────────
      if (pe.imports.length > 0) {
        const totalFuncs = pe.imports.reduce((s, d) => s + d.functions.length, 0);
        wrap.appendChild(this._renderSection(
          '📥 Imports (' + pe.imports.length + ' DLLs, ' + totalFuncs + ' functions)',
          this._renderImports(pe),
          totalFuncs
        ));
      }

      // ── Exports ────────────────────────────────────────────────────
      if (pe.exports && pe.exports.names.length > 0) {
        wrap.appendChild(this._renderSection(
          '📤 Exports (' + pe.exports.names.length + ')',
          this._renderExports(pe),
          pe.exports.names.length
        ));
      }

      // ── Resources ──────────────────────────────────────────────────
      if (pe.resources.length > 0) {
        wrap.appendChild(this._renderSection('🗂 Resources (' + pe.resources.length + ' types)', this._renderResources(pe)));
      }

      // ── Rich Header ────────────────────────────────────────────────
      if (pe.richHeader && pe.richHeader.entries.length > 0) {
        wrap.appendChild(this._renderSection('🔑 Rich Header (' + pe.richHeader.entries.length + ' entries)', this._renderRichHeader(pe)));
      }

      // ── Authenticode Certificates ──────────────────────────────────
      if (pe.certificates && pe.certificates.length > 0) {
        wrap.appendChild(this._renderSection(
          '📜 Authenticode Certificates (' + pe.certificates.length + ')',
          this._renderCertificates(pe.certificates)
        ));
      }

      // ── Data Directories ───────────────────────────────────────────
      wrap.appendChild(this._renderSection('📂 Data Directories', this._renderDataDirs(pe)));

      // ── Strings ────────────────────────────────────────────────────
      const totalStrings = pe.strings.ascii.length + pe.strings.unicode.length;
      if (totalStrings > 0) {
        wrap.appendChild(this._renderSection(
          '🔤 Strings (' + totalStrings + ')',
          this._renderStrings(pe)
        ));
      }

    } catch (err) {
      this._renderFallback(wrap, bytes, err, fileName);
    }

    // Expose extracted strings as _rawText for IOC + EncodedContentDetector.
    // On parse failure we still populate this from the fallback string scan
    // so sidebar YARA / IOC extraction keep working on truncated binaries.
    if (this._lastStrings) {
      wrap._rawText = this._lastStrings.join('\n');
    } else if (wrap._fallbackStrings) {
      wrap._rawText = wrap._fallbackStrings.join('\n');
    }

    return wrap;
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Fallback view — used when PE parsing fails (truncated/malformed files).
  //  Still shows extracted strings + a raw hex dump so IOC/YARA scans work.
  // ═══════════════════════════════════════════════════════════════════════

  _renderFallback(wrap, bytes, err, fileName) {
    const notice = document.createElement('div');
    notice.className = 'bin-fallback-notice';
    const magic = bytes.length >= 4
      ? Array.from(bytes.slice(0, 4)).map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ')
      : '—';
    notice.innerHTML =
      `<div class="bin-fallback-title"><strong>⚠ PE parsing failed — showing raw fallback view</strong></div>` +
      `<div class="bin-fallback-reason"><code>${this._esc(err.message)}</code></div>` +
      `<div class="bin-fallback-sub">The file appears to be truncated or malformed, so structural ` +
      `analysis (headers, imports, sections, …) isn't available. Extracted strings and a raw hex ` +
      `dump are shown below so IOC extraction and YARA rules can still run against the bytes.</div>` +
      `<div class="bin-fallback-info">` +
        `<span class="doc-meta-tag">${this._esc(fileName || 'unknown')}</span> ` +
        `<span class="doc-meta-tag">${bytes.length.toLocaleString()} bytes</span> ` +
        `<span class="doc-meta-tag">Magic: ${magic}</span>` +
      `</div>`;
    wrap.appendChild(notice);

    // Strings — reuse the normal extractor; it only needs the raw byte buffer.
    const strings = this._extractStrings(bytes, 6);
    const totalStrings = strings.ascii.length + strings.unicode.length;
    this._lastStrings = [...strings.ascii, ...strings.unicode];
    wrap._fallbackStrings = this._lastStrings;
    if (totalStrings > 0) {
      wrap.appendChild(this._renderSection(
        '🔤 Strings (' + totalStrings + ')',
        this._renderStrings({ strings })
      ));
    }

    // Raw hex dump (existing helper auto-caps at 4 KB with a Show-more button).
    if (bytes.length > 0) {
      const hexContent = document.createElement('div');
      hexContent.appendChild(this._renderHexDump(0, bytes.length));
      wrap.appendChild(this._renderSection(
        '📄 Raw Hex Dump (' + bytes.length.toLocaleString() + ' bytes)',
        hexContent
      ));
    }
  }


  // ═══════════════════════════════════════════════════════════════════════
  //  Section renderers (DOM builders)
  // ═══════════════════════════════════════════════════════════════════════

  _renderSection(title, contentEl, rowCount) {
    const sec = document.createElement('details');
    sec.className = 'pe-section';
    const collapse = rowCount && rowCount > 50;
    sec.open = !collapse;
    const sum = document.createElement('summary');
    sum.innerHTML = this._esc(title) + (collapse ? ` <span class="bin-collapse-note">${rowCount} rows — click to expand</span>` : '');
    sec.appendChild(sum);
    sec.appendChild(contentEl);
    return sec;
  }

  _renderHeaders(pe) {
    const rows = [
      ['Type', pe.coff.isDLL ? 'Dynamic Link Library (DLL)' : pe.coff.isSystem ? 'System Driver' : 'Executable'],
      ['Architecture', pe.optional.magicStr],
      ['Machine', pe.coff.machineStr],
      ['Entry Point', this._hex(pe.optional.entryPoint, 8)],
      ['Image Base', this._hex(pe.optional.imageBase, pe.is64 ? 16 : 8)],
      ['Linker Version', pe.optional.linkerStr],
      ['Timestamp', pe.coff.timestampStr],
      ['Subsystem', pe.optional.subsystemStr],
      ['Size of Image', (pe.optional.sizeOfImage || 0).toLocaleString() + ' bytes'],
      ['Size of Code', (pe.optional.sizeOfCode || 0).toLocaleString() + ' bytes'],
      ['Checksum', this._hex(pe.optional.checksum, 8)],
      ['Sections', pe.coff.numSections.toString()],
      ['COFF Flags', pe.coff.characteristicsFlags.join(', ') || 'None'],
      ['DLL Characteristics', pe.optional.dllCharFlags.join(', ') || 'None'],
    ];
    return this._buildTable(['Field', 'Value'], rows);
  }

  _renderSecurity(pe) {
    const s = pe.security;
    const features = [
      ['ASLR (Address Space Layout Randomization)', s.aslr, 'Randomizes memory addresses to prevent exploitation'],
      ['High Entropy ASLR', s.highEntropyAslr, 'Uses full 64-bit address space for ASLR'],
      ['DEP / NX (Data Execution Prevention)', s.dep, 'Prevents code execution from data pages'],
      ['CFG (Control Flow Guard)', s.cfg, 'Validates indirect call targets'],
      ['SEH Protection', s.noSeh, 'Exception handler overwrite protection (NO_SEH flag)'],
      ['Force Integrity', s.forceIntegrity, 'Requires code signing verification at load time'],
      ['AppContainer', s.appContainer, 'Runs in AppContainer sandbox'],
    ];

    // Check for authenticode (Certificate Table data directory)
    const hasCert = pe.dataDirectories[4] && pe.dataDirectories[4].rva !== 0 && pe.dataDirectories[4].size !== 0;

    const div = document.createElement('div');
    div.className = 'pe-security-grid';

    for (const [name, enabled, desc] of features) {
      const row = document.createElement('div');
      row.className = 'pe-sec-row' + (enabled ? ' pe-sec-on' : ' pe-sec-off');
      row.innerHTML = `<span class="pe-sec-icon">${enabled ? '✅' : '❌'}</span>` +
        `<span class="pe-sec-name">${this._esc(name)}</span>` +
        `<span class="pe-sec-desc">${this._esc(desc)}</span>`;
      div.appendChild(row);
    }

    // Authenticode
    const certRow = document.createElement('div');
    certRow.className = 'pe-sec-row' + (hasCert ? ' pe-sec-on' : ' pe-sec-off');
    certRow.innerHTML = `<span class="pe-sec-icon">${hasCert ? '✅' : '⚠️'}</span>` +
      `<span class="pe-sec-name">Authenticode Signature</span>` +
      `<span class="pe-sec-desc">${hasCert ? 'Digital signature present (Certificate Table exists)' : 'No digital signature detected'}</span>`;
    div.appendChild(certRow);

    return div;
  }

  _renderSections(pe) {
    const frag = document.createElement('div');

    const rows = pe.sections.map(s => {
      const flags = [];
      if (s.isReadable) flags.push('R');
      if (s.isWritable) flags.push('W');
      if (s.isExecutable) flags.push('X');

      const anomalies = [];
      if (s.isWritable && s.isExecutable) anomalies.push('⚠️ W+X');
      if (s.entropy > 7.0) anomalies.push('🔒 High entropy (packed?)');
      if (s.packerMatch) anomalies.push('📦 ' + s.packerMatch);

      return [
        s.name || '(empty)',
        this._hex(s.virtualAddress, 8),
        s.virtualSize.toLocaleString(),
        s.rawDataSize.toLocaleString(),
        flags.join(''),
        this._renderEntropyBar(s.entropy),
        anomalies.join(' '),
      ];
    });

    const table = this._buildTable(
      ['Name', 'VirtAddr', 'VirtSize', 'RawSize', 'Flags', 'Entropy', 'Anomalies'],
      rows, true
    );

    // Make section rows clickable → inline hex dump
    const tbody = table.querySelector('tbody');
    if (tbody) {
      const trs = Array.from(tbody.querySelectorAll('tr'));
      trs.forEach((tr, i) => {
        const sec = pe.sections[i];
        if (!sec || sec.rawDataSize === 0) return;
        tr.classList.add('bin-clickable');
        tr.addEventListener('click', () => {
          const next = tr.nextElementSibling;
          if (next && next.classList.contains('bin-hexdump-row')) {
            next.remove();
            tr.classList.remove('bin-expanded');
          } else {
            const hexRow = document.createElement('tr');
            hexRow.className = 'bin-hexdump-row';
            const td = document.createElement('td');
            td.colSpan = 7;
            td.appendChild(this._renderHexDump(sec.rawDataOffset, sec.rawDataSize));
            hexRow.appendChild(td);
            tr.after(hexRow);
            tr.classList.add('bin-expanded');
          }
        });
      });
    }

    frag.appendChild(table);
    return frag;
  }

  _renderEntropyBar(entropy) {
    // Returns an HTML string for inline use in table
    const pct = Math.min(entropy / 8 * 100, 100);
    const color = entropy > 7.0 ? '#e74c3c' : entropy > 6.0 ? '#f39c12' : '#27ae60';
    return `<div class="pe-entropy-bar"><div class="pe-entropy-fill" style="width:${pct.toFixed(1)}%;background:${color}"></div></div>` +
      `<span class="pe-entropy-val">${entropy.toFixed(3)}</span>`;
  }

  _renderImports(pe) {
    const div = document.createElement('div');
    div.className = 'pe-imports';

    // Search bar filters DLL-level <details> elements; risk toggle shows only DLLs with suspicious imports
    this._addSearchBar(div, () => Array.from(div.querySelectorAll('.pe-import-dll')), 'Filter imports…', '.pe-import-warn');

    for (const imp of pe.imports) {
      const detail = document.createElement('details');
      detail.className = 'pe-import-dll';

      const suspCount = imp.functions.filter(f => f.isSuspicious).length;
      const sum = document.createElement('summary');
      sum.innerHTML = `<strong>${this._esc(imp.dllName)}</strong>` +
        ` <span class="pe-import-count">(${imp.functions.length} functions)</span>` +
        (suspCount > 0 ? ` <span class="pe-import-warn">⚠️ ${suspCount} suspicious</span>` : '');
      detail.appendChild(sum);

      if (imp.functions.length > 0) {
        const list = document.createElement('div');
        list.className = 'pe-import-list';

        for (const fn of imp.functions) {
          const item = document.createElement('span');
          item.className = 'pe-import-func' + (fn.isSuspicious ? ' pe-suspicious' : '');
          item.textContent = fn.name;
          if (fn.isSuspicious) {
            item.title = '';
            item.style.cursor = 'pointer';
            item.addEventListener('click', (e) => {
              e.stopPropagation();
              // Remove any existing tooltip globally
              const old = document.querySelector('.bin-tooltip');
              if (old) { const wasThis = old._forFunc === fn.name; old.remove(); if (wasThis) return; }
              const cat = this._categorizeApi(fn.name);
              const detail = PeRenderer.SUSPICIOUS_APIS_DETAIL[fn.name];
              const tip = document.createElement('div');
              tip.className = 'bin-tooltip';
              tip._forFunc = fn.name;

              // Build enriched tooltip content
              let html = `<strong>${this._esc(fn.name)}</strong>`;
              if (cat) html += ` <span class="bin-info-card-cat ${cat.cls}">${this._esc(cat.cat)}</span>`;
              if (detail) {
                html += `<div class="bin-tooltip-section"><span class="bin-tooltip-label">What it does</span>${this._esc(detail.desc)}</div>`;
                html += `<div class="bin-tooltip-section"><span class="bin-tooltip-label">⚠ Why suspicious</span>${this._esc(detail.context)}</div>`;
                if (detail.mitre) html += `<div class="bin-tooltip-mitre">🔗 MITRE ATT&CK: ${this._esc(detail.mitre)}</div>`;
              } else {
                html += `<div class="bin-tooltip-desc">${this._esc(fn.suspiciousInfo)}</div>`;
              }
              tip.innerHTML = html;

              // Use fixed positioning to avoid clipping by parent overflow
              document.body.appendChild(tip);
              const rect = item.getBoundingClientRect();
              const tipH = tip.offsetHeight;
              const tipW = tip.offsetWidth;
              let top = rect.bottom + 6;
              let left = rect.left;
              let flipped = false;
              // Flip above if it would overflow viewport bottom
              if (top + tipH > window.innerHeight - 8) {
                top = rect.top - tipH - 6;
                flipped = true;
              }
              // Keep within horizontal bounds
              if (left + tipW > window.innerWidth - 8) left = window.innerWidth - tipW - 8;
              if (left < 8) left = 8;
              tip.style.left = left + 'px';
              tip.style.top = top + 'px';
              if (flipped) tip.classList.add('bin-tooltip-flip');

              // Dismiss on click outside or scroll
              const cleanup = () => { tip.remove(); document.removeEventListener('click', clickDismiss, true); window.removeEventListener('scroll', scrollDismiss, true); };
              const clickDismiss = (ev) => { if (!tip.contains(ev.target) && ev.target !== item) cleanup(); };
              const scrollDismiss = () => cleanup();
              setTimeout(() => document.addEventListener('click', clickDismiss, true), 0);
              window.addEventListener('scroll', scrollDismiss, true);
              const scrollParent = item.closest('.pe-section');
              if (scrollParent) scrollParent.addEventListener('scroll', scrollDismiss, { once: true, capture: true });
            });
          }
          list.appendChild(item);
        }
        detail.appendChild(list);
      }

      // Auto-collapse DLLs with many functions
      if (imp.functions.length > 50) {
        const note = document.createElement('span');
        note.className = 'bin-collapse-note';
        note.textContent = imp.functions.length + ' functions';
        sum.appendChild(document.createTextNode(' '));
        sum.appendChild(note);
      }

      div.appendChild(detail);
    }

    return div;
  }

  _renderExports(pe) {
    const rows = pe.exports.names.map(e => [e.ordinal.toString(), e.name]);
    const div = document.createElement('div');

    const info = document.createElement('div');
    info.className = 'pe-export-info';
    info.textContent = 'DLL Name: ' + pe.exports.dllName + ' | Ordinal Base: ' + pe.exports.ordinalBase +
      ' | Total Functions: ' + pe.exports.numFunctions;
    div.appendChild(info);

    div.appendChild(this._buildTable(['Ordinal', 'Name'], rows));
    return div;
  }

  _renderResources(pe) {
    const rows = pe.resources.map(r => [
      r.typeName,
      r.id.toString(),
      r.count > 0 ? r.count + ' entries' : 'leaf',
    ]);
    return this._buildTable(['Type', 'ID', 'Contents'], rows);
  }

  _renderRichHeader(pe) {
    const div = document.createElement('div');

    const info = document.createElement('div');
    info.className = 'pe-rich-info';
    info.textContent = 'XOR Key: ' + this._hex(pe.richHeader.xorKey, 8);
    div.appendChild(info);

    const rows = pe.richHeader.entries.map(e => [
      e.compId.toString(),
      e.buildId.toString(),
      e.count.toString(),
    ]);
    div.appendChild(this._buildTable(['Comp ID', 'Build ID', 'Count'], rows));
    return div;
  }

  _renderCertificates(certs) {
    const div = document.createElement('div');
    for (let i = 0; i < certs.length; i++) {
      const c = certs[i];
      const label = c.subject.CN || c.subjectStr || '(unnamed)';
      const now = new Date();
      let status = '✅ Valid';
      if (c.notAfter && now > c.notAfter) status = '❌ Expired';
      else if (c.notBefore && now < c.notBefore) status = '⏳ Not Yet Valid';

      let pk = c.publicKeyAlgorithm || '';
      if (c.publicKeySize) pk += ' ' + c.publicKeySize + '-bit';
      if (c.publicKeyCurve) pk += ' (' + c.publicKeyCurve + ')';

      const rows = [
        ['Subject', c.subjectStr || '(empty)'],
        ['Issuer', c.issuerStr || '(empty)'],
        ['Serial', c.serialNumber || '(none)'],
        ['Validity', `${status}  ·  ${c.notBeforeStr || '?'} → ${c.notAfterStr || '?'}`],
        ['Public Key', pk],
        ['Signature', c.signatureAlgorithm || '(unknown)'],
      ];
      if (c.isSelfSigned) rows.push(['Self-Signed', 'Yes']);
      if (c.isCA) rows.push(['CA', 'Yes']);

      // EKU
      const ekuExt = c.extensions.find(e => e.oid === '2.5.29.37');
      if (ekuExt && ekuExt.value) rows.push(['Extended Key Usage', ekuExt.value]);

      // SAN
      const sanExt = c.extensions.find(e => e.oid === '2.5.29.17');
      if (sanExt && sanExt.value) rows.push(['Subject Alt Names', sanExt.value]);

      const header = document.createElement('div');
      header.className = 'pe-rich-info';
      header.textContent = `Certificate ${i + 1}: ${label}`;
      div.appendChild(header);
      div.appendChild(this._buildTable(['Field', 'Value'], rows));
    }
    return div;
  }

  _renderDataDirs(pe) {
    const rows = pe.dataDirectories.map(dd => [
      dd.name,
      dd.rva === 0 ? '—' : this._hex(dd.rva, 8),
      dd.size === 0 ? '—' : dd.size.toLocaleString(),
    ]);
    return this._buildTable(['Directory', 'RVA', 'Size'], rows);
  }

  _renderStrings(pe) {
    const div = document.createElement('div');
    div.className = 'pe-strings';

    // Save/Copy pill group for strings
    const allStrings = [...pe.strings.ascii, ...pe.strings.unicode];
    const pillBar = document.createElement('div');
    pillBar.style.cssText = 'display:flex;align-items:center;gap:6px;margin-bottom:8px;';
    const pillGroup = document.createElement('div');
    pillGroup.className = 'btn-pill-group';
    const saveBtn = document.createElement('button');
    saveBtn.className = 'tb-btn tb-action-btn';
    saveBtn.textContent = '💾 Save';
    saveBtn.title = 'Save strings as .txt';
    saveBtn.addEventListener('click', () => {
      const blob = new Blob([allStrings.join('\n')], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href = url; a.download = 'strings.txt'; a.click();
      URL.revokeObjectURL(url);
    });
    const copyBtn = document.createElement('button');
    copyBtn.className = 'tb-btn tb-action-btn';
    copyBtn.textContent = '📋 Copy';
    copyBtn.title = 'Copy all strings to clipboard';
    copyBtn.addEventListener('click', () => {
      const text = allStrings.join('\n');
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text);
      } else {
        const ta = document.createElement('textarea'); ta.value = text; ta.style.cssText = 'position:fixed;opacity:0';
        document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta);
      }
    });
    pillGroup.appendChild(saveBtn);
    pillGroup.appendChild(copyBtn);
    pillBar.appendChild(pillGroup);
    div.appendChild(pillBar);

    const buildStringList = (strings, label) => {
      const listDiv = document.createElement('div');
      listDiv.className = 'pe-strings-list';
      for (const s of strings) {
        const line = document.createElement('div');
        line.className = 'pe-string-item';
        line.textContent = s;
        listDiv.appendChild(line);
      }

      // Search bar for this string section
      this._addSearchBar(listDiv, () => Array.from(listDiv.querySelectorAll('.pe-string-item')), 'Filter strings…');
      return listDiv;
    };

    // Tabbed interface for ASCII / Unicode strings
    const hasAscii = pe.strings.ascii.length > 0;
    const hasUnicode = pe.strings.unicode.length > 0;
    const tabs = [];
    const panes = [];
    if (hasAscii) {
      tabs.push({ label: `ASCII (${pe.strings.ascii.length})`, key: 'ascii' });
      panes.push(buildStringList(pe.strings.ascii, 'ASCII Strings'));
    }
    if (hasUnicode) {
      tabs.push({ label: `Unicode (${pe.strings.unicode.length})`, key: 'unicode' });
      panes.push(buildStringList(pe.strings.unicode, 'Unicode Strings'));
    }
    if (tabs.length > 1) {
      const tabBar = document.createElement('div');
      tabBar.className = 'bin-tab-bar';
      tabs.forEach((t, i) => {
        const btn = document.createElement('button');
        btn.className = 'bin-tab' + (i === 0 ? ' active' : '');
        btn.textContent = t.label;
        btn.addEventListener('click', () => {
          tabBar.querySelectorAll('.bin-tab').forEach(b => b.classList.remove('active'));
          btn.classList.add('active');
          panes.forEach((p, j) => { p.style.display = j === i ? '' : 'none'; });
        });
        tabBar.appendChild(btn);
      });
      div.appendChild(tabBar);
      panes.forEach((p, i) => { p.style.display = i === 0 ? '' : 'none'; div.appendChild(p); });
    } else {
      panes.forEach(p => div.appendChild(p));
    }

    return div;
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Table builder helper
  // ═══════════════════════════════════════════════════════════════════════

  _buildTable(headers, rows, allowHtml) {
    const table = document.createElement('table');
    table.className = 'pe-table';
    const thead = document.createElement('thead');
    const tr = document.createElement('tr');
    for (const h of headers) {
      const th = document.createElement('th');
      th.textContent = h;
      tr.appendChild(th);
    }
    thead.appendChild(tr);
    table.appendChild(thead);

    const tbody = document.createElement('tbody');
    for (const row of rows) {
      const rtr = document.createElement('tr');
      for (const cell of row) {
        const td = document.createElement('td');
        if (allowHtml && typeof cell === 'string' && cell.includes('<')) {
          td.innerHTML = cell;
        } else {
          td.textContent = String(cell);
        }
        rtr.appendChild(td);
      }
      tbody.appendChild(rtr);
    }
    table.appendChild(tbody);
    return table;
  }

  _esc(s) {
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Interactive helpers — hex dump, search bar, info cards
  // ═══════════════════════════════════════════════════════════════════════

  _renderHexDump(offset, size, maxInitial) {
    maxInitial = maxInitial || 4096;
    const bytes = this._bytes;
    const end = Math.min(offset + size, bytes.length);
    const totalBytes = end - offset;
    if (totalBytes <= 0) {
      const empty = document.createElement('div');
      empty.className = 'bin-hexdump';
      empty.textContent = '(empty section)';
      return empty;
    }

    const container = document.createElement('div');
    let shown = Math.min(totalBytes, maxInitial);

    const buildLines = (start, count) => {
      const frag = document.createDocumentFragment();
      const lineEnd = Math.min(start + count, totalBytes);
      for (let i = start; i < lineEnd; i += 16) {
        const line = document.createElement('div');
        line.className = 'bin-hexdump-line';
        const offSpan = document.createElement('span');
        offSpan.className = 'bin-hexdump-offset';
        offSpan.textContent = (offset + i).toString(16).toUpperCase().padStart(8, '0');
        line.appendChild(offSpan);

        let hexStr = '';
        let ascStr = '';
        for (let j = 0; j < 16; j++) {
          if (i + j < totalBytes) {
            const b = bytes[offset + i + j];
            hexStr += b ? `<span class="bin-nz">${b.toString(16).padStart(2,'0').toUpperCase()}</span> ` : '00 ';
            ascStr += (b >= 0x20 && b < 0x7F) ? String.fromCharCode(b) : '.';
          } else {
            hexStr += '   ';
            ascStr += ' ';
          }
          if (j === 7) hexStr += ' ';
        }
        const hexSpan = document.createElement('span');
        hexSpan.className = 'bin-hexdump-hex';
        hexSpan.innerHTML = hexStr;
        line.appendChild(hexSpan);

        const ascSpan = document.createElement('span');
        ascSpan.className = 'bin-hexdump-ascii';
        ascSpan.textContent = ascStr;
        line.appendChild(ascSpan);
        frag.appendChild(line);
      }
      return frag;
    };

    const dump = document.createElement('div');
    dump.className = 'bin-hexdump';
    dump.appendChild(buildLines(0, shown));
    container.appendChild(dump);

    if (totalBytes > shown) {
      const btn = document.createElement('button');
      btn.className = 'bin-hexdump-show-more';
      btn.textContent = `Show more (${(totalBytes - shown).toLocaleString()} bytes remaining)`;
      btn.addEventListener('click', () => {
        const next = Math.min(shown + 4096, totalBytes);
        dump.appendChild(buildLines(shown, next - shown));
        shown = next;
        if (shown >= totalBytes) btn.remove();
        else btn.textContent = `Show more (${(totalBytes - shown).toLocaleString()} bytes remaining)`;
      });
      container.appendChild(btn);
    }
    return container;
  }

  _addSearchBar(container, getItems, placeholder, riskSelector) {
    const wrap = document.createElement('div');
    wrap.className = 'bin-search-wrap';
    const input = document.createElement('input');
    input.type = 'text';
    input.placeholder = placeholder || 'Search…';
    const count = document.createElement('span');
    count.className = 'bin-search-count';
    wrap.appendChild(input);

    let riskOnly = false;
    let riskBtn = null;
    if (riskSelector) {
      riskBtn = document.createElement('button');
      riskBtn.className = 'bin-risk-toggle';
      riskBtn.textContent = '⚠ Risky';
      riskBtn.title = 'Show only risky/suspicious items';
      wrap.appendChild(riskBtn);
    }

    wrap.appendChild(count);

    const applyFilter = () => {
      const q = input.value.toLowerCase().trim();
      const items = getItems();
      let visible = 0;
      for (const item of items) {
        const text = item.textContent.toLowerCase();
        const matchText = !q || text.includes(q);
        const matchRisk = !riskOnly || item.querySelector(riskSelector) || item.matches(riskSelector);
        const show = matchText && matchRisk;
        item.classList.toggle('bin-hidden', !show);
        if (show) visible++;
      }
      count.textContent = (q || riskOnly) ? `${visible}/${items.length}` : '';
    };

    input.addEventListener('input', applyFilter);
    if (riskBtn) {
      riskBtn.addEventListener('click', () => {
        if (riskBtn.disabled) return;
        riskOnly = !riskOnly;
        riskBtn.classList.toggle('active', riskOnly);
        container.classList.toggle('risk-filter-active', riskOnly);
        applyFilter();
      });
      setTimeout(() => {
        const items = getItems();
        const hasRisky = items.some(item => item.querySelector(riskSelector) || item.matches(riskSelector));
        if (!hasRisky) {
          riskBtn.disabled = true;
          riskBtn.title = 'No risky items detected';
        }
      }, 0);
    }

    container.insertBefore(wrap, container.firstChild);
    return wrap;
  }

  _categorizeApi(name) {
    const info = PeRenderer.SUSPICIOUS_APIS[name];
    if (!info) return null;
    const lower = info.toLowerCase();
    if (/injection|hollowing|remote.*thread|write.*process|apc|hijack|unmap/i.test(lower))
      return { cat: 'Process Injection', cls: 'cat-inject' };
    if (/debug|sandbox|evasion|vm detection|timing/i.test(lower))
      return { cat: 'Anti-Debug / Evasion', cls: 'cat-antidebug' };
    if (/credential|lsa|sam|dpapi/i.test(lower))
      return { cat: 'Credential Theft', cls: 'cat-cred' };
    if (/c2|download|http|internet|winsock|url/i.test(lower))
      return { cat: 'Networking / C2', cls: 'cat-network' };
    if (/ransomware|encrypt|decrypt|crypto|key/i.test(lower))
      return { cat: 'Cryptography', cls: 'cat-crypto' };
    if (/registry|persistence|service/i.test(lower))
      return { cat: 'Persistence', cls: 'cat-file' };
    if (/process creation|shell|exec|command/i.test(lower))
      return { cat: 'Execution', cls: 'cat-exec' };
    if (/dynamic|load.*library|getproc/i.test(lower))
      return { cat: 'Dynamic Loading', cls: 'cat-recon' };
    return { cat: 'Suspicious', cls: 'cat-inject' };
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Security analysis (for sidebar)
  // ═══════════════════════════════════════════════════════════════════════

  analyzeForSecurity(buffer, fileName) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const findings = {
      risk: 'low',
      hasMacros: false,
      macroSize: 0,
      macroHash: '',
      autoExec: [],
      modules: [],
      externalRefs: [],
      metadata: {},
      interestingStrings: [],
      peInfo: null,
    };

    try {
      const pe = this._parse(bytes);
      findings.peInfo = pe;

      const issues = [];
      let riskScore = 0;

      // ── File type context ──────────────────────────────────────────
      const ext = ((fileName || '').split('.').pop() || '').toLowerCase();
      findings.metadata = {
        'Type': pe.coff.isDLL ? 'DLL' : pe.coff.isSystem ? 'Driver' : 'Executable',
        'Architecture': pe.optional.magicStr,
        'Machine': pe.coff.machineStr,
        'Subsystem': pe.optional.subsystemStr,
        'Compiled': pe.coff.timestampStr,
        'Entry Point': this._hex(pe.optional.entryPoint, 8),
        'Linker': pe.optional.linkerStr,
        'Sections': pe.coff.numSections.toString(),
      };

      if (pe.exports) {
        findings.metadata['Export DLL Name'] = pe.exports.dllName;
        findings.metadata['Exported Functions'] = pe.exports.numNames.toString();
      }

      // ── Version info, debug info, imphash ──────────────────────────
      if (pe.versionInfo) {
        if (pe.versionInfo.OriginalFilename) findings.metadata['Original Filename'] = pe.versionInfo.OriginalFilename;
        if (pe.versionInfo.ProductName) findings.metadata['Product Name'] = pe.versionInfo.ProductName;
        if (pe.versionInfo.FileDescription) findings.metadata['File Description'] = pe.versionInfo.FileDescription;
        if (pe.versionInfo.CompanyName) findings.metadata['Company Name'] = pe.versionInfo.CompanyName;
        if (pe.versionInfo.FileVersion) findings.metadata['File Version'] = pe.versionInfo.FileVersion;
        if (pe.versionInfo.ProductVersion) findings.metadata['Product Version'] = pe.versionInfo.ProductVersion;
        if (pe.versionInfo.InternalName) findings.metadata['Internal Name'] = pe.versionInfo.InternalName;
      }
      if (pe.debugInfo && pe.debugInfo.pdbPath) {
        findings.metadata['PDB Path'] = pe.debugInfo.pdbPath;
      }
      if (pe.imphash) {
        findings.metadata['Imphash'] = pe.imphash;
      }

      // ── Security feature checks ────────────────────────────────────
      if (!pe.security.aslr) { issues.push('ASLR disabled — vulnerable to memory exploitation'); riskScore += 1; }
      if (!pe.security.dep) { issues.push('DEP/NX disabled — data pages can execute code'); riskScore += 1; }
      if (!pe.security.cfg) { issues.push('CFG disabled — no control flow integrity'); riskScore += 0.5; }

      const hasCert = pe.dataDirectories[4] && pe.dataDirectories[4].rva !== 0 && pe.dataDirectories[4].size !== 0;
      if (!hasCert) { issues.push('No Authenticode signature'); riskScore += 1; }

      // ── Timestamp anomalies ────────────────────────────────────────
      const ts = pe.coff.timestamp;
      if (ts === 0) { issues.push('Compilation timestamp is epoch zero (likely zeroed)'); riskScore += 1; }
      else if (ts === 0xFFFFFFFF) { issues.push('Compilation timestamp is invalid (0xFFFFFFFF)'); riskScore += 1; }
      else {
        const now = Date.now() / 1000;
        if (ts > now + 86400) { issues.push('Compilation timestamp is in the future'); riskScore += 2; }
        if (ts < 946684800) { issues.push('Compilation timestamp is before year 2000 (possibly forged)'); riskScore += 0.5; }
      }

      // ── Section anomalies ──────────────────────────────────────────
      let packerDetected = false;
      for (const sec of pe.sections) {
        if (sec.isWritable && sec.isExecutable) {
          issues.push(`Section "${sec.name}" is W+X (writable and executable) — code injection risk`);
          riskScore += 2;
        }
        if (sec.entropy > 7.0) {
          issues.push(`Section "${sec.name}" has very high entropy (${sec.entropy.toFixed(3)}) — likely packed or encrypted`);
          riskScore += 1.5;
        }
        if (sec.packerMatch) {
          issues.push(`Section "${sec.name}" matches known packer: ${sec.packerMatch}`);
          packerDetected = true;
          riskScore += 2;
        }
      }

      // Low import count + high entropy = likely packed
      const totalImportFuncs = pe.imports.reduce((s, d) => s + d.functions.length, 0);
      if (totalImportFuncs < 10 && pe.sections.some(s => s.entropy > 6.5)) {
        if (!packerDetected) {
          issues.push('Very few imports (' + totalImportFuncs + ') with high-entropy sections — likely packed');
          riskScore += 2;
        }
      }

      // ── Suspicious imports ─────────────────────────────────────────
      const suspiciousImports = [];
      for (const imp of pe.imports) {
        for (const fn of imp.functions) {
          if (fn.isSuspicious) {
            suspiciousImports.push({ dll: imp.dllName, func: fn.name, info: fn.suspiciousInfo });
          }
        }
      }

      if (suspiciousImports.length > 0) {
        riskScore += Math.min(suspiciousImports.length * 0.5, 5);

        // Categorize suspicious API patterns
        const hasInjection = suspiciousImports.some(s =>
          /injection|hollowing|remote.*thread|WriteProcessMemory/i.test(s.info));
        const hasCredTheft = suspiciousImports.some(s =>
          /credential|LSA|SAM|DPAPI/i.test(s.info));
        const hasAntiDebug = suspiciousImports.some(s =>
          /debug|sandbox|evasion/i.test(s.info));
        const hasNetworking = suspiciousImports.some(s =>
          /C2|download|HTTP|Internet|Winsock/i.test(s.info));
        const hasCrypto = suspiciousImports.some(s =>
          /ransomware|encryption|crypto/i.test(s.info));

        if (hasInjection) { issues.push('Imports process injection APIs (VirtualAlloc/WriteProcessMemory/CreateRemoteThread)'); riskScore += 2; }
        if (hasCredTheft) { issues.push('Imports credential theft APIs'); riskScore += 2; }
        if (hasAntiDebug) { issues.push('Imports anti-debugging / sandbox evasion APIs'); riskScore += 1; }
        if (hasNetworking) { issues.push('Imports networking APIs (C2 / download capability)'); riskScore += 1; }
        if (hasCrypto) { issues.push('Imports cryptographic APIs (potential ransomware)'); riskScore += 1.5; }
      }

      // ── Extract IOCs from strings ──────────────────────────────────
      const allStrings = [...pe.strings.ascii, ...pe.strings.unicode].join('\n');
      const _urlRx = /https?:\/\/[^\s"'<>()\[\]{}\u0000-\u001F]{6,}/g;
      const _uncRx = /\\\\[\w.\-]{2,}(?:\\[\w.\-]+)+/g;
      const urlMatches = [...new Set([...allStrings.matchAll(_urlRx)].map(m => m[0]))];
      for (const url of urlMatches.slice(0, 50)) {
        findings.interestingStrings.push({ type: IOC.URL, url, severity: 'info' });
      }
      const uncMatches = [...new Set([...allStrings.matchAll(_uncRx)].map(m => m[0]))];
      for (const unc of uncMatches.slice(0, 20)) {
        findings.interestingStrings.push({ type: IOC.UNC_PATH, url: unc, severity: 'medium' });
      }

      // ── Risk assessment ────────────────────────────────────────────
      findings.autoExec = issues;
      if (riskScore >= 8) findings.risk = 'critical';
      else if (riskScore >= 5) findings.risk = 'high';
      else if (riskScore >= 2) findings.risk = 'medium';
      else findings.risk = 'low';

    } catch (e) {
      findings.risk = 'medium';
      findings.autoExec = ['PE parsing partially failed: ' + e.message];
    }

    return findings;
  }
}
