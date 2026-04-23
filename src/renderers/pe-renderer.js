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

    // ── Delay Import Table (T3.9) ─────────────────────────────────────
    pe.delayImports = this._parseDelayImports(bytes, pe.dataDirectories, pe.sections, is64);

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

    // ── TLS callbacks (IMAGE_DIRECTORY_ENTRY_TLS = 9) ──────────────
    // AddressOfCallBacks is a NULL-terminated array of VAs that the
    // loader invokes *before* the main entry point. Classic anti-debug
    // / early-execution vector — most benign binaries have none.
    pe.tls = this._parseTlsCallbacks(bytes, pe.dataDirectories, pe.sections, is64, pe.optional.imageBase);

    // ── .NET / CLR (IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14) ─────
    // If present, the PE is a managed (.NET) assembly. The CLR header
    // points at the metadata root which exposes the runtime version
    // string ("v4.0.30319" etc.) and the IL-only / strong-name flags.
    pe.dotnet = this._parseClrHeader(bytes, pe.dataDirectories, pe.sections);

    // ── Entry-point sanity ─────────────────────────────────────────
    // Classify which section the EP lives in and flag the well-known
    // bad cases: EP outside any section (orphaned loader), or EP in a
    // W+X section (self-modifying unpacker).
    pe.entryPointInfo = this._analyzeEntryPoint(pe);

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

    // ── Format heuristics: XLL / AutoHotkey / Go / Installer ─────────
    // Populated as flat fields on `pe` so Summary + YARA can read them
    // without a nested namespace. All four are best-effort — parse
    // failures never abort PE analysis.
    try { this._detectFormatHeuristics(bytes, pe); }
    catch (_) { /* heuristics are best-effort */ }

    return pe;
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Format heuristics — XLL / AutoHotkey / Go / Installer
  //  Each fills flat fields on `pe` consumed by render(), analyzeForSecurity()
  //  and Summary (_copyAnalysisPE in app-ui.js). Cheap scans only — no
  //  decompression, no full byte-walk beyond bounded windows.
  // ═══════════════════════════════════════════════════════════════════════

  _detectFormatHeuristics(bytes, pe) {
    // ── XLL (Excel add-in) ─────────────────────────────────────────
    //   Excel XLL add-ins are DLLs that export one or more xlAuto*
    //   functions which the host invokes on load / unload / registration.
    //   Excel-DNA shim XLLs also embed the literal string EXCELDNA in
    //   their resources.
    pe.isXll = false;
    pe.xllExports = [];
    pe.xllIsExcelDna = false;
    const XLL_HOOKS = new Set([
      'xlAutoOpen', 'xlAutoClose', 'xlAutoAdd', 'xlAutoRemove',
      'xlAutoRegister', 'xlAutoRegister12', 'xlAutoFree', 'xlAutoFree12',
      'xlAddInManagerInfo', 'xlAddInManagerInfo12',
    ]);
    if (pe.exports && pe.exports.names) {
      for (const n of pe.exports.names) {
        if (n.name && XLL_HOOKS.has(n.name)) pe.xllExports.push(n.name);
      }
    }
    if (pe.xllExports.length > 0) pe.isXll = true;
    // Excel-DNA marker scan — restrict to extractStrings output to keep this cheap.
    // Covers both ASCII and UTF-16LE strings — .NET string literals in the
    // managed metadata/resources are almost always UTF-16, so an ASCII-only
    // sweep misses most real Excel-DNA shims.
    if (pe.strings && pe.strings.ascii) {
      for (const s of pe.strings.ascii) {
        if (s.includes('EXCELDNA') || s.includes('ExcelDna.Integration')) {
          pe.xllIsExcelDna = true;
          pe.isXll = true;
          break;
        }
      }
    }
    if (!pe.xllIsExcelDna && pe.strings && pe.strings.unicode) {
      for (const s of pe.strings.unicode) {
        if (s.includes('EXCELDNA') || s.includes('ExcelDna.Integration')) {
          pe.xllIsExcelDna = true;
          pe.isXll = true;
          break;
        }
      }
    }

    // ── Compiled AutoHotkey ────────────────────────────────────────
    //   Compiled AutoHotkey scripts embed the ASCII marker
    //   `>AUTOHOTKEY SCRIPT<` at the start of an RT_RCDATA resource
    //   followed by the raw script source (up to a NUL terminator).
    pe.isAutoHotkey = false;
    pe.autoHotkeyScript = null;
    pe.autoHotkeyOffset = 0;
    const AHK_MARKER = '>AUTOHOTKEY SCRIPT<';
    const ahkIdx = this._findAscii(bytes, AHK_MARKER);
    if (ahkIdx >= 0) {
      pe.isAutoHotkey = true;
      pe.autoHotkeyOffset = ahkIdx;
      // Extract script: skip marker + optional padding, then read until
      // a NUL or the next resource marker. Cap at 256 KB to bound cost.
      const startSearch = ahkIdx + AHK_MARKER.length;
      // Walk forward past any non-printable bytes (resource header / padding)
      // until we hit the first printable ASCII character.
      let start = startSearch;
      while (start < bytes.length && start < startSearch + 64) {
        const c = bytes[start];
        if (c >= 0x20 && c < 0x7F) break;
        start++;
      }
      const cap = Math.min(bytes.length, start + 256 * 1024);
      let end = start;
      while (end < cap) {
        const c = bytes[end];
        if (c === 0) break;
        // Stop if we see binary noise (non-printable, non-whitespace)
        if (c < 0x09 || (c > 0x0D && c < 0x20) || c > 0x7E) break;
        end++;
      }
      if (end > start + 8) {
        const scriptBytes = bytes.subarray(start, end);
        try {
          pe.autoHotkeyScript = new TextDecoder('utf-8', { fatal: false }).decode(scriptBytes);
        } catch (_) {
          pe.autoHotkeyScript = String.fromCharCode(...scriptBytes);
        }
      } else {
        pe.autoHotkeyScript = '';
      }
    }

    // ── Go binary ──────────────────────────────────────────────────
    //   Two high-confidence signals:
    //     1. Go build info magic: "\xff Go buildinf:" followed by
    //        pointer size, endianness, and the module path + build settings.
    //     2. Presence of runtime.main / go:itab strings in pclntab.
    pe.isGoBinary = false;
    pe.goBuildInfo = null;
    const buildInfoMagic = new Uint8Array([0xff, 0x20, 0x47, 0x6f, 0x20, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x69, 0x6e, 0x66, 0x3a]);
    const goIdx = this._findBytes(bytes, buildInfoMagic);
    if (goIdx >= 0) {
      pe.isGoBinary = true;
      pe.goBuildInfo = this._parseGoBuildInfo(bytes, goIdx);
    } else {
      // Section-name fallback: .gopclntab is the runtime function table;
      // .go.buildinfo carries module/version metadata on newer toolchains.
      for (const s of pe.sections) {
        if (s.name === '.gopclntab' || s.name === '.go.buildinfo') {
          pe.isGoBinary = true;
          break;
        }
      }
    }

    // ── Installer framework sniff (list-only) ──────────────────────
    //   Inno Setup overlay starts with "zlb\x1A" (legacy) or
    //   "idska32\x1A" (current). NSIS installers embed the magic
    //   "NullsoftInst" in the firstheader near the end of the binary.
    pe.installerType = null;
    pe.installerVersion = null;
    // Inno: search near end of file (overlay region) then fall back to full scan
    const innoMagicA = [0x7a, 0x6c, 0x62, 0x1a];        // "zlb\x1A"
    const innoMagicB = [0x69, 0x64, 0x73, 0x6b, 0x61, 0x33, 0x32, 0x1a]; // "idska32\x1A"
    const innoIdx = this._findBytesAny(bytes, [innoMagicA, innoMagicB]);
    if (innoIdx >= 0) {
      pe.installerType = 'Inno Setup';
      // Inno stubs also contain a human-readable version string like
      // "Inno Setup Setup Data (5.5.0)" — grab if nearby.
      const vIdx = this._findAscii(bytes, 'Inno Setup Setup Data (');
      if (vIdx >= 0) {
        const end = Math.min(bytes.length, vIdx + 80);
        const str = this._str(bytes, vIdx, end - vIdx);
        const m = str.match(/Inno Setup Setup Data \(([^)]+)\)/);
        if (m) pe.installerVersion = m[1];
      }
    }
    if (!pe.installerType) {
      // NSIS: "Nullsoft Install System" ascii marker, or firstheader
      // magic 0xDEADBEEF + "NullsoftInst" near file end.
      // _findAscii returns -1 (not null) on miss, so chain with an explicit
      // fall-through instead of `??` (which would never reach the second probe).
      let nsisIdx = this._findAscii(bytes, 'Nullsoft.NSIS.exehead');
      if (nsisIdx < 0) nsisIdx = this._findAscii(bytes, 'NullsoftInst');
      const nsisLongIdx = this._findAscii(bytes, 'Nullsoft Install System');

      if (nsisIdx >= 0 || nsisLongIdx >= 0) {
        pe.installerType = 'NSIS';
        if (nsisLongIdx >= 0) {
          const end = Math.min(bytes.length, nsisLongIdx + 64);
          const str = this._str(bytes, nsisLongIdx, end - nsisLongIdx);
          const m = str.match(/Nullsoft Install System (v[0-9.]+)/);
          if (m) pe.installerVersion = m[1];
        }
      }
    }
  }

  // Locate an ASCII needle in the byte buffer. Returns index or -1.
  // (Callers that need fall-through must compare against `< 0`; `??`
  // won't work because -1 is not nullish.)
  _findAscii(bytes, needle) {
    const n = needle.length;
    if (n === 0 || n > bytes.length) return -1;
    const first = needle.charCodeAt(0);
    const last = bytes.length - n;
    outer: for (let i = 0; i <= last; i++) {
      if (bytes[i] !== first) continue;
      for (let j = 1; j < n; j++) {
        if (bytes[i + j] !== needle.charCodeAt(j)) continue outer;
      }
      return i;
    }
    return -1;
  }

  // Locate a byte sequence in the buffer. Returns index or -1.
  _findBytes(bytes, needle) {
    const n = needle.length;
    if (n === 0 || n > bytes.length) return -1;
    const first = needle[0];
    const last = bytes.length - n;
    outer: for (let i = 0; i <= last; i++) {
      if (bytes[i] !== first) continue;
      for (let j = 1; j < n; j++) {
        if (bytes[i + j] !== needle[j]) continue outer;
      }
      return i;
    }
    return -1;
  }

  // Locate any of the given byte sequences. Returns earliest hit or -1.
  _findBytesAny(bytes, needles) {
    let best = -1;
    for (const n of needles) {
      const arr = (n instanceof Uint8Array) ? n : new Uint8Array(n);
      const idx = this._findBytes(bytes, arr);
      if (idx >= 0 && (best < 0 || idx < best)) best = idx;
    }
    return best;
  }

  // Parse the Go build-info header at offset `off`. Returns a summary
  // object or null if the layout isn't recognised.
  //   Layout (since Go 1.18):
  //     [0..13]  "\xff Go buildinf:"
  //     [14]     ptrSize (usually 8)
  //     [15]     flags (bit 1 = little-endian varint table)
  //     [16..]   Go version string (varint-prefixed) + mod info (varint)
  //   Older pre-1.18 binaries use fixed ptrs at [16..] — we detect those
  //   and fall through to the pclntab signal.
  _parseGoBuildInfo(bytes, off) {
    const info = { version: null, path: null, mod: null, vcs: null, revision: null, buildTime: null, settings: {} };
    if (off + 32 > bytes.length) return info;
    const flags = bytes[off + 15];
    const varintMode = !!(flags & 0x02);
    let cursor = off + 16;
    const readVarintStr = () => {
      if (cursor >= bytes.length) return null;
      // NOTE: accumulate into a plain Number with `* 2**shift` — the obvious
      // `len |= (b & 0x7f) << shift` is unsafe here because JS `<<` coerces
      // to signed-32-bit, so any `shift >= 28` silently produces a negative
      // intermediate and corrupts the length check below. We cap the decoded
      // length at 65536 regardless, so any shift >= 24 is rejected outright.
      let len = 0, shift = 0;
      for (let i = 0; i < 10; i++) {
        if (cursor >= bytes.length) return null;
        const b = bytes[cursor++];
        if (shift >= 24) return null; // varint cannot encode a length > 64 KiB
        len += (b & 0x7f) * (2 ** shift);
        if ((b & 0x80) === 0) break;
        shift += 7;
      }
      if (len <= 0 || len > 65536 || cursor + len > bytes.length) return null;
      const s = new TextDecoder('utf-8', { fatal: false }).decode(bytes.subarray(cursor, cursor + len));
      cursor += len;
      return s;
    };
    if (varintMode) {
      info.version = readVarintStr();
      const mod = readVarintStr();
      if (mod && mod.length > 32) {
        // mod is framed by 16 padding bytes each side in the official layout;
        // strip when present.
        const trimmed = mod.replace(/^\x00+|[\x00\xff]+$/g, '');
        info.mod = trimmed;
        // Parse key=value build settings from mod (Go 1.18+)
        const settingLines = trimmed.split('\n');
        for (const line of settingLines) {
          if (line.startsWith('path\t')) info.path = line.slice(5);
          else if (line.startsWith('mod\t')) {
            const parts = line.split('\t');
            if (parts.length >= 3) info.settings['module'] = parts[1] + ' ' + parts[2];
          }
          else if (line.startsWith('build\t')) {
            const parts = line.slice(6).split('=');
            if (parts.length === 2) {
              info.settings[parts[0]] = parts[1];
              if (parts[0] === 'vcs') info.vcs = parts[1];
              if (parts[0] === 'vcs.revision') info.revision = parts[1];
              if (parts[0] === 'vcs.time') info.buildTime = parts[1];
            }
          }
        }
      }
    } else {
      // Legacy (pre-1.18) layout: pointers to version string and mod info
      // table. Skip for now — just grab the version via a nearby ASCII scan.
      const scanEnd = Math.min(off + 4096, bytes.length);
      for (let i = off + 16; i < scanEnd - 4; i++) {
        // "go1." followed by a digit is a reliable Go-version anchor
        if (bytes[i] === 0x67 && bytes[i + 1] === 0x6f && bytes[i + 2] === 0x31 && bytes[i + 3] === 0x2e) {
          let end = i;
          while (end < scanEnd && bytes[end] >= 0x20 && bytes[end] < 0x7f) end++;
          info.version = this._str(bytes, i, end - i);
          break;
        }
      }
    }
    return info;
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

    // Canonical Rich-header fingerprint (matches YARA's
    // `pe.rich_signature.hash`). Clusters binaries by the exact toolchain +
    // object-count profile that produced them — survives most re-signings
    // and light repacking because the Rich header is built into the PE at
    // link time, not adjusted afterwards.
    let richHash = null;
    try {
      if (typeof computeRichHash === 'function') {
        richHash = computeRichHash(bytes, danSOff, richOff, key);
      }
    } catch (_) { /* rich-hash is best-effort */ }

    return { xorKey: key, entries, danSOff, richOff, richHash };
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
  //  Delay Import Table parser (T3.9 — IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13)
  // ═══════════════════════════════════════════════════════════════════════
  //
  // ImgDelayDescr layout (32 bytes):
  //   u32 grAttrs        — attributes (1 = RVA-based, 0 = VA-based)
  //   u32 rvaDLLName     — RVA of DLL name
  //   u32 rvaHmod        — RVA of module handle
  //   u32 rvaIAT         — RVA of the delay-load IAT
  //   u32 rvaINT         — RVA of the delay-load INT (name table)
  //   u32 rvaBoundIAT    — RVA of optional bound IAT
  //   u32 rvaUnloadIAT   — RVA of optional unload IAT
  //   u32 dwTimeStamp    — timestamp (0 if not bound)
  //
  // The name table (INT) has the same format as regular imports: each
  // entry is a pointer-sized value — ordinal flag in the high bit, else
  // RVA to a hint/name pair. We reuse the same walk logic as _parseImports.

  _parseDelayImports(bytes, dataDirs, sections, is64) {
    if (!dataDirs[13] || dataDirs[13].rva === 0 || dataDirs[13].size === 0) return [];

    const delayOff = this._rvaToOffset(dataDirs[13].rva, sections);
    if (delayOff + 32 > bytes.length) return [];

    const imports = [];
    const maxDlls = 256;
    let descOff = delayOff;

    for (let d = 0; d < maxDlls; d++) {
      if (descOff + 32 > bytes.length) break;

      const grAttrs    = this._u32(bytes, descOff);
      const nameRva    = this._u32(bytes, descOff + 4);
      const intRva     = this._u32(bytes, descOff + 16);

      // End of delay import descriptors (all zeros)
      if (nameRva === 0 && intRva === 0) break;

      // Read DLL name
      const nameOff = this._rvaToOffset(nameRva, sections);
      const dllName = (nameOff < bytes.length) ? this._str(bytes, nameOff, 256) : '(unknown)';

      // Read imported functions from INT
      const lookupOff = this._rvaToOffset(intRva, sections);
      const functions = [];
      const maxFuncs = 4096;

      if (intRva > 0 && lookupOff < bytes.length) {
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
            const ordinal = entry & 0xFFFF;
            functions.push({ name: `Ordinal #${ordinal}`, ordinal, isSuspicious: false });
          } else {
            const hintRva = entry & 0x7FFFFFFF;
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
      descOff += 32;
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

    // ── Walk the function-RVA table to detect forwarders and to count
    //    ordinal-only slots. A PE export whose function RVA lands *inside*
    //    the export directory range is a forwarder: the bytes at that RVA
    //    spell out "OtherDll.FuncName". Slots that hold a non-zero RVA but
    //    have no corresponding entry in the name-ordinal table are the
    //    classic "ordinal-only" exports (packer / crypter tell when the
    //    ratio is high). See src/binary-exports.js for the risk rubric.
    const forwarders = [];
    let ordinalOnlyCount = 0;
    const namedOrdinals = new Set();
    for (const n of names) {
      namedOrdinals.add(n.ordinal - ordinalBase);
    }
    const funcsOff = this._rvaToOffset(funcRva, sections);
    const expRvaStart = dataDirs[0].rva;
    const expRvaEnd = dataDirs[0].rva + dataDirs[0].size;
    const maxFns = Math.min(numFunctions, 4096);
    for (let i = 0; i < maxFns; i++) {
      const fOff = funcsOff + i * 4;
      if (fOff + 4 > bytes.length) break;
      const fnRva = this._u32(bytes, fOff);
      if (fnRva === 0) continue;
      if (fnRva >= expRvaStart && fnRva < expRvaEnd) {
        const fwdOff = this._rvaToOffset(fnRva, sections);
        const fwd = (fwdOff < bytes.length) ? this._str(bytes, fwdOff, 256) : '';
        if (fwd) forwarders.push(fwd);
      }
      if (!namedOrdinals.has(i)) ordinalOnlyCount++;
    }

    return { dllName, ordinalBase, numFunctions, numNames, names, forwarders, ordinalOnlyCount };
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Resource Directory parser (three-level walk → leaves)
  // ═══════════════════════════════════════════════════════════════════════
  //
  // PE resources live in a three-level tree:
  //   Level 0 (root)    → entries keyed by *type*    (RCDATA / ICON / …)
  //   Level 1           → entries keyed by *name*    (integer ID or UTF-16)
  //   Level 2           → entries keyed by *language*
  //   Leaf              → IMAGE_RESOURCE_DATA_ENTRY  (RVA, Size, CodePage)
  //
  // Historically we only walked level 0 and returned a one-row-per-type
  // summary. That's enough for the "what kinds of resources does this PE
  // embed?" sidebar, but the interesting case — an attacker stashing a
  // secondary PE / script / archive inside an RCDATA leaf — needed a full
  // descent. This parser now returns *both* shapes:
  //
  //   pe.resources       — type-level summary (unchanged external shape)
  //   pe.resourceLeaves  — flat list of leaves with file offsets + a
  //                        first-bytes magic sniff, suitable for the
  //                        click-to-drilldown table in render() and the
  //                        embedded-payload risk pass in analyzeForSecurity().

  _parseResources(bytes, dataDirs, sections) {
    // Compatibility shim: old call-sites read the returned array directly
    // as the type-level summary. We now attach .leaves to the returned
    // array so both consumers work without a signature change.
    const summary = [];
    summary.leaves = [];

    if (!dataDirs[2] || dataDirs[2].rva === 0 || dataDirs[2].size === 0) return summary;

    const resOff = this._rvaToOffset(dataDirs[2].rva, sections);
    if (resOff + 16 > bytes.length) return summary;

    // Defensive caps — even a hostile resource table shouldn't blow the
    // parser budget. 128 types × 512 leaves aligns with parser-watchdog's
    // spirit of bounded, best-effort work.
    const MAX_TYPES = 128;
    const MAX_LEAVES = 512;
    const MAX_LEAF_SIZE = 50 * 1024 * 1024; // 50 MB

    // Read a UTF-16LE string stored as `{u16 length; u16 chars[length]}`
    // at an offset relative to the resource-table base. Used for named
    // types / named resources at any level.
    const readResStr = (relOff) => {
      const off = resOff + (relOff & 0x7FFFFFFF);
      if (off + 2 > bytes.length) return null;
      const n = this._u16(bytes, off);
      let s = '';
      for (let c = 0; c < n && off + 2 + c * 2 + 1 < bytes.length && s.length < 256; c++) {
        const ch = this._u16(bytes, off + 2 + c * 2);
        if (ch >= 0x20 && ch < 0xFFFE) s += String.fromCharCode(ch);
      }
      return s || null;
    };

    // Best-effort magic sniff via BinaryOverlay (shared helper). Returns
    // {label, extHint} or null. Guarded because BinaryOverlay loads as a
    // separate <script> element and may (theoretically) race at first
    // analysis tick.
    const sniff = (leafOff, leafSize) => {
      if (typeof BinaryOverlay === 'undefined' || !BinaryOverlay.sniffMagic) return null;
      if (leafOff < 0 || leafSize <= 0) return null;
      const head = bytes.subarray(leafOff, Math.min(leafOff + 32, bytes.length));
      return BinaryOverlay.sniffMagic(head);
    };

    try {
      // ── Level 0: types ────────────────────────────────────────────
      const l0Named = this._u16(bytes, resOff + 12);
      const l0Id = this._u16(bytes, resOff + 14);
      const l0Total = Math.min(l0Named + l0Id, MAX_TYPES);

      for (let ti = 0; ti < l0Total; ti++) {
        const typeEntryOff = resOff + 16 + ti * 8;
        if (typeEntryOff + 8 > bytes.length) break;
        const typeIdRaw = this._u32(bytes, typeEntryOff);
        const typeDataOrDir = this._u32(bytes, typeEntryOff + 4);
        const typeIsDir = !!(typeDataOrDir & 0x80000000);

        let typeId;
        let typeName;
        let typeIsNamed;
        if (typeIdRaw & 0x80000000) {
          typeIsNamed = true;
          typeId = typeIdRaw & 0x7FFFFFFF;
          typeName = readResStr(typeId) || ('Named(' + typeId + ')');
        } else {
          typeIsNamed = false;
          typeId = typeIdRaw & 0x7FFFFFFF;
          typeName = PeRenderer.RES_TYPE[typeId] || 'Type ' + typeId;
        }

        let leafCount = 0;

        if (typeIsDir) {
          // ── Level 1: names ────────────────────────────────────────
          const l1Off = resOff + (typeDataOrDir & 0x7FFFFFFF);
          if (l1Off + 16 <= bytes.length) {
            const l1Named2 = this._u16(bytes, l1Off + 12);
            const l1Id2 = this._u16(bytes, l1Off + 14);
            const l1Total = Math.min(l1Named2 + l1Id2, 256);
            for (let ni = 0; ni < l1Total && summary.leaves.length < MAX_LEAVES; ni++) {
              const nameEntryOff = l1Off + 16 + ni * 8;
              if (nameEntryOff + 8 > bytes.length) break;
              const nameIdRaw = this._u32(bytes, nameEntryOff);
              const nameDataOrDir = this._u32(bytes, nameEntryOff + 4);

              let nameId = null;
              let nameStr = null;
              if (nameIdRaw & 0x80000000) {
                nameStr = readResStr(nameIdRaw & 0x7FFFFFFF);
              } else {
                nameId = nameIdRaw & 0x7FFFFFFF;
              }

              if (!(nameDataOrDir & 0x80000000)) {
                // Level-1 entry points straight at a leaf (no language level)
                leafCount++;
                this._collectResLeaf(bytes, resOff, sections, {
                  typeId, typeName, typeIsNamed,
                  nameId, nameStr,
                  langId: null,
                  leafRelOff: nameDataOrDir & 0x7FFFFFFF,
                  MAX_LEAF_SIZE,
                  sniff,
                  out: summary.leaves,
                });
                continue;
              }

              // ── Level 2: languages ──────────────────────────────
              const l2Off = resOff + (nameDataOrDir & 0x7FFFFFFF);
              if (l2Off + 16 > bytes.length) continue;
              const l2Named = this._u16(bytes, l2Off + 12);
              const l2Id = this._u16(bytes, l2Off + 14);
              const l2Total = Math.min(l2Named + l2Id, 16);
              for (let li = 0; li < l2Total && summary.leaves.length < MAX_LEAVES; li++) {
                const langEntryOff = l2Off + 16 + li * 8;
                if (langEntryOff + 8 > bytes.length) break;
                const langIdRaw = this._u32(bytes, langEntryOff);
                const langDataOrDir = this._u32(bytes, langEntryOff + 4);
                if (langDataOrDir & 0x80000000) continue; // shouldn't happen at L2
                leafCount++;
                this._collectResLeaf(bytes, resOff, sections, {
                  typeId, typeName, typeIsNamed,
                  nameId, nameStr,
                  langId: langIdRaw & 0x7FFFFFFF,
                  leafRelOff: langDataOrDir & 0x7FFFFFFF,
                  MAX_LEAF_SIZE,
                  sniff,
                  out: summary.leaves,
                });
              }
            }
          }
        }

        summary.push({ id: typeId, typeName, isDir: typeIsDir, count: leafCount });
        if (summary.leaves.length >= MAX_LEAVES) break;
      }
    } catch (e) { /* resource parsing is best-effort */ }

    return summary;
  }

  // ── Resolve a single resource leaf ──────────────────────────────────────
  // A resource leaf is an IMAGE_RESOURCE_DATA_ENTRY at `resBase + relOff`:
  //   u32 OffsetToData   (RVA, *not* a relative offset — PE spec quirk)
  //   u32 Size
  //   u32 CodePage
  //   u32 Reserved
  _collectResLeaf(bytes, resOff, sections, opts) {
    const { typeId, typeName, typeIsNamed, nameId, nameStr, langId,
            leafRelOff, MAX_LEAF_SIZE, sniff, out } = opts;
    const deOff = resOff + leafRelOff;
    if (deOff + 16 > bytes.length) return;
    const rva = this._u32(bytes, deOff);
    const size = this._u32(bytes, deOff + 4);
    if (!size || size > MAX_LEAF_SIZE) return;
    const fileOffset = this._rvaToOffset(rva, sections);
    if (fileOffset < 0 || fileOffset + size > bytes.length) return;
    const magic = sniff(fileOffset, size);
    out.push({
      typeId, typeName, typeIsNamed,
      nameId, nameStr,
      langId,
      rva, size, fileOffset,
      magic,
    });
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
  //  TLS callback parser (IMAGE_DIRECTORY_ENTRY_TLS = 9)
  // ═══════════════════════════════════════════════════════════════════════
  //
  // IMAGE_TLS_DIRECTORY layout:
  //   StartAddressOfRawData · EndAddressOfRawData · AddressOfIndex ·
  //   AddressOfCallBacks · SizeOfZeroFill · Characteristics
  //   (first four fields are 4 B on PE32, 8 B on PE32+)
  //
  // AddressOfCallBacks is a VA pointing at a NULL-terminated array of VAs.
  // Each callback VA is invoked by the Windows loader *before* the main
  // entry point, once per DLL_PROCESS_ATTACH / DETACH / THREAD_{ATTACH,
  // DETACH} event. Benign C/C++ runtimes typically register 0 callbacks;
  // malware uses them as an anti-debug / early-exec hook because most
  // debuggers break *at* the EP, missing TLS execution entirely.

  _parseTlsCallbacks(bytes, dataDirs, sections, is64, imageBase) {
    if (!dataDirs || !dataDirs[9] || dataDirs[9].rva === 0 || dataDirs[9].size === 0) return null;
    const result = { callbacks: [], rawOffset: 0, callbackArrayRva: 0 };
    try {
      const tlsOff = this._rvaToOffset(dataDirs[9].rva, sections);
      result.rawOffset = tlsOff;
      const ptrSize = is64 ? 8 : 4;
      // AddressOfCallBacks is the 4th pointer field in IMAGE_TLS_DIRECTORY
      const aocOff = tlsOff + ptrSize * 3;
      if (aocOff + ptrSize > bytes.length) return result;

      const aocVa = is64 ? this._u64(bytes, aocOff) : this._u32(bytes, aocOff);
      if (!aocVa) return result;

      // Convert VA → RVA → file offset. ImageBase is a Number (safe up to
      // 2^53) so plain subtraction works even for the 64-bit path.
      const aocRva = aocVa - imageBase;
      if (aocRva < 0 || aocRva > 0xFFFFFFFF) return result;
      result.callbackArrayRva = aocRva >>> 0;

      let cursor = this._rvaToOffset(aocRva >>> 0, sections);
      const MAX_CALLBACKS = 32;
      for (let i = 0; i < MAX_CALLBACKS; i++) {
        if (cursor + ptrSize > bytes.length) break;
        const cbVa = is64 ? this._u64(bytes, cursor) : this._u32(bytes, cursor);
        if (!cbVa) break;
        const cbRva = cbVa - imageBase;
        const cbFileOff = (cbRva >= 0 && cbRva <= 0xFFFFFFFF)
          ? this._rvaToOffset(cbRva >>> 0, sections)
          : null;
        // Locate the containing section for the callback (if any) so the
        // renderer can flag a callback that lives in a W+X section.
        let cbSection = null;
        if (cbRva >= 0 && cbRva <= 0xFFFFFFFF) {
          const r = cbRva >>> 0;
          for (const s of sections) {
            if (r >= s.virtualAddress && r < s.virtualAddress + s.virtualSize) {
              cbSection = s.name;
              break;
            }
          }
        }
        result.callbacks.push({ va: cbVa, rva: cbRva >>> 0, fileOffset: cbFileOff, section: cbSection });
        cursor += ptrSize;
      }
    } catch (_) { /* TLS parsing is best-effort */ }
    return result;
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  .NET CLR Header parser (IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14)
  // ═══════════════════════════════════════════════════════════════════════
  //
  // IMAGE_COR20_HEADER layout (72 bytes):
  //   u32 cb                 · header size (always 72)
  //   u16 MajorRuntimeVersion / u16 MinorRuntimeVersion
  //   u32 MetaData.RVA       / u32 MetaData.Size     · CLR metadata root
  //   u32 Flags              · COMIMAGE_FLAGS_* bitfield
  //   u32 EntryPointToken / RVA
  //   u32 Resources.RVA      / u32 Resources.Size
  //   u32 StrongName.RVA     / u32 StrongName.Size   · strong-name signature
  //   u32 CodeManagerTable   (2×u32) · VTableFixups (2×u32) ·
  //   u32 ExportAddressTableJumps (2×u32) · u32 ManagedNativeHeader (2×u32)
  //
  // Metadata root (at MetaData.RVA):
  //   u32 "BSJB"  u16 major  u16 minor  u32 reserved
  //   u32 versionLen          · NUL-padded to 4
  //   char[versionLen] version  e.g. "v4.0.30319"
  //
  // The runtime version + Il-only / strong-name flags are the analyst-
  // useful pivots; we surface them on `pe.dotnet` and the render card.
  _parseClrHeader(bytes, dataDirs, sections) {
    if (!dataDirs || !dataDirs[14] || dataDirs[14].rva === 0 || dataDirs[14].size === 0) return null;
    try {
      const clrOff = this._rvaToOffset(dataDirs[14].rva, sections);
      if (clrOff + 72 > bytes.length) return null;

      const cb               = this._u32(bytes, clrOff + 0);
      const majorRuntimeVer  = this._u16(bytes, clrOff + 4);
      const minorRuntimeVer  = this._u16(bytes, clrOff + 6);
      const metadataRva      = this._u32(bytes, clrOff + 8);
      const metadataSize     = this._u32(bytes, clrOff + 12);
      const flags            = this._u32(bytes, clrOff + 16);
      const entryPointToken  = this._u32(bytes, clrOff + 20);
      const resourcesRva     = this._u32(bytes, clrOff + 24);
      const resourcesSize    = this._u32(bytes, clrOff + 28);
      const strongNameRva    = this._u32(bytes, clrOff + 32);
      const strongNameSize   = this._u32(bytes, clrOff + 36);

      // Sanity check: cb should be 72 on any real CLR header
      if (cb !== 72 && cb !== 0x48) {
        // Be permissive — some tooling writes slightly different sizes.
        // Only reject obviously bogus values.
        if (cb < 48 || cb > 256) return null;
      }

      const isILOnly         = !!(flags & 0x00000001);
      const requires32Bit    = !!(flags & 0x00000002);
      const isILLibrary      = !!(flags & 0x00000004);
      const hasStrongName    = !!(flags & 0x00000008) || (strongNameRva > 0 && strongNameSize > 0);
      const hasNativeEp      = !!(flags & 0x00000010);
      const trackDebugData   = !!(flags & 0x00010000);
      const prefer32Bit      = !!(flags & 0x00020000);

      const result = {
        cb,
        runtimeVersion: `${majorRuntimeVer}.${minorRuntimeVer}`,
        flags,
        isILOnly,
        requires32Bit,
        isILLibrary,
        hasStrongName,
        hasNativeCode: hasNativeEp || !isILOnly,
        hasNativeEntryPoint: hasNativeEp,
        trackDebugData,
        prefer32Bit,
        entryPointToken,
        metadataRva,
        metadataSize,
        resourcesRva,
        resourcesSize,
        strongNameRva,
        strongNameSize,
        runtimeVersionString: null,
        metadataMajor: null,
        metadataMinor: null,
      };

      // ── Metadata root — runtime version string (e.g. "v4.0.30319") ──
      if (metadataRva > 0 && metadataSize > 16) {
        const mdOff = this._rvaToOffset(metadataRva, sections);
        if (mdOff + 16 <= bytes.length) {
          const sig = this._u32(bytes, mdOff);
          if (sig === 0x424A5342) { // "BSJB"
            result.metadataMajor = this._u16(bytes, mdOff + 4);
            result.metadataMinor = this._u16(bytes, mdOff + 6);
            const verLen = this._u32(bytes, mdOff + 12);
            if (verLen > 0 && verLen <= 256 && mdOff + 16 + verLen <= bytes.length) {
              let s = '';
              for (let i = 0; i < verLen; i++) {
                const c = bytes[mdOff + 16 + i];
                if (c === 0) break;
                if (c >= 0x20 && c < 0x7F) s += String.fromCharCode(c);
              }
              if (s) result.runtimeVersionString = s;
            }
          }
        }
      }

      return result;
    } catch (_) {
      return null;
    }
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Entry-point sanity
  // ═══════════════════════════════════════════════════════════════════════
  //
  // Benign PEs almost always land their EP inside the `.text` section (or a
  // linker-specific equivalent like `CODE` / `.init`). Two well-known
  // malware patterns violate that:
  //
  //   • Orphan EP — the RVA does not fall inside *any* section. Frequently
  //     seen in manually-built loaders that unpack into fresh pages.
  //   • W+X EP — the EP lives in a section marked both writable and
  //     executable. Classic unpacker / self-modifying stub.
  //
  // A DLL with EntryPoint == 0 is legitimate (optional DllMain); we skip
  // the checks in that case so well-formed import-only libraries don't
  // spuriously flag.

  _analyzeEntryPoint(pe) {
    const info = {
      rva: pe.optional.entryPoint >>> 0,
      section: null,
      inText: false,
      notInText: false,
      inWX: false,
      orphaned: false,
      skipped: false,
    };
    if (info.rva === 0) {
      // Legitimate for DLLs / drivers without DllMain
      info.skipped = true;
      return info;
    }
    for (const s of pe.sections) {
      if (info.rva >= s.virtualAddress && info.rva < s.virtualAddress + Math.max(s.virtualSize, s.rawDataSize)) {
        info.section = s;
        break;
      }
    }
    if (!info.section) {
      info.orphaned = true;
      return info;
    }
    const name = info.section.name || '';
    // Accept the common linker variants; we don't want to flag legitimate
    // Delphi / older toolchain output as "anomalous" just because the
    // code section isn't literally named `.text`.
    const TEXT_LIKE = new Set(['.text', 'CODE', '.code', 'text', '.itext', 'INIT', '.init']);
    info.inText = TEXT_LIKE.has(name);
    info.notInText = !info.inText;
    info.inWX = !!(info.section.isWritable && info.section.isExecutable);
    return info;
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
      // Stash for _renderSection → BinaryTriage.shouldAutoOpen() so Tier-C
      // cards default closed on clean samples and auto-open on anomalous
      // ones. Mirrored in elf-renderer.js / macho-renderer.js.
      this._parsed = pe;
      // Stash the source filename on the parsed object so the resource
      // drill-down table in `_renderResources()` can mint synthetic child
      // filenames like `<parent>.res.<type>.<name>.<ext>` instead of the
      // anonymous 'binary' fallback. Harmless on the analyzeForSecurity
      // path (which re-parses into its own scoped `pe`).
      pe._fileName = fileName || '';
      this._lastStrings = [...pe.strings.ascii, ...pe.strings.unicode];
      // Stashed so the `_rawText` post-processing block below can pull
      // pe.versionInfo values out of the IOC-extractor corpus without
      // re-parsing the file.
      this._lastPe = pe;


      // ── Banner ─────────────────────────────────────────────────────
      const banner = document.createElement('div');
      banner.className = 'doc-extraction-banner';
      let bType = pe.coff.isDLL ? 'DLL' : pe.coff.isSystem ? 'System Driver' : 'Executable';
      // Narrow the type label when we positively identified a format-specific
      // PE so the banner immediately tells the analyst what they're looking at.
      if (pe.isXll) bType = pe.xllIsExcelDna ? 'Excel Add-in (XLL, Excel-DNA)' : 'Excel Add-in (XLL)';
      else if (pe.isAutoHotkey) bType = 'Compiled AutoHotkey Script';
      else if (pe.installerType) bType = pe.installerType + ' Installer' + (pe.installerVersion ? ' ' + pe.installerVersion : '');
      else if (pe.isGoBinary) bType = 'Go ' + (pe.coff.isDLL ? 'DLL' : 'Executable');
      const bArch = pe.optional.magicStr;
      banner.innerHTML = `<strong>PE Analysis — ${this._esc(bType)}</strong> ` +
        `<span class="doc-meta-tag">${this._esc(bArch)}</span> ` +
        `<span class="doc-meta-tag">${this._esc(pe.coff.machineStr)}</span> ` +
        `<span class="doc-meta-tag">${pe.sections.length} sections</span> ` +
        `<span class="doc-meta-tag">${pe.imports.length} imported DLLs</span>` +
        (pe.exports ? ` <span class="doc-meta-tag">${pe.exports.numNames} exports</span>` : '');
      wrap.appendChild(banner);

      // ── Format-specific extras ─────────────────────────────────────
      //   A small badge row immediately under the main banner surfacing
      //   XLL / AutoHotkey / Go / Installer detections so the analyst
      //   doesn't have to scroll the Security Features section to spot them.
      if (pe.isXll || pe.isAutoHotkey || pe.installerType || pe.isGoBinary) {
        const fmt = document.createElement('div');
        fmt.className = 'doc-extraction-banner';
        const parts = [];
        if (pe.isXll) {
          const hooks = pe.xllExports.length ? ` — exports: ${pe.xllExports.map(h => this._esc(h)).join(', ')}` : '';
          const dna = pe.xllIsExcelDna ? ' <span class="doc-meta-tag">Excel-DNA managed</span>' : '';
          parts.push(`<div>📊 <strong>XLL add-in detected</strong>${dna}${hooks}</div>`);
        }
        if (pe.isAutoHotkey) {
          const sz = pe.autoHotkeyScript ? pe.autoHotkeyScript.length : 0;
          parts.push(`<div>⌨ <strong>Compiled AutoHotkey script</strong> — ${sz.toLocaleString()} bytes extracted at RT_RCDATA offset 0x${(pe.autoHotkeyOffset||0).toString(16).toUpperCase()}</div>`);
        }
        if (pe.installerType) {
          const v = pe.installerVersion ? ` ${this._esc(pe.installerVersion)}` : '';
          parts.push(`<div>📦 <strong>${this._esc(pe.installerType)}${v} installer</strong> — payload archive embedded as PE overlay (list-only)</div>`);
        }
        if (pe.isGoBinary) {
          const g = pe.goBuildInfo || {};
          const bits = [];
          if (g.version) bits.push(`<span class="doc-meta-tag">${this._esc(g.version)}</span>`);
          if (g.path) bits.push(`<span class="doc-meta-tag">path: ${this._esc(g.path)}</span>`);
          if (g.vcs && g.revision) bits.push(`<span class="doc-meta-tag">${this._esc(g.vcs)}: ${this._esc(g.revision.slice(0, 12))}</span>`);
          parts.push(`<div>🐹 <strong>Go binary</strong> ${bits.join(' ')}</div>`);
        }
        fmt.innerHTML = parts.join('');
        wrap.appendChild(fmt);
      }

      // ── Embedded AutoHotkey script viewer ──────────────────────────
      if (pe.isAutoHotkey && pe.autoHotkeyScript) {
        const src = document.createElement('div');
        src.className = 'pe-ahk-source plaintext-scroll';
        const table = document.createElement('table');
        table.className = 'plaintext-table';
        const lines = pe.autoHotkeyScript.split(/\r?\n/);
        const maxLines = RENDER_LIMITS.MAX_TEXT_LINES_SMALL;
        const cnt = Math.min(lines.length, maxLines);
        for (let i = 0; i < cnt; i++) {
          const tr = document.createElement('tr');
          const tdNum = document.createElement('td'); tdNum.className = 'plaintext-ln'; tdNum.textContent = i + 1;
          const tdCode = document.createElement('td'); tdCode.className = 'plaintext-code'; tdCode.textContent = lines[i];
          tr.appendChild(tdNum); tr.appendChild(tdCode); table.appendChild(tr);
        }
        src.appendChild(table);
        wrap.appendChild(this._renderSection('⌨ AutoHotkey Script Source (' + (pe.autoHotkeyScript.length).toLocaleString() + ' bytes)', src, lines.length));
      }

      // ── Go build-info viewer ───────────────────────────────────────
      if (pe.isGoBinary && pe.goBuildInfo) {
        const g = pe.goBuildInfo;
        const rows = [];
        if (g.version) rows.push(['Go Version', g.version]);
        if (g.path) rows.push(['Main Package', g.path]);
        if (g.vcs) rows.push(['VCS', g.vcs]);
        if (g.revision) rows.push(['Revision', g.revision]);
        if (g.buildTime) rows.push(['Build Time', g.buildTime]);
        for (const [k, v] of Object.entries(g.settings || {})) {
          if (k === 'vcs' || k === 'vcs.revision' || k === 'vcs.time') continue;
          rows.push([k, String(v)]);
        }
        if (rows.length) {
          wrap.appendChild(this._renderSection('🐹 Go Build Info', this._buildTable(['Field', 'Value'], rows)));
        }
      }


      // ── Tier-A Triage Band ─────────────────────────────────────────
      // Verdict one-liner + coarse 0-100 risk, coloured anomaly-ribbon
      // chips, and a tactic-grouped MITRE ATT&CK strip. The analyst
      // reads this band first; everything below (Binary Pivot, Headers,
      // Sections, Imports, Strings …) is the drill-down for the chips
      // pointed at here. `_findings` was stashed by analyzeForSecurity
      // immediately before render() on the shared _loadFile path.
      try {
        if (typeof BinaryTriage !== 'undefined') {
          const triage = BinaryTriage.render({
            parsed: pe,
            findings: this._findings || {},
            format: 'PE',
            fileSize: bytes.length,
          });
          if (triage) wrap.appendChild(triage);
        }
      } catch (_) { /* triage band is best-effort */ }

      // ── Binary Pivot (shared triage card) ──────────────────────────
      // Above-the-fold summary that mirrors the ELF / Mach-O cards:
      // file-hash trio, imphash + RichHash, Authenticode signer,
      // compile timestamp with a "faked?" flag, entry-point anomaly,
      // overlay presence, and the top section-name packer match.
      // Pulls from data already computed by `_parse()` — adds no extra
      // passes over the buffer. Placed above PE Headers so the analyst
      // sees the pivots before any large tables.
      try {
        if (typeof BinarySummary !== 'undefined') {
          // Signer — first Authenticode leaf cert CN / DN if present.
          let signer = { present: false, label: 'unsigned' };
          if (pe.certificates && pe.certificates.length > 0) {
            const c = pe.certificates[0];
            const label = (c.subject && c.subject.CN) || c.subjectStr || 'signed';
            signer = { present: true, label };
          }
          // Entry-point anomaly — mirror the header badge logic.
          let epAnomaly = null;
          const epi = pe.entryPointInfo || {};
          if (!epi.skipped) {
            if (epi.orphaned) epAnomaly = 'orphaned (outside any section)';
            else if (epi.inWX) epAnomaly = 'W+X section';
            else if (epi.notInText) epAnomaly = 'non-.text section';
          }
          // Overlay — recompute the start offset; we don't keep the
          // result on `pe` to avoid bloating the parsed object.
          let overlayInfo = { present: false };
          try {
            const oStart = this._computeOverlayStart(pe);
            if (oStart > 0 && oStart < bytes.length) {
              const size = bytes.length - oStart;
              let label = null;
              if (typeof BinaryOverlay !== 'undefined' && BinaryOverlay.sniffMagic) {
                const head = bytes.subarray(oStart, Math.min(bytes.length, oStart + 32));
                const m = BinaryOverlay.sniffMagic(head);
                if (m && m.label) label = m.label;
              }
              overlayInfo = { present: true, size, label };
            }
          } catch (_) { /* best-effort */ }
          // Packer — first section with a PACKER_SECTIONS hit wins.
          let packerInfo = null;
          const packSec = pe.sections.find(s => s && s.packerMatch);
          if (packSec) {
            packerInfo = { label: packSec.packerMatch, source: 'section ' + (packSec.name || '(unnamed)') };
          }
          // .NET CLR runtime (populated by _parseClrHeader for managed
          // assemblies). Surfaces as a dedicated row on the Binary
          // Pivot card so "this is a .NET assembly, here's the CLR
          // flavour" is visible alongside the hashes and signer rather
          // than buried in the .NET Header drill-down card.
          const clrRuntime = (pe.dotnet && (pe.dotnet.runtimeVersionString || pe.dotnet.runtimeVersion)) || null;
          const card = BinarySummary.renderCard({
            bytes,
            fileSize: bytes.length,
            format: 'PE',
            formatDetail: pe.optional.magicStr + ' · ' + pe.coff.machineStr,
            importHash: pe.imphash || null,
            richHash: (pe.richHeader && pe.richHeader.richHash) || null,
            symHash: null,
            signer,
            compileTimestamp: {
              epoch: pe.coff.timestamp,
              displayStr: pe.coff.timestampStr,
            },
            entryPoint: {
              displayStr: this._hex(pe.optional.entryPoint, 8),
              section: (epi.section && epi.section.name) || null,
              anomaly: epAnomaly,
            },
            overlay: overlayInfo,
            packer: packerInfo,
            clrRuntime,
          });
          wrap.appendChild(card);
        }
      } catch (_) { /* summary card is best-effort */ }

      // ── File Headers ───────────────────────────────────────────────
      // Tier-C from here down — each card opts into triage auto-open via
      // `cardId`. Clean samples render with every card closed (triage-
      // first: read the verdict band + anomaly ribbon, drill only when
      // interested); anomalous samples auto-open the specific cards the
      // ribbon chips point at. Card-id keys are defined in
      // binary-anomalies.js::_detectPe().
      wrap.appendChild(this._renderSection('📋 PE Headers', this._renderHeaders(pe), 0, { cardId: 'headers' }));

      // ── Security Features ──────────────────────────────────────────
      wrap.appendChild(this._renderSection('🛡 Security Features', this._renderSecurity(pe), 0, { cardId: 'security' }));

      // ── Section Table ──────────────────────────────────────────────
      wrap.appendChild(this._renderSection('📦 Sections (' + pe.sections.length + ')', this._renderSections(pe), 0, { cardId: 'sections' }));

      // ── Imports ────────────────────────────────────────────────────
      if (pe.imports.length > 0) {
        const totalFuncs = pe.imports.reduce((s, d) => s + d.functions.length, 0);
        wrap.appendChild(this._renderSection(
          '📥 Imports (' + pe.imports.length + ' DLLs, ' + totalFuncs + ' functions)',
          this._renderImports(pe),
          0,
          { cardId: 'imports' }
        ));
      }

      // ── Delay-Loaded Imports (T3.9) ────────────────────────────────
      if (pe.delayImports && pe.delayImports.length > 0) {
        const totalDelayFuncs = pe.delayImports.reduce((s, d) => s + d.functions.length, 0);
        wrap.appendChild(this._renderSection(
          '⏳ Delay-Loaded Imports (' + pe.delayImports.length + ' DLLs, ' + totalDelayFuncs + ' functions)',
          this._renderImports({ imports: pe.delayImports }),
          0,
          { cardId: 'delay-imports' }
        ));
      }

      // ── Exports ────────────────────────────────────────────────────
      if (pe.exports && pe.exports.names.length > 0) {
        wrap.appendChild(this._renderSection(
          '📤 Exports (' + pe.exports.names.length + ')',
          this._renderExports(pe),
          0,
          { cardId: 'exports' }
        ));
      }

      // ── Resources ──────────────────────────────────────────────────
      if (pe.resources.length > 0) {
        wrap.appendChild(this._renderSection('🗂 Resources (' + pe.resources.length + ' types)', this._renderResources(pe), 0, { cardId: 'resources' }));
      }

      // ── Rich Header ────────────────────────────────────────────────
      if (pe.richHeader && pe.richHeader.entries.length > 0) {
        wrap.appendChild(this._renderSection('🔑 Rich Header (' + pe.richHeader.entries.length + ' entries)', this._renderRichHeader(pe), 0, { cardId: 'rich' }));
      }

      // ── TLS Callbacks (pre-entry-point hooks) ──────────────────────
      // IMAGE_DIRECTORY_ENTRY_TLS → AddressOfCallBacks; see
      // _parseTlsCallbacks(). A benign PE typically has zero; any count
      // ≥ 1 warrants a look (classic anti-debug / anti-sandbox vector,
      // MITRE T1546.009). Card only renders when at least one callback
      // was parsed so we don't pollute the viewer for the common case.
      if (pe.tls && pe.tls.callbacks && pe.tls.callbacks.length > 0) {
        wrap.appendChild(this._renderSection(
          '⏱ TLS Callbacks (' + pe.tls.callbacks.length + ')',
          this._renderTlsCallbacks(pe),
          0,
          { cardId: 'tls' }
        ));
      }

      // ── .NET CLR Header (managed assemblies) ───────────────────────
      // Present when IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR (index 14) is
      // populated; _parseClrHeader() surfaces the runtime version and
      // the IL-only / strong-name flags — the three pivots an analyst
      // cares about when triaging a managed sample.
      if (pe.dotnet) {
        wrap.appendChild(this._renderSection(
          '🔷 .NET CLR Header',
          this._renderDotnet(pe),
          0,
          { cardId: 'dotnet' }
        ));
      }

      // ── Authenticode Certificates ──────────────────────────────────
      if (pe.certificates && pe.certificates.length > 0) {
        wrap.appendChild(this._renderSection(
          '📜 Authenticode Certificates (' + pe.certificates.length + ')',
          this._renderCertificates(pe.certificates),
          0,
          { cardId: 'certificates' }
        ));
      }

      // ── Data Directories ───────────────────────────────────────────
      wrap.appendChild(this._renderSection('📂 Data Directories', this._renderDataDirs(pe), 0, { cardId: 'data-dirs' }));

      // ── Overlay (appended payload past end-of-image) ───────────────
      // Bytes past `max(section.rawDataOffset + section.rawDataSize)` are
      // the overlay. If the Certificate Table (IMAGE_DIRECTORY_ENTRY_SECURITY)
      // sits exactly there, it's a normal Authenticode-signed PE — we
      // annotate that case but flag it neutrally. Anything past the cert
      // table is a post-sign tail, the classic "sign-then-staple" tamper.
      try {
        const oStart = this._computeOverlayStart(pe);
        if (oStart > 0 && oStart < bytes.length && typeof BinaryOverlay !== 'undefined') {
          const certDD = pe.dataDirectories[4];
          const certRange = (certDD && certDD.rva > 0 && certDD.size > 0)
            ? [certDD.rva, certDD.rva + certDD.size]
            : null;
          const { el } = BinaryOverlay.renderCard({
            bytes,
            overlayStart: oStart,
            fileSize: bytes.length,
            baseName: (fileName || 'binary').replace(/\.[^.]+$/, ''),
            subtitle: 'past end-of-image',
            authenticodeRange: certRange,
          });
          wrap.appendChild(this._renderSection('📎 Overlay', el, 0, { cardId: 'overlay' }));
        }
      } catch (_) { /* overlay drill-down is best-effort */ }

      // ── Strings ────────────────────────────────────────────────────
      const totalStrings = pe.strings.ascii.length + pe.strings.unicode.length;
      if (totalStrings > 0) {
        wrap.appendChild(this._renderSection(
          '🔤 Strings (' + totalStrings + ')',
          this._renderStrings(pe),
          0,
          { cardId: 'strings' }
        ));
      }

    } catch (err) {
      this._renderFallback(wrap, bytes, err, fileName);
    }

    // Expose extracted strings as _rawText for IOC + EncodedContentDetector.
    // On parse failure we still populate this from the fallback string scan
    // so sidebar YARA / IOC extraction keep working on truncated binaries.
    //
    // VersionInfo values are stripped from the buffer fed to the generic IOC
    // regexes below — FileVersion strings like "1.9.0.8" / "10.0.17763.1"
    // are perfectly valid dotted-quad IPv4 literals and otherwise pattern-
    // match as IP IOCs even though they're pure attribution metadata. The
    // values still render in the Metadata panel via findings.metadata; this
    // only keeps them out of the IOC extractor's corpus. Consistent with
    // the "Metadata → IOC mirroring" convention in CONTRIBUTING.md — only
    // classic pivots (hashes, paths, GUIDs, MAC, emails, fingerprints)
    // should be mirrored to IOC, never attribution fluff.
    const _viSuppress = new Set();
    if (this._lastPe && this._lastPe.versionInfo) {
      for (const k of Object.keys(this._lastPe.versionInfo)) {
        const v = this._lastPe.versionInfo[k];
        if (v && typeof v === 'string') _viSuppress.add(v);
      }
    }
    const _filterVi = arr => _viSuppress.size
      ? arr.filter(s => !_viSuppress.has(s))
      : arr;
    if (this._lastStrings) {
      wrap._rawText = _filterVi(this._lastStrings).join('\n');
    } else if (wrap._fallbackStrings) {
      wrap._rawText = _filterVi(wrap._fallbackStrings).join('\n');
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

  /**
   * PE overlay start = max(rawDataOffset + rawDataSize) across sections
   * whose rawDataSize > 0. Sections with rawDataSize === 0 (BSS-style,
   * uninitialised data) do not consume file bytes and must not contribute
   * to the end-of-image pointer. Returns 0 when the PE has no sections
   * (should never happen for a well-formed image, but keeps the caller
   * branch-free).
   *
   * Shared by render() (for the overlay drill-down card) and
   * analyzeForSecurity() (for risk escalation + SHA-256 metadata).
   */
  _computeOverlayStart(pe) {
    if (!pe || !Array.isArray(pe.sections) || pe.sections.length === 0) return 0;
    let end = 0;
    for (const s of pe.sections) {
      if (!s || !s.rawDataSize) continue;
      const e = (s.rawDataOffset >>> 0) + (s.rawDataSize >>> 0);
      if (e > end) end = e;
    }
    return end;
  }

  // Render a collapsible Tier-C reference card. `opts.cardId` opts the
  // card into the triage auto-open system: clean samples start closed
  // (triage-first), anomalous samples auto-open the flagged cards.
  // `rowCount > 50` is still a size-based collapse hint that beats the
  // auto-open default on huge tables where size matters more than
  // anomalies (the chip itself already flags them).
  _renderSection(title, contentEl, rowCount, opts) {
    const sec = document.createElement('details');
    sec.className = 'pe-section';
    const collapse = rowCount && rowCount > 50;
    const cardId = opts && opts.cardId;
    let open;
    if (cardId) {
      // Triage mode: default closed, auto-open if anomalous.
      let auto = false;
      try {
        if (typeof BinaryTriage !== 'undefined') {
          auto = BinaryTriage.shouldAutoOpen({
            parsed: this._parsed,
            findings: this._findings || {},
            format: 'PE',
          }, cardId);
        }
      } catch (_) { /* best-effort */ }
      open = auto && !collapse;
    } else {
      // Legacy call sites (no cardId) keep the original rowCount behaviour.
      open = !collapse;
    }
    sec.open = !!open;
    const sum = document.createElement('summary');
    sum.innerHTML = this._esc(title) + (collapse ? ` <span class="bin-collapse-note">${rowCount} rows — click to expand</span>` : '');
    sec.appendChild(sum);
    sec.appendChild(contentEl);
    return sec;
  }

  _renderHeaders(pe) {
    // Entry-point anomaly annotation. `pe.entryPointInfo` is populated by
    // `_analyzeEntryPoint()` during `_parse()`. We surface the containing
    // section name always, and append a red badge for orphaned / W+X EPs
    // or an amber badge for EPs in a non-`.text`-like section.
    const ep = pe.entryPointInfo || {};
    let epCell = this._esc(this._hex(pe.optional.entryPoint, 8));
    if (!ep.skipped) {
      if (ep.orphaned) {
        epCell += ` <span class="pe-ep-badge pe-ep-bad" style="background:var(--risk-high);color:#fff;padding:1px 6px;border-radius:3px;margin-left:8px;font-size:0.85em">⚠ orphaned (outside any section)</span>`;
      } else if (ep.section) {
        const secName = this._esc(ep.section.name || '(unnamed)');
        if (ep.inWX) {
          epCell += ` <span class="pe-ep-badge pe-ep-bad" style="background:var(--risk-high);color:#fff;padding:1px 6px;border-radius:3px;margin-left:8px;font-size:0.85em">⚠ in W+X section ${secName}</span>`;
        } else if (ep.notInText) {
          epCell += ` <span class="pe-ep-badge pe-ep-warn" style="background:var(--risk-med);color:#000;padding:1px 6px;border-radius:3px;margin-left:8px;font-size:0.85em">⚠ in ${secName} (not a code section)</span>`;
        } else {
          epCell += ` <span class="pe-ep-badge" style="color:var(--text-muted);margin-left:8px;font-size:0.85em">in ${secName}</span>`;
        }
      }
    }

    const rows = [
      ['Type', pe.coff.isDLL ? 'Dynamic Link Library (DLL)' : pe.coff.isSystem ? 'System Driver' : 'Executable'],
      ['Architecture', pe.optional.magicStr],
      ['Machine', pe.coff.machineStr],
      ['Entry Point', epCell],
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
    return this._buildTable(['Field', 'Value'], rows, true);
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
    const color = entropy > 7.0 ? 'var(--risk-high)' : entropy > 6.0 ? 'var(--risk-med)' : 'var(--risk-low)';
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

  // ── Resources renderer (with click-to-drilldown on payload leaves) ──────
  //
  // Two-table layout:
  //   1. Type summary (original shape — Type / ID / Contents)
  //   2. Leaf detail (Type · Name · Lang · Size · Magic), rows clickable
  //      when the leaf looks like it could be a self-contained file that
  //      another Loupe renderer could handle — PE / ELF / Mach-O / ZIP /
  //      RAR / 7z / gzip / CAB / MSI-OLE / PDF / XML / shebang script,
  //      plus any RCDATA / HTML / MANIFEST / named resource (common
  //      stashing slots for secondary payloads).
  //
  // Clicking a payload-candidate row builds a synthetic File whose name
  // encodes the resource coordinates (type, name-or-ID, lang) and an
  // extension hint from the magic sniff, then dispatches `open-inner-file`
  // on the card root. _wireInnerFileListener on the PE docEl (attached in
  // app-load.js::pe()) catches that event, pushes a nav-stack entry and
  // re-enters _loadFile() — identical drill-down semantics to the ZIP /
  // MSI / EML family of renderers.
  _renderResources(pe) {
    const wrap = document.createElement('div');
    const leaves = (pe.resources && pe.resources.leaves) || [];

    // ── Type summary (unchanged external shape) ─────────────────────────
    const summaryRows = pe.resources.map(r => [
      r.typeName,
      r.id.toString(),
      r.count > 0 ? r.count + ' leaves' : 'leaf',
    ]);
    wrap.appendChild(this._buildTable(['Type', 'ID', 'Contents'], summaryRows));

    if (leaves.length === 0) return wrap;

    // ── Leaf detail table (drill-down) ──────────────────────────────────
    const header = document.createElement('div');
    header.className = 'pe-rich-info';
    header.textContent = `${leaves.length} leaf resource${leaves.length === 1 ? '' : 's'} parsed — click a payload row to analyse it as a fresh file`;
    wrap.appendChild(header);

    const rows = leaves.map(L => {
      const nameLabel = L.nameStr
        ? L.nameStr
        : (L.nameId != null ? '#' + L.nameId : '—');
      const langLabel = L.langId != null ? this._hex(L.langId, 4) : '—';
      const sizeLabel = L.size.toLocaleString() + ' B';
      const magicLabel = L.magic
        ? `<span class="doc-meta-tag">${this._esc(L.magic.label)}</span>`
        : '—';
      return [L.typeName, nameLabel, langLabel, sizeLabel, magicLabel];
    });
    const table = this._buildTable(
      ['Type', 'Name', 'Lang', 'Size', 'Magic / Hint'],
      rows,
      true
    );

    // Classes of leaves that are meaningless to redispatch — they have
    // no standalone file header any of our renderers understand, so
    // routing them would just land in the hex-dump fallback and pollute
    // the nav stack.
    //
    //   1 cursor · 2 bitmap · 3 icon · 4 menu · 5 dialog · 6 string-table
    //   7 font-dir · 8 font · 9 accelerator · 12 group-cursor ·
    //   14 group-icon · 16 version-info · 11 message-table
    const INERT_TYPE_IDS = new Set([1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 14, 16]);

    const tbody = table.querySelector('tbody');
    if (tbody) {
      const trs = Array.from(tbody.querySelectorAll('tr'));
      trs.forEach((tr, i) => {
        const L = leaves[i];
        if (!L) return;
        const isInertTypeById = !L.typeIsNamed && INERT_TYPE_IDS.has(L.typeId);
        const hasMagic = !!(L.magic && L.magic.extHint);
        // Payload candidate:
        //   – magic sniff produced a recognised container / format hint, OR
        //   – named resource type (custom type — attacker stashing slot), OR
        //   – RCDATA (10) / HTML (23) / MANIFEST (24) even without magic
        //     (common home for scripts / manifests / blobs).
        const isPayloadCandidate = !isInertTypeById && (
          hasMagic ||
          L.typeIsNamed ||
          L.typeId === 10 || L.typeId === 23 || L.typeId === 24
        );
        if (!isPayloadCandidate) return;

        tr.classList.add('bin-clickable');
        tr.title = 'Click to analyse this resource as a fresh file';
        tr.addEventListener('click', () => {
          const bytes = this._bytes;
          if (!bytes || L.fileOffset < 0 || L.fileOffset + L.size > bytes.length) return;
          const payload = bytes.subarray(L.fileOffset, L.fileOffset + L.size);

          // Pick an extension hint: magic sniff wins, then sensible
          // defaults per type, then plain .bin.
          let ext;
          if (hasMagic) ext = L.magic.extHint;
          else if (L.typeId === 23) ext = '.html';
          else if (L.typeId === 24) ext = '.xml';
          else ext = '.bin';

          // Compose a filename that's useful in the nav breadcrumb:
          //   <parent-base>.res.<type>.<name-or-id>[.lang].<ext>
          const parentBase = (pe._fileName || 'binary').replace(/\.[^.]+$/, '');
          const typeSlug = String(L.typeName || L.typeId).replace(/[^\w\-]+/g, '_');
          const nameSlug = L.nameStr
            ? String(L.nameStr).replace(/[^\w\-]+/g, '_').slice(0, 40)
            : (L.nameId != null ? String(L.nameId) : 'leaf');
          const langSlug = L.langId != null ? ('.lang' + L.langId) : '';
          const fname = `${parentBase}.res.${typeSlug}.${nameSlug}${langSlug}${ext}`
            .replace(/[<>:"/\\|?*\x00-\x1f]/g, '_');

          const f = new File([payload], fname, { type: 'application/octet-stream' });
          tr.dispatchEvent(new CustomEvent('open-inner-file', { bubbles: true, detail: f }));
        });
      });
    }
    wrap.appendChild(table);
    return wrap;
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

  // ═══════════════════════════════════════════════════════════════════════
  //  TLS Callbacks renderer
  // ═══════════════════════════════════════════════════════════════════════
  //
  // Renders the callback VA array as a clickable table. Each row expands
  // to a hex dump of the callback's first 64 bytes — enough to eyeball a
  // `ret` / `int3` stub vs. a real unpacker prologue without jumping out
  // to a disassembler.

  _renderTlsCallbacks(pe) {
    const div = document.createElement('div');
    const info = document.createElement('div');
    info.className = 'pe-rich-info';
    const n = pe.tls.callbacks.length;
    info.textContent = `${n} callback${n === 1 ? '' : 's'} registered — invoked by the loader before EntryPoint (array @ RVA ${this._hex(pe.tls.callbackArrayRva, 8)})`;
    div.appendChild(info);

    const rows = pe.tls.callbacks.map((cb, i) => {
      const wxFlag = cb.section && pe.sections.find(s => s.name === cb.section && s.isWritable && s.isExecutable);
      const secLabel = cb.section
        ? (wxFlag ? `${cb.section} ⚠ W+X` : cb.section)
        : '— (outside any section)';
      return [
        String(i + 1),
        this._hex(cb.va, pe.is64 ? 16 : 8),
        this._hex(cb.rva >>> 0, 8),
        cb.fileOffset != null ? this._hex(cb.fileOffset, 8) : '—',
        secLabel,
      ];
    });

    const table = this._buildTable(['#', 'VA', 'RVA', 'File Offset', 'Section'], rows);
    // Make rows clickable → inline hex dump of the first 64 B at each callback
    const tbody = table.querySelector('tbody');
    if (tbody) {
      const trs = Array.from(tbody.querySelectorAll('tr'));
      trs.forEach((tr, i) => {
        const cb = pe.tls.callbacks[i];
        if (!cb || cb.fileOffset == null) return;
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
            td.colSpan = 5;
            td.appendChild(this._renderHexDump(cb.fileOffset, 64));
            hexRow.appendChild(td);
            tr.after(hexRow);
            tr.classList.add('bin-expanded');
          }
        });
      });
    }
    div.appendChild(table);
    return div;
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  .NET CLR Header renderer
  // ═══════════════════════════════════════════════════════════════════════
  //
  // Displays the three pivots an analyst cares about when triaging a
  // managed assembly: the CLR runtime version string (from the BSJB
  // metadata root), the IL-only / native-code flags, and the strong-
  // name signing status. Everything else (metadata RVA / size / token /
  // resources RVA) is shown as secondary rows so the pivot block stays
  // compact.

  _renderDotnet(pe) {
    const d = pe.dotnet;
    const div = document.createElement('div');
    const info = document.createElement('div');
    info.className = 'pe-rich-info';
    const bits = [];
    if (d.isILOnly) bits.push('IL-only'); else bits.push('Mixed / Native');
    if (d.hasStrongName) bits.push('Strong-name signed');
    if (d.prefer32Bit) bits.push('Prefer 32-bit');
    if (d.isILLibrary) bits.push('IL Library');
    info.textContent = `Managed .NET assembly — ${d.runtimeVersionString || ('runtime ' + d.runtimeVersion)} · ${bits.join(' · ')}`;
    div.appendChild(info);

    const rows = [
      ['Runtime Version (CLR)', d.runtimeVersionString || '(not parsed)'],
      ['Runtime Major / Minor', d.runtimeVersion],
      ['Metadata Version', d.metadataMajor != null ? (d.metadataMajor + '.' + d.metadataMinor) : '—'],
      ['Flags', this._hex(d.flags, 8)],
      ['IL Only', d.isILOnly ? '✅ Yes' : '❌ No'],
      ['Native Code', d.hasNativeCode ? '⚠ Yes (mixed-mode)' : 'No'],
      ['Native Entry Point', d.hasNativeEntryPoint ? '⚠ Yes' : 'No'],
      ['Strong-Name Signed', d.hasStrongName ? '✅ Yes' : '❌ No'],
      ['Prefer 32-bit', d.prefer32Bit ? 'Yes' : 'No'],
      ['Requires 32-bit', d.requires32Bit ? 'Yes' : 'No'],
      ['Track Debug Data', d.trackDebugData ? 'Yes' : 'No'],
      ['Entry Point Token', this._hex(d.entryPointToken, 8)],
      ['Metadata Root RVA / Size', this._hex(d.metadataRva, 8) + '  ·  ' + d.metadataSize.toLocaleString() + ' B'],
      ['Resources RVA / Size', d.resourcesRva
        ? (this._hex(d.resourcesRva, 8) + '  ·  ' + d.resourcesSize.toLocaleString() + ' B')
        : '—'],
      ['Strong-Name Sig RVA / Size', d.strongNameRva
        ? (this._hex(d.strongNameRva, 8) + '  ·  ' + d.strongNameSize.toLocaleString() + ' B')
        : '—'],
    ];
    div.appendChild(this._buildTable(['Field', 'Value'], rows, true));
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

    // Categorised strings preview — mutex / pipe / PDB / user-path /
    // registry / Rust-panic triage card. No-op when no forensically
    // interesting categories match the corpus.
    try {
      if (typeof BinaryStrings !== 'undefined' && BinaryStrings.renderCategorisedStringsTable) {
        const catCard = BinaryStrings.renderCategorisedStringsTable(allStrings);
        if (catCard) div.appendChild(catCard);
      }
    } catch (_) { /* best-effort */ }

    const pillBar = document.createElement('div');
    pillBar.style.cssText = 'display:flex;align-items:center;gap:6px;margin-bottom:8px;';

    const pillGroup = document.createElement('div');
    pillGroup.className = 'btn-pill-group';
    const saveBtn = document.createElement('button');
    saveBtn.className = 'tb-btn tb-action-btn';
    saveBtn.textContent = '💾 Save';
    saveBtn.title = 'Save strings as .txt';
    saveBtn.addEventListener('click', () => {
      window.FileDownload.downloadText(allStrings.join('\n'), 'strings.txt', 'text/plain');
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
      if (pe.richHeader && pe.richHeader.richHash) {
        findings.metadata['RichHash'] = pe.richHeader.richHash;
      }

      // ── .NET / CLR managed-assembly metadata ───────────────────────
      // Populated by `_parseClrHeader()` during `_parse()`. Surfaced as
      // metadata rows (runtime version, IL-only / strong-name flags) and
      // as an IOC.PATTERN so analysts can pivot on "managed sample"
      // clusters. Managed .NET code is T1059.005 — a first-class
      // execution vector distinct from native code.
      if (pe.dotnet) {
        findings.metadata['Format'] = '.NET Assembly';
        findings.metadata['CLR Runtime'] = pe.dotnet.runtimeVersionString || pe.dotnet.runtimeVersion;
        if (pe.dotnet.isILOnly)      findings.metadata['IL Only']            = 'Yes';
        if (pe.dotnet.hasNativeCode) findings.metadata['Mixed-Mode / Native'] = 'Yes';
        if (pe.dotnet.hasStrongName) findings.metadata['Strong-Name Signed'] = 'Yes';
        if (pe.dotnet.prefer32Bit)   findings.metadata['Prefer 32-bit']      = 'Yes';
        const flagBits = [];
        if (pe.dotnet.isILOnly) flagBits.push('IL-only');
        if (pe.dotnet.hasNativeCode) flagBits.push('mixed-mode native');
        if (pe.dotnet.hasStrongName) flagBits.push('strong-name signed');
        pushIOC(findings, {
          type: IOC.PATTERN,
          value: '.NET Managed Assembly [T1059.005]',
          severity: 'medium',
          note: `Managed .NET binary — CLR runtime ${pe.dotnet.runtimeVersionString || pe.dotnet.runtimeVersion}${flagBits.length ? ' (' + flagBits.join(', ') + ')' : ''}.`,
          _noDomainSibling: true,
        });
        issues.push(`.NET managed assembly — CLR runtime ${pe.dotnet.runtimeVersionString || pe.dotnet.runtimeVersion} (T1059.005)`);
        riskScore += 1;
        if (pe.dotnet.hasStrongName) {
          pushIOC(findings, {
            type: IOC.PATTERN,
            value: 'Strong-name signed .NET assembly',
            severity: 'info',
            note: `Strong-name signature blob at RVA ${this._hex(pe.dotnet.strongNameRva, 8)} (${pe.dotnet.strongNameSize.toLocaleString()} B). Strong-name is an integrity check, not a trust anchor.`,
            _noDomainSibling: true,
          });
        }
        if (pe.dotnet.hasNativeCode && !pe.dotnet.isILOnly) {
          // Mixed-mode assemblies (C++/CLI etc.) execute native code
          // alongside IL — doubles the attack surface because both paths
          // run inside the same process.
          issues.push('.NET mixed-mode assembly — embeds native (non-IL) code paths alongside managed IL');
          riskScore += 0.5;
        }
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

      // ── T3.9: Suspicious delay-loaded imports ─────────────────────
      if (pe.delayImports && pe.delayImports.length > 0) {
        const totalDelayFuncs = pe.delayImports.reduce((s, d) => s + d.functions.length, 0);
        findings.metadata['Delay-Loaded DLLs'] = String(pe.delayImports.length);
        for (const imp of pe.delayImports) {
          for (const fn of imp.functions) {
            if (fn.isSuspicious) {
              pushIOC(findings, {
                type: IOC.PATTERN,
                value: `Suspicious API ${fn.name} hidden in delay-loaded import from ${imp.dllName}`,
                severity: 'medium',
                note: fn.suspiciousInfo,
                _noDomainSibling: true,
              });
              riskScore += 0.5;
            }
          }
        }
      }

      // ── Extract IOCs from parsed Authenticode certificates ─────────
      // CRL Distribution Points and AIA (OCSP / CA Issuers) are extracted
      // from DER-bounded ASN.1 fields via X509Renderer.parseCertificatesFromCMS,
      // so the values are byte-accurate with no trailing binary junk.
      // Raw-string URL extraction below skips any URL that is a prefix-match
      // against these clean cert URLs to avoid duplicates with DER artifacts.
      const certUrls = new Set();
      for (const cert of pe.certificates) {
        for (const ext of (cert.extensions || [])) {
          if (ext.crlPoints) {
            for (const uri of ext.crlPoints) {
              if (!certUrls.has(uri)) {
                certUrls.add(uri);
                pushIOC(findings, {
                  type: IOC.URL, value: uri, severity: 'info',
                  note: 'CRL Distribution Point',
                });
              }
            }
          }
          if (ext.accessMethods) {
            for (const am of ext.accessMethods) {
              if (am.location && !certUrls.has(am.location)) {
                certUrls.add(am.location);
                pushIOC(findings, {
                  type: IOC.URL, value: am.location, severity: 'info',
                  note: 'AIA (' + am.method + ')',
                });
              }
            }
          }
        }
      }

      // ── Extract IOCs from strings ──────────────────────────────────
      // IOCs extracted from ASCII + UTF-16LE string dumps. Offsets are into
      // the joined synthetic buffer, not PE file bytes — so we carry only
      // _highlightText (the raw match) and let the sidebar's text-search
      // click-to-focus locate the string in the rendered strings pane.
      const allStrings = [...pe.strings.ascii, ...pe.strings.unicode].join('\n');
      const _urlRx = /https?:\/\/[^\s"'<>()\[\]{}\u0000-\u001F]{6,}/g;
      const _uncRx = /\\\\[\w.\-]{2,}(?:\\[\w.\-]+)+/g;
      const URL_CAP = 50, UNC_CAP = 20;
      // DER SEQUENCE tag (0x30 = ASCII '0') and following length/tag bytes
      // frequently fuse onto URLs extracted from binary string dumps.
      // Clean each match before dedup and before the cert-URL prefix guard.
      const _derJunkRx = /([^0-9])0[\d]{0,2}[^a-zA-Z0-9]{0,3}$/;
      const urlMatches = [...new Set(
        [...allStrings.matchAll(_urlRx)].map(m => m[0].replace(_derJunkRx, '$1')),
      )];
      for (const url of urlMatches.slice(0, URL_CAP)) {
        // Skip URLs that match a cert URL already pushed from parsed
        // certificates above (clean cert version has better metadata).
        let isCertUrl = false;
        for (const cu of certUrls) {
          if (url.startsWith(cu)) { isCertUrl = true; break; }
        }
        if (isCertUrl) continue;
        pushIOC(findings, {
          type: IOC.URL, value: url, severity: 'info', highlightText: url,
        });
      }
      if (urlMatches.length > URL_CAP) {
        pushIOC(findings, {
          type: IOC.INFO,
          value: `URL extraction truncated at ${URL_CAP} — binary contains ${urlMatches.length} unique URLs`,
          severity: 'info',
        });
      }
      const uncMatches = [...new Set([...allStrings.matchAll(_uncRx)].map(m => m[0]))];
      for (const unc of uncMatches.slice(0, UNC_CAP)) {
        pushIOC(findings, {
          type: IOC.UNC_PATH, value: unc, severity: 'medium', highlightText: unc,
        });
      }
      if (uncMatches.length > UNC_CAP) {
        pushIOC(findings, {
          type: IOC.INFO,
          value: `UNC path extraction truncated at ${UNC_CAP} — binary contains ${uncMatches.length} unique UNC paths`,
          severity: 'info',
        });
      }

      // ── Categorised strings (mutex / pipe / PDB / registry / paths) ─
      // `allStrings` above also drives the URL/UNC pass; the same corpus
      // is handed to BinaryStrings.emit which dedups + caps + pushes each
      // category onto findings.interestingStrings as the right IOC.* type.
      // A mutex / named pipe / registry key is forensic gold on Windows
      // (mutex names cluster sibling samples; PDB paths leak build
      // usernames); surfacing them as first-class IOCs rather than
      // leaving them buried in the Strings pane pays for itself on the
      // very first triage pass.
      try {
        if (typeof BinaryStrings !== 'undefined' && BinaryStrings.emit) {
          const strCounts = BinaryStrings.emit(findings, allStrings);
          if (strCounts.mutexes)       findings.metadata['Mutex Names']      = String(strCounts.mutexes);
          if (strCounts.namedPipes)    findings.metadata['Named Pipes']      = String(strCounts.namedPipes);
          if (strCounts.pdbPaths)      findings.metadata['PDB Paths (str)']  = String(strCounts.pdbPaths);
          if (strCounts.userPaths)     findings.metadata['Build-host Paths'] = String(strCounts.userPaths);
          if (strCounts.registryPaths) findings.metadata['Registry Keys']    = String(strCounts.registryPaths);
          if (strCounts.rustPanics)    findings.metadata['Rust Panic Paths'] = String(strCounts.rustPanics);
        }
      } catch (_) { /* classification is best-effort */ }

      // ── Export-anomaly flags (side-loading / forwarders / ordinal-only) ─
      // See src/binary-exports.js. All three signals apply to PE DLLs: a
      // filename match against the hijack-libs side-load set (high), every
      // non-platform forwarder string (medium), and ordinal-only-heavy
      // export tables (medium). Passing isLib gates the side-load check so
      // EXEs accidentally named version.dll don't flag.
      try {
        if (typeof BinaryExports !== 'undefined' && BinaryExports.emit && pe.exports) {
          const expCounts = BinaryExports.emit(findings, {
            isLib: !!(pe.coff && pe.coff.isDLL),
            fileName: fileName || pe._fileName || '',
            exportNames: pe.exports.names.map(n => n.name).filter(Boolean),
            forwardedExports: pe.exports.forwarders || [],
            ordinalOnlyCount: pe.exports.ordinalOnlyCount || 0,
          });
          if (expCounts.sideLoadHit)    { findings.metadata['DLL Side-Load Host']   = 'Yes'; riskScore += 2; }
          if (expCounts.forwarderCount) { findings.metadata['Forwarded Exports']    = String(expCounts.forwarderCount); riskScore += Math.min(expCounts.forwarderCount * 0.5, 2); }
          if (expCounts.ordinalOnly)    { findings.metadata['Ordinal-Only Exports'] = String(expCounts.ordinalOnly); }
          if (expCounts.ordinalOnlyRatio >= 0.5 && expCounts.ordinalOnly >= 4) riskScore += 1;
        }
      } catch (_) { /* export-anomaly analysis is best-effort */ }


      // ── Format-family heuristics (XLL / AutoHotkey / Installer / Go) ─
      //   Each populates narrow `findings.metadata` rows so the Summary /
      //   sidebar shows what sub-type of PE this really is, plus autoExec
      //   bumps for the ones that matter for threat scoring. Keep these
      //   conservative — they fire on extension-agnostic content signals
      //   and should only *add* context, never downgrade other findings.
      if (pe.isXll) {
        findings.metadata['Format'] = pe.xllIsExcelDna ? 'Excel Add-in (XLL, Excel-DNA managed)' : 'Excel Add-in (XLL)';
        if (pe.xllExports && pe.xllExports.length) {
          findings.metadata['XLL Hooks'] = pe.xllExports.join(', ');
        }
        // XLL add-ins auto-execute xlAutoOpen when opened in Excel — treat as
        // macro-equivalent auto-exec surface. Unsigned XLLs are especially
        // risky (Excel will still load them from trusted locations).
        issues.push('Excel XLL add-in — xlAutoOpen runs automatically when the file is opened in Excel (MITRE T1137.006)');
        riskScore += 2;
        if (!hasCert) riskScore += 1;
      }

      if (pe.isAutoHotkey) {
        findings.metadata['Format'] = 'Compiled AutoHotkey Script';
        if (pe.autoHotkeyScript != null) {
          findings.metadata['AHK Script Size'] = pe.autoHotkeyScript.length.toLocaleString() + ' bytes';
        }
        issues.push('Compiled AutoHotkey script embedded as RT_RCDATA — source is visible in the viewer; AHK can send keystrokes, read the clipboard, and launch arbitrary processes');
        riskScore += 1.5;
      }

      if (pe.installerType) {
        findings.metadata['Installer'] = pe.installerType + (pe.installerVersion ? ' ' + pe.installerVersion : '');
        // Installers are benign-looking wrappers around a payload archive we
        // cannot inspect without unpacking. Surface as an info-level issue so
        // the analyst knows further triage (outside Loupe) is warranted.
        issues.push(`${pe.installerType} installer — embeds a payload archive as a PE overlay that Loupe does not unpack; triage the extracted setup script/contents separately`);
      }

      if (pe.isGoBinary) {
        findings.metadata['Format'] = 'Go Binary';
        if (pe.goBuildInfo) {
          if (pe.goBuildInfo.version) findings.metadata['Go Version'] = pe.goBuildInfo.version;
          if (pe.goBuildInfo.path) findings.metadata['Go Module Path'] = pe.goBuildInfo.path;
          if (pe.goBuildInfo.vcs && pe.goBuildInfo.revision) {
            findings.metadata['Go VCS'] = `${pe.goBuildInfo.vcs} ${pe.goBuildInfo.revision.slice(0, 12)}`;
          }
          if (pe.goBuildInfo.buildTime) findings.metadata['Go Build Time'] = pe.goBuildInfo.buildTime;
        }
        // Go binaries bundle their full runtime — the tiny imports-table
        // heuristic for "packed" fires on almost every Go EXE. Explicitly
        // note the type so the sidebar reader doesn't over-index on that.
      }

      // ── Overlay detection (appended payload past end-of-image) ─────
      // PE overlay = bytes past max(section.rawDataOffset + rawDataSize).
      // Three possible shapes:
      //   1. Overlay exactly matches dataDirectories[4] (Authenticode) →
      //      normal signed binary, don't flag.
      //   2. Bytes past the cert table → classic "sign-then-staple" tamper.
      //      Critical finding.
      //   3. No cert, but a large high-entropy trailer with unrecognised
      //      magic → stacked dropper / encrypted blob. High finding.
      // The renderer's overlay card also surfaces this; here we just
      // drive the risk score and expose the overlay SHA-256 as a
      // clickable IOC pivot.
      try {
        const oStart = this._computeOverlayStart(pe);
        if (oStart > 0 && oStart < bytes.length && typeof BinaryOverlay !== 'undefined') {
          const overlayBytes = bytes.subarray(oStart, bytes.length);
          const overlaySize = overlayBytes.length;
          const overlayPct = (overlaySize / Math.max(1, bytes.length)) * 100;
          const overlayEntropy = BinaryOverlay.shannonEntropy(overlayBytes);
          const overlayMagic = BinaryOverlay.sniffMagic(overlayBytes.subarray(0, 32));

          const certDD = pe.dataDirectories[4];
          const certStart = (certDD && certDD.rva > 0 && certDD.size > 0) ? certDD.rva : 0;
          const certEnd = certStart ? (certStart + certDD.size) : 0;
          const overlayIsJustAuthenticode = certStart > 0 && oStart === certStart && bytes.length === certEnd;
          const overlayHasPostSignTail = certStart > 0 && bytes.length > certEnd && oStart <= certEnd;

          findings.metadata['Overlay Size'] = overlaySize.toLocaleString() + ' bytes';
          findings.metadata['Overlay Entropy'] = overlayEntropy.toFixed(3);
          if (overlayMagic) findings.metadata['Overlay Magic'] = overlayMagic.label;
          if (overlayIsJustAuthenticode) {
            findings.metadata['Overlay Type'] = 'Authenticode signature (PKCS#7)';
          } else if (overlayHasPostSignTail) {
            findings.metadata['Overlay Type'] = 'Post-signature tail (bytes appended after Authenticode blob)';
            issues.push(`Post-signature overlay — ${overlaySize.toLocaleString()} bytes appended *after* the Authenticode blob. Classic sign-then-staple tamper; the signature no longer covers these bytes.`);
            riskScore += 4;
            pushIOC(findings, {
              type: IOC.PATTERN,
              value: `Post-signature overlay tail [T1553.002]`,
              severity: 'high',
              note: `Bytes appended past the Authenticode signature (${overlaySize.toLocaleString()} B, entropy ${overlayEntropy.toFixed(2)})`,
              _noDomainSibling: true,
            });
          } else if (!certStart) {
            // No cert at all — judge the overlay on its own merits.
            const large = overlayPct > 10;
            const highEntropy = overlayEntropy > 7.2;
            const unrecognised = !overlayMagic;
            if (large && highEntropy && unrecognised) {
              issues.push(`Large high-entropy overlay (${overlaySize.toLocaleString()} B, ${overlayPct.toFixed(1)}% of file, entropy ${overlayEntropy.toFixed(2)}) with no recognised container magic — likely packed / encrypted payload`);
              riskScore += 2;
              pushIOC(findings, {
                type: IOC.PATTERN,
                value: `High-entropy overlay [T1027.002]`,
                severity: 'high',
                note: `Appended payload: ${overlaySize.toLocaleString()} B (${overlayPct.toFixed(1)}%), entropy ${overlayEntropy.toFixed(2)}, no recognised magic`,
                _noDomainSibling: true,
              });
            } else if (overlayMagic) {
              findings.metadata['Overlay Type'] = `Appended ${overlayMagic.label}`;
            }
          }

          // SHA-256 is async (crypto.subtle). We can't await here without
          // making analyzeForSecurity async; instead compute it directly
          // using a cheap synchronous pathway — BinaryOverlay.sha256Hex
          // returns a Promise that resolves before most renderers finish
          // their DOM work, but findings already landed in the sidebar.
          // Accept that the hash row appears on a subsequent refresh; it's
          // still a useful pivot. (The render-side card populates its own
          // SHA-256 DOM row via promise resolution.)
          //
          // We skip Authenticode-exact overlays — the cert blob's SHA-256
          // is already the "signature hash" which the Certificates section
          // shows separately.
          if (!overlayIsJustAuthenticode) {
            BinaryOverlay.sha256Hex(overlayBytes).then(hex => {
              if (hex) findings.metadata['Overlay SHA-256'] = hex;
            });
          }
        }
      } catch (_) { /* overlay analysis is best-effort */ }

      // ── Mirror classic-pivot metadata into IOC table ────────────────
      // PE binaries carry a set of metadata fields that are actionable
      // pivots (imphash clusters similar samples; PDB paths leak build
      // hosts / usernames; OriginalFilename / InternalName survives
      // renaming for tracking); these need to land in the sidebar IOC
      // table, not just in the File Info metadata pane. Attribution
      // fluff (CompanyName, FileDescription, ProductName) stays
      // metadata-only per the "Option B" classic-pivot policy.
      mirrorMetadataIOCs(findings, {
        'Imphash':           IOC.HASH,
        'RichHash':          IOC.HASH,
        'PDB Path':          IOC.FILE_PATH,
        'Original Filename': IOC.FILE_PATH,
        'Internal Name':     IOC.FILE_PATH,
        'Export DLL Name':   IOC.FILE_PATH,
        'Go Module Path':    IOC.PATTERN,
        'Overlay SHA-256':   IOC.HASH,
      });


      // ── Entry-point sanity flags ───────────────────────────────────
      // `pe.entryPointInfo` was populated in _parse(). Two well-known
      // anomalies warrant a high-severity flag; both map to T1027.*.
      //   • orphan   — EP outside any section (hand-rolled loader stub).
      //   • W+X      — EP in a section that is simultaneously writable
      //                and executable (self-modifying unpacker).
      // A third, softer case (EP in a non-`.text`-like section) is
      // metadata-only — surfaced via the header badge but not pushed as
      // an IOC because a few legitimate linkers do this (e.g. `.init`
      // crt startup on old GCC builds).
      try {
        const epi = pe.entryPointInfo;
        if (epi && !epi.skipped) {
          if (epi.orphaned) {
            issues.push('Orphan entry point — EP RVA does not fall inside any section (T1027)');
            riskScore += 3;
            pushIOC(findings, {
              type: IOC.PATTERN,
              value: 'Orphan entry point [T1027]',
              severity: 'high',
              note: `Entry point ${this._hex(epi.rva, 8)} lies outside every defined section — typical of hand-rolled loader stubs.`,
              _noDomainSibling: true,
            });
          } else if (epi.inWX) {
            issues.push(`Entry point in W+X section "${epi.section.name}" — self-modifying unpacker pattern (T1027.002)`);
            riskScore += 2.5;
            pushIOC(findings, {
              type: IOC.PATTERN,
              value: 'Entry point in W+X section [T1027.002]',
              severity: 'high',
              note: `Entry point ${this._hex(epi.rva, 8)} lives in section "${epi.section.name}" which is marked both writable and executable.`,
              _noDomainSibling: true,
            });
          }
        }
      } catch (_) { /* entry-point analysis is best-effort */ }

      // ── TLS callbacks ──────────────────────────────────────────────
      // One or more registered callbacks = anti-debug / early-exec hook
      // (loader invokes them *before* EP). Medium by default; escalated
      // to high when an anti-debug / sandbox-evasion capability is also
      // present (classic evasion chain). MITRE T1546.009.
      try {
        if (pe.tls && pe.tls.callbacks && pe.tls.callbacks.length > 0) {
          const n = pe.tls.callbacks.length;
          findings.metadata['TLS Callbacks'] = String(n);
          const hasAntiDebugImport = suspiciousImports.some(s =>
            /debug|sandbox|evasion/i.test(s.info));
          // Also check for a TLS callback that lives in a W+X section —
          // strong indicator of a self-modifying unpacker hidden behind the
          // TLS hook.
          const cbInWX = pe.tls.callbacks.some(cb => {
            if (!cb.section) return false;
            const sec = pe.sections.find(s => s.name === cb.section);
            return sec && sec.isWritable && sec.isExecutable;
          });
          const severity = (hasAntiDebugImport || cbInWX) ? 'high' : 'medium';
          const detail = cbInWX
            ? ' — at least one callback lives in a W+X section'
            : (hasAntiDebugImport ? ' — paired with anti-debug / sandbox-evasion imports' : '');
          issues.push(`${n} TLS callback${n === 1 ? '' : 's'} registered — executed before EntryPoint (T1546.009)${detail}`);
          riskScore += (severity === 'high') ? 2.5 : 1.5;
          pushIOC(findings, {
            type: IOC.PATTERN,
            value: `TLS callbacks registered (${n}) [T1546.009]`,
            severity,
            note: `AddressOfCallBacks array @ RVA ${this._hex(pe.tls.callbackArrayRva, 8)} — ${n} callback${n === 1 ? '' : 's'} invoked by the Windows loader before the main entry point.${detail}`,
            _noDomainSibling: true,
          });
        }
      } catch (_) { /* TLS risk analysis is best-effort */ }

      // ── Capability tagging (capa-lite) ─────────────────────────────
      // Turn the wall of "X suspicious APIs" into named MITRE-tagged
      // behaviours. Evidence is carried on each IOC.PATTERN row so the
      // sidebar's click-to-focus jumps to the matched API name in the
      // imports / strings pane. Severity contributes to the risk score.
      try {
        const capImports = [];
        for (const imp of (pe.imports || [])) {
          for (const fn of (imp.functions || [])) {
            if (fn && fn.name) capImports.push(String(fn.name).toLowerCase());
          }
        }
        const capDylibs = (pe.imports || []).map(i => String(i.dllName || '').toLowerCase());
        const capStrings = [...pe.strings.ascii, ...pe.strings.unicode];
        const caps = (typeof Capabilities !== 'undefined' && Capabilities && Capabilities.detect)
          ? Capabilities.detect({ imports: capImports, dylibs: capDylibs, strings: capStrings })
          : [];
        findings.capabilities = caps;
        const sevWeight = { critical: 3, high: 2, medium: 1, low: 0.5, info: 0 };
        for (const c of caps) {
          pushIOC(findings, {
            type: IOC.PATTERN,
            value: `${c.name} [${c.mitre}]`,
            severity: c.severity === 'critical' ? 'high' : c.severity,
            note: c.description + (c.evidence && c.evidence.length ? ` — evidence: ${c.evidence.slice(0, 4).join(', ')}` : ''),
            _noDomainSibling: true,
          });
          issues.push(`${c.name} (${c.mitre})`);
          riskScore += sevWeight[c.severity] || 0;
        }
      } catch (_) { /* capability detection is best-effort */ }

      // ── Embedded resource payloads ─────────────────────────────────
      // Walk the resource leaves collected in _parseResources() and flag
      // any that carry a recognisable *file* magic — secondary PE / ELF /
      // Mach-O executables, archives (ZIP / 7z / RAR / gzip / CAB), or
      // large high-entropy blobs parked in RCDATA / HTML / MANIFEST /
      // custom-named types. Classic stashing slot for droppers (MITRE
      // T1027.009 — Embedded Payloads). Inert types (icons / cursors /
      // fonts / string tables / version info / message tables / menus /
      // dialogs / accelerators) are skipped so we don't flag ordinary
      // app icons. The renderer already makes these rows clickable; this
      // pass just drives the risk score and the sidebar IOC pivots.
      try {
        const leaves = (pe.resources && pe.resources.leaves) || [];
        if (leaves.length) {
          const INERT = new Set([1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 14, 16]);
          const EXEC_HINTS = new Set(['.exe', '.dll', '.sys', '.elf', '.so', '.dylib', '.macho']);
          const ARCHIVE_HINTS = new Set(['.zip', '.7z', '.rar', '.gz', '.cab', '.tar', '.xz', '.bz2']);
          let embeddedCount = 0;
          for (const L of leaves) {
            if (!L || (!L.typeIsNamed && INERT.has(L.typeId))) continue;
            const magic = L.magic;
            const ext = (magic && magic.extHint) ? magic.extHint.toLowerCase() : null;
            const inStashingSlot = L.typeIsNamed || L.typeId === 10 || L.typeId === 23 || L.typeId === 24;

            if (ext && EXEC_HINTS.has(ext)) {
              // Embedded secondary executable — the classic dropper pattern.
              embeddedCount++;
              const where = L.typeIsNamed
                ? `named type "${L.typeName}"`
                : `RT_${L.typeName}`;
              issues.push(`Embedded executable in ${where} (${magic.label}, ${L.size.toLocaleString()} B) — T1027.009 Embedded Payloads`);
              riskScore += 2.5;
              pushIOC(findings, {
                type: IOC.PATTERN,
                value: `Embedded ${magic.label} payload [T1027.009]`,
                severity: 'high',
                note: `${magic.label} stashed in ${where} at file offset ${this._hex(L.fileOffset, 8)} (${L.size.toLocaleString()} B). Click the resource row to analyse it as a fresh file.`,
                _noDomainSibling: true,
              });
            } else if (ext && ARCHIVE_HINTS.has(ext) && inStashingSlot) {
              // Archive in a stashing slot — not a smoking gun (some
              // legitimate installers ship help archives in RCDATA) but
              // worth medium attention.
              embeddedCount++;
              issues.push(`Embedded ${magic.label} archive in RT_${L.typeName} (${L.size.toLocaleString()} B) — T1027.009`);
              riskScore += 1.5;
              pushIOC(findings, {
                type: IOC.PATTERN,
                value: `Embedded ${magic.label} archive [T1027.009]`,
                severity: 'medium',
                note: `${magic.label} archive embedded in ${L.typeIsNamed ? `named type "${L.typeName}"` : `RT_${L.typeName}`} (${L.size.toLocaleString()} B).`,
                _noDomainSibling: true,
              });
            } else if (!magic && inStashingSlot && L.size > 64 * 1024) {
              // Large unrecognised blob in a stashing slot — candidate
              // for a packed / encrypted payload. Entropy-gate to keep
              // this from firing on normal localisation / HTML content.
              try {
                const slice = bytes.subarray(L.fileOffset, L.fileOffset + Math.min(L.size, 256 * 1024));
                const ent = (typeof BinaryOverlay !== 'undefined' && BinaryOverlay.shannonEntropy)
                  ? BinaryOverlay.shannonEntropy(slice) : 0;
                if (ent > 7.2) {
                  embeddedCount++;
                  issues.push(`High-entropy blob in ${L.typeIsNamed ? `named type "${L.typeName}"` : `RT_${L.typeName}`} (${L.size.toLocaleString()} B, entropy ${ent.toFixed(2)}) — possible packed payload (T1027.002)`);
                  riskScore += 1;
                  pushIOC(findings, {
                    type: IOC.PATTERN,
                    value: `High-entropy resource blob [T1027.002]`,
                    severity: 'medium',
                    note: `${L.size.toLocaleString()} B at file offset ${this._hex(L.fileOffset, 8)} (entropy ${ent.toFixed(2)}) with no recognised magic — candidate packed / encrypted payload.`,
                    _noDomainSibling: true,
                  });
                }
              } catch (_) { /* per-leaf entropy is best-effort */ }
            }
          }
          if (embeddedCount > 0) {
            findings.metadata['Embedded Resource Payloads'] = String(embeddedCount);
          }
        }
      } catch (_) { /* resource-payload analysis is best-effort */ }

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

    // Stash for render(): the shared _loadFile path calls analyzeForSecurity()
    // on this same instance before render(), so render() can reach the
    // completed findings for the Tier-A triage band without a second pass.
    this._findings = findings;
    return findings;
  }
}
