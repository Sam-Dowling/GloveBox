// ════════════════════════════════════════════════════════════════
// macho-renderer.js — macOS Mach-O / Universal Binary parser + analysis view
// Supports: executables, dylibs, bundles, objects, Fat/Universal binaries
// Handles both 32-bit and 64-bit Mach-O, plus Fat (multi-arch) containers
// ════════════════════════════════════════════════════════════════

class MachoRenderer {

  // ── Static constant maps ───────────────────────────────────────

  // Mach-O magic numbers
  static MAGIC = {
    0xFEEDFACE: { name: 'MH_MAGIC',    bits: 32, le: true  },
    0xCEFAEDFE: { name: 'MH_CIGAM',    bits: 32, le: false },
    0xFEEDFACF: { name: 'MH_MAGIC_64', bits: 64, le: true  },
    0xCFFAEDFE: { name: 'MH_CIGAM_64', bits: 64, le: false },
    0xCAFEBABE: { name: 'FAT_MAGIC',   bits: 0,  le: false },
    0xBEBAFECA: { name: 'FAT_CIGAM',   bits: 0,  le: true  },
  };

  // CPU types
  static CPU_TYPE = {
    1:  'VAX',
    6:  'MC680x0',
    7:  'x86 (i386)',
    0x01000007: 'x86-64 (AMD64)',
    10: 'MC98000',
    11: 'HPPA',
    12: 'ARM',
    0x0100000C: 'ARM64 (AArch64)',
    0x0200000C: 'ARM64_32',
    13: 'MC88000',
    14: 'SPARC',
    15: 'i860',
    18: 'PowerPC',
    0x01000012: 'PowerPC64',
  };

  // CPU subtypes for common architectures
  static CPU_SUBTYPE_X86 = {
    3: 'ALL', 4: 'ARCH1', 8: 'HASWELL',
  };
  static CPU_SUBTYPE_X86_64 = {
    3: 'ALL', 4: 'HASWELL', 8: 'IVYBRIDGE',
  };
  static CPU_SUBTYPE_ARM = {
    0: 'ALL', 5: 'V4T', 6: 'V6', 7: 'V5TEJ', 8: 'XSCALE',
    9: 'V7', 10: 'V7F', 11: 'V7S', 12: 'V7K', 13: 'V8', 14: 'V6M', 15: 'V7M', 16: 'V7EM',
  };
  static CPU_SUBTYPE_ARM64 = {
    0: 'ALL', 1: 'V8', 2: 'E',
  };

  // File types
  static FILE_TYPE = {
    1:  'MH_OBJECT',
    2:  'MH_EXECUTE',
    3:  'MH_FVMLIB',
    4:  'MH_CORE',
    5:  'MH_PRELOAD',
    6:  'MH_DYLIB',
    7:  'MH_DYLINKER',
    8:  'MH_BUNDLE',
    9:  'MH_DYLIB_STUB',
    10: 'MH_DSYM',
    11: 'MH_KEXT_BUNDLE',
    12: 'MH_FILESET',
  };

  static FILE_TYPE_DESC = {
    1:  'Relocatable Object',
    2:  'Executable',
    3:  'Fixed VM Library',
    4:  'Core Dump',
    5:  'Preloaded Executable',
    6:  'Dynamic Library',
    7:  'Dynamic Linker',
    8:  'Bundle (Plugin)',
    9:  'Dynamic Library Stub',
    10: 'Debug Symbols (dSYM)',
    11: 'Kernel Extension',
    12: 'Kernel Fileset',
  };

  // Load command types
  static LC = {
    0x01: 'LC_SEGMENT',
    0x02: 'LC_SYMTAB',
    0x03: 'LC_SYMSEG',
    0x04: 'LC_THREAD',
    0x05: 'LC_UNIXTHREAD',
    0x0B: 'LC_DYSYMTAB',
    0x0C: 'LC_LOAD_DYLIB',
    0x0D: 'LC_ID_DYLIB',
    0x0E: 'LC_LOAD_DYLINKER',
    0x0F: 'LC_ID_DYLINKER',
    0x11: 'LC_DYLD_INFO',
    0x19: 'LC_SEGMENT_64',
    0x1A: 'LC_ROUTINES_64',
    0x1B: 'LC_UUID',
    0x1C: 'LC_RPATH',
    0x1D: 'LC_CODE_SIGNATURE',
    0x1E: 'LC_SEGMENT_SPLIT_INFO',
    0x1F: 'LC_REEXPORT_DYLIB',
    0x20: 'LC_LAZY_LOAD_DYLIB',
    0x21: 'LC_ENCRYPTION_INFO',
    0x22: 'LC_DYLD_INFO_ONLY',
    0x23: 'LC_LOAD_UPWARD_DYLIB',
    0x24: 'LC_VERSION_MIN_MACOSX',
    0x25: 'LC_VERSION_MIN_IPHONEOS',
    0x26: 'LC_FUNCTION_STARTS',
    0x27: 'LC_DYLD_ENVIRONMENT',
    0x28: 'LC_MAIN',
    0x29: 'LC_DATA_IN_CODE',
    0x2A: 'LC_SOURCE_VERSION',
    0x2B: 'LC_DYLIB_CODE_SIGN_DRS',
    0x2C: 'LC_ENCRYPTION_INFO_64',
    0x2D: 'LC_LINKER_OPTION',
    0x2E: 'LC_LINKER_OPTIMIZATION_HINT',
    0x2F: 'LC_VERSION_MIN_TVOS',
    0x30: 'LC_VERSION_MIN_WATCHOS',
    0x31: 'LC_NOTE',
    0x32: 'LC_BUILD_VERSION',
    0x33: 'LC_DYLD_EXPORTS_TRIE',
    0x34: 'LC_DYLD_CHAINED_FIXUPS',
    0x35: 'LC_FILESET_ENTRY',
    0x80000022: 'LC_DYLD_INFO_ONLY',
    0x80000028: 'LC_MAIN',
    0x8000001C: 'LC_RPATH',
    0x8000001D: 'LC_CODE_SIGNATURE',
    0x80000033: 'LC_DYLD_EXPORTS_TRIE',
    0x80000034: 'LC_DYLD_CHAINED_FIXUPS',
  };

  // Mach-O header flags
  static MH_FLAGS = {
    0x1:       'MH_NOUNDEFS',
    0x2:       'MH_INCRLINK',
    0x4:       'MH_DYLDLINK',
    0x8:       'MH_BINDATLOAD',
    0x10:      'MH_PREBOUND',
    0x20:      'MH_SPLIT_SEGS',
    0x40:      'MH_LAZY_INIT',
    0x80:      'MH_TWOLEVEL',
    0x100:     'MH_FORCE_FLAT',
    0x200:     'MH_NOMULTIDEFS',
    0x400:     'MH_NOFIXPREBINDING',
    0x800:     'MH_PREBINDABLE',
    0x1000:    'MH_ALLMODSBOUND',
    0x2000:    'MH_SUBSECTIONS_VIA_SYMBOLS',
    0x4000:    'MH_CANONICAL',
    0x8000:    'MH_WEAK_DEFINES',
    0x10000:   'MH_BINDS_TO_WEAK',
    0x20000:   'MH_ALLOW_STACK_EXECUTION',
    0x40000:   'MH_ROOT_SAFE',
    0x80000:   'MH_SETUID_SAFE',
    0x100000:  'MH_NO_REEXPORTED_DYLIBS',
    0x200000:  'MH_PIE',
    0x400000:  'MH_DEAD_STRIPPABLE_DYLIB',
    0x800000:  'MH_HAS_TLV_DESCRIPTORS',
    0x1000000: 'MH_NO_HEAP_EXECUTION',
    0x2000000: 'MH_APP_EXTENSION_SAFE',
    0x4000000: 'MH_NLIST_OUTOFSYNC_WITH_DYLDINFO',
    0x8000000: 'MH_SIM_SUPPORT',
    0x80000000: 'MH_DYLIB_IN_CACHE',
  };

  // VM protection flags
  static VM_PROT = { 1: 'READ', 2: 'WRITE', 4: 'EXECUTE' };

  // Build version platforms
  static PLATFORM = {
    1: 'macOS', 2: 'iOS', 3: 'tvOS', 4: 'watchOS',
    5: 'bridgeOS', 6: 'Mac Catalyst', 7: 'iOS Simulator',
    8: 'tvOS Simulator', 9: 'watchOS Simulator', 10: 'DriverKit',
    11: 'visionOS', 12: 'visionOS Simulator',
  };

  // Build version tool types
  static BUILD_TOOL = { 1: 'clang', 2: 'swift', 3: 'ld', 4: 'lld' };

  // ── Detailed suspicious API info (description, context, MITRE ATT&CK) ─────────
  static SUSPICIOUS_APIS_DETAIL = {
    ptrace: {
      desc: 'Traces or controls another process — can read/write memory and registers.',
      context: 'Anti-debugging: a process calls ptrace(PT_DENY_ATTACH) to prevent debugger attachment.',
      mitre: 'T1622 — Debugger Evasion',
    },
    dlopen: {
      desc: 'Opens a shared library and returns a handle for dlsym lookups.',
      context: 'Runtime loading of dylibs enables plugin-based malware or evasion of static analysis.',
      mitre: 'T1129 — Shared Modules',
    },
    dlsym: {
      desc: 'Resolves a symbol (function/variable) from a dynamically loaded library.',
      context: 'Combined with dlopen, allows API-hiding by resolving functions at runtime.',
      mitre: 'T1106 — Native API',
    },
    execve: {
      desc: 'Replaces the current process image with a new program.',
      context: 'Core execution primitive in macOS. Combined with socket+dup2, forms a reverse shell.',
      mitre: 'T1059 — Command and Scripting Interpreter',
    },
    execvp: {
      desc: 'Searches PATH and executes a program, replacing the current process.',
      context: 'Convenient execution primitive often used to launch shell commands.',
      mitre: 'T1059 — Command and Scripting Interpreter',
    },
    system: {
      desc: 'Executes a shell command string via /bin/sh -c.',
      context: 'Simplest command execution — frequently used by macOS malware for payload delivery.',
      mitre: 'T1059.004 — Unix Shell',
    },
    popen: {
      desc: 'Executes a shell command and returns a pipe for reading/writing.',
      context: 'Enables command execution with output capture — used for reconnaissance or data exfiltration.',
      mitre: 'T1059.004 — Unix Shell',
    },
    fork: {
      desc: 'Creates a child process that is a copy of the parent.',
      context: 'Used to daemonize malware or create persistent backdoors.',
      mitre: 'T1106 — Native API',
    },
    socket: {
      desc: 'Creates a network communication endpoint (TCP, UDP, raw).',
      context: 'Foundation for C2 channels, data exfiltration, and reverse shells.',
      mitre: 'T1071 — Application Layer Protocol',
    },
    connect: {
      desc: 'Initiates a connection on a socket to a remote address.',
      context: 'Outbound connection to C2 server. Part of reverse shell triad (socket+connect+dup2+exec).',
      mitre: 'T1071 — Application Layer Protocol',
    },
    bind: {
      desc: 'Assigns a local address/port to a socket.',
      context: 'Creates a network listener — indicator of a bind shell or backdoor.',
      mitre: 'T1571 — Non-Standard Port',
    },
    listen: {
      desc: 'Marks a socket as a passive listener for incoming connections.',
      context: 'Server-side socket that waits for attacker connections — classic backdoor pattern.',
      mitre: 'T1571 — Non-Standard Port',
    },
    mmap: {
      desc: 'Maps files or anonymous memory into the process address space.',
      context: 'Can create RWX memory regions for in-memory code execution.',
      mitre: 'T1055.009 — Proc Memory',
    },
    mprotect: {
      desc: 'Changes memory protection flags on mapped pages.',
      context: 'Used to make data pages executable at runtime — enables shellcode execution.',
      mitre: 'T1055.009 — Proc Memory',
    },
    dup2: {
      desc: 'Duplicates a file descriptor to a specified target FD number.',
      context: 'Critical in reverse shells — redirects stdin/stdout/stderr to a network socket.',
      mitre: 'T1059 — Command and Scripting Interpreter',
    },
    unlink: {
      desc: 'Removes a file or directory entry from the filesystem.',
      context: 'Anti-forensics: malware deletes itself after execution to remove evidence.',
      mitre: 'T1070.004 — File Deletion',
    },
    _NSCreateObjectFileImageFromMemory: {
      desc: 'Creates a Mach-O image object from a memory buffer.',
      context: 'Fileless execution technique — loads and runs code entirely from memory without touching disk.',
      mitre: 'T1620 — Reflective Code Loading',
    },
    NSLinkModule: {
      desc: 'Links a Mach-O image into the running process.',
      context: 'Used with NSCreateObjectFileImageFromMemory for in-memory Mach-O loading.',
      mitre: 'T1620 — Reflective Code Loading',
    },
    AuthorizationExecuteWithPrivileges: {
      desc: 'Executes a program with elevated (root) privileges via authorization dialog.',
      context: 'Deprecated but still used by malware for privilege escalation via fake auth prompts.',
      mitre: 'T1548.004 — Elevated Execution with Prompt',
    },
    SecKeychainFindGenericPassword: {
      desc: 'Searches the keychain for a generic password item.',
      context: 'Credential theft — infostealers like Atomic Stealer dump keychain passwords.',
      mitre: 'T1555.001 — Keychain',
    },
    SecKeychainFindInternetPassword: {
      desc: 'Searches the keychain for an internet password item.',
      context: 'Browser/service credential theft from the macOS keychain.',
      mitre: 'T1555.001 — Keychain',
    },
    SecItemCopyMatching: {
      desc: 'Searches the keychain and returns matching items.',
      context: 'Modern keychain API for credential extraction — used by macOS infostealers.',
      mitre: 'T1555.001 — Keychain',
    },
    SecKeychainItemCopyContent: {
      desc: 'Copies the data/attributes from a keychain item.',
      context: 'Extracts stored credential data from keychain entries.',
      mitre: 'T1555.001 — Keychain',
    },
    IOServiceGetMatchingServices: {
      desc: 'Finds IOKit services matching a given dictionary.',
      context: 'Hardware enumeration — used for VM detection, USB enumeration, or hardware fingerprinting.',
      mitre: 'T1082 — System Information Discovery',
    },
    CGDisplayCreateImage: {
      desc: 'Creates an image of the current screen contents.',
      context: 'Screen capture for surveillance or data theft.',
      mitre: 'T1113 — Screen Capture',
    },
    CGEventTapCreate: {
      desc: 'Creates an event tap to intercept system-level input events.',
      context: 'Keylogging — captures keystrokes by tapping into the macOS event system.',
      mitre: 'T1056.001 — Keylogging',
    },
    CGWindowListCreateImage: {
      desc: 'Captures a composite image of a set of windows.',
      context: 'Screen capture / surveillance — used to screenshot specific application windows.',
      mitre: 'T1113 — Screen Capture',
    },
    SMLoginItemSetEnabled: {
      desc: 'Enables or disables a login item for the current user.',
      context: 'Persistence mechanism — adds malware to login items so it runs at each user login.',
      mitre: 'T1547.015 — Login Items',
    },
    LSSharedFileListInsertItemURL: {
      desc: 'Inserts an item into a shared file list (e.g. login items).',
      context: 'Legacy persistence via login items — adds a URL to the user login item list.',
      mitre: 'T1547.015 — Login Items',
    },
    task_for_pid: {
      desc: 'Gets the Mach task port for a process by PID.',
      context: 'Enables reading/writing another process memory — core technique for process injection on macOS.',
      mitre: 'T1055 — Process Injection',
    },
    mach_vm_read: {
      desc: 'Reads virtual memory from another Mach task.',
      context: 'Cross-process memory read — credential theft, code inspection, or data extraction.',
      mitre: 'T1003 — OS Credential Dumping',
    },
    mach_vm_write: {
      desc: 'Writes to virtual memory of another Mach task.',
      context: 'Code injection into another process via Mach VM API.',
      mitre: 'T1055 — Process Injection',
    },
  };

  // ── Suspicious symbol/function names for Mach-O binaries ──────────
  static SUSPICIOUS_SYMBOLS = {
    'ptrace': 'Anti-debugging — PT_DENY_ATTACH prevents debugger attachment',
    'dlopen': 'Dynamic library loading — runtime code injection',
    'dlsym': 'Dynamic symbol resolution — runtime function lookup',
    'execve': 'Process execution — can launch arbitrary commands',
    'execvp': 'Process execution — can launch arbitrary commands',
    'execl': 'Process execution — can launch arbitrary commands',
    'system': 'Shell command execution — arbitrary command execution',
    'popen': 'Shell command execution via pipe',
    'fork': 'Process creation — can spawn child processes',
    'socket': 'Network socket creation — potential C2/data exfiltration',
    'connect': 'Network connection — outbound communication',
    'bind': 'Network binding — potential backdoor/listener',
    'listen': 'Network listener — potential backdoor',
    'accept': 'Network accept — server-side connection handling',
    'send': 'Network send — data exfiltration capability',
    'recv': 'Network receive — command reception capability',
    'sendto': 'UDP send — data exfiltration capability',
    'recvfrom': 'UDP receive — command reception capability',
    'mmap': 'Memory mapping — can map executable memory regions',
    'mprotect': 'Memory permission change — can make data executable',
    'dup2': 'File descriptor duplication — used in reverse shells',
    'unlink': 'File deletion — anti-forensics / self-deletion',
    '_NSCreateObjectFileImageFromMemory': 'Fileless Mach-O loading — in-memory code execution',
    'NSLinkModule': 'Dynamic module linking — used with fileless loading',
    'AuthorizationExecuteWithPrivileges': 'Privilege escalation — deprecated root execution API',
    'SecKeychainFindGenericPassword': 'Keychain access — credential theft',
    'SecKeychainFindInternetPassword': 'Keychain access — browser/service credentials',
    'SecItemCopyMatching': 'Keychain search — modern credential extraction API',
    'SecKeychainItemCopyContent': 'Keychain data extraction — reading stored credentials',
    'IOServiceGetMatchingServices': 'IOKit hardware enumeration — VM detection/fingerprinting',
    'CGDisplayCreateImage': 'Screen capture — surveillance capability',
    'CGEventTapCreate': 'Event tap — keylogging capability',
    'CGWindowListCreateImage': 'Window capture — surveillance capability',
    'SMLoginItemSetEnabled': 'Login item persistence — auto-launch at login',
    'LSSharedFileListInsertItemURL': 'Login item persistence — legacy API',
    'task_for_pid': 'Mach task port — cross-process memory access',
    'mach_vm_read': 'VM read — cross-process memory reading',
    'mach_vm_write': 'VM write — cross-process code injection',
    'sysctl': 'System info query — anti-debug/VM detection (hw.model, kern.proc)',
    'kqueue': 'Kernel event notification — file/process monitoring',
    'setuid': 'Set user ID — privilege escalation',
    'setgid': 'Set group ID — privilege escalation',
    'chroot': 'Change root — sandbox escape',
    'prctl': 'Process control — can rename process',
  };

  // ═══════════════════════════════════════════════════════════════════════
  //  Binary read helpers (endian-aware)
  // ═══════════════════════════════════════════════════════════════════════

  _u8(b, o) { return b[o]; }

  _u16(b, o) {
    return this._le
      ? b[o] | (b[o + 1] << 8)
      : (b[o] << 8) | b[o + 1];
  }

  _u32(b, o) {
    return this._le
      ? (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0
      : ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
  }

  // Returns a BigInt-safe 64-bit value as a Number (loses precision above 2^53)
  _u64(b, o) {
    if (this._le) {
      const lo = this._u32(b, o);
      const hi = this._u32(b, o + 4);
      return hi * 0x100000000 + lo;
    } else {
      const hi = this._u32(b, o);
      const lo = this._u32(b, o + 4);
      return hi * 0x100000000 + lo;
    }
  }

  // Read big-endian uint32 (for Fat headers, which are always BE)
  _u32be(b, o) {
    return ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
  }

  _str(b, o, maxLen) {
    let s = '';
    for (let i = 0; i < maxLen && o + i < b.length; i++) {
      if (b[o + i] === 0) break;
      s += String.fromCharCode(b[o + i]);
    }
    return s;
  }

  _hex(v, digits) {
    if (typeof v === 'number') return '0x' + v.toString(16).toUpperCase().padStart(digits || 8, '0');
    return '0x0';
  }

  _entropy(b, offset, length) {
    if (length <= 0 || offset + length > b.length) return 0;
    const freq = new Uint32Array(256);
    const end = Math.min(offset + length, b.length);
    const actual = end - offset;
    for (let i = offset; i < end; i++) freq[b[i]]++;
    let ent = 0;
    for (let i = 0; i < 256; i++) {
      if (freq[i] === 0) continue;
      const p = freq[i] / actual;
      ent -= p * Math.log2(p);
    }
    return ent;
  }

  _esc(s) { return (s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }

  _fmtVersion(v) {
    return `${(v >> 16) & 0xFFFF}.${(v >> 8) & 0xFF}.${v & 0xFF}`;
  }

  _protStr(prot) {
    return (prot & 1 ? 'R' : '-') + (prot & 2 ? 'W' : '-') + (prot & 4 ? 'X' : '-');
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Fat/Universal binary detection and parsing
  // ═══════════════════════════════════════════════════════════════════════

  _parseFatHeader(bytes) {
    if (bytes.length < 8) return null;
    const magic = this._u32be(bytes, 0);
    if (magic !== 0xCAFEBABE && magic !== 0xBEBAFECA) return null;

    // Disambiguate FAT from Java class file (both use 0xCAFEBABE)
    // Java class files have version numbers in bytes 4-7 that are small (e.g., 0x0000 0x0037)
    // Fat binaries have arch count which is typically 1-4
    const nfat = this._u32be(bytes, 4);
    if (nfat === 0 || nfat > 20) return null; // Too many or zero = not a Fat binary

    const arches = [];
    for (let i = 0; i < nfat && i < 20; i++) {
      const off = 8 + i * 20;
      if (off + 20 > bytes.length) break;
      const cputype = this._u32be(bytes, off);
      const cpusubtype = this._u32be(bytes, off + 4) & 0x00FFFFFF;
      const offset = this._u32be(bytes, off + 8);
      const size = this._u32be(bytes, off + 12);
      const align = this._u32be(bytes, off + 16);
      arches.push({
        cputype,
        cpusubtype,
        cputypeStr: MachoRenderer.CPU_TYPE[cputype] || `Unknown (${this._hex(cputype, 8)})`,
        offset,
        size,
        align,
      });
    }
    return { nfat, arches };
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Core Mach-O parser
  // ═══════════════════════════════════════════════════════════════════════

  _parse(bytes, baseOffset) {
    baseOffset = baseOffset || 0;
    const b = bytes;

    if (baseOffset + 28 > b.length) throw new Error('File too small for Mach-O header');

    // Read magic (always try native byte order first, then detect)
    const rawMagic = (b[baseOffset] | (b[baseOffset + 1] << 8) | (b[baseOffset + 2] << 16) | (b[baseOffset + 3] << 24)) >>> 0;
    const beMagic = ((b[baseOffset] << 24) | (b[baseOffset + 1] << 16) | (b[baseOffset + 2] << 8) | b[baseOffset + 3]) >>> 0;

    let magic;
    if (rawMagic === 0xFEEDFACE || rawMagic === 0xFEEDFACF) {
      magic = rawMagic;
      this._le = true;
    } else if (rawMagic === 0xCEFAEDFE || rawMagic === 0xCFFAEDFE) {
      magic = beMagic;
      this._le = false;
    } else if (beMagic === 0xFEEDFACE || beMagic === 0xFEEDFACF) {
      magic = beMagic;
      this._le = false;
    } else {
      throw new Error('Not a valid Mach-O file (bad magic: ' + this._hex(rawMagic, 8) + ')');
    }

    this._is64 = (magic === 0xFEEDFACF);
    const headerSize = this._is64 ? 32 : 28;

    if (baseOffset + headerSize > b.length) throw new Error('File too small for Mach-O header');

    const mo = {};
    mo.magic = magic;
    mo.magicStr = this._is64 ? 'MH_MAGIC_64 (64-bit)' : 'MH_MAGIC (32-bit)';
    mo.baseOffset = baseOffset;

    // Header fields (after magic at offset 0)
    mo.cputype = this._u32(b, baseOffset + 4);
    mo.cpusubtype = this._u32(b, baseOffset + 8) & 0x00FFFFFF;
    mo.filetype = this._u32(b, baseOffset + 12);
    mo.ncmds = this._u32(b, baseOffset + 16);
    mo.sizeofcmds = this._u32(b, baseOffset + 20);
    mo.flags = this._u32(b, baseOffset + 24);
    if (this._is64) {
      mo.reserved = this._u32(b, baseOffset + 28);
    }

    mo.cputypeStr = MachoRenderer.CPU_TYPE[mo.cputype] || `Unknown (${this._hex(mo.cputype, 8)})`;
    mo.filetypeStr = MachoRenderer.FILE_TYPE[mo.filetype] || `Unknown (${mo.filetype})`;
    mo.filetypeDesc = MachoRenderer.FILE_TYPE_DESC[mo.filetype] || 'Unknown';

    // Decode CPU subtype
    if (mo.cputype === 7) {
      mo.cpusubtypeStr = MachoRenderer.CPU_SUBTYPE_X86[mo.cpusubtype] || `${mo.cpusubtype}`;
    } else if (mo.cputype === 0x01000007) {
      mo.cpusubtypeStr = MachoRenderer.CPU_SUBTYPE_X86_64[mo.cpusubtype] || `${mo.cpusubtype}`;
    } else if (mo.cputype === 12) {
      mo.cpusubtypeStr = MachoRenderer.CPU_SUBTYPE_ARM[mo.cpusubtype] || `${mo.cpusubtype}`;
    } else if (mo.cputype === 0x0100000C) {
      mo.cpusubtypeStr = MachoRenderer.CPU_SUBTYPE_ARM64[mo.cpusubtype] || `${mo.cpusubtype}`;
    } else {
      mo.cpusubtypeStr = `${mo.cpusubtype}`;
    }

    // Decode flags
    mo.flagsList = [];
    for (const [bit, name] of Object.entries(MachoRenderer.MH_FLAGS)) {
      if (mo.flags & Number(bit)) mo.flagsList.push(name);
    }

    // ── Parse load commands ──────────────────────────────────────────
    mo.loadCommands = [];
    mo.segments = [];
    mo.sections = [];
    mo.dylibs = [];
    mo.rpaths = [];
    mo.uuid = '';
    mo.entryPoint = null;
    mo.sourceVersion = '';
    mo.buildVersion = null;
    mo.minVersion = null;
    mo.codeSignature = null;
    mo.encryptionInfo = null;
    mo.symtabCmd = null;
    mo.dysymtabCmd = null;
    mo.dylinker = '';

    let cmdOff = baseOffset + headerSize;
    const maxCmds = Math.min(mo.ncmds, 512); // Safety cap

    for (let i = 0; i < maxCmds; i++) {
      if (cmdOff + 8 > b.length) break;
      const cmd = this._u32(b, cmdOff);
      const cmdsize = this._u32(b, cmdOff + 4);
      if (cmdsize < 8 || cmdOff + cmdsize > b.length) break;

      const cmdName = MachoRenderer.LC[cmd] || MachoRenderer.LC[cmd & 0x7FFFFFFF] || `0x${cmd.toString(16).toUpperCase()}`;
      const lc = { cmd, cmdName, cmdsize, offset: cmdOff };

      // ── LC_SEGMENT / LC_SEGMENT_64 ──────────────────────────────
      if (cmd === 0x01 || cmd === 0x19) {
        const seg = this._parseSegment(b, cmdOff, cmd === 0x19);
        lc.segment = seg;
        mo.segments.push(seg);
        for (const sec of seg.sections) {
          mo.sections.push(sec);
        }
      }

      // ── LC_SYMTAB ───────────────────────────────────────────────
      else if (cmd === 0x02) {
        mo.symtabCmd = {
          symoff: this._u32(b, cmdOff + 8),
          nsyms: this._u32(b, cmdOff + 12),
          stroff: this._u32(b, cmdOff + 16),
          strsize: this._u32(b, cmdOff + 20),
        };
        lc.detail = `${mo.symtabCmd.nsyms} symbols`;
      }

      // ── LC_DYSYMTAB ─────────────────────────────────────────────
      else if (cmd === 0x0B) {
        mo.dysymtabCmd = {
          ilocalsym: this._u32(b, cmdOff + 8),
          nlocalsym: this._u32(b, cmdOff + 12),
          iextdefsym: this._u32(b, cmdOff + 16),
          nextdefsym: this._u32(b, cmdOff + 20),
          iundefsym: this._u32(b, cmdOff + 24),
          nundefsym: this._u32(b, cmdOff + 28),
        };
        lc.detail = `${mo.dysymtabCmd.nundefsym} undefined, ${mo.dysymtabCmd.nextdefsym} external`;
      }

      // ── LC_LOAD_DYLIB / LC_LOAD_WEAK_DYLIB / LC_REEXPORT_DYLIB / LC_LAZY_LOAD_DYLIB ──
      else if (cmd === 0x0C || cmd === 0x18 || cmd === 0x1F || cmd === 0x20 ||
               (cmd & 0x7FFFFFFF) === 0x0C || (cmd & 0x7FFFFFFF) === 0x18) {
        const nameOff = this._u32(b, cmdOff + 8);
        const name = this._str(b, cmdOff + nameOff, Math.min(cmdsize - nameOff, 256));
        const timestamp = this._u32(b, cmdOff + 12);
        const curVer = this._u32(b, cmdOff + 16);
        const compatVer = this._u32(b, cmdOff + 20);
        const type = cmd === 0x18 || (cmd & 0x7FFFFFFF) === 0x18 ? 'weak'
          : cmd === 0x1F ? 'reexport'
          : cmd === 0x20 ? 'lazy'
          : 'required';
        mo.dylibs.push({ name, curVer: this._fmtVersion(curVer), compatVer: this._fmtVersion(compatVer), type });
        lc.detail = name;
      }

      // ── LC_ID_DYLIB ─────────────────────────────────────────────
      else if (cmd === 0x0D) {
        const nameOff = this._u32(b, cmdOff + 8);
        mo.idDylib = this._str(b, cmdOff + nameOff, Math.min(cmdsize - nameOff, 256));
        lc.detail = mo.idDylib;
      }

      // ── LC_LOAD_DYLINKER / LC_ID_DYLINKER ──────────────────────
      else if (cmd === 0x0E || cmd === 0x0F) {
        const nameOff = this._u32(b, cmdOff + 8);
        mo.dylinker = this._str(b, cmdOff + nameOff, Math.min(cmdsize - nameOff, 256));
        lc.detail = mo.dylinker;
      }

      // ── LC_UUID ─────────────────────────────────────────────────
      else if (cmd === 0x1B) {
        const uuidBytes = b.subarray(cmdOff + 8, cmdOff + 24);
        const hex = Array.from(uuidBytes).map(x => x.toString(16).padStart(2, '0')).join('');
        mo.uuid = hex.replace(/(.{8})(.{4})(.{4})(.{4})(.{12})/, '$1-$2-$3-$4-$5').toUpperCase();
        lc.detail = mo.uuid;
      }

      // ── LC_MAIN ─────────────────────────────────────────────────
      else if (cmd === 0x28 || cmd === 0x80000028) {
        mo.entryPoint = this._u64(b, cmdOff + 8);
        lc.detail = `entry offset ${this._hex(mo.entryPoint, 16)}`;
      }

      // ── LC_RPATH ────────────────────────────────────────────────
      else if (cmd === 0x1C || cmd === 0x8000001C) {
        const nameOff = this._u32(b, cmdOff + 8);
        const rpath = this._str(b, cmdOff + nameOff, Math.min(cmdsize - nameOff, 256));
        mo.rpaths.push(rpath);
        lc.detail = rpath;
      }

      // ── LC_CODE_SIGNATURE ───────────────────────────────────────
      else if (cmd === 0x1D || cmd === 0x8000001D) {
        mo.codeSignature = {
          dataoff: this._u32(b, cmdOff + 8),
          datasize: this._u32(b, cmdOff + 12),
        };
        lc.detail = `offset ${this._hex(mo.codeSignature.dataoff, 8)}, ${mo.codeSignature.datasize.toLocaleString()} bytes`;
      }

      // ── LC_ENCRYPTION_INFO / LC_ENCRYPTION_INFO_64 ──────────────
      else if (cmd === 0x21 || cmd === 0x2C) {
        mo.encryptionInfo = {
          cryptoff: this._u32(b, cmdOff + 8),
          cryptsize: this._u32(b, cmdOff + 12),
          cryptid: this._u32(b, cmdOff + 16),
        };
        lc.detail = mo.encryptionInfo.cryptid ? 'Encrypted' : 'Not encrypted';
      }

      // ── LC_SOURCE_VERSION ───────────────────────────────────────
      else if (cmd === 0x2A) {
        const ver = this._u64(b, cmdOff + 8);
        const a = Math.floor(ver / 0x10000000000) & 0xFFFFFF;
        const bb = Math.floor(ver / 0x40000000) & 0x3FF;
        const c = Math.floor(ver / 0x100000) & 0x3FF;
        const d = Math.floor(ver / 0x400) & 0x3FF;
        const e = ver & 0x3FF;
        mo.sourceVersion = `${a}.${bb}.${c}.${d}.${e}`;
        lc.detail = mo.sourceVersion;
      }

      // ── LC_BUILD_VERSION ────────────────────────────────────────
      else if (cmd === 0x32) {
        const platform = this._u32(b, cmdOff + 8);
        const minos = this._u32(b, cmdOff + 12);
        const sdk = this._u32(b, cmdOff + 16);
        const ntools = this._u32(b, cmdOff + 20);
        const tools = [];
        for (let t = 0; t < Math.min(ntools, 10); t++) {
          const toff = cmdOff + 24 + t * 8;
          if (toff + 8 > b.length) break;
          const tool = this._u32(b, toff);
          const tver = this._u32(b, toff + 4);
          tools.push({ tool: MachoRenderer.BUILD_TOOL[tool] || `${tool}`, version: this._fmtVersion(tver) });
        }
        mo.buildVersion = {
          platform: MachoRenderer.PLATFORM[platform] || `Unknown (${platform})`,
          minos: this._fmtVersion(minos),
          sdk: this._fmtVersion(sdk),
          tools,
        };
        lc.detail = `${mo.buildVersion.platform} ${mo.buildVersion.minos} (SDK ${mo.buildVersion.sdk})`;
      }

      // ── LC_VERSION_MIN_MACOSX / IPHONEOS / TVOS / WATCHOS ──────
      else if (cmd >= 0x24 && cmd <= 0x30 && [0x24, 0x25, 0x2F, 0x30].includes(cmd)) {
        const ver = this._u32(b, cmdOff + 8);
        const sdk = this._u32(b, cmdOff + 12);
        const platMap = { 0x24: 'macOS', 0x25: 'iOS', 0x2F: 'tvOS', 0x30: 'watchOS' };
        mo.minVersion = {
          platform: platMap[cmd] || 'Unknown',
          version: this._fmtVersion(ver),
          sdk: this._fmtVersion(sdk),
        };
        lc.detail = `${mo.minVersion.platform} ${mo.minVersion.version} (SDK ${mo.minVersion.sdk})`;
      }

      mo.loadCommands.push(lc);
      cmdOff += cmdsize;
    }

    // ── Parse symbol table ──────────────────────────────────────────
    mo.symbols = [];
    if (mo.symtabCmd) {
      this._parseSymbols(b, mo, baseOffset);
    }

    // ── Code signature analysis ─────────────────────────────────────
    mo.codeSignatureInfo = null;
    if (mo.codeSignature && mo.codeSignature.dataoff + 8 <= b.length) {
      mo.codeSignatureInfo = this._parseCodeSignature(b, mo.codeSignature.dataoff, mo.codeSignature.datasize);
    }

    // ── Security features ───────────────────────────────────────────
    mo.security = this._detectSecurity(mo);

    // ── String extraction ───────────────────────────────────────────
    mo.strings = this._extractStrings(b, mo, baseOffset);

    return mo;
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Segment + section parser
  // ═══════════════════════════════════════════════════════════════════════

  _parseSegment(b, off, is64) {
    const seg = {};
    seg.segname = this._str(b, off + 8, 16);

    if (is64) {
      seg.vmaddr = this._u64(b, off + 24);
      seg.vmsize = this._u64(b, off + 32);
      seg.fileoff = this._u64(b, off + 40);
      seg.filesize = this._u64(b, off + 48);
      seg.maxprot = this._u32(b, off + 56);
      seg.initprot = this._u32(b, off + 60);
      seg.nsects = this._u32(b, off + 64);
      seg.segflags = this._u32(b, off + 68);
    } else {
      seg.vmaddr = this._u32(b, off + 24);
      seg.vmsize = this._u32(b, off + 28);
      seg.fileoff = this._u32(b, off + 32);
      seg.filesize = this._u32(b, off + 36);
      seg.maxprot = this._u32(b, off + 40);
      seg.initprot = this._u32(b, off + 44);
      seg.nsects = this._u32(b, off + 48);
      seg.segflags = this._u32(b, off + 52);
    }

    seg.maxprotStr = this._protStr(seg.maxprot);
    seg.initprotStr = this._protStr(seg.initprot);

    // Parse sections within this segment
    seg.sections = [];
    const secHeaderSize = is64 ? 80 : 68;
    const secStart = off + (is64 ? 72 : 56);
    const maxSects = Math.min(seg.nsects, 256);

    for (let j = 0; j < maxSects; j++) {
      const soff = secStart + j * secHeaderSize;
      if (soff + secHeaderSize > b.length) break;

      const sec = {};
      sec.sectname = this._str(b, soff, 16);
      sec.segname = this._str(b, soff + 16, 16);

      if (is64) {
        sec.addr = this._u64(b, soff + 32);
        sec.size = this._u64(b, soff + 40);
        sec.offset = this._u32(b, soff + 48);
        sec.align = this._u32(b, soff + 52);
        sec.reloff = this._u32(b, soff + 56);
        sec.nreloc = this._u32(b, soff + 60);
        sec.flags = this._u32(b, soff + 64);
      } else {
        sec.addr = this._u32(b, soff + 32);
        sec.size = this._u32(b, soff + 36);
        sec.offset = this._u32(b, soff + 40);
        sec.align = this._u32(b, soff + 44);
        sec.reloff = this._u32(b, soff + 48);
        sec.nreloc = this._u32(b, soff + 52);
        sec.flags = this._u32(b, soff + 56);
      }

      // Calculate entropy
      if (sec.size > 0 && sec.offset > 0 && sec.offset + sec.size <= b.length) {
        sec.entropy = this._entropy(b, sec.offset, Math.min(sec.size, 1048576));
      } else {
        sec.entropy = 0;
      }

      seg.sections.push(sec);
    }

    return seg;
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Symbol table parser
  // ═══════════════════════════════════════════════════════════════════════

  _parseSymbols(b, mo, baseOffset) {
    const cmd = mo.symtabCmd;
    const entSize = this._is64 ? 16 : 12; // nlist_64 vs nlist
    const maxSyms = Math.min(cmd.nsyms, 20000); // Safety cap

    for (let i = 0; i < maxSyms; i++) {
      const off = cmd.symoff + i * entSize;
      if (off + entSize > b.length) break;

      const sym = {};
      sym.strx = this._u32(b, off);
      sym.type = b[off + 4];
      sym.sect = b[off + 5];
      sym.desc = this._u16(b, off + 6);

      if (this._is64) {
        sym.value = this._u64(b, off + 8);
      } else {
        sym.value = this._u32(b, off + 8);
      }

      // Read name from string table
      if (sym.strx > 0 && cmd.stroff + sym.strx < b.length) {
        sym.name = this._str(b, cmd.stroff + sym.strx, Math.min(256, b.length - cmd.stroff - sym.strx));
      } else {
        sym.name = '';
      }

      // Decode nlist type fields
      sym.isExternal = !!(sym.type & 0x01);
      sym.typeField = (sym.type >> 1) & 0x07;
      sym.isPrivateExternal = !!(sym.type & 0x10);
      sym.isStab = !!(sym.type & 0xE0);

      // Type classification
      if (sym.isStab) {
        sym.typeStr = 'STAB';
      } else if (sym.typeField === 0) {
        sym.typeStr = sym.isExternal ? 'UNDEF (ext)' : 'UNDEF';
      } else if (sym.typeField === 1) {
        sym.typeStr = 'ABS';
      } else if (sym.typeField === 5) {
        sym.typeStr = 'INDR';
      } else if (sym.typeField === 6) {
        sym.typeStr = 'PBUD';
      } else if (sym.typeField === 7) {
        sym.typeStr = 'SECT';
      } else {
        sym.typeStr = `0x${sym.type.toString(16)}`;
      }

      // Only include named symbols (skip stabs and empty)
      if (sym.name && !sym.isStab) {
        mo.symbols.push(sym);
      }
    }
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Code signature parser (lightweight — presence + basic info)
  // ═══════════════════════════════════════════════════════════════════════

  _parseCodeSignature(b, offset, size) {
    if (offset + 12 > b.length) return null;

    // SuperBlob header (always big-endian)
    const magic = this._u32be(b, offset);
    if (magic !== 0xFADE0CC0) return { present: true, valid: false, detail: 'Unknown signature format' };

    const length = this._u32be(b, offset + 4);
    const count = this._u32be(b, offset + 8);
    const info = { present: true, valid: true, blobs: count, detail: `${count} signature blob(s)` };

    // Parse blob index
    for (let i = 0; i < Math.min(count, 10); i++) {
      const boff = offset + 12 + i * 8;
      if (boff + 8 > b.length) break;
      const btype = this._u32be(b, boff);
      const boffset = this._u32be(b, boff + 4);
      const blobStart = offset + boffset;
      if (blobStart + 8 > b.length) continue;

      const blobMagic = this._u32be(b, blobStart);

      if (blobMagic === 0xFADE0C02) {
        // CodeDirectory
        if (blobStart + 44 <= b.length) {
          const cdVersion = this._u32be(b, blobStart + 8);
          const cdFlags = this._u32be(b, blobStart + 12);
          info.cdVersion = `0x${cdVersion.toString(16)}`;
          info.cdFlags = cdFlags;
          info.hardenedRuntime = !!(cdFlags & 0x10000);
          info.libraryValidation = !!(cdFlags & 0x2000);
          info.runtime = !!(cdFlags & 0x10000);
          // Read team ID if available
          const teamOffset = blobStart + 40 <= b.length ? this._u32be(b, blobStart + 36) : 0;
          if (teamOffset > 0 && blobStart + teamOffset < b.length) {
            info.teamId = this._str(b, blobStart + teamOffset, 32);
          }
        }
      } else if (blobMagic === 0xFADE0B01) {
        // CMS signature blob — extract X.509 certificates
        info.hasCMSSignature = true;
        try {
          const blobLen = this._u32be(b, blobStart + 4);
          if (blobLen > 8 && blobStart + blobLen <= b.length) {
            const cmsBytes = b.subarray(blobStart + 8, blobStart + blobLen);
            const result = X509Renderer.parseCertificatesFromCMS(cmsBytes);
            if (result.certs.length) info.certificates = result.certs;
          }
        } catch (_) { /* cert parsing is best-effort */ }
      } else if (blobMagic === 0xFADE7172) {
        // Entitlements
        if (blobStart + 8 <= b.length) {
          const entLen = this._u32be(b, blobStart + 4);
          if (entLen > 8 && blobStart + entLen <= b.length) {
            const entData = this._str(b, blobStart + 8, Math.min(entLen - 8, 4096));
            info.entitlements = entData;
          }
        }
      }
    }

    return info;
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Security feature detection
  // ═══════════════════════════════════════════════════════════════════════

  _detectSecurity(mo) {
    const sec = {};

    // PIE (Position Independent Executable)
    sec.pie = !!(mo.flags & 0x200000); // MH_PIE

    // NX Heap (No Heap Execution)
    sec.nxHeap = !!(mo.flags & 0x1000000); // MH_NO_HEAP_EXECUTION

    // Allow stack execution (bad — indicates NX stack is disabled)
    sec.allowStackExec = !!(mo.flags & 0x20000); // MH_ALLOW_STACK_EXECUTION
    sec.nxStack = !sec.allowStackExec;

    // Stack canary — check for ___stack_chk_fail or ___stack_chk_guard
    sec.stackCanary = mo.symbols.some(s =>
      s.name === '___stack_chk_fail' || s.name === '___stack_chk_guard' ||
      s.name === '_____stack_chk_fail' || s.name === '_____stack_chk_guard'
    );

    // ARC (Automatic Reference Counting) — check for objc_release/objc_retain
    sec.arc = mo.symbols.some(s =>
      s.name === '_objc_release' || s.name === '_objc_retain' ||
      s.name === '_objc_autoreleasePoolPush' || s.name === '_objc_autoreleasePoolPop'
    );

    // Code signature
    sec.signed = !!mo.codeSignature;
    sec.codeSignatureInfo = mo.codeSignatureInfo;

    // Hardened runtime (from code signature flags)
    sec.hardenedRuntime = !!(mo.codeSignatureInfo && mo.codeSignatureInfo.hardenedRuntime);

    // Library validation
    sec.libraryValidation = !!(mo.codeSignatureInfo && mo.codeSignatureInfo.libraryValidation);

    // Restricted segment
    sec.restricted = mo.segments.some(s => s.segname === '__RESTRICT');

    // Encryption
    sec.encrypted = !!(mo.encryptionInfo && mo.encryptionInfo.cryptid !== 0);

    // RPATH (security concern — can be hijacked)
    sec.rpaths = mo.rpaths;

    return sec;
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  String extraction
  // ═══════════════════════════════════════════════════════════════════════

  _extractStrings(bytes, mo, baseOffset) {
    const strings = [];
    const seen = new Set();
    const maxStrings = 10000;
    const minLen = 4;

    // Extract from sections likely to contain readable content
    const stringSections = mo.sections.filter(s =>
      s.size > 0 && s.offset > 0 && s.offset + s.size <= bytes.length &&
      (s.sectname === '__cstring' || s.sectname === '__oslogstring' ||
       s.sectname === '__const' || s.sectname === '__ustring' ||
       s.sectname === '__cfstring' || s.sectname === '__objc_methname' ||
       s.sectname === '__objc_classname' || s.sectname === '__data' ||
       s.segname === '__DATA' || s.segname === '__DATA_CONST')
    );

    // If no recognized sections, scan __TEXT and __DATA segments
    const scanSections = stringSections.length > 0
      ? stringSections
      : mo.sections.filter(s => s.size > 0 && s.offset > 0 && s.offset + s.size <= bytes.length);

    for (const sec of scanSections) {
      if (strings.length >= maxStrings) break;
      const end = Math.min(sec.offset + sec.size, bytes.length);

      // Pass 1: ASCII runs
      let current = '';
      for (let i = sec.offset; i < end; i++) {
        const c = bytes[i];
        if (c >= 0x20 && c < 0x7F) {
          current += String.fromCharCode(c);
        } else {
          if (current.length >= minLen && !seen.has(current)) {
            seen.add(current);
            strings.push(current);
            if (strings.length >= maxStrings) break;
          }
          current = '';
        }
      }
      if (current.length >= minLen && !seen.has(current) && strings.length < maxStrings) {
        seen.add(current);
        strings.push(current);
      }

      // Pass 2: UTF-16LE runs — Mach-O uses __ustring for wide-char
      // literals, and Swift / NSString resources often store UTF-16
      // text that the ASCII pass skips entirely.
      if (strings.length >= maxStrings) break;
      current = '';
      for (let i = sec.offset; i + 1 < end; i += 2) {
        const lo = bytes[i], hi = bytes[i + 1];
        if (hi === 0 && lo >= 0x20 && lo < 0x7F) {
          current += String.fromCharCode(lo);
        } else {
          if (current.length >= minLen && !seen.has(current)) {
            seen.add(current);
            strings.push(current);
            if (strings.length >= maxStrings) break;
          }
          current = '';
        }
      }
      if (current.length >= minLen && !seen.has(current) && strings.length < maxStrings) {
        seen.add(current);
        strings.push(current);
      }
    }

    return strings;
  }


  // ═══════════════════════════════════════════════════════════════════════
  //  Render — builds DOM for viewer pane
  // ═══════════════════════════════════════════════════════════════════════

  render(buffer, fileName) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    this._bytes = bytes;
    const wrap = document.createElement('div');
    wrap.className = 'macho-view';
    let parsedStrings = null;

    try {
      // Check for Fat/Universal binary first
      const fat = this._parseFatHeader(bytes);
      let mo;
      let fatInfo = null;

      if (fat) {
        fatInfo = fat;
        // Parse the first (or best) architecture slice
        if (fat.arches.length > 0) {
          // Prefer x86_64 or ARM64 if available
          const preferred = fat.arches.find(a =>
            a.cputype === 0x01000007 || a.cputype === 0x0100000C
          ) || fat.arches[0];
          mo = this._parse(bytes, preferred.offset);
        } else {
          throw new Error('Fat binary has no architecture slices');
        }
      } else {
        mo = this._parse(bytes, 0);
      }

      // Stash parsed structure for _renderSection() auto-open lookups via
      // BinaryTriage.shouldAutoOpen() — mirrors pe/elf renderers.
      this._parsed = mo;

      parsedStrings = mo.strings;


      // ── Banner ─────────────────────────────────────────────────────
      const banner = document.createElement('div');
      banner.className = 'doc-extraction-banner';
      const bType = mo.filetypeDesc;
      banner.innerHTML = `<strong>Mach-O Analysis — ${this._esc(bType)}</strong> ` +
        (fatInfo ? `<span class="doc-meta-tag">Universal (${fatInfo.nfat} arch)</span> ` : '') +
        `<span class="doc-meta-tag">${this._esc(mo.magicStr)}</span> ` +
        `<span class="doc-meta-tag">${this._esc(mo.cputypeStr)}</span> ` +
        `<span class="doc-meta-tag">${mo.segments.length} segments</span> ` +
        `<span class="doc-meta-tag">${mo.loadCommands.length} load commands</span>` +
        (mo.dylibs.length > 0 ? ` <span class="doc-meta-tag">${mo.dylibs.length} dylibs</span>` : '') +
        (mo.security.signed ? ' <span class="doc-meta-tag">✓ Signed</span>' : '');
      wrap.appendChild(banner);

      // ── Fat/Universal info (if applicable) ────────────────────────
      if (fatInfo) {
        wrap.appendChild(this._renderSection('🏗 Universal Binary', this._renderFatInfo(fatInfo)));
      }

      // ── Tier-A Triage Band ─────────────────────────────────────────
      // Verdict one-liner + coarse 0-100 risk, coloured anomaly-ribbon
      // chips, and a tactic-grouped MITRE ATT&CK strip. The analyst
      // reads this band first; everything below (Binary Pivot, Header,
      // Segments, Load Commands, Dylibs, Symbols, Code Signing,
      // Entitlements, Strings …) is the drill-down for the chips
      // pointed at here. `_findings` was stashed by analyzeForSecurity
      // immediately before render() on the shared _loadFile path.
      try {
        if (typeof BinaryTriage !== 'undefined') {
          const triage = BinaryTriage.render({
            parsed: mo,
            findings: this._findings || {},
            format: 'Mach-O',
            fileSize: bytes.length,
          });
          if (triage) wrap.appendChild(triage);
        }
      } catch (_) { /* triage band is best-effort */ }

      // ── Binary Pivot (shared triage card) ─────────────────────────
      // Identical layout to the PE / ELF cards — SHA-256 / SHA-1 / MD5
      // over the whole file, Mach-O import-hash (MD5 of sorted
      // dylib:symbol pairs), SymHash, code-signature signer (Team ID
      // or CMS leaf CN, or "Ad-hoc signed" / "unsigned"), entry-point
      // offset + section, overlay presence, and a section-name packer
      // guess. Mach-O carries no compile timestamp in its structural
      // header so that slot is omitted.
      try {
        if (typeof BinarySummary !== 'undefined') {
          // Import-shape hash — mirror the computation in
          // analyzeForSecurity() (dylib:symbol pairs, lowercased,
          // sorted, deduplicated). This is the Mach-O analogue of
          // imphash/telfhash.
          let importHash = null;
          let symHashVal = null;
          try {
            const importedSymNames = mo.symbols
              .filter(s => s && s.name && s.typeField === 0 && s.isExternal)
              .map(s => s.name);
            const dylibBasenames = (mo.dylibs || []).map(d => {
              const n = typeof d === 'string' ? d : (d && d.name) || '';
              const slash = n.lastIndexOf('/');
              return slash >= 0 ? n.slice(slash + 1) : n;
            });
            if (typeof computeSymHash === 'function') {
              symHashVal = computeSymHash(importedSymNames, dylibBasenames) || null;
            }
            // Mach-O import hash = MD5 of the sorted, deduplicated,
            // lowercased "dylib:symbol" pairs (matches analyzeForSecurity).
            if (typeof computeImportHashFromList === 'function' && importedSymNames.length) {
              const pairs = [];
              const dylibs = dylibBasenames.filter(Boolean);
              for (const sym of importedSymNames) {
                const s = String(sym).toLowerCase();
                if (dylibs.length === 0) {
                  pairs.push(s);
                } else {
                  for (const dl of dylibs) {
                    pairs.push(String(dl).toLowerCase() + ':' + s);
                  }
                }
              }
              const uniq = [...new Set(pairs)].sort();
              if (uniq.length) importHash = computeImportHashFromList(uniq) || null;
            }
          } catch (_) { /* best-effort */ }

          // Signer — prefer Team ID, then the first CMS leaf CN, then
          // "Ad-hoc signed" for an unauthenticated code-signature blob,
          // else "unsigned".
          let signer = { present: false, label: 'unsigned' };
          const csi = mo.codeSignatureInfo;
          if (csi && csi.teamId) {
            signer = { present: true, label: 'Team ID: ' + csi.teamId };
          } else if (csi && csi.certificates && csi.certificates.length > 0) {
            const c = csi.certificates[0];
            const label = (c.subject && c.subject.CN) || c.subjectStr || 'signed';
            signer = { present: true, label };
          } else if (mo.codeSignature) {
            signer = { present: true, label: 'Ad-hoc signed' };
          }

          // Entry-point section lookup — Mach-O sections use
          // sectname/segname and `addr` as the virtual address; EP is
          // a file offset (LC_MAIN) for modern binaries, so the section
          // match is a best-effort "offset-in-range" sweep.
          let epSection = null;
          let epDisplay = null;
          if (mo.entryPoint !== null && mo.entryPoint !== undefined) {
            const digits = (mo.magicStr && mo.magicStr.indexOf('64') !== -1) ? 16 : 8;
            epDisplay = this._hex(mo.entryPoint, digits);
            try {
              for (const s of (mo.sections || [])) {
                if (!s || !s.size || !s.offset) continue;
                if (mo.entryPoint >= s.offset && mo.entryPoint < s.offset + s.size) {
                  epSection = (s.segname ? s.segname + ',' : '') + (s.sectname || '');
                  break;
                }
              }
            } catch (_) { /* best-effort */ }
          }

          // Overlay + first-bytes magic.
          let overlayInfo = { present: false };
          try {
            const oStart = this._computeOverlayStart(mo);
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

          // Packer — Mach-O packers are rare; tiny inline lookup for
          // the best-known section-name markers (UPX Mach-O stubs).
          let packerInfo = null;
          try {
            const MACHO_PACKER_SECTIONS = {
              '__XHDR': 'UPX',
            };
            const hit = (mo.sections || []).find(s => s && MACHO_PACKER_SECTIONS[s.sectname]);
            if (hit) {
              packerInfo = {
                label: MACHO_PACKER_SECTIONS[hit.sectname],
                source: 'section ' + hit.sectname,
              };
            }
          } catch (_) { /* best-effort */ }

          const formatDetail = [mo.magicStr, mo.cputypeStr].filter(Boolean).join(' · ');

          // Identity pivots — Team ID, Bundle ID, SDK/min-OS are the
          // stable cross-sample pivots an analyst uses to fingerprint
          // a Mach-O:
          //   • teamId   — CodeDirectory blob (mo.codeSignatureInfo)
          //   • bundleId — embedded Info.plist (stashed into findings.
          //                metadata['Bundle ID'] by analyzeForSecurity)
          //   • sdkMinOS — LC_BUILD_VERSION / legacy LC_VERSION_MIN_*
          const teamId = (mo.codeSignatureInfo && mo.codeSignatureInfo.teamId) || null;
          const bundleId = (this._findings
            && this._findings.metadata
            && this._findings.metadata['Bundle ID']) || null;
          let sdkMinOS = null;
          if (mo.buildVersion) {
            const bv = mo.buildVersion;
            sdkMinOS = `${bv.platform} min ${bv.minos} · SDK ${bv.sdk}`;
          } else if (mo.minVersion) {
            const mv = mo.minVersion;
            sdkMinOS = `${mv.platform} min ${mv.version} · SDK ${mv.sdk}`;
          }

          // Loupe does not walk the CMS root-of-trust, so downgrade the
          // "signed" badge to the tri-state "signer present" rendering.
          // analyzeForSecurity set signer.present=true when a Team ID or
          // cert chain was embedded; verified:false makes the UI honest
          // about what was and wasn't checked.
          const signerVerified = signer && signer.present
            ? Object.assign({}, signer, { verified: false })
            : signer;

          const card = BinarySummary.renderCard({
            bytes,
            fileSize: bytes.length,
            format: 'Mach-O',
            formatDetail,
            importHash,
            richHash: null,
            symHash: symHashVal,
            signer: signerVerified,
            compileTimestamp: null,
            entryPoint: epDisplay ? {
              displayStr: epDisplay,
              section: epSection,
              anomaly: null,
            } : null,
            overlay: overlayInfo,
            packer: packerInfo,
            teamId,
            bundleId,
            sdkMinOS,
          });
          wrap.appendChild(card);
        }
      } catch (_) { /* summary card is best-effort */ }

      // ── Tier-C reference cards (collapsed by default — auto-open on anomaly) ─
      // Everything below is the drill-down for the Tier-A verdict band
      // and anomaly ribbon. `_renderSection(..., {cardId})` routes the
      // open/closed decision through BinaryTriage.shouldAutoOpen() so
      // benign samples surface a clean triage surface while genuinely
      // anomalous cards (W+X segments, unusual RPATHs, suspect
      // signatures, high-entropy sections, …) are already open when the
      // analyst scrolls down.

      // ── Mach-O Header ─────────────────────────────────────────────
      wrap.appendChild(this._renderSection('📋 Mach-O Header', this._renderHeaders(mo), 0, { cardId: 'header' }));

      // ── Security Features ─────────────────────────────────────────
      wrap.appendChild(this._renderSection('🛡 Security Features', this._renderSecurity(mo), 0, { cardId: 'security' }));

      // ── Segments & Sections ───────────────────────────────────────
      if (mo.segments.length > 0) {
        wrap.appendChild(this._renderSection(
          '📦 Segments & Sections (' + mo.segments.length + ' segments, ' + mo.sections.length + ' sections)',
          this._renderSegments(mo),
          0,
          { cardId: 'segments' }
        ));
      }

      // ── Load Commands ─────────────────────────────────────────────
      if (mo.loadCommands.length > 0) {
        wrap.appendChild(this._renderSection(
          '⚙ Load Commands (' + mo.loadCommands.length + ')',
          this._renderLoadCommands(mo),
          0,
          { cardId: 'load-commands' }
        ));
      }

      // ── Dynamic Libraries ─────────────────────────────────────────
      if (mo.dylibs.length > 0) {
        wrap.appendChild(this._renderSection(
          '📚 Dynamic Libraries (' + mo.dylibs.length + ')',
          this._renderDylibs(mo),
          0,
          { cardId: 'dylibs' }
        ));
      }

      // ── Symbols ───────────────────────────────────────────────────
      const imports = mo.symbols.filter(s => s.name && s.typeField === 0 && s.isExternal);
      const exports = mo.symbols.filter(s => s.name && s.typeField === 7 && (s.isExternal || s.isPrivateExternal));

      if (imports.length > 0) {
        wrap.appendChild(this._renderSection(
          '📥 Imported Symbols (' + imports.length + ')',
          this._renderSymbols(imports, true),
          0,
          { cardId: 'symbols' }
        ));
      }

      if (exports.length > 0) {
        wrap.appendChild(this._renderSection(
          '📤 Exported Symbols (' + exports.length + ')',
          this._renderSymbols(exports, false),
          0,
          { cardId: 'symbols' }
        ));
      }

      // ── Code Signature ────────────────────────────────────────────
      if (mo.codeSignatureInfo) {
        wrap.appendChild(this._renderSection('🔐 Code Signature', this._renderCodeSignature(mo), 0, { cardId: 'codesig' }));
      }


      // ── Overlay (appended payload past end-of-image) ──────────────
      // Thin: bytes past max(seg.fileoff + seg.filesize) are the
      // overlay. Fat: compute per-slice — the parsed slice's overlay
      // sits between its payload end and its declared (offset+size);
      // Fat-container trailing bytes past the last slice end are a
      // separate overlay on the outer wrapper. No Authenticode
      // equivalent on Mach-O (code signature is an inline load
      // command, handled separately by _parseCodeSignature).
      try {
        if (typeof BinaryOverlay !== 'undefined') {
          const baseName = (fileName || 'binary').replace(/\.[^.]+$/, '');

          if (fatInfo) {
            // Slice that we deeply parsed
            const preferred = fatInfo.arches.find(a =>
              a.cputype === 0x01000007 || a.cputype === 0x0100000C
            ) || fatInfo.arches[0];
            const sliceEnd = preferred.offset + preferred.size;
            const sliceOverlayStart = this._computeOverlayStart(mo);
            if (sliceOverlayStart > 0 && sliceOverlayStart < sliceEnd && sliceEnd <= bytes.length) {
              const { el } = BinaryOverlay.renderCard({
                bytes,
                overlayStart: sliceOverlayStart,
                fileSize: sliceEnd,
                baseName,
                subtitle: `past slice end — ${preferred.cputypeStr}`,
              });
              wrap.appendChild(this._renderSection('📎 Overlay (slice)', el));
            }

            // Fat-container tail: bytes past the last slice's end
            let lastSliceEnd = 0;
            for (const a of fatInfo.arches) {
              const e = a.offset + a.size;
              if (e > lastSliceEnd) lastSliceEnd = e;
            }
            if (lastSliceEnd > 0 && lastSliceEnd < bytes.length) {
              const { el } = BinaryOverlay.renderCard({
                bytes,
                overlayStart: lastSliceEnd,
                fileSize: bytes.length,
                baseName,
                subtitle: 'past last slice (Fat container tail)',
              });
              wrap.appendChild(this._renderSection('📎 Overlay (Fat tail)', el));
            }
          } else {
            const oStart = this._computeOverlayStart(mo);
            if (oStart > 0 && oStart < bytes.length) {
              const { el } = BinaryOverlay.renderCard({
                bytes,
                overlayStart: oStart,
                fileSize: bytes.length,
                baseName,
                subtitle: 'past end-of-image',
              });
              wrap.appendChild(this._renderSection('📎 Overlay', el));
            }
          }
        }
      } catch (_) { /* overlay drill-down is best-effort */ }

      // ── Strings ───────────────────────────────────────────────────
      if (mo.strings.length > 0) {
        wrap.appendChild(this._renderSection(
          '🔤 Strings (' + mo.strings.length + ')',
          this._renderStrings(mo)
        ));
      }

    } catch (err) {
      parsedStrings = this._renderFallback(wrap, bytes, err, fileName);
    }


    // Expose extracted strings as _rawText so the general IOC extraction
    // pipeline and EncodedContentDetector scan clean string data instead
    // of noisy DOM text (table headers, hex addresses, UI chrome, etc.)
    if (parsedStrings && parsedStrings.length > 0) {
      wrap._rawText = lfNormalize(parsedStrings.join('\n'));
    }

    return wrap;
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Graceful fallback for malformed / truncated Mach-O binaries
  // ═══════════════════════════════════════════════════════════════════════

  _renderFallback(wrap, bytes, err, fileName) {
    const notice = document.createElement('div');
    notice.className = 'bin-fallback-notice';
    const magic = bytes.length >= 4
      ? Array.from(bytes.slice(0, 4)).map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ')
      : '—';
    notice.innerHTML =
      `<div class="bin-fallback-title"><strong>⚠ Mach-O parsing failed — showing raw fallback view</strong></div>` +
      `<div class="bin-fallback-reason"><code>${this._esc(err.message)}</code></div>` +
      `<div class="bin-fallback-sub">The file appears to be truncated or malformed, so structural ` +
      `analysis (header, load commands, segments, symbols, …) isn't available. Extracted strings and ` +
      `a raw hex dump are shown below so IOC extraction and YARA rules can still run against the bytes.</div>` +
      `<div class="bin-fallback-info">` +
        `<span class="doc-meta-tag">${this._esc(fileName || 'unknown')}</span> ` +
        `<span class="doc-meta-tag">${bytes.length.toLocaleString()} bytes</span> ` +
        `<span class="doc-meta-tag">Magic: ${magic}</span>` +
      `</div>`;
    wrap.appendChild(notice);

    // Generic string scan — the normal _extractStrings requires a parsed
    // Mach-O object (it uses mo.sections), so we scan the raw buffer directly.
    const strings = this._rawStringScan(bytes);
    if (strings.length > 0) {
      const fakeMo = { strings };
      wrap.appendChild(this._renderSection(
        '🔤 Strings (' + strings.length + ')',
        this._renderStrings(fakeMo)
      ));
    }

    // Raw hex dump — reuse the same helper normally used by section rows.
    if (bytes.length > 0) {
      const hexContent = document.createElement('div');
      hexContent.appendChild(this._renderHexDump(0, bytes.length));
      wrap.appendChild(this._renderSection(
        '📄 Raw Hex Dump (' + bytes.length.toLocaleString() + ' bytes)',
        hexContent
      ));
    }

    return strings;
  }

  // Byte-scan fallback used when no parsed Mach-O structure is available.
  _rawStringScan(bytes) {
    const strings = [];
    const seen = new Set();
    const minLen = 4;
    const maxStrings = 10000;
    const maxScan = Math.min(bytes.length, 8 * 1024 * 1024);
    let current = '';
    for (let i = 0; i < maxScan && strings.length < maxStrings; i++) {
      const c = bytes[i];
      if (c >= 0x20 && c < 0x7F) {
        current += String.fromCharCode(c);
      } else {
        if (current.length >= minLen && !seen.has(current)) {
          seen.add(current);
          strings.push(current);
        }
        current = '';
      }
    }
    if (current.length >= minLen && !seen.has(current) && strings.length < maxStrings) {
      strings.push(current);
    }
    return strings;
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Section renderers (DOM builders)
  // ═══════════════════════════════════════════════════════════════════════

  _renderSection(title, contentEl, rowCount, opts) {
    const sec = document.createElement('details');
    sec.className = 'macho-section';
    const collapse = rowCount && rowCount > 50;
    const cardId = opts && opts.cardId;
    let open;
    if (cardId) {
      let auto = false;
      try {
        if (typeof BinaryTriage !== 'undefined') {
          auto = BinaryTriage.shouldAutoOpen({
            parsed: this._parsed,
            findings: this._findings || {},
            format: 'Mach-O',
          }, cardId);
        }
      } catch (_) { /* best-effort */ }
      open = auto && !collapse;
    } else {
      open = !collapse;
    }
    sec.open = !!open;
    const sum = document.createElement('summary');
    sum.innerHTML = this._esc(title) + (collapse ? ` <span class="bin-collapse-note">${rowCount} rows — click to expand</span>` : '');
    sec.appendChild(sum);
    sec.appendChild(contentEl);
    return sec;
  }


  _renderFatInfo(fat) {
    const rows = fat.arches.map((a, i) => [
      i.toString(),
      a.cputypeStr,
      this._hex(a.offset, 8),
      a.size.toLocaleString(),
      `2^${a.align}`,
    ]);
    return this._buildTable(['#', 'Architecture', 'Offset', 'Size', 'Align'], rows);
  }

  _renderHeaders(mo) {
    const digits = this._is64 ? 16 : 8;
    const rows = [
      ['Magic', mo.magicStr],
      ['CPU Type', `${mo.cputypeStr} (subtype: ${mo.cpusubtypeStr})`],
      ['File Type', `${mo.filetypeStr} — ${mo.filetypeDesc}`],
      ['Load Commands', `${mo.ncmds} commands (${mo.sizeofcmds.toLocaleString()} bytes)`],
      ['Flags', `${this._hex(mo.flags, 8)}` + (mo.flagsList.length > 0 ? ` — ${mo.flagsList.join(', ')}` : '')],
    ];
    if (mo.uuid) rows.push(['UUID', mo.uuid]);
    if (mo.entryPoint !== null) rows.push(['Entry Point', this._hex(mo.entryPoint, digits)]);
    if (mo.dylinker) rows.push(['Dynamic Linker', mo.dylinker]);
    if (mo.idDylib) rows.push(['Library ID', mo.idDylib]);
    if (mo.sourceVersion) rows.push(['Source Version', mo.sourceVersion]);
    if (mo.buildVersion) {
      rows.push(['Platform', `${mo.buildVersion.platform} (min: ${mo.buildVersion.minos}, SDK: ${mo.buildVersion.sdk})`]);
      if (mo.buildVersion.tools.length > 0) {
        rows.push(['Build Tools', mo.buildVersion.tools.map(t => `${t.tool} ${t.version}`).join(', ')]);
      }
    } else if (mo.minVersion) {
      rows.push(['Min Version', `${mo.minVersion.platform} ${mo.minVersion.version} (SDK: ${mo.minVersion.sdk})`]);
    }
    return this._buildTable(['Field', 'Value'], rows);
  }

  _renderSecurity(mo) {
    const s = mo.security;
    const div = document.createElement('div');
    div.className = 'macho-security-grid';

    const features = [
      ['PIE (Position Independent)', s.pie, s.pie
        ? 'PIE enabled — full ASLR for executable'
        : 'Not PIE — fixed load address, limited ASLR'],
      ['Stack Canary', s.stackCanary, s.stackCanary
        ? 'Stack canary enabled — buffer overflow protection via __stack_chk_fail'
        : 'No stack canary detected — vulnerable to stack buffer overflows'],
      ['NX Stack', s.nxStack, s.nxStack
        ? 'NX Stack — stack is non-executable'
        : 'Stack execution allowed — shellcode can run from stack'],
      ['NX Heap', s.nxHeap, s.nxHeap
        ? 'NX Heap — heap is non-executable'
        : 'Heap execution not restricted'],
      ['ARC (Automatic Reference Counting)', s.arc, s.arc
        ? 'ARC enabled — memory-safe Objective-C references'
        : 'ARC not detected — manual memory management or pure C/C++'],
      ['Code Signed', s.signed, s.signed
        ? 'Code signature present' + (s.codeSignatureInfo && s.codeSignatureInfo.hasCMSSignature ? ' (with CMS signature)' : '')
        : 'No code signature — unsigned binary'],
      ['Hardened Runtime', s.hardenedRuntime, s.hardenedRuntime
        ? 'Hardened runtime enabled — restricted debugging, DYLD variables, and library injection'
        : 'Hardened runtime not enabled'],
      ['Library Validation', s.libraryValidation, s.libraryValidation
        ? 'Library validation — only loads signed libraries'
        : 'Library validation not enabled — can load unsigned dylibs'],
    ];

    for (const [name, enabled, desc] of features) {
      const row = document.createElement('div');
      row.className = 'macho-sec-row' + (enabled ? ' macho-sec-on' : ' macho-sec-off');
      const icon = enabled ? '✅' : '❌';
      row.innerHTML = `<span class="macho-sec-icon">${icon}</span>` +
        `<span class="macho-sec-name">${this._esc(name)}</span>` +
        `<span class="macho-sec-desc">${this._esc(desc)}</span>`;
      div.appendChild(row);
    }

    // RPATH warning
    if (s.rpaths.length > 0) {
      for (const rp of s.rpaths) {
        const rpathRow = document.createElement('div');
        rpathRow.className = 'macho-sec-row macho-sec-off';
        rpathRow.innerHTML = `<span class="macho-sec-icon">⚠️</span>` +
          `<span class="macho-sec-name">RPATH</span>` +
          `<span class="macho-sec-desc">RPATH set to "${this._esc(rp)}" — potential dylib hijacking vector</span>`;
        div.appendChild(rpathRow);
      }
    }

    // Encryption warning
    if (s.encrypted) {
      const encRow = document.createElement('div');
      encRow.className = 'macho-sec-row macho-sec-off';
      encRow.innerHTML = `<span class="macho-sec-icon">🔒</span>` +
        `<span class="macho-sec-name">Encrypted</span>` +
        `<span class="macho-sec-desc">Binary has encrypted segments — may be packed or protected</span>`;
      div.appendChild(encRow);
    }

    // Restricted segment
    if (s.restricted) {
      const resRow = document.createElement('div');
      resRow.className = 'macho-sec-row macho-sec-on';
      resRow.innerHTML = `<span class="macho-sec-icon">✅</span>` +
        `<span class="macho-sec-name">Restricted</span>` +
        `<span class="macho-sec-desc">__RESTRICT segment present — DYLD_* environment variables ignored</span>`;
      div.appendChild(resRow);
    }

    return div;
  }

  _renderSegments(mo) {
    const div = document.createElement('div');
    const digits = this._is64 ? 16 : 8;

    for (const seg of mo.segments) {
      const segDetails = document.createElement('details');
      segDetails.className = 'macho-segment-block';
      segDetails.open = true;

      const segSum = document.createElement('summary');
      segSum.className = 'macho-segment-name';
      const protWarn = (seg.initprot & 2) && (seg.initprot & 4) ? ' <span class="macho-warn-badge">W+X</span>' : '';
      segSum.innerHTML = `<strong>${this._esc(seg.segname || '(unnamed)')}</strong>` +
        ` <span class="macho-seg-meta">VM: ${this._hex(seg.vmaddr, digits)} Size: ${seg.vmsize.toLocaleString()} ` +
        `Prot: ${seg.initprotStr}/${seg.maxprotStr}</span>${protWarn}`;
      segDetails.appendChild(segSum);

      if (seg.sections.length > 0) {
        const rows = seg.sections.map(sec => [
          sec.sectname,
          this._hex(sec.addr, digits),
          this._hex(sec.offset, 8),
          sec.size.toLocaleString(),
          sec.entropy > 0 ? sec.entropy.toFixed(3) : '—',
        ]);
        const table = this._buildTable(['Section', 'Address', 'Offset', 'Size', 'Entropy'], rows,
          (row, i) => {
            const sec = seg.sections[i];
            if (sec.entropy > 7.0) row.classList.add('macho-highlight');
            if (sec.size > 0 && sec.offset > 0) {
              row.classList.add('bin-clickable');
              row.addEventListener('click', () => {
                const next = row.nextElementSibling;
                if (next && next.classList.contains('bin-hexdump-row')) {
                  next.remove(); row.classList.remove('bin-expanded');
                } else {
                  const hr = document.createElement('tr'); hr.className = 'bin-hexdump-row';
                  const td = document.createElement('td'); td.colSpan = 5;
                  td.appendChild(this._renderHexDump(sec.offset, sec.size));
                  hr.appendChild(td); row.after(hr); row.classList.add('bin-expanded');
                }
              });
            }
          }
        );
        segDetails.appendChild(table);
      } else {
        // Segment with no sections — show segment properties as info
        const info = document.createElement('div');
        info.className = 'macho-seg-info';
        info.innerHTML =
          `<span class="macho-seg-info-item">File Offset: <strong>${this._hex(seg.fileoff, 8)}</strong></span>` +
          `<span class="macho-seg-info-item">File Size: <strong>${seg.filesize.toLocaleString()}</strong></span>` +
          `<span class="macho-seg-info-item">VM Size: <strong>${seg.vmsize.toLocaleString()}</strong></span>` +
          `<span class="macho-seg-info-item">Init Prot: <strong>${seg.initprotStr}</strong></span>` +
          `<span class="macho-seg-info-item">Max Prot: <strong>${seg.maxprotStr}</strong></span>` +
          (seg.filesize === 0 ? '<span class="macho-seg-info-note">No file content — virtual memory reservation only</span>' : '');
        segDetails.appendChild(info);
      }

      div.appendChild(segDetails);
    }

    return div;
  }

  _renderLoadCommands(mo) {
    const rows = mo.loadCommands.map((lc, i) => [
      i.toString(),
      lc.cmdName,
      lc.cmdsize.toLocaleString() + ' bytes',
      lc.detail || (lc.segment ? `${lc.segment.segname} (${lc.segment.sections.length} sections)` : ''),
    ]);
    return this._buildTable(['#', 'Command', 'Size', 'Detail'], rows);
  }

  _renderDylibs(mo) {
    const div = document.createElement('div');

    const rows = mo.dylibs.map(d => {
      const typeBadge = d.type !== 'required'
        ? `<span class="macho-dylib-type macho-dylib-${d.type}">${d.type}</span> `
        : '';
      return [
        typeBadge + this._esc(d.name),
        d.curVer,
        d.compatVer,
      ];
    });

    const table = this._buildTable(['Library', 'Version', 'Compat Version'], rows, null, true);
    div.appendChild(table);

    // RPATH info
    if (mo.rpaths.length > 0) {
      const rpDiv = document.createElement('div');
      rpDiv.style.marginTop = '10px';
      rpDiv.innerHTML = `<strong>RPATHs:</strong>`;
      for (const rp of mo.rpaths) {
        const item = document.createElement('div');
        item.className = 'macho-rpath-item';
        item.innerHTML = `<span class="macho-warn-text">${this._esc(rp)}</span>`;
        rpDiv.appendChild(item);
      }
      div.appendChild(rpDiv);
    }

    return div;
  }

  _renderSymbols(syms, isImport) {
    const digits = this._is64 ? 16 : 8;
    const suspMap = MachoRenderer.SUSPICIOUS_SYMBOLS;

    const rows = syms.map(sym => {
      // Strip leading underscore for display (Mach-O convention)
      const displayName = sym.name.startsWith('_') ? sym.name.substring(1) : sym.name;
      const lookupName = suspMap[sym.name] ? sym.name : (suspMap[displayName] ? displayName : null);
      const suspicious = lookupName ? suspMap[lookupName] : null;
      const nameHtml = suspicious
        ? `<span class="macho-suspicious-sym" title="${this._esc(suspicious)}">${this._esc(sym.name)} ⚠️</span>`
        : this._esc(sym.name);
      return [
        nameHtml,
        sym.typeStr,
        isImport ? '—' : this._hex(sym.value, digits),
        suspicious ? `<span class="macho-suspicious-desc">${this._esc(suspicious)}</span>` : '',
      ];
    });

    const table = this._buildTable(
      ['Name', 'Type', 'Value', isImport ? 'Risk' : 'Info'],
      rows,
      (row, i) => {
        const sym = syms[i];
        const displayName = sym.name.startsWith('_') ? sym.name.substring(1) : sym.name;
        const lookupName = suspMap[sym.name] ? sym.name : (suspMap[displayName] ? displayName : null);
        if (lookupName) {
          row.classList.add('macho-suspicious-row');
          row.style.cursor = 'pointer';
          row.addEventListener('click', () => {
            const next = row.nextElementSibling;
            if (next && next.classList.contains('bin-info-card-row')) {
              next.remove(); return;
            }
            const info = suspMap[lookupName];
            const detail = MachoRenderer.SUSPICIOUS_APIS_DETAIL[lookupName];
            const cat = this._categorizeSymbol(lookupName);
            const cardRow = document.createElement('tr'); cardRow.className = 'bin-info-card-row';
            const td = document.createElement('td'); td.colSpan = 4;
            const card = document.createElement('div'); card.className = 'bin-info-card';
            let html = `<strong>${this._esc(lookupName)}</strong>` +
              (cat ? ` <span class="bin-info-card-cat ${cat.cls}">${this._esc(cat.cat)}</span>` : ` <span class="bin-info-card-cat cat-inject">Suspicious</span>`);
            if (detail) {
              html += `<div class="bin-tooltip-section"><span class="bin-tooltip-label">What it does</span>${this._esc(detail.desc)}</div>`;
              html += `<div class="bin-tooltip-section"><span class="bin-tooltip-label">⚠ Why suspicious</span>${this._esc(detail.context)}</div>`;
              if (detail.mitre) html += `<div class="bin-tooltip-mitre">🔗 MITRE ATT&CK: ${this._esc(detail.mitre)}</div>`;
            } else {
              html += `<p class="bin-info-card-desc">${this._esc(info)}</p>`;
            }
            card.innerHTML = html;
            td.appendChild(card); cardRow.appendChild(td); row.after(cardRow);
          });
        }
      },
      true
    );

    // Wrap table in a container for search bar
    const wrapper = document.createElement('div');
    this._addSearchBar(wrapper, () => Array.from(table.querySelectorAll('tbody tr:not(.bin-info-card-row)')), 'Filter symbols…', '.macho-suspicious-row');
    wrapper.appendChild(table);
    return wrapper;
  }

  _renderCodeSignature(mo) {
    const info = mo.codeSignatureInfo;
    const div = document.createElement('div');

    const rows = [
      ['Present', info.present ? 'Yes' : 'No'],
      ['Blobs', `${info.blobs || 0} signature blob(s)`],
    ];
    if (info.cdVersion) rows.push(['CodeDirectory Version', info.cdVersion]);
    if (info.teamId) rows.push(['Team ID', info.teamId]);
    if (info.hasCMSSignature) rows.push(['CMS Signature', 'Present (Apple / third-party signed)' + (info.certificates ? ` — ${info.certificates.length} certificate(s)` : '')]);
    if (info.hardenedRuntime) rows.push(['Hardened Runtime', '✅ Enabled']);
    if (info.libraryValidation) rows.push(['Library Validation', '✅ Enabled']);

    div.appendChild(this._buildTable(['Field', 'Value'], rows));

    // Certificates
    if (info.certificates && info.certificates.length > 0) {
      for (let i = 0; i < info.certificates.length; i++) {
        const c = info.certificates[i];
        const label = c.subject.CN || c.subjectStr || '(unnamed)';
        const now = new Date();
        let status = '✅ Valid';
        if (c.notAfter && now > c.notAfter) status = '❌ Expired';
        else if (c.notBefore && now < c.notBefore) status = '⏳ Not Yet Valid';
        let pk = c.publicKeyAlgorithm || '';
        if (c.publicKeySize) pk += ' ' + c.publicKeySize + '-bit';
        if (c.publicKeyCurve) pk += ' (' + c.publicKeyCurve + ')';
        const certRows = [
          ['Subject', c.subjectStr || '(empty)'],
          ['Issuer', c.issuerStr || '(empty)'],
          ['Serial', c.serialNumber || '(none)'],
          ['Validity', `${status}  ·  ${c.notBeforeStr || '?'} → ${c.notAfterStr || '?'}`],
          ['Public Key', pk],
          ['Signature', c.signatureAlgorithm || '(unknown)'],
        ];
        if (c.isSelfSigned) certRows.push(['Self-Signed', 'Yes']);
        if (c.isCA) certRows.push(['CA', 'Yes']);
        const ekuExt = c.extensions.find(e => e.oid === '2.5.29.37');
        if (ekuExt && ekuExt.value) certRows.push(['Extended Key Usage', ekuExt.value]);
        const heading = document.createElement('div');
        heading.style.cssText = 'font-weight:600;margin:12px 0 4px;';
        heading.textContent = `Certificate ${i + 1}: ${label}`;
        div.appendChild(heading);
        div.appendChild(this._buildTable(['Field', 'Value'], certRows));
      }
    }

    // Entitlements
    if (info.entitlements) {
      const entDetails = document.createElement('details');
      entDetails.style.marginTop = '10px';
      const entSum = document.createElement('summary');
      entSum.textContent = 'Entitlements';
      entSum.style.cursor = 'pointer';
      entSum.style.fontWeight = '600';
      entDetails.appendChild(entSum);
      const pre = document.createElement('pre');
      pre.className = 'macho-entitlements';
      pre.textContent = info.entitlements;
      entDetails.appendChild(pre);
      div.appendChild(entDetails);
    }

    return div;
  }

  _renderStrings(mo) {
    const div = document.createElement('div');
    div.className = 'macho-strings-container';

    // Categorised-strings triage card (mutexes/pipes/registry are Windows-only
    // and will quietly produce no hits on Mach-O; PDB/user-path/Rust-panic
    // categories remain useful for cross-compiled binaries).
    try {
      if (typeof BinaryStrings !== 'undefined' && BinaryStrings.renderCategorisedStringsTable) {
        const cats = BinaryStrings.renderCategorisedStringsTable(mo.strings || []);
        if (cats) div.appendChild(cats);
      }
    } catch (_) { /* non-fatal */ }

    // Save/Copy pill group for strings

    const pillBar = document.createElement('div');
    pillBar.style.cssText = 'display:flex;align-items:center;gap:6px;margin-bottom:8px;';
    const pillGroup = document.createElement('div');
    pillGroup.className = 'btn-pill-group';
    const saveBtn = document.createElement('button');
    saveBtn.className = 'tb-btn tb-action-btn';
    saveBtn.textContent = '💾 Save';
    saveBtn.title = 'Save strings as .txt';
    saveBtn.addEventListener('click', () => {
      window.FileDownload.downloadText(mo.strings.join('\n'), 'strings.txt', 'text/plain');
    });
    const copyBtn = document.createElement('button');
    copyBtn.className = 'tb-btn tb-action-btn';
    copyBtn.textContent = '📋 Copy';
    copyBtn.title = 'Copy all strings to clipboard';
    copyBtn.addEventListener('click', () => {
      const text = mo.strings.join('\n');
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

    const list = document.createElement('div');
    list.className = 'macho-strings-list';

    for (const s of mo.strings) {
      const item = document.createElement('div');
      item.className = 'macho-string-item';
      item.textContent = s;
      list.appendChild(item);
    }

    this._addSearchBar(div, () => Array.from(list.querySelectorAll('.macho-string-item')), 'Filter strings…');
    div.appendChild(list);
    return div;
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Interactive helpers — hex dump, search bar
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
        const line = document.createElement('div'); line.className = 'bin-hexdump-line';
        const offSpan = document.createElement('span'); offSpan.className = 'bin-hexdump-offset';
        offSpan.textContent = (offset + i).toString(16).toUpperCase().padStart(8, '0');
        line.appendChild(offSpan);
        let hexStr = '', ascStr = '';
        for (let j = 0; j < 16; j++) {
          if (i + j < totalBytes) {
            const b = bytes[offset + i + j];
            hexStr += b ? `<span class="bin-nz">${b.toString(16).padStart(2,'0').toUpperCase()}</span> ` : '00 ';
            ascStr += (b >= 0x20 && b < 0x7F) ? String.fromCharCode(b) : '.';
          } else { hexStr += '   '; ascStr += ' '; }
          if (j === 7) hexStr += ' ';
        }
        const hexSpan = document.createElement('span'); hexSpan.className = 'bin-hexdump-hex';
        hexSpan.innerHTML = hexStr; line.appendChild(hexSpan);
        const ascSpan = document.createElement('span'); ascSpan.className = 'bin-hexdump-ascii';
        ascSpan.textContent = ascStr; line.appendChild(ascSpan);
        frag.appendChild(line);
      }
      return frag;
    };
    const dump = document.createElement('div'); dump.className = 'bin-hexdump';
    dump.appendChild(buildLines(0, shown)); container.appendChild(dump);
    if (totalBytes > shown) {
      const btn = document.createElement('button'); btn.className = 'bin-hexdump-show-more';
      btn.textContent = `Show more (${(totalBytes - shown).toLocaleString()} bytes remaining)`;
      btn.addEventListener('click', () => {
        const next = Math.min(shown + 4096, totalBytes);
        dump.appendChild(buildLines(shown, next - shown)); shown = next;
        if (shown >= totalBytes) btn.remove();
        else btn.textContent = `Show more (${(totalBytes - shown).toLocaleString()} bytes remaining)`;
      });
      container.appendChild(btn);
    }
    return container;
  }

  _addSearchBar(container, getItems, placeholder, riskSelector) {
    const wrap = document.createElement('div'); wrap.className = 'bin-search-wrap';
    const input = document.createElement('input'); input.type = 'text';
    input.placeholder = placeholder || 'Search…';
    const count = document.createElement('span'); count.className = 'bin-search-count';
    wrap.appendChild(input);
    let riskOnly = false, riskBtn = null;
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

  _categorizeSymbol(name) {
    const info = MachoRenderer.SUSPICIOUS_SYMBOLS[name];
    if (!info) return null;
    const lower = info.toLowerCase();
    if (/debug|prevent|deny_attach/i.test(lower)) return { cat: 'Anti-Debug', cls: 'cat-antidebug' };
    if (/injection|another.*process|task_for_pid|mach_vm/i.test(lower)) return { cat: 'Process Injection', cls: 'cat-inject' };
    if (/execution|command|shell|exec/i.test(lower)) return { cat: 'Execution', cls: 'cat-exec' };
    if (/network|socket|C2|exfiltration|backdoor|listener|connection|send|recv/i.test(lower)) return { cat: 'Networking', cls: 'cat-network' };
    if (/privilege|setuid|setgid|capability/i.test(lower)) return { cat: 'Privilege Escalation', cls: 'cat-cred' };
    if (/keychain|credential|password/i.test(lower)) return { cat: 'Credential Access', cls: 'cat-cred' };
    if (/fileless|memory.*load|NSCreateObject/i.test(lower)) return { cat: 'Fileless Execution', cls: 'cat-crypto' };
    if (/deletion|forensic|self.*delet/i.test(lower)) return { cat: 'Anti-Forensics', cls: 'cat-file' };
    if (/dynamic|dlopen|dlsym/i.test(lower)) return { cat: 'Dynamic Loading', cls: 'cat-recon' };
    if (/screen.*capture|window.*capture|surveillance|keylog|event.*tap/i.test(lower)) return { cat: 'Surveillance', cls: 'cat-recon' };
    if (/persistence|login.*item|launch/i.test(lower)) return { cat: 'Persistence', cls: 'cat-file' };
    if (/iokit|hardware|vm.*detect|fingerprint/i.test(lower)) return { cat: 'Reconnaissance', cls: 'cat-recon' };
    if (/memory|mmap|mprotect/i.test(lower)) return { cat: 'Memory Manipulation', cls: 'cat-inject' };
    if (/sandbox|chroot/i.test(lower)) return { cat: 'Sandbox Escape', cls: 'cat-antidebug' };
    if (/process|fork|clone|spawn/i.test(lower)) return { cat: 'Process Control', cls: 'cat-exec' };
    if (/dup2|descriptor/i.test(lower)) return { cat: 'FD Manipulation', cls: 'cat-exec' };
    if (/system.*info|sysctl/i.test(lower)) return { cat: 'Discovery', cls: 'cat-recon' };
    return { cat: 'Suspicious', cls: 'cat-inject' };
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Overlay start — max(seg.fileoff + seg.filesize) across LC_SEGMENT[_64]
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Compute the first byte offset past the declared end-of-image for a
   * parsed Mach-O. For thin binaries this is `max(seg.fileoff +
   * seg.filesize)` across all LC_SEGMENT / LC_SEGMENT_64 load commands.
   * Also bounds against the code-signature tail (LC_CODE_SIGNATURE's
   * dataoff + datasize) — on macOS the code signature is an inline
   * load command, not an overlay, but it sits past the segment payload
   * and anything after it is genuinely trailing bytes.
   *
   * Returns 0 when the binary has no segments (object files, dSYMs).
   * Callers bound this against the slice's declared size (Fat) or
   * `bytes.length` (thin).
   */
  _computeOverlayStart(mo) {
    if (!mo || !Array.isArray(mo.segments)) return 0;
    let end = 0;
    for (const seg of mo.segments) {
      if (!seg || !seg.filesize) continue;
      const e = (seg.fileoff + seg.filesize);
      if (e > end) end = e;
    }
    // Code signature sits past segment data on signed binaries.
    if (mo.codeSignature && mo.codeSignature.datasize) {
      const e = mo.codeSignature.dataoff + mo.codeSignature.datasize;
      if (e > end) end = e;
    }
    return end;
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Table builder
  // ═══════════════════════════════════════════════════════════════════════

  _buildTable(headers, rows, rowCallback, allowHtml) {
    const tbl = document.createElement('table');
    tbl.className = 'macho-table';
    const thead = document.createElement('thead');
    const hr = document.createElement('tr');
    for (const h of headers) {
      const th = document.createElement('th');
      th.textContent = h;
      hr.appendChild(th);
    }
    thead.appendChild(hr);
    tbl.appendChild(thead);

    const tbody = document.createElement('tbody');
    rows.forEach((cols, i) => {
      const tr = document.createElement('tr');
      for (const c of cols) {
        const td = document.createElement('td');
        if (allowHtml && typeof c === 'string' && c.includes('<')) {
          td.innerHTML = c;
        } else {
          td.textContent = c;
        }
        tr.appendChild(td);
      }
      if (rowCallback) rowCallback(tr, i);
      tbody.appendChild(tr);
    });
    tbl.appendChild(tbody);
    return tbl;
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Security analysis — returns standard findings object
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
      machoInfo: null,
    };

    try {
      // Check for Fat/Universal binary
      const fat = this._parseFatHeader(bytes);
      let mo;

      if (fat) {
        if (fat.arches.length > 0) {
          const preferred = fat.arches.find(a =>
            a.cputype === 0x01000007 || a.cputype === 0x0100000C
          ) || fat.arches[0];
          mo = this._parse(bytes, preferred.offset);
        } else {
          throw new Error('Fat binary has no architecture slices');
        }
        findings.metadata['Universal Binary'] = `${fat.nfat} architectures`;
      } else {
        mo = this._parse(bytes, 0);
      }

      findings.machoInfo = mo;

      const issues = [];
      let riskScore = 0;

      // ── File type context ──────────────────────────────────────────
      findings.metadata = {
        ...findings.metadata,
        'Type': mo.filetypeDesc,
        'Class': mo.magicStr,
        'CPU': `${mo.cputypeStr} (${mo.cpusubtypeStr})`,
        'Segments': mo.segments.length.toString(),
        'Sections': mo.sections.length.toString(),
        'Load Commands': mo.loadCommands.length.toString(),
      };

      if (mo.uuid) findings.metadata['UUID'] = mo.uuid;
      if (mo.dylinker) findings.metadata['Dynamic Linker'] = mo.dylinker;
      if (mo.entryPoint !== null) findings.metadata['Entry Point'] = this._hex(mo.entryPoint, this._is64 ? 16 : 8);
      if (mo.dylibs.length > 0) findings.metadata['Dynamic Libraries'] = mo.dylibs.length.toString();
      if (mo.buildVersion) findings.metadata['Platform'] = `${mo.buildVersion.platform} ${mo.buildVersion.minos}`;
      else if (mo.minVersion) findings.metadata['Platform'] = `${mo.minVersion.platform} ${mo.minVersion.version}`;
      if (mo.idDylib) findings.metadata['Library ID'] = mo.idDylib;
      if (mo.sourceVersion) findings.metadata['Source Version'] = mo.sourceVersion;

      // ── SymHash (Mach-O symbol-import hash) ────────────────────────
      // Anchalysis / symhash-style cross-sample pivot: MD5 of the
      // sorted, de-duplicated list of imported (UNDEF + external)
      // symbol names combined with their source dylib basenames.
      try {
        const importedSymNames = mo.symbols
          .filter(s => s.name && s.typeField === 0 && s.isExternal)
          .map(s => s.name);
        const dylibBasenames = (mo.dylibs || []).map(d =>
          typeof d === 'string' ? d : (d && d.name) || ''
        );
        if (typeof computeSymHash === 'function') {
          const sh = computeSymHash(importedSymNames, dylibBasenames);
          if (sh) findings.metadata['SymHash'] = sh;
        }
      } catch (_) { /* hash computation is best-effort */ }


      // ── Extract embedded Info.plist for Bundle ID ──────────────────
      try {
        const plistSec = mo.sections.find(s => s.sectname === '__info_plist' && s.size > 0 && s.offset > 0);
        if (plistSec && plistSec.offset + plistSec.size <= bytes.length) {
          const plistData = new TextDecoder('utf-8', { fatal: false }).decode(
            bytes.subarray(plistSec.offset, plistSec.offset + Math.min(plistSec.size, 65536))
          );
          // Extract CFBundleIdentifier from XML plist
          const idMatch = plistData.match(/<key>CFBundleIdentifier<\/key>\s*<string>([^<]+)<\/string>/);
          if (idMatch) findings.metadata['Bundle ID'] = idMatch[1];
          // Extract CFBundleName
          const nameMatch = plistData.match(/<key>CFBundleName<\/key>\s*<string>([^<]+)<\/string>/);
          if (nameMatch) findings.metadata['Bundle Name'] = nameMatch[1];
          // Extract CFBundleExecutable
          const execMatch = plistData.match(/<key>CFBundleExecutable<\/key>\s*<string>([^<]+)<\/string>/);
          if (execMatch) findings.metadata['Bundle Executable'] = execMatch[1];
          // Extract CFBundleVersion
          const verMatch = plistData.match(/<key>CFBundleVersion<\/key>\s*<string>([^<]+)<\/string>/);
          if (verMatch) findings.metadata['Bundle Version'] = verMatch[1];
        }
      } catch (_) { /* plist parsing is best-effort */ }

      // ── Security feature checks ────────────────────────────────────
      if (!mo.security.pie && mo.filetype === 2) { // MH_EXECUTE
        issues.push('Not PIE — fixed load address, limited ASLR effectiveness');
        riskScore += 1;
      }

      if (!mo.security.stackCanary) {
        issues.push('No stack canary — vulnerable to stack buffer overflows');
        riskScore += 1;
      }

      if (!mo.security.nxStack) {
        issues.push('Stack execution allowed — shellcode can run from stack');
        riskScore += 1.5;
      }

      if (!mo.security.nxHeap && mo.filetype === 2) {
        issues.push('Heap execution not restricted — code can execute from heap');
        riskScore += 0.5;
      }

      if (!mo.security.signed) {
        issues.push('No code signature — unsigned binary');
        riskScore += 1;
      }

      if (!mo.security.hardenedRuntime && mo.filetype === 2) {
        issues.push('Hardened runtime not enabled — allows debugging, DYLD injection, and unsigned library loading');
        riskScore += 0.5;
      }

      if (mo.security.encrypted) {
        issues.push('Binary has encrypted segments — may be packed or protected');
        riskScore += 2;
      }

      // ── RPATH analysis ─────────────────────────────────────────────
      for (const rp of mo.security.rpaths) {
        if (rp.includes('@loader_path') || rp.includes('@executable_path')) {
          issues.push(`RPATH "${rp}" — relative path could enable dylib hijacking`);
          riskScore += 0.5;
        } else {
          issues.push(`RPATH "${rp}" — custom library search path`);
          riskScore += 0.3;
        }
      }

      // ── Section anomalies ──────────────────────────────────────────
      for (const sec of mo.sections) {
        if (sec.entropy > 7.0 && sec.size > 1024) {
          issues.push(`Section "${sec.sectname}" (${sec.segname}) has very high entropy (${sec.entropy.toFixed(3)}) — likely packed or encrypted`);
          riskScore += 1.5;
        }
      }

      // ── Segment anomalies ──────────────────────────────────────────
      for (const seg of mo.segments) {
        if ((seg.initprot & 2) && (seg.initprot & 4)) { // W+X
          issues.push(`Segment "${seg.segname}" has W+X permissions — unusual, potential code injection region`);
          riskScore += 2;
        }
      }

      // ── Suspicious symbol analysis ─────────────────────────────────
      const suspMap = MachoRenderer.SUSPICIOUS_SYMBOLS;
      const allSymNames = mo.symbols.map(s => {
        const display = s.name.startsWith('_') ? s.name.substring(1) : s.name;
        return { sym: s, lookup: suspMap[s.name] ? s.name : (suspMap[display] ? display : null) };
      }).filter(x => x.lookup);

      const suspiciousImports = allSymNames.filter(x =>
        x.sym.typeField === 0 && x.sym.isExternal
      );

      if (suspiciousImports.length > 0) {
        riskScore += Math.min(suspiciousImports.length * 0.3, 4);

        const hasExec = suspiciousImports.some(x =>
          /execution|command|launch/i.test(suspMap[x.lookup]));
        const hasInjection = suspiciousImports.some(x =>
          /injection|another.*process|task_for_pid|mach_vm/i.test(suspMap[x.lookup]));
        const hasNetwork = suspiciousImports.some(x =>
          /network|socket|C2|exfiltration|backdoor/i.test(suspMap[x.lookup]));
        const hasPrivesc = suspiciousImports.some(x =>
          /privilege|AuthorizationExecute/i.test(suspMap[x.lookup]));
        const hasAntiDebug = suspiciousImports.some(x =>
          /debug|deny_attach|prevent/i.test(suspMap[x.lookup]));
        const hasKeychain = suspiciousImports.some(x =>
          /keychain|credential|password/i.test(suspMap[x.lookup]));
        const hasFileless = suspiciousImports.some(x =>
          /fileless|NSCreateObject|memory.*load/i.test(suspMap[x.lookup]));
        const hasSurveillance = suspiciousImports.some(x =>
          /screen.*capture|keylog|event.*tap|window.*capture/i.test(suspMap[x.lookup]));
        const hasPersistence = suspiciousImports.some(x =>
          /login.*item|persistence/i.test(suspMap[x.lookup]));

        if (hasExec) { issues.push('Imports command execution functions (execve/system/popen)'); riskScore += 1; }
        if (hasInjection) { issues.push('Imports process memory manipulation APIs (task_for_pid/mach_vm_write)'); riskScore += 2; }
        if (hasNetwork) { issues.push('Imports network socket APIs — potential C2/backdoor capability'); riskScore += 1; }
        if (hasPrivesc) { issues.push('Imports privilege escalation functions (AuthorizationExecuteWithPrivileges)'); riskScore += 2; }
        if (hasAntiDebug) { issues.push('Imports anti-debugging function (ptrace/PT_DENY_ATTACH)'); riskScore += 1; }
        if (hasKeychain) { issues.push('Imports Keychain access APIs — potential credential theft (Atomic Stealer pattern)'); riskScore += 2.5; }
        if (hasFileless) { issues.push('Imports fileless execution functions (NSCreateObjectFileImageFromMemory)'); riskScore += 2; }
        if (hasSurveillance) { issues.push('Imports screen capture/keylogging APIs — surveillance capability'); riskScore += 2; }
        if (hasPersistence) { issues.push('Imports login item/persistence APIs'); riskScore += 1.5; }

        // Check for reverse shell pattern: socket + dup2 + exec
        const hasSocket = suspiciousImports.some(x => x.lookup === 'socket');
        const hasDup2 = suspiciousImports.some(x => x.lookup === 'dup2');
        const hasExecve = suspiciousImports.some(x =>
          x.lookup === 'execve' || x.lookup === 'execvp' || x.lookup === 'execl');
        if (hasSocket && hasDup2 && hasExecve) {
          issues.push('Reverse shell pattern detected: socket + dup2 + exec combination');
          riskScore += 3;
        }
      }

      // ── Entitlements analysis ──────────────────────────────────────
      if (mo.codeSignatureInfo && mo.codeSignatureInfo.entitlements) {
        const ent = mo.codeSignatureInfo.entitlements;
        if (ent.includes('com.apple.security.cs.disable-library-validation')) {
          issues.push('Entitlement: disable-library-validation — allows loading unsigned dylibs');
          riskScore += 1.5;
        }
        if (ent.includes('com.apple.security.get-task-allow')) {
          issues.push('Entitlement: get-task-allow — allows debugging (development build or malware evasion)');
          riskScore += 0.5;
        }
        if (ent.includes('com.apple.security.cs.allow-unsigned-executable-memory')) {
          issues.push('Entitlement: allow-unsigned-executable-memory — can create unsigned executable memory');
          riskScore += 1;
        }
        if (ent.includes('com.apple.security.cs.disable-executable-page-protection')) {
          issues.push('Entitlement: disable-executable-page-protection — weakens memory protections');
          riskScore += 1.5;
        }
      }

      // ── Stripped binary check ──────────────────────────────────────
      const hasLocalSyms = mo.symbols.some(s => !s.isExternal && s.typeField === 7);
      if (!hasLocalSyms && mo.symbols.length > 0) {
        findings.metadata['Stripped'] = 'Yes (no local symbols)';
      } else if (mo.symbols.length === 0) {
        findings.metadata['Stripped'] = 'Yes (no symbol table)';
        issues.push('Stripped binary — no symbols, harder to analyze');
        riskScore += 0.5;
      } else {
        findings.metadata['Stripped'] = 'No';
      }

      // ── Extract IOCs from strings ──────────────────────────────────
      // IOCs come from the synthetic joined string buffer, not file
      // bytes — carry only _highlightText for sidebar text-search
      // click-to-focus. Truncation markers surface as IOC.INFO so the
      // Summary/Share view sees the cap.
      const allStrings = mo.strings.join('\n');
      const _urlRx = /https?:\/\/[^\s"'<>()\[\]{}\u0000-\u001F]{6,}/g;
      const _uncRx = /\\\\[\w.\-]{2,}(?:\\[\w.\-]+)+/g;
      const URL_CAP = 100, UNC_CAP = 40;
      // DER SEQUENCE tag (0x30 = ASCII '0') and following length/tag bytes
      // frequently fuse onto URLs extracted from binary string dumps.
      const _derJunkRx = /([^0-9])0[\d]{0,2}[^a-zA-Z0-9]{0,3}$/;
      const urlMatches = [...new Set(
        [...allStrings.matchAll(_urlRx)].map(m => m[0].replace(_derJunkRx, '$1')),
      )];
      for (const url of urlMatches.slice(0, URL_CAP)) {
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

      // ── Categorised strings (PDB paths, build-host paths, …) ──────
      // Mutex / named-pipe / registry patterns are Windows-only and will
      // be no-ops on Mach-O, but PDB-path and POSIX user-home path
      // extraction still fire: cross-compiled or dual-target tooling
      // frequently leaks `/Users/<builder>/…` and `.pdb`-style debug
      // paths even in ARM64 Mach-O output. Emit with the same IOC.*
      // types so the sidebar groups them with PE / ELF hits.
      try {
        if (typeof BinaryStrings !== 'undefined' && BinaryStrings.emit) {
          const strCounts = BinaryStrings.emit(findings, allStrings);
          if (strCounts.pdbPaths)   findings.metadata['PDB Paths (str)']   = String(strCounts.pdbPaths);
          if (strCounts.userPaths)  findings.metadata['Build-host Paths']  = String(strCounts.userPaths);
          if (strCounts.rustPanics) findings.metadata['Rust Panic Paths']  = String(strCounts.rustPanics);
        }
      } catch (_) { /* classification is best-effort */ }

      // ── Export-anomaly flags (side-loading + re-export proxying) ────
      // Mach-O has no ordinal notion, but LC_REEXPORT_DYLIB (cmd 0x1F)
      // is the direct analogue of a PE forwarder — a dylib that re-
      // exports every symbol from another dylib, optionally running its
      // own __attribute__((constructor)) init functions on load. Classic
      // dylib-proxy side-loading technique. The side-loading filename
      // check is gated on MH_DYLIB (filetype 6) so we don't warn about
      // an EXE accidentally named version.dll.
      try {
        if (typeof BinaryExports !== 'undefined' && BinaryExports.emit) {
          const exportNames = (mo.symbols || [])
            .filter(s => s.name && s.typeField === 7 && (s.isExternal || s.isPrivateExternal))
            .map(s => s.name);
          const reexports = (mo.dylibs || [])
            .filter(d => d && d.type === 'reexport' && d.name)
            .map(d => d.name);
          const expCounts = BinaryExports.emit(findings, {
            isLib: mo.filetype === 6,
            fileName: fileName || '',
            exportNames,
            forwardedExports: reexports,
            ordinalOnlyCount: 0,
          });
          if (expCounts.sideLoadHit)    { findings.metadata['DLL Side-Load Host'] = 'Yes'; riskScore += 2; }
          if (expCounts.forwarderCount) { findings.metadata['Re-exported Dylibs'] = String(expCounts.forwarderCount); riskScore += Math.min(expCounts.forwarderCount * 0.5, 2); }
        }
      } catch (_) { /* export-anomaly analysis is best-effort */ }

      // ── Mirror dylibs + RPATHs as individual IOCs ──────────────────
      // `mirrorMetadataIOCs` can't see these because the metadata row only
      // stores a count ("Dynamic Libraries" = "5"); emit directly instead.
      if (mo.dylibs && mo.dylibs.length) {
        const DYLIB_CAP = 80;
        for (const dl of mo.dylibs.slice(0, DYLIB_CAP)) {
          const name = (typeof dl === 'string') ? dl : (dl && dl.name ? dl.name : null);
          if (!name) continue;
          pushIOC(findings, {
            type: IOC.FILE_PATH, value: name, severity: 'info',
            highlightText: name, note: 'Linked dylib',
          });
        }
        if (mo.dylibs.length > DYLIB_CAP) {
          pushIOC(findings, {
            type: IOC.INFO,
            value: `Dylib extraction truncated at ${DYLIB_CAP} — binary links ${mo.dylibs.length} libraries`,
            severity: 'info',
          });
        }
      }
      if (mo.security && mo.security.rpaths && mo.security.rpaths.length) {
        for (const rp of mo.security.rpaths.slice(0, 20)) {
          pushIOC(findings, {
            type: IOC.FILE_PATH, value: rp, severity: 'info',
            highlightText: rp, note: 'RPATH',
          });
        }
      }

      // ── Overlay detection (appended payload past end-of-image) ─────
      // Thin: max(seg.fileoff + seg.filesize), also bounded by
      // LC_CODE_SIGNATURE extent. Fat: we analyse the parsed slice's
      // overlay (between its payload and its declared (offset,size))
      // and separately the Fat container's trailing bytes past the
      // last slice. No Authenticode exemption: the Mach-O code
      // signature sits at LC_CODE_SIGNATURE's declared range and is
      // already absorbed by _computeOverlayStart.
      try {
        if (typeof BinaryOverlay !== 'undefined') {
          let overlayStart = this._computeOverlayStart(mo);
          let overlayEnd = bytes.length;
          let overlayContext = 'past end-of-image';

          if (fat) {
            const preferred = fat.arches.find(a =>
              a.cputype === 0x01000007 || a.cputype === 0x0100000C
            ) || fat.arches[0];
            const sliceEnd = preferred.offset + preferred.size;
            overlayEnd = Math.min(sliceEnd, bytes.length);
            overlayContext = `past slice end (${preferred.cputypeStr})`;

            // Fat-container tail — bytes past the last slice end. If
            // present, this is the interesting overlay (outer wrapper
            // tampering); escalate separately so the risk calibrates.
            let lastSliceEnd = 0;
            for (const a of fat.arches) {
              const e = a.offset + a.size;
              if (e > lastSliceEnd) lastSliceEnd = e;
            }
            if (lastSliceEnd > 0 && lastSliceEnd < bytes.length) {
              const tailBytes = bytes.subarray(lastSliceEnd, bytes.length);
              const tailSize = tailBytes.length;
              const tailPct = (tailSize / Math.max(1, bytes.length)) * 100;
              const tailEntropy = BinaryOverlay.shannonEntropy(tailBytes);
              const tailMagic = BinaryOverlay.sniffMagic(tailBytes.subarray(0, 32));
              findings.metadata['Fat Tail Size'] = tailSize.toLocaleString() + ' bytes';
              findings.metadata['Fat Tail Entropy'] = tailEntropy.toFixed(3);
              if (tailMagic) findings.metadata['Fat Tail Magic'] = tailMagic.label;
              issues.push(`Fat/Universal container has ${tailSize.toLocaleString()} B trailing bytes past the last slice — atypical for a normal Fat binary`);
              riskScore += 1.5;
              pushIOC(findings, {
                type: IOC.PATTERN,
                value: `Fat container trailing bytes [T1027]`,
                severity: 'high',
                note: `${tailSize.toLocaleString()} B past last slice (${tailPct.toFixed(1)}% of file), entropy ${tailEntropy.toFixed(2)}${tailMagic ? `, magic ${tailMagic.label}` : ''}`,
                _noDomainSibling: true,
              });
              // PLAN D2: notify App of late metadata write so the sidebar
              // re-renders once the async digest settles. Direct mutation
              // is preserved so any synchronous downstream consumer of
              // `findings.metadata` in the rest of `analyzeForSecurity`
              // still sees the value; `updateFindings` just makes the
              // existing snapshot-based sidebar refresh aware of it.
              BinaryOverlay.sha256Hex(tailBytes).then(hex => {
                if (!hex) return;
                findings.metadata['Fat Tail SHA-256'] = hex;
                if (typeof window !== 'undefined' && window.app
                    && typeof window.app.updateFindings === 'function') {
                  window.app.updateFindings({
                    metadata: { 'Fat Tail SHA-256': hex },
                  });
                }
              });
            }
          }

          if (overlayStart > 0 && overlayStart < overlayEnd) {
            const overlayBytes = bytes.subarray(overlayStart, overlayEnd);
            const overlaySize = overlayBytes.length;
            const overlayPct = (overlaySize / Math.max(1, overlayEnd)) * 100;
            const overlayEntropy = BinaryOverlay.shannonEntropy(overlayBytes);
            const overlayMagic = BinaryOverlay.sniffMagic(overlayBytes.subarray(0, 32));

            findings.metadata['Overlay Size'] = overlaySize.toLocaleString() + ' bytes';
            findings.metadata['Overlay Entropy'] = overlayEntropy.toFixed(3);
            if (overlayMagic) findings.metadata['Overlay Magic'] = overlayMagic.label;

            const large = overlayPct > 10;
            const highEntropy = overlayEntropy > 7.2;
            const unrecognised = !overlayMagic;
            if (large && highEntropy && unrecognised) {
              issues.push(`Large high-entropy overlay (${overlaySize.toLocaleString()} B, ${overlayPct.toFixed(1)}% ${overlayContext}, entropy ${overlayEntropy.toFixed(2)}) with no recognised container magic — likely packed / encrypted payload`);
              riskScore += 2;
              pushIOC(findings, {
                type: IOC.PATTERN,
                value: `High-entropy overlay [T1027.002]`,
                severity: 'high',
                note: `Appended payload: ${overlaySize.toLocaleString()} B (${overlayPct.toFixed(1)}%) ${overlayContext}, entropy ${overlayEntropy.toFixed(2)}, no recognised magic`,
                _noDomainSibling: true,
              });
            } else if (overlayMagic) {
              findings.metadata['Overlay Type'] = `Appended ${overlayMagic.label}`;
            }

            // PLAN D2: see Fat Tail SHA-256 site above for rationale.
            BinaryOverlay.sha256Hex(overlayBytes).then(hex => {
              if (!hex) return;
              findings.metadata['Overlay SHA-256'] = hex;
              if (typeof window !== 'undefined' && window.app
                  && typeof window.app.updateFindings === 'function') {
                window.app.updateFindings({
                  metadata: { 'Overlay SHA-256': hex },
                });
              }
            });
          }
        }
      } catch (_) { /* overlay analysis is best-effort */ }

      // ── Mirror classic-pivot metadata into IOC table ───────────────
      // Option-B pivots: UUID/Bundle ID/Source Version are all stable
      // cross-sample pivots. Bundle Name/Bundle Version stay metadata-
      // only (attribution fluff).
      mirrorMetadataIOCs(findings, {
        'UUID':              IOC.GUID,
        'Bundle ID':         IOC.PATTERN,
        'Bundle Executable': IOC.FILE_PATH,
        'Dynamic Linker':    IOC.FILE_PATH,
        'Library ID':        IOC.FILE_PATH,
        'Source Version':    IOC.PATTERN,
        'SymHash':           IOC.HASH,
        'Overlay SHA-256':   IOC.HASH,
        'Fat Tail SHA-256':  IOC.HASH,
      });

      // ── Capability tagging (capa-lite) ─────────────────────────────
      // Cross-platform behaviour-tagging: feed imported symbol names
      // (with leading underscore stripped — Mach-O convention), linked
      // dylib basenames, and the string corpus into the shared
      // Capabilities engine. Each hit becomes an IOC.PATTERN + issue
      // and contributes a severity-weighted bump to riskScore.
      try {
        if (typeof Capabilities !== 'undefined' && Capabilities && typeof Capabilities.detect === 'function') {
          const importTokens = mo.symbols
            .filter(s => s.name && s.typeField === 0 && s.isExternal)
            .map(s => s.name.startsWith('_') ? s.name.substring(1) : s.name);
          const dylibTokens = (mo.dylibs || []).map(d =>
            typeof d === 'string' ? d : (d && d.name) || ''
          ).filter(Boolean);
          const caps = Capabilities.detect({
            imports: importTokens,
            dylibs:  dylibTokens,
            strings: mo.strings || [],
          }) || [];
          if (caps.length) {
            findings.capabilities = caps;
            const sevWeight = { critical: 3, high: 2, medium: 1, low: 0.5 };
            for (const cap of caps) {
              pushIOC(findings, {
                type: IOC.PATTERN,
                value: `[capability] ${cap.name}` + (cap.mitre ? ` (${cap.mitre})` : ''),
                severity: cap.severity || 'info',
                note: cap.description || '',
                _noDomainSibling: true,
              });
              issues.push(`Capability — ${cap.name}` + (cap.mitre ? ` [${cap.mitre}]` : ''));
              riskScore += sevWeight[cap.severity] || 0;
            }
          }
        }
      } catch (_) { /* capability detection is best-effort */ }

      // ── Risk assessment ────────────────────────────────────────────
      findings.autoExec = issues;
      if (riskScore >= 8) escalateRisk(findings, 'critical');
      else if (riskScore >= 5) escalateRisk(findings, 'high');
      else if (riskScore >= 2) escalateRisk(findings, 'medium');
      else escalateRisk(findings, 'low');


    } catch (e) {
      escalateRisk(findings, 'medium');
      findings.autoExec = ['Mach-O parsing partially failed: ' + e.message];
    }

    // Stash the completed findings on the instance so render() — which
    // runs immediately after analyzeForSecurity on the shared _loadFile
    // path — can feed them into the Tier-A Triage Band without a second
    // pass over the buffer. Paralleled in pe-renderer.js / elf-renderer.js.
    this._findings = findings;
    return findings;
  }
}
