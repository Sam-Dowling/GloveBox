// ════════════════════════════════════════════════════════════════
// elf-renderer.js — Linux ELF (ELF32/ELF64) binary parser + analysis view
// Supports: executables, shared objects, relocatable objects, core dumps
// Handles both little-endian and big-endian, 32-bit and 64-bit
// ════════════════════════════════════════════════════════════════

class ElfRenderer {

  // ── Static constant maps ───────────────────────────────────────

  // ELF OS/ABI values
  static OSABI = {
    0: 'UNIX System V', 1: 'HP-UX', 2: 'NetBSD', 3: 'Linux',
    6: 'Solaris', 7: 'AIX', 8: 'IRIX', 9: 'FreeBSD',
    10: 'Tru64', 11: 'Novell Modesto', 12: 'OpenBSD',
    64: 'ARM EABI', 97: 'ARM', 255: 'Standalone',
  };

  // ELF type
  static TYPE = {
    0: 'NONE', 1: 'REL (Relocatable)', 2: 'EXEC (Executable)',
    3: 'DYN (Shared Object)', 4: 'CORE (Core Dump)',
  };

  // Machine architecture
  static MACHINE = {
    0: 'None', 2: 'SPARC', 3: 'x86 (i386)', 6: 'Motorola 68000',
    7: 'Motorola 88000', 8: 'Intel MCU', 9: 'Intel 80860',
    10: 'MIPS', 15: 'HP PA-RISC', 20: 'PowerPC', 21: 'PowerPC64',
    22: 'S390', 40: 'ARM', 42: 'SuperH', 43: 'SPARC V9',
    50: 'IA-64', 62: 'x86-64 (AMD64)', 183: 'AArch64 (ARM64)',
    243: 'RISC-V', 247: 'eBPF',
  };

  // Program header types
  static PT_TYPE = {
    0: 'NULL', 1: 'LOAD', 2: 'DYNAMIC', 3: 'INTERP', 4: 'NOTE',
    5: 'SHLIB', 6: 'PHDR', 7: 'TLS',
    0x6474E550: 'GNU_EH_FRAME', 0x6474E551: 'GNU_STACK',
    0x6474E552: 'GNU_RELRO', 0x6474E553: 'GNU_PROPERTY',
    0x70000001: 'PROC_SPECIFIC',
  };

  // Section header types
  static SHT_TYPE = {
    0: 'NULL', 1: 'PROGBITS', 2: 'SYMTAB', 3: 'STRTAB', 4: 'RELA',
    5: 'HASH', 6: 'DYNAMIC', 7: 'NOTE', 8: 'NOBITS', 9: 'REL',
    10: 'SHLIB', 11: 'DYNSYM', 14: 'INIT_ARRAY', 15: 'FINI_ARRAY',
    16: 'PREINIT_ARRAY', 17: 'GROUP', 18: 'SYMTAB_SHNDX',
    0x6FFFFFF6: 'GNU_HASH', 0x6FFFFFFD: 'VERDEF',
    0x6FFFFFFE: 'VERNEED', 0x6FFFFFFF: 'VERSYM',
  };

  // Section flags
  static SHF = {
    0x1: 'WRITE', 0x2: 'ALLOC', 0x4: 'EXECINSTR',
    0x10: 'MERGE', 0x20: 'STRINGS', 0x40: 'INFO_LINK',
    0x80: 'LINK_ORDER', 0x100: 'OS_NONCONFORMING',
    0x200: 'GROUP', 0x400: 'TLS',
  };

  // Dynamic tag types
  static DT_TAG = {
    0: 'NULL', 1: 'NEEDED', 2: 'PLTRELSZ', 3: 'PLTGOT',
    4: 'HASH', 5: 'STRTAB', 6: 'SYMTAB', 7: 'RELA',
    8: 'RELASZ', 9: 'RELAENT', 10: 'STRSZ', 11: 'SYMENT',
    12: 'INIT', 13: 'FINI', 14: 'SONAME', 15: 'RPATH',
    16: 'SYMBOLIC', 17: 'REL', 18: 'RELSZ', 19: 'RELENT',
    20: 'PLTREL', 21: 'DEBUG', 22: 'TEXTREL', 23: 'JMPREL',
    24: 'BIND_NOW', 25: 'INIT_ARRAY', 26: 'FINI_ARRAY',
    27: 'INIT_ARRAYSZ', 28: 'FINI_ARRAYSZ', 29: 'RUNPATH',
    30: 'FLAGS', 32: 'PREINIT_ARRAY',
    0x6FFFFFFB: 'FLAGS_1', 0x6FFFFFFE: 'VERNEED',
    0x6FFFFFFF: 'VERNEEDNUM', 0x6FFFFFF0: 'VERSYM',
    0x6FFFFFFA: 'RELCOUNT', 0x6FFFFFF9: 'RELACOUNT',
    0x6FFFFFF5: 'GNU_HASH',
  };

  // Symbol binding
  static STB = { 0: 'LOCAL', 1: 'GLOBAL', 2: 'WEAK', 10: 'LOOS', 13: 'HIOS' };

  // Symbol type
  static STT = {
    0: 'NOTYPE', 1: 'OBJECT', 2: 'FUNC', 3: 'SECTION',
    4: 'FILE', 5: 'COMMON', 6: 'TLS', 10: 'LOOS',
  };

  // Symbol visibility
  static STV = { 0: 'DEFAULT', 1: 'INTERNAL', 2: 'HIDDEN', 3: 'PROTECTED' };

  // ── Detailed symbol info (description, context, MITRE ATT&CK) ─────────
  static SUSPICIOUS_SYMBOLS_DETAIL = {
    ptrace: {
      desc: 'Traces or controls another process — can read/write memory and registers.',
      context: 'Used for anti-debugging: a process calls ptrace on itself to prevent debuggers from attaching.',
      mitre: 'T1622 — Debugger Evasion',
    },
    dlopen: {
      desc: 'Opens a shared library and returns a handle for dlsym lookups.',
      context: 'Runtime loading of libraries enables plugin-based malware or evasion of static analysis.',
      mitre: 'T1129 — Shared Modules',
    },
    dlsym: {
      desc: 'Resolves a symbol (function/variable) from a dynamically loaded library.',
      context: 'Combined with dlopen, allows API-hiding by resolving functions at runtime instead of via the symbol table.',
      mitre: 'T1106 — Native API',
    },
    execve: {
      desc: 'Replaces the current process image with a new program.',
      context: 'Core execution primitive in Linux. Combined with socket+dup2, forms a reverse shell.',
      mitre: 'T1059 — Command and Scripting Interpreter',
    },
    execvp: {
      desc: 'Searches PATH and executes a program, replacing the current process.',
      context: 'Convenient execution primitive often used to launch shell commands.',
      mitre: 'T1059 — Command and Scripting Interpreter',
    },
    system: {
      desc: 'Executes a shell command string via /bin/sh -c.',
      context: 'Simplest command execution — frequently used by malware for downloading payloads or running exploits.',
      mitre: 'T1059.004 — Unix Shell',
    },
    popen: {
      desc: 'Executes a shell command and returns a pipe for reading/writing.',
      context: 'Enables command execution with output capture — used for reconnaissance or data exfiltration.',
      mitre: 'T1059.004 — Unix Shell',
    },
    fork: {
      desc: 'Creates a child process that is a copy of the parent.',
      context: 'Used to daemonize malware, create persistent backdoors, or fork-bomb a system.',
      mitre: 'T1106 — Native API',
    },
    socket: {
      desc: 'Creates a network communication endpoint (TCP, UDP, raw).',
      context: 'Foundation for all network communication — C2 channels, data exfiltration, and reverse shells.',
      mitre: 'T1071 — Application Layer Protocol',
    },
    connect: {
      desc: 'Initiates a connection on a socket to a remote address.',
      context: 'Outbound connection to C2 server or callback host. Part of the reverse shell triad (socket+connect+dup2+exec).',
      mitre: 'T1071 — Application Layer Protocol',
    },
    bind: {
      desc: 'Assigns a local address/port to a socket.',
      context: 'Creates a network listener — indicator of a bind shell or backdoor accepting remote connections.',
      mitre: 'T1571 — Non-Standard Port',
    },
    listen: {
      desc: 'Marks a socket as a passive listener for incoming connections.',
      context: 'Server-side socket that waits for attacker connections — classic backdoor pattern.',
      mitre: 'T1571 — Non-Standard Port',
    },
    mmap: {
      desc: 'Maps files or anonymous memory into the process address space.',
      context: 'Can create RWX memory regions for in-memory code execution, bypassing file-based detection.',
      mitre: 'T1055.009 — Proc Memory',
    },
    mprotect: {
      desc: 'Changes memory protection flags on mapped pages.',
      context: 'Used to make data pages executable at runtime — enables shellcode execution from heap/stack.',
      mitre: 'T1055.009 — Proc Memory',
    },
    memfd_create: {
      desc: 'Creates an anonymous file in memory backed by RAM, not disk.',
      context: 'Key fileless execution technique — load and execute binaries without touching the filesystem.',
      mitre: 'T1620 — Reflective Code Loading',
    },
    fexecve: {
      desc: 'Executes a program referenced by a file descriptor rather than a path.',
      context: 'Enables fileless execution when combined with memfd_create — runs binaries from memory.',
      mitre: 'T1620 — Reflective Code Loading',
    },
    process_vm_readv: {
      desc: 'Reads memory from another process without ptrace.',
      context: 'Enables credential/secret theft from other process memory or cross-process data harvesting.',
      mitre: 'T1003 — OS Credential Dumping',
    },
    process_vm_writev: {
      desc: 'Writes to another process\'s memory without ptrace.',
      context: 'Code injection into a running process — can modify execution flow or inject shellcode.',
      mitre: 'T1055 — Process Injection',
    },
    init_module: {
      desc: 'Loads a kernel module (LKM) from a memory buffer.',
      context: 'Rootkit installation technique — loads malicious code directly into the kernel.',
      mitre: 'T1547.006 — Kernel Modules and Extensions',
    },
    finit_module: {
      desc: 'Loads a kernel module from a file descriptor.',
      context: 'Modern rootkit installation — loads kernel modules with optional flag control.',
      mitre: 'T1547.006 — Kernel Modules and Extensions',
    },
    setuid: {
      desc: 'Sets the effective user ID of the calling process.',
      context: 'Privilege escalation — used by SUID binaries or exploits to gain root privileges.',
      mitre: 'T1548.001 — Setuid and Setgid',
    },
    setgid: {
      desc: 'Sets the effective group ID of the calling process.',
      context: 'Privilege escalation via group membership changes.',
      mitre: 'T1548.001 — Setuid and Setgid',
    },
    chroot: {
      desc: 'Changes the root directory for the calling process.',
      context: 'Can be used in container/sandbox escape attacks by pivoting the filesystem root.',
      mitre: 'T1611 — Escape to Host',
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
    keyctl: {
      desc: 'Manipulates the kernel keyring (add, read, search keys).',
      context: 'Access to kernel keyring can expose cryptographic keys, certificates, and cached credentials.',
      mitre: 'T1552 — Unsecured Credentials',
    },
    kexec_load: {
      desc: 'Loads a new kernel image for later execution (warm reboot).',
      context: 'Extreme persistence/rootkit technique — replaces the running kernel without a full reboot.',
      mitre: 'T1542 — Pre-OS Boot',
    },
    personality: {
      desc: 'Sets the process execution domain (e.g., Linux, SVR4).',
      context: 'Can disable ASLR for the process (ADDR_NO_RANDOMIZE flag), weakening exploit mitigations.',
      mitre: 'T1497.001 — System Checks',
    },
  };

  // ── Suspicious symbol/function names for ELF binaries ──────────
  static SUSPICIOUS_SYMBOLS = {
    'ptrace': 'Anti-debugging — can detect/prevent debugger attachment',
    'dlopen': 'Dynamic library loading — runtime code injection',
    'dlsym': 'Dynamic symbol resolution — runtime function lookup',
    'execve': 'Process execution — can launch arbitrary commands',
    'execvp': 'Process execution — can launch arbitrary commands',
    'execl': 'Process execution — can launch arbitrary commands',
    'system': 'Shell command execution — arbitrary command execution',
    'popen': 'Shell command execution via pipe',
    'fork': 'Process creation — can spawn child processes',
    'clone': 'Process/thread creation — low-level spawning',
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
    'memfd_create': 'Anonymous file in memory — fileless execution technique',
    'fexecve': 'Execute from file descriptor — fileless execution',
    'process_vm_readv': 'Read another process memory — credential/data theft',
    'process_vm_writev': 'Write another process memory — code injection',
    'keyctl': 'Kernel keyring access — credential access',
    'init_module': 'Kernel module loading — rootkit installation',
    'finit_module': 'Kernel module loading — rootkit installation',
    'delete_module': 'Kernel module removal — rootkit cleanup',
    'mount': 'Filesystem mount — persistence/privilege escalation',
    'umount': 'Filesystem unmount — anti-forensics',
    'chroot': 'Change root — container/sandbox escape',
    'setuid': 'Set user ID — privilege escalation',
    'setgid': 'Set group ID — privilege escalation',
    'setreuid': 'Set real/effective UID — privilege escalation',
    'setregid': 'Set real/effective GID — privilege escalation',
    'capset': 'Set process capabilities — privilege manipulation',
    'prctl': 'Process control — can rename process, set dumpable flag',
    'unlink': 'File deletion — anti-forensics / self-deletion',
    'unlinkat': 'File deletion — anti-forensics / self-deletion',
    'inotify_init': 'File monitoring — surveillance capability',
    'fanotify_init': 'Filesystem monitoring — surveillance capability',
    'kexec_load': 'Load new kernel — extreme persistence/rootkit',
    'dup2': 'File descriptor duplication — used in reverse shells',
    'shmget': 'Shared memory — IPC / covert communication',
    'msgget': 'Message queue — IPC / covert communication',
    'personality': 'Execution domain — can disable ASLR',
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

  // Read address/offset (4 or 8 bytes depending on class)
  _uAddr(b, o) {
    return this._is64 ? this._u64(b, o) : this._u32(b, o);
  }

  // Address size in bytes
  get _addrSize() { return this._is64 ? 8 : 4; }

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

  // ═══════════════════════════════════════════════════════════════════════
  //  String table reader — read null-terminated string from string table
  // ═══════════════════════════════════════════════════════════════════════

  _readStringTable(bytes, strtabOffset, strtabSize, nameIndex) {
    if (nameIndex === 0 || nameIndex >= strtabSize) return '';
    const start = strtabOffset + nameIndex;
    if (start >= bytes.length) return '';
    return this._str(bytes, start, Math.min(256, bytes.length - start));
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Core ELF parser
  // ═══════════════════════════════════════════════════════════════════════

  _parse(bytes) {
    // ── Validate ELF magic ────────────────────────────────────────
    if (bytes.length < 64 ||
        bytes[0] !== 0x7F || bytes[1] !== 0x45 || bytes[2] !== 0x4C || bytes[3] !== 0x46) {
      throw new Error('Not a valid ELF file (bad magic)');
    }

    const elf = {};

    // ── ELF identification ────────────────────────────────────────
    const ei_class = bytes[4]; // 1=32-bit, 2=64-bit
    const ei_data = bytes[5];  // 1=LE, 2=BE
    const ei_version = bytes[6];
    const ei_osabi = bytes[7];
    const ei_abiversion = bytes[8];

    this._is64 = ei_class === 2;
    this._le = ei_data === 1;

    elf.ident = {
      class: ei_class,
      classStr: ei_class === 1 ? 'ELF32' : ei_class === 2 ? 'ELF64' : 'Unknown',
      data: ei_data,
      dataStr: ei_data === 1 ? 'Little Endian' : ei_data === 2 ? 'Big Endian' : 'Unknown',
      version: ei_version,
      osabi: ei_osabi,
      osabiStr: ElfRenderer.OSABI[ei_osabi] || `Unknown (${ei_osabi})`,
      abiVersion: ei_abiversion,
    };

    // ── ELF header fields ─────────────────────────────────────────
    elf.type = this._u16(bytes, 16);
    elf.typeStr = ElfRenderer.TYPE[elf.type] || `Unknown (${elf.type})`;
    elf.machine = this._u16(bytes, 18);
    elf.machineStr = ElfRenderer.MACHINE[elf.machine] || `Unknown (${elf.machine})`;
    elf.version = this._u32(bytes, 20);

    if (this._is64) {
      elf.entry = this._u64(bytes, 24);
      elf.phoff = this._u64(bytes, 32);
      elf.shoff = this._u64(bytes, 40);
      elf.flags = this._u32(bytes, 48);
      elf.ehsize = this._u16(bytes, 52);
      elf.phentsize = this._u16(bytes, 54);
      elf.phnum = this._u16(bytes, 56);
      elf.shentsize = this._u16(bytes, 58);
      elf.shnum = this._u16(bytes, 60);
      elf.shstrndx = this._u16(bytes, 62);
    } else {
      elf.entry = this._u32(bytes, 24);
      elf.phoff = this._u32(bytes, 28);
      elf.shoff = this._u32(bytes, 32);
      elf.flags = this._u32(bytes, 36);
      elf.ehsize = this._u16(bytes, 40);
      elf.phentsize = this._u16(bytes, 42);
      elf.phnum = this._u16(bytes, 44);
      elf.shentsize = this._u16(bytes, 46);
      elf.shnum = this._u16(bytes, 48);
      elf.shstrndx = this._u16(bytes, 50);
    }

    // Determine file sub-type
    elf.isExec = elf.type === 2;
    elf.isDyn = elf.type === 3;
    elf.isRel = elf.type === 1;
    elf.isCore = elf.type === 4;

    // ── Program headers (segments) ────────────────────────────────
    elf.segments = [];
    const maxSegments = Math.min(elf.phnum, 256); // Safety cap
    for (let i = 0; i < maxSegments; i++) {
      const off = elf.phoff + i * elf.phentsize;
      if (off + elf.phentsize > bytes.length) break;

      const seg = {};
      seg.type = this._u32(bytes, off);
      seg.typeStr = ElfRenderer.PT_TYPE[seg.type] || `0x${seg.type.toString(16).toUpperCase()}`;

      if (this._is64) {
        seg.flags = this._u32(bytes, off + 4);
        seg.offset = this._u64(bytes, off + 8);
        seg.vaddr = this._u64(bytes, off + 16);
        seg.paddr = this._u64(bytes, off + 24);
        seg.filesz = this._u64(bytes, off + 32);
        seg.memsz = this._u64(bytes, off + 40);
        seg.align = this._u64(bytes, off + 48);
      } else {
        seg.offset = this._u32(bytes, off + 4);
        seg.vaddr = this._u32(bytes, off + 8);
        seg.paddr = this._u32(bytes, off + 12);
        seg.filesz = this._u32(bytes, off + 16);
        seg.memsz = this._u32(bytes, off + 20);
        seg.flags = this._u32(bytes, off + 24);
        seg.align = this._u32(bytes, off + 28);
      }

      // Decode permission flags
      seg.permR = !!(seg.flags & 4);
      seg.permW = !!(seg.flags & 2);
      seg.permX = !!(seg.flags & 1);
      seg.permStr = (seg.permR ? 'R' : '-') + (seg.permW ? 'W' : '-') + (seg.permX ? 'X' : '-');

      elf.segments.push(seg);
    }

    // ── Section headers ───────────────────────────────────────────
    elf.sections = [];
    const maxSections = Math.min(elf.shnum, 256); // Safety cap

    // First, locate section header string table
    let shstrtabOff = 0, shstrtabSize = 0;
    if (elf.shstrndx < maxSections && elf.shoff > 0) {
      const stOff = elf.shoff + elf.shstrndx * elf.shentsize;
      if (stOff + elf.shentsize <= bytes.length) {
        if (this._is64) {
          shstrtabOff = this._u64(bytes, stOff + 24);
          shstrtabSize = this._u64(bytes, stOff + 32);
        } else {
          shstrtabOff = this._u32(bytes, stOff + 16);
          shstrtabSize = this._u32(bytes, stOff + 20);
        }
      }
    }

    for (let i = 0; i < maxSections; i++) {
      const off = elf.shoff + i * elf.shentsize;
      if (off + elf.shentsize > bytes.length) break;

      const sec = {};
      sec.nameIdx = this._u32(bytes, off);
      sec.type = this._u32(bytes, off + 4);

      if (this._is64) {
        sec.flags = this._u64(bytes, off + 8);
        sec.addr = this._u64(bytes, off + 16);
        sec.offset = this._u64(bytes, off + 24);
        sec.size = this._u64(bytes, off + 32);
        sec.link = this._u32(bytes, off + 40);
        sec.info = this._u32(bytes, off + 44);
        sec.addralign = this._u64(bytes, off + 48);
        sec.entsize = this._u64(bytes, off + 56);
      } else {
        sec.flags = this._u32(bytes, off + 8);
        sec.addr = this._u32(bytes, off + 12);
        sec.offset = this._u32(bytes, off + 16);
        sec.size = this._u32(bytes, off + 20);
        sec.link = this._u32(bytes, off + 24);
        sec.info = this._u32(bytes, off + 28);
        sec.addralign = this._u32(bytes, off + 32);
        sec.entsize = this._u32(bytes, off + 36);
      }

      // Read section name from string table
      sec.name = this._readStringTable(bytes, shstrtabOff, shstrtabSize, sec.nameIdx);
      sec.typeStr = ElfRenderer.SHT_TYPE[sec.type] || `0x${sec.type.toString(16).toUpperCase()}`;

      // Decode section flags
      sec.flagsList = [];
      for (const [bit, name] of Object.entries(ElfRenderer.SHF)) {
        if (sec.flags & Number(bit)) sec.flagsList.push(name);
      }
      sec.flagsStr = sec.flagsList.join(' | ') || 'None';

      sec.isWritable = !!(sec.flags & 0x1);
      sec.isAlloc = !!(sec.flags & 0x2);
      sec.isExec = !!(sec.flags & 0x4);

      // Calculate entropy for allocated sections with file content
      if (sec.size > 0 && sec.type !== 8 /* NOBITS */ && sec.offset + sec.size <= bytes.length) {
        sec.entropy = this._entropy(bytes, sec.offset, Math.min(sec.size, 1048576));
      } else {
        sec.entropy = 0;
      }

      elf.sections.push(sec);
    }

    // ── Interpreter (PT_INTERP) ───────────────────────────────────
    elf.interpreter = '';
    const interpSeg = elf.segments.find(s => s.type === 3); // PT_INTERP
    if (interpSeg && interpSeg.offset + interpSeg.filesz <= bytes.length) {
      elf.interpreter = this._str(bytes, interpSeg.offset, interpSeg.filesz);
    }

    // ── Dynamic section parsing ───────────────────────────────────
    elf.dynamic = [];
    elf.neededLibs = [];
    elf.soname = '';
    elf.rpath = '';
    elf.runpath = '';
    elf.dynamicFlags = 0;
    elf.dynamicFlags1 = 0;

    const dynSeg = elf.segments.find(s => s.type === 2); // PT_DYNAMIC
    if (dynSeg && dynSeg.offset + dynSeg.filesz <= bytes.length) {
      // First find the STRTAB address so we can resolve DT_NEEDED names
      let dynStrtabAddr = 0;
      let dynStrtabSize = 0;
      const entSize = this._is64 ? 16 : 8;
      const maxDynEntries = Math.min(Math.floor(dynSeg.filesz / entSize), 2000);

      // First pass: find STRTAB
      for (let i = 0; i < maxDynEntries; i++) {
        const eoff = dynSeg.offset + i * entSize;
        if (eoff + entSize > bytes.length) break;
        const tag = this._is64 ? this._u64(bytes, eoff) : this._u32(bytes, eoff);
        const val = this._is64 ? this._u64(bytes, eoff + 8) : this._u32(bytes, eoff + 4);
        if (tag === 0) break; // DT_NULL
        if (tag === 5) dynStrtabAddr = val; // DT_STRTAB
        if (tag === 10) dynStrtabSize = val; // DT_STRSZ
      }

      // Resolve strtab address to file offset
      let dynStrtabOff = 0;
      if (dynStrtabAddr > 0) {
        // Find which segment contains the strtab address
        for (const seg of elf.segments) {
          if (seg.type === 1 && dynStrtabAddr >= seg.vaddr && dynStrtabAddr < seg.vaddr + seg.filesz) {
            dynStrtabOff = seg.offset + (dynStrtabAddr - seg.vaddr);
            break;
          }
        }
        // Fallback: try sections
        if (dynStrtabOff === 0) {
          for (const sec of elf.sections) {
            if (sec.name === '.dynstr' && sec.offset > 0) {
              dynStrtabOff = sec.offset;
              dynStrtabSize = sec.size;
              break;
            }
          }
        }
      }

      // Second pass: parse all entries
      for (let i = 0; i < maxDynEntries; i++) {
        const eoff = dynSeg.offset + i * entSize;
        if (eoff + entSize > bytes.length) break;
        const tag = this._is64 ? this._u64(bytes, eoff) : this._u32(bytes, eoff);
        const val = this._is64 ? this._u64(bytes, eoff + 8) : this._u32(bytes, eoff + 4);
        if (tag === 0) break; // DT_NULL

        const tagName = ElfRenderer.DT_TAG[tag] || `0x${tag.toString(16).toUpperCase()}`;
        let valStr = this._hex(val, this._is64 ? 16 : 8);

        // Resolve string values
        if ((tag === 1 || tag === 14 || tag === 15 || tag === 29) && dynStrtabOff > 0) {
          // DT_NEEDED, DT_SONAME, DT_RPATH, DT_RUNPATH
          const name = this._readStringTable(bytes, dynStrtabOff, dynStrtabSize || 0x10000, val);
          if (name) valStr = name;
          if (tag === 1) elf.neededLibs.push(name);
          if (tag === 14) elf.soname = name;
          if (tag === 15) elf.rpath = name;
          if (tag === 29) elf.runpath = name;
        }

        if (tag === 30) elf.dynamicFlags = val;  // DT_FLAGS
        if (tag === 0x6FFFFFFB) elf.dynamicFlags1 = val; // DT_FLAGS_1

        elf.dynamic.push({ tag, tagName, val, valStr });
      }
    }

    // ── Symbol tables ─────────────────────────────────────────────
    elf.dynsyms = [];
    elf.symtab = [];

    this._parseSymbolTable(bytes, elf, '.dynsym', '.dynstr', elf.dynsyms);
    this._parseSymbolTable(bytes, elf, '.symtab', '.strtab', elf.symtab);

    // ── Note sections ─────────────────────────────────────────────
    elf.notes = [];
    for (const seg of elf.segments) {
      if (seg.type !== 4) continue; // PT_NOTE
      this._parseNotes(bytes, seg.offset, seg.filesz, elf.notes);
    }
    // Also check SHT_NOTE sections if no PT_NOTE found
    if (elf.notes.length === 0) {
      for (const sec of elf.sections) {
        if (sec.type !== 7) continue; // SHT_NOTE
        this._parseNotes(bytes, sec.offset, sec.size, elf.notes);
      }
    }

    // ── Security features ─────────────────────────────────────────
    elf.security = this._detectSecurity(elf);

    // ── String extraction ─────────────────────────────────────────
    elf.strings = this._extractStrings(bytes, elf);

    // ── Format heuristics: Go binary ──────────────────────────────
    //   Mirrors PeRenderer._detectFormatHeuristics. Populates flat
    //   fields on `elf` for Summary / YARA consumption. Best-effort —
    //   failures don't abort ELF analysis.
    try { this._detectGoBinary(bytes, elf); }
    catch (_) { /* best-effort */ }

    return elf;
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Go binary detection (shared heuristic with pe-renderer.js)
  // ═══════════════════════════════════════════════════════════════════════

  _detectGoBinary(bytes, elf) {
    elf.isGoBinary = false;
    elf.goBuildInfo = null;

    // Signal 1: "\xff Go buildinf:" magic header, carries version + VCS.
    const magic = new Uint8Array([0xff, 0x20, 0x47, 0x6f, 0x20, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x69, 0x6e, 0x66, 0x3a]);
    const goIdx = this._findBytesInRange(bytes, magic, 0, bytes.length);
    if (goIdx >= 0) {
      elf.isGoBinary = true;
      elf.goBuildInfo = this._parseGoBuildInfo(bytes, goIdx);
      return;
    }

    // Signal 2: section-name fallback. .gopclntab is the runtime function
    // table present in every stripped Go binary; .go.buildinfo appears on
    // newer toolchains. Either alone is high-confidence.
    for (const s of elf.sections) {
      if (s.name === '.gopclntab' || s.name === '.go.buildinfo' ||
          s.name === '.note.go.buildid') {
        elf.isGoBinary = true;
        return;
      }
    }
  }

  // Byte-sequence search constrained to [start, end). Returns index or -1.
  _findBytesInRange(bytes, needle, start, end) {
    const n = needle.length;
    if (n === 0) return -1;
    const stop = Math.min(end, bytes.length) - n;
    const first = needle[0];
    outer: for (let i = start; i <= stop; i++) {
      if (bytes[i] !== first) continue;
      for (let j = 1; j < n; j++) if (bytes[i + j] !== needle[j]) continue outer;
      return i;
    }
    return -1;
  }

  // Same parser as pe-renderer.js — Go build-info is format-agnostic.
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
        const trimmed = mod.replace(/^\x00+|[\x00\xff]+$/g, '');
        info.mod = trimmed;
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
      // Pre-1.18 layout — just grab the version via an ASCII scan.
      const scanEnd = Math.min(off + 4096, bytes.length);
      for (let i = off + 16; i < scanEnd - 4; i++) {
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
  //  Symbol table parser
  // ═══════════════════════════════════════════════════════════════════════

  _parseSymbolTable(bytes, elf, symSecName, strSecName, dest) {
    const symSec = elf.sections.find(s => s.name === symSecName);
    const strSec = elf.sections.find(s => s.name === strSecName);
    if (!symSec || !strSec) return;

    const entSize = this._is64 ? 24 : 16;
    const count = symSec.entsize > 0 ? Math.floor(symSec.size / symSec.entsize) : Math.floor(symSec.size / entSize);
    const maxSyms = Math.min(count, 10000); // Safety cap

    for (let i = 0; i < maxSyms; i++) {
      const off = symSec.offset + i * entSize;
      if (off + entSize > bytes.length) break;

      const sym = {};
      if (this._is64) {
        sym.nameIdx = this._u32(bytes, off);
        sym.info = bytes[off + 4];
        sym.other = bytes[off + 5];
        sym.shndx = this._u16(bytes, off + 6);
        sym.value = this._u64(bytes, off + 8);
        sym.size = this._u64(bytes, off + 16);
      } else {
        sym.nameIdx = this._u32(bytes, off);
        sym.value = this._u32(bytes, off + 4);
        sym.size = this._u32(bytes, off + 8);
        sym.info = bytes[off + 12];
        sym.other = bytes[off + 13];
        sym.shndx = this._u16(bytes, off + 14);
      }

      sym.bind = sym.info >> 4;
      sym.type = sym.info & 0xF;
      sym.visibility = sym.other & 0x3;

      sym.bindStr = ElfRenderer.STB[sym.bind] || `${sym.bind}`;
      sym.typeStr = ElfRenderer.STT[sym.type] || `${sym.type}`;
      sym.visStr = ElfRenderer.STV[sym.visibility] || `${sym.visibility}`;

      // Read name from string table
      sym.name = this._readStringTable(bytes, strSec.offset, strSec.size, sym.nameIdx);

      // Skip empty/null symbols
      if (sym.name || sym.value || sym.type) {
        dest.push(sym);
      }
    }
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Note section parser
  // ═══════════════════════════════════════════════════════════════════════

  _parseNotes(bytes, offset, size, dest) {
    if (offset + size > bytes.length) return;
    const maxNotes = 32; // Safety cap
    let pos = offset;
    const end = offset + size;
    let count = 0;

    while (pos + 12 <= end && count < maxNotes) {
      const namesz = this._u32(bytes, pos);
      const descsz = this._u32(bytes, pos + 4);
      const type = this._u32(bytes, pos + 8);
      pos += 12;

      const nameEnd = pos + namesz;
      if (nameEnd > end) break;
      const name = namesz > 0 ? this._str(bytes, pos, namesz) : '';
      pos = (nameEnd + 3) & ~3; // Align to 4 bytes

      const descStart = pos;
      const descEnd = pos + descsz;
      if (descEnd > end) break;

      const note = { name, type, descsz };

      // Interpret known note types
      if (name === 'GNU' && type === 1 && descsz >= 16) {
        // NT_GNU_ABI_TAG
        const os = this._u32(bytes, descStart);
        const major = this._u32(bytes, descStart + 4);
        const minor = this._u32(bytes, descStart + 8);
        const patch = this._u32(bytes, descStart + 12);
        const osName = os === 0 ? 'Linux' : os === 1 ? 'GNU' : os === 2 ? 'Solaris' : os === 3 ? 'FreeBSD' : `OS(${os})`;
        note.desc = `ABI: ${osName} ${major}.${minor}.${patch}`;
        note.typeStr = 'GNU_ABI_TAG';
      } else if (name === 'GNU' && type === 3 && descsz > 0) {
        // NT_GNU_BUILD_ID
        const idBytes = bytes.subarray(descStart, Math.min(descStart + descsz, descStart + 40));
        note.desc = 'Build ID: ' + Array.from(idBytes).map(b => b.toString(16).padStart(2, '0')).join('');
        note.typeStr = 'GNU_BUILD_ID';
      } else if (name === 'GNU' && type === 5) {
        note.desc = 'GNU property note';
        note.typeStr = 'GNU_PROPERTY';
      } else {
        note.desc = `${name} type=${type} (${descsz} bytes)`;
        note.typeStr = `TYPE_${type}`;
      }

      dest.push(note);
      pos = (descEnd + 3) & ~3;
      count++;
    }
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Security feature detection
  // ═══════════════════════════════════════════════════════════════════════

  _detectSecurity(elf) {
    const sec = {};

    // RELRO: Partial = has PT_GNU_RELRO, Full = also has BIND_NOW
    const hasRelro = elf.segments.some(s => s.type === 0x6474E552); // PT_GNU_RELRO
    const hasBindNow = !!(elf.dynamicFlags & 0x8) || // DF_BIND_NOW
                       !!(elf.dynamicFlags1 & 0x1);  // DF_1_NOW
    sec.relro = hasRelro ? (hasBindNow ? 'Full' : 'Partial') : 'None';

    // Stack canary: presence of __stack_chk_fail in dynamic symbols
    sec.stackCanary = elf.dynsyms.some(s => s.name === '__stack_chk_fail' || s.name === '__stack_chk_guard');

    // NX (non-executable stack): PT_GNU_STACK without execute flag
    const gnuStack = elf.segments.find(s => s.type === 0x6474E551); // PT_GNU_STACK
    if (gnuStack) {
      sec.nx = !gnuStack.permX; // NX enabled if stack is NOT executable
    } else {
      sec.nx = false; // No GNU_STACK means default (may be executable on some systems)
    }

    // PIE: ELF type is DYN and has INTERP (shared object used as executable)
    // Pure shared libraries are DYN but without INTERP
    const hasInterp = elf.segments.some(s => s.type === 3); // PT_INTERP
    if (elf.isDyn && hasInterp) {
      sec.pie = true;
    } else if (elf.isDyn && !hasInterp) {
      sec.pie = 'DSO'; // Dynamic shared object (always position-independent)
    } else {
      sec.pie = false;
    }

    // FORTIFY: presence of *_chk symbols
    sec.fortify = elf.dynsyms.some(s => s.name && /_chk(@|$)/.test(s.name));
    sec.fortifyCount = elf.dynsyms.filter(s => s.name && /_chk(@|$)/.test(s.name)).length;

    // RPATH/RUNPATH (security concern — can be hijacked)
    sec.rpath = elf.rpath;
    sec.runpath = elf.runpath;

    return sec;
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  String extraction
  // ═══════════════════════════════════════════════════════════════════════

  _extractStrings(bytes, elf) {
    const strings = [];
    const seen = new Set();
    const maxStrings = 10000;
    const minLen = 4;

    // Extract from loadable sections that are likely to contain readable content
    const stringSections = elf.sections.filter(s =>
      s.size > 0 && s.type !== 8 /* NOBITS */ && s.offset + s.size <= bytes.length &&
      (s.name === '.rodata' || s.name === '.data' || s.name === '.comment' ||
       s.name === '.note.gnu.build-id' || s.name === '.note.ABI-tag' ||
       (s.isAlloc && !s.isExec && s.type === 1 /* PROGBITS */))
    );

    // If no recognized sections, scan all PROGBITS with ALLOC flag
    const scanSections = stringSections.length > 0
      ? stringSections
      : elf.sections.filter(s => s.size > 0 && s.type === 1 && s.offset + s.size <= bytes.length);

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

      // Pass 2: UTF-16LE runs — catches wide-char paths/URLs/commands that
      // ASCII-only scanning misses (e.g. Windows-style API strings embedded
      // in cross-compiled ELF binaries, Qt/ICU UTF-16 resource tables).
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
    wrap.className = 'elf-view';
    let parsedStrings = null;

    try {
      const elf = this._parse(bytes);
      parsedStrings = elf.strings;

      // ── Banner ─────────────────────────────────────────────────────
      const banner = document.createElement('div');
      banner.className = 'doc-extraction-banner';
      let bType = elf.isDyn && elf.interpreter ? 'PIE Executable' : elf.isDyn ? 'Shared Object' : elf.isExec ? 'Executable' : elf.isRel ? 'Relocatable' : elf.isCore ? 'Core Dump' : 'ELF';
      if (elf.isGoBinary) bType = 'Go ' + bType;
      banner.innerHTML = `<strong>ELF Analysis — ${this._esc(bType)}</strong> ` +
        `<span class="doc-meta-tag">${this._esc(elf.ident.classStr)}</span> ` +
        `<span class="doc-meta-tag">${this._esc(elf.machineStr)}</span> ` +
        `<span class="doc-meta-tag">${this._esc(elf.ident.dataStr)}</span> ` +
        `<span class="doc-meta-tag">${elf.sections.length} sections</span> ` +
        `<span class="doc-meta-tag">${elf.segments.length} segments</span>` +
        (elf.neededLibs.length > 0 ? ` <span class="doc-meta-tag">${elf.neededLibs.length} libraries</span>` : '');
      wrap.appendChild(banner);

      // ── Go binary badge + build-info ─────────────────────────────
      //   Mirrors the PE renderer: surface the Go detection immediately
      //   under the main banner so analysts don't have to scroll.
      if (elf.isGoBinary) {
        const fmt = document.createElement('div');
        fmt.className = 'doc-extraction-banner';
        const g = elf.goBuildInfo || {};
        const bits = [];
        if (g.version) bits.push(`<span class="doc-meta-tag">${this._esc(g.version)}</span>`);
        if (g.path) bits.push(`<span class="doc-meta-tag">path: ${this._esc(g.path)}</span>`);
        if (g.vcs && g.revision) bits.push(`<span class="doc-meta-tag">${this._esc(g.vcs)}: ${this._esc(g.revision.slice(0, 12))}</span>`);
        fmt.innerHTML = `<div>🐹 <strong>Go binary</strong> ${bits.join(' ')}</div>`;
        wrap.appendChild(fmt);

        if (elf.goBuildInfo) {
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
      }

      // ── Binary Pivot (shared triage card) ───────────────────────
      // Identical layout to the PE / Mach-O cards — SHA-256 / SHA-1 /
      // MD5 over the whole file, telfhash-style import hash, "unsigned"
      // signer row (ELF has no structural signer; code signing is an
      // external tooling convention), entry-point RVA, overlay
      // presence, and a strings-driven packer guess. ELF has no
      // compile timestamp in its structural header so that slot is
      // omitted entirely.
      try {
        if (typeof BinarySummary !== 'undefined') {
          // Compute the telfhash-style import hash from the sorted,
          // deduplicated dynamic-symbol imports (shndx === 0). Mirrors
          // the computation in analyzeForSecurity() so the card row is
          // consistent with the sidebar pivot.
          let importHash = null;
          try {
            const importNames = [...new Set(
              (elf.dynsyms || [])
                .filter(s => s && s.name && s.shndx === 0)
                .map(s => String(s.name).toLowerCase())
            )].sort();
            if (importNames.length && typeof computeImportHashFromList === 'function') {
              importHash = computeImportHashFromList(importNames) || null;
            }
          } catch (_) { /* best-effort */ }

          // Entry-point section — ELF doesn't carry an `entryPointInfo`
          // like PE; compute a minimal section lookup here so the card
          // row matches the header table. Orphan-EP / W+X anomalies are
          // not currently surfaced as a separate ELF helper so only
          // section placement is shown.
          let epSection = null;
          try {
            if (elf.entry && elf.sections && elf.sections.length) {
              for (const s of elf.sections) {
                if (!s) continue;
                const sz = s.sh_size || 0;
                const addr = s.sh_addr || 0;
                if (sz && addr && elf.entry >= addr && elf.entry < addr + sz) {
                  epSection = s.name || null;
                  break;
                }
              }
            }
          } catch (_) { /* best-effort */ }

          // Overlay presence + first-bytes magic.
          let overlayInfo = { present: false };
          try {
            const oStart = this._computeOverlayStart(elf);
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

          // Packer — ELF doesn't carry a canonical section-name table
          // like PE's PACKER_SECTIONS; use a tiny inline lookup for the
          // best-known ELF packers that can be spotted by either an
          // unusual section name or a strings-level marker.
          let packerInfo = null;
          try {
            const ELF_PACKER_SECTIONS = {
              'UPX0': 'UPX', 'UPX1': 'UPX', 'UPX!': 'UPX',
            };
            const hit = (elf.sections || []).find(s => s && ELF_PACKER_SECTIONS[s.name]);
            if (hit) {
              packerInfo = { label: ELF_PACKER_SECTIONS[hit.name], source: 'section ' + hit.name };
            } else {
              // Strings-level fallback — UPX stubs embed the literal
              // "UPX!" tag near the start of the packed image.
              const strs = elf.strings || [];
              for (let i = 0; i < strs.length && i < 200; i++) {
                const s = strs[i];
                if (typeof s === 'string' && s.includes('UPX!')) {
                  packerInfo = { label: 'UPX', source: 'strings UPX!' };
                  break;
                }
              }
            }
          } catch (_) { /* best-effort */ }

          const formatDetail = [elf.ident && elf.ident.classStr, elf.machineStr].filter(Boolean).join(' · ');
          const card = BinarySummary.renderCard({
            bytes,
            fileSize: bytes.length,
            format: 'ELF',
            formatDetail,
            importHash,
            richHash: null,
            symHash: null,
            signer: { present: false, label: '— (ELF has no structural signer)' },
            compileTimestamp: null,
            entryPoint: {
              displayStr: this._hex(elf.entry || 0, elf.ident && elf.ident.classStr === 'ELF64' ? 16 : 8),
              section: epSection,
              anomaly: null,
            },
            overlay: overlayInfo,
            packer: packerInfo,
          });
          wrap.appendChild(card);
        }
      } catch (_) { /* summary card is best-effort */ }

      // ── ELF Header ──────────────────────────────────────────────
      wrap.appendChild(this._renderSection('📋 ELF Header', this._renderHeaders(elf)));


      // ── Security Features ───────────────────────────────────────
      wrap.appendChild(this._renderSection('🛡 Security Features', this._renderSecurity(elf)));

      // ── Program Headers (Segments) ──────────────────────────────
      if (elf.segments.length > 0) {
        wrap.appendChild(this._renderSection(
          '📦 Segments (' + elf.segments.length + ')',
          this._renderSegments(elf)
        ));
      }

      // ── Section Headers ─────────────────────────────────────────
      if (elf.sections.length > 0) {
        wrap.appendChild(this._renderSection(
          '📑 Sections (' + elf.sections.length + ')',
          this._renderSections(elf)
        ));
      }

      // ── Dynamic Libraries ───────────────────────────────────────
      if (elf.neededLibs.length > 0 || elf.soname || elf.dynamic.length > 0) {
        wrap.appendChild(this._renderSection(
          '📚 Dynamic Linking' + (elf.neededLibs.length > 0 ? ' (' + elf.neededLibs.length + ' libraries)' : ''),
          this._renderDynamic(elf)
        ));
      }

      // ── Symbols ─────────────────────────────────────────────────
      const importSyms = elf.dynsyms.filter(s => s.name && s.shndx === 0 && (s.type === 2 || s.bind === 1 || s.bind === 2));
      const exportSyms = elf.dynsyms.filter(s => s.name && s.shndx !== 0 && (s.bind === 1 || s.bind === 2));

      if (importSyms.length > 0) {
        wrap.appendChild(this._renderSection(
          '📥 Imported Symbols (' + importSyms.length + ')',
          this._renderSymbols(importSyms, true),
          importSyms.length
        ));
      }

      if (exportSyms.length > 0) {
        wrap.appendChild(this._renderSection(
          '📤 Exported Symbols (' + exportSyms.length + ')',
          this._renderSymbols(exportSyms, false),
          exportSyms.length
        ));
      }

      // ── Notes ───────────────────────────────────────────────────
      if (elf.notes.length > 0) {
        wrap.appendChild(this._renderSection(
          '📝 Notes (' + elf.notes.length + ')',
          this._renderNotes(elf)
        ));
      }

      // ── Overlay (appended payload past end-of-image) ───────────────
      // Bytes past `max(sh.offset + sh.size)` across non-SHT_NOBITS
      // sections are the overlay. Stripped binaries without section
      // headers fall back to program-header extent.
      try {
        const oStart = this._computeOverlayStart(elf);
        if (oStart > 0 && oStart < bytes.length && typeof BinaryOverlay !== 'undefined') {
          const { el } = BinaryOverlay.renderCard({
            bytes,
            overlayStart: oStart,
            fileSize: bytes.length,
            baseName: (fileName || 'binary').replace(/\.[^.]+$/, ''),
            subtitle: 'past end-of-image',
          });
          wrap.appendChild(this._renderSection('📎 Overlay', el));
        }
      } catch (_) { /* overlay drill-down is best-effort */ }

      // ── Strings ─────────────────────────────────────────────────

      if (elf.strings.length > 0) {
        wrap.appendChild(this._renderSection(
          '🔤 Strings (' + elf.strings.length + ')',
          this._renderStrings(elf)
        ));
      }

    } catch (err) {
      parsedStrings = this._renderFallback(wrap, bytes, err, fileName);
    }

    // Expose extracted strings as _rawText so the general IOC extraction
    // pipeline and EncodedContentDetector scan clean string data instead
    // of noisy DOM text (table headers, hex addresses, UI chrome, etc.)
    // On parse failure we still populate from the fallback scan so YARA
    // and IOC extraction keep running on truncated binaries.
    if (parsedStrings && parsedStrings.length > 0) {
      wrap._rawText = parsedStrings.join('\n');
    }

    return wrap;
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Fallback view — used when ELF parsing fails (truncated/malformed).
  //  Still shows extracted strings + a raw hex dump so IOC/YARA scans work.
  //  Returns the extracted strings array so caller can expose _rawText.
  // ═══════════════════════════════════════════════════════════════════════

  _renderFallback(wrap, bytes, err, fileName) {
    const notice = document.createElement('div');
    notice.className = 'bin-fallback-notice';
    const magic = bytes.length >= 4
      ? Array.from(bytes.slice(0, 4)).map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ')
      : '—';
    notice.innerHTML =
      `<div class="bin-fallback-title"><strong>⚠ ELF parsing failed — showing raw fallback view</strong></div>` +
      `<div class="bin-fallback-reason"><code>${this._esc(err.message)}</code></div>` +
      `<div class="bin-fallback-sub">The file appears to be truncated or malformed, so structural ` +
      `analysis (headers, segments, sections, …) isn't available. Extracted strings and a raw hex ` +
      `dump are shown below so IOC extraction and YARA rules can still run against the bytes.</div>` +
      `<div class="bin-fallback-info">` +
        `<span class="doc-meta-tag">${this._esc(fileName || 'unknown')}</span> ` +
        `<span class="doc-meta-tag">${bytes.length.toLocaleString()} bytes</span> ` +
        `<span class="doc-meta-tag">Magic: ${magic}</span>` +
      `</div>`;
    wrap.appendChild(notice);

    // Generic string scan — the normal _extractStrings requires a parsed elf
    // object (it uses section offsets), so we scan the raw buffer directly.
    const strings = this._rawStringScan(bytes);
    if (strings.length > 0) {
      const fakeElf = { strings };
      wrap.appendChild(this._renderSection(
        '🔤 Strings (' + strings.length + ')',
        this._renderStrings(fakeElf)
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

  // Byte-scan fallback used when no parsed ELF structure is available.
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

  /**
   * ELF overlay start = max(sh.offset + sh.size) across all sections whose
   * type ≠ SHT_NOBITS (8). SHT_NOBITS sections don't consume file bytes
   * (.bss, .tbss) so they must be excluded. For stripped binaries whose
   * section headers have been removed or zeroed, fall back to the program-
   * header extent: max(ph.offset + ph.filesz) across all loadable segments.
   * Returns 0 when neither probe yields a positive extent.
   *
   * Shared by render() (for the overlay drill-down card) and
   * analyzeForSecurity() (for risk escalation + SHA-256 metadata).
   */
  _computeOverlayStart(elf) {
    if (!elf) return 0;
    let end = 0;
    if (Array.isArray(elf.sections)) {
      for (const s of elf.sections) {
        if (!s) continue;
        if (s.type === 8) continue;           // SHT_NOBITS — no file bytes
        if (!s.size || !(s.offset >= 0)) continue;
        const e = (s.offset + s.size);
        if (e > end) end = e;
      }
    }
    if (end === 0 && Array.isArray(elf.segments)) {
      for (const p of elf.segments) {
        if (!p || !p.filesz) continue;
        const e = (p.offset + p.filesz);
        if (e > end) end = e;
      }
    }
    // Also bound against section-header-table end: the SHT itself can live
    // past the last section, and anything past it is still overlay.
    if (elf.shoff && elf.shnum && elf.shentsize) {
      const shtEnd = elf.shoff + elf.shnum * elf.shentsize;
      if (shtEnd > end) end = shtEnd;
    }
    return end;
  }

  _renderSection(title, contentEl, rowCount) {

    const sec = document.createElement('details');
    sec.className = 'elf-section';
    const collapse = rowCount && rowCount > 50;
    sec.open = !collapse;
    const sum = document.createElement('summary');
    sum.innerHTML = this._esc(title) + (collapse ? ` <span class="bin-collapse-note">${rowCount} rows — click to expand</span>` : '');
    sec.appendChild(sum);
    sec.appendChild(contentEl);
    return sec;
  }

  _renderHeaders(elf) {
    const digits = this._is64 ? 16 : 8;
    const rows = [
      ['Class', elf.ident.classStr],
      ['Endianness', elf.ident.dataStr],
      ['OS/ABI', elf.ident.osabiStr],
      ['Type', elf.typeStr],
      ['Machine', elf.machineStr],
      ['Entry Point', this._hex(elf.entry, digits)],
      ['Flags', this._hex(elf.flags, 8)],
      ['Program Headers', `${elf.phnum} entries × ${elf.phentsize} bytes (offset ${this._hex(elf.phoff, digits)})`],
      ['Section Headers', `${elf.shnum} entries × ${elf.shentsize} bytes (offset ${this._hex(elf.shoff, digits)})`],
      ['Header Size', `${elf.ehsize} bytes`],
    ];
    if (elf.interpreter) {
      rows.push(['Interpreter', elf.interpreter]);
    }
    if (elf.soname) {
      rows.push(['SONAME', elf.soname]);
    }
    return this._buildTable(['Field', 'Value'], rows);
  }

  _renderSecurity(elf) {
    const s = elf.security;
    const div = document.createElement('div');
    div.className = 'elf-security-grid';

    const features = [
      ['RELRO (Relocation Read-Only)', s.relro !== 'None', s.relro === 'Full'
        ? 'Full RELRO — GOT is read-only, prevents GOT overwrite attacks'
        : s.relro === 'Partial'
          ? 'Partial RELRO — some sections read-only after relocation'
          : 'No RELRO — GOT is writable, vulnerable to GOT overwrite'],
      ['Stack Canary', s.stackCanary, s.stackCanary
        ? 'Stack canary enabled — buffer overflow protection via __stack_chk_fail'
        : 'No stack canary detected — vulnerable to stack buffer overflows'],
      ['NX (Non-Executable Stack)', s.nx, s.nx
        ? 'NX enabled — stack is non-executable, prevents shellcode on stack'
        : 'NX disabled — stack is executable, shellcode can run from stack'],
      ['PIE (Position Independent)', s.pie === true || s.pie === 'DSO', s.pie === true
        ? 'PIE enabled — full ASLR for executable'
        : s.pie === 'DSO'
          ? 'Shared object — inherently position-independent'
          : 'Not PIE — fixed load address, limited ASLR'],
      ['FORTIFY_SOURCE', s.fortify, s.fortify
        ? `FORTIFY enabled — ${s.fortifyCount} hardened function(s) detected`
        : 'No FORTIFY detected — standard libc functions used'],
    ];

    for (const [name, enabled, desc] of features) {
      const row = document.createElement('div');
      row.className = 'elf-sec-row' + (enabled ? ' elf-sec-on' : ' elf-sec-off');
      const icon = name.includes('RELRO') && s.relro === 'Partial' ? '⚠️' : (enabled ? '✅' : '❌');
      row.innerHTML = `<span class="elf-sec-icon">${icon}</span>` +
        `<span class="elf-sec-name">${this._esc(name)}</span>` +
        `<span class="elf-sec-desc">${this._esc(desc)}</span>`;
      div.appendChild(row);
    }

    // RPATH/RUNPATH warning
    if (s.rpath || s.runpath) {
      const rpathRow = document.createElement('div');
      rpathRow.className = 'elf-sec-row elf-sec-off';
      const path = s.rpath || s.runpath;
      const label = s.rpath ? 'RPATH' : 'RUNPATH';
      rpathRow.innerHTML = `<span class="elf-sec-icon">⚠️</span>` +
        `<span class="elf-sec-name">${label}</span>` +
        `<span class="elf-sec-desc">${label} set to "${this._esc(path)}" — potential library hijacking vector</span>`;
      div.appendChild(rpathRow);
    }

    return div;
  }

  _renderSegments(elf) {
    const digits = this._is64 ? 16 : 8;
    const rows = elf.segments.map((seg, i) => [
      i.toString(),
      seg.typeStr,
      this._hex(seg.offset, digits),
      this._hex(seg.vaddr, digits),
      seg.filesz.toLocaleString(),
      seg.memsz.toLocaleString(),
      seg.permStr,
      this._hex(seg.align, 4),
    ]);
    const table = this._buildTable(['#', 'Type', 'Offset', 'VirtAddr', 'FileSize', 'MemSize', 'Flags', 'Align'], rows,
      (row, i) => {
        if (elf.segments[i].permW && elf.segments[i].permX) row.classList.add('elf-highlight');
        const seg = elf.segments[i];
        if (seg.filesz > 0) {
          row.classList.add('bin-clickable');
          row.addEventListener('click', () => {
            const next = row.nextElementSibling;
            if (next && next.classList.contains('bin-hexdump-row')) {
              next.remove(); row.classList.remove('bin-expanded');
            } else {
              const hr = document.createElement('tr'); hr.className = 'bin-hexdump-row';
              const td = document.createElement('td'); td.colSpan = 8;
              td.appendChild(this._renderHexDump(seg.offset, seg.filesz));
              hr.appendChild(td); row.after(hr); row.classList.add('bin-expanded');
            }
          });
        }
      }
    );
    return table;
  }

  _renderSections(elf) {
    const digits = this._is64 ? 16 : 8;
    const rows = elf.sections.map((sec, i) => [
      i.toString(),
      sec.name || '(null)',
      sec.typeStr,
      this._hex(sec.addr, digits),
      this._hex(sec.offset, digits),
      sec.size.toLocaleString(),
      sec.flagsStr,
      sec.entropy > 0 ? sec.entropy.toFixed(3) : '—',
    ]);
    return this._buildTable(['#', 'Name', 'Type', 'Address', 'Offset', 'Size', 'Flags', 'Entropy'], rows,
      (row, i) => {
        const sec = elf.sections[i];
        if (sec.entropy > 7.0) row.classList.add('elf-highlight');
        if (sec.isWritable && sec.isExec) row.classList.add('elf-highlight');
        if (sec.size > 0 && sec.offset > 0) {
          row.classList.add('bin-clickable');
          row.addEventListener('click', () => {
            const next = row.nextElementSibling;
            if (next && next.classList.contains('bin-hexdump-row')) {
              next.remove(); row.classList.remove('bin-expanded');
            } else {
              const hr = document.createElement('tr'); hr.className = 'bin-hexdump-row';
              const td = document.createElement('td'); td.colSpan = 8;
              td.appendChild(this._renderHexDump(sec.offset, sec.size));
              hr.appendChild(td); row.after(hr); row.classList.add('bin-expanded');
            }
          });
        }
      }
    );
  }

  _renderDynamic(elf) {
    const div = document.createElement('div');

    // Needed libraries
    if (elf.neededLibs.length > 0) {
      const libDiv = document.createElement('div');
      libDiv.className = 'elf-lib-list';
      const h = document.createElement('h4');
      h.textContent = 'Required Libraries';
      h.style.margin = '0 0 6px 0';
      libDiv.appendChild(h);
      for (const lib of elf.neededLibs) {
        const item = document.createElement('div');
        item.className = 'elf-lib-item';
        item.textContent = lib;
        libDiv.appendChild(item);
      }
      div.appendChild(libDiv);
    }

    // SONAME
    if (elf.soname) {
      const p = document.createElement('p');
      p.innerHTML = `<strong>SONAME:</strong> ${this._esc(elf.soname)}`;
      p.style.margin = '8px 0';
      div.appendChild(p);
    }

    // RPATH / RUNPATH
    if (elf.rpath) {
      const p = document.createElement('p');
      p.innerHTML = `<strong>RPATH:</strong> <span class="elf-warn-text">${this._esc(elf.rpath)}</span>`;
      p.style.margin = '4px 0';
      div.appendChild(p);
    }
    if (elf.runpath) {
      const p = document.createElement('p');
      p.innerHTML = `<strong>RUNPATH:</strong> <span class="elf-warn-text">${this._esc(elf.runpath)}</span>`;
      p.style.margin = '4px 0';
      div.appendChild(p);
    }

    // Dynamic section entries (collapsed by default)
    if (elf.dynamic.length > 0) {
      const details = document.createElement('details');
      details.style.marginTop = '10px';
      const sum = document.createElement('summary');
      sum.textContent = `All Dynamic Entries (${elf.dynamic.length})`;
      sum.style.cursor = 'pointer';
      details.appendChild(sum);

      const rows = elf.dynamic.map(d => [d.tagName, d.valStr]);
      details.appendChild(this._buildTable(['Tag', 'Value'], rows));
      div.appendChild(details);
    }

    return div;
  }

  _renderSymbols(syms, isImport) {
    const digits = this._is64 ? 16 : 8;
    const suspMap = ElfRenderer.SUSPICIOUS_SYMBOLS;

    const rows = syms.map(sym => {
      const suspicious = suspMap[sym.name];
      const nameHtml = suspicious
        ? `<span class="elf-suspicious-sym" title="${this._esc(suspicious)}">${this._esc(sym.name)} ⚠️</span>`
        : this._esc(sym.name);
      return [
        nameHtml,
        sym.typeStr,
        sym.bindStr,
        sym.visStr,
        isImport ? '—' : this._hex(sym.value, digits),
        suspicious ? `<span class="elf-suspicious-desc">${this._esc(suspicious)}</span>` : '',
      ];
    });

    const table = this._buildTable(
      ['Name', 'Type', 'Bind', 'Vis', 'Value', isImport ? 'Risk' : 'Info'],
      rows,
      (row, i) => {
        if (suspMap[syms[i].name]) {
          row.classList.add('elf-suspicious-row');
          // Clickable info card for suspicious symbols
          row.style.cursor = 'pointer';
          row.addEventListener('click', () => {
            const next = row.nextElementSibling;
            if (next && next.classList.contains('bin-info-card-row')) {
              next.remove(); return;
            }
            const info = suspMap[syms[i].name];
            const detail = ElfRenderer.SUSPICIOUS_SYMBOLS_DETAIL[syms[i].name];
            const cat = this._categorizeElfSymbol(syms[i].name);
            const cardRow = document.createElement('tr'); cardRow.className = 'bin-info-card-row';
            const td = document.createElement('td'); td.colSpan = 6;
            const card = document.createElement('div'); card.className = 'bin-info-card';
            let html = `<strong>${this._esc(syms[i].name)}</strong>` +
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
    this._addSearchBar(wrapper, () => Array.from(table.querySelectorAll('tbody tr:not(.bin-info-card-row)')), 'Filter symbols…', '.elf-suspicious-row');
    wrapper.appendChild(table);
    return wrapper;
  }

  _renderNotes(elf) {
    const rows = elf.notes.map(n => [n.typeStr, n.name, n.desc, `${n.descsz} bytes`]);
    return this._buildTable(['Type', 'Owner', 'Description', 'Size'], rows);
  }

  _renderStrings(elf) {
    const div = document.createElement('div');
    div.className = 'elf-strings-container';

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
      const blob = new Blob([elf.strings.join('\n')], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href = url; a.download = 'strings.txt'; a.click();
      URL.revokeObjectURL(url);
    });
    const copyBtn = document.createElement('button');
    copyBtn.className = 'tb-btn tb-action-btn';
    copyBtn.textContent = '📋 Copy';
    copyBtn.title = 'Copy all strings to clipboard';
    copyBtn.addEventListener('click', () => {
      const text = elf.strings.join('\n');
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
    list.className = 'elf-strings-list';

    for (const s of elf.strings) {
      const item = document.createElement('div');
      item.className = 'elf-string-item';
      item.textContent = s;
      list.appendChild(item);
    }

    // Search bar for strings
    this._addSearchBar(div, () => Array.from(list.querySelectorAll('.elf-string-item')), 'Filter strings…');
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

  _categorizeElfSymbol(name) {
    const info = ElfRenderer.SUSPICIOUS_SYMBOLS[name];
    if (!info) return null;
    const lower = info.toLowerCase();
    if (/debug|prevent/i.test(lower)) return { cat: 'Anti-Debug', cls: 'cat-antidebug' };
    if (/injection|another.*process|process_vm/i.test(lower)) return { cat: 'Process Injection', cls: 'cat-inject' };
    if (/execution|command|shell|exec/i.test(lower)) return { cat: 'Execution', cls: 'cat-exec' };
    if (/network|socket|C2|exfiltration|backdoor|listener|connection|send|recv/i.test(lower)) return { cat: 'Networking', cls: 'cat-network' };
    if (/privilege|setuid|setgid|capability|capset/i.test(lower)) return { cat: 'Privilege Escalation', cls: 'cat-cred' };
    if (/rootkit|kernel.*module/i.test(lower)) return { cat: 'Rootkit', cls: 'cat-inject' };
    if (/fileless|memfd|memory.*map|executable.*mem/i.test(lower)) return { cat: 'Fileless Execution', cls: 'cat-crypto' };
    if (/deletion|forensic|self.*delet/i.test(lower)) return { cat: 'Anti-Forensics', cls: 'cat-file' };
    if (/dynamic|dlopen|dlsym/i.test(lower)) return { cat: 'Dynamic Loading', cls: 'cat-recon' };
    if (/mount|chroot|container|sandbox/i.test(lower)) return { cat: 'Sandbox Escape', cls: 'cat-antidebug' };
    if (/monitor|surveillance|inotify|fanotify/i.test(lower)) return { cat: 'Surveillance', cls: 'cat-recon' };
    if (/memory|mmap|mprotect/i.test(lower)) return { cat: 'Memory Manipulation', cls: 'cat-inject' };
    if (/IPC|shared.*mem|message.*queue/i.test(lower)) return { cat: 'IPC', cls: 'cat-network' };
    if (/process|fork|clone|spawn/i.test(lower)) return { cat: 'Process Control', cls: 'cat-exec' };
    if (/ASLR|personality/i.test(lower)) return { cat: 'Evasion', cls: 'cat-antidebug' };
    if (/dup2|descriptor/i.test(lower)) return { cat: 'FD Manipulation', cls: 'cat-exec' };
    if (/keyctl|credential|keyring/i.test(lower)) return { cat: 'Credential Access', cls: 'cat-cred' };
    if (/kexec|kernel/i.test(lower)) return { cat: 'Persistence', cls: 'cat-file' };
    return { cat: 'Suspicious', cls: 'cat-inject' };
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Table builder
  // ═══════════════════════════════════════════════════════════════════════

  _buildTable(headers, rows, rowCallback, allowHtml) {
    const tbl = document.createElement('table');
    tbl.className = 'elf-table';
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
      elfInfo: null,
    };

    try {
      const elf = this._parse(bytes);
      findings.elfInfo = elf;

      const issues = [];
      let riskScore = 0;

      // ── File type context ──────────────────────────────────────────
      const bType = elf.isDyn && elf.interpreter ? 'PIE Executable' : elf.isDyn ? 'Shared Object' : elf.isExec ? 'Executable' : elf.isRel ? 'Relocatable' : elf.isCore ? 'Core Dump' : 'ELF';
      findings.metadata = {
        'Type': bType,
        'Class': elf.ident.classStr,
        'Endianness': elf.ident.dataStr,
        'Machine': elf.machineStr,
        'OS/ABI': elf.ident.osabiStr,
        'Entry Point': this._hex(elf.entry, this._is64 ? 16 : 8),
        'Segments': elf.segments.length.toString(),
        'Sections': elf.sections.length.toString(),
      };

      if (elf.interpreter) findings.metadata['Interpreter'] = elf.interpreter;
      if (elf.soname) findings.metadata['SONAME'] = elf.soname;
      if (elf.neededLibs.length > 0) findings.metadata['Libraries'] = elf.neededLibs.length.toString();

      // ── ELF import hash (telfhash-style) ────────────────────────────
      // MD5 of the sorted, deduplicated list of dynamic-symbol imports
      // (entries with shndx === 0, i.e. defined elsewhere). Lets the
      // analyst cluster ELF malware variants that share a common libc
      // import shape independently of compilation artefacts. The hash
      // is stable under re-linking, light repacking, and most re-strips.
      try {
        const importNames = [...new Set(
          (elf.dynsyms || [])
            .filter(s => s && s.name && s.shndx === 0)
            .map(s => String(s.name).toLowerCase())
        )].sort();
        if (importNames.length && typeof computeImportHashFromList === 'function') {
          const ih = computeImportHashFromList(importNames);
          if (ih) findings.metadata['Import Hash (MD5)'] = ih;
        }
      } catch (_) { /* best-effort */ }


      // ── Security feature checks ────────────────────────────────────
      if (elf.security.relro === 'None') {
        issues.push('No RELRO — GOT is writable, vulnerable to GOT overwrite attacks');
        riskScore += 1;
      } else if (elf.security.relro === 'Partial') {
        issues.push('Partial RELRO — GOT still partially writable');
        riskScore += 0.5;
      }

      if (!elf.security.stackCanary) {
        issues.push('No stack canary — vulnerable to stack buffer overflows');
        riskScore += 1;
      }

      if (!elf.security.nx) {
        issues.push('NX disabled — stack is executable, shellcode can run from stack');
        riskScore += 1.5;
      }

      if (elf.security.pie === false && elf.isExec) {
        issues.push('Not PIE — fixed load address, limited ASLR effectiveness');
        riskScore += 0.5;
      }

      if (elf.security.rpath) {
        issues.push(`RPATH set to "${elf.security.rpath}" — potential library hijacking vector`);
        riskScore += 1;
      }

      if (elf.security.runpath) {
        issues.push(`RUNPATH set to "${elf.security.runpath}" — potential library hijacking vector`);
        riskScore += 0.5;
      }

      // ── Section anomalies ──────────────────────────────────────────
      for (const sec of elf.sections) {
        if (sec.isWritable && sec.isExec) {
          issues.push(`Section "${sec.name}" is W+X (writable and executable) — code injection risk`);
          riskScore += 2;
        }
        if (sec.entropy > 7.0 && sec.size > 1024) {
          issues.push(`Section "${sec.name}" has very high entropy (${sec.entropy.toFixed(3)}) — likely packed or encrypted`);
          riskScore += 1.5;
        }
      }

      // ── Segment anomalies ──────────────────────────────────────────
      for (const seg of elf.segments) {
        if (seg.type === 1 && seg.permW && seg.permX) { // LOAD segment W+X
          issues.push(`LOAD segment at ${this._hex(seg.vaddr, 8)} is W+X — unusual, potential shellcode region`);
          riskScore += 2;
        }
      }

      // ── Suspicious symbol analysis ─────────────────────────────────
      const suspMap = ElfRenderer.SUSPICIOUS_SYMBOLS;
      const suspiciousImports = elf.dynsyms.filter(s =>
        s.name && s.shndx === 0 && suspMap[s.name]
      );

      if (suspiciousImports.length > 0) {
        riskScore += Math.min(suspiciousImports.length * 0.3, 4);

        // Categorize suspicious patterns
        const hasExec = suspiciousImports.some(s =>
          /execution|command|launch/i.test(suspMap[s.name]));
        const hasInjection = suspiciousImports.some(s =>
          /injection|another.*process/i.test(suspMap[s.name]));
        const hasNetwork = suspiciousImports.some(s =>
          /network|socket|C2|exfiltration|backdoor/i.test(suspMap[s.name]));
        const hasPrivesc = suspiciousImports.some(s =>
          /privilege|setuid|setgid|capability/i.test(suspMap[s.name]));
        const hasAntiDebug = suspiciousImports.some(s =>
          /debug|prevent/i.test(suspMap[s.name]));
        const hasRootkit = suspiciousImports.some(s =>
          /rootkit|kernel.*module/i.test(suspMap[s.name]));
        const hasFileless = suspiciousImports.some(s =>
          /fileless|memfd|memory/i.test(suspMap[s.name]));
        const hasAntiForensic = suspiciousImports.some(s =>
          /forensic|deletion|self.*delet/i.test(suspMap[s.name]));

        if (hasExec) { issues.push('Imports command execution functions (execve/system/popen)'); riskScore += 1; }
        if (hasInjection) { issues.push('Imports process memory manipulation APIs'); riskScore += 2; }
        if (hasNetwork) { issues.push('Imports network socket APIs — potential C2/backdoor capability'); riskScore += 1; }
        if (hasPrivesc) { issues.push('Imports privilege escalation functions (setuid/setgid)'); riskScore += 1.5; }
        if (hasAntiDebug) { issues.push('Imports anti-debugging function (ptrace)'); riskScore += 1; }
        if (hasRootkit) { issues.push('Imports kernel module loading functions — potential rootkit'); riskScore += 3; }
        if (hasFileless) { issues.push('Imports fileless execution functions (memfd_create/fexecve)'); riskScore += 2; }
        if (hasAntiForensic) { issues.push('Imports file deletion functions — potential self-deletion'); riskScore += 0.5; }

        // Check for reverse shell pattern: socket + dup2 + execve
        const hasSocket = suspiciousImports.some(s => s.name === 'socket');
        const hasDup2 = suspiciousImports.some(s => s.name === 'dup2');
        const hasExecve = suspiciousImports.some(s => s.name === 'execve' || s.name === 'execvp' || s.name === 'execl');
        if (hasSocket && hasDup2 && hasExecve) {
          issues.push('Reverse shell pattern detected: socket + dup2 + exec combination');
          riskScore += 3;
        }

        // Check for RWX memory pattern: mmap + mprotect
        const hasMmap = suspiciousImports.some(s => s.name === 'mmap');
        const hasMprotect = suspiciousImports.some(s => s.name === 'mprotect');
        if (hasMmap && hasMprotect) {
          issues.push('Runtime code generation pattern: mmap + mprotect — can create executable memory');
          riskScore += 1;
        }
      }

      // ── Stripped binary check ──────────────────────────────────────
      const hasSymtab = elf.sections.some(s => s.name === '.symtab');
      if (!hasSymtab) {
        findings.metadata['Stripped'] = 'Yes (no .symtab)';
      } else {
        findings.metadata['Stripped'] = 'No';
      }

      // ── Static linking check ───────────────────────────────────────
      if (!elf.interpreter && elf.isExec) {
        issues.push('Statically linked executable — unusual for modern binaries, may be obfuscated/packed');
        riskScore += 1;
        findings.metadata['Linking'] = 'Static';
      } else if (elf.interpreter) {
        findings.metadata['Linking'] = 'Dynamic';
      }

      // ── Extract IOCs from strings ──────────────────────────────────
      // IOCs come from the synthetic joined string buffer, not file
      // bytes — carry only _highlightText for sidebar text-search
      // click-to-focus. Truncation markers surface as IOC.INFO so the
      // Summary/Share view sees the cap.
      const allStrings = elf.strings.join('\n');
      const _urlRx = /https?:\/\/[^\s"'<>()\[\]{}\u0000-\u001F]{6,}/g;
      const _uncRx = /\\\\[\w.\-]{2,}(?:\\[\w.\-]+)+/g;
      const URL_CAP = 50, UNC_CAP = 20;
      const urlMatches = [...new Set([...allStrings.matchAll(_urlRx)].map(m => m[0]))];
      for (const url of urlMatches.slice(0, URL_CAP)) {
        findings.interestingStrings.push({
          type: IOC.URL, url, severity: 'info', _highlightText: url,
        });
      }
      if (urlMatches.length > URL_CAP) {
        findings.interestingStrings.push({
          type: IOC.INFO,
          url: `URL extraction truncated at ${URL_CAP} — binary contains ${urlMatches.length} unique URLs`,
          severity: 'info',
        });
      }
      const uncMatches = [...new Set([...allStrings.matchAll(_uncRx)].map(m => m[0]))];
      for (const unc of uncMatches.slice(0, UNC_CAP)) {
        findings.interestingStrings.push({
          type: IOC.UNC_PATH, url: unc, severity: 'medium', _highlightText: unc,
        });
      }
      if (uncMatches.length > UNC_CAP) {
        findings.interestingStrings.push({
          type: IOC.INFO,
          url: `UNC path extraction truncated at ${UNC_CAP} — binary contains ${uncMatches.length} unique UNC paths`,
          severity: 'info',
        });
      }

      // ── Categorised strings (PDB paths, build-host paths, …) ──────
      // Mutex / named-pipe / registry patterns are Windows-specific and
      // will be no-ops on ELF, but PDB-path and POSIX user-home path
      // extraction still fire on ELF: cross-compiled stealers often
      // embed stray build-host paths and forgotten PDBs from their
      // Windows/Linux dual-target toolchain. Emit with the same
      // IOC.* types so the sidebar groups them with the PE/Mach-O hits.
      try {
        if (typeof BinaryStrings !== 'undefined' && BinaryStrings.emit) {
          const strCounts = BinaryStrings.emit(findings, allStrings);
          if (strCounts.pdbPaths)   findings.metadata['PDB Paths (str)']   = String(strCounts.pdbPaths);
          if (strCounts.userPaths)  findings.metadata['Build-host Paths']  = String(strCounts.userPaths);
          if (strCounts.rustPanics) findings.metadata['Rust Panic Paths']  = String(strCounts.rustPanics);
        }
      } catch (_) { /* classification is best-effort */ }

      // ── Export-anomaly flags (side-loading host filename only) ───────
      // ELF has no forwarder / ordinal-export notion, but the side-loading
      // *filename* check still fires if a cross-compiled attacker drops a
      // DLL-named .so next to a Windows-targeting payload (seen in dual-
      // target stealers). `isLib` is only true for ET_DYN shared objects
      // that carry a DT_SONAME — rules out PIE executables, which are
      // ET_DYN too but have no SONAME and are never side-load targets.
      try {
        if (typeof BinaryExports !== 'undefined' && BinaryExports.emit) {
          const exportNames = (elf.dynsyms || [])
            .filter(s => s.name && s.shndx !== 0 && (s.bind === 1 || s.bind === 2))
            .map(s => s.name);
          const expCounts = BinaryExports.emit(findings, {
            isLib: !!(elf.isDyn && elf.soname),
            fileName: elf.soname || fileName || '',
            exportNames,
            forwardedExports: [],
            ordinalOnlyCount: 0,
          });
          if (expCounts.sideLoadHit) { findings.metadata['DLL Side-Load Host'] = 'Yes'; riskScore += 2; }
        }
      } catch (_) { /* export-anomaly analysis is best-effort */ }

      // ── Go binary metadata ─────────────────────────────────────────
      // Surface the Go-specific fields on findings.metadata so the Summary
      // (_copyAnalysisELF in app-ui.js) can display them alongside the
      // standard ELF header info. Kept below the generic linking check
      // so ordering in the Summary mirrors PE output.
      if (elf.isGoBinary) {
        findings.metadata['Format'] = 'Go Binary';
        if (elf.goBuildInfo) {
          if (elf.goBuildInfo.version) findings.metadata['Go Version'] = elf.goBuildInfo.version;
          if (elf.goBuildInfo.path) findings.metadata['Go Module Path'] = elf.goBuildInfo.path;
          if (elf.goBuildInfo.vcs && elf.goBuildInfo.revision) {
            findings.metadata['Go VCS'] = `${elf.goBuildInfo.vcs} ${elf.goBuildInfo.revision.slice(0, 12)}`;
          }
          if (elf.goBuildInfo.buildTime) findings.metadata['Go Build Time'] = elf.goBuildInfo.buildTime;
        }
      }

      // ── Mirror dylibs + RPATHs + classic-pivot metadata into IOCs ──
      // `findings.metadata` only stores a lib count ("Libraries" = "7");
      // the actual NEEDED lib paths are in `elf.neededLibs` — emit each
      // one individually so they become clickable IOCs in the sidebar.
      // Same for RPATH/RUNPATH which are real filesystem pivots.
      if (elf.neededLibs && elf.neededLibs.length > 0) {
        const LIB_CAP = 40;
        const libs = elf.neededLibs.slice(0, LIB_CAP);
        for (const name of libs) {
          if (!name) continue;
          pushIOC(findings, {
            type: IOC.FILE_PATH, value: name, severity: 'info',
            note: 'ELF NEEDED library',
          });
        }
        if (elf.neededLibs.length > LIB_CAP) {
          pushIOC(findings, {
            type: IOC.INFO,
            value: `…+${elf.neededLibs.length - LIB_CAP} more NEEDED libraries`,
            severity: 'info',
          });
        }
      }
      if (elf.rpath) {
        // Split on ':' because DT_RPATH can encode multiple search paths.
        for (const rp of String(elf.rpath).split(':').map(s => s.trim()).filter(Boolean)) {
          pushIOC(findings, {
            type: IOC.FILE_PATH, value: rp, severity: 'medium',
            note: 'ELF DT_RPATH (library search path — hijack vector)',
          });
        }
      }
      if (elf.runpath) {
        for (const rp of String(elf.runpath).split(':').map(s => s.trim()).filter(Boolean)) {
          pushIOC(findings, {
            type: IOC.FILE_PATH, value: rp, severity: 'medium',
            note: 'ELF DT_RUNPATH (library search path — hijack vector)',
          });
        }
      }
      // ── Overlay detection (appended payload past end-of-image) ─────
      // ELF overlay = bytes past max(sh.offset + sh.size) across non-
      // SHT_NOBITS sections (or max program-header extent for stripped
      // binaries). A large high-entropy overlay with no recognised
      // container magic is a classic stacked-dropper / packed-payload
      // shape. No Authenticode equivalent to special-case on ELF.
      try {
        const oStart = this._computeOverlayStart(elf);
        if (oStart > 0 && oStart < bytes.length && typeof BinaryOverlay !== 'undefined') {
          const overlayBytes = bytes.subarray(oStart, bytes.length);
          const overlaySize = overlayBytes.length;
          const overlayPct = (overlaySize / Math.max(1, bytes.length)) * 100;
          const overlayEntropy = BinaryOverlay.shannonEntropy(overlayBytes);
          const overlayMagic = BinaryOverlay.sniffMagic(overlayBytes.subarray(0, 32));

          findings.metadata['Overlay Size'] = overlaySize.toLocaleString() + ' bytes';
          findings.metadata['Overlay Entropy'] = overlayEntropy.toFixed(3);
          if (overlayMagic) findings.metadata['Overlay Magic'] = overlayMagic.label;

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

          // SHA-256 lands on metadata once the async digest settles; the
          // sidebar will pick it up on the next refresh. The render-side
          // card also populates its own row via the same promise.
          BinaryOverlay.sha256Hex(overlayBytes).then(hex => {
            if (hex) findings.metadata['Overlay SHA-256'] = hex;
          });
        }
      } catch (_) { /* overlay analysis is best-effort */ }

      // Classic-pivot fields: interpreter leaks the target libc flavour,
      // SONAME is the canonical lib identifier, Go Module Path leaks the
      // build-host VCS URL. Attribution fluff stays metadata-only per the
      // "Option B" classic-pivot policy.
      mirrorMetadataIOCs(findings, {
        'Interpreter':        IOC.FILE_PATH,
        'SONAME':             IOC.FILE_PATH,
        'Go Module Path':     IOC.PATTERN,
        'Import Hash (MD5)':  IOC.HASH,
        'Overlay SHA-256':    IOC.HASH,
      });


      // ── Capability tagging (capa-lite) ─────────────────────────────
      // Turn the wall of "X suspicious symbols" into named MITRE-tagged
      // behaviours. ELF symbol names carry no leading `_`, so we pass
      // dynsym names directly; the string corpus covers LD_PRELOAD /
      // systemd paths / /etc/shadow references captured by _extractStrings.
      try {
        const capImports = [...new Set(
          (elf.dynsyms || [])
            .filter(s => s && s.name && s.shndx === 0)
            .map(s => String(s.name).toLowerCase())
        )];
        const capDylibs = (elf.neededLibs || []).map(n => String(n || '').toLowerCase());
        const capStrings = elf.strings || [];
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

      // ── Risk assessment ────────────────────────────────────────────
      findings.autoExec = issues;

      if (riskScore >= 8) findings.risk = 'critical';
      else if (riskScore >= 5) findings.risk = 'high';
      else if (riskScore >= 2) findings.risk = 'medium';
      else findings.risk = 'low';

    } catch (e) {
      findings.risk = 'medium';
      findings.autoExec = ['ELF parsing partially failed: ' + e.message];
    }

    return findings;
  }
}
