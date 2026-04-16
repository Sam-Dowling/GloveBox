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

    return elf;
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
      let current = '';
      const end = Math.min(sec.offset + sec.size, bytes.length);

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
      const bType = elf.isDyn && elf.interpreter ? 'PIE Executable' : elf.isDyn ? 'Shared Object' : elf.isExec ? 'Executable' : elf.isRel ? 'Relocatable' : elf.isCore ? 'Core Dump' : 'ELF';
      banner.innerHTML = `<strong>ELF Analysis — ${this._esc(bType)}</strong> ` +
        `<span class="doc-meta-tag">${this._esc(elf.ident.classStr)}</span> ` +
        `<span class="doc-meta-tag">${this._esc(elf.machineStr)}</span> ` +
        `<span class="doc-meta-tag">${this._esc(elf.ident.dataStr)}</span> ` +
        `<span class="doc-meta-tag">${elf.sections.length} sections</span> ` +
        `<span class="doc-meta-tag">${elf.segments.length} segments</span>` +
        (elf.neededLibs.length > 0 ? ` <span class="doc-meta-tag">${elf.neededLibs.length} libraries</span>` : '');
      wrap.appendChild(banner);

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

      // ── Strings ─────────────────────────────────────────────────
      if (elf.strings.length > 0) {
        wrap.appendChild(this._renderSection(
          '🔤 Strings (' + elf.strings.length + ')',
          this._renderStrings(elf)
        ));
      }

    } catch (err) {
      const errBox = document.createElement('div');
      errBox.className = 'elf-error';
      errBox.textContent = 'ELF parsing error: ' + err.message;
      wrap.appendChild(errBox);
    }

    // Expose extracted strings as _rawText so the general IOC extraction
    // pipeline and EncodedContentDetector scan clean string data instead
    // of noisy DOM text (table headers, hex addresses, UI chrome, etc.)
    if (parsedStrings && parsedStrings.length > 0) {
      wrap._rawText = parsedStrings.join('\n');
    }

    return wrap;
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Section renderers (DOM builders)
  // ═══════════════════════════════════════════════════════════════════════

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
      const allStrings = elf.strings.join('\n');
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
      findings.autoExec = ['ELF parsing partially failed: ' + e.message];
    }

    return findings;
  }
}
