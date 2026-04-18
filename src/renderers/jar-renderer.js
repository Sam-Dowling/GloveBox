// jar-renderer.js — JAR/WAR/EAR/CLASS file analyzer for Java security analysis
// Parses Java archives (ZIP-based) and standalone .class files.
// Extracts MANIFEST.MF, class file metadata, constant pool strings, dependencies.

class JarRenderer {

  // ── Java class file version → Java SE mapping ───────────────────────────
  static JAVA_VERSIONS = {
    45: '1.1', 46: '1.2', 47: '1.3', 48: '1.4', 49: '5', 50: '6',
    51: '7', 52: '8', 53: '9', 54: '10', 55: '11', 56: '12',
    57: '13', 58: '14', 59: '15', 60: '16', 61: '17', 62: '18',
    63: '19', 64: '20', 65: '21', 66: '22', 67: '23', 68: '24'
  };

  // ── Class access flags ──────────────────────────────────────────────────
  static ACCESS_FLAGS = {
    0x0001: 'PUBLIC', 0x0010: 'FINAL', 0x0020: 'SUPER', 0x0200: 'INTERFACE',
    0x0400: 'ABSTRACT', 0x1000: 'SYNTHETIC', 0x2000: 'ANNOTATION', 0x4000: 'ENUM',
    0x8000: 'MODULE'
  };

  // ── Suspicious Java APIs / classes (for constant pool string scanning) ──
  static SUSPICIOUS_APIS = {
    // Command execution
    'Runtime.exec': { desc: 'OS command execution', severity: 'high', mitre: 'T1059' },
    'ProcessBuilder': { desc: 'Process creation', severity: 'high', mitre: 'T1059' },
    'Runtime.getRuntime': { desc: 'Runtime access for command execution', severity: 'high', mitre: 'T1059' },
    // Reflection / classloading
    'ClassLoader': { desc: 'Dynamic class loading', severity: 'medium', mitre: 'T1620' },
    'URLClassLoader': { desc: 'Remote class loading', severity: 'high', mitre: 'T1105' },
    'defineClass': { desc: 'Runtime class definition', severity: 'high', mitre: 'T1620' },
    'java.lang.reflect': { desc: 'Reflection API usage', severity: 'medium', mitre: 'T1620' },
    'Method.invoke': { desc: 'Reflective method invocation', severity: 'medium', mitre: 'T1620' },
    'forName': { desc: 'Dynamic class loading by name', severity: 'medium', mitre: 'T1620' },
    // Serialization (deserialization attacks)
    'ObjectInputStream': { desc: 'Java deserialization', severity: 'high', mitre: 'T1059' },
    'readObject': { desc: 'Deserialization entry point', severity: 'high', mitre: 'T1059' },
    'readResolve': { desc: 'Deserialization hook', severity: 'medium', mitre: 'T1059' },
    'Serializable': { desc: 'Serializable interface', severity: 'low', mitre: 'T1059' },
    // JNDI / Naming (Log4Shell family)
    'InitialContext': { desc: 'JNDI context creation', severity: 'high', mitre: 'T1190' },
    'jndi:': { desc: 'JNDI lookup string', severity: 'critical', mitre: 'T1190' },
    'javax.naming': { desc: 'JNDI naming API', severity: 'medium', mitre: 'T1190' },
    'NamingManager': { desc: 'JNDI naming manager', severity: 'high', mitre: 'T1190' },
    // Network
    'Socket': { desc: 'Network socket', severity: 'medium', mitre: 'T1071' },
    'ServerSocket': { desc: 'Server socket (listener)', severity: 'high', mitre: 'T1571' },
    'HttpURLConnection': { desc: 'HTTP connection', severity: 'medium', mitre: 'T1071.001' },
    'URL.openConnection': { desc: 'URL connection', severity: 'medium', mitre: 'T1071' },
    'DatagramSocket': { desc: 'UDP socket', severity: 'medium', mitre: 'T1071' },
    // Crypto
    'javax.crypto': { desc: 'Cryptographic operations', severity: 'medium', mitre: 'T1486' },
    'Cipher': { desc: 'Encryption/decryption', severity: 'medium', mitre: 'T1486' },
    'SecretKey': { desc: 'Secret key handling', severity: 'medium', mitre: 'T1552' },
    'KeyGenerator': { desc: 'Key generation', severity: 'medium', mitre: 'T1486' },
    // File system
    'FileOutputStream': { desc: 'File write operations', severity: 'low', mitre: 'T1005' },
    'RandomAccessFile': { desc: 'Random file access', severity: 'low', mitre: 'T1005' },
    'Files.write': { desc: 'File write (NIO)', severity: 'low', mitre: 'T1005' },
    // Native code
    'System.loadLibrary': { desc: 'Native library loading', severity: 'high', mitre: 'T1055' },
    'System.load': { desc: 'Native library loading (path)', severity: 'high', mitre: 'T1055' },
    'JNI': { desc: 'Java Native Interface', severity: 'medium', mitre: 'T1055' },
    // Script engines
    'ScriptEngine': { desc: 'Script engine (eval)', severity: 'high', mitre: 'T1059' },
    'ScriptEngineManager': { desc: 'Script engine factory', severity: 'high', mitre: 'T1059' },
    'Nashorn': { desc: 'JavaScript engine', severity: 'high', mitre: 'T1059.007' },
    // Java agent / instrumentation
    'java.lang.instrument': { desc: 'Java instrumentation API', severity: 'high', mitre: 'T1055' },
    'Instrumentation': { desc: 'Bytecode instrumentation', severity: 'high', mitre: 'T1055' },
    'agentmain': { desc: 'Dynamic agent entry point', severity: 'high', mitre: 'T1055' },
    'premain': { desc: 'Static agent entry point', severity: 'high', mitre: 'T1055' },
    // Privilege / security
    'SecurityManager': { desc: 'Security manager manipulation', severity: 'medium', mitre: 'T1562' },
    'AccessController': { desc: 'Access control operations', severity: 'medium', mitre: 'T1562' },
    'setSecurityManager': { desc: 'Security manager override', severity: 'high', mitre: 'T1562' },
    'ProtectionDomain': { desc: 'Protection domain access', severity: 'medium', mitre: 'T1562' },
    // Credential / keystore
    'KeyStore': { desc: 'Keystore access', severity: 'medium', mitre: 'T1552.004' },
    'PasswordCallback': { desc: 'Password callback handler', severity: 'medium', mitre: 'T1056' },
  };

  // ── Known obfuscator signatures ─────────────────────────────────────────
  static OBFUSCATOR_SIGNATURES = [
    { pattern: /^[a-z]{1,2}\/[a-z]{1,2}\/[a-z]{1,2}$/, name: 'ProGuard (aggressive)' },
    { pattern: /Allatori/i, name: 'Allatori Obfuscator' },
    { pattern: /zelix|ZKM/i, name: 'Zelix KlassMaster' },
    { pattern: /DashO/i, name: 'DashO Obfuscator' },
    { pattern: /yguard/i, name: 'yGuard Obfuscator' },
    { pattern: /stringer/i, name: 'Stringer (string encryptor)' },
  ];

  // ── Deserialization gadget classes ──────────────────────────────────────
  static GADGET_CLASSES = [
    'org.apache.commons.collections.functors.InvokerTransformer',
    'org.apache.commons.collections.functors.ChainedTransformer',
    'org.apache.commons.collections.functors.ConstantTransformer',
    'org.apache.commons.collections4.functors.InvokerTransformer',
    'org.apache.commons.beanutils.BeanComparator',
    'com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl',
    'org.springframework.beans.factory.ObjectFactory',
    'org.codehaus.groovy.runtime.ConvertedClosure',
    'bsh.Interpreter',
    'org.mozilla.javascript.NativeJavaObject',
    'com.mchange.v2.c3p0.WrapperConnectionPoolDataSource',
    'org.hibernate.property.BasicPropertyAccessor',
    'com.alibaba.fastjson.JSON',
    'org.apache.wicket.util.upload.DiskFileItem',
    'org.jboss.interceptor.proxy.InterceptorMethodHandler',
  ];

  // ── WAR / EAR config files ─────────────────────────────────────────────
  static CONFIG_FILES = [
    'META-INF/MANIFEST.MF', 'META-INF/maven/', 'META-INF/services/',
    'WEB-INF/web.xml', 'WEB-INF/classes/', 'WEB-INF/lib/',
    'META-INF/application.xml', 'META-INF/ejb-jar.xml',
    'META-INF/persistence.xml', 'META-INF/beans.xml',
    'log4j2.xml', 'log4j.xml', 'log4j.properties', 'logback.xml',
    'application.properties', 'application.yml', 'application.yaml',
    'META-INF/spring.factories', 'META-INF/spring/', 'spring.xml',
  ];

  // ── Constant pool tag types ────────────────────────────────────────────
  static CP_TAGS = {
    1: 'Utf8', 3: 'Integer', 4: 'Float', 5: 'Long', 6: 'Double',
    7: 'Class', 8: 'String', 9: 'Fieldref', 10: 'Methodref',
    11: 'InterfaceMethodref', 12: 'NameAndType', 15: 'MethodHandle',
    16: 'MethodType', 17: 'Dynamic', 18: 'InvokeDynamic', 19: 'Module', 20: 'Package'
  };

  // ═════════════════════════════════════════════════════════════════════════
  //  Static helpers
  // ═════════════════════════════════════════════════════════════════════════
  _esc(s) { return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }
  _fmtBytes(n) {
    if (n === 0) return '0 B';
    const k = 1024, s = ['B', 'KB', 'MB', 'GB'];
    const i = Math.min(Math.floor(Math.log(n) / Math.log(k)), s.length - 1);
    return parseFloat((n / Math.pow(k, i)).toFixed(1)) + ' ' + s[i];
  }

  // ═════════════════════════════════════════════════════════════════════════
  //  Java class file magic detection
  // ═════════════════════════════════════════════════════════════════════════
  static isJavaClass(bytes) {
    if (bytes.length < 10) return false;
    // CA FE BA BE magic
    if (bytes[0] !== 0xCA || bytes[1] !== 0xFE || bytes[2] !== 0xBA || bytes[3] !== 0xBE) return false;
    // Major version at bytes 6-7 (big-endian): Java 1.1=45 through Java 24=68
    const major = (bytes[6] << 8) | bytes[7];
    return major >= 45 && major <= 68;
  }

  // ═════════════════════════════════════════════════════════════════════════
  //  Parse a single .class file constant pool
  // ═════════════════════════════════════════════════════════════════════════
  _parseClassFile(bytes, offset = 0) {
    if (bytes.length < offset + 10) return null;
    const dv = new DataView(bytes.buffer, bytes.byteOffset + offset, bytes.length - offset);
    let pos = 0;

    // Magic
    const magic = dv.getUint32(pos); pos += 4;
    if (magic !== 0xCAFEBABE) return null;

    const minorVersion = dv.getUint16(pos); pos += 2;
    const majorVersion = dv.getUint16(pos); pos += 2;
    const javaVersion = JarRenderer.JAVA_VERSIONS[majorVersion] || `Unknown (${majorVersion})`;

    // Constant pool
    const cpCount = dv.getUint16(pos); pos += 2;
    const constants = [null]; // index 0 is unused
    const strings = [];
    const classRefs = [];
    const methodRefs = [];
    const fieldRefs = [];
    const nameAndTypes = [];

    for (let i = 1; i < cpCount; i++) {
      if (pos >= dv.byteLength) break;
      const tag = dv.getUint8(pos); pos += 1;

      switch (tag) {
        case 1: { // Utf8
          const len = dv.getUint16(pos); pos += 2;
          const strBytes = new Uint8Array(bytes.buffer, bytes.byteOffset + offset + pos, Math.min(len, dv.byteLength - pos));
          let str;
          try { str = new TextDecoder('utf-8', { fatal: false }).decode(strBytes); }
          catch { str = ''; }
          pos += len;
          constants.push({ tag, value: str });
          strings.push({ index: i, value: str });
          break;
        }
        case 3: // Integer
          constants.push({ tag, value: dv.getInt32(pos) }); pos += 4; break;
        case 4: // Float
          constants.push({ tag, value: dv.getFloat32(pos) }); pos += 4; break;
        case 5: // Long
          constants.push({ tag, value: null }); pos += 8; i++; constants.push(null); break;
        case 6: // Double
          constants.push({ tag, value: null }); pos += 8; i++; constants.push(null); break;
        case 7: // Class
          constants.push({ tag, nameIndex: dv.getUint16(pos) }); pos += 2;
          classRefs.push(i);
          break;
        case 8: // String
          constants.push({ tag, stringIndex: dv.getUint16(pos) }); pos += 2; break;
        case 9: // Fieldref
          constants.push({ tag, classIndex: dv.getUint16(pos), natIndex: dv.getUint16(pos + 2) }); pos += 4;
          fieldRefs.push(i);
          break;
        case 10: // Methodref
          constants.push({ tag, classIndex: dv.getUint16(pos), natIndex: dv.getUint16(pos + 2) }); pos += 4;
          methodRefs.push(i);
          break;
        case 11: // InterfaceMethodref
          constants.push({ tag, classIndex: dv.getUint16(pos), natIndex: dv.getUint16(pos + 2) }); pos += 4;
          methodRefs.push(i);
          break;
        case 12: // NameAndType
          constants.push({ tag, nameIndex: dv.getUint16(pos), descIndex: dv.getUint16(pos + 2) }); pos += 4;
          nameAndTypes.push(i);
          break;
        case 15: // MethodHandle
          constants.push({ tag }); pos += 3; break;
        case 16: // MethodType
          constants.push({ tag }); pos += 2; break;
        case 17: case 18: // Dynamic / InvokeDynamic
          constants.push({ tag }); pos += 4; break;
        case 19: case 20: // Module / Package
          constants.push({ tag, nameIndex: dv.getUint16(pos) }); pos += 2; break;
        default:
          constants.push({ tag: 0 });
          break;
      }
    }

    // Access flags, this_class, super_class
    let accessFlags = 0, thisClassIdx = 0, superClassIdx = 0, interfaceCount = 0;
    if (pos + 8 <= dv.byteLength) {
      accessFlags = dv.getUint16(pos); pos += 2;
      thisClassIdx = dv.getUint16(pos); pos += 2;
      superClassIdx = dv.getUint16(pos); pos += 2;
      interfaceCount = dv.getUint16(pos); pos += 2;
    }

    // Resolve class names
    const resolveName = (idx) => {
      if (!idx || !constants[idx]) return '?';
      const c = constants[idx];
      if (c.tag === 7 && c.nameIndex && constants[c.nameIndex]) return constants[c.nameIndex].value || '?';
      if (c.tag === 1) return c.value || '?';
      return '?';
    };

    const thisClass = resolveName(thisClassIdx);
    const superClass = resolveName(superClassIdx);

    // Resolve interfaces
    const interfaces = [];
    for (let j = 0; j < interfaceCount && pos + 2 <= dv.byteLength; j++) {
      const ifIdx = dv.getUint16(pos); pos += 2;
      interfaces.push(resolveName(ifIdx));
    }

    // Count fields and methods
    let fieldsCount = 0, methodsCount = 0;
    if (pos + 2 <= dv.byteLength) {
      fieldsCount = dv.getUint16(pos); pos += 2;
      // Skip field entries
      for (let j = 0; j < fieldsCount && pos + 8 <= dv.byteLength; j++) {
        pos += 6; // access, name, desc
        const attrCount = dv.getUint16(pos); pos += 2;
        for (let a = 0; a < attrCount && pos + 6 <= dv.byteLength; a++) {
          pos += 2; // name index
          const attrLen = dv.getUint32(pos); pos += 4;
          pos += attrLen;
        }
      }
    }
    if (pos + 2 <= dv.byteLength) {
      methodsCount = dv.getUint16(pos); pos += 2;
    }

    // Resolve class references
    const resolvedClasses = classRefs.map(i => resolveName(i)).filter(n => n !== '?');

    // Resolve access flag names
    const flagNames = [];
    for (const [bit, name] of Object.entries(JarRenderer.ACCESS_FLAGS)) {
      if (accessFlags & parseInt(bit)) flagNames.push(name);
    }

    return {
      majorVersion, minorVersion, javaVersion,
      accessFlags, flagNames,
      thisClass, superClass, interfaces,
      fieldsCount, methodsCount,
      cpCount: cpCount - 1,
      constants, strings, classRefs: resolvedClasses,
      methodRefs, fieldRefs, nameAndTypes
    };
  }

  // ═════════════════════════════════════════════════════════════════════════
  //  Parse MANIFEST.MF
  // ═════════════════════════════════════════════════════════════════════════
  _parseManifest(text) {
    const attrs = {};
    const sections = [];
    let currentSection = null;
    let lastKey = null;

    for (const raw of text.split(/\r?\n/)) {
      // Continuation line (starts with space)
      if (raw.startsWith(' ') && lastKey) {
        if (currentSection) currentSection[lastKey] += raw.substring(1);
        else if (attrs[lastKey]) attrs[lastKey] += raw.substring(1);
        continue;
      }
      // Empty line = new section
      if (raw.trim() === '') {
        if (currentSection && Object.keys(currentSection).length > 0) {
          sections.push(currentSection);
        }
        currentSection = {};
        lastKey = null;
        continue;
      }
      const colon = raw.indexOf(':');
      if (colon === -1) continue;
      const key = raw.substring(0, colon).trim();
      const value = raw.substring(colon + 1).trim();
      lastKey = key;
      if (!currentSection || Object.keys(currentSection).length === 0) {
        // Still in main section
        if (currentSection && Object.keys(currentSection).length === 0) currentSection = null;
        attrs[key] = value;
      } else {
        currentSection[key] = value;
      }
    }
    if (currentSection && Object.keys(currentSection).length > 0) {
      sections.push(currentSection);
    }
    return { attrs, sections };
  }

  // ═════════════════════════════════════════════════════════════════════════
  //  Analyze string constants for suspicious patterns
  // ═════════════════════════════════════════════════════════════════════════
  _analyzeStrings(strings) {
    const suspicious = [];
    const imports = new Set();
    const urls = [];
    const ips = [];

    for (const s of strings) {
      const v = s.value || s;
      if (typeof v !== 'string' || v.length < 3) continue;

      // Track imports (class references with /)
      if (/^[a-zA-Z_$][\w$]*(?:\/[a-zA-Z_$][\w$]*){1,10}$/.test(v)) {
        const pkg = v.replace(/\//g, '.').replace(/\.[A-Z][^.]*$/, '');
        if (pkg.includes('.')) imports.add(pkg);
      }

      // Check suspicious APIs
      for (const [api, info] of Object.entries(JarRenderer.SUSPICIOUS_APIS)) {
        if (v.includes(api)) {
          suspicious.push({ value: v, api, ...info, source: s.index !== undefined ? `CP#${s.index}` : 'string' });
          break;
        }
      }

      // Check deserialization gadgets
      for (const gadget of JarRenderer.GADGET_CLASSES) {
        const dotted = v.replace(/\//g, '.');
        if (dotted.includes(gadget)) {
          suspicious.push({ value: v, api: gadget.split('.').pop(), desc: 'Deserialization gadget class', severity: 'critical', mitre: 'T1059', source: s.index !== undefined ? `CP#${s.index}` : 'string' });
          break;
        }
      }

      // Extract URLs
      if (/https?:\/\/[^\s"'<>]{4,}/.test(v)) urls.push(v);
      if (/^ldaps?:\/\//.test(v) || /^rmi:\/\//.test(v)) {
        urls.push(v);
        suspicious.push({ value: v, api: 'JNDI URI', desc: 'JNDI remote lookup URI', severity: 'critical', mitre: 'T1190', source: s.index !== undefined ? `CP#${s.index}` : 'string' });
      }

      // Extract IPs
      const ipMatch = v.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/);
      if (ipMatch && !/^(127\.0\.0\.|0\.0\.0\.|255\.|192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ipMatch[1])) {
        ips.push(ipMatch[1]);
      }
    }

    return { suspicious, imports: [...imports].sort(), urls, ips };
  }

  // ═════════════════════════════════════════════════════════════════════════
  //  Detect obfuscation indicators
  // ═════════════════════════════════════════════════════════════════════════
  _detectObfuscation(classEntries, allStrings) {
    const indicators = [];
    let shortNames = 0;
    const totalClasses = classEntries.length;

    for (const entry of classEntries) {
      const name = entry.path || entry;
      const simpleName = typeof name === 'string' ? name.replace(/.*\//, '').replace('.class', '') : '';
      if (/^[a-z]{1,2}$/.test(simpleName)) shortNames++;
      // Check obfuscator signatures in path
      for (const sig of JarRenderer.OBFUSCATOR_SIGNATURES) {
        if (sig.pattern.test(name)) {
          indicators.push(`${sig.name} detected (${name})`);
        }
      }
    }

    if (totalClasses > 5 && shortNames / totalClasses > 0.5) {
      indicators.push(`High ratio of short class names (${shortNames}/${totalClasses}) — likely obfuscated`);
    }

    // Check string constants for obfuscator markers
    for (const s of allStrings) {
      const v = typeof s === 'string' ? s : s.value;
      if (!v) continue;
      for (const sig of JarRenderer.OBFUSCATOR_SIGNATURES) {
        if (sig.pattern.test(v)) {
          indicators.push(`${sig.name} marker in string constant: "${v.substring(0, 60)}"`);
        }
      }
    }

    return indicators;
  }

  // ═════════════════════════════════════════════════════════════════════════
  //  Render (main entry point)
  // ═════════════════════════════════════════════════════════════════════════
  async render(buffer, fileName) {
    const wrap = document.createElement('div');
    wrap.className = 'jar-view';
    const bytes = new Uint8Array(buffer);
    const ext = (fileName || '').split('.').pop().toLowerCase();

    // ── Standalone .class file ──────────────────────────────────────────
    if (ext === 'class' || (JarRenderer.isJavaClass(bytes) && !this._isZip(bytes))) {
      return this._renderClassFile(wrap, bytes, fileName);
    }

    // ── JAR / WAR / EAR (ZIP-based) ────────────────────────────────────
    try {
      const zip = await JSZip.loadAsync(buffer);
      return await this._renderJarContents(wrap, zip, buffer, fileName, ext);
    } catch (e) {
      wrap.innerHTML = `<div class="jar-banner jar-banner-error">
        <span class="jar-banner-icon">❌</span>
        <div><strong>Failed to parse JAR/ZIP structure</strong><br>
        <span style="opacity:0.7">${this._esc(e.message || String(e))}</span></div>
      </div>`;
      return wrap;
    }
  }

  _isZip(bytes) {
    return bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4B && bytes[2] === 0x03 && bytes[3] === 0x04;
  }

  // ═════════════════════════════════════════════════════════════════════════
  //  Render standalone .class file
  // ═════════════════════════════════════════════════════════════════════════
  _renderClassFile(wrap, bytes, fileName) {
    const parsed = this._parseClassFile(bytes);
    if (!parsed) {
      wrap.innerHTML = `<div class="jar-banner jar-banner-error">
        <span class="jar-banner-icon">❌</span>
        <div><strong>Invalid Java class file</strong></div>
      </div>`;
      return wrap;
    }

    const analysis = this._analyzeStrings(parsed.strings);

    // Banner
    const simpleName = parsed.thisClass.replace(/\//g, '.').replace(/.*\./, '');
    const bannerHTML = `<div class="jar-banner">
      <span class="jar-banner-icon">☕</span>
      <div>
        <strong>${this._esc(simpleName)}</strong>
        <span class="jar-badge jar-badge-java">Java ${this._esc(parsed.javaVersion)}</span>
        ${parsed.flagNames.map(f => `<span class="jar-badge">${f}</span>`).join(' ')}
        <br><span style="opacity:0.7">${this._esc(fileName || 'class file')} · ${this._fmtBytes(bytes.length)} · ${parsed.cpCount} constant pool entries</span>
      </div>
    </div>`;

    // Header grid: Class Info (left) + Findings (right, or empty-state)
    const findingsHTML = analysis.suspicious.length > 0
      ? this._buildSuspiciousHTML(analysis.suspicious)
      : `<div class="jar-findings-empty">✓ No suspicious API usage detected in constant pool.</div>`;
    const headerGridHTML = `<div class="jar-header-grid">
      <section class="jar-pane jar-manifest-pane" aria-label="Class Information">
        <header class="jar-pane-header">📋 Class Information</header>
        <div class="jar-pane-body">${this._buildClassInfoHTML(parsed)}</div>
      </section>
      <section class="jar-pane jar-findings-pane" aria-label="Security Findings">
        <header class="jar-pane-header">⚠️ Security Findings${analysis.suspicious.length ? ` <span class="jar-pane-count">${analysis.suspicious.length}</span>` : ''}</header>
        <div class="jar-pane-body">${findingsHTML}</div>
      </section>
    </div>`;

    // Tabs: Strings + (optional) Class References
    const tabs = [];
    tabs.push({
      key: 'strings',
      label: `🔤 Strings`,
      count: parsed.strings.length,
      html: this._buildStringConstantsHTML(parsed.strings, analysis)
    });
    if (parsed.classRefs.length > 0) {
      tabs.push({
        key: 'refs',
        label: '🔗 Class References',
        count: parsed.classRefs.length,
        html: this._buildClassRefsHTML(parsed.classRefs)
      });
    }
    const tabsHTML = this._buildTabsHTML(tabs);

    wrap.innerHTML = bannerHTML + headerGridHTML + tabsHTML;

    this._addSearchBar(wrap);
    this._wireTabs(wrap);
    return wrap;
  }


  // ═════════════════════════════════════════════════════════════════════════
  //  Render JAR/WAR/EAR contents
  // ═════════════════════════════════════════════════════════════════════════
  async _renderJarContents(wrap, zip, buffer, fileName, ext) {
    const entries = [];
    const classEntries = [];
    const resourceEntries = [];
    const configEntries = [];
    let manifestText = null;
    let totalSize = 0;

    // Collect all entries
    zip.forEach((path, entry) => {
      const info = { path, dir: entry.dir, size: entry._data ? (entry._data.uncompressedSize || 0) : 0, date: entry.date, compressedSize: entry._data ? (entry._data.compressedSize || 0) : 0 };
      entries.push(info);
      if (!entry.dir) {
        totalSize += info.size;
        const lower = path.toLowerCase();
        if (lower.endsWith('.class')) classEntries.push(info);
        else if (JarRenderer.CONFIG_FILES.some(c => lower.includes(c.toLowerCase()) || lower === c.toLowerCase())) configEntries.push(info);
        else resourceEntries.push(info);
      }
    });

    // Read MANIFEST.MF
    const manifestEntry = zip.file('META-INF/MANIFEST.MF') || zip.file('meta-inf/manifest.mf');
    if (manifestEntry) {
      try { manifestText = await manifestEntry.async('string'); } catch {}
    }
    const manifest = manifestText ? this._parseManifest(manifestText) : null;

    // Parse class files (up to 1000 to avoid performance issues on huge JARs)
    const classLimit = Math.min(classEntries.length, 1000);
    const parsedClasses = [];
    const allStrings = [];
    for (let i = 0; i < classLimit; i++) {
      try {
        const classFile = zip.file(classEntries[i].path);
        if (!classFile) continue;
        const classBytes = new Uint8Array(await classFile.async('arraybuffer'));
        const parsed = this._parseClassFile(classBytes);
        if (parsed) {
          parsedClasses.push({ ...parsed, path: classEntries[i].path, size: classEntries[i].size });
          allStrings.push(...parsed.strings);
        }
      } catch {}
    }

    // Read web.xml / application.xml for WAR/EAR
    let webXmlContent = null;
    const webXmlEntry = zip.file('WEB-INF/web.xml');
    if (webXmlEntry) {
      try { webXmlContent = await webXmlEntry.async('string'); } catch {}
    }

    // Analyze strings from all parsed classes
    const stringAnalysis = this._analyzeStrings(allStrings);
    const obfuscation = this._detectObfuscation(classEntries, allStrings);

    // Detect archive type
    const archiveType = ext === 'war' ? 'WAR' : ext === 'ear' ? 'EAR' : 'JAR';
    const hasWebInf = entries.some(e => e.path.startsWith('WEB-INF/'));
    const hasMetaApp = entries.some(e => e.path === 'META-INF/application.xml');
    const detectedType = hasMetaApp ? 'EAR' : hasWebInf ? 'WAR' : archiveType;

    // Java version summary
    const javaVersions = new Map();
    for (const c of parsedClasses) {
      const v = c.javaVersion;
      javaVersions.set(v, (javaVersions.get(v) || 0) + 1);
    }
    const primaryJavaVersion = [...javaVersions.entries()].sort((a, b) => b[1] - a[1])[0];

    // ── Banner ──────────────────────────────────────────────────────────
    let bannerHTML = `<div class="jar-banner">
      <span class="jar-banner-icon">☕</span>
      <div>
        <strong>${this._esc(fileName || 'Java Archive')}</strong>
        <span class="jar-badge jar-badge-type">${detectedType}</span>`;
    if (primaryJavaVersion) bannerHTML += ` <span class="jar-badge jar-badge-java">Java ${this._esc(primaryJavaVersion[0])}</span>`;
    if (manifest && manifest.attrs['Main-Class']) bannerHTML += ` <span class="jar-badge jar-badge-main">Main: ${this._esc(manifest.attrs['Main-Class'])}</span>`;
    if (obfuscation.length > 0) bannerHTML += ` <span class="jar-badge jar-badge-warn">⚠ Obfuscated</span>`;
    bannerHTML += `<br><span style="opacity:0.7">${classEntries.length} classes · ${resourceEntries.length + configEntries.length} resources · ${entries.filter(e => e.dir).length} directories · ${this._fmtBytes(totalSize)} uncompressed</span>`;
    if (classEntries.length > classLimit) bannerHTML += `<br><span style="opacity:0.6; font-size:0.85em">⚡ Analyzed first ${classLimit} of ${classEntries.length} class files</span>`;
    bannerHTML += `</div></div>`;

    // ── Header grid: Manifest (left) + Security Findings (right) ────────
    const manifestHTML = manifest
      ? this._buildManifestHTML(manifest)
      : `<div class="jar-findings-empty">No MANIFEST.MF found.</div>`;

    let findingsBodyHTML = '';
    const findingsCount = stringAnalysis.suspicious.length + obfuscation.length;
    if (stringAnalysis.suspicious.length > 0) findingsBodyHTML += this._buildSuspiciousHTML(stringAnalysis.suspicious);
    if (obfuscation.length > 0) {
      findingsBodyHTML += '<h4 class="jar-findings-subhead">🔒 Obfuscation Indicators</h4><ul class="jar-obfuscation-list">';
      for (const o of obfuscation) findingsBodyHTML += `<li>${this._esc(o)}</li>`;
      findingsBodyHTML += '</ul>';
    }
    if (findingsCount === 0) findingsBodyHTML = `<div class="jar-findings-empty">✓ No suspicious API usage, obfuscation, or gadget classes detected.</div>`;

    const headerGridHTML = `<div class="jar-header-grid">
      <section class="jar-pane jar-manifest-pane" aria-label="MANIFEST.MF">
        <header class="jar-pane-header">📄 MANIFEST.MF</header>
        <div class="jar-pane-body">${manifestHTML}</div>
      </section>
      <section class="jar-pane jar-findings-pane" aria-label="Security Findings">
        <header class="jar-pane-header">⚠️ Security Findings${findingsCount ? ` <span class="jar-pane-count">${findingsCount}</span>` : ''}</header>
        <div class="jar-pane-body">${findingsBodyHTML}</div>
      </section>
    </div>`;

    // ── Tabs: Classes / Dependencies / Strings / Resources / web.xml ────
    const interestingStrings = allStrings.filter(s => {
      const v = s.value;
      if (!v || v.length < 4 || v.length > 500) return false;
      if (/^\([A-Z\[;/()]*\)[A-Z\[;/()VIJFDLBCSZa-z]*$/.test(v)) return false;
      if (/^<(init|clinit)>$/.test(v)) return false;
      if (/^(Code|LineNumberTable|SourceFile|StackMapTable|InnerClasses|Exceptions|Signature|Deprecated|ConstantValue|LocalVariableTable|LocalVariableTypeTable|BootstrapMethods|RuntimeVisibleAnnotations|RuntimeInvisibleAnnotations|EnclosingMethod|NestMembers|NestHost|PermittedSubclasses|Record)$/.test(v)) return false;
      return true;
    });

    const tabs = [];
    if (parsedClasses.length > 0) {
      tabs.push({
        key: 'classes',
        label: '☕ Classes',
        count: classEntries.length,
        html: this._buildClassListHTML(parsedClasses, classEntries.length > classLimit)
      });
    }
    if (stringAnalysis.imports.length > 0) {
      tabs.push({
        key: 'deps',
        label: '📦 Dependencies',
        count: stringAnalysis.imports.length,
        html: this._buildDependenciesHTML(stringAnalysis.imports)
      });
    }
    if (interestingStrings.length > 0) {
      tabs.push({
        key: 'strings',
        label: '🔤 Strings',
        count: interestingStrings.length,
        html: this._buildStringConstantsHTML(interestingStrings.slice(0, 500), stringAnalysis)
      });
    }
    if (configEntries.length > 0 || resourceEntries.length > 0) {
      tabs.push({
        key: 'resources',
        label: '🗂 Resources',
        count: configEntries.length + resourceEntries.length,
        html: this._buildResourcesHTML(configEntries, resourceEntries)
      });
    }
    if (webXmlContent) {
      tabs.push({
        key: 'webxml',
        label: '🌐 web.xml',
        count: null,
        html: `<pre class="jar-xml-source">${this._esc(webXmlContent)}</pre>`
      });
    }
    const tabsHTML = this._buildTabsHTML(tabs);

    // ── File tree (all entries, nested) ─────────────────────────────────
    const treeHTML = `<section class="jar-pane jar-tree-pane" aria-label="File tree">
      <header class="jar-pane-header">📁 Archive Contents <span class="jar-pane-count">${entries.filter(e => !e.dir).length}</span>
        <span class="jar-pane-actions">
          <button type="button" class="jar-tree-toggle-all" data-action="expand">Expand all</button>
          <button type="button" class="jar-tree-toggle-all" data-action="collapse">Collapse all</button>
        </span>
      </header>
      <div class="jar-pane-body jar-tree-body">${this._buildFileTreeHTML(entries)}</div>
    </section>`;

    wrap.innerHTML = bannerHTML + headerGridHTML + tabsHTML + treeHTML;

    // Inner file open listener (for tree Open buttons, resource tables, etc.)
    wrap.addEventListener('click', async (e) => {
      const btn = e.target.closest('[data-jar-open]');
      if (!btn) return;
      e.preventDefault();
      e.stopPropagation();
      const path = btn.getAttribute('data-jar-open');
      const entry = zip.file(path);
      if (!entry) return;
      try {
        const ab = await entry.async('arraybuffer');
        const name = path.split('/').pop();
        const innerFile = new File([ab], name);
        wrap.dispatchEvent(new CustomEvent('open-inner-file', { bubbles: true, detail: innerFile }));
      } catch {}
    });

    this._wireTabs(wrap);
    this._wireFileTree(wrap);
    this._addSearchBar(wrap);
    return wrap;
  }


  // ═════════════════════════════════════════════════════════════════════════
  //  HTML building helpers
  // ═════════════════════════════════════════════════════════════════════════

  _renderSection(title, content, open = false) {
    return `<details class="jar-section"${open ? ' open' : ''}>
      <summary>${title}</summary>
      <div class="jar-section-body">${content}</div>
    </details>`;
  }

  _buildClassInfoHTML(parsed) {
    return `<table class="jar-table">
      <tr><th>Class Name</th><td>${this._esc(parsed.thisClass.replace(/\//g, '.'))}</td></tr>
      <tr><th>Super Class</th><td>${this._esc(parsed.superClass.replace(/\//g, '.'))}</td></tr>
      ${parsed.interfaces.length ? `<tr><th>Interfaces</th><td>${parsed.interfaces.map(i => this._esc(i.replace(/\//g, '.'))).join(', ')}</td></tr>` : ''}
      <tr><th>Java Version</th><td>Java ${this._esc(parsed.javaVersion)} (class file ${parsed.majorVersion}.${parsed.minorVersion})</td></tr>
      <tr><th>Access Flags</th><td>${parsed.flagNames.join(', ') || 'none'} (0x${parsed.accessFlags.toString(16).padStart(4, '0')})</td></tr>
      <tr><th>Fields</th><td>${parsed.fieldsCount}</td></tr>
      <tr><th>Methods</th><td>${parsed.methodsCount}</td></tr>
      <tr><th>Constant Pool</th><td>${parsed.cpCount} entries</td></tr>
    </table>`;
  }

  _buildManifestHTML(manifest) {
    // Highlight security-relevant keys
    const securityKeys = new Set(['Main-Class', 'Class-Path', 'Premain-Class', 'Agent-Class',
      'Boot-Class-Path', 'Can-Retransform-Classes', 'Can-Redefine-Classes', 'Permissions',
      'Codebase', 'Trusted-Library', 'Sealed']);

    let html = '<table class="jar-table jar-manifest-table">';
    for (const [key, value] of Object.entries(manifest.attrs)) {
      const cls = securityKeys.has(key) ? ' class="jar-manifest-security"' : '';
      html += `<tr${cls}><th>${this._esc(key)}</th><td>${this._esc(value)}</td></tr>`;
    }
    html += '</table>';

    if (manifest.sections.length > 0) {
      html += `<div class="jar-manifest-sections"><strong>Per-entry attributes:</strong> ${manifest.sections.length} section(s)</div>`;
    }
    return html;
  }

  _buildClassListHTML(parsedClasses, truncated) {
    let html = `<table class="jar-table jar-class-table">
      <thead><tr><th>Class</th><th>Java</th><th>Super</th><th>Flags</th><th>Fields</th><th>Methods</th><th>CP</th><th>Size</th></tr></thead><tbody>`;
    for (const c of parsedClasses) {
      const name = c.thisClass.replace(/\//g, '.');
      html += `<tr>
        <td title="${this._esc(name)}">${this._esc(name.length > 60 ? '...' + name.slice(-57) : name)}</td>
        <td>${this._esc(c.javaVersion)}</td>
        <td title="${this._esc(c.superClass.replace(/\//g, '.'))}">${this._esc(c.superClass.replace(/.*\//, ''))}</td>
        <td>${c.flagNames.join(', ')}</td>
        <td>${c.fieldsCount}</td>
        <td>${c.methodsCount}</td>
        <td>${c.cpCount}</td>
        <td>${this._fmtBytes(c.size || 0)}</td>
      </tr>`;
    }
    html += '</tbody></table>';
    if (truncated) html += `<div class="jar-truncated">⚡ Showing first 1,000 classes only</div>`;
    return html;
  }

  _buildStringConstantsHTML(strings, analysis) {
    const suspiciousValues = new Set(analysis.suspicious.map(s => s.value));
    const urlValues = new Set(analysis.urls);

    let html = '<div class="jar-string-list">';
    for (const s of strings) {
      const v = s.value || s;
      if (typeof v !== 'string') continue;
      const isSusp = suspiciousValues.has(v);
      const isUrl = urlValues.has(v) || /^(https?|ldaps?|rmi|ftp):\/\//.test(v);
      const cls = isSusp ? 'jar-string-suspicious' : isUrl ? 'jar-string-url' : '';
      const prefix = s.index !== undefined ? `<span class="jar-cp-index">#${s.index}</span> ` : '';
      html += `<div class="jar-string-entry${cls ? ' ' + cls : ''}">${prefix}<code>${this._esc(v.length > 200 ? v.substring(0, 200) + '…' : v)}</code></div>`;
    }
    html += '</div>';
    return html;
  }

  _buildClassRefsHTML(classRefs) {
    const grouped = {};
    for (const ref of classRefs) {
      const dotted = ref.replace(/\//g, '.');
      const pkg = dotted.includes('.') ? dotted.replace(/\.[^.]+$/, '') : '(default)';
      if (!grouped[pkg]) grouped[pkg] = [];
      grouped[pkg].push(dotted);
    }
    let html = '<div class="jar-class-refs">';
    for (const [pkg, classes] of Object.entries(grouped).sort((a, b) => a[0].localeCompare(b[0]))) {
      html += `<div class="jar-ref-group"><strong>${this._esc(pkg)}</strong>`;
      for (const c of classes.sort()) {
        const simple = c.replace(/.*\./, '');
        html += `<span class="jar-ref-class">${this._esc(simple)}</span>`;
      }
      html += '</div>';
    }
    html += '</div>';
    return html;
  }

  _buildSuspiciousHTML(suspicious) {
    // Group by severity
    const bySeverity = { critical: [], high: [], medium: [], low: [] };
    const seen = new Set();
    for (const s of suspicious) {
      const key = s.api + ':' + s.value;
      if (seen.has(key)) continue;
      seen.add(key);
      (bySeverity[s.severity] || bySeverity.medium).push(s);
    }

    let html = '<div class="jar-suspicious-list">';
    for (const level of ['critical', 'high', 'medium', 'low']) {
      for (const s of bySeverity[level]) {
        html += `<div class="jar-suspicious-item jar-sev-${level}">
          <span class="jar-sev-badge jar-sev-badge-${level}">${level.toUpperCase()}</span>
          <strong>${this._esc(s.api)}</strong> — ${this._esc(s.desc)}
          ${s.mitre ? `<span class="jar-mitre">${this._esc(s.mitre)}</span>` : ''}
          <div class="jar-suspicious-value"><code>${this._esc(s.value.length > 120 ? s.value.substring(0, 120) + '…' : s.value)}</code></div>
        </div>`;
      }
    }
    html += '</div>';
    return html;
  }

  _buildDependenciesHTML(imports) {
    // Categorize
    const categories = { 'java.': [], 'javax.': [], 'sun.': [], 'com.sun.': [], 'org.': [], 'com.': [], 'Other': [] };
    for (const imp of imports) {
      let placed = false;
      for (const prefix of ['java.', 'javax.', 'sun.', 'com.sun.']) {
        if (imp.startsWith(prefix)) { categories[prefix].push(imp); placed = true; break; }
      }
      if (!placed) {
        if (imp.startsWith('org.')) categories['org.'].push(imp);
        else if (imp.startsWith('com.')) categories['com.'].push(imp);
        else categories['Other'].push(imp);
      }
    }

    let html = '<div class="jar-deps">';
    const labels = { 'java.': '☕ Java Standard', 'javax.': '☕ Java Extensions', 'sun.': '⚙️ Sun Internal', 'com.sun.': '⚙️ Sun/Oracle', 'org.': '📦 Open Source (org.)', 'com.': '📦 Commercial/Other (com.)', 'Other': '📦 Other' };
    for (const [prefix, pkgs] of Object.entries(categories)) {
      if (pkgs.length === 0) continue;
      html += `<div class="jar-dep-group"><strong>${labels[prefix]}</strong> (${pkgs.length})`;
      html += '<div class="jar-dep-list">';
      for (const p of pkgs) html += `<span class="jar-dep-pkg">${this._esc(p)}</span>`;
      html += '</div></div>';
    }
    html += '</div>';
    return html;
  }

  _buildResourcesHTML(configEntries, resourceEntries) {
    let html = '';
    if (configEntries.length > 0) {
      html += '<h4 style="margin:6px 0">Configuration Files</h4><table class="jar-table"><thead><tr><th>Path</th><th>Size</th><th></th></tr></thead><tbody>';
      for (const e of configEntries) {
        html += `<tr><td>${this._esc(e.path)}</td><td>${this._fmtBytes(e.size)}</td><td><button class="jar-open-btn" data-jar-open="${this._esc(e.path)}">Open</button></td></tr>`;
      }
      html += '</tbody></table>';
    }
    if (resourceEntries.length > 0) {
      const displayEntries = resourceEntries.slice(0, 200);
      html += `<h4 style="margin:12px 0 6px">Other Resources (${resourceEntries.length})</h4><table class="jar-table"><thead><tr><th>Path</th><th>Size</th><th></th></tr></thead><tbody>`;
      for (const e of displayEntries) {
        html += `<tr><td>${this._esc(e.path)}</td><td>${this._fmtBytes(e.size)}</td><td><button class="jar-open-btn" data-jar-open="${this._esc(e.path)}">Open</button></td></tr>`;
      }
      html += '</tbody></table>';
      if (resourceEntries.length > 200) html += `<div class="jar-truncated">⚡ Showing first 200 of ${resourceEntries.length} resources</div>`;
    }
    return html;
  }

  // ═════════════════════════════════════════════════════════════════════════
  //  Tabs (bin-style)
  // ═════════════════════════════════════════════════════════════════════════
  _buildTabsHTML(tabs) {
    if (!tabs || tabs.length === 0) {
      return '<div class="jar-tabs jar-tabs-empty"><em>No tabbed content available for this archive.</em></div>';
    }
    let bar = '<div class="jar-tab-bar" role="tablist">';
    let panes = '<div class="jar-tab-panes">';
    tabs.forEach((t, i) => {
      const active = i === 0 ? ' active' : '';
      const countHTML = t.count != null ? ` <span class="jar-tab-count">${t.count}</span>` : '';
      bar += `<button type="button" class="jar-tab-btn${active}" role="tab" data-jar-tab="${t.key}" aria-selected="${i === 0}">${t.label}${countHTML}<span class="jar-tab-hits" hidden></span></button>`;
      panes += `<div class="jar-tab-pane${active}" role="tabpanel" data-jar-tab-pane="${t.key}"${i === 0 ? '' : ' hidden'}>${t.html}</div>`;
    });
    bar += '</div>';
    panes += '</div>';
    return `<div class="jar-tabs">${bar}${panes}</div>`;
  }

  _wireTabs(wrap) {
    const bar = wrap.querySelector('.jar-tab-bar');
    if (!bar) return;
    bar.addEventListener('click', (e) => {
      const btn = e.target.closest('.jar-tab-btn');
      if (!btn) return;
      const key = btn.getAttribute('data-jar-tab');
      // Buttons
      bar.querySelectorAll('.jar-tab-btn').forEach(b => {
        const on = b === btn;
        b.classList.toggle('active', on);
        b.setAttribute('aria-selected', on ? 'true' : 'false');
      });
      // Panes
      wrap.querySelectorAll('.jar-tab-pane').forEach(p => {
        const on = p.getAttribute('data-jar-tab-pane') === key;
        p.classList.toggle('active', on);
        if (on) p.removeAttribute('hidden');
        else p.setAttribute('hidden', '');
      });
    });
  }

  // ═════════════════════════════════════════════════════════════════════════
  //  File tree (nested archive browser)
  // ═════════════════════════════════════════════════════════════════════════
  _buildFileTreeHTML(entries) {
    // Build nested tree from flat entry list.
    // Root is a synthetic folder; children keyed by path segment.
    const root = { children: new Map(), files: [] };
    // Sort so parent dirs precede children, and folders first within a level.
    const sorted = [...entries].sort((a, b) => a.path.localeCompare(b.path));
    for (const e of sorted) {
      if (e.dir) continue; // skip explicit dir entries; we synthesise folders from file paths
      const parts = e.path.split('/').filter(Boolean);
      if (parts.length === 0) continue;
      let node = root;
      for (let i = 0; i < parts.length - 1; i++) {
        const seg = parts[i];
        if (!node.children.has(seg)) node.children.set(seg, { children: new Map(), files: [] });
        node = node.children.get(seg);
      }
      node.files.push({ name: parts[parts.length - 1], entry: e });
    }
    // Render recursively. Folders are collapsed by default.
    const renderNode = (node, pathPrefix, depth) => {
      let html = '';
      // Folder children first (sorted by name)
      const folderNames = [...node.children.keys()].sort((a, b) => a.localeCompare(b));
      for (const name of folderNames) {
        const child = node.children.get(name);
        const childPath = pathPrefix ? pathPrefix + '/' + name : name;
        const fileCount = this._countFilesInNode(child);
        html += `<li class="jar-tree-folder" data-jar-folder-path="${this._esc(childPath)}">
          <div class="jar-tree-row jar-tree-folder-row" tabindex="0" role="button" aria-expanded="false">
            <span class="jar-tree-caret" aria-hidden="true">▸</span>
            <span class="jar-tree-icon" aria-hidden="true">📁</span>
            <span class="jar-tree-name">${this._esc(name)}</span>
            <span class="jar-tree-meta">${fileCount} item${fileCount === 1 ? '' : 's'}</span>
          </div>
          <ul class="jar-tree-children" hidden>${renderNode(child, childPath, depth + 1)}</ul>
        </li>`;
      }
      // Files (sorted by name)
      const files = [...node.files].sort((a, b) => a.name.localeCompare(b.name));
      for (const f of files) {
        const icon = f.name.toLowerCase().endsWith('.class') ? '☕'
          : /\.(xml|properties|yml|yaml|json|txt|mf)$/i.test(f.name) ? '📝'
          : /\.(jar|war|ear|zip)$/i.test(f.name) ? '📦'
          : /\.(png|jpe?g|gif|bmp|svg|ico)$/i.test(f.name) ? '🖼'
          : '📄';
        html += `<li class="jar-tree-file" data-jar-file-name="${this._esc(f.name)}">
          <div class="jar-tree-row jar-tree-file-row">
            <span class="jar-tree-caret" aria-hidden="true"></span>
            <span class="jar-tree-icon" aria-hidden="true">${icon}</span>
            <span class="jar-tree-name" title="${this._esc(f.entry.path)}">${this._esc(f.name)}</span>
            <span class="jar-tree-meta">${this._fmtBytes(f.entry.size)}</span>
            <button type="button" class="jar-open-btn" data-jar-open="${this._esc(f.entry.path)}">Open</button>
          </div>
        </li>`;
      }
      return html;
    };
    const body = renderNode(root, '', 0);
    if (!body) return '<div class="jar-findings-empty">Archive is empty.</div>';
    return `<ul class="jar-tree" role="tree">${body}</ul>`;
  }

  _countFilesInNode(node) {
    let n = node.files.length;
    for (const child of node.children.values()) n += this._countFilesInNode(child);
    return n;
  }

  _wireFileTree(wrap) {
    const tree = wrap.querySelector('.jar-tree');
    if (!tree) return;

    const toggleFolder = (li, force) => {
      const row = li.querySelector(':scope > .jar-tree-folder-row');
      const kids = li.querySelector(':scope > .jar-tree-children');
      if (!row || !kids) return;
      const currentlyOpen = !kids.hasAttribute('hidden');
      const open = typeof force === 'boolean' ? force : !currentlyOpen;
      if (open) { kids.removeAttribute('hidden'); row.setAttribute('aria-expanded', 'true'); li.classList.add('jar-tree-open'); }
      else { kids.setAttribute('hidden', ''); row.setAttribute('aria-expanded', 'false'); li.classList.remove('jar-tree-open'); }
    };

    tree.addEventListener('click', (e) => {
      // Open button — don't intercept (handled by outer wrap listener)
      if (e.target.closest('[data-jar-open]')) return;
      const folderRow = e.target.closest('.jar-tree-folder-row');
      if (folderRow) {
        toggleFolder(folderRow.parentElement);
      }
    });
    tree.addEventListener('keydown', (e) => {
      if (e.key !== 'Enter' && e.key !== ' ') return;
      const folderRow = e.target.closest('.jar-tree-folder-row');
      if (folderRow) {
        e.preventDefault();
        toggleFolder(folderRow.parentElement);
      }
    });

    // Expand/Collapse all buttons
    const pane = wrap.querySelector('.jar-tree-pane');
    if (pane) {
      pane.addEventListener('click', (e) => {
        const btn = e.target.closest('.jar-tree-toggle-all');
        if (!btn) return;
        const action = btn.getAttribute('data-action');
        const force = action === 'expand';
        tree.querySelectorAll('li.jar-tree-folder').forEach(li => toggleFolder(li, force));
      });
    }
  }

  // ═════════════════════════════════════════════════════════════════════════
  //  Search bar — tab- and tree-aware
  // ═════════════════════════════════════════════════════════════════════════
  _addSearchBar(wrap) {
    const bar = document.createElement('div');
    bar.className = 'jar-search-bar';
    bar.innerHTML = `<input type="text" class="jar-search-input" placeholder="🔍 Search manifest, classes, strings, APIs, tree…">
      <span class="jar-search-status" hidden></span>`;
    wrap.prepend(bar);

    const input = bar.querySelector('.jar-search-input');
    const status = bar.querySelector('.jar-search-status');
    let debounce = null;

    const rowSelectors = [
      '.jar-table tbody tr',
      '.jar-manifest-table tr',
      '.jar-string-entry',
      '.jar-suspicious-item',
      '.jar-ref-group',
      '.jar-dep-pkg',
      '.jar-obfuscation-list li',
    ].join(', ');

    const applyFilter = (q) => {
      // 1) Row-level filter across all panes (hidden tabs included — we'll switch to first hit below).
      let totalHits = 0;
      wrap.querySelectorAll(rowSelectors).forEach(el => {
        if (!q) { el.classList.remove('jar-hit', 'jar-no-hit'); return; }
        const match = el.textContent.toLowerCase().includes(q);
        el.classList.toggle('jar-hit', match);
        el.classList.toggle('jar-no-hit', !match);
        if (match) totalHits++;
      });

      // 2) Tab hit-count badges + auto-switch to first tab with hits.
      const tabBar = wrap.querySelector('.jar-tab-bar');
      const panes = wrap.querySelectorAll('.jar-tab-pane');
      let firstHitKey = null;
      panes.forEach(pane => {
        const key = pane.getAttribute('data-jar-tab-pane');
        const paneHits = q ? pane.querySelectorAll('.jar-hit').length : 0;
        const btn = tabBar && tabBar.querySelector(`.jar-tab-btn[data-jar-tab="${key}"]`);
        if (btn) {
          const hitsEl = btn.querySelector('.jar-tab-hits');
          if (hitsEl) {
            if (q && paneHits > 0) { hitsEl.textContent = ` ${paneHits}`; hitsEl.hidden = false; }
            else { hitsEl.textContent = ''; hitsEl.hidden = true; }
          }
          btn.classList.toggle('jar-tab-has-hits', q && paneHits > 0);
        }
        if (q && paneHits > 0 && !firstHitKey) firstHitKey = key;
      });
      if (firstHitKey && tabBar) {
        // Only switch if the current active tab has no hits.
        const activeBtn = tabBar.querySelector('.jar-tab-btn.active');
        const activeKey = activeBtn ? activeBtn.getAttribute('data-jar-tab') : null;
        const activePane = activeKey ? wrap.querySelector(`.jar-tab-pane[data-jar-tab-pane="${activeKey}"]`) : null;
        const activeHits = activePane ? activePane.querySelectorAll('.jar-hit').length : 0;
        if (activeHits === 0) {
          const targetBtn = tabBar.querySelector(`.jar-tab-btn[data-jar-tab="${firstHitKey}"]`);
          if (targetBtn) targetBtn.click();
        }
      }

      // 3) File tree: highlight matching names and auto-expand ancestor folders.
      const tree = wrap.querySelector('.jar-tree');
      if (tree) {
        // Clear previous highlights & auto-expansion.
        tree.querySelectorAll('.jar-tree-hit').forEach(el => el.classList.remove('jar-tree-hit'));
        tree.querySelectorAll('li.jar-tree-auto-expanded').forEach(li => {
          li.classList.remove('jar-tree-auto-expanded');
          const kids = li.querySelector(':scope > .jar-tree-children');
          const row = li.querySelector(':scope > .jar-tree-folder-row');
          if (kids) kids.setAttribute('hidden', '');
          if (row) row.setAttribute('aria-expanded', 'false');
          li.classList.remove('jar-tree-open');
        });

        if (q) {
          const fileLis = tree.querySelectorAll('li.jar-tree-file');
          let treeHits = 0;
          fileLis.forEach(li => {
            const name = (li.getAttribute('data-jar-file-name') || '').toLowerCase();
            const match = name.includes(q);
            if (match) {
              li.classList.add('jar-tree-hit');
              treeHits++;
              // Auto-expand ancestor folders
              let parent = li.parentElement; // <ul.jar-tree-children>
              while (parent && parent !== tree) {
                if (parent.tagName === 'LI' && parent.classList.contains('jar-tree-folder')) {
                  parent.classList.add('jar-tree-auto-expanded', 'jar-tree-open');
                  const kids = parent.querySelector(':scope > .jar-tree-children');
                  const row = parent.querySelector(':scope > .jar-tree-folder-row');
                  if (kids) kids.removeAttribute('hidden');
                  if (row) row.setAttribute('aria-expanded', 'true');
                }
                parent = parent.parentElement;
              }
            }
          });
          totalHits += treeHits;
        }
      }

      // 4) Status line
      if (q) { status.hidden = false; status.textContent = totalHits === 0 ? 'No matches' : `${totalHits} match${totalHits === 1 ? '' : 'es'}`; }
      else { status.hidden = true; status.textContent = ''; }
    };

    input.addEventListener('input', () => {
      clearTimeout(debounce);
      debounce = setTimeout(() => applyFilter(input.value.toLowerCase().trim()), 200);
    });
  }


  // ═════════════════════════════════════════════════════════════════════════
  //  Security analysis (for sidebar)
  // ═════════════════════════════════════════════════════════════════════════
  async analyzeForSecurity(buffer, fileName) {
    const f = {
      risk: 'info', hasMacros: false, macroCode: '', macroSize: 0, macroHash: '',
      autoExec: false, modules: [], externalRefs: [], metadata: {}, signatureMatches: [],
      interestingStrings: []
    };

    const bytes = new Uint8Array(buffer);
    const ext = (fileName || '').split('.').pop().toLowerCase();

    // ── Standalone .class file ──────────────────────────────────────────
    if (ext === 'class' || (JarRenderer.isJavaClass(bytes) && !this._isZip(bytes))) {
      return this._analyzeClassFile(f, bytes, fileName);
    }

    // ── JAR / WAR / EAR ────────────────────────────────────────────────
    try {
      const zip = await JSZip.loadAsync(buffer);
      return await this._analyzeJar(f, zip, bytes, fileName, ext);
    } catch {
      f.metadata['Format'] = 'Invalid JAR/ZIP';
      return f;
    }
  }

  // ── Analyze standalone class file ────────────────────────────────────
  _analyzeClassFile(f, bytes, fileName) {
    f.metadata['Format'] = 'Java Class File';
    f.metadata['Size'] = this._fmtBytes(bytes.length);

    const parsed = this._parseClassFile(bytes);
    if (!parsed) return f;

    f.metadata['Java Version'] = `Java ${parsed.javaVersion} (class ${parsed.majorVersion}.${parsed.minorVersion})`;
    f.metadata['Class'] = parsed.thisClass.replace(/\//g, '.');
    f.metadata['Super Class'] = parsed.superClass.replace(/\//g, '.');
    f.metadata['Access Flags'] = parsed.flagNames.join(', ') || 'none';
    f.metadata['Fields'] = String(parsed.fieldsCount);
    f.metadata['Methods'] = String(parsed.methodsCount);
    f.metadata['Constant Pool'] = `${parsed.cpCount} entries`;

    const analysis = this._analyzeStrings(parsed.strings);
    this._applyAnalysisToFindings(f, analysis, this._detectObfuscation([{ path: fileName }], parsed.strings));

    return f;
  }

  // ── Analyze JAR/WAR/EAR ──────────────────────────────────────────────
  async _analyzeJar(f, zip, bytes, fileName, ext) {
    const entries = [];
    const classEntries = [];
    let totalSize = 0;
    let manifestText = null;

    zip.forEach((path, entry) => {
      entries.push({ path, dir: entry.dir, size: entry._data ? (entry._data.uncompressedSize || 0) : 0 });
      if (!entry.dir) {
        totalSize += entry._data ? (entry._data.uncompressedSize || 0) : 0;
        if (path.toLowerCase().endsWith('.class')) classEntries.push({ path });
      }
    });

    // Detect type
    const hasWebInf = entries.some(e => e.path.startsWith('WEB-INF/'));
    const hasMetaApp = entries.some(e => e.path === 'META-INF/application.xml');
    const detectedType = hasMetaApp ? 'EAR' : hasWebInf ? 'WAR' : 'JAR';

    f.metadata['Format'] = `Java ${detectedType}`;
    f.metadata['Size'] = this._fmtBytes(bytes.length);
    f.metadata['Entries'] = `${entries.length} (${classEntries.length} classes)`;
    f.metadata['Uncompressed Size'] = this._fmtBytes(totalSize);

    // Read MANIFEST
    const manifestEntry = zip.file('META-INF/MANIFEST.MF') || zip.file('meta-inf/manifest.mf');
    if (manifestEntry) {
      try { manifestText = await manifestEntry.async('string'); } catch {}
    }
    if (manifestText) {
      const manifest = this._parseManifest(manifestText);
      if (manifest.attrs['Main-Class']) f.metadata['Main-Class'] = manifest.attrs['Main-Class'];
      if (manifest.attrs['Class-Path']) f.metadata['Class-Path'] = manifest.attrs['Class-Path'];
      if (manifest.attrs['Premain-Class']) {
        f.metadata['⚠ Premain-Class'] = manifest.attrs['Premain-Class'];
        f.interestingStrings.push({ type: IOC.PATTERN, url: `Java Agent: ${manifest.attrs['Premain-Class']}`, severity: 'high' });
      }
      if (manifest.attrs['Agent-Class']) {
        f.metadata['⚠ Agent-Class'] = manifest.attrs['Agent-Class'];
        f.interestingStrings.push({ type: IOC.PATTERN, url: `Dynamic Agent: ${manifest.attrs['Agent-Class']}`, severity: 'high' });
      }
    }

    // Parse class files
    const classLimit = Math.min(classEntries.length, 1000);
    const allStrings = [];
    const parsedClasses = [];
    let highestJava = 0;
    for (let i = 0; i < classLimit; i++) {
      try {
        const classFile = zip.file(classEntries[i].path);
        if (!classFile) continue;
        const classBytes = new Uint8Array(await classFile.async('arraybuffer'));
        const parsed = this._parseClassFile(classBytes);
        if (parsed) {
          parsedClasses.push(parsed);
          allStrings.push(...parsed.strings);
          if (parsed.majorVersion > highestJava) highestJava = parsed.majorVersion;
        }
      } catch {}
    }

    if (highestJava > 0) {
      f.metadata['Java Version'] = `Java ${JarRenderer.JAVA_VERSIONS[highestJava] || highestJava}+ (class ${highestJava})`;
    }

    const analysis = this._analyzeStrings(allStrings);
    const obfuscation = this._detectObfuscation(classEntries, allStrings);
    this._applyAnalysisToFindings(f, analysis, obfuscation);

    // Check for dangerous file types inside JAR
    const dangerousExts = new Set(['exe', 'dll', 'bat', 'cmd', 'ps1', 'vbs', 'sh', 'so', 'dylib']);
    for (const e of entries) {
      if (e.dir) continue;
      const eExt = e.path.split('.').pop().toLowerCase();
      if (dangerousExts.has(eExt)) {
        f.interestingStrings.push({ type: IOC.FILE_PATH, url: e.path, severity: 'medium', note: 'Suspicious resource inside JAR' });
        if (f.risk === 'info' || f.risk === 'low') f.risk = 'medium';
      }
    }

    // Check for nested JARs (dependency JARs)
    const nestedJars = entries.filter(e => !e.dir && e.path.toLowerCase().endsWith('.jar'));
    if (nestedJars.length > 0) {
      f.metadata['Nested JARs'] = String(nestedJars.length);
    }

    // Store detailed data for analysis copy
    const manifest = manifestText ? this._parseManifest(manifestText) : null;
    f.jarInfo = {
      manifest,
      classes: classEntries.map(c => c.path),
      dependencies: analysis.imports || [],
      suspiciousAPIs: analysis.suspicious || [],
      obfuscation,
      resources: entries.filter(e => !e.dir && !e.path.toLowerCase().endsWith('.class')).map(e => e.path),
      configFiles: entries.filter(e => !e.dir && JarRenderer.CONFIG_FILES.some(p => e.path.match(p))).map(e => e.path),
    };

    return f;
  }

  // ── Apply string analysis results to findings ────────────────────────
  _applyAnalysisToFindings(f, analysis, obfuscation) {
    // Suspicious APIs → interestingStrings
    for (const s of analysis.suspicious) {
      f.interestingStrings.push({
        type: IOC.PATTERN,
        url: `${s.api}: ${s.desc}`,
        severity: s.severity || 'medium'
      });
    }

    // URLs
    for (const url of analysis.urls) {
      f.interestingStrings.push({ type: IOC.URL, url, severity: 'info' });
    }
    f.externalRefs = analysis.urls.map(u => ({ type: IOC.URL, url: u, severity: 'info' }));

    // IPs
    for (const ip of analysis.ips) {
      f.interestingStrings.push({ type: IOC.IP, url: ip, severity: 'medium' });
    }

    // Obfuscation
    for (const o of obfuscation) {
      f.interestingStrings.push({ type: IOC.PATTERN, url: `Obfuscation: ${o}`, severity: 'high' });
    }

    // Risk assessment
    let criticalCount = 0, highCount = 0, mediumCount = 0;
    for (const s of analysis.suspicious) {
      if (s.severity === 'critical') criticalCount++;
      else if (s.severity === 'high') highCount++;
      else if (s.severity === 'medium') mediumCount++;
    }

    if (criticalCount > 0) f.risk = 'critical';
    else if (highCount >= 3 || obfuscation.length > 0) f.risk = 'high';
    else if (highCount > 0 || mediumCount >= 3) f.risk = 'medium';
    else if (mediumCount > 0) f.risk = 'low';
    else f.risk = 'info';
  }
}
