'use strict';
// ════════════════════════════════════════════════════════════════════════════
// eml-renderer.js — Parses and renders RFC 5322 / MIME email (.eml) files
// Pure text-based parser, no external dependencies.
// ════════════════════════════════════════════════════════════════════════════
class EmlRenderer {

  render(buffer) {
    const text = new TextDecoder('utf-8', { fatal: false }).decode(
      new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer)
    );
    const wrap = document.createElement('div');
    wrap.className = 'eml-view';

    try {
      const email = this._parse(text);

      // Header table
      const tbl = document.createElement('table');
      tbl.className = 'msg-header-table';
      const headerRows = [
        ['From', email.from],
        ['To', email.to],
        ['Cc', email.cc],
        ['Date', email.date],
        ['Subject', email.subject],
      ];
      if (email.replyTo && email.replyTo !== email.from) {
        headerRows.push(['Reply-To', email.replyTo]);
      }
      for (const [lbl, val] of headerRows) {
        if (!val) continue;
        const tr = document.createElement('tr');
        const tdL = document.createElement('td');
        tdL.className = 'lbl';
        tdL.textContent = lbl;
        const tdV = document.createElement('td');
        tdV.textContent = val;
        tr.appendChild(tdL);
        tr.appendChild(tdV);
        tbl.appendChild(tr);
      }
      wrap.appendChild(tbl);

      // Attachments — Extracted Files table (shown at top for easy access)
      if (email.attachments.length) {
        const banner = document.createElement('div'); banner.className = 'doc-extraction-banner';
        banner.innerHTML = `<strong>Attachments (${email.attachments.length})</strong> — click any file to open it for analysis.`;
        wrap.appendChild(banner);

        const attTbl = document.createElement('table'); attTbl.className = 'zip-table';
        const thead = document.createElement('thead');
        const hr = document.createElement('tr');
        for (const h of ['', 'Filename', 'Size', '']) {
          const th = document.createElement('th'); th.textContent = h; hr.appendChild(th);
        }
        thead.appendChild(hr); attTbl.appendChild(thead);

        const tbody = document.createElement('tbody');
        for (const att of email.attachments) {
          const tr = document.createElement('tr');
          if (att.data) tr.classList.add('zip-row-clickable');

          // Icon
          const tdIcon = document.createElement('td'); tdIcon.className = 'zip-icon';
          tdIcon.textContent = this._getFileIcon(att.filename); tr.appendChild(tdIcon);

          // Filename
          const tdName = document.createElement('td'); tdName.className = 'zip-path';
          tdName.textContent = att.filename || 'unnamed';
          const ext = (att.filename || '').split('.').pop().toLowerCase();
          if (/^(exe|dll|scr|com|bat|cmd|vbs|js|ps1|hta|msi|jar)$/.test(ext)) {
            const badge = document.createElement('span'); badge.className = 'zip-badge-danger'; badge.textContent = 'EXECUTABLE';
            tdName.appendChild(badge);
          }
          tr.appendChild(tdName);

          // Size
          const tdSize = document.createElement('td'); tdSize.className = 'zip-size';
          tdSize.textContent = att.size ? this._fmtSize(att.size) : '—'; tr.appendChild(tdSize);

          // Actions
          const tdAction = document.createElement('td'); tdAction.className = 'zip-action';
          if (att.data) {
            const openBtn = document.createElement('span'); openBtn.className = 'zip-badge-open';
            openBtn.textContent = '🔍 Open';
            openBtn.title = `Open ${att.filename} for analysis`;
            openBtn.addEventListener('click', (ev) => {
              ev.stopPropagation();
              this._openAttachment(att, wrap);
            });
            tdAction.appendChild(openBtn);

            const dlBtn = document.createElement('span'); dlBtn.className = 'zip-badge-open';
            dlBtn.style.marginLeft = '6px';
            dlBtn.textContent = '⬇';
            dlBtn.title = `Download ${att.filename}`;
            dlBtn.addEventListener('click', (ev) => {
              ev.stopPropagation();
              this._downloadAttachment(att);
            });
            tdAction.appendChild(dlBtn);
          }
          tr.appendChild(tdAction);

          // Row click opens file
          if (att.data) {
            tr.addEventListener('click', () => this._openAttachment(att, wrap));
          }

          tbody.appendChild(tr);
        }
        attTbl.appendChild(tbody); wrap.appendChild(attTbl);
      }

      // Subject line
      if (email.subject) {
        const subj = document.createElement('div');
        subj.className = 'msg-subject';
        subj.textContent = email.subject;
        wrap.appendChild(subj);
      }

      // Auth results
      if (email.authResults) {
        const ad = document.createElement('div');
        ad.className = 'eml-auth-results';
        ad.textContent = '🔐 ' + email.authResults;
        wrap.appendChild(ad);
      }

      // Body
      const bodyFrame = document.createElement('div');
      bodyFrame.className = 'msg-body-frame';
      if (email.bodyHtml) {
        this._sanitize(email.bodyHtml, bodyFrame);
      } else {
        bodyFrame.textContent = email.bodyText || '(no body content)';
      }
      wrap.appendChild(bodyFrame);

    } catch (e) {
      const eb = document.createElement('div');
      eb.className = 'error-box';
      const h3 = document.createElement('h3');
      h3.textContent = 'Failed to parse .eml file';
      eb.appendChild(h3);
      const p = document.createElement('p');
      p.textContent = e.message;
      eb.appendChild(p);
      wrap.appendChild(eb);
    }

    // Expose the raw decoded source so the shared sidebar IOC sweep in
    // app-load.js scans the real message text instead of falling back to
    // `docEl.textContent`. Without this, adjacent header-table <td>s (e.g.
    // "…action required" in Subject + "Reply-To" label + "attacker@…" value)
    // collapse into a single whitespace-free blob and the generic email
    // regex greedily extends the local-part, producing bogus IOCs like
    // `requiredReply-Toattacker@evil.example.com`.
    wrap._rawText = text;
    return wrap;
  }

  async analyzeForSecurity(buffer) {
    const f = {
      risk: 'low', hasMacros: false, macroSize: 0, macroHash: '',
      autoExec: [], modules: [], externalRefs: [], metadata: {}
    };

    try {
      const text = new TextDecoder('utf-8', { fatal: false }).decode(
        new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer)
      );
      const email = this._parse(text);

      f.metadata = {};
      if (email.from) f.metadata.from = email.from;
      if (email.to) f.metadata.to = email.to;
      if (email.cc) f.metadata.cc = email.cc;
      if (email.replyTo) f.metadata.replyTo = email.replyTo;
      if (email.date) f.metadata.date = email.date;
      if (email.subject) f.metadata.subject = email.subject;
      if (email.messageId) f.metadata.messageId = email.messageId;

      // Surface parsed auth-results so the Summary writer's
      // "Email Authentication" block has content. SPF / DKIM / DMARC verdicts
      // are embedded inside Authentication-Results on most MTAs (we don't
      // get them as distinct headers), so forward the combined string to
      // each field — the writer prints only what's set.
      if (email.authResults) {
        f.authResults = email.authResults;
        const ar = email.authResults.toLowerCase();
        const pick = (tag) => {
          const m = ar.match(new RegExp('\\b' + tag + '\\s*=\\s*([a-z]+)'));
          return m ? m[1] : '';
        };
        const spfV = pick('spf'), dkimV = pick('dkim'), dmarcV = pick('dmarc');
        if (spfV) f.spf = spfV;
        if (dkimV) f.dkim = dkimV;
        if (dmarcV) f.dmarc = dmarcV;
      }

      // Attachment inventory for the Summary writer's _copyAnalysisEML helper.
      // We use the already-parsed MIME attachment list rather than re-parsing.
      if (email.attachments && email.attachments.length) {
        f.metadata.attachments = email.attachments.map(a => ({
          name: a.filename || '(unnamed)',
          size: a.size || 0,
        }));
      }


      // ── Dedup helpers ──────────────────────────────────────────────────
      // `raw` is the verbatim match text (used as _highlightText so the
      // sidebar navigator can locate the span inside the rendered body
      // even when the cleaned URL differs from what the eye sees).
      const seenEmails = new Set();
      const seenUrls = new Set();
      const seenIps = new Set();
      const pushEmail = (addr, note, severity, raw) => {
        if (!addr) return;
        const key = addr.toLowerCase();
        if (seenEmails.has(key)) return;
        seenEmails.add(key);
        const ref = { type: IOC.EMAIL, url: addr, severity: severity || 'info', note };
        if (raw) ref._highlightText = raw;
        f.externalRefs.push(ref);
      };
      const pushUrl = (url, note, severity, raw) => {
        if (!url) return;
        // Strip common trailing punctuation that is usually not part of the URL
        const clean = url.replace(/[.,;:!?)\]>'"]+$/, '');
        const key = clean.toLowerCase();
        if (seenUrls.has(key)) return;
        seenUrls.add(key);
        // ── SafeLink / URLDefense unwrap ──
        // Proofpoint URLDefense and Microsoft SafeLinks wrap the real
        // destination inside a vendor-controlled URL. Surface BOTH: the
        // wrapper (info) so analysts see the email provider, and the
        // decoded inner URL (high) — that's the URL the victim would
        // actually reach if they clicked. Each extracted child IOC's
        // `_highlightText` points to the wrapper so the sidebar
        // navigator still flashes the visible wrapper text in the body.
        let unwrapped = null;
        if (typeof EncodedContentDetector !== 'undefined') {
          try { unwrapped = EncodedContentDetector.unwrapSafeLink(clean); }
          catch (_) { unwrapped = null; }
        }
        if (unwrapped) {
          const wrapperRef = {
            type: IOC.URL,
            url: clean,
            severity: 'info',
            note: note ? `${unwrapped.provider} wrapper (${note})` : `${unwrapped.provider} wrapper`,
          };
          if (raw) wrapperRef._highlightText = raw;
          f.externalRefs.push(wrapperRef);

          // Push the decoded inner URL at high severity. An unwrapped
          // SafeLink has bypassed the vendor's click-time check by the
          // time an analyst is reading the message, so it warrants a
          // closer look than a bare in-body URL.
          const innerClean = (unwrapped.originalUrl || '').replace(/[.,;:!?)\]>'"]+$/, '');
          const innerKey = innerClean.toLowerCase();
          if (innerClean && !seenUrls.has(innerKey)) {
            seenUrls.add(innerKey);
            const innerRef = {
              type: IOC.URL,
              url: innerClean,
              severity: 'high',
              note: note ? `Extracted from ${unwrapped.provider} (${note})` : `Extracted from ${unwrapped.provider}`,
              _highlightText: raw || clean,
            };
            f.externalRefs.push(innerRef);
          }

          // Microsoft SafeLinks embeds the recipient email in the `data`
          // parameter — surface it as an EMAIL IOC for pivot.
          if (unwrapped.emails && unwrapped.emails.length) {
            for (const em of unwrapped.emails) {
              pushEmail(em, `Extracted from ${unwrapped.provider}`, 'medium', raw || clean);
            }
          }
          return;
        }

        const ref = { type: IOC.URL, url: clean, severity: severity || 'medium', note };
        if (raw) ref._highlightText = raw;
        f.externalRefs.push(ref);
      };
      const pushIp = (ip, note, severity, raw) => {
        if (!ip || seenIps.has(ip)) return;
        // Too few digits → likely version string (e.g. 6.0.0.0), not a real IP
        if (ip.replace(/\D/g, '').length < 5) return;
        seenIps.add(ip);
        const ref = { type: IOC.IP, url: ip, severity: severity || 'medium', note };
        if (raw) ref._highlightText = raw;
        f.externalRefs.push(ref);
      };


      const EMAIL_RE  = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
      const URL_RE    = /https?:\/\/[^\s"'<>()]+/gi;
      const IPV4_RE   = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;

      // ── 1. Sender IP from Received chain ───────────────────────────────
      // Received headers live in the raw header block; walk every Received
      // line, pull any IPv4 inside [brackets] or (parens) which is where MTAs
      // record the peer address.
      const norm = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
      const headerBlock = (() => {
        const i = norm.indexOf('\n\n');
        return i >= 0 ? norm.substring(0, i) : norm;
      })();
      const unfoldedHeaders = headerBlock.replace(/\n[ \t]+/g, ' ');
      for (const line of unfoldedHeaders.split('\n')) {
        if (!/^Received:/i.test(line)) continue;
        const ips = line.match(IPV4_RE) || [];
        for (const ip of ips) {
          // Skip obvious non-routable noise
          if (/^(0\.|127\.|255\.)/.test(ip)) continue;
          pushIp(ip, 'Received header', 'medium');
        }
      }

      // ── 2. Header addresses (From / To / Cc / Reply-To) ────────────────
      const headerMap = [
        ['From', email.from],
        ['To', email.to],
        ['Cc', email.cc],
        ['Reply-To', email.replyTo],
      ];
      for (const [label, raw] of headerMap) {
        if (!raw) continue;
        const addrs = raw.match(EMAIL_RE) || [];
        for (const a of addrs) pushEmail(a, label, 'info');
      }

      // ── 3. Suspicious: Reply-To different from From (detection) ────────
      let replyToMismatch = false;
      if (email.replyTo && email.from) {
        const fromAddr = (email.from.match(EMAIL_RE) || [])[0] || email.from;
        const rtAddr   = (email.replyTo.match(EMAIL_RE) || [])[0] || email.replyTo;
        if (fromAddr.toLowerCase() !== rtAddr.toLowerCase()) {
          replyToMismatch = true;
          f.externalRefs.push({
            type: IOC.PATTERN,
            url: `Reply-To (${rtAddr}) differs from From (${fromAddr})`,
            severity: 'medium'
          });
          if (f.risk === 'low') f.risk = 'medium';
        }
      }

      // ── 4. URLs and emails in body (plain + HTML) ──────────────────────
      // matchAll so we can carry `m[0]` as _highlightText — necessary when
      // pushUrl's trailing-punctuation strip means the cleaned URL would
      // never match the rendered body text verbatim.
      const bodies = [email.bodyText || '', email.bodyHtml || ''];
      for (const body of bodies) {
        if (!body) continue;
        for (const m of body.matchAll(URL_RE)) {
          pushUrl(m[0], 'in body', 'medium', m[0]);
        }
        for (const m of body.matchAll(EMAIL_RE)) {
          pushEmail(m[0], 'in body', 'info', m[0]);
        }
      }

      // Also extract href= targets in HTML — catches cases where the visible
      // text differs from the target anchor.
      if (email.bodyHtml) {
        const hrefs = email.bodyHtml.match(/href\s*=\s*["']([^"']+)["']/gi) || [];
        for (const h of hrefs) {
          const m = h.match(/href\s*=\s*["']([^"']+)["']/i);
          if (m && /^https?:\/\//i.test(m[1])) pushUrl(m[1], 'href target', 'medium', m[1]);
        }
      }


      // ── 5. Dangerous attachments ───────────────────────────────────────
      const dangerExts = /\.(exe|scr|com|pif|bat|cmd|vbs|vbe|js|jse|wsf|wsh|ps1|hta|lnk|cpl|msi|dll|reg|inf|sct|gadget)$/i;
      const imageExts = /\.(png|jpe?g|gif|bmp|webp)$/i;
      // QR-decode cap for image attachments. QR-based phishing ("quishing")
      // lures the recipient into scanning an image attachment that encodes
      // the real payload URL — the URL never appears as text in the
      // message body, so without this pass it slips past every text-only
      // URL extractor above.
      const QR_ATT_CAP = 16;
      let qrAttScanned = 0;
      let qrAttIndex = 0;
      const qrPromises = [];
      for (const att of email.attachments) {
        if (dangerExts.test(att.filename)) {
          f.externalRefs.push({
            type: IOC.ATTACHMENT,
            url: att.filename,
            severity: 'high'
          });
          f.risk = 'high';
        }

        // ── QR-decode image attachments ────────────────────────────────
        if (typeof QrDecoder !== 'undefined' && att.data && att.data.length &&
            qrAttScanned < QR_ATT_CAP && imageExts.test(att.filename || '')) {
          qrAttScanned++;
          const idx = ++qrAttIndex;
          const extLower = (att.filename.split('.').pop() || 'png').toLowerCase();
          const mime = extLower === 'jpg' || extLower === 'jpeg' ? 'image/jpeg' :
                       'image/' + extLower;
          // decodeBlob needs a real ArrayBuffer — attachments are stored as
          // Uint8Array, so copy into a standalone buffer to avoid subarray
          // view issues with URL.createObjectURL.
          const ab = new Uint8Array(att.data).buffer;
          qrPromises.push(
            QrDecoder.decodeBlob(ab, mime)
              .then(qr => { if (qr) QrDecoder.applyToFindings(f, qr, `eml-attachment-${idx}`); })
              .catch(() => { /* swallow */ })
          );
        }
      }

      // Wait for every in-flight QR decode to resolve — _renderSidebar
      // reads a one-shot snapshot of findings after this method resolves,
      // so fire-and-forget would land the QR IOC after first paint.
      if (qrPromises.length) {
        try { await Promise.all(qrPromises); } catch (_) { /* swallow */ }
      }


      // ── 6. Tracking pixels in HTML body ────────────────────────────────
      // Emitted as IOC.URL (not PATTERN) so they land in the IOCs pane with
      // the same click-to-copy / navigate behaviour as every other URL.
      if (email.bodyHtml) {
        const imgMatches = email.bodyHtml.match(/<img[^>]+>/gi) || [];
        for (const img of imgMatches) {
          if (/width\s*[=:]\s*["']?[01](?:px)?["']?/i.test(img) &&
              /height\s*[=:]\s*["']?[01](?:px)?["']?/i.test(img)) {
            const srcM = img.match(/src\s*=\s*["']?([^"'\s>]+)/i);
            if (srcM && /^https?:\/\//i.test(srcM[1])) {
              // Override any earlier in-body push with the richer note
              const clean = srcM[1].replace(/[.,;:!?)\]>'"]+$/, '');
              const existing = f.externalRefs.find(r => r.type === IOC.URL && r.url === clean);
              if (existing) {
                existing.note = 'Tracking pixel (1x1 image)';
                existing.severity = 'medium';
              } else {
                pushUrl(clean, 'Tracking pixel (1x1 image)', 'medium');
              }
              if (f.risk === 'low') f.risk = 'medium';
            }
          }
        }
      }

      // ── 7. Auth results (detection) ────────────────────────────────────
      // Three-way authentication failure (SPF+DKIM+DMARC all fail/none) is
      // a strong phishing signal — stronger than any single failing check.
      let authTripleFail = false;
      if (email.authResults) {
        const ar = email.authResults.toLowerCase();
        const failOrNone = v => v === 'fail' || v === 'softfail' || v === 'none' ||
                                v === 'neutral' || v === 'temperror' || v === 'permerror';
        const pickV = (tag) => {
          const m = ar.match(new RegExp('\\b' + tag + '\\s*=\\s*([a-z]+)'));
          return m ? m[1] : '';
        };
        const spfV = pickV('spf'), dkimV = pickV('dkim'), dmarcV = pickV('dmarc');
        authTripleFail = spfV && dkimV && dmarcV &&
          failOrNone(spfV) && failOrNone(dkimV) && failOrNone(dmarcV);

        if (ar.includes('fail') || ar.includes('none')) {
          f.externalRefs.push({
            type: IOC.PATTERN,
            url: 'SPF/DKIM/DMARC check: ' + email.authResults.substring(0, 200),
            severity: authTripleFail ? 'high' : 'medium'
          });
          if (f.risk === 'low') f.risk = 'medium';
        }
      }

      // ── Risk escalation ────────────────────────────────────────────────
      // URLs in the body + Reply-To mismatch is the classic phishing combo.
      // Triple-auth-fail + body URL is the classic spoofed-sender + payload
      // combo — every verified-origin check failed and the message still
      // carries a clickable URL.
      const hasBodyUrl = f.externalRefs.some(r => r.type === IOC.URL);
      if (replyToMismatch && hasBodyUrl && f.risk !== 'high') f.risk = 'high';
      if (authTripleFail && hasBodyUrl && f.risk !== 'high') f.risk = 'high';

      // Mirror classic-pivot metadata into the IOC table. Message-ID,
      // Reply-To, From, and To are the header-level pivots every
      // email-threat investigation starts from.
      mirrorMetadataIOCs(f, {
        messageId: IOC.PATTERN,
        replyTo:   IOC.EMAIL,
        from:      IOC.EMAIL,
        to:        IOC.EMAIL,
      });

    } catch (_) { /* parse failed — non-fatal */ }

    return f;
  }

  // ── MIME parser ─────────────────────────────────────────────────────────

  _parse(text) {
    const norm = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
    const sepIdx = norm.indexOf('\n\n');
    const headerBlock = sepIdx >= 0 ? norm.substring(0, sepIdx) : norm;
    const bodyBlock = sepIdx >= 0 ? norm.substring(sepIdx + 2) : '';

    const headers = this._parseHeaders(headerBlock);
    const email = {
      from: headers['from'] || '',
      to: headers['to'] || '',
      cc: headers['cc'] || '',
      date: headers['date'] || '',
      subject: this._decodeHeader(headers['subject'] || ''),
      replyTo: headers['reply-to'] || '',
      messageId: headers['message-id'] || '',
      authResults: headers['authentication-results'] || '',
      contentType: headers['content-type'] || 'text/plain',
      bodyText: '',
      bodyHtml: '',
      attachments: [],
    };

    // Decode subject if MIME-encoded
    email.from = this._decodeHeader(email.from);
    email.to = this._decodeHeader(email.to);
    email.cc = this._decodeHeader(email.cc);

    const ct = email.contentType.toLowerCase();
    const boundary = this._getBoundary(email.contentType);

    if (boundary) {
      this._parseMultipart(bodyBlock, boundary, email, headers);
    } else if (ct.includes('text/html')) {
      email.bodyHtml = this._decodeBody(bodyBlock, headers['content-transfer-encoding'] || '');
    } else {
      email.bodyText = this._decodeBody(bodyBlock, headers['content-transfer-encoding'] || '');
    }

    return email;
  }

  _parseHeaders(block) {
    // Unfold headers (lines starting with whitespace continue previous header)
    const unfolded = block.replace(/\n[ \t]+/g, ' ');
    const headers = {};
    for (const line of unfolded.split('\n')) {
      const idx = line.indexOf(':');
      if (idx > 0) {
        const key = line.substring(0, idx).trim().toLowerCase();
        const val = line.substring(idx + 1).trim();
        headers[key] = headers[key] ? headers[key] + ', ' + val : val;
      }
    }
    return headers;
  }

  _parseMultipart(body, boundary, email, parentHeaders) {
    const delim = '--' + boundary;
    const parts = body.split(delim);

    for (let i = 1; i < parts.length; i++) {
      let part = parts[i];
      if (part.startsWith('--')) break; // closing delimiter

      // Strip leading newline
      if (part.startsWith('\n')) part = part.substring(1);

      const sepIdx = part.indexOf('\n\n');
      if (sepIdx < 0) continue;

      const partHeaderBlock = part.substring(0, sepIdx);
      const partBody = part.substring(sepIdx + 2);
      const partHeaders = this._parseHeaders(partHeaderBlock);

      const pct = (partHeaders['content-type'] || 'text/plain').toLowerCase();
      const cte = partHeaders['content-transfer-encoding'] || '';
      const cd = partHeaders['content-disposition'] || '';

      // Nested multipart
      const subBoundary = this._getBoundary(partHeaders['content-type'] || '');
      if (subBoundary) {
        this._parseMultipart(partBody, subBoundary, email, partHeaders);
        continue;
      }

      // Attachment
      if (cd.toLowerCase().includes('attachment') || (cd.toLowerCase().includes('filename'))) {
        const fn = this._extractFilename(cd) || this._extractFilename(partHeaders['content-type'] || '') || 'attachment';
        const decoded = this._decodeBodyBinary(partBody, cte);
        email.attachments.push({ filename: fn, size: decoded.length, data: decoded });
        continue;
      }

      // Inline content
      if (pct.includes('text/html') && !email.bodyHtml) {
        email.bodyHtml = this._decodeBody(partBody, cte);
      } else if (pct.includes('text/plain') && !email.bodyText) {
        email.bodyText = this._decodeBody(partBody, cte);
      } else if (!pct.includes('text/')) {
        // Non-text inline = treat as attachment
        const fn = this._extractFilename(cd) || this._extractFilename(partHeaders['content-type'] || '') || 'inline-content';
        const decoded = this._decodeBodyBinary(partBody, cte);
        email.attachments.push({ filename: fn, size: decoded.length, data: decoded });
      }
    }
  }

  _getBoundary(ct) {
    const m = ct.match(/boundary\s*=\s*"?([^";\s]+)"?/i);
    return m ? m[1] : null;
  }

  _extractFilename(headerVal) {
    // Try filename*= (RFC 5987) first, then filename=
    let m = headerVal.match(/filename\*\s*=\s*[^']*'[^']*'([^;\s"]+)/i);
    if (m) return decodeURIComponent(m[1]);
    m = headerVal.match(/filename\s*=\s*"?([^";\n]+)"?/i);
    if (m) return m[1].trim();
    m = headerVal.match(/name\s*=\s*"?([^";\n]+)"?/i);
    if (m) return m[1].trim();
    return null;
  }

  _decodeBody(body, cte) {
    const enc = (cte || '').toLowerCase().trim();
    if (enc === 'base64') {
      try { return atob(body.replace(/\s/g, '')); } catch (_) { return body; }
    }
    if (enc === 'quoted-printable') {
      return body
        .replace(/=\n/g, '')                           // soft line breaks
        .replace(/=([0-9A-Fa-f]{2})/g, (_, hex) =>
          String.fromCharCode(parseInt(hex, 16))
        );
    }
    return body;
  }

  _decodeBodyBinary(body, cte) {
    const enc = (cte || '').toLowerCase().trim();
    if (enc === 'base64') {
      try {
        const binaryStr = atob(body.replace(/\s/g, ''));
        const bytes = new Uint8Array(binaryStr.length);
        for (let i = 0; i < binaryStr.length; i++) bytes[i] = binaryStr.charCodeAt(i);
        return bytes;
      } catch (_) {
        return new TextEncoder().encode(body);
      }
    }
    if (enc === 'quoted-printable') {
      const decoded = body
        .replace(/=\n/g, '')
        .replace(/=([0-9A-Fa-f]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
      return new TextEncoder().encode(decoded);
    }
    return new TextEncoder().encode(body);
  }

  _decodeHeader(val) {
    if (!val) return val;
    // RFC 2047: =?charset?encoding?text?=
    return val.replace(/=\?([^?]+)\?([BbQq])\?([^?]*)\?=/g, (_, charset, enc, text) => {
      try {
        if (enc.toUpperCase() === 'B') {
          return atob(text);
        }
        // Q-encoding
        return text.replace(/_/g, ' ').replace(/=([0-9A-Fa-f]{2})/g, (__, h) =>
          String.fromCharCode(parseInt(h, 16))
        );
      } catch (_) { return text; }
    });
  }

  _sanitize(html, container) {
    // Sanitize HTML: strip scripts, event handlers, dangerous elements.
    //
    // NOTE: <a href> is deliberately *not* passed through as a live link.
    // Loupe is a forensic viewer — an analyst clicking a phishing URL in a
    // sample they are triaging would be a real-world safety problem. Anchors
    // are rewritten to inert <span class="eml-link-inert" title="<url>"> so
    // the visible text and the underlying href stay inspectable but nothing
    // navigates.
    const allowedTags = new Set([
      'p', 'br', 'div', 'span', 'b', 'i', 'u', 'em', 'strong', 'a', 'ul', 'ol', 'li',
      'table', 'tr', 'td', 'th', 'thead', 'tbody', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
      'pre', 'code', 'blockquote', 'hr', 'font', 'center', 'sub', 'sup', 'small', 'big',
      'dl', 'dt', 'dd', 'abbr', 'address', 'cite', 'q', 'mark',
    ]);
    // Dangerous elements to completely remove (not just strip tag)
    const dangerousTags = new Set(['script', 'style', 'meta', 'link', 'object', 'iframe', 'embed', 'svg', 'math', 'base', 'form']);
    const allowedAttrs = new Set(['style', 'class', 'align', 'valign', 'width', 'height', 'colspan', 'rowspan', 'dir', 'color', 'size', 'face']);

    const doc = new DOMParser().parseFromString(html, 'text/html');

    function walk(node, target) {
      for (const child of Array.from(node.childNodes)) {
        if (child.nodeType === 3) { // text node
          target.appendChild(document.createTextNode(child.textContent));
          continue;
        }
        if (child.nodeType !== 1) continue;
        const tag = child.tagName.toLowerCase();
        
        // Completely skip dangerous elements
        if (dangerousTags.has(tag)) continue;

        // ── Anchor → inert span ─────────────────────────────────────────
        // Rewrite every <a> as <span class="eml-link-inert"> so analysts
        // see the link text (and can hover to see the real href via the
        // title attribute) but a click cannot navigate anywhere.
        if (tag === 'a') {
          const span = document.createElement('span');
          span.className = 'eml-link-inert';
          const hrefAttr = child.getAttribute('href');
          if (hrefAttr) span.title = hrefAttr;
          walk(child, span);
          target.appendChild(span);
          continue;
        }

        // If not in allowed list, unwrap (keep children but not the tag)
        if (!allowedTags.has(tag)) {
          walk(child, target);
          continue;
        }
        
        const el = document.createElement(tag);
        
        // Copy allowed attributes with sanitization
        for (const attr of Array.from(child.attributes)) {
          const name = attr.name.toLowerCase();
          // Skip event handlers
          if (name.startsWith('on')) continue;
          if (!allowedAttrs.has(name)) continue;

          if (name === 'style') {

            // Comprehensive CSS XSS sanitization
            const cleanStyle = attr.value
              .replace(/expression\s*\(/gi, '')
              .replace(/javascript\s*:/gi, '')
              .replace(/vbscript\s*:/gi, '')
              .replace(/-moz-binding\s*:/gi, '')
              .replace(/behavior\s*:/gi, '')
              .replace(/url\s*\([^)]*\)/gi, '')  // Remove all url() to prevent data: exploits
              .replace(/\\[0-9a-f]{1,6}/gi, ''); // Remove unicode escapes that could spell javascript
            el.setAttribute(name, cleanStyle);
          } else {
            el.setAttribute(name, attr.value);
          }
        }
        
        walk(child, el);
        target.appendChild(el);
      }
    }

    if (doc.body) walk(doc.body, container);
  }

  _fmtSize(n) {
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(1) + ' MB';
  }

  _openAttachment(att, wrap) {
    if (!att.data) return;
    const file = new File([att.data], att.filename || 'attachment', { type: 'application/octet-stream' });
    wrap.dispatchEvent(new CustomEvent('open-inner-file', { bubbles: true, detail: file }));
  }

  _downloadAttachment(att) {
    if (!att.data) return;
    window.FileDownload.downloadBytes(
      att.data,
      att.filename || 'attachment',
      'application/octet-stream',
    );
  }

  _getFileIcon(name) {
    const ext = (name || '').split('.').pop().toLowerCase();
    if (['exe', 'dll', 'scr', 'com', 'msi'].includes(ext)) return '⚙️';
    if (['bat', 'cmd', 'ps1', 'vbs', 'js', 'sh'].includes(ext)) return '📜';
    if (['doc', 'docx', 'docm', 'odt', 'rtf'].includes(ext)) return '📄';
    if (['xls', 'xlsx', 'xlsm', 'ods', 'csv'].includes(ext)) return '📊';
    if (['ppt', 'pptx', 'pptm', 'odp'].includes(ext)) return '📽️';
    if (['pdf'].includes(ext)) return '📕';
    if (['zip', 'rar', '7z', 'tar', 'gz'].includes(ext)) return '📦';
    if (['jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg'].includes(ext)) return '🖼️';
    if (['txt', 'log', 'md'].includes(ext)) return '📝';
    if (['html', 'htm', 'xml', 'json'].includes(ext)) return '🌐';
    if (['eml', 'msg'].includes(ext)) return '✉️';
    return '📄';
  }
}
