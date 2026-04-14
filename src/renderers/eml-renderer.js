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

      // Attachments — Extracted Files table
      if (email.attachments.length) {
        const banner = document.createElement('div'); banner.className = 'doc-extraction-banner';
        banner.innerHTML = `<strong>Attachments (${email.attachments.length})</strong> — click any file to open it for analysis.`;
        wrap.appendChild(banner);

        const tbl = document.createElement('table'); tbl.className = 'zip-table';
        const thead = document.createElement('thead');
        const hr = document.createElement('tr');
        for (const h of ['', 'Filename', 'Size', '']) {
          const th = document.createElement('th'); th.textContent = h; hr.appendChild(th);
        }
        thead.appendChild(hr); tbl.appendChild(thead);

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
        tbl.appendChild(tbody); wrap.appendChild(tbl);
      }

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

    return wrap;
  }

  analyzeForSecurity(buffer) {
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
      if (email.date) f.metadata.date = email.date;
      if (email.subject) f.metadata.subject = email.subject;
      if (email.messageId) f.metadata.messageId = email.messageId;

      // Suspicious: Reply-To different from From
      if (email.replyTo && email.from && email.replyTo !== email.from) {
        f.externalRefs.push({
          type: IOC.PATTERN,
          url: `Reply-To (${email.replyTo}) differs from From (${email.from})`,
          severity: 'medium'
        });
        if (f.risk === 'low') f.risk = 'medium';
      }

      // Dangerous attachments
      const dangerExts = /\.(exe|scr|com|pif|bat|cmd|vbs|vbe|js|jse|wsf|wsh|ps1|hta|lnk|cpl|msi|dll|reg|inf|sct|gadget)$/i;
      for (const att of email.attachments) {
        if (dangerExts.test(att.filename)) {
          f.externalRefs.push({
            type: IOC.ATTACHMENT,
            url: att.filename,
            severity: 'high'
          });
          f.risk = 'high';
        }
      }

      // Check for tracking pixels in HTML body
      if (email.bodyHtml) {
        const imgMatches = email.bodyHtml.match(/<img[^>]+>/gi) || [];
        for (const img of imgMatches) {
          if (/width\s*[=:]\s*["']?1(?:px)?["']?/i.test(img) &&
            /height\s*[=:]\s*["']?1(?:px)?["']?/i.test(img)) {
            f.externalRefs.push({
              type: IOC.PATTERN,
              url: (img.match(/src\s*=\s*["']?([^"'\s>]+)/i) || ['', '(embedded)'])[1],
              severity: 'info'
            });
          }
        }
      }

      // Auth results
      if (email.authResults) {
        const ar = email.authResults.toLowerCase();
        if (ar.includes('fail') || ar.includes('none')) {
          f.externalRefs.push({
            type: IOC.PATTERN,
            url: 'SPF/DKIM/DMARC check: ' + email.authResults.substring(0, 200),
            severity: 'medium'
          });
          if (f.risk === 'low') f.risk = 'medium';
        }
      }

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
    // Sanitize HTML: strip scripts, event handlers, dangerous elements
    const allowedTags = new Set([
      'p', 'br', 'div', 'span', 'b', 'i', 'u', 'em', 'strong', 'a', 'ul', 'ol', 'li',
      'table', 'tr', 'td', 'th', 'thead', 'tbody', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
      'pre', 'code', 'blockquote', 'hr', 'font', 'center', 'sub', 'sup', 'small', 'big',
      'dl', 'dt', 'dd', 'abbr', 'address', 'cite',
    ]);
    const allowedAttrs = new Set(['style', 'class', 'align', 'valign', 'width', 'height', 'colspan', 'rowspan', 'dir', 'color', 'size', 'face']);

    const tmp = document.createElement('div');
    tmp.innerHTML = html;

    function walk(node) {
      const children = [...node.childNodes];
      for (const child of children) {
        if (child.nodeType === 3) continue; // text node
        if (child.nodeType !== 1) { child.remove(); continue; }
        const tag = child.tagName.toLowerCase();
        if (!allowedTags.has(tag)) {
          // Replace with its text content
          const txt = document.createTextNode(child.textContent);
          node.replaceChild(txt, child);
          continue;
        }
        // Strip dangerous attributes
        for (const attr of [...child.attributes]) {
          if (!allowedAttrs.has(attr.name.toLowerCase()) || attr.name.toLowerCase().startsWith('on')) {
            child.removeAttribute(attr.name);
          }
        }
        // Strip javascript: from style
        if (child.getAttribute('style')) {
          child.setAttribute('style',
            child.getAttribute('style').replace(/expression\s*\(/gi, '').replace(/javascript\s*:/gi, '')
          );
        }
        walk(child);
      }
    }

    walk(tmp);
    container.innerHTML = tmp.innerHTML;
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
    const blob = new Blob([att.data], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = att.filename || 'attachment';
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    URL.revokeObjectURL(url);
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
