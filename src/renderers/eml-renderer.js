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

      // Attachments
      if (email.attachments.length) {
        const al = document.createElement('div');
        al.className = 'msg-attach-list';
        const h4 = document.createElement('h4');
        h4.textContent = `📎 Attachments (${email.attachments.length})`;
        al.appendChild(h4);
        for (const att of email.attachments) {
          const item = document.createElement('span');
          item.className = 'msg-attach-item';
          item.textContent = att.filename + (att.size ? ` (${att.size})` : '');
          al.appendChild(item);
        }
        wrap.appendChild(al);
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
          type: 'Suspicious Header',
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
            type: 'Dangerous Attachment',
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
              type: 'Tracking Pixel',
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
            type: 'Auth Warning',
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
        const decoded = this._decodeBody(partBody, cte);
        email.attachments.push({ filename: fn, size: this._fmtSize(decoded.length) });
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
        email.attachments.push({ filename: fn, size: '' });
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
      'p','br','div','span','b','i','u','em','strong','a','ul','ol','li',
      'table','tr','td','th','thead','tbody','h1','h2','h3','h4','h5','h6',
      'pre','code','blockquote','hr','font','center','sub','sup','small','big',
      'dl','dt','dd','abbr','address','cite',
    ]);
    const allowedAttrs = new Set(['style','class','align','valign','width','height','colspan','rowspan','dir','color','size','face']);

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
}
