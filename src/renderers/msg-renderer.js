'use strict';
// ════════════════════════════════════════════════════════════════════════════
// msg-renderer.js — Renders .msg (Outlook) files via OLE CFB / MAPI properties
// Depends on: ole-cfb-parser.js, constants.js (sanitizeUrl)
// ════════════════════════════════════════════════════════════════════════════
class MsgRenderer {
  render(buffer) {
    const wrap = document.createElement('div'); wrap.className = 'msg-view';
    let msg;
    try {
      const cfb = new OleCfbParser(buffer).parse();
      msg = this._extract(cfb);
    } catch(e) {
      const b=document.createElement('div'); b.className='error-box';
      const h=document.createElement('h3'); h.textContent='Failed to parse .msg'; b.appendChild(h);
      const p=document.createElement('p');  p.textContent=e.message;              b.appendChild(p);
      wrap.appendChild(b); return wrap;
    }
    const page = document.createElement('div');
    page.className = 'page msg-page';
    page.style.cssText = 'width:816px;min-height:300px;padding:40px 60px;margin:0 auto;';

    // Header fields table
    const fields = [['From',msg.from],['To',msg.to],['CC',msg.cc],['Date',msg.date],['Subject',msg.subject||'(No Subject)']].filter(([,v])=>v);
    if (fields.length) {
      const tbl=document.createElement('table'); tbl.className='msg-header-table';
      for (const [l,v] of fields) {
        const tr=document.createElement('tr');
        const th=document.createElement('th'); th.textContent=l+':';
        const td=document.createElement('td'); td.textContent=v;
        tr.appendChild(th); tr.appendChild(td); tbl.appendChild(tr);
      }
      page.appendChild(tbl);
    }
    const hr=document.createElement('hr'); hr.style.cssText='margin:16px 0;border:none;border-top:1px solid #ddd;'; page.appendChild(hr);

    // Body
    if (msg.bodyHtml) { const d=document.createElement('div'); d.className='msg-body-html'; this._sanitize(msg.bodyHtml,d); page.appendChild(d); }
    else if (msg.body) { const d=document.createElement('div'); d.style.cssText='white-space:pre-wrap;font-size:10pt;line-height:1.5;'; d.textContent=msg.body; page.appendChild(d); }
    else { const p=document.createElement('p'); p.style.cssText='color:#888;font-style:italic;'; p.textContent='(No message body)'; page.appendChild(p); }

    // Attachments
    if (msg.attachments.length) {
      const hr2=document.createElement('hr'); hr2.style.cssText='margin:16px 0;border:none;border-top:1px solid #ddd;'; page.appendChild(hr2);
      const h4=document.createElement('h4'); h4.style.cssText='font-size:11pt;margin-bottom:8px;'; h4.textContent=`Attachments (${msg.attachments.length})`; page.appendChild(h4);
      const ul=document.createElement('ul'); ul.style.cssText='margin:0 0 0 20px;font-size:10pt;';
      for (const a of msg.attachments) {
        const li=document.createElement('li'); li.textContent=(a.name||'unnamed')+(a.size?` — ${(a.size/1024).toFixed(1)} KB`:''); ul.appendChild(li);
      }
      page.appendChild(ul);
    }
    wrap.appendChild(page); return wrap;
  }

  _extract(cfb) {
    const msg = {subject:'',from:'',to:'',cc:'',date:'',body:'',bodyHtml:'',attachments:[]};
    const gs  = id => this._u16(cfb.streams.get(`__substg1.0_${id}001f`));
    msg.subject = gs('0037'); msg.body = gs('1000');
    msg.from    = gs('0c1a') || gs('5d01') || gs('0065');
    msg.to      = gs('0e04'); msg.cc = gs('0e03');
    const htmlBin = cfb.streams.get('__substg1.0_10130102');
    if (htmlBin) { try { msg.bodyHtml = new TextDecoder('utf-8',{fatal:false}).decode(htmlBin); } catch(e){} }
    if (!msg.bodyHtml) msg.bodyHtml = gs('1013');
    if (msg.bodyHtml && !/<(html|body|div|p|table|span|br)\b/i.test(msg.bodyHtml)) msg.bodyHtml = '';

    // Date from MAPI properties
    const props = cfb.streams.get('__properties_version1.0');
    if (props && props.length >= 32) {
      const dv = new DataView(props.buffer, props.byteOffset, props.byteLength);
      const count = dv.getUint32(16, true);
      for (let i=0; i<count && 32+i*16+16<=props.length; i++) {
        const off=32+i*16, pType=dv.getUint16(off,true), pId=dv.getUint16(off+2,true);
        if (pType===0x0040 && (pId===0x0039||pId===0x0E06)) {
          const lo=dv.getUint32(off+8,true), hi=dv.getUint32(off+12,true);
          const ms = (hi*4294967296+lo)/10000 - 11644473600000;
          if (ms>0 && ms<32503680000000) { msg.date = new Date(ms).toLocaleString(); break; }
        }
      }
    }
    // Attachments
    const attPfx = new Set();
    for (const path of cfb.streams.keys()) { const m=path.match(/^(__attach_version1\.0_#\d+)\//); if(m) attPfx.add(m[1]); }
    for (const pre of attPfx) {
      const name =
        this._u16(cfb.streams.get(`${pre}/__substg1.0_3707001f`)) ||
        this._u16(cfb.streams.get(`${pre}/__substg1.0_3704001f`)) ||
        (()=>{ const d=cfb.streams.get(`${pre}/__substg1.0_3707001e`); return d?new TextDecoder('latin1').decode(d):''; })() ||
        'attachment';
      const data = cfb.streams.get(`${pre}/__substg1.0_37010102`);
      msg.attachments.push({name, size: data ? data.length : 0});
    }
    return msg;
  }

  _u16(data) { if(!data||!data.length)return ''; try{return new TextDecoder('utf-16le').decode(data).replace(/\0+$/,'');}catch(e){return '';} }

  _sanitize(html, container) {
    const OK   = new Set(['p','br','b','strong','i','em','u','s','span','div','ul','ol','li','table','thead','tbody','tr','th','td','h1','h2','h3','h4','h5','h6','blockquote','pre','code','hr','a','font','center']);
    const ATTR = new Set(['href','style','color','size','face','align','colspan','rowspan']);
    const walk = (node, target) => {
      for (const c of Array.from(node.childNodes)) {
        if (c.nodeType===3) { target.appendChild(document.createTextNode(c.textContent)); continue; }
        if (c.nodeType!==1) continue;
        const tag = c.tagName.toLowerCase();
        if (['script','style','meta','link','object','iframe','embed'].includes(tag)) continue;
        if (!OK.has(tag)) { walk(c, target); continue; }
        const el = document.createElement(tag);
        for (const a of Array.from(c.attributes)) {
          const n = a.name.toLowerCase(); if (!ATTR.has(n)) continue;
          if (n==='href') { const s=sanitizeUrl(a.value); if(s) el.setAttribute(n,s); }
          else if (n==='style') { el.setAttribute(n, a.value.replace(/(expression|javascript|vbscript)/gi,'')); }
          else el.setAttribute(n, a.value);
        }
        walk(c, el); target.appendChild(el);
      }
    };
    const doc = new DOMParser().parseFromString(html, 'text/html');
    if (doc.body) walk(doc.body, container);
  }

  analyzeForSecurity(buffer) {
    const f = {risk:'low',hasMacros:false,macroSize:0,macroHash:'',autoExec:[],modules:[],externalRefs:[],metadata:{}};
    try {
      const cfb = new OleCfbParser(buffer).parse();
      const msg = this._extract(cfb);
      f.metadata = {title: msg.subject, creator: msg.from, created: msg.date};
      for (const a of msg.attachments) {
        if (/\.(exe|bat|cmd|vbs|js|ps1|hta|scr|msi|dll|com|jar)$/i.test(a.name))
          { f.risk='high'; f.externalRefs.push({type:'Dangerous Attachment',url:a.name,severity:'high'}); }
        else if (/\.(doc[mx]?|xls[mx]?|ppt[mx]?|doc|xls|ppt)$/i.test(a.name))
          { if(f.risk==='low')f.risk='medium'; f.externalRefs.push({type:'Office Attachment',url:a.name,severity:'medium'}); }
      }
      if (msg.bodyHtml) {
        for (const u of (msg.bodyHtml.match(/https?:\/\/[^\s"'<>()]+/gi)||[]).slice(0,10))
          f.externalRefs.push({type:'HTML Link',url:u,severity:'info'});
        if (/width=.{0,5}[01].{0,5}height=.{0,5}[01]/i.test(msg.bodyHtml))
          f.externalRefs.push({type:'Possible Tracking Pixel',url:'1x1 or 0x0 image detected',severity:'medium'});
      }
      if (f.externalRefs.some(r=>r.severity!=='info') && f.risk==='low') f.risk='medium';
    } catch(e) {}
    return f;
  }
}
