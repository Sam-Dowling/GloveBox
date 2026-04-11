'use strict';
// ════════════════════════════════════════════════════════════════════════════
// pptx-renderer.js — Renders .pptx / .pptm slides via JSZip + DrawingML
// Depends on: vba-utils.js, constants.js (PKG), JSZip (vendor)
// ════════════════════════════════════════════════════════════════════════════
class PptxRenderer {
  constructor() {
    this.PML  = 'http://schemas.openxmlformats.org/presentationml/2006/main';
    this.DML  = 'http://schemas.openxmlformats.org/drawingml/2006/main';
    this.DMLR = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships';
    this.TBL  = 'http://schemas.openxmlformats.org/drawingml/2006/table';
  }

  async render(buffer) {
    const wrap = document.createElement('div'); wrap.className = 'pptx-view';
    let zip;
    try { zip = await JSZip.loadAsync(buffer); }
    catch(e) { return this._err(wrap, 'Failed to parse presentation', e.message); }
    const presXml  = await this._xml(zip, 'ppt/presentation.xml');
    if (!presXml) { wrap.textContent = 'Could not parse presentation.xml'; return wrap; }
    const presRels = await this._xml(zip, 'ppt/_rels/presentation.xml.rels');
    const sldSz = presXml.getElementsByTagNameNS(this.PML, 'sldSz')[0];
    const emuW  = parseInt(sldSz?.getAttribute('cx')||'9144000');
    const emuH  = parseInt(sldSz?.getAttribute('cy')||'5143500');
    const pxW   = 720, scale = pxW/emuW, pxH = Math.round(emuH*scale);
    const relMap = new Map();
    if (presRels) for(const r of presRels.getElementsByTagNameNS(PKG,'Relationship')) relMap.set(r.getAttribute('Id'), r.getAttribute('Target'));
    const media    = await this._loadMedia(zip, 'ppt/media/');
    const sldIdLst = presXml.getElementsByTagNameNS(this.PML, 'sldIdLst')[0];
    const sldIds   = sldIdLst ? Array.from(sldIdLst.getElementsByTagNameNS(this.PML,'sldId')) : [];
    if (sldIds.length) {
      const lbl=document.createElement('div'); lbl.className='pptx-slide-counter';
      lbl.textContent=`${sldIds.length} slide${sldIds.length!==1?'s':''}`; wrap.appendChild(lbl);
    }
    for (let i=0; i<sldIds.length; i++) {
      const rId    = sldIds[i].getAttributeNS(this.DMLR,'id') || sldIds[i].getAttribute('r:id');
      const target = relMap.get(rId); if (!target) continue;
      const sPath  = 'ppt/' + target.replace(/^(\.\.\/)+/,'');
      const sXml   = await this._xml(zip, sPath); if (!sXml) continue;
      const sRelPath = sPath.replace(/([^/]+)$/, '_rels/$1.rels');
      const sRelXml  = await this._xml(zip, sRelPath);
      const sMedia = new Map();
      if (sRelXml) for (const r of sRelXml.getElementsByTagNameNS(PKG,'Relationship')) {
        const t=r.getAttribute('Target')||''; const mk='media/'+t.split('media/').pop();
        const src=media.get(mk); if(src) sMedia.set(r.getAttribute('Id'), src);
      }
      wrap.appendChild(this._renderSlide(sXml, i+1, sldIds.length, pxW, pxH, scale, sMedia));
    }
    if (!sldIds.length) {
      const p=document.createElement('p'); p.style.cssText='color:#888;padding:20px;text-align:center';
      p.textContent='No slides found.'; wrap.appendChild(p);
    }
    return wrap;
  }

  async _loadMedia(zip, prefix) {
    const map=new Map(), MIME={png:'image/png',jpg:'image/jpeg',jpeg:'image/jpeg',gif:'image/gif',bmp:'image/bmp'};
    for (const [path, file] of Object.entries(zip.files)) {
      if (!path.startsWith(prefix)||file.dir) continue;
      const ext=path.split('.').pop().toLowerCase(); if(!MIME[ext]) continue;
      const b64=await file.async('base64');
      map.set('media/'+path.slice(prefix.length), `data:${MIME[ext]};base64,${b64}`);
    }
    return map;
  }

  _renderSlide(xml, num, total, w, h, scale, media) {
    const slide=document.createElement('div'); slide.className='pptx-slide';
    slide.style.cssText=`width:${w}px;height:${h}px;position:relative;overflow:hidden;`;
    const bg=document.createElement('div'); bg.style.cssText='position:absolute;inset:0;background:white;'; slide.appendChild(bg);
    const trees=xml.getElementsByTagNameNS(this.PML,'spTree');
    for(const tree of Array.from(trees)) this._shapes(tree, slide, scale, media);
    const badge=document.createElement('div'); badge.className='pptx-slide-num'; badge.textContent=`${num}/${total}`; slide.appendChild(badge);
    return slide;
  }

  _shapes(container, parent, scale, media) {
    for (const c of Array.from(container.childNodes)) {
      if (c.nodeType!==1) continue;
      if      (c.localName==='sp')           this._sp(c, parent, scale);
      else if (c.localName==='pic')          this._pic(c, parent, scale, media);
      else if (c.localName==='grpSp')        this._shapes(c, parent, scale, media);
      else if (c.localName==='graphicFrame') this._gf(c, parent, scale);
    }
  }

  _xfrm(el) {
    const spPr=el.getElementsByTagNameNS(this.PML,'spPr')[0];
    const xf=spPr?spPr.getElementsByTagNameNS(this.DML,'xfrm')[0]:null; if(!xf) return null;
    const off=xf.getElementsByTagNameNS(this.DML,'off')[0], ext=xf.getElementsByTagNameNS(this.DML,'ext')[0];
    if(!off||!ext) return null;
    return {x:parseInt(off.getAttribute('x')||0), y:parseInt(off.getAttribute('y')||0),
            cx:parseInt(ext.getAttribute('cx')||0), cy:parseInt(ext.getAttribute('cy')||0),
            rot:parseInt(xf.getAttribute('rot')||0)};
  }

  _pos(el, s, x) {
    el.style.position='absolute'; el.style.left=(x.x*s)+'px'; el.style.top=(x.y*s)+'px';
    el.style.width=(x.cx*s)+'px'; el.style.height=(x.cy*s)+'px';
    if(x.rot) el.style.transform=`rotate(${x.rot/60000}deg)`;
  }

  _sp(sp, parent, scale) {
    const x=this._xfrm(sp); if(!x) return;
    const div=document.createElement('div'); div.style.cssText='overflow:hidden;box-sizing:border-box;'; this._pos(div,scale,x);
    const spPr=sp.getElementsByTagNameNS(this.PML,'spPr')[0];
    if(spPr){const sf=spPr.getElementsByTagNameNS(this.DML,'solidFill')[0];if(sf){const sc=sf.getElementsByTagNameNS(this.DML,'srgbClr')[0];if(sc)div.style.background='#'+sc.getAttribute('val');}}
    const txBody=sp.getElementsByTagNameNS(this.PML,'txBody')[0];
    if(txBody) this._txBody(txBody, div, scale);
    parent.appendChild(div);
  }

  _txBody(txBody, container, scale) {
    for(const p of Array.from(txBody.getElementsByTagNameNS(this.DML,'p'))){
      const pd=document.createElement('p'); pd.style.cssText='margin:0;padding:0 2px;line-height:1.2;';
      const pPr=p.getElementsByTagNameNS(this.DML,'pPr')[0];
      if(pPr){const a=pPr.getAttribute('algn');if(a==='ctr')pd.style.textAlign='center';else if(a==='r')pd.style.textAlign='right';}
      let has=false;
      for(const r of Array.from(p.getElementsByTagNameNS(this.DML,'r'))){
        const t=r.getElementsByTagNameNS(this.DML,'t')[0]; if(!t) continue;
        const sp=document.createElement('span'); sp.textContent=t.textContent;
        const rPr=r.getElementsByTagNameNS(this.DML,'rPr')[0];
        if(rPr){
          const sz=rPr.getAttribute('sz'); if(sz) sp.style.fontSize=Math.round(parseInt(sz)/100*scale*1.6)+'px';
          if(rPr.getAttribute('b')==='1') sp.style.fontWeight='bold';
          if(rPr.getAttribute('i')==='1') sp.style.fontStyle='italic';
          const fc=rPr.getElementsByTagNameNS(this.DML,'solidFill')[0];
          if(fc){const sc=fc.getElementsByTagNameNS(this.DML,'srgbClr')[0];if(sc)sp.style.color='#'+sc.getAttribute('val');}
        }
        pd.appendChild(sp); has=true;
      }
      for(const br of Array.from(p.getElementsByTagNameNS(this.DML,'br'))) pd.appendChild(document.createElement('br'));
      container.appendChild(has ? pd : document.createElement('br'));
    }
  }

  _pic(pic, parent, scale, media) {
    const x=this._xfrm(pic); if(!x) return;
    const bf=pic.getElementsByTagNameNS(this.PML,'blipFill')[0]; if(!bf) return;
    const blip=bf.getElementsByTagNameNS(this.DML,'blip')[0]; if(!blip) return;
    const rId=blip.getAttributeNS(this.DMLR,'embed')||blip.getAttribute('r:embed');
    const src=media.get(rId); if(!src) return;
    const img=document.createElement('img'); img.src=src; img.alt=''; img.style.objectFit='contain';
    this._pos(img,scale,x); parent.appendChild(img);
  }

  _gf(gf, parent, scale) {
    const tbl=gf.getElementsByTagNameNS(this.TBL,'tbl')[0]; if(!tbl) return;
    const x=this._xfrm(gf); if(!x) return;
    const wrap=document.createElement('div'); wrap.style.overflow='auto'; this._pos(wrap,scale,x);
    const table=document.createElement('table'); table.style.cssText='border-collapse:collapse;width:100%;';
    for(const tr of Array.from(tbl.getElementsByTagNameNS(this.TBL,'tr'))){
      const row=document.createElement('tr');
      for(const tc of Array.from(tr.getElementsByTagNameNS(this.TBL,'tc'))){
        const td=document.createElement('td'); td.style.cssText='border:1px solid #ccc;padding:2px 4px;vertical-align:top;';
        const gs=parseInt(tc.getAttribute('gridSpan')||1), rs=parseInt(tc.getAttribute('rowSpan')||1);
        if(gs>1)td.colSpan=gs; if(rs>1)td.rowSpan=rs;
        const tbx=tc.getElementsByTagNameNS(this.TBL,'txBody')[0]; if(tbx) this._txBody(tbx, td, scale*0.8);
        row.appendChild(td);
      }
      table.appendChild(row);
    }
    wrap.appendChild(table); parent.appendChild(wrap);
  }

  async _xml(zip, path) {
    try {
      const f=zip.file(path); if(!f) return null;
      const d=new DOMParser().parseFromString(await f.async('string'),'text/xml');
      return d.getElementsByTagName('parsererror').length ? null : d;
    } catch(e){ return null; }
  }

  async analyzeForSecurity(buffer, fileName) {
    const ext = (fileName||'').split('.').pop().toLowerCase();
    const f = {risk:'low',hasMacros:false,macroSize:0,macroHash:'',autoExec:[],modules:[],externalRefs:[],metadata:{}};
    try {
      const zip = await JSZip.loadAsync(buffer);
      const vba = zip.file('ppt/vbaProject.bin');
      if (vba || ['pptm','potm','ppam'].includes(ext)) {
        f.hasMacros = true; f.risk = 'medium';
        if (vba) {
          const d = await vba.async('uint8array');
          f.macroSize = d.length;
          f.rawBin    = d;
          f.modules   = parseVBAText(d);
          for (const m of f.modules) {
            if (!m.source) continue;
            const pats = autoExecPatterns(m.source);
            if (pats.length) { f.autoExec.push({module:m.name, patterns:pats}); f.risk='high'; }
          }
        }
      }
      const core = await this._xml(zip, 'docProps/core.xml');
      if (core) {
        const DC='http://purl.org/dc/elements/1.1/', DCP='http://schemas.openxmlformats.org/package/2006/metadata/core-properties';
        const g=(ns,n)=>core.getElementsByTagNameNS(ns,n)[0]?.textContent?.trim()||'';
        f.metadata={title:g(DC,'title'),subject:g(DC,'subject'),creator:g(DC,'creator'),lastModifiedBy:g(DCP,'lastModifiedBy'),created:g(DCP,'created'),modified:g(DCP,'modified')};
      }
      for (const [p, file] of Object.entries(zip.files)) {
        if (!p.endsWith('.rels')||file.dir) continue;
        const rXml=new DOMParser().parseFromString(await file.async('string'),'text/xml');
        for (const r of rXml.getElementsByTagNameNS(PKG,'Relationship')) {
          const mode=r.getAttribute('TargetMode'), target=r.getAttribute('Target');
          if (mode==='External' && target) {
            const t=(r.getAttribute('Type')||'').split('/').pop();
            const sv=t==='hyperlink'?'info':'medium';
            f.externalRefs.push({type:t==='hyperlink'?'Hyperlink':'External',url:target,severity:sv});
            if(sv!=='info'&&f.risk==='low') f.risk='medium';
          }
        }
      }
    } catch(e) {}
    return f;
  }

  _err(wrap, title, msg) {
    const b=document.createElement('div'); b.className='error-box';
    const h=document.createElement('h3'); h.textContent=title; b.appendChild(h);
    const p=document.createElement('p');  p.textContent=msg;   b.appendChild(p);
    wrap.appendChild(b); return wrap;
  }
}
