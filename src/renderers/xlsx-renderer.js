'use strict';
// ════════════════════════════════════════════════════════════════════════════
// xlsx-renderer.js — Renders .xlsx / .xlsm / .xls / .ods via SheetJS
// Depends on: vba-utils.js, XLSX (vendor / SheetJS), JSZip (vendor)
// ════════════════════════════════════════════════════════════════════════════
class XlsxRenderer {
  render(buffer, fileName) {
    const wrap = document.createElement('div'); wrap.className = 'xlsx-view';
    let wb;
    try { wb = XLSX.read(new Uint8Array(buffer), {type:'array',cellStyles:true,cellDates:true,sheetRows:10001}); }
    catch(e) { return this._err(wrap, 'Failed to parse spreadsheet', e.message); }
    if (!wb.SheetNames.length) { wrap.textContent='No sheets found.'; return wrap; }
    const tabBar = document.createElement('div'); tabBar.className='sheet-tab-bar'; wrap.appendChild(tabBar);
    const area   = document.createElement('div'); area.className='sheet-content-area'; wrap.appendChild(area);
    const panes  = wb.SheetNames.map((name, i) => {
      const tab  = document.createElement('button'); tab.className='sheet-tab'; tab.textContent=name; tabBar.appendChild(tab);
      const pane = document.createElement('div'); pane.className='sheet-content'; pane.style.display='none'; area.appendChild(pane);
      const p = {tab, pane, done: false};
      tab.addEventListener('click', () => {
        panes.forEach(x => { x.tab.classList.remove('active'); x.pane.style.display='none'; });
        tab.classList.add('active'); pane.style.display='block';
        if (!p.done) { this._renderSheet(wb.Sheets[name], pane); p.done=true; }
      });
      return p;
    });
    panes[0].tab.click();
    return wrap;
  }

  _renderSheet(ws, container) {
    if (!ws||!ws['!ref']) {
      const p=document.createElement('p'); p.style.cssText='color:#888;padding:20px';
      p.textContent='Empty sheet'; container.appendChild(p); return;
    }
    const rng=XLSX.utils.decode_range(ws['!ref']), maxR=Math.min(rng.e.r, rng.s.r+9999);
    const merges=ws['!merges']||[], cols=ws['!cols']||[];
    const mStart=new Map(), mSkip=new Set();
    for(const m of merges){
      mStart.set(`${m.s.r},${m.s.c}`, {cs:m.e.c-m.s.c+1, rs:m.e.r-m.s.r+1});
      for(let r=m.s.r;r<=m.e.r;r++) for(let c=m.s.c;c<=m.e.c;c++) if(r!==m.s.r||c!==m.s.c) mSkip.add(`${r},${c}`);
    }
    const scr=document.createElement('div'); scr.style.cssText='overflow:auto;max-height:calc(100vh - 160px)';
    const tbl=document.createElement('table'); tbl.className='xlsx-table';
    const thead=document.createElement('thead'), hRow=document.createElement('tr');
    const corner=document.createElement('th'); corner.className='xlsx-corner'; hRow.appendChild(corner);
    for(let c=rng.s.c;c<=rng.e.c;c++){
      const th=document.createElement('th'); th.className='xlsx-col-header'; th.textContent=XLSX.utils.encode_col(c);
      const w=cols[c-rng.s.c]; if(w&&w.wch) th.style.minWidth=Math.max(40,Math.round(w.wch*7))+'px';
      hRow.appendChild(th);
    }
    thead.appendChild(hRow); tbl.appendChild(thead);
    const tbody=document.createElement('tbody');
    for(let r=rng.s.r;r<=maxR;r++){
      const tr=document.createElement('tr');
      const rh=document.createElement('th'); rh.className='xlsx-row-header'; rh.textContent=r+1; tr.appendChild(rh);
      for(let c=rng.s.c;c<=rng.e.c;c++){
        const key=`${r},${c}`; if(mSkip.has(key)) continue;
        const td=document.createElement('td'); td.className='xlsx-cell';
        const m=mStart.get(key); if(m){if(m.cs>1)td.colSpan=m.cs;if(m.rs>1)td.rowSpan=m.rs;}
        const cell=ws[XLSX.utils.encode_cell({r,c})];
        if(cell){
          td.textContent=cell.w!==undefined?cell.w:(cell.t==='b'?(cell.v?'TRUE':'FALSE'):(cell.t==='e'?'#ERR':String(cell.v??'')));
          if(cell.t==='n') td.style.textAlign='right';
        }
        tr.appendChild(td);
      }
      tbody.appendChild(tr);
    }
    if(maxR<rng.e.r){
      const tr=document.createElement('tr'); const td=document.createElement('td');
      td.colSpan=rng.e.c-rng.s.c+2; td.style.cssText='text-align:center;color:#888;padding:8px;font-style:italic';
      td.textContent=`… ${rng.e.r-maxR} more rows`; tr.appendChild(td); tbody.appendChild(tr);
    }
    tbl.appendChild(tbody); scr.appendChild(tbl); container.appendChild(scr);
  }

  async analyzeForSecurity(buffer, fileName) {
    const ext = (fileName||'').split('.').pop().toLowerCase();
    const f = {risk:'low',hasMacros:false,macroSize:0,macroHash:'',autoExec:[],modules:[],externalRefs:[],metadata:{}};
    try {
      const wb = XLSX.read(new Uint8Array(buffer), {type:'array', bookVBA:true});
      if (wb.Props) {
        f.metadata = {
          title:          wb.Props.Title         || '',
          subject:        wb.Props.Subject        || '',
          creator:        wb.Props.Author         || '',
          lastModifiedBy: wb.Props.LastAuthor     || '',
          created:  wb.Props.CreatedDate  ? new Date(wb.Props.CreatedDate).toLocaleString()  : '',
          modified: wb.Props.ModifiedDate ? new Date(wb.Props.ModifiedDate).toLocaleString() : '',
        };
      }
      if (wb.vbaraw || ['xlsm','xltm','xlam'].includes(ext)) {
        f.hasMacros = true; f.risk = 'medium';
        if (wb.vbaraw) f.macroSize = wb.vbaraw.byteLength || wb.vbaraw.length || 0;
        try {
          const zip = await JSZip.loadAsync(buffer);
          const vbaEntry = zip.file('xl/vbaProject.bin') || zip.file('xl/vbaProject.bin'.replace('xl/',''));
          if (vbaEntry) {
            const vbaData = await vbaEntry.async('uint8array');
            if (!f.macroSize) f.macroSize = vbaData.length;
            f.rawBin  = vbaData;
            f.modules = parseVBAText(vbaData);
            for (const m of f.modules) {
              if (!m.source) continue;
              const pats = autoExecPatterns(m.source);
              if (pats.length) { f.autoExec.push({module:m.name, patterns:pats}); f.risk='high'; }
            }
          }
          if (!f.rawBin && wb.vbaraw)
            f.rawBin = wb.vbaraw instanceof Uint8Array ? wb.vbaraw : new Uint8Array(wb.vbaraw);
        } catch(e) {
          if (!f.rawBin && wb.vbaraw) {
            try { f.rawBin = wb.vbaraw instanceof Uint8Array ? wb.vbaraw : new Uint8Array(wb.vbaraw); } catch(_){}
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
