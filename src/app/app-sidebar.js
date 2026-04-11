// ════════════════════════════════════════════════════════════════════════════
// App — sidebar rendering (risk bar + three tab panes)
// ════════════════════════════════════════════════════════════════════════════
Object.assign(App.prototype, {

  _renderSidebar(fileName, analyzer) {
    const f=this.findings;
    // Risk bar
    const rb=document.getElementById('sb-risk');
    rb.className=`sb-risk risk-${f.risk}`;
    document.getElementById('sb-risk-title').textContent=
      f.risk==='high'?'🔴 HIGH RISK — Auto-execute macros detected':
      f.risk==='medium'?(f.hasMacros?'🟡 Macros present':'🟡 Potential risks detected'):
      '🟢 No threats detected';
    // Populate tabs
    this._renderSummaryTab(fileName);
    const allRefs=[...(f.externalRefs||[]),...(f.interestingStrings||[])];
    this._renderExtractedTab(allRefs,fileName);
    this._renderMacrosTab(analyzer);
    // Badges
    const eb=document.getElementById('stab-badge-extracted');
    if(allRefs.length){eb.textContent=allRefs.length;eb.classList.remove('hidden');}
    else eb.classList.add('hidden');
    const mb=document.getElementById('stab-badge-macros');
    if(f.hasMacros){
      mb.textContent=(f.autoExec&&f.autoExec.length)?'!':'•';
      mb.className='stab-badge'+(f.autoExec&&f.autoExec.length?' danger':'');
      mb.classList.remove('hidden');
    } else mb.classList.add('hidden');
    // Auto-select best tab
    let tab='summary';
    if(f.hasMacros&&f.autoExec&&f.autoExec.length) tab='macros';
    else if(allRefs.length) tab='extracted';
    this._switchTab(tab);
    // Show sidebar
    if(!this.sidebarOpen) this._toggleSidebar();
  },

  _renderSummaryTab(fileName) {
    const f=this.findings,pane=document.getElementById('stab-summary');
    pane.innerHTML='';
    const ext=(fileName||'').split('.').pop().toLowerCase();
    const FMT={docx:'Word Document',docm:'Word Macro-Enabled Document',
      xlsx:'Excel Workbook',xlsm:'Excel Macro-Enabled Workbook',
      xls:'Excel 97-2003 Workbook',ods:'OpenDocument Spreadsheet',
      pptx:'PowerPoint Presentation',pptm:'PowerPoint Macro-Enabled Presentation',
      csv:'Comma-Separated Values',tsv:'Tab-Separated Values',
      doc:'Word 97-2003 Document',msg:'Outlook Message'};
    const fmtEl=document.createElement('p');
    fmtEl.style.cssText='font-size:11px;color:#888;margin-bottom:8px;';
    fmtEl.textContent=(FMT[ext]||'Office Document')+' (.'+ext+')';
    pane.appendChild(fmtEl);

    // Hashes
    const hh=this._sec('File Hashes');pane.appendChild(hh);
    const ht=document.createElement('table');ht.className='hash-table';
    const hashes=this.fileHashes
      ?[['MD5',this.fileHashes.md5],['SHA-1',this.fileHashes.sha1],['SHA-256',this.fileHashes.sha256]]
      :[['MD5','computing…'],['SHA-1','computing…'],['SHA-256','computing…']];
    for(const[alg,val] of hashes){
      const tr=document.createElement('tr');
      const td1=document.createElement('td');td1.textContent=alg;
      const td2=document.createElement('td');td2.className='hash-val';
      const sp=document.createElement('span');sp.textContent=val;td2.appendChild(sp);
      if(val&&val.length>10){
        const cb=document.createElement('button');cb.className='copy-url-btn';cb.textContent='📋';cb.title='Copy';
        cb.addEventListener('click',()=>this._copyToClipboard(val));td2.appendChild(cb);
      }
      if(alg==='SHA-256'&&this.fileHashes&&this.fileHashes.sha256.length>10){
        const vt=document.createElement('a');
        vt.href='https://www.virustotal.com/gui/file/'+val+'/detection';
        vt.target='_blank';vt.rel='noopener noreferrer';
        vt.textContent='🔎 VT';vt.title='Search on VirusTotal';
        vt.style.cssText='font-size:10px;margin-left:6px;color:#1a73e8;text-decoration:none;';
        td2.appendChild(vt);
      }
      tr.appendChild(td1);tr.appendChild(td2);ht.appendChild(tr);
    }
    pane.appendChild(ht);

    // VBA project info
    if(f.hasMacros&&f.macroHash){
      pane.appendChild(this._sec('VBA Project'));
      const vt=document.createElement('table');vt.className='hash-table';
      const r1=document.createElement('tr');
      const r1a=document.createElement('td');r1a.textContent='Size';
      const r1b=document.createElement('td');r1b.className='hash-val';r1b.textContent=this._fmtBytes(f.macroSize||0);
      r1.appendChild(r1a);r1.appendChild(r1b);vt.appendChild(r1);
      const r2=document.createElement('tr');
      const r2a=document.createElement('td');r2a.textContent='SHA-256';
      const r2b=document.createElement('td');r2b.className='hash-val';
      const sp2=document.createElement('span');sp2.textContent=f.macroHash;r2b.appendChild(sp2);
      const cb2=document.createElement('button');cb2.className='copy-url-btn';cb2.textContent='📋';
      cb2.addEventListener('click',()=>this._copyToClipboard(f.macroHash));r2b.appendChild(cb2);
      r2.appendChild(r2a);r2.appendChild(r2b);vt.appendChild(r2);
      pane.appendChild(vt);
    }

    // Metadata
    const metaVals=Object.entries(f.metadata||{}).filter(([,v])=>v);
    if(metaVals.length){
      pane.appendChild(this._sec('Document Metadata'));
      const mt=document.createElement('table');mt.className='meta-table';
      const labels={title:'Title',subject:'Subject',creator:'Author',lastModifiedBy:'Last Modified By',created:'Created',modified:'Modified',revision:'Revision'};
      for(const[k,v] of metaVals){
        const tr=document.createElement('tr');
        const td1=document.createElement('td');td1.textContent=labels[k]||k;
        const td2=document.createElement('td');td2.textContent=v;
        tr.appendChild(td1);tr.appendChild(td2);mt.appendChild(tr);
      }
      pane.appendChild(mt);
    }
    if(!metaVals.length&&!f.hasMacros){
      const p=document.createElement('p');p.style.cssText='color:#888;font-size:11px;margin-top:8px;';
      p.textContent='No metadata found.';pane.appendChild(p);
    }
  },

  _renderExtractedTab(refs, fileName) {
    const pane=document.getElementById('stab-extracted');pane.innerHTML='';
    if(!refs.length){
      const p=document.createElement('p');p.style.cssText='color:#888;text-align:center;margin-top:20px;font-size:12px;';
      p.textContent='✅ No external references or interesting strings found.';pane.appendChild(p);return;
    }
    // Severity summary bar
    const high=refs.filter(r=>r.severity==='high').length;
    const med=refs.filter(r=>r.severity==='medium').length;
    const inf=refs.filter(r=>r.severity==='info').length;
    const bar=document.createElement('div');bar.className='sev-bar';
    if(high){const s=document.createElement('span');s.style.color='#721c24';s.textContent=`🔴 ${high} high`;bar.appendChild(s);}
    if(med) {const s=document.createElement('span');s.style.color='#856404';s.textContent=`🟡 ${med} medium`;bar.appendChild(s);}
    if(inf) {const s=document.createElement('span');s.style.color='#666';s.textContent=`ℹ ${inf} info`;bar.appendChild(s);}
    pane.appendChild(bar);
    // Search
    const srch=document.createElement('input');srch.type='text';srch.placeholder='Search…';srch.className='ext-search';
    pane.appendChild(srch);
    // Download all
    const dl=document.createElement('button');dl.className='tb-btn';
    dl.style.cssText='font-size:11px;margin-bottom:8px;width:100%;display:block;';
    dl.textContent='⬇ Download All (.txt)';
    dl.addEventListener('click',()=>this._downloadExtracted(refs,fileName));
    pane.appendChild(dl);
    // Table
    const tbl=document.createElement('table');tbl.className='ext-table';
    const thead=document.createElement('thead');const htr=document.createElement('tr');
    for(const h of ['Type','Value','Risk']){const th=document.createElement('th');th.textContent=h;htr.appendChild(th);}
    thead.appendChild(htr);tbl.appendChild(thead);
    const tbody=document.createElement('tbody');
    for(const ref of refs){
      const tr=document.createElement('tr');tr.dataset.search=(ref.type+' '+ref.url).toLowerCase();
      const td1=document.createElement('td');td1.textContent=ref.type;
      const td2=document.createElement('td');td2.className='ext-val';
      const sp=document.createElement('span');sp.textContent=ref.url;td2.appendChild(sp);
      const cb=document.createElement('button');cb.className='copy-url-btn';cb.textContent='📋';cb.title='Copy';
      cb.addEventListener('click',(e)=>{e.stopPropagation();this._copyToClipboard(ref.url);});
      td2.appendChild(cb);
      const td3=document.createElement('td');
      const badge=document.createElement('span');badge.className=`badge badge-${ref.severity}`;badge.textContent=ref.severity;
      td3.appendChild(badge);
      tr.appendChild(td1);tr.appendChild(td2);tr.appendChild(td3);tbody.appendChild(tr);
    }
    tbl.appendChild(tbody);pane.appendChild(tbl);
    srch.addEventListener('input',()=>{
      const q=srch.value.toLowerCase();
      for(const tr of tbody.rows) tr.classList.toggle('hidden',!!q&&!tr.dataset.search.includes(q));
    });
  },

  _renderMacrosTab(analyzer) {
    const f=this.findings,pane=document.getElementById('stab-macros');pane.innerHTML='';
    if(!f.hasMacros){
      const p=document.createElement('p');p.style.cssText='color:#888;text-align:center;margin-top:20px;font-size:12px;';
      p.textContent='No macros detected in this file.';pane.appendChild(p);return;
    }
    const hasSource=f.modules&&f.modules.some(m=>m.source);
    // Download button
    const dl=document.createElement('button');dl.className='tb-btn';
    dl.style.cssText='font-size:11px;margin-bottom:10px;width:100%;display:block;';
    dl.textContent=hasSource?'💾 Download Macros (.txt)':'💾 Download Macros (.bin)';
    dl.addEventListener('click',()=>this._downloadMacros());pane.appendChild(dl);
    // Auto-exec warning
    if(f.autoExec&&f.autoExec.length){
      const w=document.createElement('div');
      w.style.cssText='background:#f8d7da;border:1px solid #f5c6cb;border-radius:4px;padding:8px 10px;margin-bottom:10px;font-size:11px;color:#721c24;';
      w.innerHTML='<strong>🚨 Auto-execute patterns:</strong>';
      const ul=document.createElement('ul');ul.style.cssText='margin:4px 0 0 16px;';
      for(const{module,patterns} of f.autoExec) for(const pat of patterns){
        const li=document.createElement('li');li.textContent=`${module}: ${pat}`;ul.appendChild(li);}
      w.appendChild(ul);pane.appendChild(w);
    }
    // Obfuscation hint
    if(f.rawBin&&f.rawBin.length>0&&hasSource){
      const srcLen=(f.modules||[]).reduce((s,m)=>s+(m.source||'').length,0);
      if(srcLen>0&&f.rawBin.length>srcLen*5){
        const hint=document.createElement('div');
        hint.style.cssText='background:#fff3cd;border:1px solid #ffc107;border-radius:4px;padding:8px 10px;margin-bottom:10px;font-size:11px;color:#856404;';
        hint.textContent=`⚠ Decoded source (${this._fmtBytes(srcLen)}) is much smaller than VBA binary (${this._fmtBytes(f.rawBin.length)}) — possible obfuscation or compression.`;
        pane.appendChild(hint);
      }
    }
    if(!hasSource){
      const note=document.createElement('p');note.style.cssText='color:#888;font-size:11px;font-style:italic;margin-bottom:8px;';
      note.textContent='Source could not be decoded as text. Raw binary available for download above.';pane.appendChild(note);return;
    }
    // Module source blocks
    const hi=analyzer||{highlightVBA:s=>escHtml(s)};
    for(const mod of (f.modules||[])){
      if(!mod.source) continue;
      const hasAuto=(f.autoExec||[]).some(a=>a.module===mod.name);
      const det=document.createElement('details');det.open=(f.modules.filter(m=>m.source).length===1);
      const sum=document.createElement('summary');sum.style.cssText='cursor:pointer;font-weight:600;font-size:11px;padding:4px 0;';
      sum.textContent=`📄 ${mod.name}`;
      if(hasAuto){const b=document.createElement('span');b.className='badge badge-high';b.style.marginLeft='6px';b.textContent='auto-exec';sum.appendChild(b);}
      det.appendChild(sum);
      const pre=document.createElement('pre');pre.className='vba-code';
      pre.innerHTML=hi.highlightVBA(mod.source);
      det.appendChild(pre);pane.appendChild(det);
    }
  },

});
