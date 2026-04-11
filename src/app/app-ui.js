// ════════════════════════════════════════════════════════════════════════════
// App — UI utilities: tabs, sidebar toggle, downloads, clipboard, zoom, theme
// ════════════════════════════════════════════════════════════════════════════
Object.assign(App.prototype, {

  // ── Helper: section heading ──────────────────────────────────────────────
  _sec(label) {
    const d=document.createElement('div');d.className='sb-section';d.textContent=label;return d;
  },

  // ── Tab switching ────────────────────────────────────────────────────────
  _switchTab(name) {
    if(!this.sidebarOpen) this._toggleSidebar();
    this.activeTab=name;
    document.querySelectorAll('.stab').forEach(b=>b.classList.toggle('active',b.dataset.tab===name));
    document.querySelectorAll('.stab-pane').forEach(p=>p.classList.toggle('hidden',p.id!==`stab-${name}`));
  },

  _toggleSidebar() {
    this.sidebarOpen=!this.sidebarOpen;
    document.getElementById('sidebar').classList.toggle('hidden',!this.sidebarOpen);
    document.getElementById('sidebar-resize').classList.toggle('hidden',!this.sidebarOpen);
  },

  // ── Sidebar resize ─────────────────────────────────────────────────────
  _setupSidebarResize() {
    const handle=document.getElementById('sidebar-resize');
    const sidebar=document.getElementById('sidebar');
    let startX, startW;
    const onMove=e=>{
      const dx=startX-e.clientX;
      const newW=Math.min(Math.max(startW+dx,window.innerWidth*0.33),window.innerWidth*0.6);
      sidebar.style.width=newW+'px';
    };
    const onUp=()=>{
      document.body.classList.remove('sb-resizing');
      window.removeEventListener('mousemove',onMove);
      window.removeEventListener('mouseup',onUp);
    };
    handle.addEventListener('mousedown',e=>{
      e.preventDefault();
      startX=e.clientX;
      startW=sidebar.getBoundingClientRect().width;
      document.body.classList.add('sb-resizing');
      window.addEventListener('mousemove',onMove);
      window.addEventListener('mouseup',onUp);
    });
  },

  // ── Downloads ────────────────────────────────────────────────────────────
  _downloadMacros() {
    const f=this.findings;
    const info=document.getElementById('file-info').textContent;
    const base=info.split('·')[0].trim().replace(/\.[^.]+$/,'')||'macros';
    const mods=(f.modules||[]).filter(m=>m.source);
    if(mods.length){
      const sep='='.repeat(60),lines=[];
      for(const mod of mods){lines.push(`' ${sep}`);lines.push(`' VBA Module: ${mod.name}`);lines.push(`' ${sep}`);lines.push(mod.source);lines.push('');}
      const blob=new Blob([lines.join('\n')],{type:'text/plain'});
      const url=URL.createObjectURL(blob);
      const a=document.createElement('a');a.href=url;a.download=base+'_macros.txt';a.click();
      URL.revokeObjectURL(url);this._toast('Macro source downloaded');
    } else if(f.rawBin&&f.rawBin.length){
      const blob=new Blob([f.rawBin],{type:'application/octet-stream'});
      const url=URL.createObjectURL(blob);
      const a=document.createElement('a');a.href=url;a.download=base+'_vbaProject.bin';a.click();
      URL.revokeObjectURL(url);this._toast('Raw VBA binary downloaded — use olevba/oledump to inspect');
    } else { this._toast('No macro data available','error'); }
  },

  _downloadExtracted(refs, fileName) {
    const base=(fileName||'extracted').replace(/\.[^.]+$/,'');
    const lines=['Type\tValue\tSeverity',...refs.map(r=>`${r.type}\t${r.url}\t${r.severity}`)];
    const blob=new Blob([lines.join('\n')],{type:'text/plain'});
    const url=URL.createObjectURL(blob);
    const a=document.createElement('a');a.href=url;a.download=base+'_extracted.txt';a.click();
    URL.revokeObjectURL(url);this._toast('Extracted data downloaded');
  },

  // ── Clipboard ────────────────────────────────────────────────────────────
  _copyToClipboard(text) {
    if(navigator.clipboard&&navigator.clipboard.writeText){
      navigator.clipboard.writeText(text).then(()=>this._toast('Copied!')).catch(()=>this._copyFallback(text));
    } else this._copyFallback(text);
  },

  _copyFallback(text) {
    const ta=document.createElement('textarea');ta.value=text;ta.style.cssText='position:fixed;opacity:0;top:0;left:0;';
    document.body.appendChild(ta);ta.focus();ta.select();
    try{document.execCommand('copy');this._toast('Copied!');}catch(e){this._toast('Copy failed','error');}
    document.body.removeChild(ta);
  },

  // ── Clear file ────────────────────────────────────────────────────────────
  _clearFile() {
    // Reset viewer
    document.getElementById('page-container').innerHTML='';
    // Restore drop zone
    const dz=document.getElementById('drop-zone');
    dz.className=''; dz.innerHTML='';
    const icon=document.createElement('span');icon.className='dz-icon';icon.textContent='📄';dz.appendChild(icon);
    const txt=document.createElement('div');txt.className='dz-text';txt.textContent='Drop a file here to analyse';dz.appendChild(txt);
    const sub=document.createElement('div');sub.className='dz-sub';sub.textContent='docx · xlsx · pptx · pdf · doc · msg · eml · lnk · hta · csv · and any file · 100% offline';dz.appendChild(sub);
    // Hide file info + close button
    document.getElementById('file-info').textContent='';
    document.getElementById('btn-close').classList.add('hidden');
    // Close sidebar
    if(this.sidebarOpen) this._toggleSidebar();
    // Reset state
    this.findings=null; this.fileHashes=null;
    this._fileBuffer=null; this._yaraResults=null;
    // Remove pan cursor
    document.getElementById('viewer').classList.remove('pannable');
    // Reset zoom
    this._setZoom(100);
  },

  // ── Viewer pan (click-and-drag) ───────────────────────────────────────────
  _setupViewerPan() {
    const viewer=document.getElementById('viewer');
    let isPanning=false, startX, startY, scrollL, scrollT;
    viewer.addEventListener('mousedown',e=>{
      // Only pan if a document is loaded (drop zone hidden) and not on interactive elements
      const dz=document.getElementById('drop-zone');
      if(!dz.classList.contains('has-document')) return;
      const tag=e.target.tagName;
      if(tag==='BUTTON'||tag==='INPUT'||tag==='A'||tag==='TEXTAREA'||tag==='SELECT') return;
      if(e.target.closest('.zoom-fab')||e.target.closest('.tb-btn')||e.target.closest('.copy-url-btn')) return;
      // Don't pan on plaintext views (they have their own scrolling)
      if(e.target.closest('.plaintext-scroll')||e.target.closest('.sheet-content-area')||e.target.closest('.csv-scroll')) return;
      isPanning=true;
      startX=e.clientX; startY=e.clientY;
      scrollL=viewer.scrollLeft; scrollT=viewer.scrollTop;
      viewer.classList.add('panning');
      e.preventDefault();
    });
    window.addEventListener('mousemove',e=>{
      if(!isPanning) return;
      viewer.scrollLeft=scrollL-(e.clientX-startX);
      viewer.scrollTop=scrollT-(e.clientY-startY);
    });
    window.addEventListener('mouseup',()=>{
      if(!isPanning) return;
      isPanning=false;
      viewer.classList.remove('panning');
    });
  },

  // ── Zoom / theme / loading / toast ────────────────────────────────────────
  _setZoom(z) {
    this.zoom=Math.min(200,Math.max(50,z));
    document.getElementById('zoom-level').textContent=`${this.zoom}%`;
    document.getElementById('page-container').style.transform=`scale(${this.zoom/100})`;
  },

  _toggleTheme() {
    this.dark=!this.dark;
    document.body.classList.toggle('dark',this.dark);
    document.getElementById('btn-theme').textContent=this.dark?'☀':'🌙';
  },

  _setLoading(on) {
    document.getElementById('loading').classList.toggle('hidden',!on);
  },

  _toast(msg, type='info') {
    const t=document.getElementById('toast');t.textContent=msg;
    t.className=type==='error'?'toast-error':'';t.classList.remove('hidden');
    setTimeout(()=>t.classList.add('hidden'),3000);
  },

  _fmtBytes(b) {
    if(!b||b<1024) return(b||0)+' B';
    if(b<1048576) return(b/1024).toFixed(1)+' KB';
    return(b/1048576).toFixed(1)+' MB';
  },

});

document.addEventListener('DOMContentLoaded', () => new App().init());
