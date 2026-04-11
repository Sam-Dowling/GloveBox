// ════════════════════════════════════════════════════════════════════════════
// App — core class definition, constructor, init, drop-zone, toolbar wiring
// ════════════════════════════════════════════════════════════════════════════
class App {
  constructor() {
    this.zoom=100; this.dark=true; this.findings=null;
    this.fileHashes=null; this.sidebarOpen=false; this.activeTab='summary';
    this._fileBuffer=null; this._yaraResults=null; this._yaraEscHandler=null;
  }

  init() {
    document.body.classList.add('dark');
    document.getElementById('btn-theme').textContent='☀';
    this._setupDrop();
    this._setupToolbar();
    this._setupSidebarResize();
    this._setupViewerPan();
    // Keyboard shortcuts: S=toggle sidebar, Y=YARA dialog, 1/2/3=switch tabs
    document.addEventListener('keydown',e=>{
      if(e.target.tagName==='INPUT'||e.target.tagName==='TEXTAREA'||e.altKey||e.ctrlKey||e.metaKey) return;
      if(e.key==='s'||e.key==='S') this._toggleSidebar();
      else if(e.key==='y'||e.key==='Y') this._openYaraDialog();
      else if(e.key==='1') this._switchTab('summary');
      else if(e.key==='2') this._switchTab('extracted');
      else if(e.key==='3') this._switchTab('macros');
    });
  }

  _setupDrop() {
    const dz=document.getElementById('drop-zone'),fi=document.getElementById('file-input');
    let _dragTimer;
    window.addEventListener('dragenter',()=>{
      clearTimeout(_dragTimer);
      document.querySelectorAll('iframe').forEach(f=>f.style.pointerEvents='none');
    });
    window.addEventListener('dragover',e=>{e.preventDefault();e.stopPropagation();});
    window.addEventListener('dragleave',()=>{
      _dragTimer=setTimeout(()=>{
        document.querySelectorAll('iframe').forEach(f=>f.style.pointerEvents='');
      },100);
    });
    window.addEventListener('drop',e=>{
      e.preventDefault();e.stopPropagation();
      clearTimeout(_dragTimer);
      document.querySelectorAll('iframe').forEach(f=>f.style.pointerEvents='');
      this._handleFiles(e.dataTransfer?.files);
    });
    dz.addEventListener('dragover',e=>{e.preventDefault();dz.classList.add('drag-over');});
    dz.addEventListener('dragleave',()=>dz.classList.remove('drag-over'));
    dz.addEventListener('drop',e=>{e.preventDefault();dz.classList.remove('drag-over');this._handleFiles(e.dataTransfer?.files);});
    dz.addEventListener('click',()=>fi.click());
    fi.addEventListener('change',e=>{const f=e.target.files[0];if(f)this._loadFile(f);fi.value='';});
  }

  _setupToolbar() {
    document.getElementById('btn-open').addEventListener('click',()=>document.getElementById('file-input').click());
    document.getElementById('btn-security').addEventListener('click',()=>this._toggleSidebar());
    document.getElementById('btn-yara').addEventListener('click',()=>this._openYaraDialog());
    document.getElementById('btn-close').addEventListener('click',()=>this._clearFile());
    document.getElementById('btn-zoom-out').addEventListener('click',()=>this._setZoom(this.zoom-10));
    document.getElementById('btn-zoom-in').addEventListener('click',()=>this._setZoom(this.zoom+10));
    document.getElementById('btn-theme').addEventListener('click',()=>this._toggleTheme());
    document.querySelectorAll('.stab').forEach(btn=>
      btn.addEventListener('click',()=>this._switchTab(btn.dataset.tab))
    );
  }

  _handleFiles(files) {
    if(!files||!files.length) return;
    this._loadFile(files[0]);
  }
}
