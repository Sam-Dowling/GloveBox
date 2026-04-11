// ════════════════════════════════════════════════════════════════════════════
// _md5  — compact pure-JS MD5 (crypto.subtle doesn't support MD5)
// ════════════════════════════════════════════════════════════════════════════
function _md5(bytes) {
  function add(x,y){const l=(x&0xFFFF)+(y&0xFFFF);return(((x>>16)+(y>>16)+(l>>16))<<16)|(l&0xFFFF);}
  function rol(x,n){return(x<<n)|(x>>>(32-n));}
  const T=[];for(let i=1;i<=64;i++)T[i]=Math.floor(Math.abs(Math.sin(i))*0x100000000)>>>0;
  const S=[7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21];
  const n=bytes.length,pad=new Uint8Array((n+72)&~63);
  pad.set(bytes);pad[n]=0x80;
  const dv=new DataView(pad.buffer);
  dv.setUint32(pad.length-8,n<<3,true);dv.setUint32(pad.length-4,n>>>29,true);
  let a=0x67452301,b=0xEFCDAB89,c=0x98BADCFE,d=0x10325476;
  for(let o=0;o<pad.length;o+=64){
    const W=[];for(let i=0;i<16;i++)W[i]=dv.getUint32(o+i*4,true);
    let A=a,B=b,C=c,D=d;
    for(let i=0;i<64;i++){
      let F,g;
      if(i<16){F=(B&C)|(~B&D);g=i;}
      else if(i<32){F=(D&B)|(~D&C);g=(5*i+1)%16;}
      else if(i<48){F=B^C^D;g=(3*i+5)%16;}
      else{F=C^(B|~D);g=7*i%16;}
      F=add(add(add(F,A),W[g]),T[i+1]);
      A=D;D=C;C=B;B=add(B,rol(F,S[i]));
    }
    a=add(a,A);b=add(b,B);c=add(c,C);d=add(d,D);
  }
  return[a,b,c,d].map(v=>[v&255,v>>8&255,v>>16&255,v>>24&255].map(x=>x.toString(16).padStart(2,'0')).join('')).join('');
}

// ════════════════════════════════════════════════════════════════════════════
// App — file loading, hashing, interesting-string extraction
// ════════════════════════════════════════════════════════════════════════════
Object.assign(App.prototype, {

  async _loadFile(file) {
    this._setLoading(true);
    document.getElementById('file-info').textContent=file.name;
    const ext=file.name.split('.').pop().toLowerCase();
    try {
      const buffer=await file.arrayBuffer();
      let docEl, analyzer=null;

      // Compute file hashes in parallel with parsing
      const hashPromise=this._hashFile(buffer);

      if(['docx','docm'].includes(ext)){
        const parsed=await new DocxParser().parse(buffer);
        analyzer=new SecurityAnalyzer();
        this.findings=analyzer.analyze(parsed);
        docEl=new ContentRenderer(parsed).render();
      } else if(['xlsx','xlsm','xls','ods'].includes(ext)){
        const r=new XlsxRenderer();
        this.findings=await r.analyzeForSecurity(buffer,file.name);
        docEl=r.render(buffer,file.name);
      } else if(['pptx','pptm'].includes(ext)){
        const r=new PptxRenderer();
        this.findings=await r.analyzeForSecurity(buffer,file.name);
        docEl=await r.render(buffer);
      } else if(['csv','tsv'].includes(ext)){
        const text=await file.text();
        const r=new CsvRenderer();
        this.findings=r.analyzeForSecurity(text);
        docEl=r.render(text,file.name);
      } else if(ext==='doc'){
        const r=new DocBinaryRenderer();
        this.findings=r.analyzeForSecurity(buffer);
        docEl=r.render(buffer);
      } else if(ext==='msg'){
        const r=new MsgRenderer();
        this.findings=r.analyzeForSecurity(buffer);
        docEl=r.render(buffer);
      } else {
        throw new Error(`Unsupported format: .${ext}`);
      }

      // Extract interesting strings from rendered text + VBA source
      this.findings.interestingStrings=this._extractInterestingStrings(docEl.textContent,this.findings);

      const pc=document.getElementById('page-container');
      pc.innerHTML=''; pc.appendChild(docEl);

      const dz=document.getElementById('drop-zone');
      dz.className='has-document'; dz.innerHTML='';
      const sp=document.createElement('span'); sp.textContent='📁 Drop another file to open'; dz.appendChild(sp);

      const pages=pc.querySelectorAll('.page').length;
      const pi=pages>0?`  ·  ${pages} page${pages!==1?'s':''}`:'';
      document.getElementById('file-info').textContent=`${file.name}${pi}  ·  ${this._fmtBytes(file.size)}`;

      // Await hashes and render sidebar
      this.fileHashes=await hashPromise;
      this._renderSidebar(file.name,analyzer);
    } catch(e){
      console.error(e);
      this._toast(`Failed to open: ${e.message}`,'error');
      const pc=document.getElementById('page-container'); pc.innerHTML='';
      const eb=document.createElement('div'); eb.className='error-box';
      const h3=document.createElement('h3'); h3.textContent='Failed to open file'; eb.appendChild(h3);
      const p1=document.createElement('p'); p1.textContent=e.message; eb.appendChild(p1);
      pc.appendChild(eb);
    } finally { this._setLoading(false); }
  },

  // ── Hashing ─────────────────────────────────────────────────────────────
  async _hashFile(buffer) {
    const data=buffer instanceof ArrayBuffer?buffer:buffer.buffer;
    try {
      const [s1,s256]=await Promise.all([
        crypto.subtle.digest('SHA-1',data),
        crypto.subtle.digest('SHA-256',data)
      ]);
      const hex=b=>Array.from(new Uint8Array(b)).map(x=>x.toString(16).padStart(2,'0')).join('');
      return {md5:_md5(new Uint8Array(data)),sha1:hex(s1),sha256:hex(s256)};
    } catch(e){ return {md5:'—',sha1:'—',sha256:'—'}; }
  },

  // ── Interesting string extraction ────────────────────────────────────────
  _extractInterestingStrings(text,findings) {
    const seen=new Set((findings.externalRefs||[]).map(r=>r.url));
    const results=[];
    const add=(type,val,sev)=>{
      val=(val||'').trim().replace(/[.,;:!?)\]>]+$/,'');
      if(!val||val.length<4||val.length>400||seen.has(val)) return;
      seen.add(val); results.push({type,url:val,severity:sev});
    };
    // Scan rendered text + VBA modules
    const sources=[text,...(findings.modules||[]).map(m=>m.source||'')];
    const full=sources.join('\n');
    for(const m of full.matchAll(/https?:\/\/[^\s"'<>()\[\]{}\u0000-\u001F]{6,}/g)) add('URL',m[0],'info');
    for(const m of full.matchAll(/\b[a-zA-Z0-9._%+\-]{2,}@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,6}\b/g)) add('Email',m[0],'info');
    for(const m of full.matchAll(/\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g)){
      const parts=m[0].split('.').map(Number);
      if(parts.every(p=>p<=255)&&!m[0].startsWith('0.')) add('IP Address',m[0],'medium');
    }
    for(const m of full.matchAll(/[A-Za-z]:\\(?:[\w\-. ]+\\)+[\w\-. ]{2,}/g)) add('File Path',m[0],'medium');
    for(const m of full.matchAll(/\\\\[\w.\-]{2,}(?:\\[\w.\-]{1,})+/g)) add('UNC Path',m[0],'medium');
    // VBA-specific URL scan with higher severity
    for(const mod of (findings.modules||[])){
      for(const m of (mod.source||'').matchAll(/https?:\/\/[^\s"']{6,}/g)){
        const v=m[0].replace(/[.,;:!?)\]>]+$/,'');
        if(!seen.has(v)){seen.add(v);results.push({type:'URL (VBA)',url:v,severity:'high'});}
      }
    }
    return results.slice(0,300);
  },

});
