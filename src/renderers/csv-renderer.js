'use strict';
// ════════════════════════════════════════════════════════════════════════════
// csv-renderer.js — Renders .csv and .tsv files as styled tables
// No external dependencies beyond the browser DOM.
// ════════════════════════════════════════════════════════════════════════════
class CsvRenderer {
  render(text, fileName) {
    const wrap=document.createElement('div'); wrap.className='csv-view';
    const ext=(fileName||'').split('.').pop().toLowerCase();
    const delim=ext==='tsv'?'\t':this._delim(text);
    const rows=this._parse(text,delim);
    if(!rows.length){wrap.textContent='Empty file.';return wrap;}
    const info=document.createElement('div'); info.className='csv-info';
    const dn=delim==='\t'?'Tab':delim===','?'Comma':delim===';'?'Semicolon':'Pipe';
    info.textContent=`${rows.length} rows × ${rows[0].length} columns · delimiter: ${dn}`; wrap.appendChild(info);
    const scr=document.createElement('div'); scr.style.cssText='overflow:auto;max-height:calc(100vh - 140px)';
    const tbl=document.createElement('table'); tbl.className='xlsx-table csv-table';
    rows.forEach((row,ri)=>{
      if(ri>10000)return;
      const tr=document.createElement('tr');
      const rh=document.createElement(ri===0?'th':'td'); rh.className='xlsx-row-header'; rh.textContent=ri===0?'#':ri; tr.appendChild(rh);
      row.forEach(cell=>{
        const td=document.createElement(ri===0?'th':'td'); td.className=ri===0?'xlsx-col-header csv-header':'xlsx-cell'; td.textContent=cell;
        if(ri>0&&cell.trim()&&!isNaN(parseFloat(cell)))td.style.textAlign='right';
        tr.appendChild(td);
      });
      tbl.appendChild(tr);
    });
    scr.appendChild(tbl); wrap.appendChild(scr); return wrap;
  }

  /** Auto-detect delimiter by counting occurrences in the first line. */
  _delim(text){const line=(text.split('\n')[0]||'');const c={',':0,';':0,'\t':0,'|':0};let inQ=false;for(const ch of line){if(ch==='"'){inQ=!inQ;}else if(!inQ&&c[ch]!==undefined)c[ch]++;}return Object.entries(c).sort((a,b)=>b[1]-a[1])[0][0];}

  _parse(text,delim){const rows=[];for(const line of text.replace(/\r\n/g,'\n').replace(/\r/g,'\n').split('\n')){if(!line.trim())continue;rows.push(this._split(line,delim));}return rows;}

  _split(line,delim){const cells=[];let cur='',inQ=false;for(let i=0;i<line.length;i++){const ch=line[i];if(ch==='"'){if(inQ&&line[i+1]==='"'){cur+='"';i++;}else inQ=!inQ;}else if(ch===delim&&!inQ){cells.push(cur);cur='';}else cur+=ch;}cells.push(cur);return cells;}

  analyzeForSecurity(text) {
    const f={risk:'low',hasMacros:false,macroSize:0,macroHash:'',autoExec:[],modules:[],externalRefs:[],metadata:{}};
    if(text.split('\n').slice(0,1000).some(l=>l.trim()&&/^["']?[=+\-@]/.test(l.trim()))){
      f.risk='medium';
      f.externalRefs.push({type:'Formula Injection Risk',url:'Cells beginning with =, +, -, or @ (potential formula injection)',severity:'medium'});
    }
    return f;
  }
}
