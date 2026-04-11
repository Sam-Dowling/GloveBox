'use strict';
// ════════════════════════════════════════════════════════════════════════════
// numbering-resolver.js — Resolves Word list numbering and bullet formatting
// Depends on: constants.js
// ════════════════════════════════════════════════════════════════════════════
class NumberingResolver {
  constructor(doc) {
    this.abstract={}; this.nums={}; this.counters={};
    if(doc) this._parse(doc);
  }

  _parse(doc) {
    for(const an of doc.getElementsByTagNameNS(W,'abstractNum')){
      const id=wa(an,'abstractNumId'); if(!id) continue;
      const levels={};
      for(const lv of an.getElementsByTagNameNS(W,'lvl')){
        const il=parseInt(wa(lv,'ilvl')||'0');
        const nf=wfirst(lv,'numFmt'), lt=wfirst(lv,'lvlText'), st=wfirst(lv,'start'), pp=wfirst(lv,'pPr');
        let indent=null;
        if(pp){const ind=wfirst(pp,'ind');if(ind)indent={left:parseInt(wa(ind,'left')||'0'),hanging:parseInt(wa(ind,'hanging')||'0')};}
        levels[il]={numFmt:nf?wa(nf,'val'):'bullet', lvlText:lt?wa(lt,'val'):'•', start:st?parseInt(wa(st,'val')||'1'):1, indent};
      }
      this.abstract[id]=levels;
    }
    for(const num of doc.getElementsByTagNameNS(W,'num')){
      const id=wa(num,'numId'); if(!id) continue;
      const abd=wfirst(num,'abstractNumId');
      const overrides={};
      for(const ov of num.getElementsByTagNameNS(W,'lvlOverride')){
        const il=parseInt(wa(ov,'ilvl')||'0'); const so=wfirst(ov,'startOverride');
        if(so) overrides[il]=parseInt(wa(so,'val')||'1');
      }
      this.nums[id]={abstractId:abd?wa(abd,'val'):null, overrides};
    }
  }

  getLvl(numId,ilvl){
    const num=this.nums[numId]; if(!num) return null;
    const abs=this.abstract[num.abstractId]; if(!abs) return null;
    const lv=abs[ilvl]||abs[0]; if(!lv) return null;
    const start=num.overrides[ilvl]!==undefined?num.overrides[ilvl]:lv.start;
    return {...lv,start};
  }

  nextCount(numId,ilvl){
    const key=`${numId}:${ilvl}`;
    for(const k of Object.keys(this.counters)){
      const [kn,ki]=k.split(':').map(Number);
      if(kn===parseInt(numId)&&ki>ilvl) delete this.counters[k];
    }
    const lv=this.getLvl(numId,ilvl); const start=lv?lv.start:1;
    if(!(key in this.counters)) this.counters[key]=start;
    else this.counters[key]++;
    return this.counters[key];
  }

  isOrdered(numId,ilvl){const lv=this.getLvl(numId,ilvl); return lv&&lv.numFmt!=='bullet'&&lv.numFmt!=='none';}

  formatMarker(numId,ilvl,count){
    const lv=this.getLvl(numId,ilvl); if(!lv) return `${count}.`;
    if(lv.numFmt==='bullet'){
      const t=lv.lvlText||'•'; if(!t||t.includes('%')) return '•';
      const MAP={'\u2022':'•','\u2023':'▷','\u25e6':'◦','\u2043':'⁃','\uf0b7':'•','\u00b7':'•'};
      return MAP[t]||t;
    }
    if(lv.numFmt==='none') return '';
    const fmt=lv.lvlText||'%1.';
    const cvt=(n,f)=>{
      switch(f){
        case'lowerLetter': return String.fromCharCode(96+(((n-1)%26)+1));
        case'upperLetter': return String.fromCharCode(64+(((n-1)%26)+1));
        case'lowerRoman':  return toRoman(n).toLowerCase();
        case'upperRoman':  return toRoman(n);
        default:           return String(n);
      }
    };
    return fmt.replace(/%(\d)/g, (_,i)=> cvt(count, i==='1'?lv.numFmt:'decimal'));
  }

  reset(){this.counters={};}
}
