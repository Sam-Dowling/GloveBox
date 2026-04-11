'use strict';
// ════════════════════════════════════════════════════════════════════════════
// style-resolver.js — Resolves Word paragraph and run styles with inheritance
// Depends on: constants.js
// ════════════════════════════════════════════════════════════════════════════
class StyleResolver {
  constructor(doc) {
    this.styles = {}; this.defaults = {run:{}, para:{}};
    if (doc) { this._parseDefaults(doc); this._parseStyles(doc); }
  }

  _parseDefaults(doc) {
    const dd = wfirst(doc, 'docDefaults'); if (!dd) return;
    const rDef = wfirst(dd,'rPrDefault'); if(rDef){const r=wfirst(rDef,'rPr');if(r)this.defaults.run=this._rpr(r);}
    const pDef = wfirst(dd,'pPrDefault'); if(pDef){const p=wfirst(pDef,'pPr');if(p)this.defaults.para=this._ppr(p);}
  }

  _parseStyles(doc) {
    for (const s of doc.getElementsByTagNameNS(W,'style')) {
      const id = wa(s,'styleId'); if (!id) continue;
      const bo = wfirst(s,'basedOn');
      this.styles[id] = {
        id, type:wa(s,'type'),
        name: (wfirst(s,'name') && wa(wfirst(s,'name'),'val')) || id,
        basedOn: bo ? wa(bo,'val') : null,
        rPr: wfirst(s,'rPr') ? this._rpr(wfirst(s,'rPr')) : {},
        pPr: wfirst(s,'pPr') ? this._ppr(wfirst(s,'pPr')) : {},
      };
    }
  }

  _rpr(el) {
    if (!el) return {};
    const p = {};
    const bool = (tag, key) => {
      const e = wfirst(el,tag); if(e){ const v=wa(e,'val'); p[key]=(v!=='0'&&v!=='false'); }
    };
    bool('b','bold'); bool('i','italic'); bool('strike','strike');
    bool('dstrike','dstrike'); bool('caps','caps'); bool('smallCaps','smallCaps'); bool('vanish','hidden');
    const u=wfirst(el,'u'); if(u){const v=wa(u,'val'); p.underline=(!!v&&v!=='none');}
    const c=wfirst(el,'color'); if(c){const v=wa(c,'val');if(v&&v!=='auto')p.color='#'+v;}
    const sz=wfirst(el,'sz'); if(sz){const v=parseInt(wa(sz,'val')||'');if(!isNaN(v))p.fontSize=v/2;}
    const rf=wfirst(el,'rFonts'); if(rf) p.fontFamily=wa(rf,'ascii')||wa(rf,'hAnsi')||wa(rf,'cs');
    const hl=wfirst(el,'highlight'); if(hl){const v=wa(hl,'val');if(v&&v!=='none')p.highlight=v;}
    const va=wfirst(el,'vertAlign'); if(va) p.vertAlign=wa(va,'val');
    const rs=wfirst(el,'rStyle'); if(rs) p.rStyleId=wa(rs,'val');
    return p;
  }

  _ppr(el) {
    if (!el) return {};
    const p = {};
    const jc=wfirst(el,'jc'); if(jc) p.jc=wa(jc,'val');
    const ind=wfirst(el,'ind');
    if(ind){
      const lv=wa(ind,'left'),rv=wa(ind,'right'),hv=wa(ind,'hanging'),fv=wa(ind,'firstLine');
      if(lv)p.indLeft=parseInt(lv); if(rv)p.indRight=parseInt(rv);
      if(hv)p.indHanging=parseInt(hv); if(fv)p.indFirstLine=parseInt(fv);
    }
    const sp=wfirst(el,'spacing');
    if(sp){
      const bv=wa(sp,'before'),av=wa(sp,'after'),lv=wa(sp,'line'),lr=wa(sp,'lineRule');
      if(bv)p.spaceBefore=parseInt(bv); if(av)p.spaceAfter=parseInt(av);
      if(lv){p.spaceLine=parseInt(lv); p.spaceLineRule=lr||'auto';}
    }
    const shd=wfirst(el,'shd'); if(shd){const f=wa(shd,'fill');if(f&&f!=='auto')p.bgColor='#'+f;}
    const ps=wfirst(el,'pStyle'); if(ps) p.styleId=wa(ps,'val');
    const pb=wfirst(el,'pageBreakBefore'); if(pb) p.pageBreakBefore=(wa(pb,'val')!=='0'&&wa(pb,'val')!=='false');
    const np=wfirst(el,'numPr');
    if(np){
      const ni=wfirst(np,'numId'),il=wfirst(np,'ilvl');
      if(ni) p.numId=wa(ni,'val');
      p.ilvl = il ? parseInt(wa(il,'val')||'0') : 0;
    }
    const pBdr=wfirst(el,'pBdr');
    if(pBdr){
      p.borders={};
      for(const side of ['top','bottom','left','right']){
        const b=wfirst(pBdr,side);
        if(b){const v=wa(b,'val'),sz=wa(b,'sz'),col=wa(b,'color');
          if(v&&v!=='none') p.borders[side]={
            width:sz?parseInt(sz)/8:1, color:col&&col!=='auto'?'#'+col:'#000', style:'solid'
          };
        }
      }
    }
    return p;
  }

  resolveRunStyle(id, _depth=0) {
    if (!id||!this.styles[id]||_depth>10) return {};
    const s=this.styles[id];
    const base = s.basedOn ? this.resolveRunStyle(s.basedOn,_depth+1) : {...this.defaults.run};
    return {...base,...s.rPr};
  }

  resolveParaStyle(id, _depth=0) {
    if (!id||!this.styles[id]||_depth>10) return {pPr:{...this.defaults.para},rPr:{...this.defaults.run}};
    const s=this.styles[id];
    const base = s.basedOn ? this.resolveParaStyle(s.basedOn,_depth+1) : {pPr:{...this.defaults.para},rPr:{...this.defaults.run}};
    return {pPr:{...base.pPr,...s.pPr}, rPr:{...base.rPr,...s.rPr}};
  }

  isHeading(id) {
    if (!id) return null;
    const s=this.styles[id]; if(!s) return null;
    const name=(s.name||'').toLowerCase().replace(/\s+/g,'');
    const m=name.match(/^heading(\d+)$/); if(m) return parseInt(m[1]);
    const m2=id.match(/^[Hh]eading(\d+)$/); if(m2) return parseInt(m2[1]);
    return null;
  }
}
