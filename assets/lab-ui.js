// Shared report renderer for labs: renderReport(el, result, {side: html})
(function(root){
var COL={critical:'#ff4d4d',high:'#ff6b6b',medium:'#f0b429',low:'#5ab0ff',info:'#8a98ad',good:'#2ee6a6'};
function esc(s){return String(s).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]})}
function renderReport(el,r,o){
  o=o||{};
  var col=r.score>=75?'#2ee6a6':r.score>=50?'#f0b429':'#ff6b6b',counts={};
  r.findings.forEach(function(f){counts[f.sev]=(counts[f.sev]||0)+1});
  var chips=['critical','high','medium','low','info','good'].filter(function(k){return counts[k]}).map(function(k){return '<span class="chip" style="color:'+COL[k]+';border-color:'+COL[k]+'">'+counts[k]+' '+k+'</span>'}).join('');
  var list=r.findings.map(function(f){return '<div class="box" style="border-left:3px solid '+COL[f.sev]+';margin-bottom:10px"><div class="mono" style="font-size:12px;color:'+COL[f.sev]+'">'+f.sev.toUpperCase()+(f.pts?' · −'+f.pts:'')+'</div><h3 style="margin:4px 0">'+esc(f.title)+'</h3><p style="color:var(--mute);font-size:14.5px">'+esc(f.detail)+'</p>'+(f.fix?'<p style="font-size:14.5px;margin-top:6px"><b class="ok">Fix:</b> '+esc(f.fix)+'</p>':'')+'</div>'}).join('');
  el.innerHTML='<div class="lab-cols"><div class="box" style="display:flex;gap:22px;align-items:center;flex-wrap:wrap"><div style="width:120px;height:120px;border-radius:50%;background:conic-gradient('+col+' '+r.score*3.6+'deg,var(--line) 0);display:grid;place-items:center"><div style="width:96px;height:96px;border-radius:50%;background:var(--panel);display:grid;place-items:center;text-align:center"><div><div style="font-size:32px;font-weight:700;color:'+col+'">'+r.score+'</div><div class="mono" style="font-size:12px;color:var(--mute)">grade '+r.grade+'</div></div></div></div><div style="flex:1;min-width:200px"><h3 style="font-size:17px;margin-bottom:8px">'+esc(r.verdict)+'</h3><div class="chips">'+chips+'</div></div></div>'+(o.side?'<div class="box">'+o.side+'</div>':'<div></div>')+'</div><h2 style="margin-top:26px">Findings &amp; recommendations</h2>'+list;
}
root.renderReport=renderReport;root.labEsc=esc;
})(window);
