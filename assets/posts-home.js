// Fills "Latest writing" on the home page from posts/index.json (hidden if there are no posts).
fetch('posts/index.json').then(function(r){return r.ok?r.json():[]}).then(function(p){
  if(!p.length)return;
  function e(s){return String(s).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]})}
  document.getElementById('lp').innerHTML=p.slice(0,3).map(function(x){var ext=x.url&&/^https:\/\//.test(x.url);return '<a class="card post-card" href="'+(ext?e(x.url)+'" target="_blank" rel="noopener':'blog.html#'+e(x.slug))+'"><div class="meta mono">'+e(x.date)+(ext?' · medium ↗':'')+'</div><h3 style="margin-top:6px">'+e(x.title)+'</h3><p>'+e(x.summary)+'</p></a>'}).join('');
  document.getElementById('latest').hidden=false;
}).catch(function(){});
