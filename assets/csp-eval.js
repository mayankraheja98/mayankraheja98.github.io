// Pure CSP evaluator. evalCSP(text) -> {score, grade, verdict, findings, directives, reportOnly, xssEffective}
(function(root){
var KNOWN=['default-src','script-src','script-src-elem','script-src-attr','style-src','style-src-elem','style-src-attr','img-src','font-src','connect-src','media-src','object-src','frame-src','child-src','worker-src','manifest-src','prefetch-src','base-uri','form-action','frame-ancestors','sandbox','report-uri','report-to','upgrade-insecure-requests','block-all-mixed-content','require-trusted-types-for','trusted-types','plugin-types','referrer','require-sri-for'];
var DEPRECATED={'block-all-mixed-content':'Deprecated; superseded by upgrade-insecure-requests.','plugin-types':'Deprecated and removed from the spec.','referrer':'Obsolete; use the Referrer-Policy header.','require-sri-for':'Removed; not supported by browsers.','prefetch-src':'Deprecated and not widely supported.'};
var UNQ=/^(self|none|unsafe-inline|unsafe-eval|strict-dynamic)$/i;
var NONCE=/^'nonce-([A-Za-z0-9+\/_=-]+)'$/, HASH=/^'sha(256|384|512)-[A-Za-z0-9+\/_=-]+'$/;
// hosts commonly abusable for CSP bypass (JSONP endpoints, hosted Angular/libs, user-content hosting)
var RISKY=['ajax.googleapis.com','cdnjs.cloudflare.com','cdn.jsdelivr.net','unpkg.com','raw.githubusercontent.com','googleapis.com','www.google.com','accounts.google.com','gstatic.com','github.io','githubusercontent.com','amazonaws.com','cloudfront.net','herokuapp.com','appspot.com','firebaseapp.com','web.app','azurewebsites.net','azureedge.net','netlify.app','vercel.app','pages.dev','workers.dev','ajax.aspnetcdn.com','code.jquery.com','yastatic.net'];
function hostOf(src){return src.replace(/^[a-z][a-z0-9+.-]*:\/\//i,'').split('/')[0].split(':')[0].toLowerCase()}
function riskyHost(src){
  if(/^'/.test(src)||/^[a-z][a-z0-9+.-]*:$/i.test(src)||src==='*')return null;
  var h=hostOf(src),w=h.indexOf('*.')===0,d=w?h.slice(2):h;
  for(var i=0;i<RISKY.length;i++){var r=RISKY[i];
    if(d===r||d.slice(-r.length-1)==='.'+r)return r;
    if(w&&(r===d||r.slice(-d.length-1)==='.'+d))return r}
  return null}
function parse(text){
  text=String(text||'').trim();var reportOnly=false,meta=false;
  var mm=text.match(/<meta[^>]*content=(["'])([\s\S]*?)\1/i);
  if(mm){meta=true;if(/content-security-policy-report-only/i.test(text))reportOnly=true;text=mm[2]}
  var m=text.match(/^content-security-policy(-report-only)?\s*:\s*/i);
  if(m){reportOnly=reportOnly||!!m[1];text=text.slice(m[0].length)}
  text=text.replace(/\r?\n/g,' ');
  var d=Object.create(null),order=[],dups=[];
  text.split(';').forEach(function(p){p=p.trim();if(!p)return;var t=p.split(/\s+/),n=t[0].toLowerCase();
    if(Object.prototype.hasOwnProperty.call(d,n)){dups.push(n);return}d[n]=t.slice(1);order.push(n)});
  return {d:d,order:order,dups:dups,reportOnly:reportOnly,meta:meta};
}
function evalCSP(text){
  var P=parse(text),d=P.d,F=[],score=100,cap=100;
  function add(sev,pts,title,detail,fix){F.push({sev:sev,pts:pts,title:title,detail:detail,fix:fix});score-=pts}
  function note(sev,title,detail,fix){F.push({sev:sev,pts:0,title:title,detail:detail,fix:fix})}
  if(!P.order.length)return {score:0,grade:'F',verdict:'No CSP directives found. The page has no Content-Security-Policy protection.',findings:[{sev:'critical',pts:100,title:'No policy',detail:'Empty or unparsable input.',fix:"Start with: script-src 'nonce-{RANDOM}' 'strict-dynamic' https: 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'"}],directives:[],reportOnly:false,xssEffective:false};
  if(P.reportOnly){cap=40;note('high','Report-Only mode: policy is not enforced','Content-Security-Policy-Report-Only only reports violations; it blocks nothing.','Once violations are triaged, ship the same policy in the enforcing Content-Security-Policy header.')}
  if(P.meta)add('low',3,'Delivered via <meta> tag','Meta CSP cannot use frame-ancestors, report-uri or sandbox, and only applies after the tag is parsed.','Deliver CSP as an HTTP response header.');
  P.dups.forEach(function(n){note('low','Duplicate directive: '+n,'Browsers use only the first occurrence; later ones are ignored.','Merge into a single directive.')});

  P.order.forEach(function(n){
    var vs=d[n];
    if(KNOWN.indexOf(n)<0)add('low',3,'Unknown directive: '+n,'Not a recognised CSP directive; browsers ignore it. Possible typo.','Check the spelling against the CSP spec.');
    if(Object.prototype.hasOwnProperty.call(DEPRECATED,n))note('info','Deprecated directive: '+n,DEPRECATED[n],'Remove it.');
    vs.forEach(function(v){if(UNQ.test(v))add('medium',8,'Unquoted keyword "'+v+'" in '+n,'Without quotes this is treated as a hostname, not the CSP keyword, so the policy does not do what you intend.',"Write it as '"+v.toLowerCase()+"'.")});
    if(vs.indexOf("'none'")>-1&&vs.length>1)note('low',"'none' combined with other sources in "+n,"'none' is ignored when other sources are present.","Use either 'none' alone or an explicit list.");
  });

  // ---- script control
  var scriptDirs=[];
  if(d['script-src'])scriptDirs.push(['script-src',d['script-src']]);
  else if(d['default-src'])scriptDirs.push(['default-src (fallback for script-src)',d['default-src']]);
  if(d['script-src-elem'])scriptDirs.push(['script-src-elem',d['script-src-elem']]);
  var xssOk=true;
  if(!scriptDirs.length){add('critical',35,'No script restriction','Neither script-src nor default-src is set, so scripts from anywhere run. XSS is not mitigated.',"Add script-src with nonces or hashes, e.g. script-src 'nonce-{RANDOM}' 'strict-dynamic'; or at minimum default-src 'self'.");xssOk=false}
  scriptDirs.forEach(function(sd){
    var name=sd[0],v=sd[1],nonce=false,hash=false,sdyn=false,short=false;
    v.forEach(function(s){var m=s.match(NONCE);if(m){nonce=true;if(m[1].length<16)short=true}if(HASH.test(s))hash=true;if(s==="'strict-dynamic'")sdyn=true});
    var modern=nonce||hash,trusted=sdyn&&modern;
    if(short)add('medium',5,'Short nonce in '+name,'Nonces should carry at least 128 bits of entropy (16+ base64 chars) and change on every response.','Generate a fresh cryptographically random nonce per response.');
    if(nonce&&!short)note('info','Nonce in '+name+': verify it is unique per response','A static or reused nonce is trivially bypassable.','Generate a new random nonce on every response.');
    if(sdyn&&!modern)add('low',3,"'strict-dynamic' without nonce/hash in "+name,"strict-dynamic only takes effect together with a nonce or hash.","Add a 'nonce-…' or hash source.");
    if(trusted)note('good',"Strict policy: nonce/hash + 'strict-dynamic' in "+name,"Modern browsers ignore host allow-lists and 'unsafe-inline' here, which is the recommended approach.","Keep https: / 'unsafe-inline' only as legacy fallbacks.");
    else if(modern)note('good','Nonce/hash used in '+name,'Inline scripts need a matching nonce or hash.',"Consider adding 'strict-dynamic' to simplify and strengthen the policy.");
    v.forEach(function(s){
      if(s==="'unsafe-inline'"){
        if(modern)note('info',"'unsafe-inline' in "+name+' (ignored)',"Ignored by browsers that understand nonces/hashes; only a fallback for very old browsers.",'Acceptable as a fallback.');
        else{add('high',30,"'unsafe-inline' in "+name,'Allows inline scripts and event handlers, which defeats CSP as an XSS defence.','Remove it; use nonces or hashes and move inline handlers into script files.');xssOk=false}
      }else if(s==="'unsafe-eval'")add('medium',15,"'unsafe-eval' in "+name,'Allows eval(), new Function() and string timers, a common XSS gadget.',"Remove it and refactor eval usage; use 'wasm-unsafe-eval' if only WebAssembly needs it.");
      else if(s==="'unsafe-hashes'")add('low',4,"'unsafe-hashes' in "+name,'Allows specific inline event handlers by hash, weakening the policy.','Move handlers into script files with addEventListener.');
      else if(s==="'wasm-unsafe-eval'")note('info',"'wasm-unsafe-eval' in "+name,'Permits WebAssembly compilation only; much narrower than unsafe-eval.','Fine if you need WebAssembly.');
      else if(trusted){/* host/scheme lists are ignored under strict-dynamic */}
      else if(s==='*'){add('high',30,'Wildcard * in '+name,'Allows scripts from any host.','Replace * with specific trusted hosts or move to nonces.');xssOk=false}
      else if(s==='data:'){add('high',30,'data: in '+name,'data: URIs allow attacker-controlled scripts.','Remove data:.');xssOk=false}
      else if(s==='http:'){add('high',25,'http: scheme in '+name,'Allows scripts from any plain-HTTP host, which can also be tampered with in transit.','Remove it.');xssOk=false}
      else if(s==='https:'){add('high',20,'https: scheme-wide source in '+name,'Allows scripts from any HTTPS host on the internet.',"Allow specific hosts, or use nonces with 'strict-dynamic'.");xssOk=false}
      else if(s==='blob:'||s==='filesystem:')add('medium',12,s+' in '+name,'Attacker-influenced content can be loaded as script via '+s+' URLs.','Remove it unless strictly required.');
      else if(/^http:\/\//i.test(s))add('low',5,'Insecure http:// source in '+name+': '+s,'Scripts fetched over HTTP can be modified by a network attacker.','Use https://.');
      else if(/^(https?:\/\/)?\*\./i.test(s)&&!riskyHost(s))add('low',6,'Wildcard subdomain in '+name+': '+s,'Any subdomain, including forgotten or takeover-prone ones, is trusted.','List exact hosts.');
      var r=riskyHost(s);
      if(r&&!trusted)add('high',15,'Bypass-prone host in '+name+': '+s,'"'+r+'" hosts JSONP endpoints, popular libraries (e.g. AngularJS) or user content that can be abused to run arbitrary script despite the allow-list.',"Self-host the needed files with SRI, or switch to nonces + 'strict-dynamic'.");
    });
    if(!trusted&&!modern&&v.indexOf("'self'")>-1)add('low',3,"'self' in "+name,'Any JSONP endpoint, upload or reflected file on your own origin becomes a script source.','Prefer nonces/hashes; make sure no user-controlled files are served from the origin.');
  });

  // ---- object-src / base-uri / frame-ancestors / form-action
  var obj=d['object-src']||d['default-src'];
  if(!(obj&&obj.length===1&&obj[0]==="'none'")){
    if(!obj)add('high',15,'object-src not set','Plugin content (<object>/<embed>) is unrestricted and has historically been a CSP bypass.',"Add object-src 'none'.");
    else add('medium',10,"object-src is not 'none'",'Plugin content is permitted.',"Set object-src 'none'.");
  }
  var bu=d['base-uri'];
  if(!bu)add('medium',8,'base-uri not set','An injected <base> tag can redirect relative script URLs to an attacker host (base-uri does not fall back to default-src).',"Add base-uri 'none' (or 'self').");
  else if(bu.some(function(s){return s==='*'||s==='https:'||s==='http:'}))add('medium',8,'base-uri is too permissive','Allows <base> pointing to arbitrary hosts.',"Use 'none' or 'self'.");
  var fa=d['frame-ancestors'];
  if(!fa&&!P.meta)add('medium',10,'frame-ancestors not set','The page can be framed by any site, enabling clickjacking (X-Frame-Options may cover this separately).',"Add frame-ancestors 'self' (or 'none').");
  else if(fa&&fa.some(function(s){return s==='*'||s==='https:'||s==='http:'}))add('medium',10,'frame-ancestors is too permissive','Any site can frame this page.',"Restrict to 'self' or named partners.");
  var fm=d['form-action'];
  if(!fm)add('low',5,'form-action not set','Forms (including injected ones) can submit to any host; it does not fall back to default-src.',"Add form-action 'self'.");
  else if(fm.indexOf('*')>-1)add('low',5,'form-action allows *','Forms can submit to any host.',"Use 'self' or named hosts.");

  // ---- other fetch directives
  ['connect-src','img-src','frame-src','child-src','media-src','font-src','style-src','worker-src','manifest-src'].forEach(function(n){
    var v=d[n];if(!v)return;
    var pts=n==='connect-src'?5:n==='worker-src'?8:2;
    var broad=v.indexOf('*')>-1||v.indexOf('https:')>-1||v.indexOf('http:')>-1||(n==='connect-src'&&v.indexOf('data:')>-1);
    if(broad)add('low',pts,'Broad source in '+n,'Wildcard or scheme-wide sources allow loading or sending data to arbitrary hosts'+(n==='connect-src'?' (data exfiltration)':'')+'.','Allow-list only the hosts you need.');
    if(n==='style-src'&&v.indexOf("'unsafe-inline'")>-1&&!v.some(function(s){return NONCE.test(s)||HASH.test(s)}))add('low',4,"'unsafe-inline' in style-src",'Inline styles enable CSS-based data exfiltration and UI redressing.','Use nonces/hashes for inline styles, or external stylesheets.');
  });
  if(!d['default-src']&&!d['connect-src'])add('low',3,'No default-src fallback',"Fetch directives you did not list (connect-src, img-src, …) are unrestricted.","Add default-src 'self' or 'none' as a baseline.");
  if(!d['upgrade-insecure-requests']&&!d['block-all-mixed-content'])add('info',2,'upgrade-insecure-requests not set','Mixed-content http:// subresources are not auto-upgraded.','Add upgrade-insecure-requests if the site is HTTPS-only.');
  if(!d['report-uri']&&!d['report-to'])note('info','No violation reporting','Without report-uri / report-to you will not learn about violations or attacks.','Add report-to (with a Reporting-Endpoints header) and keep report-uri as a fallback.');
  if(d['require-trusted-types-for'])note('good','Trusted Types enforced','Strong defence against DOM-based XSS sinks.','Keep it, and restrict trusted-types policy names.');
  else note('info','Trusted Types not enabled','DOM XSS sinks (innerHTML etc.) are not locked down.',"Consider require-trusted-types-for 'script' once your code supports it.");

  if(!xssOk)cap=Math.min(cap,49);
  score=Math.max(0,Math.min(score,cap));
  var grade=score>=90?'A':score>=75?'B':score>=60?'C':score>=40?'D':'F';
  var ord={critical:0,high:1,medium:2,low:3,info:4,good:5};
  F.sort(function(a,b){return ord[a.sev]-ord[b.sev]});
  var verdict=!xssOk?'Script controls are weak: this CSP will not reliably stop XSS.':P.reportOnly?'Policy looks reasonable but is only reporting, not enforcing.':score>=75?'Strong policy: script execution is meaningfully restricted.':'Script execution is restricted, but hardening gaps remain.';
  return {score:score,grade:grade,verdict:verdict,findings:F,directives:P.order.map(function(n){return [n,d[n]]}),reportOnly:P.reportOnly,xssEffective:xssOk};
}
root.evalCSP=evalCSP;if(typeof module!=='undefined')module.exports={evalCSP:evalCSP};
})(typeof window!=='undefined'?window:globalThis);
