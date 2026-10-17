// Response-header evaluator. evalHeaders(text,{partial}) -> {score,grade,verdict,findings,headers,cookies}
// frameVerdict(text) -> {framable: true|false|null, reason}
(function(root){
function parseHeaders(text){
  text=String(text||'').replace(/\r/g,'').trim();
  // several responses (redirect chain)? keep the last block that starts with an HTTP status line
  var blocks=text.split(/\n\s*\n(?=HTTP\/)/);text=blocks[blocks.length-1];
  var h=Object.create(null),cookies=[],status=null,order=[];
  text.split('\n').forEach(function(line){
    var m=line.match(/^HTTP\/[\d.]+\s+(\d{3})/i);if(m){status=m[1];return}
    var i=line.indexOf(':');if(i<1)return;
    var n=line.slice(0,i).trim().toLowerCase(),v=line.slice(i+1).trim();
    if(!/^[a-z0-9!#$%&'*+.^_`|~-]+$/.test(n))return;
    if(n==='set-cookie'){cookies.push(v);return}
    if(h[n]!==undefined)h[n]+=', '+v;else{h[n]=v;order.push(n)}
  });
  return {h:h,cookies:cookies,status:status,order:order};
}
function parseCookie(c){
  var p=c.split(';').map(function(s){return s.trim()}),nv=p.shift(),i=nv.indexOf('='),a={};
  p.forEach(function(x){var j=x.indexOf('=');var k=(j<0?x:x.slice(0,j)).toLowerCase();a[k]=j<0?true:x.slice(j+1)});
  return {name:i<0?nv:nv.slice(0,i),attrs:a};
}
function frameAncestors(h){
  var csp=h['content-security-policy']; if(!csp)return null;
  var m=csp.split(';').map(function(s){return s.trim()}).filter(function(s){return /^frame-ancestors\s/i.test(s)})[0];
  return m?m.split(/\s+/).slice(1):null;
}
function frameVerdict(text){
  var P=parseHeaders(text),h=P.h,xfo=h['x-frame-options'],fa=frameAncestors(h);
  if(!P.order.length&&!P.cookies.length)return {framable:null,reason:'No headers provided.'};
  if(fa){ if(fa.length===1&&fa[0]==="'none'")return {framable:false,reason:"CSP frame-ancestors 'none' blocks all framing."};
    if(fa.indexOf('*')>-1||fa.indexOf('https:')>-1||fa.indexOf('http:')>-1)return {framable:true,reason:'CSP frame-ancestors is overly permissive ('+fa.join(' ')+').'};
    return {framable:false,reason:'CSP frame-ancestors restricts framing to: '+fa.join(' ')+'. Only those origins can frame this page.'} }
  if(xfo){var v=xfo.toLowerCase();
    if(/deny/.test(v))return {framable:false,reason:'X-Frame-Options: DENY blocks framing.'};
    if(/sameorigin/.test(v))return {framable:false,reason:'X-Frame-Options: SAMEORIGIN only allows same-origin framing.'};
    if(/allow-from/.test(v))return {framable:true,reason:'ALLOW-FROM is obsolete and ignored by modern browsers, so the page is likely framable.'};
    return {framable:true,reason:'Unrecognised X-Frame-Options value "'+xfo+'" will be ignored by browsers.'}}
  return {framable:true,reason:'Neither X-Frame-Options nor CSP frame-ancestors is present, so any site can frame this page.'};
}
function evalHeaders(text,opts){
  opts=opts||{};var P=parseHeaders(text),h=P.h,F=[],score=100,partial=!!opts.partial;
  function add(sev,pts,title,detail,fix){F.push({sev:sev,pts:pts,title:title,detail:detail,fix:fix});score-=pts}
  function note(sev,title,detail,fix){F.push({sev:sev,pts:0,title:title,detail:detail,fix:fix})}
  // a "missing" finding: downgraded to info when we can't see all headers
  function miss(sev,pts,title,detail,fix){if(partial)note('info',title+' (not visible)','Header not exposed via CORS, so absence cannot be confirmed. '+detail,fix);else add(sev,pts,title,detail,fix)}
  if(!P.order.length&&!P.cookies.length)return {score:0,grade:'F',verdict:'No headers could be parsed. Paste raw response headers (Name: value per line).',findings:[],headers:[],cookies:[]};

  // HSTS
  var hsts=h['strict-transport-security'];
  if(!hsts)miss('high',15,'Strict-Transport-Security missing','Browsers may connect over HTTP first, enabling SSL-stripping and downgrade attacks (only matters on HTTPS responses).','Strict-Transport-Security: max-age=31536000; includeSubDomains');
  else{var ma=(hsts.match(/max-age\s*=\s*"?(\d+)/i)||[])[1];
    if(!ma)add('medium',8,'HSTS has no valid max-age','The directive is required; the header is ignored without it.','Add max-age=31536000.');
    else if(+ma<15552000)add('low',5,'HSTS max-age is short ('+ma+'s)','Protection lapses quickly if the user does not revisit.','Use at least 31536000 (1 year).');
    else note('good','HSTS enabled (max-age='+ma+')','Browsers will refuse plain-HTTP connections.','Add includeSubDomains (and consider preload) if all subdomains are HTTPS.');
    if(ma&&!/includesubdomains/i.test(hsts))note('info','HSTS without includeSubDomains','Subdomains can still be downgraded or cookie-injected.','Add includeSubDomains once all subdomains support HTTPS.')}

  // CSP
  var csp=h['content-security-policy'];
  if(!csp&&h['content-security-policy-report-only'])miss('medium',12,'Only a Report-Only CSP is present','Report-Only does not block anything.','Promote it to Content-Security-Policy once violations are clean.');
  else if(!csp)miss('high',20,'Content-Security-Policy missing','No browser-enforced defence in depth against XSS and data injection.',"Start with: script-src 'nonce-{RANDOM}' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'");
  else if(root.evalCSP){var r=root.evalCSP(csp);
    if(!r.xssEffective)add('high',12,'CSP present but weak (CSP score '+r.score+'/'+r.grade+')','The policy does not effectively restrict script execution. See the CSP Evaluator lab for specific gaps.','Run the policy through the CSP Evaluator and fix the high findings.');
    else if(r.score<75)add('low',5,'CSP present with gaps (CSP score '+r.score+'/'+r.grade+')','Script control is OK but hardening directives are missing.','Run the policy through the CSP Evaluator.');
    else note('good','Strong CSP (CSP score '+r.score+'/'+r.grade+')','Script execution is meaningfully restricted.','Keep monitoring violations.')}
  else note('good','CSP present','Content-Security-Policy header found.','Review it with the CSP Evaluator lab.');

  // Framing
  var xfo=h['x-frame-options'],fa=frameAncestors(h);
  if(!xfo&&!fa)miss('medium',10,'No clickjacking protection','Neither X-Frame-Options nor CSP frame-ancestors is set, so other sites can frame the page.',"Content-Security-Policy: frame-ancestors 'self' (and X-Frame-Options: SAMEORIGIN for old browsers)");
  else{ if(xfo&&/allow-from/i.test(xfo))add('low',4,'X-Frame-Options ALLOW-FROM is obsolete','Modern browsers ignore it.',"Use CSP frame-ancestors with explicit origins.");
    else if(xfo&&!/^(deny|sameorigin)$/i.test(xfo.trim()))add('medium',6,'Invalid X-Frame-Options value: '+xfo,'Only DENY and SAMEORIGIN are valid; others are ignored.','Use DENY or SAMEORIGIN.');
    else note('good','Framing restricted','Clickjacking protection present ('+(fa?'frame-ancestors '+fa.join(' '):'X-Frame-Options: '+xfo)+').',fa?'':'Also add CSP frame-ancestors.')}

  // nosniff
  var xcto=h['x-content-type-options'];
  if(!xcto)miss('medium',8,'X-Content-Type-Options missing','Browsers may MIME-sniff responses, turning uploads or JSON into executable content.','X-Content-Type-Options: nosniff');
  else if(!/nosniff/i.test(xcto))add('low',5,'X-Content-Type-Options has wrong value: '+xcto,'Only "nosniff" is valid.','X-Content-Type-Options: nosniff');
  else note('good','X-Content-Type-Options: nosniff','MIME sniffing disabled.','');

  // Referrer / Permissions
  var rp=h['referrer-policy'];
  if(!rp)miss('low',5,'Referrer-Policy missing','Full URLs (possibly containing tokens or IDs) may leak to other origins.','Referrer-Policy: strict-origin-when-cross-origin (or no-referrer)');
  else if(/unsafe-url|^no-referrer-when-downgrade$/i.test(rp.trim()))add('low',3,'Referrer-Policy is lenient: '+rp,'Leaks the full URL cross-origin.','Use strict-origin-when-cross-origin or stricter.');
  else note('good','Referrer-Policy: '+rp,'Referrer leakage is limited.','');
  if(!h['permissions-policy']&&!h['feature-policy'])miss('low',4,'Permissions-Policy missing','Powerful features (camera, microphone, geolocation, …) are not explicitly restricted.','Permissions-Policy: camera=(), microphone=(), geolocation=()');
  else if(h['feature-policy']&&!h['permissions-policy'])note('info','Feature-Policy is deprecated','Replaced by Permissions-Policy.','Migrate to Permissions-Policy.');

  // cross-origin isolation (informational)
  ['cross-origin-opener-policy','cross-origin-resource-policy','cross-origin-embedder-policy'].forEach(function(n){
    if(!h[n])miss('info',n==='cross-origin-embedder-policy'?0:2,n.replace(/(^|-)./g,function(c){return c.toUpperCase()})+' not set','Part of cross-origin isolation / Spectre-era hardening.',n==='cross-origin-opener-policy'?'Cross-Origin-Opener-Policy: same-origin':n==='cross-origin-resource-policy'?'Cross-Origin-Resource-Policy: same-origin (or same-site)':'Cross-Origin-Embedder-Policy: require-corp (only if you need isolation)')});

  // X-XSS-Protection
  var xxp=h['x-xss-protection'];
  if(xxp!==undefined){var t=xxp.trim();
    if(/^0/.test(t))note('good','X-XSS-Protection: 0','The legacy XSS auditor is disabled, which is the modern recommendation.','');
    else if(/mode\s*=\s*block/i.test(t))note('info','X-XSS-Protection: '+xxp+' (legacy)','Deprecated and ignored by modern browsers; the old auditor itself had security issues.','Replace with a strong CSP and set X-XSS-Protection: 0 (or remove it).');
    else add('low',2,'X-XSS-Protection enabled without mode=block','The legacy auditor in "sanitize" mode could be abused to disable legitimate scripts.','Set X-XSS-Protection: 0 and rely on CSP.')}
  else note('info','X-XSS-Protection absent','Fine: the header is deprecated and ignored by modern browsers. Rely on CSP instead.','');

  // information disclosure
  var srv=h['server'];
  if(srv){ if(/\d+\.\d+/.test(srv))add('low',5,'Server header discloses version: '+srv,'Version banners help attackers pick known exploits.','Remove the version (e.g. ServerTokens Prod / server_tokens off).');
    else note('info','Server header present: '+srv,'Reveals the technology stack.','Consider removing or genericising it.')}
  ['x-powered-by','x-aspnet-version','x-aspnetmvc-version','x-generator','x-drupal-cache','x-runtime','x-backend-server','x-server','x-served-by','x-php-version','x-version'].forEach(function(n){
    if(h[n]!==undefined)add('low',4,'Information disclosure: '+n+': '+h[n],'Exposes framework, version or infrastructure details.','Remove this header at the app or proxy.')});

  // CORS
  var aco=h['access-control-allow-origin'],acc=(h['access-control-allow-credentials']||'').toLowerCase()==='true';
  if(aco){ if(aco==='*'&&acc)add('high',20,'CORS: wildcard origin with credentials','Browsers reject this combination, but it signals a misconfiguration (often paired with reflected origins).','Return a specific allow-listed origin.');
    else if(aco==='null')add('medium',10,'CORS allows Origin: null','Sandboxed iframes and local files send a null origin, so any attacker can satisfy this.','Never allow the null origin.');
    else if(aco==='*')note('info','CORS: Access-Control-Allow-Origin: *','Fine for public, unauthenticated resources only.','Do not use on endpoints returning user-specific data.');
    else if(acc)note('info','CORS with credentials for '+aco,'Verify the origin is validated against an allow-list and not reflected from the request.','Never reflect arbitrary Origin values.')}

  // caching
  var cc=h['cache-control']||'';
  if(!cc&&!h['pragma'])miss('info',2,'Cache-Control missing','Responses with sensitive data could be cached by browsers or proxies.','Cache-Control: no-store (for authenticated or sensitive pages)');
  else if(cc&&!/no-store/i.test(cc))note('info','Cache-Control lacks no-store','Fine for public assets; sensitive pages should use no-store.','Use Cache-Control: no-store on authenticated responses.');

  // deprecated
  if(h['public-key-pins'])add('low',2,'HPKP (Public-Key-Pins) present','Deprecated and removed; risks self-inflicted denial of service.','Remove it.');
  if(h['expect-ct'])note('info','Expect-CT is deprecated','Certificate Transparency is now enforced by browsers.','Remove it.');

  // cookies
  var cookies=P.cookies.map(parseCookie),cpts=0,cn=[];
  cookies.forEach(function(c){var a=c.attrs,prob=[];
    var host=/^__host-/i.test(c.name),secure=a.secure!==undefined,ss=(typeof a.samesite==='string'?a.samesite.toLowerCase():null);
    if(!secure){prob.push('no Secure');cpts+=5}
    if(a.httponly===undefined){prob.push('no HttpOnly');cpts+=4}
    if(!ss){prob.push('no SameSite');cpts+=3}
    else if(ss==='none'&&!secure){prob.push('SameSite=None without Secure (rejected by browsers)');cpts+=3}
    if(a.domain&&!host)prob.push('Domain='+a.domain+' (shared with all subdomains)');
    if(/^__secure-/i.test(c.name)&&!secure)prob.push('__Secure- prefix without Secure');
    if(host&&(!secure||a.path!=='/'||a.domain!==undefined))prob.push('__Host- prefix rules violated (needs Secure, Path=/, no Domain)');
    cn.push({name:c.name,problems:prob})});
  if(cookies.length){var tot=Math.min(cpts,20),bad=cn.filter(function(x){return x.problems.length});
    if(bad.length)add('medium',tot,'Cookie flag issues ('+bad.length+' of '+cookies.length+')',bad.map(function(x){return x.name+': '+x.problems.join(', ')}).join(' · '),'Set Secure; HttpOnly; SameSite=Lax (or Strict) on session cookies; consider the __Host- prefix.');
    else note('good','All cookies have recommended flags','Secure, HttpOnly and SameSite present on '+cookies.length+' cookie(s).','')}
  else if(partial)note('info','Cookies not visible','Set-Cookie headers are never exposed to JavaScript via fetch.','Paste raw headers (curl -sI) to evaluate cookie flags.');
  else note('info','No Set-Cookie headers in this response','Cookies set on other responses (e.g. login) are not covered.','Check the login response separately.');

  score=Math.max(0,Math.min(100,score));
  var grade=score>=90?'A':score>=75?'B':score>=60?'C':score>=40?'D':'F';
  var o={critical:0,high:1,medium:2,low:3,info:4,good:5};F.sort(function(a,b){return o[a.sev]-o[b.sev]});
  var verdict=partial?'Partial view (CORS-limited): score is indicative only, missing headers were not penalised.':score>=90?'Excellent header hygiene.':score>=75?'Good, with a few gaps.':score>=60?'Fair: several protections are missing.':'Weak: key security headers are missing or misconfigured.';
  return {score:score,grade:grade,verdict:verdict,findings:F,headers:P.order.map(function(n){return [n,h[n]]}),cookies:P.cookies};
}
root.evalHeaders=evalHeaders;root.frameVerdict=frameVerdict;
if(typeof module!=='undefined')module.exports={evalHeaders:evalHeaders,frameVerdict:frameVerdict};
})(typeof window!=='undefined'?window:globalThis);
