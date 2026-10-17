// SPF / DMARC / DKIM analysis. Pure logic; DNS is injected so it can be tested offline.
// analyzeEmailAuth(domain, dns, opts) where dns = {txt(name)->Promise<string[]>, mx(name)->Promise<string[]>}
(function(root){
var COMMON_SELECTORS=['default','google','selector1','selector2','k1','k2','s1','s2','mail','dkim','mandrill','smtp','mxvault','zoho','amazonses'];
function norm(d){return String(d||'').trim().toLowerCase().replace(/^[a-z]+:\/\//,'').replace(/^.*@/,'').split('/')[0].replace(/\.$/,'')}
function validDomain(d){return /^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,63}$/.test(d)}
function orgDomain(d){var p=d.split('.');if(p.length<=2)return d;var two=p.slice(-2).join('.');
  return /^(co|com|org|net|gov|ac|edu)\.[a-z]{2}$/.test(two)?p.slice(-3).join('.'):two}
function parseSPF(rec){
  var t=rec.trim().split(/\s+/).slice(1),terms=[];
  t.forEach(function(x){var m=x.match(/^([+\-~?])?([a-z0-9]+)(?:([:=\/])(.*))?$/i);
    if(!m){terms.push({raw:x,mech:'?invalid'});return}
    terms.push({raw:x,q:m[1]||'+',mech:m[2].toLowerCase(),sep:m[3],val:m[4]})});
  return terms;
}
async function spfWalk(domain,dns,state,depth){
  var recs=(await dns.txt(domain)).filter(function(r){return /^v=spf1(\s|$)/i.test(r.trim())});
  if(!recs.length)return null;
  if(recs.length>1&&depth===0)state.multi=recs.length;
  var terms=parseSPF(recs[0]),extra=[];
  for(var i=0;i<terms.length;i++){var t=terms[i];
    if(['include','a','mx','ptr','exists'].indexOf(t.mech)>-1)state.lookups++;
    if(t.mech==='redirect'&&t.sep==='=')state.lookups++;
    if(t.mech==='include'&&t.val&&depth<10&&!state.seen[t.val.toLowerCase()]){
      state.seen[t.val.toLowerCase()]=1;state.includes.push(t.val);
      var sub=await spfWalk(t.val,dns,state,depth+1);
      if(!sub)state.voidIncludes.push(t.val)}
    if(t.mech==='redirect'&&t.val&&depth<10&&!state.seen[t.val.toLowerCase()]){
      state.seen[t.val.toLowerCase()]=1;var rr=await spfWalk(t.val,dns,state,depth+1);
      if(depth===0&&rr)extra=rr.terms.map(function(x){x.viaRedirect=true;return x});
      if(!rr)state.voidIncludes.push(t.val)}}
  // appended after the loop so redirect-target terms are not counted twice
  return {record:recs[0],terms:terms.concat(extra)};
}
function parseTags(rec){var o=Object.create(null);rec.split(';').forEach(function(p){var i=p.indexOf('=');if(i>0)o[p.slice(0,i).trim().toLowerCase()]=p.slice(i+1).trim()});return o}
function dkimBits(p){var b64=p.replace(/\s/g,'');if(!b64)return 0;var bytes=Math.floor(b64.length*3/4)-(b64.match(/=+$/)||[''])[0].length;return bytes<100?512:bytes<200?1024:bytes<400?2048:4096}
async function analyzeEmailAuth(input,dns,opts){
  opts=opts||{};var domain=norm(input),F=[],score=100,info={};
  function add(sev,pts,title,detail,fix){F.push({sev:sev,pts:pts,title:title,detail:detail,fix:fix});score-=pts}
  function note(sev,title,detail,fix){F.push({sev:sev,pts:0,title:title,detail:detail,fix:fix})}
  if(!validDomain(domain))throw new Error('Enter a valid domain such as example.com');

  var mx=[];try{mx=await dns.mx(domain)}catch(e){}
  info.mx=mx;
  var spfState={lookups:0,includes:[],voidIncludes:[],seen:{},multi:0},spf=await spfWalk(domain,dns,spfState,0);
  info.spf=spf&&spf.record;info.spfIncludes=spfState.includes;info.spfLookups=spfState.lookups;
  var nullMail=!mx.length;

  // ---- SPF
  if(!spf){add('critical',30,'No SPF record','Anyone can send mail claiming to be from this domain without failing SPF.',nullMail?'Publish "v=spf1 -all" if the domain sends no mail.':'Publish an SPF record, e.g. "v=spf1 include:<your-provider> -all".')}
  else{
    if(spfState.multi)add('high',20,'Multiple SPF records ('+spfState.multi+')','More than one v=spf1 record causes a PermError, so SPF fails for every message.','Merge into a single record.');
    var terms=spf.terms,all=terms.filter(function(t){return t.mech==='all'})[0],red=terms.filter(function(t){return t.mech==='redirect'})[0];
    if(all){ if(all.q==='+')add('critical',40,'SPF ends with +all','Authorises every server on the internet to send as this domain.','Use -all (or ~all while testing).');
      else if(all.q==='?')add('high',15,'SPF ends with ?all (neutral)','Provides no enforcement.','Use -all, or ~all during rollout.');
      else if(all.q==='~')add('low',4,'SPF uses ~all (softfail)','Mail from unlisted servers is flagged, not rejected; DMARC enforcement usually covers this.','Move to -all once all senders are listed.');
      else note('good','SPF uses -all (hard fail)','Unlisted senders fail SPF.','')}
    else if(!red)add('high',15,'SPF has no "all" mechanism','Without an all/redirect terminator, the default is neutral for unlisted servers.','End the record with -all.');
    terms.filter(function(t){return t.mech==='ptr'}).forEach(function(){add('low',4,'SPF uses ptr','The ptr mechanism is deprecated, slow and unreliable.','Replace it with ip4/ip6/include entries.')});
    terms.filter(function(t){return t.mech==='ip4'&&t.val}).forEach(function(t){var m=t.val.match(/\/(\d+)$/),pl=m?+m[1]:32;
      if(pl<=8&&t.q==='+')add('high',25,'Overly broad ip4 range: '+t.val,'Authorises a huge address block.','List only the exact sender ranges.');
      else if(pl<=16&&t.q==='+')add('medium',8,'Broad ip4 range: '+t.val,'Authorises a very large number of hosts.','Narrow the range to your sending infrastructure.')});
    terms.filter(function(t){return t.mech==='?invalid'}).forEach(function(t){add('medium',6,'Invalid SPF term: '+t.raw,'Invalid terms can cause a PermError.','Fix the syntax.')});
    if(spfState.lookups>10)add('high',20,'SPF exceeds 10 DNS lookups ('+spfState.lookups+')','RFC 7208 limits SPF to 10 include/a/mx/ptr/exists/redirect lookups; above that SPF returns PermError and fails.','Remove unused includes or flatten the record.');
    else if(spfState.lookups>=8)add('low',4,'SPF is near the 10-lookup limit ('+spfState.lookups+'/10)','Adding another provider may break SPF.','Audit includes; consider flattening.');
    else note('good','SPF DNS lookups: '+spfState.lookups+'/10','Within the RFC limit.','');
    spfState.voidIncludes.forEach(function(v){add('medium',8,'SPF include has no SPF record: '+v,'An include/redirect to a domain without SPF causes a PermError.','Remove or fix the include.')});
    if(spf.record.length>450)note('info','SPF record is long ('+spf.record.length+' chars)','Records over ~450 bytes may not fit in a UDP DNS response.','Consider flattening or reducing includes.');
    if(nullMail&&!(all&&all.q==='-'&&terms.length===1))note('info','Domain has no MX records','If this domain sends no mail, a null SPF "v=spf1 -all" and DMARC p=reject protect it from spoofing.','Publish "v=spf1 -all".')}

  // ---- DMARC
  var dm=await dns.txt('_dmarc.'+domain),org=orgDomain(domain),inherited=false;
  dm=dm.filter(function(r){return /^v=DMARC1/i.test(r.trim())});
  if(!dm.length&&org!==domain){dm=(await dns.txt('_dmarc.'+org)).filter(function(r){return /^v=DMARC1/i.test(r.trim())});inherited=dm.length>0}
  var dmarc=null;
  if(!dm.length){add('critical',30,'No DMARC record','Without DMARC, receivers have no policy for spoofed mail and you get no reports.','Publish _dmarc.'+domain+' TXT: "v=DMARC1; p=none; rua=mailto:dmarc@'+domain+'" then move to quarantine/reject.')}
  else{
    info.dmarc=dm[0];dmarc=parseTags(dm[0]);
    if(inherited)note('info','DMARC inherited from organisational domain '+org,'No _dmarc record on the subdomain; the parent policy (and sp= tag) applies.','');
    if(dm.length>1)add('medium',10,'Multiple DMARC records','Receivers ignore DMARC when more than one record exists.','Keep a single record.');
    var p=(dmarc.p||'').toLowerCase();
    if(['none','quarantine','reject'].indexOf(p)<0)add('high',15,'DMARC p= tag missing or invalid','The policy tag is required.','Set p=quarantine or p=reject.');
    else if(p==='none')add('high',15,'DMARC policy is p=none (monitor only)','Spoofed mail is still delivered; this only collects reports.','After reviewing reports, move to p=quarantine and then p=reject.');
    else if(p==='quarantine')add('low',4,'DMARC policy is p=quarantine','Spoofed mail goes to spam but may still be seen.','Move to p=reject once legitimate senders are aligned.');
    else note('good','DMARC policy is p=reject','Spoofed mail is rejected by compliant receivers.','');
    if(dmarc.sp){var sp=dmarc.sp.toLowerCase();if(sp==='none'&&p!=='none')add('medium',8,'Subdomain policy sp=none weakens DMARC','Attackers can spoof subdomains even though the main domain is protected.','Remove sp= or set it to quarantine/reject.')}
    var pct=dmarc.pct===undefined?100:parseInt(dmarc.pct,10);
    if(!isNaN(pct)&&pct<100&&p!=='none')add('medium',6,'DMARC pct='+pct,'Only '+pct+'% of failing mail is subject to the policy.','Raise to pct=100 after testing.');
    if(!dmarc.rua)add('low',5,'No DMARC aggregate reporting (rua)','You will not see who is sending as your domain.','Add rua=mailto:… to receive aggregate reports.');
    else note('good','Aggregate reports enabled (rua)',dmarc.rua,'');
    if(dmarc.adkim==='s'||dmarc.aspf==='s')note('good','Strict alignment configured','adkim/aspf=s makes spoofing via lookalike subdomains harder.','');
    else note('info','Relaxed DKIM/SPF alignment (default)','Subdomains of the domain can satisfy alignment.','Use adkim=s; aspf=s if your senders allow it.');
  }

  // ---- DKIM
  var sels=(opts.selector?[opts.selector.trim()]:COMMON_SELECTORS),found=[];
  var res=await Promise.all(sels.map(async function(s){var r=[];try{r=await dns.txt(s+'._domainkey.'+domain)}catch(e){}
    return [s,r.filter(function(x){return /v=DKIM1|p=/i.test(x)})]}));
  res.forEach(function(x){if(x[1].length)found.push([x[0],x[1][0]])});
  info.dkim=found;
  if(found.length){found.forEach(function(f){var t=parseTags(f[1]),p=t.p||'';
    if(!p)note('info','DKIM key revoked for selector '+f[0],'Empty p= means the key has been revoked.','');
    else{var bits=dkimBits(p);
      if(bits<=512)add('high',12,'DKIM selector '+f[0]+': ~'+bits+'-bit key','Trivially factorable.','Rotate to a 2048-bit RSA key.');
      else if(bits<=1024)add('medium',8,'DKIM selector '+f[0]+': ~1024-bit key','Considered weak; large providers recommend 2048-bit.','Rotate to a 2048-bit RSA key.');
      else note('good','DKIM selector '+f[0]+': ~'+bits+'-bit key','Key size is adequate.','')}
    if(/(^|;)\s*t=y/.test(f[1]))add('low',3,'DKIM selector '+f[0]+' in testing mode (t=y)','Receivers may treat failures leniently.','Remove t=y once verified.')})}
  else note('info',opts.selector?'DKIM selector "'+opts.selector+'" not found':'No DKIM keys found on common selectors','DKIM selectors can be any name, so this does not prove DKIM is missing.','Enter your real selector (found in the DKIM-Signature "s=" tag of a received email).');

  // ---- MTA-STS / TLS-RPT (informational)
  var sts=[],rpt=[];try{sts=await dns.txt('_mta-sts.'+domain);rpt=await dns.txt('_smtp._tls.'+domain)}catch(e){}
  if(sts.some(function(r){return /v=STSv1/i.test(r)}))note('good','MTA-STS record found','Inbound mail can require TLS.','Verify the policy file at https://mta-sts.'+domain+'/.well-known/mta-sts.txt');
  else if(!nullMail)note('info','No MTA-STS record','Inbound SMTP connections can be downgraded to plaintext.','Consider publishing MTA-STS (and TLS-RPT).');
  if(rpt.some(function(r){return /v=TLSRPTv1/i.test(r)}))note('good','TLS-RPT record found','You receive SMTP TLS failure reports.','');

  score=Math.max(0,Math.min(100,score));
  var grade=score>=90?'A':score>=75?'B':score>=60?'C':score>=40?'D':'F';
  var o={critical:0,high:1,medium:2,low:3,info:4,good:5};F.sort(function(a,b){return o[a.sev]-o[b.sev]});
  var dp=dmarc&&(dmarc.p||'').toLowerCase(),enforced=dp==='quarantine'||dp==='reject';
  var verdict=!dmarc?'Spoofable: no DMARC policy, so receivers are free to accept forged mail.':!enforced?'Likely spoofable: DMARC is monitor-only (p=none).':!spf?'DMARC enforced but SPF is missing; rely on DKIM alignment.':'Spoofing protection is enforced.';
  return {domain:domain,score:score,grade:grade,verdict:verdict,findings:F,info:info};
}
root.analyzeEmailAuth=analyzeEmailAuth;root.parseSPF=parseSPF;
if(typeof module!=='undefined')module.exports={analyzeEmailAuth:analyzeEmailAuth,parseSPF:parseSPF};
})(typeof window!=='undefined'?window:globalThis);
