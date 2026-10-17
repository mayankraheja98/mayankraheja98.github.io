(function(){
  var out=document.getElementById('tout'),inp=document.getElementById('tin');if(!out||!inp)return;
  var hist=[],hi=0;
  var C={
    help:function(){return 'Commands:\n  <span class="c">whoami</span>      who am I\n  <span class="c">about</span>       short bio\n  <span class="c">skills</span>      focus areas\n  <span class="c">experience</span>  career timeline\n  <span class="c">education</span>   degrees\n  <span class="c">projects</span>    open projects page\n  <span class="c">blog</span>        open blog\n  <span class="c">contact</span>     how to reach me\n  <span class="c">theme</span>       toggle light/dark\n  <span class="c">clear</span>       clear screen'},
    whoami:function(){return 'mayank raheja - senior security engineer @ flipkart\nDevSecOps · AI security · AppSec · Bengaluru, India'},
    about:function(){return 'Started as a pentester and bug hunter; now building security into\nsoftware delivery at scale. Currently securing AI/LLM systems and\nautomating DevSecOps. eMasters in Cybersecurity, IIT Kanpur (2026).'},
    skills:function(){return '[+] DevSecOps     CI/CD, SAST/DAST/SCA, secrets scanning\n[+] AI Security    OWASP LLM Top 10, agents, threat modelling\n[+] AppSec         web/API/mobile testing, secure code review\n[+] VulnMgmt       triage, prioritisation, remediation'},
    experience:function(){return 'SEP 2024 - now   Senior Security Engineer  @ Flipkart\nMAY 2021 - SEP24  Security Engineer         @ Nykaa\nJUL 2020 - APR21  Assoc. Infosec Consultant @ RiskBricks Solutions\nJAN 2020 - JUN 2020 Security Analyst Intern   @ Kratikal Tech'},
    education:function(){return 'eMasters, Cybersecurity - IIT Kanpur (Jul 2026)\nB.Tech CSE - Maharaja Surajmal Institute of Technology (2016-20)'},
    contact:function(){return 'email    <a href="mailto:mrmayankraheja@gmail.com">mrmayankraheja@gmail.com</a>\nlinkedin <a href="https://www.linkedin.com/in/rahejahere/" target="_blank" rel="noopener">/in/rahejahere</a>'},
    projects:function(){setTimeout(function(){location.href='projects.html'},500);return 'opening projects…'},
    blog:function(){setTimeout(function(){location.href='blog.html'},500);return 'opening blog…'},
    theme:function(){window.toggleTheme();return 'theme toggled.'},
    clear:function(){out.innerHTML='';return null},
    ls:function(){return 'about  skills  experience  education  projects  blog  contact'},
    sudo:function(){return 'nice try. this incident will be reported. (to nobody)'},
    'cat /etc/passwd':function(){return 'root:x:0:0:... just kidding. try <span class="c">help</span>.'}
  };
  function esc(s){return s.replace(/[&<>]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;'}[c]})}
  function print(h){out.insertAdjacentHTML('beforeend',h+'\n');out.scrollTop=out.scrollHeight}
  function run(cmd){
    cmd=cmd.trim();print('<span class="m">$</span> '+esc(cmd));if(!cmd)return;
    var k=cmd.toLowerCase(),f=C[k]||(k.indexOf('sudo')===0?C.sudo:null);
    if(f){var r=f();if(r!==null)print(r)}else print('command not found: '+esc(cmd)+' - try <span class="c">help</span>');
  }
  inp.addEventListener('keydown',function(e){
    if(e.key==='Enter'){hist.push(inp.value);hi=hist.length;run(inp.value);inp.value=''}
    else if(e.key==='ArrowUp'&&hi>0){hi--;inp.value=hist[hi];e.preventDefault()}
    else if(e.key==='ArrowDown'){hi=Math.min(hi+1,hist.length);inp.value=hist[hi]||'';e.preventDefault()}
  });
  document.querySelectorAll('[data-cmd]').forEach(function(b){b.onclick=function(){run(b.dataset.cmd)}});
  document.getElementById('term').addEventListener('click',function(){inp.focus({preventScroll:true})});
  print('Welcome. Type <span class="c">help</span> or tap a command below.');
})();
