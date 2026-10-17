(function(){
  var root=document.documentElement;
  function cur(){return root.getAttribute('data-theme')||'light'}
  function set(t){root.setAttribute('data-theme',t);try{localStorage.setItem('theme',t)}catch(e){}
    var b=document.getElementById('themeBtn');if(b)b.textContent=t==='dark'?'☀':'☾'}
  window.toggleTheme=function(){set(cur()==='dark'?'light':'dark')};
  document.addEventListener('DOMContentLoaded',function(){
    set(cur());
    var b=document.getElementById('themeBtn');if(b)b.onclick=window.toggleTheme;
    var y=document.getElementById('y');if(y)y.textContent=new Date().getFullYear();
    var io=new IntersectionObserver(function(e){e.forEach(function(x){if(x.isIntersecting){x.target.classList.add('in');io.unobserve(x.target)}})},{threshold:.1});
    document.querySelectorAll('.reveal').forEach(function(el){io.observe(el)});
  });
})();
