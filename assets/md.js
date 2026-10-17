// Small, safe Markdown renderer + front-matter stripper (window.md, window.stripFront).
// Supports: ##/### headings, paragraphs, - and 1. lists, > quotes, ``` code, ---, **bold**, *italic*, `code`, [link](url), ![img](url)
(function(root){
function esc(s){return s.replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]})}
var URL_OK='(?:https?:\\/\\/|\\/|\\.\\/|\\.\\.\\/|#|[A-Za-z0-9_-]+[\\/.])[^)\\s]*';
function inline(s){
  s=esc(s);
  // protect inline code from further formatting
  var codes=[];
  s=s.replace(/`([^`]+)`/g,function(_,c){codes.push(c);return '\u0000'+(codes.length-1)+'\u0000'});
  s=s.replace(new RegExp('!\\[([^\\]]*)\\]\\(('+URL_OK+')\\)','g'),'<img src="$2" alt="$1" loading="lazy" style="max-width:100%;border-radius:8px">');
  s=s.replace(new RegExp('\\[([^\\]]+)\\]\\(('+URL_OK+')\\)','g'),'<a href="$2" rel="noopener">$1</a>');
  s=s.replace(/\*\*([^*]+)\*\*/g,'<strong>$1</strong>').replace(/(^|[^*])\*([^*\s][^*]*)\*/g,'$1<em>$2</em>');
  return s.replace(/\u0000(\d+)\u0000/g,function(_,i){return '<code>'+codes[+i]+'</code>'});
}
function stripFront(src){var m=src.match(/^---\r?\n[\s\S]*?\r?\n---\r?\n?([\s\S]*)$/);return m?m[1]:src}
function md(src){
  var lines=stripFront(src).replace(/\r/g,'').split('\n'),h='',i=0,list=null,para=[];
  function flushP(){if(para.length){h+='<p>'+inline(para.join(' '))+'</p>';para=[]}}
  function closeL(){if(list){h+='</'+list+'>';list=null}}
  while(i<lines.length){
    var l=lines[i];
    if(/^```/.test(l)){flushP();closeL();var c=[];i++;while(i<lines.length&&!/^```/.test(lines[i])){c.push(lines[i]);i++}h+='<pre><code>'+esc(c.join('\n'))+'</code></pre>'}
    else if(/^### /.test(l)){flushP();closeL();h+='<h3>'+inline(l.slice(4))+'</h3>'}
    else if(/^## /.test(l)){flushP();closeL();h+='<h2>'+inline(l.slice(3))+'</h2>'}
    else if(/^---+\s*$/.test(l)){flushP();closeL();h+='<hr>'}
    else if(/^> ?/.test(l)){flushP();closeL();h+='<blockquote>'+inline(l.replace(/^> ?/,''))+'</blockquote>'}
    else if(/^[-*] /.test(l)){flushP();if(list!=='ul'){closeL();h+='<ul>';list='ul'}h+='<li>'+inline(l.slice(2))+'</li>'}
    else if(/^\d+\. /.test(l)){flushP();if(list!=='ol'){closeL();h+='<ol>';list='ol'}h+='<li>'+inline(l.replace(/^\d+\. /,''))+'</li>'}
    else if(l.trim()===''){flushP();closeL()}
    else{closeL();para.push(l.trim())}
    i++;
  }
  flushP();closeL();return h;
}
root.md=md;root.stripFront=stripFront;
})(window);
