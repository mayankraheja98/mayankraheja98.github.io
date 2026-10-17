// Registry of labs. Add an entry here + a page at labs/<slug>.html (copy labs/_template.html).
// category: any string - new categories appear as filters automatically.
// level: "beginner" | "intermediate" | "advanced"
window.LABS = [
 {slug:"prompt-injection",title:"Prompt Injection Sandbox",category:"AI Security",level:"beginner",icon:"💉",
  summary:"Try to extract a secret from a simulated chatbot across 3 levels of weak defenses. Learn why filters fail.",tags:["LLM","OWASP LLM01"],date:"2026-10-14"},
 {slug:"jwt-inspector",title:"JWT Inspector",category:"AppSec",level:"beginner",icon:"🔑",
  summary:"Decode a JWT locally in your browser and flag common weaknesses: alg none, no expiry, risky header fields.",tags:["Auth","Tools"],date:"2026-10-14"}
 ,{slug:"csp-evaluator",title:"CSP Evaluator",category:"AppSec",level:"intermediate",icon:"🛡",
  summary:"Paste a Content-Security-Policy and get a score, the gaps, and concrete fixes: unsafe-inline, bypass-prone hosts, missing base-uri and more.",tags:["CSP","XSS","Headers"],date:"2026-10-14"}
 ,{slug:"header-analyzer",title:"Response Header Analyzer",category:"AppSec",level:"beginner",icon:"📋",
  summary:"Paste HTTP response headers and audit HSTS, CSP, framing, nosniff, referrer policy, cookie flags, server info leaks and CORS.",tags:["Headers","Cookies","HSTS"],date:"2026-10-14"}
 ,{slug:"email-auth",title:"SPF / DMARC / DKIM Lookup",category:"Email Security",level:"intermediate",icon:"✉️",
  summary:"Check if a domain can be spoofed. Live DNS lookups of SPF (with the 10-lookup limit), DMARC, DKIM, MX and MTA-STS, with a score and fixes.",tags:["SPF","DMARC","DKIM","DNS"],date:"2026-10-14"}
 ,{slug:"clickjacking",title:"Clickjacking Tester",category:"AppSec",level:"beginner",icon:"🖱",
  summary:"Load a URL in a frame, see if it can be embedded, and visualise the attacker's decoy overlay. Cross-check with X-Frame-Options / frame-ancestors.",tags:["Clickjacking","Framing","UI redress"],date:"2026-10-14"}
];
