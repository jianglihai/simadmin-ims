// ims.js — IMS panel JS (served by simadmin-ims on :3001)
(function(){
  function api(p){return fetch(p,{method:(p.startsWith("/api/ims/register")||p.startsWith("/api/ims/unregister"))?"POST":"GET"}).then(r=>r.json()).catch(()=>null)}
  function fmt(v){return(v==null||v==""||v===false)?"—":String(v)}
  window.refresh=async function(){
    var s=await api("/api/ims/status")||{};
    var dd=document.getElementById("dd"),ddt=document.getElementById("ddt");
    if(!dd) return;
    dd.className="dot "+(s.daemon?"ok":"err");
    ddt.textContent=s.daemon||"未运行";
    var rd=document.getElementById("rd");
    rd.className="dot "+(s.registered?"ok":s.registering?"idle":"idle");
    document.getElementById("r").textContent=s.registered?"已注册":s.registering?"注册中…":"未注册";
    document.getElementById("ip").textContent=fmt(s.local_ip);
    document.getElementById("pc").textContent=fmt(s.pcscf);
    document.getElementById("dom").textContent=fmt(s.ims_domain);
    document.getElementById("ver").textContent=fmt(s.version);
    document.getElementById("reg").textContent=s.log||"无日志";
  };
  window.doReg=async function(){var r=await api("/api/ims/register");document.getElementById("reg").textContent=r?JSON.stringify(r):"已请求";window.refresh()};
  window.doUnreg=async function(){var r=await api("/api/ims/unregister");document.getElementById("reg").textContent=r?JSON.stringify(r):"已请求";window.refresh()};
  window.refresh();
  setInterval(window.refresh,5000);
})();
