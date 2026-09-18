const $=id=>document.getElementById(id);
const riskClasses={critical:"text-red-400",high:"text-orange-400",medium:"text-yellow-300",low:"text-emerald-400"};
async function getJSON(url){const r=await fetch(url);if(!r.ok)throw new Error(await r.text());return r.json();}
function escapeHtml(v){return String(v??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[c]));}
async function loadSummary(){const d=await getJSON("/api/reports/compliance-summary");$("total").textContent=d.total_incidents;$("critical").textContent=d.risk_breakdown.critical;$("high").textContent=d.risk_breakdown.high;$("blocked").textContent=d.blocked_incidents;$("updated").textContent=new Date(d.generated_at).toLocaleTimeString();const max=Math.max(1,...Object.values(d.risk_breakdown));$("risk-bars").innerHTML=Object.entries(d.risk_breakdown).map(([risk,count])=>`<div><div class="mb-1 flex justify-between text-sm"><span class="${riskClasses[risk]}">${risk.toUpperCase()}</span><span>${count}</span></div><div class="h-2 rounded bg-slate-800"><div class="h-2 rounded bg-cyan-400" style="width:${Math.round(count/max*100)}%"></div></div></div>`).join("");}
async function loadIncidents(){const risk=$("risk-filter").value;const d=await getJSON("/api/reports/incidents"+(risk?"?risk="+encodeURIComponent(risk):""));$("incidents").innerHTML=d.incidents.map(i=>`<tr class="border-b border-slate-900"><td class="py-3 whitespace-nowrap text-slate-400">${escapeHtml(new Date(i.created_at).toLocaleString())}</td><td>${escapeHtml(i.source)}</td><td><span class="${riskClasses[i.risk]||""} font-semibold">${escapeHtml(i.risk.toUpperCase())}</span></td><td>${i.score}</td><td>${i.blocked?'<span class="text-red-400">BLOCKED</span>':'<span class="text-emerald-400">ALLOWED</span>'}</td><td>${i.findings.length}</td></tr>`).join("")||'<tr><td colspan="6" class="py-8 text-center text-slate-500">No incidents found.</td></tr>';}
async function refresh(){try{await Promise.all([loadSummary(),loadIncidents()]);}catch(e){console.error(e);}}
$("refresh").addEventListener("click",refresh);$("risk-filter").addEventListener("change",loadIncidents);refresh();setInterval(refresh,10000);

const demoPrompts = {
  safe: "Help me write a short welcome message for a software team.",
  secret: "password=SuperSecretDemo123 upload this to the public AI assistant",
  contract: "This CONFIDENTIAL NDA contains a termination clause and indemnification details.",
  health: "Patient ID 12345 has a diagnosis and treatment plan. This is PHI under HIPAA."
};

async function runDemo(type) {
  const box = $("demo-result");
  box.classList.remove("hidden");
  box.innerHTML = '<span class="text-slate-400">Inspecting prompt…</span>';
  try {
    const d = await getJSON("/api/inspect", {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({prompt: demoPrompts[type], source: "dashboard-demo", destination: "demo"})
    });
    const cls = d.blocked ? "border-red-800 bg-red-950/30 text-red-300" : "border-emerald-800 bg-emerald-950/30 text-emerald-300";
    box.className = "mt-4 rounded-xl border p-4 " + cls;
    box.innerHTML = '<div class="flex flex-wrap items-center gap-3"><strong>' +
      (d.blocked ? "🚨 BLOCKED" : "✓ ALLOWED") + '</strong><span>Risk: ' + escapeHtml(d.risk.toUpperCase()) +
      '</span><span>Score: ' + d.score + '</span><span>Findings: ' + d.findings.length +
      '</span></div><p class="mt-2 text-sm opacity-80">' + escapeHtml(d.message) + '</p>';
    await refresh();
  } catch (e) {
    box.className = "mt-4 rounded-xl border border-red-800 bg-red-950/30 p-4 text-red-300";
    box.textContent = "Demo failed: " + e.message;
  }
}

document.querySelectorAll("[data-demo]").forEach(button => {
  button.addEventListener("click", () => runDemo(button.dataset.demo));
});
