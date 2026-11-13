import { analyze } from "/lib/analyze.js";
import { parseManifest, parseTrace } from "/lib/model.js";
import { reportMarkdown } from "/lib/report.js";

const $ = (id) => document.getElementById(id);
function el(tag, text, cls) { const e = document.createElement(tag); if (text !== undefined) e.textContent = text; if (cls) e.className = cls; return e; }
function table(headers, rows, classes = []) {
  const t = document.createElement("table");
  const h = document.createElement("tr");
  headers.forEach((x) => h.append(el("th", x)));
  t.append(h);
  rows.forEach((r) => { const tr = document.createElement("tr"); r.forEach((c, i) => tr.append(el("td", String(c), classes[i] ? classes[i](c) : undefined))); t.append(tr); });
  return t;
}
function cards(items) {
  const box = el("div", undefined, "cards");
  for (const [label, value, cls] of items) { const c = el("div", undefined, `card ${cls ?? ""}`); c.append(el("b", String(value)), el("span", label)); box.append(c); }
  return box;
}
function panel(title, ...kids) { const p = el("div", undefined, "panel"); p.append(el("h2", title), ...kids); return p; }
function copyButton(getMd) {
  const b = el("button", "Copy markdown");
  b.type = "button";
  b.addEventListener("click", async () => { try { await navigator.clipboard.writeText(getMd()); b.textContent = "Copied"; setTimeout(() => { b.textContent = "Copy markdown"; }, 1500); } catch { /* clipboard blocked */ } });
  return b;
}
function downloadButton(getMd, name) {
  const b = el("button", "Download .md");
  b.type = "button";
  b.addEventListener("click", () => { const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([getMd()], { type: "text/markdown" })); a.download = name; a.click(); URL.revokeObjectURL(a.href); });
  return b;
}
async function sample(name) { return (await fetch(`/examples/${name}`)).text(); }
function showError(box, e) { box.replaceChildren(el("p", String(e.message ?? e), "err")); }
function setupTabs() {
  document.querySelectorAll("#tabs button").forEach((b) => b.addEventListener("click", () => {
    document.querySelectorAll("#tabs button").forEach((x) => x.classList.toggle("on", x === b));
    document.querySelectorAll(".tab").forEach((s) => { s.hidden = s.id !== `p-${b.dataset.tab}`; });
  }));
}
const cls = (map) => (v) => map[v] ?? "";


function run() {
  const out = $("out");
  out.replaceChildren();
  if (!$("tools").value.trim() || !$("trace").value.trim()) return;
  try {
    const allow = $("allow").value.split(",").map((s) => s.trim()).filter(Boolean);
    const r = analyze(parseManifest($("tools").value), parseTrace($("trace").value), allow);
    const md = reportMarkdown(r);
    const blocked = r.replay.filter((x) => x.decision !== "allow").length;
    out.append(cards([["Verdict", r.verdict, r.verdict === "clean" ? "ok" : r.verdict === "exposed" ? "warn" : "bad"], ["Lethal trifecta", r.trifecta ? "yes" : "no", r.trifecta ? "bad" : "ok"], ["Findings", r.findings.length], ["Policy would stop", blocked, blocked ? "warn" : "ok"]]));
    out.append(panel("Findings", r.findings.length ? table(["Severity", "Step", "Finding", "Evidence"], r.findings.map((f) => [f.severity, f.step === null ? "-" : f.step, f.title, f.evidence]), [cls({ critical: "s-high", high: "s-high", medium: "s-medium", low: "s-low" })]) : el("p", "No findings.")));
    const acts = r.replay.filter((x) => x.decision !== "allow");
    out.append(panel("Policy replay", acts.length ? table(["Step", "Tool", "Decision", "Reason"], acts.map((x) => [x.step, x.tool, x.decision, x.reason]), [null, null, cls({ block: "s-high", approve: "s-medium" })]) : el("p", "The policy would not have interrupted this trace.")));
    const row = el("div", undefined, "row");
    row.append(copyButton(() => md), downloadButton(() => md, "trifecta-guard.md"));
    out.append(row);
  } catch (e) { showError(out, e); }
}

for (const b of document.querySelectorAll("[data-trace]")) {
  b.addEventListener("click", async () => {
    [$("tools").value, $("trace").value] = await Promise.all([sample("tools.json"), sample(b.dataset.trace)]);
    run();
  });
}
for (const id of ["tools", "trace", "allow"]) $(id).addEventListener("input", run);
