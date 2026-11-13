import { Report } from "./analyze.js";

export function reportMarkdown(r: Report): string {
  const L: string[] = [`# Agent trace analysis: ${r.agent}`, "", `Verdict: **${r.verdict}**`, `Capabilities: ${r.caps.join(", ") || "none"}`, `Lethal trifecta: ${r.trifecta ? "**yes**" : "no"} (${r.ruleOfTwo} of 3 risk properties present)`, ""];
  L.push("## Findings", "");
  if (!r.findings.length) L.push("No findings.");
  else { L.push("| Severity | Step | Finding | Evidence |", "|---|---|---|---|"); for (const f of r.findings) L.push(`| ${f.severity} | ${f.step ?? "-"} | ${f.title} | ${f.evidence.replace(/\|/g, "/")} |`); }
  const acts = r.replay.filter((x) => x.decision !== "allow");
  L.push("", "## Policy replay", "", `Policy: block external calls after untrusted input: ${r.policy.blockExternalAfterUntrusted ? "on" : "off"}; destination allowlist: ${r.policy.destinationAllowlist.join(", ") || "(none)"}; approval for state changes: ${r.policy.requireApprovalForStateChange ? "on" : "off"}.`, "");
  if (!acts.length) L.push("The policy would not have interrupted this trace.");
  else { L.push("| Step | Tool | Decision | Reason |", "|---|---|---|---|"); for (const x of acts) L.push(`| ${x.step} | ${x.tool} | ${x.decision} | ${x.reason} |`); }
  L.push("", "## Design guidance", "", "- Break the trifecta: remove one of private data, untrusted input or external communication from any single agent session (the Agents Rule of Two idea).", "- Never let the model choose a destination: take recipients and URLs from the user or from a fixed allowlist.", "- Treat tool output as data. Quarantine untrusted content in a separate context that cannot call tools.", "", "Heuristic analysis of one recorded trace. It shows what happened and what a policy would have stopped. It does not prove an agent is safe.");
  return L.join("\n") + "\n";
}
