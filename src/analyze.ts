import { Cap, Event, Manifest, capsOf } from "./model.js";
import { atoms, injectionSignals, sharedRun, strings } from "./provenance.js";

export type Severity = "critical" | "high" | "medium" | "low";
export interface Finding { id: string; severity: Severity; step: number | null; title: string; evidence: string }
export interface Policy { blockExternalAfterUntrusted: boolean; destinationAllowlist: string[]; requireApprovalForStateChange: boolean }
export interface Replay { step: number; tool: string; decision: "allow" | "block" | "approve"; reason: string }
export interface Report {
  agent: string; caps: Cap[]; trifecta: boolean; ruleOfTwo: number;
  findings: Finding[]; verdict: "clean" | "exposed" | "compromised"; replay: Replay[]; policy: Policy;
}

const HIGH: Severity[] = ["critical", "high", "medium", "low"];

export function staticCaps(m: Manifest): Cap[] {
  return [...new Set(m.tools.flatMap((t) => t.caps))];
}

export function suggestPolicy(m: Manifest, allow: string[] = []): Policy {
  const caps = staticCaps(m);
  return { blockExternalAfterUntrusted: caps.includes("untrusted-input") && caps.includes("external-comms"), destinationAllowlist: allow, requireApprovalForStateChange: caps.includes("state-change") };
}

export function analyze(m: Manifest, trace: Event[], allowlist: string[] = []): Report {
  const findings: Finding[] = [];
  const f = (id: string, severity: Severity, step: number | null, title: string, evidence: string) => findings.push({ id, severity, step, title, evidence });
  const caps = staticCaps(m);
  const has = (c: Cap) => caps.includes(c);
  const trifecta = has("private-data") && has("untrusted-input") && has("external-comms");
  const ruleOfTwo = (has("untrusted-input") ? 1 : 0) + (has("private-data") ? 1 : 0) + (has("external-comms") || has("state-change") ? 1 : 0);
  if (trifecta) f("trifecta", "high", null, "Agent holds the lethal trifecta", "Tools give it private data, untrusted content and an external channel. Any injected instruction can read and leak.");

  const userText = trace.filter((e) => e.type === "user").map((e) => e.text ?? "").join("\n");
  const userAtoms = new Set(atoms(userText));
  const untrusted: { step: number; text: string }[] = [];
  const privateRes: { step: number; text: string }[] = [];
  const trustedText: string[] = [];
  const policy = suggestPolicy(m, allowlist);
  const replay: Replay[] = [];
  let tainted = false;
  let taintStep = 0;

  for (const e of trace) {
    if (e.type === "tool_result") {
      const c = capsOf(m, e.tool);
      const t = e.text ?? "";
      if (c.includes("untrusted-input")) {
        untrusted.push({ step: e.step, text: t });
        tainted = true; taintStep = tainted && taintStep ? taintStep : e.step;
        const sig = injectionSignals(t);
        if (sig.length) f("injection-signal", "medium", e.step, `Instruction-like content in ${e.tool} output`, sig.join("; "));
      } else if (c.includes("private-data")) privateRes.push({ step: e.step, text: t });
      else trustedText.push(t);
      continue;
    }
    if (e.type !== "tool_call") continue;
    const c = capsOf(m, e.tool);
    const tool = m.tools.find((t) => t.name === e.tool);
    if (!tool) { f("unknown-tool", "low", e.step, `Tool ${e.tool} is not in the manifest`, "Capabilities unknown, treated as unclassified."); continue; }
    const argStrings = strings(e.args);
    const joined = argStrings.join("\n");
    const dests = new Set<string>();
    for (const a of tool.destinationArgs) for (const s of strings(e.args?.[a])) atoms(s).forEach((x) => dests.add(x));
    if (!tool.destinationArgs.length) atoms(joined).forEach((x) => dests.add(x));
    const external = c.includes("external-comms"), change = c.includes("state-change");
    let decision: Replay["decision"] = "allow", reason = "no rule matched";

    if (external || change) {
      const fromUntrusted = [...dests].filter((d) => !userAtoms.has(d) && untrusted.some((u) => u.text.toLowerCase().includes(d)));
      const fromUser = [...dests].every((d) => userAtoms.has(d));
      const leaked = privateRes.map((p) => ({ p, run: sharedRun(p.text, joined) })).filter((x) => x.run);
      if (external && fromUntrusted.length) {
        f("attacker-destination", "critical", e.step, `${e.tool} sends to a destination that only appeared in untrusted content`, `${fromUntrusted.join(", ")} first seen in the output of step ${untrusted.find((u) => u.text.toLowerCase().includes(fromUntrusted[0]!))!.step}, never in the user's request.`);
      }
      if (external && leaked.length) {
        f("exfiltration", fromUntrusted.length || tainted ? "critical" : "high", e.step, `${e.tool} carries data copied from a private source`, `Text from step ${leaked[0]!.p.step} (private) appears in the arguments: "${leaked[0]!.run}".`);
      }
      if (external && tainted && !fromUntrusted.length && !leaked.length && !fromUser) f("external-after-untrusted", "medium", e.step, `${e.tool} called after untrusted content entered the context`, `Context tainted since step ${taintStep}; destination ${[...dests].join(", ") || "(none found)"} cannot be tied to the user's request.`);
      if (change && tainted) f("state-change-after-untrusted", "medium", e.step, `${e.tool} changes state after untrusted content`, `Context tainted since step ${taintStep}. Require approval.`);

      if (external && policy.destinationAllowlist.length && [...dests].some((d) => !allowed(d, policy.destinationAllowlist))) { decision = "block"; reason = "destination not in allowlist"; }
      else if (external && policy.blockExternalAfterUntrusted && tainted && !(fromUser && dests.size > 0)) { decision = "block"; reason = "external call after untrusted input without a user-given destination"; }
      else if (change && policy.requireApprovalForStateChange && tainted) { decision = "approve"; reason = "state change after untrusted input"; }
    }
    replay.push({ step: e.step, tool: e.tool!, decision, reason });
  }

  const sev = (s: Severity) => HIGH.indexOf(s);
  findings.sort((a, b) => sev(a.severity) - sev(b.severity) || (a.step ?? 0) - (b.step ?? 0));
  const verdict: Report["verdict"] = findings.some((x) => x.severity === "critical") ? "compromised" : findings.length ? "exposed" : "clean";
  return { agent: m.agent, caps, trifecta, ruleOfTwo, findings, verdict, replay, policy };
}

function allowed(dest: string, allow: string[]): boolean {
  return allow.some((a) => dest === a.toLowerCase() || dest.endsWith("." + a.toLowerCase()) || (a.startsWith("@") && dest.endsWith(a.toLowerCase())));
}
