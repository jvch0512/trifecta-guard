export class ModelError extends Error {}

export type Cap = "private-data" | "untrusted-input" | "external-comms" | "state-change";
export const CAPS: Cap[] = ["private-data", "untrusted-input", "external-comms", "state-change"];

export interface Tool { name: string; caps: Cap[]; destinationArgs: string[] }
export interface Manifest { agent: string; tools: Tool[] }
export interface Event { step: number; type: "user" | "tool_call" | "tool_result"; tool?: string; text?: string; args?: Record<string, unknown>; callStep?: number }

const rec = (v: unknown, w: string): Record<string, unknown> => {
  if (typeof v !== "object" || v === null || Array.isArray(v)) throw new ModelError(`${w} must be an object`);
  return v as Record<string, unknown>;
};

export function parseManifest(text: string): Manifest {
  let j: unknown;
  try { j = JSON.parse(text); } catch { throw new ModelError("manifest is not valid JSON"); }
  const o = rec(j, "manifest");
  if (!Array.isArray(o["tools"])) throw new ModelError("manifest.tools must be an array");
  return {
    agent: typeof o["agent"] === "string" ? o["agent"] : "agent",
    tools: o["tools"].map((t, i) => {
      const r = rec(t, `tools[${i}]`);
      if (typeof r["name"] !== "string") throw new ModelError(`tools[${i}].name must be a string`);
      const caps = Array.isArray(r["caps"]) ? r["caps"].map(String) : [];
      for (const c of caps) if (!CAPS.includes(c as Cap)) throw new ModelError(`tools[${i}] has unknown capability "${c}" (known: ${CAPS.join(", ")})`);
      return { name: r["name"], caps: caps as Cap[], destinationArgs: Array.isArray(r["destinationArgs"]) ? r["destinationArgs"].map(String) : [] };
    }),
  };
}

/** Trace is JSON Lines. Each line: {type:"user"|"tool_call"|"tool_result", ...}. Steps are numbered by line. */
export function parseTrace(text: string): Event[] {
  const out: Event[] = [];
  let step = 0;
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim()) continue;
    step++;
    let j: unknown;
    try { j = JSON.parse(line); } catch { throw new ModelError(`trace line ${step} is not valid JSON`); }
    const r = rec(j, `trace line ${step}`);
    const type = r["type"];
    if (type !== "user" && type !== "tool_call" && type !== "tool_result") throw new ModelError(`trace line ${step}: type must be user, tool_call or tool_result`);
    if (type !== "user" && typeof r["tool"] !== "string") throw new ModelError(`trace line ${step}: ${type} needs a "tool"`);
    out.push({
      step, type,
      tool: typeof r["tool"] === "string" ? r["tool"] : undefined,
      text: typeof r["text"] === "string" ? r["text"] : typeof r["result"] === "string" ? r["result"] : undefined,
      args: typeof r["args"] === "object" && r["args"] !== null && !Array.isArray(r["args"]) ? (r["args"] as Record<string, unknown>) : undefined,
    });
  }
  if (!out.length) throw new ModelError("trace is empty");
  return out;
}

export const capsOf = (m: Manifest, tool: string | undefined): Cap[] => m.tools.find((t) => t.name === tool)?.caps ?? [];
