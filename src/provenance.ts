export type Origin = "user" | "private" | "untrusted" | "trusted-tool" | "model";

const URL_RE = /\bhttps?:\/\/[^\s"'<>)\]]+/gi;
const EMAIL_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;

export function hostOf(u: string): string | null {
  try { return new URL(u).hostname.toLowerCase(); } catch { return null; }
}

/** Atoms that identify a destination or a payload inside a string: e-mail addresses, URL hosts, long tokens. */
export function atoms(s: string): string[] {
  const out = new Set<string>();
  for (const m of s.matchAll(EMAIL_RE)) out.add(m[0].toLowerCase());
  for (const m of s.matchAll(URL_RE)) { const h = hostOf(m[0]); if (h) out.add(h); }
  return [...out];
}

export function strings(v: unknown, acc: string[] = []): string[] {
  if (typeof v === "string") acc.push(v);
  else if (Array.isArray(v)) v.forEach((x) => strings(x, acc));
  else if (typeof v === "object" && v !== null) Object.values(v).forEach((x) => strings(x, acc));
  return acc;
}

const norm = (s: string) => s.toLowerCase().replace(/\s+/g, " ").trim();

/** Longest shared run of words between a and b, in words. Detects payload copied from a source into an argument. */
export function sharedRun(a: string, b: string, min = 5): string | null {
  const aw = norm(a).split(" "), bw = norm(b).split(" ");
  if (bw.length < min || aw.length < min) return null;
  const idx = new Map<string, number[]>();
  for (let i = 0; i + min <= aw.length; i++) { const k = aw.slice(i, i + min).join(" "); idx.set(k, [...(idx.get(k) ?? []), i]); }
  for (let j = 0; j + min <= bw.length; j++) {
    const k = bw.slice(j, j + min).join(" ");
    if (idx.has(k)) return k;
  }
  return null;
}

const INJECTION = [
  /ignore (all |any )?(previous|prior|above) (instructions|messages)/i,
  /disregard (the )?(previous|prior|above|system)/i,
  /\b(you must|you should|please) (now )?(send|forward|email|post|upload|exfiltrate|delete|execute|run)\b/i,
  /\bnew (instructions|task)\b/i,
  /do not (tell|inform|mention to) the user/i,
  /\bwithout (telling|informing|notifying) the user\b/i,
  /<!--[\s\S]*?-->/,
  /[​-‏⁠﻿]/,
  /\bassistant[:,] (please )?(send|forward|run)/i,
];

export function injectionSignals(text: string): string[] {
  const out: string[] = [];
  for (const r of INJECTION) { const m = r.exec(text); if (m) out.push(m[0].length > 60 ? m[0].slice(0, 57) + "..." : m[0]); }
  return out;
}
