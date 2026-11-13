#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { analyze } from "./analyze.js";
import { ModelError, parseManifest, parseTrace } from "./model.js";
import { reportMarkdown } from "./report.js";

const USAGE = `trifecta-guard

  trifecta-guard analyze <trace.jsonl> --tools tools.json [--allow host,@domain] [--json] [--fail-on exposed|compromised]

Exit codes: 0 ok, 1 verdict at or above --fail-on, 2 bad input.`;

function opt(a: string[], n: string): string | undefined { const i = a.indexOf(n); return i >= 0 ? a[i + 1] : undefined; }

function main(argv: string[]): number {
  const [cmd, file] = argv;
  const tools = opt(argv, "--tools");
  if (cmd !== "analyze" || !file || !tools) { console.error(USAGE); return 2; }
  const failOn = opt(argv, "--fail-on");
  if (failOn && failOn !== "exposed" && failOn !== "compromised") { console.error("--fail-on must be exposed or compromised"); return 2; }
  try {
    const r = analyze(parseManifest(readFileSync(tools, "utf8")), parseTrace(readFileSync(file, "utf8")), (opt(argv, "--allow") ?? "").split(",").filter(Boolean));
    process.stdout.write(argv.includes("--json") ? JSON.stringify(r, null, 2) + "\n" : reportMarkdown(r));
    const rank: Record<string, number> = { clean: 0, exposed: 1, compromised: 2 };
    return failOn && (rank[r.verdict] ?? 0) >= (rank[failOn] ?? 0) ? 1 : 0;
  } catch (e) {
    if (e instanceof ModelError || (e as NodeJS.ErrnoException).code === "ENOENT") { console.error(`error: ${(e as Error).message}`); return 2; }
    throw e;
  }
}

process.exitCode = main(process.argv.slice(2));
