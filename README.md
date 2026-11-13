# trifecta-guard

Taint and provenance analysis for LLM agent traces. Give it the tool manifest of an agent and one recorded trace and it tells you whether the agent holds the lethal trifecta, whether an injected instruction steered a call to a destination the user never gave, which private data left through that call, and what a simple policy would have blocked. Zero runtime dependencies. CLI and browser tool.

Live demo: https://jvch0512.github.io/trifecta-guard/ (runs in the tab, nothing is uploaded)

## Why

Prompt injection stays unsolved at the model level, so the practical defence is architectural. The lethal trifecta (Simon Willison, June 2025) names the combination that makes an agent exploitable: access to private data, exposure to untrusted content and a way to communicate externally. Meta's Agents Rule of Two (October 2025) turns it into a design rule: an agent session should hold at most two of untrusted input, sensitive data access, and external communication or state change.

Most tools in this space attack agents (see mcp-red-team). trifecta-guard does the other half: it reads what an agent actually did and shows the evidence a reviewer needs.

## Quick start

```bash
npm install
npm test
node dist/src/cli.js analyze examples/attack.jsonl --tools examples/tools.json
node dist/src/cli.js analyze examples/benign.jsonl --tools examples/tools.json
node dist/src/cli.js analyze trace.jsonl --tools tools.json --allow mycompany.example --fail-on compromised
npm start   # UI on http://127.0.0.1:8787
```

## Inputs

- Manifest: each tool with capabilities `private-data`, `untrusted-input`, `external-comms`, `state-change`, and optionally `destinationArgs` (which arguments carry recipients or URLs).
- Trace: JSON Lines with `user`, `tool_call` (tool, args) and `tool_result` (tool, result) entries. Export it from your agent framework's logging or tracing.

## What it detects

| Finding | How |
|---|---|
| Lethal trifecta | Union of the manifest capabilities |
| Attacker-controlled destination | A recipient or host in an external call that appears in untrusted tool output and never in the user's request |
| Exfiltration | Five or more consecutive words from a private tool result reappear in the arguments of an external call |
| External call after untrusted input | Context was tainted and the destination cannot be tied to the user |
| State change after untrusted input | Same, for state-changing tools |
| Injection signals | Instruction-like phrases, hidden HTML comments, zero-width characters in untrusted output |

Policy replay applies three rules to the same trace: block external calls after untrusted input unless the user gave the destination, enforce a destination allowlist, and require approval for state changes after untrusted input.

## Limits

One trace is evidence, not proof: a clean trace does not make an agent safe, and the word-run test misses paraphrased or encoded leaks. Taint is tracked at context level, not per token. Capability labels are yours to get right.

## References

- Simon Willison, "The lethal trifecta for AI agents", June 2025.
- Meta AI, "Agents Rule of Two", October 2025.
- Debenedetti et al., "Defeating Prompt Injections by Design" (CaMeL), 2025.

## License

MIT
