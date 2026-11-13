# Agent trace analysis: inbox-assistant

Verdict: **exposed**
Capabilities: private-data, untrusted-input, external-comms, state-change
Lethal trifecta: **yes** (3 of 3 risk properties present)

## Findings

| Severity | Step | Finding | Evidence |
|---|---|---|---|
| high | - | Agent holds the lethal trifecta | Tools give it private data, untrusted content and an external channel. Any injected instruction can read and leak. |

## Policy replay

Policy: block external calls after untrusted input: on; destination allowlist: (none); approval for state changes: on.

The policy would not have interrupted this trace.

## Design guidance

- Break the trifecta: remove one of private data, untrusted input or external communication from any single agent session (the Agents Rule of Two idea).
- Never let the model choose a destination: take recipients and URLs from the user or from a fixed allowlist.
- Treat tool output as data. Quarantine untrusted content in a separate context that cannot call tools.

Heuristic analysis of one recorded trace. It shows what happened and what a policy would have stopped. It does not prove an agent is safe.
