node dist/src/cli.js analyze examples/attack.jsonl --tools examples/tools.json > /tmp/a.md || true; diff /tmp/a.md docs/sample-attack.md
node dist/src/cli.js analyze examples/benign.jsonl --tools examples/tools.json > /tmp/b.md; diff /tmp/b.md docs/sample-benign.md
test "$(node dist/src/cli.js analyze examples/attack.jsonl --tools examples/tools.json --fail-on compromised >/dev/null; echo $?)" = "1"
