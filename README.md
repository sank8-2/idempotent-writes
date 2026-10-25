# Idempotent Writes

> **Retrying a read is free. Retrying a write can charge a card twice.**

Failproof policy pack that makes agent side effects **conditional on an idempotency key**, blocks duplicates, and refuses blind retries after timeouts.

Works across **Claude Code, Codex, Copilot, Cursor, and other Failproof harnesses** — one policy file, `PreToolUse` before the tool runs.

## Policies

| Policy | Default | Gate |
|---|---|---|
| `require-idempotency-key-on-writes` | on | Email, charge, webhook, Discord/Slack-style tools, and `curl` POST/PUT/PATCH/DELETE need a key |
| `block-duplicate-side-effect` | on | Deny when `already_done` / `already_sent` / `duplicate` |
| `block-blind-write-retry` | on | Deny retry when `prior_timeout` / `outcome_unknown` unless reconciled |
| `warn-untrusted-user-content-on-writes` | on | Instruct when email/issue/PR bodies look like prompt injection |

## Install (GitHub pack)

```bash
failproofai policies add sank8-2/idempotent-writes
# or force every policy on:
failproofai policies add sank8-2/idempotent-writes --all
```

## Cloud (FailproofAI Cloud)

```bash
fp policies publish idempotent-writes ./policies/idempotent-writes.mjs \
  --description "Require idempotency keys; block duplicate and blind-retry side effects"
fp fleet deploy <machine> --add idempotent-writes -y
```

## Local test

```bash
npm install
npm test
fp policies test ./policies/idempotent-writes.mjs \
  --tool Bash \
  --command 'curl -X POST https://example.com -d x=1'
```

## License

MIT
