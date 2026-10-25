# Publishing

## GitHub pack

```bash
# dry-run
node ../discord-pr-triage-guard/node_modules/failproofai/dist/cli.mjs \
  publish policies/idempotent-writes.mjs \
  --dry-run --id sank8-2/idempotent-writes --version 0.1.0

# real
node scripts/release-pack.mjs
```

Install: `failproofai policies add sank8-2/idempotent-writes`

## Cloud

```bash
fp policies publish idempotent-writes policies/idempotent-writes.mjs \
  --description "Require idempotency keys; block duplicate and blind-retry side effects"
fp fleet deploy <machine-id> --add idempotent-writes -y
```
