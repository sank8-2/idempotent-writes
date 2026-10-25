#!/usr/bin/env node
import { spawn } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { existsSync } from "node:fs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const candidates = [
  join(root, "node_modules/failproofai/dist/cli.mjs"),
  join(root, "../discord-pr-triage-guard/node_modules/failproofai/dist/cli.mjs"),
];
const cliPath = candidates.find((p) => existsSync(p));
if (!cliPath) {
  console.error("failproofai dist/cli.mjs not found — run npm install");
  process.exit(1);
}

const dry = process.argv.includes("--dry-run");
const args = [
  "publish",
  "policies/idempotent-writes.mjs",
  "--repo",
  "sank8-2/idempotent-writes",
  "--id",
  "sank8-2/idempotent-writes",
  "--version",
  "0.1.0",
  "--notes",
  "Require idempotency keys on agent writes; block duplicates and blind retries after timeouts; warn on untrusted user content.",
];
if (dry) args.push("--dry-run");

const child = spawn(process.execPath, [cliPath, ...args], {
  cwd: root,
  stdio: "inherit",
  env: process.env,
});
child.on("exit", (code) => process.exit(code ?? 1));
