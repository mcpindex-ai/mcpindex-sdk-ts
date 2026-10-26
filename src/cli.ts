#!/usr/bin/env node
/**
 * `mcpindex` CLI entry point. `login` is self-serve sign-in (GitHub or Google) that mints and
 * stores a free api_key at ~/.mcpindex/credentials.json; see src/login.ts for the loopback
 * flow. Parsing and dispatch live in src/cliMain.ts so they can be tested without a process.
 */

import { runCli } from "./cliMain.js";

runCli(process.argv.slice(2))
  .then((code) => process.exit(code))
  .catch((e) => {
    process.stderr.write(`mcpindex: ${e instanceof Error ? e.message : String(e)}\n`);
    process.exit(1);
  });
