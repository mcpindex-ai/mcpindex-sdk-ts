#!/usr/bin/env node
/**
 * `mcpindex` CLI. Currently one command: `login` — self-serve sign-in (GitHub or Google) that mints
 * and stores a free api_key at ~/.mcpindex/credentials.json. See src/login.ts for the loopback flow.
 */

import { loadApiKey, credentialsPath, runLogin, parseProvider } from "./login.js";

const USAGE = `mcpindex - trust-to-act gate for MCP tool calls

Usage:
  mcpindex login [--provider github|google]   Sign in; mints and stores a free api_key (default github)
  mcpindex whoami                             Show whether a key is stored (never prints the key)
  mcpindex help                               Show this help

Env:
  MCPINDEX_WEB_BASE  Override the login host (default https://mcpindex.ai)
`;

async function main(argv: string[]): Promise<number> {
  const cmd = argv[0];
  switch (cmd) {
    case "login": {
      const provider = parseProvider(argv.slice(1));
      if (provider === null) {
        process.stderr.write(`login: --provider must be "github" or "google"\n`);
        return 2;
      }
      try {
        await runLogin({ provider });
        return 0;
      } catch (e) {
        process.stderr.write(`login failed: ${e instanceof Error ? e.message : String(e)}\n`);
        return 1;
      }
    }
    case "whoami": {
      const has = loadApiKey() !== null;
      process.stdout.write(has ? `signed in (key at ${credentialsPath()})\n` : "not signed in - run: mcpindex login\n");
      return has ? 0 : 1;
    }
    case "help":
    case "--help":
    case "-h":
    case undefined:
      process.stdout.write(USAGE);
      return 0;
    default:
      process.stderr.write(`unknown command: ${cmd}\n\n${USAGE}`);
      return 2;
  }
}

main(process.argv.slice(2))
  .then((code) => process.exit(code))
  .catch((e) => {
    process.stderr.write(`mcpindex: ${e instanceof Error ? e.message : String(e)}\n`);
    process.exit(1);
  });
