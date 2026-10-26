/**
 * The `mcpindex` CLI, minus the process glue in cli.ts, so tests can drive it with fakes.
 *
 * Arguments are parsed strictly before anything runs. `login` starts a loopback listener,
 * opens a browser and mints a real key, so a flag it does not know (`--help`, a typo) must
 * never fall through to it: help exits 0, anything unrecognised exits 2, and neither touches
 * the network or the credentials file.
 */

import { readFileSync } from "node:fs";
import { credentialsPath, loadApiKey, runLogin, type LoginProvider } from "./login.js";

export const USAGE = `mcpindex - trust-to-act gate for MCP tool calls

Usage:
  mcpindex login [--provider github|google]   Sign in; mints and stores a free api_key (default github)
  mcpindex whoami                             Show whether a key is stored (never prints the key)
  mcpindex help                               Show this help
  mcpindex --version                          Print the package version

Every command takes --help / -h.

Env:
  MCPINDEX_WEB_BASE  Override the login host (default https://mcpindex.ai)
`;

export type CliCommand =
  | { kind: "help" }
  | { kind: "version" }
  | { kind: "login"; provider: LoginProvider }
  | { kind: "whoami" }
  | { kind: "error"; message: string };

const HELP_FLAGS = new Set(["--help", "-h"]);

/** Pure: argv (without node and script) to the one thing to do. Never has side effects. */
export function parseCliArgs(argv: readonly string[]): CliCommand {
  const [cmd, ...rest] = argv;
  if (cmd === undefined || cmd === "help" || HELP_FLAGS.has(cmd)) {
    if (rest.length > 0) return { kind: "error", message: `unexpected argument: ${rest[0]}` };
    return { kind: "help" };
  }
  if (cmd === "--version") {
    if (rest.length > 0) return { kind: "error", message: `unexpected argument: ${rest[0]}` };
    return { kind: "version" };
  }
  if (cmd !== "login" && cmd !== "whoami") return { kind: "error", message: `unknown command: ${cmd}` };
  // Help anywhere after a command wins, so `login --provider google --help` still only prints.
  if (rest.some((a) => HELP_FLAGS.has(a))) return { kind: "help" };
  if (cmd === "whoami") {
    if (rest.length > 0) return { kind: "error", message: `whoami: unexpected argument: ${rest[0]}` };
    return { kind: "whoami" };
  }
  let provider: LoginProvider | null = null;
  for (let i = 0; i < rest.length; i++) {
    const arg = rest[i]!;
    let value: string | undefined;
    if (arg === "--provider") {
      value = rest[i + 1];
      i += 1;
    } else if (arg.startsWith("--provider=")) {
      value = arg.slice("--provider=".length);
    } else {
      return { kind: "error", message: `login: unexpected argument: ${arg}` };
    }
    if (provider !== null) return { kind: "error", message: "login: --provider given more than once" };
    if (value !== "github" && value !== "google") {
      return { kind: "error", message: `login: --provider must be "github" or "google"` };
    }
    provider = value;
  }
  return { kind: "login", provider: provider ?? "github" };
}

export interface CliDeps {
  stdout: (s: string) => void;
  stderr: (s: string) => void;
  login: (provider: LoginProvider) => Promise<unknown>;
  hasKey: () => boolean;
  keyPath: () => string;
  version: () => string;
}

export function packageVersion(): string {
  // dist/src/cliMain.js -> ../../package.json, which npm always ships.
  const raw = readFileSync(new URL("../../package.json", import.meta.url), "utf8");
  const v = (JSON.parse(raw) as { version?: unknown }).version;
  if (typeof v !== "string" || v.length === 0) throw new Error("package.json has no version");
  return v;
}

export const defaultCliDeps: CliDeps = {
  stdout: (s) => void process.stdout.write(s),
  stderr: (s) => void process.stderr.write(s),
  login: (provider) => runLogin({ provider }),
  hasKey: () => loadApiKey() !== null,
  keyPath: credentialsPath,
  version: packageVersion,
};

/** Run one CLI invocation and return its exit code. */
export async function runCli(argv: readonly string[], deps: CliDeps = defaultCliDeps): Promise<number> {
  const parsed = parseCliArgs(argv);
  switch (parsed.kind) {
    case "help":
      deps.stdout(USAGE);
      return 0;
    case "version":
      deps.stdout(`${deps.version()}\n`);
      return 0;
    case "error":
      deps.stderr(`${parsed.message}\n\n${USAGE}`);
      return 2;
    case "whoami": {
      const has = deps.hasKey();
      deps.stdout(has ? `signed in (key at ${deps.keyPath()})\n` : "not signed in - run: mcpindex login\n");
      return has ? 0 : 1;
    }
    case "login":
      try {
        await deps.login(parsed.provider);
        return 0;
      } catch (e) {
        deps.stderr(`login failed: ${e instanceof Error ? e.message : String(e)}\n`);
        return 1;
      }
  }
}
