import { strict as assert } from "node:assert";
import test from "node:test";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { parseCliArgs, runCli, USAGE, type CliDeps } from "../src/cliMain.js";

// A login during these tests would open a browser and mint a real key. Every fake below
// records the attempt and fails the test instead.
function fakeDeps(): CliDeps & { out: string[]; err: string[]; logins: string[] } {
  const out: string[] = [];
  const err: string[] = [];
  const logins: string[] = [];
  return {
    out,
    err,
    logins,
    stdout: (s) => void out.push(s),
    stderr: (s) => void err.push(s),
    login: async (p) => {
      logins.push(p);
    },
    hasKey: () => false,
    keyPath: () => "/nonexistent/credentials.json",
    version: () => "9.9.9-test",
  };
}

const HELP_FORMS: string[][] = [
  [],
  ["help"],
  ["--help"],
  ["-h"],
  ["login", "--help"],
  ["login", "-h"],
  ["login", "--provider", "google", "--help"],
  ["login", "--bogus", "--help"],
  ["whoami", "--help"],
  ["whoami", "-h"],
];

for (const argv of HELP_FORMS) {
  test(`help: mcpindex ${argv.join(" ") || "(bare)"} prints usage, exits 0, never logs in`, async () => {
    const d = fakeDeps();
    assert.equal(await runCli(argv, d), 0);
    assert.equal(d.out.join(""), USAGE);
    assert.deepEqual(d.err, []);
    assert.deepEqual(d.logins, []);
  });
}

const BAD_FORMS: string[][] = [
  ["login", "--hlep"],
  ["login", "help"],
  ["login", "extra"],
  ["login", "--provider"],
  ["login", "--provider", "gitlab"],
  ["login", "--provider=gitlab"],
  ["login", "--provider", "github", "--provider", "google"],
  ["login", "--provider", "github", "--version"],
  ["whoami", "--verbose"],
  ["whoami", "extra"],
  ["help", "login"],
  ["--version", "extra"],
  ["report"],
  ["--bogus"],
];

for (const argv of BAD_FORMS) {
  test(`strict: mcpindex ${argv.join(" ")} prints usage to stderr, exits 2, never logs in`, async () => {
    const d = fakeDeps();
    assert.equal(await runCli(argv, d), 2);
    assert.deepEqual(d.out, []);
    const err = d.err.join("");
    assert.ok(err.endsWith(USAGE), "usage follows the error");
    assert.ok(err.length > USAGE.length, "names what was wrong");
    assert.deepEqual(d.logins, []);
  });
}

test("login runs only on an exact form, with the provider it was given", async () => {
  const cases: Array<[string[], string]> = [
    [["login"], "github"],
    [["login", "--provider", "google"], "google"],
    [["login", "--provider=github"], "github"],
  ];
  for (const [argv, provider] of cases) {
    const d = fakeDeps();
    assert.equal(await runCli(argv, d), 0, argv.join(" "));
    assert.deepEqual(d.logins, [provider], argv.join(" "));
  }
});

test("--version prints the version and nothing else", async () => {
  const d = fakeDeps();
  assert.equal(await runCli(["--version"], d), 0);
  assert.deepEqual(d.out, ["9.9.9-test\n"]);
  assert.deepEqual(d.logins, []);
});

test("whoami does not log in", async () => {
  const d = fakeDeps();
  assert.equal(await runCli(["whoami"], d), 1);
  assert.match(d.out.join(""), /not signed in/);
  assert.deepEqual(d.logins, []);
});

test("parseCliArgs is pure: the same argv gives the same command", () => {
  assert.deepEqual(parseCliArgs(["login", "--help"]), { kind: "help" });
  assert.deepEqual(parseCliArgs(["login"]), { kind: "login", provider: "github" });
  assert.equal(parseCliArgs(["login", "-x"]).kind, "error");
});

// The real binary, end to end. MCPINDEX_WEB_BASE is not a URL, so if parsing ever fell
// through to login again, runLogin would reject before binding a port or opening a browser
// and this would fail on the exit code rather than mint a key.
const CLI = fileURLToPath(new URL("../src/cli.js", import.meta.url));
const PKG = JSON.parse(readFileSync(fileURLToPath(new URL("../../package.json", import.meta.url)), "utf8")) as {
  version: string;
};

function runBin(args: string[]) {
  const home = mkdtempSync(join(tmpdir(), "mcpindex-cli-home-"));
  const state = mkdtempSync(join(tmpdir(), "mcpindex-cli-state-"));
  const r = spawnSync(process.execPath, [CLI, ...args], {
    encoding: "utf8",
    timeout: 20_000,
    env: { PATH: process.env.PATH ?? "", HOME: home, MCPINDEX_STATE_DIR: state, MCPINDEX_WEB_BASE: "not-a-url" },
  });
  return { ...r, home, state };
}

test("binary: login --help, -h and an unknown flag exit without logging in or writing state", () => {
  for (const [args, code] of [
    [["login", "--help"], 0],
    [["login", "-h"], 0],
    [["login", "--hlep"], 2],
    [["--help"], 0],
  ] as Array<[string[], number]>) {
    const r = runBin(args);
    assert.equal(r.status, code, `${args.join(" ")}: ${r.stderr}`);
    assert.doesNotMatch(r.stdout + r.stderr, /Opening your browser|login failed|Signed in/, args.join(" "));
    assert.equal(existsSync(join(r.home, ".mcpindex")), false, "nothing under HOME/.mcpindex");
    assert.deepEqual(readdirSync(r.state), [], "nothing in the state dir");
  }
});

test("binary: --version prints package.json's version", () => {
  const r = runBin(["--version"]);
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stdout, `${PKG.version}\n`);
});
