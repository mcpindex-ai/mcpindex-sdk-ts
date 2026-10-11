/**
 * Pin store lock-reload-merge: two processes writing one file keep both pins.
 * Also covers launchKey round-trip and approvePending on a persistent store.
 */

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { PreflightPin, type ToolDef } from "../src/preflight.js";
import { wrap } from "../src/wrap.js";

// Compiled tests live in dist/test/; the built sources are in dist/src/.
const ROOT = fileURLToPath(new URL("../..", import.meta.url));

function tool(name: string, description: string): ToolDef {
  return {
    name,
    description,
    inputSchema: { type: "object", properties: {} },
  };
}

test("old pin file without launch_key loads and writes back without that field", () => {
  const dir = mkdtempSync(join(tmpdir(), "mcpindex-pin-"));
  try {
    const path = join(dir, "srv.json");
    writeFileSync(
      path,
      JSON.stringify(
        {
          version: 2,
          pins: [
            {
              server_id: "srv",
              tool_name: "echo",
              definition_hash: "ab".repeat(32),
              pinned_at: "2026-10-09T00:00:00+00:00",
            },
          ],
        },
        null,
        2,
      ) + "\n",
    );
    const pin = new PreflightPin(path);
    const got = pin.get("srv", "echo");
    assert.ok(got);
    assert.equal(got.launchKey, undefined);
    pin.put({
      serverId: "srv",
      toolName: "echo",
      definitionHash: got.definitionHash,
      pinnedAt: got.pinnedAt,
      schema: null,
    });
    const raw = readFileSync(path, "utf8");
    assert.equal(raw.includes("launch_key"), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("two child processes pin into one file without losing writes", () => {
  const dir = mkdtempSync(join(tmpdir(), "mcpindex-pin-"));
  try {
    const path = join(dir, "srv.json");
    const preflight = join(ROOT, "dist/src/preflight.js");
    const child = `
import { PreflightPin } from ${JSON.stringify(preflight)};
const path = process.argv[2];
const prefix = process.argv[3];
const count = Number(process.argv[4]);
const pin = new PreflightPin(path);
for (let i = 0; i < count; i++) {
  pin.put({
    serverId: "srv",
    toolName: prefix + "-" + i,
    definitionHash: "ab".repeat(32),
    pinnedAt: "2026-10-09T00:00:00+00:00",
    schema: null,
  });
}
`;
    const script = join(dir, "child.mjs");
    writeFileSync(script, child);
    const runnerPath = join(dir, "runner.cjs");
    writeFileSync(
      runnerPath,
      `
const { spawn } = require("node:child_process");
const path = ${JSON.stringify(path)};
const script = ${JSON.stringify(script)};
const kids = ["a", "b"].map((prefix) =>
  spawn(process.execPath, [script, path, prefix, "40"], { stdio: ["ignore", "pipe", "pipe"] })
);
Promise.all(
  kids.map(
    (k) =>
      new Promise((res, rej) => {
        let err = "";
        k.stderr.on("data", (chunk) => { err += chunk; });
        k.on("exit", (code) => {
          if (code === 0) res(undefined);
          else rej(new Error(err || String(code)));
        });
      }),
  ),
)
  .then(() => process.exit(0))
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });
`,
    );
    const out = spawnSync(process.execPath, [runnerPath], { encoding: "utf8" });
    assert.equal(out.status, 0, out.stderr + out.stdout);
    const pin = new PreflightPin(path);
    const names = new Set(pin.toolsFor("srv").map((p) => p.toolName));
    for (const prefix of ["a", "b"]) {
      for (let i = 0; i < 40; i++) {
        assert.ok(names.has(`${prefix}-${i}`), `missing ${prefix}-${i}`);
      }
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("wrap with persistent store withholds a new tool and approvePending admits it", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mcpindex-state-"));
  const prev = process.env.MCPINDEX_STATE_DIR;
  process.env.MCPINDEX_STATE_DIR = dir;
  try {
    const pinPath = join(dir, "pins", "srv.json");
    const tools: ToolDef[] = [tool("echo", "Echo a line")];
    const notices: Array<[string, string]> = [];
    const session = {
      async listTools() {
        return { tools: [...tools] };
      },
      async callTool(params: { name: string; arguments?: Record<string, unknown> }) {
        return { ok: true, name: params.name };
      },
    };
    const wrapped = wrap(session, {
      pin: new PreflightPin(pinPath),
      serverId: "srv",
      onWithheld: (_s, name, _r, digest) => notices.push([name, digest]),
    });
    const first = (await wrapped.listTools()) as { tools: ToolDef[] };
    assert.deepEqual(
      first.tools.map((t) => t.name),
      ["echo"],
    );
    tools.push(tool("note", "Write a note"));
    const second = (await wrapped.listTools()) as { tools: ToolDef[] };
    assert.deepEqual(
      second.tools.map((t) => t.name),
      ["echo"],
    );
    assert.equal(notices.length, 1);
    assert.equal(notices[0]![0], "note");
    assert.ok(notices[0]![1].length >= 8);
    const written = wrapped.approvePending("note", notices[0]![1]);
    assert.ok(written);
    const third = (await wrapped.listTools()) as { tools: ToolDef[] };
    assert.deepEqual(
      third.tools.map((t) => t.name).sort(),
      ["echo", "note"],
    );
    const call = (await wrapped.callTool({
      name: "note",
      arguments: {},
    } as { name: string; arguments?: Record<string, unknown> })) as { ok: boolean };
    assert.equal(call.ok, true);
  } finally {
    if (prev === undefined) delete process.env.MCPINDEX_STATE_DIR;
    else process.env.MCPINDEX_STATE_DIR = prev;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a stale .lck is broken and an empty leftover .lock does not block", () => {
  const dir = mkdtempSync(join(tmpdir(), "mcpindex-pin-"));
  try {
    const path = join(dir, "srv.json");
    const lock = `${path}.lck`;
    writeFileSync(lock, "1\n2000-01-01T00:00:00.000Z\n");
    const old = new Date(Date.now() - 120_000);
    utimesSync(lock, old, old);
    const pin = new PreflightPin(path);
    pin.put({
      serverId: "srv",
      toolName: "echo",
      definitionHash: "ab".repeat(32),
      pinnedAt: "2026-10-09T00:00:00+00:00",
      schema: null,
    });
    assert.ok(pin.get("srv", "echo"));
    writeFileSync(`${path}.lock`, "");
    pin.put({
      serverId: "srv",
      toolName: "note",
      definitionHash: "cd".repeat(32),
      pinnedAt: "2026-10-09T00:00:00+00:00",
      schema: null,
    });
    assert.ok(pin.get("srv", "note"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("file-store put succeeds when process.platform is win32", () => {
  const dir = mkdtempSync(join(tmpdir(), "mcpindex-pin-"));
  const original = Object.getOwnPropertyDescriptor(process, "platform");
  try {
    Object.defineProperty(process, "platform", { value: "win32", configurable: true });
    const path = join(dir, "srv.json");
    const pin = new PreflightPin(path);
    pin.put({
      serverId: "srv",
      toolName: "echo",
      definitionHash: "ab".repeat(32),
      pinnedAt: "2026-10-09T00:00:00+00:00",
      schema: null,
    });
    assert.ok(pin.get("srv", "echo"));
  } finally {
    if (original) Object.defineProperty(process, "platform", original);
    rmSync(dir, { recursive: true, force: true });
  }
});
