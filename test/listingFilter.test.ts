import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Gate, Posture } from "../src/gate.js";
import { filterListing, replaceToolList } from "../src/listingFilter.js";
import { Decision, PreflightPin, defaultPinStorePath } from "../src/preflight.js";
import { DEFAULT_SERVER_ID, wrap } from "../src/wrap.js";
import { PreflightHold } from "../src/wrap.js";

const BASE = {
  name: "echo",
  description: "one",
  inputSchema: { type: "object", properties: {} },
};

function gate(): Gate {
  const g = new Gate({ pin: new PreflightPin(), serverId: "srv", posture: Posture.GUARD });
  g.observe("echo", { ...BASE });
  return g;
}

test("disposition matches decide and does not move the pin", () => {
  const changed = { ...BASE, description: "two" };
  const left = gate();
  const right = gate();
  const decided = left.decide("echo", changed);
  const before = right["pin" as never];
  void before;
  const pinBefore = new PreflightPin();
  const fresh = new Gate({ pin: pinBefore, serverId: "srv", posture: Posture.GUARD });
  fresh.observe("echo", { ...BASE });
  const hash = pinBefore.get("srv", "echo")?.definitionHash;
  const outcome = filterListing(fresh, [changed], new Set());
  assert.equal(outcome.kept.length, 0);
  assert.equal(decided[1].decision, Decision.HOLD);
  assert.equal(pinBefore.get("srv", "echo")?.definitionHash, hash);
});

test("monitor keeps the entry and a wrong type is left out", () => {
  const monitor = new Gate({ pin: new PreflightPin(), serverId: "srv", posture: Posture.MONITOR });
  const changed = { ...BASE, description: "two" };
  monitor.observe("echo", { ...BASE });
  const shown = filterListing(monitor, [changed], new Set());
  assert.equal(shown.kept.length, 1);
  const bad = { ...BASE, inputSchema: ["nope"] };
  const guarded = filterListing(gate(), [bad], new Set());
  assert.equal(guarded.kept.length, 0);
  assert.match(guarded.withheld[0]?.reason ?? "", /inputSchema is not an object/);
});

test("duplicate names and a withheld call", async () => {
  const notices: string[] = [];
  const session = {
    tools: [{ ...BASE }],
    calls: 0,
    async listTools() {
      return { tools: this.tools, note: "kept" };
    },
    async callTool(_params?: { name?: string; arguments?: Record<string, unknown> }) {
      this.calls += 1;
      return { ok: true };
    },
    async request(req: { method: string; params?: Record<string, unknown> }) {
      if (req.method === "tools/list") return { result: { tools: this.tools } };
      this.calls += 1;
      return { result: { ok: true } };
    },
  };
  const wrapped = wrap(session, {
    pin: new PreflightPin(),
    serverId: "srv",
    onWithheld: (_s, tool) => notices.push(tool),
  });
  await wrapped.listTools();
  session.tools = [{ ...BASE, description: "two" }];
  const listed = await wrapped.listTools();
  assert.deepEqual(listed.tools, []);
  assert.equal(listed.note, "kept");
  assert.deepEqual(notices, ["echo"]);
  await assert.rejects(wrapped.callTool({ name: "echo", arguments: {} }), (err: unknown) => {
    assert.ok(err instanceof PreflightHold);
    assert.match(err.verdict.reason, /escalation was not attempted/);
    return true;
  });
  assert.equal(session.calls, 0);
  const viaRequest = await wrapped.request({ method: "tools/list", params: {} });
  assert.deepEqual(viaRequest.result.tools, []);
});

test("replace keeps extra fields", () => {
  const replaced = replaceToolList({ tools: [BASE], extra: 1 }, []) as { tools: unknown[]; extra: number };
  assert.equal(replaced.extra, 1);
  assert.deepEqual(replaced.tools, []);
});

test("file pin survives a new store and memory does not", () => {
  const dir = mkdtempSync(join(tmpdir(), "mcpindex-pin-"));
  const previous = process.env.MCPINDEX_STATE_DIR;
  process.env.MCPINDEX_STATE_DIR = dir;
  try {
    const path = defaultPinStorePath("srv/id");
    const pin = new PreflightPin(path);
    pin.put({
      serverId: "srv/id",
      toolName: "echo",
      definitionHash: "abc",
      pinnedAt: "2026-10-05T00:00:00+00:00",
      schema: null,
      via: "manual",
      classification: { grade: "b" },
    });
    const again = new PreflightPin(path);
    const loaded = again.get("srv/id", "echo");
    assert.equal(loaded?.definitionHash, "abc");
    assert.equal(loaded?.via, "manual");
    assert.deepEqual(loaded?.classification, { grade: "b" });
    const text = readFileSync(path, "utf8");
    assert.match(text, /"via": "manual"/);
    again.put({
      serverId: "srv/id",
      toolName: "echo",
      definitionHash: "abc",
      pinnedAt: "2026-10-05T00:00:00+00:00",
      schema: null,
      via: "tofu",
    });
    const round = JSON.parse(readFileSync(path, "utf8")) as { pins: Record<string, unknown>[] };
    assert.equal(round.pins[0]?.["via"], undefined);
    const memory = wrap({ listTools: async () => ({ tools: [] }) }, { pinStore: "memory", serverId: "mem" });
    assert.equal(memory.__interceptor__ !== undefined, true);
  } finally {
    if (previous === undefined) delete process.env.MCPINDEX_STATE_DIR;
    else process.env.MCPINDEX_STATE_DIR = previous;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the default pin is a file only when a serverId is given", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mcpindex-pin-"));
  const previous = process.env.MCPINDEX_STATE_DIR;
  process.env.MCPINDEX_STATE_DIR = dir;
  const tool = { name: "search", description: "Find things.", inputSchema: { type: "object" } };
  const session = { listTools: async () => ({ tools: [tool] }) };
  try {
    await wrap(session).listTools();
    assert.equal(existsSync(defaultPinStorePath(DEFAULT_SERVER_ID)), false);
    await wrap(session, { serverId: "named" }).listTools();
    assert.equal(existsSync(defaultPinStorePath("named")), true);
    await wrap(session, { pinStore: "file" }).listTools();
    assert.equal(existsSync(defaultPinStorePath(DEFAULT_SERVER_ID)), true);
  } finally {
    if (previous === undefined) delete process.env.MCPINDEX_STATE_DIR;
    else process.env.MCPINDEX_STATE_DIR = previous;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("two unnamed wrapped servers do not share pins", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mcpindex-pin-"));
  const previous = process.env.MCPINDEX_STATE_DIR;
  process.env.MCPINDEX_STATE_DIR = dir;
  try {
    const a = { listTools: async () => ({ tools: [{ name: "search", description: "Search docs.", inputSchema: { type: "object" } }] }) };
    const b = { listTools: async () => ({ tools: [{ name: "search", description: "Search tickets.", inputSchema: { type: "object" } }] }) };
    await wrap(a).listTools();
    const listed = (await wrap(b).listTools()) as { tools: { name: string }[] };
    assert.deepEqual(listed.tools.map((t) => t.name), ["search"]);
  } finally {
    if (previous === undefined) delete process.env.MCPINDEX_STATE_DIR;
    else process.env.MCPINDEX_STATE_DIR = previous;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a deleted pin file does not silently start over", () => {
  const dir = mkdtempSync(join(tmpdir(), "mcpindex-pin-"));
  const path = join(dir, "pins.json");
  const pin = new PreflightPin(path);
  pin.put({
    serverId: "srv",
    toolName: "echo",
    definitionHash: "abc",
    pinnedAt: "2026-10-05T00:00:00+00:00",
    schema: null,
  });
  rmSync(path);
  const again = new PreflightPin(path);
  assert.match(again.tainted ?? "", /missing but this server was pinned before/);
  const g = new Gate({ pin: again, serverId: "srv", posture: Posture.MONITOR });
  const verdict = g.decide("echo", BASE)[1];
  assert.equal(verdict.decision, Decision.HOLD);
  assert.equal(verdict.tamperEvidence, true);
});
