/**
 * CallGate order and default staleness, the _meta decision, and listing event
 * fields that must match the Python host (draft 1c).
 */

import assert from "node:assert/strict";
import test from "node:test";

import { CallGate, DEFAULT_MAX_STALENESS_MS, checkListing } from "../../src/lock/check.js";
import { metaDigest, toolDigest } from "../../src/lock/digest.js";
import { listingEvent } from "../../src/lock/events.js";
import { FrozenMap, LockError, identityKey } from "../../src/lock/lock.js";
import type { Identity, Lock, Shard, ToolEntry } from "../../src/lock/lock.js";

const ID: Identity = { kind: "remote", url: "https://mcp.example.com/v1/mcp" };
const SNAP = { snapshotId: "s", loadedAt: 0 };

function lockOf(entries: Array<[string, unknown, string?]>): Lock {
  const tools = new Map<string, ToolEntry>();
  for (const [name, tool, meta] of entries) {
    const digest = toolDigest(tool) as string;
    const approval = { subject: "t", at: "2026-10-19T00:00:00Z", via: "api" as const };
    const contract = `sha256-${digest.slice(7)}.json`;
    tools.set(name, meta === undefined ? { digest, contract, approval } : { digest, contract, metaDigest: meta, approval });
  }
  const shard: Shard = { identity: ID, attributes: null, instructions: null, tools: new FrozenMap(tools) };
  return { shards: new FrozenMap([[identityKey(ID), shard]]), aliases: new FrozenMap([]), sequence: null };
}

const SEARCH = { name: "search", inputSchema: { type: "object" } };

test("call reason order: in progress, unreachable, none completed, whole-lock error, stale", () => {
  let clock = 0;
  const gate = new CallGate({ maxStalenessMs: 10, now: () => clock });
  assert.equal(gate.check("search"), "no-listing");
  gate.markUnreachable();
  assert.equal(gate.check("search"), "unreachable");
  gate.beginListing();
  assert.equal(gate.check("search"), "no-listing");
  gate.record(checkListing(new LockError("lock-unreadable", "x"), ID, { tools: [SEARCH] }, "guard"), SNAP);
  clock = 100;
  assert.equal(gate.check("search"), "lock-unreadable");
});

test("S6: a whole-lock error is reported before lock-stale", () => {
  let clock = 0;
  const gate = new CallGate({ maxStalenessMs: 10, now: () => clock });
  const failed = checkListing(new LockError("lock-unreadable", "x"), ID, { tools: [SEARCH] }, "guard");
  gate.record(failed, SNAP);
  clock = 1_000;
  assert.equal(gate.isStale(), true);
  assert.equal(gate.check("search"), "lock-unreadable");
  const ok = checkListing(lockOf([["search", SEARCH]]), ID, { tools: [SEARCH] }, "guard");
  gate.record(ok, { snapshotId: "t", loadedAt: 0 });
  assert.equal(gate.check("search"), "lock-stale");
});

test("S5: the gate goes stale after 60 s by default, the same default as the Python host", () => {
  assert.equal(DEFAULT_MAX_STALENESS_MS, 60_000);
  let clock = 0;
  const gate = new CallGate({ now: () => clock });
  gate.record(checkListing(lockOf([["search", SEARCH]]), ID, { tools: [SEARCH] }, "guard"), SNAP);
  clock = 60_000;
  assert.equal(gate.check("search"), "allow");
  clock = 60_001;
  assert.equal(gate.check("search"), "lock-stale");
});

test("S1: the gate refuses every call with no-listing while a listing is in progress", () => {
  const gate = new CallGate();
  gate.record(checkListing(lockOf([["search", SEARCH]]), ID, { tools: [SEARCH] }, "guard"), { snapshotId: "s", loadedAt: Date.now() });
  assert.equal(gate.check("search"), "allow");
  gate.beginListing();
  assert.equal(gate.check("search"), "no-listing");
  gate.endListing();
  assert.equal(gate.check("search"), "allow");
});

test("S3: the four _meta cases, and a _meta that is not an object", () => {
  const meta = { ui: { resourceUri: "ui://a" } };
  const withMeta = { ...SEARCH, _meta: meta };
  const changed = { ...SEARCH, _meta: { ui: { resourceUri: "ui://b" } } };
  const approvedMeta = metaDigest(withMeta) as string;
  assert.match(approvedMeta, /^sha256:[0-9a-f]{64}$/);
  assert.equal(metaDigest(SEARCH), null);
  assert.equal(metaDigest({ ...SEARCH, _meta: "x" }), null);
  for (const posture of ["guard", "monitor"] as const) {
    const guard = posture === "guard";
    // Matches: relayed, no flag.
    const a = checkListing(lockOf([["search", SEARCH, approvedMeta]]), ID, { tools: [withMeta] }, posture);
    assert.deepEqual([...a.shown], ["search"]);
    assert.deepEqual(a.meta.get("search"), { relay: true, flag: null });
    assert.equal(a.stripMeta.size, 0);
    // Differs: shown, flagged meta-changed, removed under guard only.
    const b = checkListing(lockOf([["search", SEARCH, approvedMeta]]), ID, { tools: [changed] }, posture);
    assert.deepEqual([...b.shown], ["search"]);
    assert.deepEqual(b.meta.get("search"), { relay: !guard, flag: "meta-changed" });
    assert.equal(b.stripMeta.has(0), guard);
    assert.ok(b.callable.has("search"));
    assert.equal(b.tools[0]?.meta, "meta-changed");
    // Not an object: no meta digest, so it changed.
    const s = checkListing(lockOf([["search", SEARCH, approvedMeta]]), ID, { tools: [{ ...SEARCH, _meta: "x" }] }, posture);
    assert.deepEqual(s.meta.get("search"), { relay: !guard, flag: "meta-changed" });
    // No metaDigest approved and a served _meta: meta-unapproved.
    const c = checkListing(lockOf([["search", SEARCH]]), ID, { tools: [withMeta] }, posture);
    assert.deepEqual(c.meta.get("search"), { relay: !guard, flag: "meta-unapproved" });
    assert.equal(c.stripMeta.has(0), guard);
    // No served _meta: nothing to decide.
    const d = checkListing(lockOf([["search", SEARCH, approvedMeta]]), ID, { tools: [SEARCH] }, posture);
    assert.equal(d.meta.size, 0);
  }
});

test("T5: counts.withheld counts unnamed entries and a whole-lock failure reports no instructions code", () => {
  const ctx = { host: "h", identity: ID };
  const tools = [SEARCH, { inputSchema: {} }, 7];
  const ok = checkListing(lockOf([["search", SEARCH]]), ID, { tools }, "guard");
  const e1 = listingEvent(ctx, ok, "s");
  assert.deepEqual(e1.counts, { served: 3, shown: 1, withheld: 2, removed: 0 });
  const failed = checkListing(new LockError("lock-unreadable", "x"), ID, { tools, instructions: "hi" }, "monitor");
  const e2 = listingEvent(ctx, failed, "s");
  assert.deepEqual(e2.counts, { served: 3, shown: 0, withheld: 3, removed: 0 });
  assert.equal(e2.instructions, null);
  assert.equal(e2.lockError, "lock-unreadable");
  assert.equal(failed.stripInstructions, true);
});
