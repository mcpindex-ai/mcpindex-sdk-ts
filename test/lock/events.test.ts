/**
 * Lock events go to the caller's sink only and never carry arguments,
 * results, descriptions, instructions text or credentials.
 */

import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

import { EVENT_SCHEMA, approvalEvent, jsonlFileSink, listingEvent } from "../../src/lock/events.js";
import type { LockEvent } from "../../src/lock/events.js";
import { checkListing } from "../../src/lock/check.js";
import { FileLockStore } from "../../src/lock/store.js";
import { lockClient } from "../../src/lock/rawList.js";
import type { Identity } from "../../src/lock/lock.js";

const ID: Identity = { kind: "remote", url: "https://mcp.example.com/v1/mcp" };
const MARKERS = ["DESC-MARKER", "INSTR-MARKER", "ARG-MARKER", "RESULT-MARKER", "Bearer sk-live-CREDENTIAL", "TOKEN-MARKER"];

test("a guarded session emits listing and refusal events with no leaked text", async () => {
  const root = mkdtempSync(join(tmpdir(), "mcplock-events-"));
  try {
    mkdirSync(join(root, ".mcp", "lock"), { recursive: true });
    mkdirSync(join(root, ".mcp", "contracts"), { recursive: true });
    const store = new FileLockStore({ root });
    const search = { name: "search", description: "Search DESC-MARKER.", inputSchema: { type: "object" as const } };
    await store.approve({ identity: ID, tool: search, subject: "github:owner", via: "pr", ref: "pr-1" });

    const server = new Server(
      { name: "s", version: "1" },
      { capabilities: { tools: {} }, instructions: "INSTR-MARKER Bearer sk-live-CREDENTIAL" },
    );
    server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [search, { name: "exfil", description: "DESC-MARKER changed", inputSchema: { type: "object" as const } }],
    }));
    server.setRequestHandler(CallToolRequestSchema, async () => ({ content: [{ type: "text", text: "RESULT-MARKER TOKEN-MARKER" }] }));
    const [c, s] = InMemoryTransport.createLinkedPair();
    await server.connect(s);
    const events: LockEvent[] = [];
    const client = new Client({ name: "c", version: "1" });
    await lockClient(client, c, { store, identity: ID, posture: "guard", host: "ci-runner-3", sink: (e) => events.push(e) });
    await client.listTools();
    await client.callTool({ name: "search", arguments: { q: "ARG-MARKER", auth: "Bearer sk-live-CREDENTIAL" } });
    await assert.rejects(client.callTool({ name: "exfil", arguments: { q: "ARG-MARKER" } }));
    await client.close();

    assert.deepEqual(events.map((e) => e.type), ["listing", "refusal"]);
    const text = JSON.stringify(events);
    for (const m of MARKERS) assert.ok(!text.includes(m), `event text leaked ${m}`);
    const listing = events[0];
    assert.ok(listing?.type === "listing");
    assert.equal(listing.schema, EVENT_SCHEMA);
    assert.equal(listing.host, "ci-runner-3");
    assert.deepEqual(listing.server, { h16: "022711de5f88d01f", slug: "mcp-example-com-v1-mcp" });
    assert.equal(listing.instructions, "instructions-changed");
    assert.deepEqual(listing.counts, { served: 2, shown: 1, withheld: 1, removed: 0 });
    assert.deepEqual(
      listing.tools.map((t) => [t.name, t.decision, t.reason]),
      [
        ["search", "shown", null],
        ["exfil", "withheld", "new-tool"],
      ],
    );
    assert.match(listing.time, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
    // Every member is one the spec lists (plus snapshotId).
    assert.deepEqual(
      Object.keys(listing).sort(),
      ["counts", "host", "id", "instructions", "lockError", "posture", "removed", "schema", "server", "snapshotId", "time", "tools", "type"],
    );
    for (const t of listing.tools) assert.deepEqual(Object.keys(t).sort(), ["approved", "decision", "meta", "name", "reason", "served"]);
    const refusal = events[1];
    assert.ok(refusal?.type === "refusal");
    assert.deepEqual([refusal.tool, refusal.reason], ["exfil", "new-tool"]);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("event builders take only the fields they write", () => {
  const ctx = { host: "h", identity: ID, now: () => new Date("2026-10-19T17:05:00.123Z"), newId: () => "01" };
  const d = checkListing(
    { shards: new Map(), aliases: new Map(), sequence: null },
    ID,
    { tools: [{ name: "a", description: "DESC-MARKER" }], instructions: "INSTR-MARKER" },
    "guard",
  );
  const e = listingEvent(ctx, d, "sha256:x");
  assert.equal(e.time, "2026-10-19T17:05:00Z");
  assert.ok(!JSON.stringify(e).includes("MARKER"));
  const a = approvalEvent(ctx, { tool: "a", digest: "sha256:y", via: "pr", subject: "github:o" });
  assert.equal(a.ref, null);
});

test("the file sink appends one JSON line per event, only where the caller points it", () => {
  const dir = mkdtempSync(join(tmpdir(), "mcplock-sink-"));
  try {
    const path = join(dir, "events.jsonl");
    const sink = jsonlFileSink(path);
    const ctx = { host: "h", identity: ID };
    sink(approvalEvent(ctx, { tool: "a", digest: "sha256:y", via: "pr", subject: "s" }));
    sink(approvalEvent(ctx, { tool: "b", digest: "sha256:z", via: "pr", subject: "s" }));
    const lines = readFileSync(path, "utf8").trim().split("\n");
    assert.equal(lines.length, 2);
    assert.equal((JSON.parse(lines[1] as string) as { tool: string }).tool, "b");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
