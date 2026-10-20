/**
 * File LockStore: the shared conformance suite, byte-stable writes, manifest
 * upkeep, and refusing to build on a lock that does not load.
 */

import assert from "node:assert/strict";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { FileLockStore, runLockStoreConformance } from "../../src/lock/store.js";
import { LockError, loadLock, shardFilename } from "../../src/lock/lock.js";
import type { Identity } from "../../src/lock/lock.js";

const VECTORS = join(fileURLToPath(new URL("../../..", import.meta.url)), "test", "fixtures", "mcp-lock-vectors", "lock");
const REMOTE: Identity = { kind: "remote", url: "https://mcp.example.com/v1/mcp" };
const APPROVAL = { subject: "github:docs-owner", at: "2026-10-19T17:00:00Z", via: "pr" as const, ref: "pr-42" };

function emptyRoot(): { root: string; done: () => void } {
  const root = mkdtempSync(join(tmpdir(), "mcplock-store-"));
  mkdirSync(join(root, ".mcp", "lock"), { recursive: true });
  mkdirSync(join(root, ".mcp", "contracts"), { recursive: true });
  return { root, done: () => rmSync(root, { recursive: true, force: true }) };
}

test("file store passes the LockStore conformance suite", async () => {
  const roots: Array<() => void> = [];
  try {
    const results = await runLockStoreConformance(() => {
      const r = emptyRoot();
      roots.push(r.done);
      return new FileLockStore({ root: r.root });
    });
    for (const r of results) assert.ok(r.ok, `${r.name}: ${r.error}`);
    assert.ok(results.length >= 10);
  } finally {
    for (const done of roots) done();
  }
});

test("approving the vector tools writes the same contract bytes, and a shard that re-reads to the same entries", async () => {
  const r = emptyRoot();
  try {
    const listing = JSON.parse(readFileSync(join(VECTORS, "all-approved", "listing.json"), "utf8")) as { tools: unknown[] };
    const store = new FileLockStore({ root: r.root });
    for (const tool of listing.tools) await store.approve({ identity: REMOTE, tool, ...APPROVAL });
    for (const file of readdirSync(join(VECTORS, "all-approved", ".mcp", "contracts"))) {
      assert.deepEqual(
        readFileSync(join(r.root, ".mcp", "contracts", file)),
        readFileSync(join(VECTORS, "all-approved", ".mcp", "contracts", file)),
        file,
      );
    }
    const name = shardFilename(REMOTE);
    const written = readFileSync(join(r.root, ".mcp", "lock", name), "utf8");
    // The vector shard also carries attributes and instructions; with those
    // removed it is byte-identical to what the store wrote.
    const vector = JSON.parse(readFileSync(join(VECTORS, "all-approved", ".mcp", "lock", name), "utf8")) as Record<string, unknown>;
    delete vector.attributes;
    delete vector.instructions;
    assert.equal(written, JSON.stringify(vector, null, 2) + "\n");
    const loaded = await loadLock(r.root);
    assert.deepEqual([...(loaded.lock.shards.values().next().value?.tools.keys() ?? [])], ["search", "fetch"]);
  } finally {
    r.done();
  }
});

test("re-approving keeps tool order; approving instructions keeps attributes", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mcplock-store-"));
  try {
    const root = join(tmp, "case");
    cpSync(join(VECTORS, "all-approved"), root, { recursive: true });
    const name = shardFilename(REMOTE);
    const before = readFileSync(join(root, ".mcp", "lock", name), "utf8");
    const listing = JSON.parse(readFileSync(join(root, "listing.json"), "utf8")) as { tools: unknown[]; instructions: string };
    const store = new FileLockStore({ root });
    await store.approve({ identity: REMOTE, tool: listing.tools[0], ...APPROVAL });
    await store.approve({ identity: REMOTE, instructions: listing.instructions, ...APPROVAL });
    assert.equal(readFileSync(join(root, ".mcp", "lock", name), "utf8"), before);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("an existing manifest is rewritten with sequence + 1 and current hashes", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mcplock-store-"));
  try {
    const root = join(tmp, "case");
    cpSync(join(VECTORS, "manifest-ok"), root, { recursive: true });
    const seq = (JSON.parse(readFileSync(join(root, ".mcp", "lock", "MANIFEST.json"), "utf8")) as { sequence: number }).sequence;
    const store = new FileLockStore({ root, requireManifest: true });
    await store.approve({
      identity: REMOTE,
      tool: { name: "extra", description: "x", inputSchema: { type: "object" } },
      ...APPROVAL,
    });
    const manifest = JSON.parse(readFileSync(join(root, ".mcp", "lock", "MANIFEST.json"), "utf8")) as { sequence: number };
    assert.equal(manifest.sequence, seq + 1);
    const snap = await store.loadSnapshot();
    assert.ok(!(snap.lock instanceof LockError), String((snap.lock as LockError).detail));
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("the store refuses to write onto a lock that does not load, and leaves no temp files", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mcplock-store-"));
  try {
    const root = join(tmp, "case");
    cpSync(join(VECTORS, "contract-tampered"), root, { recursive: true });
    const store = new FileLockStore({ root });
    await assert.rejects(
      store.approve({ identity: REMOTE, tool: { name: "x", inputSchema: { type: "object" } }, ...APPROVAL }),
      (exc: unknown) => exc instanceof LockError && exc.reason === "contract-mismatch",
    );
    assert.deepEqual(
      readdirSync(join(root, ".mcp")).filter((n) => n.endsWith(".tmp") || n.endsWith(".lck")),
      [],
    );
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("a signed store tracks the accepted sequence across loads and reports it", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mcplock-store-"));
  try {
    const root = join(tmp, "case");
    cpSync(join(VECTORS, "manifest-ok"), root, { recursive: true });
    writeFileSync(join(root, ".mcp", "lock", "MANIFEST.json.sigstore"), "{}");
    const seen: number[] = [];
    const signer = { issuer: "https://issuer.example", san: "https://example/sign@refs/heads/main" };
    const store = new FileLockStore({ root, signer, verifier: { verify: async () => true }, onSequence: (s) => seen.push(s) });
    const first = await store.loadSnapshot();
    assert.ok(!(first.lock instanceof LockError));
    const seq = (first.lock as { sequence: number }).sequence;
    assert.deepEqual(seen, [seq]);
    // Roll the manifest back by one: the in-memory floor refuses it.
    const mPath = join(root, ".mcp", "lock", "MANIFEST.json");
    const text = readFileSync(mPath, "utf8").replace(`"sequence": ${seq}`, `"sequence": ${seq - 1}`);
    writeFileSync(mPath, text);
    const second = await store.loadSnapshot();
    assert.ok(second.lock instanceof LockError && second.lock.reason === "lock-signature-invalid");
    assert.ok(existsSync(mPath));
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});
