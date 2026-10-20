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

import { FileLockStore } from "../../src/lock/store.js";
import { runLockStoreConformance } from "./conformance.js";
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

test("a signed store keeps the accepted sequence in its sequence file and in memory", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mcplock-store-"));
  try {
    const root = join(tmp, "case");
    cpSync(join(VECTORS, "manifest-ok"), root, { recursive: true });
    writeFileSync(join(root, ".mcp", "lock", "MANIFEST.json.sigstore"), "{}");
    const signer = { issuer: "https://issuer.example", san: "https://example/sign@refs/heads/main" };
    const sequencePath = join(tmp, "sequence");
    const store = new FileLockStore({ root, signer, verifier: { verify: async () => true }, sequencePath });
    const first = await store.loadSnapshot();
    assert.ok(!(first.lock instanceof LockError));
    const seq = (first.lock as { sequence: number }).sequence;
    assert.equal(readFileSync(sequencePath, "ascii"), `${seq}\n`);
    // Roll the manifest back by one: refused.
    const mPath = join(root, ".mcp", "lock", "MANIFEST.json");
    const text = readFileSync(mPath, "utf8").replace(`"sequence": ${seq}`, `"sequence": ${seq - 1}`);
    writeFileSync(mPath, text);
    const second = await store.loadSnapshot();
    assert.ok(second.lock instanceof LockError && second.lock.reason === "lock-signature-invalid");
    // A fresh store instance reads the floor from the file.
    const restarted = new FileLockStore({ root, signer, verifier: { verify: async () => true }, sequencePath });
    const third = await restarted.loadSnapshot();
    assert.ok(third.lock instanceof LockError && third.lock.reason === "lock-signature-invalid");
    // The in-memory floor holds even when the file is reset under the store.
    rmSync(sequencePath);
    const fourth = await store.loadSnapshot();
    assert.ok(fourth.lock instanceof LockError && fourth.lock.reason === "lock-signature-invalid");
    assert.ok(existsSync(mPath));
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("a signer without a sequence store is refused at load as lock-signature-invalid", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mcplock-store-"));
  try {
    const root = join(tmp, "case");
    cpSync(join(VECTORS, "manifest-ok"), root, { recursive: true });
    writeFileSync(join(root, ".mcp", "lock", "MANIFEST.json.sigstore"), "{}");
    const signer = { issuer: "https://issuer.example", san: "https://example/sign@refs/heads/main" };
    const store = new FileLockStore({ root, signer, verifier: { verify: async () => true } });
    const snap = await store.loadSnapshot();
    assert.ok(snap.lock instanceof LockError);
    assert.equal(snap.lock.reason, "lock-signature-invalid");
    assert.match(snap.lock.detail, /sequence store/);
    // A sequence file that does not hold digits fails closed too.
    const bad = join(tmp, "seq");
    writeFileSync(bad, "seven\n");
    const store2 = new FileLockStore({ root, signer, verifier: { verify: async () => true }, sequencePath: bad });
    const snap2 = await store2.loadSnapshot();
    assert.ok(snap2.lock instanceof LockError && snap2.lock.reason === "lock-signature-invalid");
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("the writer adds a manifest when the host requires or signs one, as the Python store does", async () => {
  for (const extra of [{ requireManifest: true }, { signer: { issuer: "i", san: "s" }, sequencePath: "/nonexistent/seq" }]) {
    const r = emptyRoot();
    try {
      const store = new FileLockStore({ root: r.root, ...extra });
      await store.approve({ identity: REMOTE, tool: { name: "a", inputSchema: { type: "object" } }, ...APPROVAL });
      const manifest = JSON.parse(readFileSync(join(r.root, ".mcp", "lock", "MANIFEST.json"), "utf8")) as { sequence: number };
      assert.equal(manifest.sequence, 1);
      const loaded = await loadLock(r.root, { requireManifest: true });
      assert.equal(loaded.lock.sequence, 1);
    } finally {
      r.done();
    }
  }
  const plain = emptyRoot();
  try {
    await new FileLockStore({ root: plain.root }).approve({
      identity: REMOTE,
      tool: { name: "a", inputSchema: { type: "object" } },
      ...APPROVAL,
    });
    assert.equal(existsSync(join(plain.root, ".mcp", "lock", "MANIFEST.json")), false);
  } finally {
    plain.done();
  }
});
