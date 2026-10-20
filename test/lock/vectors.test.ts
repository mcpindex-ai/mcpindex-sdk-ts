/**
 * mcp.lock draft 1 vectors, vendored from mcp-tool-pinning tag vectors-draft-1b
 * (1f38955) into test/fixtures/mcp-lock-vectors. SHA256SUMS is pinned below;
 * every vendored file must match it, so the vectors cannot drift silently.
 *
 * Each group counts its cases and the last test checks the total, so a vector
 * that is skipped by mistake fails the run.
 */

import assert from "node:assert/strict";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { canonicalize, toolDigest } from "../../src/lock/digest.js";
import {
  LockError,
  commandIdentity,
  formatLockFile,
  formatManifest,
  formatShard,
  identityH16,
  identityKey,
  loadLock,
  packageIdentity,
  parseShard,
  readLockDir,
  remoteIdentity,
  shardFilename,
  slug,
  strictJson,
  validateIdentity,
} from "../../src/lock/lock.js";
import type { Identity, Lock, Posture } from "../../src/lock/lock.js";
import { checkCall, checkListing } from "../../src/lock/check.js";

const ROOT = fileURLToPath(new URL("../../..", import.meta.url));
const VECTORS = join(ROOT, "test", "fixtures", "mcp-lock-vectors");
const SUMS_SHA256 = "cd2447cb03db6e89875b74a2f9ef017b5f72f54b8544c0c0dc64c3e18f3880cc";

const sha256 = (data: Buffer | string): string => createHash("sha256").update(data).digest("hex");
const readJson = (rel: string): unknown => JSON.parse(readFileSync(join(VECTORS, rel), "utf8"));

const counts = { tools: 0, raw: 0, identity: 0, lock: 0, contracts: 0 };

test("SHA256SUMS is the pinned vectors-draft-1b file and covers every vendored file", () => {
  const sums = readFileSync(join(VECTORS, "SHA256SUMS"));
  assert.equal(sha256(sums), SUMS_SHA256);
  const listed = new Map<string, string>();
  for (const line of sums.toString("utf8").split("\n")) {
    if (line === "") continue;
    listed.set(line.slice(66), line.slice(0, 64));
  }
  const onDisk: string[] = [];
  const walk = (dir: string, rel: string): void => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) walk(join(dir, e.name), r);
      else onDisk.push(r);
    }
  };
  walk(VECTORS, "");
  const files = onDisk.filter((f) => f !== "SHA256SUMS").sort();
  assert.deepEqual(files, [...listed.keys()].sort());
  for (const f of files) assert.equal(sha256(readFileSync(join(VECTORS, f))), listed.get(f), f);
});

test("tools.json: parsed tool digests", () => {
  const cases = readJson("tools.json") as Array<{ name: string; tool: unknown; expected: string | null }>;
  for (const c of cases) {
    // Round-trip through text so the tool is JSON.parse output, as on the wire.
    const tool = JSON.parse(JSON.stringify(c.tool)) as unknown;
    assert.equal(toolDigest(tool), c.expected, c.name);
    counts.tools++;
  }
  assert.equal(counts.tools, 42);
});

test("digest/*.json: raw text through JSON.parse", () => {
  const index = readJson("digest/index.json") as Record<string, { expected: string | null }>;
  for (const [name, { expected }] of Object.entries(index)) {
    const text = readFileSync(join(VECTORS, "digest", `${name}.json`)).toString("utf8");
    let got: string | null;
    try {
      got = toolDigest(JSON.parse(text));
    } catch {
      got = null; // not JSON (NaN, Infinity): no digest
    }
    assert.equal(got, expected, name);
    counts.raw++;
  }
  assert.equal(counts.raw, 45);
});

test("identity.json: normalization, key, h16, slug, filename", () => {
  const cases = readJson("identity.json") as Array<Record<string, unknown>>;
  for (const c of cases) {
    const given = c.input as Record<string, unknown>;
    const make = (): Identity => {
      if ("url" in given) return remoteIdentity(given.url as string);
      if ("registry" in given) return packageIdentity(given.registry as string, given.name as string);
      return commandIdentity(given.command as string, given.args as string[]);
    };
    if (c.error === true) {
      assert.throws(make, Error, String(c.name));
    } else {
      const identity = make();
      assert.deepEqual({ ...identity }, c.identity, String(c.name));
      assert.equal(identityKey(identity), c.key, String(c.name));
      assert.equal(identityH16(identity), c.h16, String(c.name));
      assert.equal(slug(identity), c.slug, String(c.name));
      assert.equal(shardFilename(identity), c.filename, String(c.name));
      // A normalized identity validates as a lock reader sees it.
      assert.deepEqual({ ...validateIdentity(c.identity) }, c.identity);
    }
    counts.identity++;
  }
  assert.equal(counts.identity, 29);
});

function materialize(name: string, tmp: string): string {
  const root = join(tmp, name);
  cpSync(join(VECTORS, "lock", name), root, { recursive: true });
  const setupPath = join(root, "setup.json");
  if (existsSync(setupPath)) {
    const setup = JSON.parse(readFileSync(setupPath, "utf8")) as {
      symlinks?: Array<{ path: string; target: string }>;
      files?: Array<{ path: string; text: string }>;
    };
    for (const link of setup.symlinks ?? []) {
      mkdirSync(dirname(join(root, link.path)), { recursive: true });
      symlinkSync(link.target, join(root, link.path));
    }
    for (const item of setup.files ?? []) {
      mkdirSync(dirname(join(root, item.path)), { recursive: true });
      writeFileSync(join(root, item.path), item.text, "utf8");
    }
  }
  return root;
}

async function runCase(root: string): Promise<Record<string, unknown>> {
  const config = JSON.parse(readFileSync(join(root, "config.json"), "utf8")) as Record<string, unknown>;
  const identity = JSON.parse(readFileSync(join(root, "server.json"), "utf8")) as Identity;
  let lock: Lock | LockError;
  try {
    lock = (
      await loadLock(root, {
        requireManifest: (config.requireManifest as boolean | undefined) ?? false,
        signer: (config.signer as { issuer: string; san: string } | undefined) ?? null,
        lastSequence: (config.lastSequence as number | undefined) ?? null,
        // No verifier: a configured signer must then fail closed.
      })
    ).lock;
  } catch (exc) {
    assert.ok(exc instanceof LockError, String(exc));
    lock = exc;
  }
  const expected = JSON.parse(readFileSync(join(root, "expected.json"), "utf8")) as { calls: Record<string, string> };
  const listingPath = join(root, "listing.json");
  const decision = existsSync(listingPath)
    ? checkListing(lock, identity, JSON.parse(readFileSync(listingPath, "utf8")), config.posture as Posture)
    : null;
  const calls: Record<string, string> = {};
  for (const name of Object.keys(expected.calls)) calls[name] = checkCall(decision, name);
  return {
    lockError: lock instanceof LockError ? lock.reason : null,
    shown: decision ? [...decision.shown] : [],
    withheld: decision ? Object.fromEntries(decision.withheld) : {},
    flagged: decision ? Object.fromEntries(decision.flagged) : {},
    removed: decision ? [...decision.removed] : [],
    instructions: decision ? decision.instructions : null,
    stripInstructions: decision ? decision.stripInstructions : false,
    calls,
  };
}

test("lock/*: every case gives the expected outcome", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mcplock-vectors-"));
  try {
    const names = readdirSync(join(VECTORS, "lock"), { withFileTypes: true })
      .filter((e) => e.isDirectory())
      .map((e) => e.name)
      .sort();
    for (const name of names) {
      const root = materialize(name, tmp);
      const expected = JSON.parse(readFileSync(join(root, "expected.json"), "utf8")) as unknown;
      assert.deepEqual(await runCase(root), expected, name);
      counts.lock++;
    }
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
  assert.equal(counts.lock, 46);
});

test("contract files are RFC 8785 text of themselves", () => {
  for (const name of readdirSync(join(VECTORS, "lock")).sort()) {
    const dir = join(VECTORS, "lock", name, ".mcp", "contracts");
    if (!existsSync(dir)) continue;
    for (const file of readdirSync(dir).sort()) {
      const text = readFileSync(join(dir, file), "utf8");
      assert.equal(canonicalize(JSON.parse(text)), text, `${name}/${file}`);
      counts.contracts++;
    }
  }
  assert.ok(counts.contracts > 0);
});

test("writer: re-formatting each well-formed vector shard, alias map and manifest gives the same bytes", () => {
  let shards = 0;
  let others = 0;
  for (const name of readdirSync(join(VECTORS, "lock")).sort()) {
    const lockDir = join(VECTORS, "lock", name, ".mcp", "lock");
    if (!existsSync(lockDir)) continue;
    let files: Map<string, Buffer>;
    try {
      files = readLockDir(lockDir);
    } catch {
      continue;
    }
    for (const [file, bytes] of files) {
      if (file === "MANIFEST.json") {
        let doc: { sequence: number; files: Record<string, string> };
        try {
          doc = strictJson(bytes, file) as { sequence: number; files: Record<string, string> };
        } catch {
          continue; // a manifest the reader refuses (sequence 1.0, 1e0) has no writer form
        }
        const listed = new Map<string, Buffer>();
        let complete = true;
        for (const f of Object.keys(doc.files)) {
          const b = files.get(f);
          if (b === undefined || "sha256:" + sha256(b) !== doc.files[f]) complete = false;
          else listed.set(f, b);
        }
        if (complete && listed.size === [...files.keys()].filter((f) => !f.startsWith("MANIFEST")).length) {
          assert.deepEqual(formatManifest(doc.sequence, listed), bytes, `${name}/${file}`);
          others++;
        }
        continue;
      }
      if (file === "aliases.json") {
        // The generic writer reproduces any lock file from its parsed form.
        assert.deepEqual(formatLockFile(toWriter(JSON.parse(bytes.toString("utf8")))), bytes, `${name}/${file}`);
        others++;
        continue;
      }
      let shard;
      try {
        shard = parseShard(file, bytes, (c) => {
          const p = join(VECTORS, "lock", name, ".mcp", "contracts", c);
          return existsSync(p) ? readFileSync(p) : null;
        });
      } catch {
        continue;
      }
      assert.deepEqual(formatShard(shard), bytes, `${name}/${file}`);
      shards++;
    }
  }
  assert.ok(shards >= 20, `only ${shards} shards round-tripped`);
  assert.ok(others >= 2, `only ${others} manifests or alias maps round-tripped`);
});

type W = null | boolean | number | string | W[] | { entries: Array<[string, W]> };
function toWriter(v: unknown): W {
  if (Array.isArray(v)) return v.map(toWriter);
  if (v !== null && typeof v === "object") {
    return { entries: Object.keys(v).map((k) => [k, toWriter((v as Record<string, unknown>)[k])] as [string, W]) };
  }
  return v as W;
}

test("vector totals", () => {
  // tools 42 + raw 45 + identity 29 + lock 46 = 162 decision vectors, plus contracts.
  assert.equal(counts.tools + counts.raw + counts.identity + counts.lock, 162);
});
