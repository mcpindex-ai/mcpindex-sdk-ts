/**
 * mcp.lock draft 1 revision 1e vectors, vendored from mcp-tool-pinning tag
 * vectors-draft-1e (79151a5) into test/fixtures/mcp-lock-vectors with
 * `git archive vectors-draft-1e vectors`. SHA256SUMS is pinned below; every
 * vendored file must match it, so the vectors cannot drift silently.
 *
 * Lock cases load through FileLockStore with the case's host config, and their
 * listing event is compared member by member except id, time and snapshotId.
 * Session cases (session.json) drive a LockedTransport over a scripted server,
 * so the adapter itself is what answers each call and each server frame.
 * Frame cases run classifyFrame with the pending requests' methods. Host
 * config cases run hostPathProblem and the FileLockStore constructor.
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
import { HANDSHAKE_METHODS, LockedTransport, classifyFrame, idMatches } from "../../src/lock/rawList.js";
import type { FrameKind } from "../../src/lock/rawList.js";
import { listingEvent } from "../../src/lock/events.js";
import { FileLockStore, HostConfigError, hostPathProblem } from "../../src/lock/store.js";
import type { SequenceStore } from "../../src/lock/store.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";

const ROOT = fileURLToPath(new URL("../../..", import.meta.url));
const VECTORS = join(ROOT, "test", "fixtures", "mcp-lock-vectors");
const SUMS_SHA256 = "72bc7f1beb2d52e24f3b2782a11a808af71d4c8f0271dda3c6885fd1bb4796f5";

const sha256 = (data: Buffer | string): string => createHash("sha256").update(data).digest("hex");
const readJson = (rel: string): unknown => JSON.parse(readFileSync(join(VECTORS, rel), "utf8"));

const counts = { tools: 0, raw: 0, identity: 0, lock: 0, sessions: 0, frames: 0, host: 0, contracts: 0 };

test("SHA256SUMS is the pinned vectors-draft-1e file and covers every vendored file", () => {
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
  assert.equal(counts.raw, 48);
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

interface CaseConfig {
  posture: Posture;
  host: string;
  requireManifest?: boolean;
  signer?: { issuer: string; san: string };
  sequenceStore?: boolean;
  lastSequence?: number;
  maxStaleness?: number;
  testVerifier?: "accept-any";
}

/** The case's host config as a FileLockStore. `clock` is read for loadedAt. */
function storeFor(root: string, config: CaseConfig, clock: () => number): FileLockStore {
  let stored: number | null = config.lastSequence ?? null;
  const sequenceStore: SequenceStore | undefined =
    config.sequenceStore === true
      ? {
          read: () => stored,
          write: (n: number) => {
            stored = n;
          },
        }
      : undefined;
  return new FileLockStore({
    root,
    requireManifest: config.requireManifest ?? false,
    signer: config.signer ?? null,
    // accept-any exists only in test runners; without it a signer fails closed.
    verifier: config.testVerifier === "accept-any" ? { verify: async () => true } : null,
    ...(sequenceStore !== undefined ? { sequenceStore } : {}),
    now: clock,
  });
}

async function runCase(root: string): Promise<Record<string, unknown>> {
  const config = JSON.parse(readFileSync(join(root, "config.json"), "utf8")) as CaseConfig;
  const identity = JSON.parse(readFileSync(join(root, "server.json"), "utf8")) as Identity;
  const snapshot = await storeFor(root, config, () => 0).loadSnapshot();
  const lock: Lock | LockError = snapshot.lock;
  const expected = JSON.parse(readFileSync(join(root, "expected.json"), "utf8")) as { calls: Record<string, string> };
  const listingPath = join(root, "listing.json");
  const decision = existsSync(listingPath)
    ? checkListing(lock, identity, JSON.parse(readFileSync(listingPath, "utf8")), config.posture)
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
    meta: decision ? Object.fromEntries([...decision.meta].map(([k, v]) => [k, { relay: v.relay, flag: v.flag }])) : {},
    event: decision ? comparable(listingEvent({ host: config.host, identity }, decision, snapshot.snapshotId)) : null,
  };
}

/** A listing event without the members the vectors leave out: id, time and snapshotId. */
function comparable(event: object): Record<string, unknown> {
  const { id: _id, time: _time, snapshotId: _snapshot, ...rest } = event as Record<string, unknown>;
  return JSON.parse(JSON.stringify(rest)) as Record<string, unknown>;
}

/** A server that answers only when a session step tells it to. */
class ScriptedServer implements Transport {
  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: <T extends JSONRPCMessage>(message: T) => void;
  readonly sent: Array<Record<string, unknown>> = [];
  async start(): Promise<void> {}
  async send(m: JSONRPCMessage): Promise<void> {
    this.sent.push(m as unknown as Record<string, unknown>);
  }
  async close(): Promise<void> {}
  frame(message: Record<string, unknown>): void {
    this.onmessage?.(message as unknown as JSONRPCMessage);
  }
}

type Step = {
  op: string;
  id?: string | number;
  method?: string;
  frame?: unknown;
  errorTo?: string | number | null;
  listing?: string;
  advance?: number;
  path?: string;
  text?: string;
  tool?: string;
  expect?: string;
};

/** Run session.json against a LockedTransport. Returns every call whose verdict differs. */
async function runSession(root: string): Promise<string[]> {
  const config = JSON.parse(readFileSync(join(root, "config.json"), "utf8")) as CaseConfig;
  const identity = JSON.parse(readFileSync(join(root, "server.json"), "utf8")) as Identity;
  const { steps } = JSON.parse(readFileSync(join(root, "session.json"), "utf8")) as { steps: Step[] };
  let clock = 0;
  const server = new ScriptedServer();
  const locked = new LockedTransport(server, {
    store: storeFor(root, config, () => clock),
    identity,
    posture: config.posture,
    ...(config.maxStaleness !== undefined ? { maxStalenessMs: config.maxStaleness * 1000 } : {}),
    now: () => clock,
  });
  const delivered = new Map<unknown, Record<string, unknown>>();
  const waiters = new Map<unknown, () => void>();
  const log: Array<Record<string, unknown>> = [];
  const errors: Error[] = [];
  locked.onmessage = (m) => {
    const msg = m as unknown as Record<string, unknown>;
    log.push(msg);
    delivered.set(msg.id, msg);
    waiters.get(msg.id)?.();
  };
  locked.onerror = (e) => errors.push(e);
  const answered = (id: unknown): Promise<void> =>
    delivered.has(id) ? Promise.resolve() : new Promise<void>((res) => waiters.set(id, res));
  await locked.start();
  let seq = 0;
  let listId: string | number | null = null;
  const mismatches: string[] = [];
  for (const [index, step] of steps.entries()) {
    if (step.op === "list-start") {
      listId = step.id ?? `list-${++seq}`;
      await locked.send({ jsonrpc: "2.0", id: listId, method: "tools/list" } as JSONRPCMessage);
    } else if (step.op === "request") {
      await locked.send({ jsonrpc: "2.0", id: step.id as string | number, method: step.method as string } as JSONRPCMessage);
    } else if (step.op === "frame") {
      // What the client sees for this frame: nothing, the frame itself, or an error under errorTo.
      const before = log.length;
      const errorsBefore = errors.length;
      server.frame(step.frame as Record<string, unknown>);
      await new Promise((res) => setImmediate(res));
      const out = log.slice(before);
      const dropped = errors.length > errorsBefore && out.every((m) => m.error !== undefined);
      // A relayed frame reaches the client as sent; a handshake answer may lose its instructions.
      const passed = out.length === 1 && out[0]?.error === undefined;
      const got = dropped ? "drop" : passed && JSON.stringify(out[0]) === JSON.stringify(step.frame) ? "relay" : passed ? "handshake" : "?";
      const want = step.expect === "handshake" && got === "relay" ? "relay" : step.expect;
      if (got !== want) mismatches.push(`step ${index}: frame gave ${got}, expected ${String(step.expect)}`);
      const errorTo = out.filter((m) => m.error !== undefined).map((m) => m.id);
      const wantErrorTo = step.errorTo === null || step.errorTo === undefined ? [] : [step.errorTo];
      if (JSON.stringify(errorTo) !== JSON.stringify(wantErrorTo)) {
        mismatches.push(`step ${index}: frame answered ${JSON.stringify(errorTo)}, expected ${JSON.stringify(wantErrorTo)}`);
      }
    } else if (step.op === "list-complete" || step.op === "list-fail") {
      assert.ok(listId !== null, `step ${index}: no listing started`);
      const id = listId;
      if (step.op === "list-complete") {
        const listing = JSON.parse(readFileSync(join(root, step.listing as string), "utf8")) as { tools: unknown[] };
        server.frame({ jsonrpc: "2.0", id, result: { tools: listing.tools } });
      } else {
        server.frame({ jsonrpc: "2.0", id, error: { code: -32603, message: "listing failed" } });
      }
      await answered(id);
    } else if (step.op === "list-changed") {
      server.frame({ jsonrpc: "2.0", method: "notifications/tools/list_changed" });
      await new Promise((res) => setImmediate(res));
    } else if (step.op === "clock") {
      clock += (step.advance as number) * 1000;
    } else if (step.op === "write") {
      writeFileSync(join(root, step.path as string), step.text as string, "utf8");
    } else if (step.op === "call") {
      const id = `call-${++seq}`;
      const before = server.sent.length;
      await locked.send({ jsonrpc: "2.0", id, method: "tools/call", params: { name: step.tool, arguments: {} } } as JSONRPCMessage);
      let got: string;
      if (server.sent.length > before && server.sent[server.sent.length - 1]?.id === id) {
        got = "allow";
      } else {
        await answered(id);
        got = String(((delivered.get(id)?.error as { data?: { reason?: string } } | undefined)?.data?.reason) ?? "?");
      }
      if (got !== step.expect) mismatches.push(`step ${index}: call ${String(step.tool)} gave ${got}, expected ${String(step.expect)}`);
    } else {
      throw new Error(`unknown session op ${step.op}`);
    }
  }
  return mismatches;
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
      if (existsSync(join(root, "session.json"))) {
        assert.deepEqual(await runSession(root), [], name);
        counts.sessions++;
      }
      counts.lock++;
    }
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
  assert.equal(counts.lock, 61);
  assert.equal(counts.sessions, 6);
});

test("frames.json: what the adapter does with each server frame (section 9.2.2)", () => {
  const cases = readJson("frames.json") as Array<{
    name: string;
    pending: Array<{ id: unknown; method: string }>;
    frame: unknown;
    expect: FrameKind;
  }>;
  for (const c of cases) {
    const inflight = c.pending.filter((p) => p.method === "tools/list").map((p) => p.id);
    const handshake = c.pending.filter((p) => HANDSHAKE_METHODS.includes(p.method)).map((p) => p.id);
    const got = classifyFrame(
      c.frame,
      (id) => idMatches(id, inflight),
      (id) => idMatches(id, handshake),
    );
    assert.equal(got, c.expect, c.name);
    counts.frames++;
  }
  assert.equal(counts.frames, 25);
});

test("host-config.json: sequencePath and trustedRoot outside the lock's repository (section 8.2)", () => {
  const cases = readJson("host-config.json") as Array<{
    name: string;
    dirs?: string[];
    files?: string[];
    texts?: Array<{ path: string; text: string }>;
    symlinks?: Array<{ path: string; target: string }>;
    lockRoot: string;
    sequencePath?: string;
    trustedRoot?: string;
    expect: "accept" | "refuse";
  }>;
  for (const c of cases) {
    const base = mkdtempSync(join(tmpdir(), "mcplock-host-"));
    try {
      for (const d of c.dirs ?? []) mkdirSync(join(base, d), { recursive: true });
      for (const f of c.files ?? []) {
        mkdirSync(dirname(join(base, f)), { recursive: true });
        writeFileSync(join(base, f), "");
      }
      for (const t of c.texts ?? []) {
        mkdirSync(dirname(join(base, t.path)), { recursive: true });
        writeFileSync(join(base, t.path), t.text);
      }
      for (const l of c.symlinks ?? []) {
        mkdirSync(dirname(join(base, l.path)), { recursive: true });
        symlinkSync(l.target, join(base, l.path));
      }
      const root = join(base, c.lockRoot);
      // Joined as strings, not with join(): some cases hold a `..` the system must resolve.
      const sequencePath = c.sequencePath === undefined ? undefined : `${base}/${c.sequencePath}`;
      const trustedRootPath = c.trustedRoot === undefined ? undefined : `${base}/${c.trustedRoot}`;
      const problem = hostPathProblem(root, { sequencePath, trustedRootPath });
      assert.equal(problem === null ? "accept" : "refuse", c.expect, `${c.name}: ${String(problem)}`);
      // The file store applies the same rule when it is constructed.
      const make = (): FileLockStore =>
        new FileLockStore({
          root,
          ...(sequencePath !== undefined ? { sequencePath } : {}),
          ...(trustedRootPath !== undefined ? { trustedRootPath } : {}),
        });
      if (c.expect === "refuse") assert.throws(make, HostConfigError, c.name);
      else make();
    } finally {
      rmSync(base, { recursive: true, force: true });
    }
    counts.host++;
  }
  assert.equal(counts.host, 14);
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
  // tools 42 + raw 48 + identity 29 + lock 61 + frames 25 + host 14 = 219 vectors
  // (6 of the lock cases also run a session), plus contracts.
  assert.equal(counts.tools + counts.raw + counts.identity + counts.lock + counts.frames + counts.host, 219);
});
