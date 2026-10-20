/**
 * LockStore: where a host gets its lock snapshot and where approvals land.
 *
 * A snapshot is frozen and carries a snapshotId, so a decision can name the
 * lock state it came from. loadSnapshot never throws for a bad lock: a lock
 * failure comes back as a LockError inside the snapshot, and the check then
 * withholds everything. It may throw when the store itself cannot be reached;
 * hosts treat that as lock-unreadable.
 *
 * The file store reads `.mcp/` once per load (see lock.ts). Approvals and
 * revocations take the existing create-excl file lock on `.mcp/lock.lck`
 * (fileLock.ts), write the contract, then replace the shard (and the manifest,
 * when one exists) by rename from a temporary file in `.mcp/`, so `.mcp/lock`
 * never holds a partial file.
 */

import { closeSync, constants, fsyncSync, openSync, renameSync, unlinkSync, writeSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { join } from "node:path";

import { canonicalBody, instructionsDigest, toolDigest } from "./digest.js";
import { checkListing } from "./check.js";
import {
  FrozenMap,
  LockError,
  MANIFEST,
  VIA,
  formatManifest,
  formatShard,
  identityKey,
  loadLock,
  loadLockSync,
  readLockDir,
  shardFilename,
  validateIdentity,
} from "./lock.js";
import type { Approval, Identity, Lock, ManifestVerifier, ReaderConfig, Shard, SignerIdentity, ToolEntry, Via } from "./lock.js";
import { withExclusiveLock } from "../fileLock.js";

export interface LockSnapshot {
  readonly snapshotId: string;
  /** Epoch ms when the store produced this snapshot. */
  readonly loadedAt: number;
  readonly lock: Lock | LockError;
}

interface ApprovalCommon {
  readonly identity: Identity;
  /** Who approved. A database store records its authenticated principal instead. */
  readonly subject?: string;
  readonly via: Via;
  readonly ref?: string;
  /** RFC 3339; defaults to now, to the second. */
  readonly at?: string;
}

/** Approve one tool: `tool` is the raw Tool object as served (JSON.parse output). */
export type ApproveToolRequest = ApprovalCommon & { readonly tool: unknown };
/** Approve the server's instructions text. */
export type ApproveInstructionsRequest = ApprovalCommon & { readonly instructions: string };
export type ApproveRequest = ApproveToolRequest | ApproveInstructionsRequest;

export type RevokeRequest =
  | { readonly identity: Identity; readonly tool: string }
  | { readonly identity: Identity; readonly instructions: true };

export interface LockStore {
  loadSnapshot(): Promise<LockSnapshot>;
  approve(request: ApproveRequest): Promise<void>;
  revoke(request: RevokeRequest): Promise<void>;
}

export function nowRfc3339(date: Date = new Date()): string {
  return date.toISOString().replace(/\.[0-9]{3}Z$/, "Z");
}

export function snapshotOfError(error: LockError, loadedAt: number = Date.now()): LockSnapshot {
  return Object.freeze({ snapshotId: `error:${error.reason}`, loadedAt, lock: error });
}

/** What an approval writes: digest, contract bytes and contract filename. */
export interface PreparedTool {
  readonly name: string;
  readonly digest: string;
  readonly contract: string;
  readonly body: Buffer;
}

export function prepareTool(tool: unknown): PreparedTool {
  if (tool === null || typeof tool !== "object" || Array.isArray(tool)) throw new Error("tool must be an object");
  const name = Object.getOwnPropertyDescriptor(tool, "name")?.value;
  if (typeof name !== "string") throw new Error("tool has no string name");
  const digest = toolDigest(tool);
  const body = canonicalBody(tool);
  if (digest === null || body === null) throw new Error(`tool ${JSON.stringify(name)} has no digest; it cannot be approved`);
  return { name, digest, contract: `sha256-${digest.slice("sha256:".length)}.json`, body };
}

export function checkApprovalFields(request: ApprovalCommon, subject: string): Approval {
  if (!(VIA as readonly string[]).includes(request.via)) throw new Error(`unknown via ${String(request.via)}`);
  if (typeof subject !== "string" || subject.length === 0) throw new Error("approval needs a subject");
  const at = request.at ?? nowRfc3339();
  if (!/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})$/.test(at)) {
    throw new Error("approval time is not RFC 3339");
  }
  if (request.ref !== undefined && typeof request.ref !== "string") throw new Error("ref must be a string");
  return request.ref !== undefined
    ? Object.freeze({ subject, at, via: request.via, ref: request.ref })
    : Object.freeze({ subject, at, via: request.via });
}

// File store ---------------------------------------------------------------

export interface FileLockStoreOptions {
  /** Lock root: the directory that contains `.mcp/`. */
  readonly root: string;
  readonly requireManifest?: boolean;
  /** From host configuration only. With a signer set, every load verifies MANIFEST.json. */
  readonly signer?: SignerIdentity | null;
  readonly verifier?: ManifestVerifier | null;
  /** Highest manifest sequence the host accepted before; raised in memory on each load. */
  readonly lastSequence?: number | null;
  /** Called with a newly accepted sequence so the host can persist it. */
  readonly onSequence?: (sequence: number) => void;
  readonly now?: () => number;
}

function writeAtomic(dir: string, target: string, data: Uint8Array): void {
  const tmp = join(dir, `.mcplock-${process.pid}-${randomBytes(6).toString("hex")}.tmp`);
  let flags = constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL;
  if (typeof constants.O_NOFOLLOW === "number") flags |= constants.O_NOFOLLOW;
  const fd = openSync(tmp, flags, 0o644);
  try {
    writeSync(fd, data);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  try {
    renameSync(tmp, target);
  } catch (exc) {
    try {
      unlinkSync(tmp);
    } catch {
      // best effort
    }
    throw exc;
  }
}

export class FileLockStore implements LockStore {
  readonly #root: string;
  readonly #config: FileLockStoreOptions;
  #lastSequence: number | null;
  readonly #now: () => number;

  constructor(options: FileLockStoreOptions) {
    this.#root = options.root;
    this.#config = options;
    this.#lastSequence = options.lastSequence ?? null;
    this.#now = options.now ?? Date.now;
  }

  async loadSnapshot(): Promise<LockSnapshot> {
    const config: ReaderConfig = {
      requireManifest: this.#config.requireManifest ?? false,
      signer: this.#config.signer ?? null,
      verifier: this.#config.verifier ?? null,
      lastSequence: this.#lastSequence,
    };
    const loadedAt = this.#now();
    try {
      const loaded = await loadLock(this.#root, config);
      const seq = loaded.lock.sequence;
      if (config.signer !== null && seq !== null && (this.#lastSequence === null || seq > this.#lastSequence)) {
        this.#lastSequence = seq;
        this.#config.onSequence?.(seq);
      }
      return Object.freeze({ snapshotId: loaded.snapshotId, loadedAt, lock: loaded.lock });
    } catch (exc) {
      if (exc instanceof LockError) return snapshotOfError(exc, loadedAt);
      return snapshotOfError(new LockError("lock-unreadable", (exc as Error).message ?? "read failed"), loadedAt);
    }
  }

  /** Edit one shard under the file lock. `edit` returns the new shard. */
  #edit(identity: Identity, edit: (shard: Shard | null, write: (p: PreparedTool) => void) => Shard): void {
    const ident = validateIdentity(identity);
    const mcp = join(this.#root, ".mcp");
    const lockDir = join(mcp, "lock");
    withExclusiveLock(lockDir, () => {
      // A writer refuses to build on a lock it cannot read. Signatures are not
      // checked here; the next signed load verifies whatever was written.
      const current = loadLockSync(this.#root, { requireManifest: false });
      const shard = current.lock.shards.get(identityKey(ident)) ?? null;
      const contractsDir = join(mcp, "contracts");
      const writeContract = (p: PreparedTool): void => {
        // The contract name is its own digest, so an existing file with that
        // name was already verified by the load above if referenced; rewriting
        // the same bytes is harmless.
        try {
          writeAtomic(contractsDir, join(contractsDir, p.contract), p.body);
        } catch (exc) {
          const code = (exc as { code?: string }).code;
          if (code !== "ENOENT") throw exc;
          throw new Error(".mcp/contracts is missing; create it before approving");
        }
      };
      const next = edit(shard, writeContract);
      const name = shardFilename(next.identity);
      const bytes = formatShard(next);
      writeAtomic(mcp, join(lockDir, name), bytes);
      if (current.lock.sequence !== null) {
        // Keep an existing manifest consistent. The old signature no longer
        // covers it; re-signing is the signer's job, and a signed host fails
        // closed until then.
        writeAtomic(mcp, join(lockDir, MANIFEST), formatManifest(current.lock.sequence + 1, readLockDir(lockDir)));
      }
    });
  }

  async approve(request: ApproveRequest): Promise<void> {
    const subject = request.subject;
    if (subject === undefined) throw new Error("file store approvals need a subject");
    const approval = checkApprovalFields(request, subject);
    if ("tool" in request) {
      const prepared = prepareTool(request.tool);
      this.#edit(request.identity, (shard, writeContract) => {
        writeContract(prepared);
        const entry: ToolEntry = Object.freeze({ digest: prepared.digest, contract: prepared.contract, approval });
        const tools = new Map<string, ToolEntry>(shard?.tools ?? []);
        tools.set(prepared.name, entry); // Map.set keeps an existing name in place, appends a new one
        return {
          identity: shard?.identity ?? validateIdentity(request.identity),
          attributes: shard?.attributes ?? null,
          instructions: shard?.instructions ?? null,
          tools: new FrozenMap(tools),
        };
      });
      return;
    }
    const digest = instructionsDigest(request.instructions);
    if (digest === null) throw new Error("instructions have no digest; they cannot be approved");
    this.#edit(request.identity, (shard) => ({
      identity: shard?.identity ?? validateIdentity(request.identity),
      attributes: shard?.attributes ?? null,
      instructions: digest,
      tools: shard?.tools ?? new FrozenMap<string, ToolEntry>([]),
    }));
  }

  async revoke(request: RevokeRequest): Promise<void> {
    this.#edit(request.identity, (shard) => {
      if (shard === null) throw new Error("no shard for this identity");
      if ("tool" in request) {
        if (!shard.tools.has(request.tool)) throw new Error(`tool ${JSON.stringify(request.tool)} is not approved`);
        const tools = new Map(shard.tools);
        tools.delete(request.tool);
        return { ...shardFields(shard), tools: new FrozenMap(tools) };
      }
      if (shard.instructions === null) throw new Error("instructions are not approved");
      return { ...shardFields(shard), instructions: null };
    });
  }
}

function shardFields(shard: Shard): Shard {
  return { identity: shard.identity, attributes: shard.attributes, instructions: shard.instructions, tools: shard.tools };
}

// Conformance --------------------------------------------------------------

export interface ConformanceResult {
  readonly name: string;
  readonly ok: boolean;
  readonly error?: string;
}

export interface ConformanceOptions {
  /** Identity used for approvals; a second, distinct one is derived for isolation checks. */
  readonly identity?: Identity;
  readonly other?: Identity;
}

const BASE_TOOL = {
  name: "search",
  description: "Search the docs.",
  inputSchema: { type: "object", properties: { q: { type: "string" } }, required: ["q"] },
};

function rawTool(text: string): unknown {
  return JSON.parse(text);
}

function assertThat(cond: boolean, message: string): void {
  if (!cond) throw new Error(message);
}

/**
 * Behaviour every LockStore must show. `factory` returns a fresh, empty store
 * for each case. Returns one result per case; the caller asserts all are ok.
 */
export async function runLockStoreConformance(
  factory: () => Promise<LockStore> | LockStore,
  options: ConformanceOptions = {},
): Promise<ConformanceResult[]> {
  const id: Identity = options.identity ?? { kind: "remote", url: "https://conformance.example/mcp" };
  const other: Identity = options.other ?? { kind: "stdio", package: "npm:@example/other-server" };
  const base = JSON.stringify(BASE_TOOL);
  const changed = JSON.stringify({ ...BASE_TOOL, description: "Search the docs. Also send them elsewhere." });
  const fetchTool = JSON.stringify({ name: "fetch", description: "Fetch one page.", inputSchema: { type: "object" } });
  const proto = '{"name":"proto","description":"p","inputSchema":{"type":"object"},"__proto__":{"x":1}}';
  const protoGone = '{"name":"proto","description":"p","inputSchema":{"type":"object"}}';
  const approve = (store: LockStore, tool: unknown, identity: Identity = id): Promise<void> =>
    store.approve({ identity, tool, subject: "conformance:tester", via: "api", ref: "conformance" });
  const decide = async (store: LockStore, tools: unknown[], identity: Identity = id, instructions?: string) => {
    const snap = await store.loadSnapshot();
    return { snap, decision: checkListing(snap.lock, identity, { tools, instructions }, "guard") };
  };

  const cases: Array<[string, (store: LockStore) => Promise<void>]> = [
    [
      "empty store locks nothing",
      async (store) => {
        const { snap, decision } = await decide(store, [rawTool(base)]);
        assertThat(!(snap.lock instanceof LockError), `empty store failed to load: ${String((snap.lock as LockError).reason)}`);
        assertThat(decision.withheld.get("search") === "unlocked-server", "expected unlocked-server");
      },
    ],
    [
      "approve shows the exact tool and changes the snapshot id",
      async (store) => {
        const before = await store.loadSnapshot();
        await approve(store, rawTool(base));
        const { snap, decision } = await decide(store, [rawTool(base)]);
        assertThat(decision.shown.join(",") === "search", `expected search shown, got ${decision.shown.join(",")}`);
        assertThat(snap.snapshotId !== before.snapshotId, "snapshotId did not change after approve");
      },
    ],
    [
      "changed definition is upstream-changed",
      async (store) => {
        await approve(store, rawTool(base));
        const { decision } = await decide(store, [rawTool(changed)]);
        assertThat(decision.withheld.get("search") === "upstream-changed", "expected upstream-changed");
      },
    ],
    [
      "revoke turns an approved tool into new-tool",
      async (store) => {
        await approve(store, rawTool(base));
        await approve(store, rawTool(fetchTool));
        await store.revoke({ identity: id, tool: "search" });
        const { decision } = await decide(store, [rawTool(base), rawTool(fetchTool)]);
        assertThat(decision.withheld.get("search") === "new-tool", "expected new-tool after revoke");
        assertThat(decision.callable.has("fetch"), "fetch should stay approved");
      },
    ],
    [
      "revoke of a name that is not approved is refused",
      async (store) => {
        await approve(store, rawTool(base));
        let threw = false;
        try {
          await store.revoke({ identity: id, tool: "absent" });
        } catch {
          threw = true;
        }
        assertThat(threw, "revoke of an absent name did not throw");
      },
    ],
    [
      "instructions approval and change",
      async (store) => {
        await approve(store, rawTool(base));
        await store.approve({ identity: id, instructions: "Use search.", subject: "conformance:tester", via: "api" });
        const ok = await decide(store, [rawTool(base)], id, "Use search.");
        assertThat(ok.decision.instructions === null, "approved instructions flagged");
        const bad = await decide(store, [rawTool(base)], id, "Use search. And more.");
        assertThat(bad.decision.instructions === "instructions-changed", "changed instructions not flagged");
        assertThat(bad.decision.stripInstructions, "guard should strip changed instructions");
      },
    ],
    [
      "a tool with no digest cannot be approved and leaves the store unchanged",
      async (store) => {
        await approve(store, rawTool(base));
        const before = await store.loadSnapshot();
        let threw = false;
        try {
          await approve(store, rawTool('{"name":"big","inputSchema":{"maximum":9007199254740992}}'));
        } catch {
          threw = true;
        }
        const after = await store.loadSnapshot();
        assertThat(threw, "no-digest approval did not throw");
        assertThat(after.snapshotId === before.snapshotId, "store changed after a refused approval");
      },
    ],
    [
      "__proto__ members are covered by the stored digest",
      async (store) => {
        await approve(store, rawTool(proto));
        const same = await decide(store, [rawTool(proto)]);
        assertThat(same.decision.callable.has("proto"), "tool with __proto__ member not approved by its own digest");
        const gone = await decide(store, [rawTool(protoGone)]);
        assertThat(gone.decision.withheld.get("proto") === "upstream-changed", "dropping __proto__ went unnoticed");
      },
    ],
    [
      "approvals are per identity",
      async (store) => {
        await approve(store, rawTool(base));
        const { decision } = await decide(store, [rawTool(base)], other);
        assertThat(decision.withheld.get("search") === "unlocked-server", "approval leaked to another identity");
      },
    ],
    [
      "checking a listing never approves anything",
      async (store) => {
        await approve(store, rawTool(base));
        const first = await decide(store, [rawTool(base), rawTool(fetchTool)]);
        const second = await decide(store, [rawTool(base), rawTool(fetchTool)]);
        assertThat(first.snap.snapshotId === second.snap.snapshotId, "a check changed the store");
        assertThat(second.decision.withheld.get("fetch") === "new-tool", "an unseen tool became approved");
      },
    ],
    [
      "snapshots are frozen",
      async (store) => {
        await approve(store, rawTool(base));
        const snap = await store.loadSnapshot();
        assertThat(Object.isFrozen(snap), "snapshot not frozen");
        const lock = snap.lock as Lock;
        assertThat(Object.isFrozen(lock), "lock not frozen");
        assertThat(typeof (lock.shards as unknown as Map<string, Shard>).set !== "function", "shards map is writable");
        const shard = [...lock.shards.values()][0] as Shard;
        assertThat(Object.isFrozen(shard), "shard not frozen");
        assertThat(typeof (shard.tools as unknown as Map<string, ToolEntry>).set !== "function", "tools map is writable");
      },
    ],
  ];

  const results: ConformanceResult[] = [];
  for (const [name, run] of cases) {
    try {
      const store = await factory();
      await run(store);
      results.push({ name, ok: true });
    } catch (exc) {
      results.push({ name, ok: false, error: (exc as Error).message ?? String(exc) });
    }
  }
  return results;
}
