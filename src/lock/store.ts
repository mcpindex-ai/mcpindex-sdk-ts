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

import { closeSync, constants, fsyncSync, lstatSync, openSync, readFileSync, realpathSync, renameSync, unlinkSync, writeSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

import { canonicalBody, instructionsDigest, metaDigest, toolDigest } from "./digest.js";
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
import { sigstoreVerifier } from "./signing.js";

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
  /** Digest of the served top-level `_meta`, when the tool has one with a digest. */
  readonly metaDigest: string | null;
}

export function prepareTool(tool: unknown): PreparedTool {
  if (tool === null || typeof tool !== "object" || Array.isArray(tool)) throw new Error("tool must be an object");
  const name = Object.getOwnPropertyDescriptor(tool, "name")?.value;
  if (typeof name !== "string") throw new Error("tool has no string name");
  const digest = toolDigest(tool);
  const body = canonicalBody(tool);
  if (digest === null || body === null) throw new Error(`tool ${JSON.stringify(name)} has no digest; it cannot be approved`);
  return { name, digest, contract: `sha256-${digest.slice("sha256:".length)}.json`, body, metaDigest: metaDigest(tool) };
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

// Sequence store -----------------------------------------------------------

/**
 * Where a host keeps the highest manifest (or head) sequence it accepted, so
 * a rollback is refused across restarts (section 8.2 step 3). `read` returns
 * null when nothing was recorded yet and throws when the record is unusable.
 */
export interface SequenceStore {
  read(): number | null;
  write(sequence: number): void;
}

/**
 * A host-owned file holding the sequence as ASCII digits and a newline, the
 * format the Python host writes to its sequence_path. A missing file is no
 * record; a file that is not a regular file or does not hold digits throws.
 */
export function fileSequenceStore(path: string): SequenceStore {
  const full = resolve(path);
  return {
    read(): number | null {
      let st;
      try {
        st = lstatSync(full);
      } catch (exc) {
        if ((exc as { code?: string }).code === "ENOENT") return null;
        throw new Error("last accepted sequence is unreadable");
      }
      if (!st.isFile()) throw new Error("last accepted sequence is not a regular file");
      let raw: Buffer;
      try {
        raw = readFileSync(full);
      } catch {
        throw new Error("last accepted sequence is unreadable");
      }
      if (raw.some((b) => b > 0x7f)) throw new Error("last accepted sequence is unreadable");
      const text = raw.toString("latin1").trim();
      if (!/^[0-9]+$/.test(text)) throw new Error("last accepted sequence is not an integer");
      const n = Number(text);
      if (!Number.isSafeInteger(n)) throw new Error("last accepted sequence is not an integer");
      return n;
    },
    write(sequence: number): void {
      writeAtomic(dirname(full), full, Buffer.from(`${sequence}\n`, "ascii"), basename(full));
    },
  };
}

// Host configuration paths ---------------------------------------------------

/** A host configuration the host must not run with. Thrown when a store is constructed. */
export class HostConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "HostConfigError";
  }
}

function exists(path: string): boolean {
  try {
    lstatSync(path);
    return true;
  } catch {
    return false;
  }
}

/** realpath of the nearest existing ancestor, with the rest of the path appended. */
function resolvedPath(path: string): string {
  const rest: string[] = [];
  let probe = resolve(path);
  while (!exists(probe) && dirname(probe) !== probe) {
    rest.unshift(basename(probe));
    probe = dirname(probe);
  }
  let real: string;
  try {
    real = realpathSync(probe);
  } catch {
    real = probe;
  }
  return rest.length === 0 ? real : join(real, ...rest);
}

function within(path: string, root: string): boolean {
  const rel = relative(root, path);
  return rel === "" || (rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
}

/**
 * The repository that holds the lock (section 8.2): the nearest directory at
 * or above the lock root with a `.git` entry (a directory, or a file as in a
 * worktree), else the lock root. Returned resolved.
 */
export function repositoryRoot(lockRoot: string): string {
  const start = resolvedPath(lockRoot);
  for (let dir = start; ; dir = dirname(dir)) {
    if (exists(join(dir, ".git"))) return dir;
    if (dirname(dir) === dir) return start;
  }
}

/**
 * Null if every named host path lies outside the repository that holds the
 * lock, else what is wrong. Each path is checked as given (made absolute) and
 * resolved, against the repository root as found and the lock root as given.
 */
export function hostPathProblem(lockRoot: string, paths: Readonly<Record<string, string | null | undefined>>): string | null {
  const repo = repositoryRoot(lockRoot);
  const roots = [repo, resolve(lockRoot)];
  for (const [key, value] of Object.entries(paths)) {
    if (value === null || value === undefined) continue;
    const given = resolve(value);
    for (const candidate of [given, resolvedPath(given)]) {
      if (roots.some((root) => within(candidate, root))) {
        return `${key} lies inside the repository that holds the lock (${repo}); whoever writes the lock could choose it`;
      }
    }
  }
  return null;
}

// File store ---------------------------------------------------------------

export interface FileLockStoreOptions {
  /** Lock root: the directory that contains `.mcp/`. */
  readonly root: string;
  readonly requireManifest?: boolean;
  /**
   * From host configuration only. With a signer set, every load verifies
   * MANIFEST.json, and the host must also name a sequence store
   * (sequencePath or sequenceStore); without one every load is
   * lock-signature-invalid.
   */
  readonly signer?: SignerIdentity | null;
  readonly verifier?: ManifestVerifier | null;
  /**
   * Sigstore trusted_root.json from host configuration. Without `verifier`,
   * the store verifies with sigstoreVerifier over this file. It must lie
   * outside the repository that holds the lock (section 8.2).
   */
  readonly trustedRootPath?: string;
  /**
   * Host-owned file for the last accepted sequence (see fileSequenceStore).
   * It must lie outside the repository that holds the lock.
   */
  readonly sequencePath?: string;
  /** Or any other place the host keeps it. Takes precedence over sequencePath. */
  readonly sequenceStore?: SequenceStore;
  readonly now?: () => number;
}

function writeAtomic(dir: string, target: string, data: Uint8Array, prefix = ""): void {
  const tmp = join(dir, `.${prefix}mcplock-${process.pid}-${randomBytes(6).toString("hex")}.tmp`);
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

/** The higher of two sequence floors; null only when both are. */
export function sequenceFloor(a: number | null, b: number | null): number | null {
  if (a === null) return b;
  if (b === null) return a;
  return Math.max(a, b);
}

export class FileLockStore implements LockStore {
  readonly #root: string;
  readonly #config: FileLockStoreOptions;
  readonly #sequences: SequenceStore | null;
  /** In-memory floor for this store instance; never lowered. */
  #lastSequence: number | null = null;
  readonly #now: () => number;
  readonly #verifier: ManifestVerifier | null;

  /** Throws HostConfigError when sequencePath or trustedRootPath lies inside the lock's repository. */
  constructor(options: FileLockStoreOptions) {
    const problem = hostPathProblem(options.root, {
      sequencePath: options.sequencePath,
      trustedRootPath: options.trustedRootPath,
    });
    if (problem !== null) throw new HostConfigError(problem);
    this.#root = options.root;
    this.#config = options;
    this.#sequences =
      options.sequenceStore ?? (options.sequencePath !== undefined ? fileSequenceStore(options.sequencePath) : null);
    this.#verifier =
      options.verifier ?? (options.trustedRootPath !== undefined ? sigstoreVerifier({ trustedRootPath: options.trustedRootPath }) : null);
    this.#now = options.now ?? Date.now;
  }

  async loadSnapshot(): Promise<LockSnapshot> {
    const signer = this.#config.signer ?? null;
    const loadedAt = this.#now();
    try {
      let last: number | null = null;
      if (signer !== null) {
        if (this.#sequences === null) {
          throw new LockError(
            "lock-signature-invalid",
            "a signer is configured but the host config names no sequence store (sequencePath); rollback cannot be refused",
          );
        }
        let stored: number | null;
        try {
          stored = this.#sequences.read();
        } catch (exc) {
          throw new LockError("lock-signature-invalid", (exc as Error).message ?? "last accepted sequence is unreadable");
        }
        last = sequenceFloor(stored, this.#lastSequence);
      }
      const config: ReaderConfig = {
        requireManifest: this.#config.requireManifest ?? false,
        signer,
        sequenceStore: this.#sequences !== null,
        verifier: this.#verifier,
        lastSequence: last,
      };
      const loaded = await loadLock(this.#root, config);
      const seq = loaded.lock.sequence;
      if (signer !== null && seq !== null && (last === null || seq > last)) {
        this.#lastSequence = seq;
        try {
          this.#sequences?.write(seq);
        } catch {
          // As in the Python host: not recording the new floor weakens rollback
          // protection on the next start; the in-memory floor still holds, and
          // this load is no less trustworthy.
        }
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
      const signer = this.#config.signer ?? null;
      if (current.lock.sequence !== null || this.#config.requireManifest === true || signer !== null) {
        // Same rule as the Python store: write a manifest when one exists or
        // the host requires or signs one. The old signature no longer covers
        // it; re-signing is the signer's job, and a signed host fails closed
        // until then.
        const sequence = current.lock.sequence === null ? 1 : current.lock.sequence + 1;
        writeAtomic(mcp, join(lockDir, MANIFEST), formatManifest(sequence, readLockDir(lockDir)));
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
        const entry: ToolEntry =
          prepared.metaDigest === null
            ? Object.freeze({ digest: prepared.digest, contract: prepared.contract, approval })
            : Object.freeze({ digest: prepared.digest, contract: prepared.contract, metaDigest: prepared.metaDigest, approval });
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
