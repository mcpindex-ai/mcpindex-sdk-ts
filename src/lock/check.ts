/**
 * The lock check (section 9): a pure decision over one complete listing, and a
 * per-connection CallGate that allows `tools/call` only for names shown on the
 * latest checked listing.
 *
 * Lock mode has no first-use pin, no auto-accept and no re-pin. Nothing here
 * writes to a lock; the lock changes only through LockStore.approve/revoke.
 */

import { compareCodePoints, instructionsDigest, toolDigest } from "./digest.js";
import { LockError, POSTURES, identityKey } from "./lock.js";
import type { Identity, Lock, LockErrorReason, Posture } from "./lock.js";

export const LOCK_REFUSAL_CODE = -32011;
export const LOCK_REFUSAL_MESSAGE = "Tool withheld by lock";

export type ToolReason = "unlocked-server" | "duplicate-name" | "no-digest" | "new-tool" | "upstream-changed";
export type CallReason = ToolReason | LockErrorReason | "no-listing" | "not-listed" | "classifier-error" | "unreachable";

export interface ToolOutcome {
  readonly name: string;
  readonly served: string | null;
  readonly approved: string | null;
  readonly decision: "shown" | "withheld";
  readonly reason: ToolReason | LockErrorReason | null;
}

export interface Decision {
  readonly posture: Posture;
  /** Names shown to the model, in listing order (a duplicate name under monitor repeats). */
  readonly shown: readonly string[];
  /** Name to reason, under guard (or for any lock failure). */
  readonly withheld: ReadonlyMap<string, ToolReason | LockErrorReason>;
  /** Name to reason, under monitor: shown but reported. */
  readonly flagged: ReadonlyMap<string, ToolReason>;
  readonly removed: readonly string[];
  readonly instructions: "instructions-changed" | null;
  readonly stripInstructions: boolean;
  readonly lockError: LockErrorReason | null;
  /** The allow-list for calls on this connection. */
  readonly callable: ReadonlySet<string>;
  /** Indexes into the listing's tools array of the entries the model may see. */
  readonly shownIndexes: readonly number[];
  /** One row per named listing entry, for the listing event. */
  readonly tools: readonly ToolOutcome[];
  readonly served: number;
}

export interface Listing {
  readonly tools: readonly unknown[];
  readonly instructions?: unknown;
}

export function isPosture(value: unknown): value is Posture {
  return typeof value === "string" && (POSTURES as readonly string[]).includes(value);
}

function nameOf(tool: unknown): string | null {
  if (tool === null || typeof tool !== "object" || Array.isArray(tool)) return null;
  const name = Object.getOwnPropertyDescriptor(tool, "name")?.value;
  return typeof name === "string" ? name : null;
}

function freezeAll<T extends object>(value: T): T {
  return Object.freeze(value);
}

/**
 * Check one complete listing against a lock, or against a whole-lock failure.
 * `listing.tools` is the raw array as received; nothing is fetched again.
 */
export function checkListing(lock: Lock | LockError, identity: Identity, listing: Listing, posture: Posture): Decision {
  if (!isPosture(posture)) throw new Error(`unknown posture ${String(posture)}`);
  const guard = posture !== "monitor";
  const raw = listing.tools;
  if (!Array.isArray(raw)) throw new TypeError("listing has no tools array");
  const served = listing.instructions;
  const hasInstructions = served !== undefined && served !== null;

  const shown: string[] = [];
  const shownIndexes: number[] = [];
  const withheld = new Map<string, ToolReason | LockErrorReason>();
  const flagged = new Map<string, ToolReason>();
  const callable = new Set<string>();
  const tools: ToolOutcome[] = [];

  if (lock instanceof LockError) {
    for (const tool of raw) {
      const name = nameOf(tool);
      if (name === null) continue;
      withheld.set(name, lock.reason);
      tools.push(freezeAll({ name, served: toolDigest(tool), approved: null, decision: "withheld", reason: lock.reason }));
    }
    return freezeAll({
      posture,
      shown,
      withheld,
      flagged,
      removed: [],
      instructions: null,
      stripInstructions: hasInstructions,
      lockError: lock.reason,
      callable,
      shownIndexes,
      tools,
      served: raw.length,
    });
  }

  const shard = lock.shards.get(identityKey(identity)) ?? null;
  const counts = new Map<string, number>();
  for (const tool of raw) {
    const name = nameOf(tool);
    if (name !== null) counts.set(name, (counts.get(name) ?? 0) + 1);
  }
  raw.forEach((tool, index) => {
    const name = nameOf(tool);
    if (name === null) return; // never shown, never callable
    const digest = toolDigest(tool);
    const entry = shard?.tools.get(name) ?? null;
    let reason: ToolReason | null;
    if (shard === null) reason = "unlocked-server";
    else if ((counts.get(name) ?? 0) > 1) reason = "duplicate-name";
    else if (digest === null) reason = "no-digest";
    else if (entry === null) reason = "new-tool";
    else if (entry.digest !== digest) reason = "upstream-changed";
    else reason = null;
    const approved = entry?.digest ?? null;
    if (reason !== null && guard) {
      withheld.set(name, reason);
      tools.push(freezeAll({ name, served: digest, approved, decision: "withheld", reason }));
      return;
    }
    if (reason !== null) flagged.set(name, reason);
    shown.push(name);
    shownIndexes.push(index);
    callable.add(name);
    tools.push(freezeAll({ name, served: digest, approved, decision: "shown", reason }));
  });

  const removed = shard === null ? [] : [...shard.tools.keys()].filter((n) => !counts.has(n)).sort(compareCodePoints);
  let instructions: "instructions-changed" | null = null;
  let stripInstructions = false;
  if (hasInstructions) {
    const locked = shard?.instructions ?? null;
    const digest = typeof served === "string" ? instructionsDigest(served) : null;
    if (locked === null || digest !== locked) {
      instructions = "instructions-changed";
      stripInstructions = guard;
    }
  }
  return freezeAll({
    posture,
    shown,
    withheld,
    flagged,
    removed,
    instructions,
    stripInstructions,
    lockError: null,
    callable,
    shownIndexes,
    tools,
    served: raw.length,
  });
}

/** Decide instructions alone, for a host that sees them before any listing (initialize). */
export function checkInstructions(
  lock: Lock | LockError,
  identity: Identity,
  instructions: unknown,
  posture: Posture,
): { readonly reason: "instructions-changed" | LockErrorReason | null; readonly strip: boolean } {
  if (instructions === undefined || instructions === null) return { reason: null, strip: false };
  const d = checkListing(lock, identity, { tools: [], instructions }, posture);
  if (d.lockError !== null) return { reason: d.lockError, strip: true };
  return { reason: d.instructions, strip: d.stripInstructions };
}

/** 'allow', or the reason sent in data.reason of a -32011 error. */
export function checkCall(decision: Decision | null, name: string): "allow" | CallReason {
  if (decision === null) return "no-listing";
  if (decision.lockError !== null) return decision.lockError;
  if (decision.callable.has(name)) return "allow";
  return decision.withheld.get(name) ?? "not-listed";
}

export interface RefusalError {
  readonly code: typeof LOCK_REFUSAL_CODE;
  readonly message: string;
  readonly data: { readonly reason: CallReason; readonly tool: string };
}

export function refusalError(name: string, reason: CallReason): RefusalError {
  return { code: LOCK_REFUSAL_CODE, message: LOCK_REFUSAL_MESSAGE, data: { reason, tool: name } };
}

/** Error thrown to callers who check through CallGate.enforce. */
export class LockRefusal extends Error {
  readonly code = LOCK_REFUSAL_CODE;
  readonly reason: CallReason;
  readonly tool: string;
  constructor(tool: string, reason: CallReason) {
    super(LOCK_REFUSAL_MESSAGE);
    this.name = "LockRefusal";
    this.tool = tool;
    this.reason = reason;
  }
  toJsonRpcError(): RefusalError {
    return refusalError(this.tool, this.reason);
  }
}

export interface CallGateOptions {
  /** Refuse calls with `lock-stale` once the snapshot behind the decision is older than this. */
  readonly maxStalenessMs?: number;
  readonly now?: () => number;
}

/**
 * Per-connection allow-list. `record` replaces the decision only when a
 * complete listing has been checked; a list_changed notification does not
 * clear it, so until the next listing completes the previous allow-list stays
 * and names that are new on the server are not callable.
 */
export class CallGate {
  #decision: Decision | null = null;
  #snapshotAt = 0;
  #snapshotId: string | null = null;
  #unreachable = false;
  readonly #maxStalenessMs: number | null;
  readonly #now: () => number;

  constructor(options: CallGateOptions = {}) {
    const max = options.maxStalenessMs;
    if (max !== undefined && !(Number.isFinite(max) && max >= 0)) throw new Error("maxStalenessMs must be >= 0");
    this.#maxStalenessMs = max ?? null;
    this.#now = options.now ?? Date.now;
  }

  get decision(): Decision | null {
    return this.#decision;
  }

  get snapshotId(): string | null {
    return this.#snapshotId;
  }

  /** Install the decision for the latest complete listing. */
  record(decision: Decision, snapshot: { readonly snapshotId: string; readonly loadedAt: number }): void {
    this.#decision = decision;
    this.#snapshotId = snapshot.snapshotId;
    this.#snapshotAt = snapshot.loadedAt;
    this.#unreachable = false;
  }

  /** The server sent something that is not a listing; refuse every call until one completes. */
  markUnreachable(): void {
    this.#unreachable = true;
  }

  isStale(): boolean {
    if (this.#decision === null || this.#maxStalenessMs === null) return false;
    return this.#now() - this.#snapshotAt > this.#maxStalenessMs;
  }

  check(name: string): "allow" | CallReason {
    if (this.#unreachable) return "unreachable";
    if (this.#decision !== null && this.isStale()) return "lock-stale";
    return checkCall(this.#decision, name);
  }

  enforce(name: string): void {
    const verdict = this.check(name);
    if (verdict !== "allow") throw new LockRefusal(name, verdict);
  }
}
