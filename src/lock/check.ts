/**
 * The lock check (section 9): a pure decision over one complete listing, and a
 * per-connection CallGate that allows `tools/call` only for names shown on the
 * latest checked listing.
 *
 * Lock mode has no first-use pin, no auto-accept and no re-pin. Nothing here
 * writes to a lock; the lock changes only through LockStore.approve/revoke.
 */

import { compareCodePoints, hasTopMeta, instructionsDigest, metaDigest, toolDigest } from "./digest.js";
import { LockError, POSTURES, identityKey } from "./lock.js";
import type { Identity, Lock, LockErrorReason, Posture } from "./lock.js";

export const LOCK_REFUSAL_CODE = -32011;
export const LOCK_REFUSAL_MESSAGE = "Tool withheld by lock";

export type ToolReason = "unlocked-server" | "duplicate-name" | "no-digest" | "new-tool" | "upstream-changed";
/** Why a shown tool's top-level `_meta` was not relayed as approved (draft 1c). */
export type MetaReason = "meta-changed" | "meta-unapproved";
export type CallReason = ToolReason | LockErrorReason | "no-listing" | "not-listed" | "classifier-error" | "unreachable";

export interface ToolOutcome {
  readonly name: string;
  readonly served: string | null;
  readonly approved: string | null;
  readonly decision: "shown" | "withheld";
  readonly reason: ToolReason | LockErrorReason | null;
  /** Section 9.2.3 flag for a shown tool's top-level `_meta`, else null. */
  readonly meta: MetaReason | null;
}

/** Section 9.2.3 decision for one shown tool that has a top-level `_meta`. */
export interface MetaDecision {
  /** True when `_meta` reaches the client as served. */
  readonly relay: boolean;
  readonly flag: MetaReason | null;
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
  /**
   * Every shown tool with a top-level `_meta`: name to whether it is relayed
   * and its flag. A served `_meta` that does not match the approved
   * metaDigest is flagged; under guard it is removed before the tool is
   * relayed (stripMeta), under monitor it is relayed and reported.
   */
  readonly meta: ReadonlyMap<string, MetaDecision>;
  /** Indexes into the listing's tools array whose `_meta` is removed before relay. */
  readonly stripMeta: ReadonlySet<number>;
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
  const meta = new Map<string, MetaDecision>();
  const stripMeta = new Set<number>();
  const tools: ToolOutcome[] = [];

  if (lock instanceof LockError) {
    for (const tool of raw) {
      const name = nameOf(tool);
      if (name === null) continue;
      withheld.set(name, lock.reason);
      tools.push(freezeAll({ name, served: toolDigest(tool), approved: null, decision: "withheld", reason: lock.reason, meta: null }));
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
      meta: new Map(),
      stripMeta: new Set(),
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
      tools.push(freezeAll({ name, served: digest, approved, decision: "withheld", reason, meta: null }));
      return;
    }
    if (reason !== null) flagged.set(name, reason);
    let flag: MetaReason | null = null;
    if (hasTopMeta(tool)) {
      const approvedMeta = entry?.metaDigest;
      if (approvedMeta === undefined) flag = "meta-unapproved";
      else if (metaDigest(tool) !== approvedMeta) flag = "meta-changed";
      meta.set(name, freezeAll({ relay: flag === null || !guard, flag }));
      if (flag !== null && guard) stripMeta.add(index);
    }
    shown.push(name);
    shownIndexes.push(index);
    callable.add(name);
    tools.push(freezeAll({ name, served: digest, approved, decision: "shown", reason, meta: flag }));
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
    meta,
    stripMeta,
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
  /** `tool` is left out when the call's name was not a string, as in the Python host. */
  readonly data: { readonly reason: CallReason; readonly tool?: string };
}

export function refusalError(name: string | null, reason: CallReason): RefusalError {
  const data = name === null ? { reason } : { reason, tool: name };
  return { code: LOCK_REFUSAL_CODE, message: LOCK_REFUSAL_MESSAGE, data };
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

/** Default age after which a call first reloads the snapshot (section 9.8), as in the Python host. */
export const DEFAULT_MAX_STALENESS_MS = 60_000;

export interface CallGateOptions {
  /**
   * Section 9.8: once the snapshot behind the decision is older than this, a
   * call reloads it first (LockedTransport) and is refused with `lock-stale`
   * when the reload fails. Default 60 s. Pass Infinity to never go stale.
   */
  readonly maxStalenessMs?: number;
  readonly now?: () => number;
}

/**
 * Per-connection allow-list. `record` replaces the decision only when a
 * complete listing has been checked. A list_changed notification does not
 * touch it. While a listing is in progress (section 9.2.1: `beginListing`
 * until `record` or `markUnreachable`) every call is refused with
 * `no-listing`, so nothing is called on the strength of a listing that is
 * being replaced.
 *
 * Order of reasons (section 9.5): `no-listing` while a listing is in
 * progress or before any listing has ended; then the whole-lock error of the
 * latest completed listing, which a later failed listing does not clear;
 * then `unreachable` after a failed listing; then `lock-stale`; then the
 * per-name answer.
 */
export class CallGate {
  #decision: Decision | null = null;
  #snapshotAt = 0;
  #snapshotId: string | null = null;
  #unreachable = false;
  #collecting = false;
  readonly #maxStalenessMs: number;
  readonly #now: () => number;

  constructor(options: CallGateOptions = {}) {
    const max = options.maxStalenessMs ?? DEFAULT_MAX_STALENESS_MS;
    if (!(max >= 0)) throw new Error("maxStalenessMs must be >= 0");
    this.#maxStalenessMs = max;
    this.#now = options.now ?? Date.now;
  }

  get decision(): Decision | null {
    return this.#decision;
  }

  get snapshotId(): string | null {
    return this.#snapshotId;
  }

  /** A listing started: the host asked for its first page. */
  beginListing(): void {
    this.#collecting = true;
  }

  /** The listing in progress ended without a decision and without failing. */
  endListing(): void {
    this.#collecting = false;
  }

  get listingInProgress(): boolean {
    return this.#collecting;
  }

  /** Install the decision for the latest complete listing. */
  record(decision: Decision, snapshot: { readonly snapshotId: string; readonly loadedAt: number }): void {
    this.#decision = decision;
    this.#snapshotId = snapshot.snapshotId;
    this.#snapshotAt = snapshot.loadedAt;
    this.#unreachable = false;
    this.#collecting = false;
  }

  /** The latest listing failed; refuse every call with `unreachable` until one completes. */
  markUnreachable(): void {
    this.#unreachable = true;
    this.#collecting = false;
  }

  get unreachable(): boolean {
    return this.#unreachable;
  }

  isStale(): boolean {
    if (this.#decision === null) return false;
    return this.#now() - this.#snapshotAt > this.#maxStalenessMs;
  }

  check(name: string): "allow" | CallReason {
    const decision = this.#decision;
    if (this.#collecting || (decision === null && !this.#unreachable)) return "no-listing";
    if (decision !== null && decision.lockError !== null) return decision.lockError;
    if (this.#unreachable || decision === null) return "unreachable";
    if (this.isStale()) return "lock-stale";
    return checkCall(decision, name);
  }

  enforce(name: string): void {
    const verdict = this.check(name);
    if (verdict !== "allow") throw new LockRefusal(name, verdict);
  }
}
