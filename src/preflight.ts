/**
 * Pin store + verdict types — a port of the load-bearing primitives from Python
 * `tooling/cse/preflight.py` (`PinnedTool`, `PreflightPin`, `Decision`,
 * `PreflightVerdict`). The pin stores ONLY the public-contract hash (+ optional
 * PUBLIC schema for diff detail) — NEVER a token, by construction.
 */

import { randomBytes } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { tmpdir, homedir } from "node:os";
import { basename, dirname, join } from "node:path";

import { withExclusiveLock } from "./fileLock.js";
import { mdText } from "./render.js";
import { hashTool } from "./canonical.js";
import type { Change } from "./schemaDiff.js";
import type { FleetAdvisory } from "./driftQuery.js";

const PIN_STORE_VERSION = 2;
const EVER_PINNED_NAME = ".ever-pinned.json";

export type ToolDef = Record<string, unknown>;

export enum Decision {
  PROCEED = "PROCEED",
  HOLD = "HOLD",
  INCONCLUSIVE = "INCONCLUSIVE",
}

export interface PinnedTool {
  readonly serverId: string;
  readonly toolName: string;
  readonly definitionHash: string;
  readonly pinnedAt: string;
  readonly schema: ToolDef | null;
  /** Omitted on disk when it is the first-seen baseline, so a Python pin round-trips. */
  readonly via?: string;
  /** Kept so a pin written by the Python store is not stripped on the next flush. */
  readonly classification?: unknown;
  /**
   * Exact launch key when the pin was written, for example ``npm:pkg@1.2.3``.
   * Absent on pins written before this field; those behave as floating.
   */
  readonly launchKey?: string;
}

export function utcNowIso(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, (m) => m).replace("Z", "+00:00");
}

/** Tier 0a advisory action-classification — the READ-side mirror of the Python
 * `action_classification` wire payload (`tooling/cse/action_class.py`). Keys are
 * the snake_case wire contract (what the server/Python `model_dump` emits) so a
 * consumer can read a server verdict's block directly. ADVISORY only: it rides
 * ALONGSIDE the decision and NEVER alters PROCEED/HOLD. Values are closed-vocab
 * strings (enums) and ref ids — never an argument value or secret (the no-PII
 * invariant is enforced Python-side at serialization). This SDK does not yet
 * COMPUTE the block locally (the `classify()` port is deferred to the in-process
 * interceptor); the field is populated only from a server/hosted verdict, else null. */
export interface ActionClassification {
  readonly action_types: readonly string[];
  readonly effective_action_type: string;
  readonly resource: {
    readonly kind: string;
    readonly pattern: string;
    readonly scope_hint: string;
  };
  readonly side_effect_class: string;
  readonly reversibility: string;
  readonly egress: string;
  readonly autonomy_ceiling: string;
  readonly autonomy_ceiling_basis: string;
  readonly known_risk_notes: readonly {
    readonly note_class: string;
    readonly severity: string;
    readonly source: { readonly ref_type: string; readonly ref_id: string };
    readonly provenance: string;
  }[];
  readonly evidence: readonly { readonly ref_type: string; readonly ref_id: string }[];
}

/** A structured, honest pre-flight result. A verdict is a CONTRACT DIFF, never a
 * "this is unsafe" claim (AD-6). Mirrors `PreflightVerdict`. */
/** WHY a call was held — the single fact the agent-facing renderer dispatches on.
 *
 * A CLOSED vocabulary the producer sets. It exists because the renderer used to infer the
 * same distinction from proxies (`isContractDiff`, `drift.length`), and a proxy is only ever
 * right on the shapes its author had in mind. Values are the wire strings, unchanged.
 *
 * UNSET is not a state any producer should emit — it is the loud default, so a forgotten
 * field fails closed instead of impersonating a deliberate "drift".
 * Python twin: `cse.preflight.HoldClass`. */
export const HoldClass = {
  DRIFT: "drift",
  UNCHECKABLE: "uncheckable",
  FINDING: "finding",
  INTERNAL: "internal",
  WITHHELD: "withheld",
  APPROVAL: "approval",
  UNSET: "unset",
} as const;
export type HoldClass = (typeof HoldClass)[keyof typeof HoldClass];

export interface PreflightVerdict {
  readonly serverId: string;
  readonly toolName: string;
  readonly decision: Decision;
  readonly reason: string;
  readonly drift: readonly Change[];
  readonly failOpenWarning: boolean;
  readonly isContractDiff: boolean;
  /** Did the upstream call ALREADY EXECUTE when this verdict was produced?
   *
   * TRUE ONLY on the result-withhold path. Every other HOLD is pre-flight - the call never
   * left the process. Do NOT infer this from `isContractDiff`, which answers a different
   * question ("was this a contract comparison") and is false on five pre-flight shapes,
   * including the most common HOLD in production ("no pin for this tool on this session").
   * Python twin: `PreflightVerdict.already_executed`. */
  readonly alreadyExecuted?: boolean;
  /** WHY this call was held, as a closed vocabulary the PRODUCER sets - never inferred by a
   * renderer from `isContractDiff` and `drift.length`. That inference was wrong on every
   * shape where a comparison RAN and something other than a diff fired.
   *   "drift"       a comparison ran and found a difference
   *   "uncheckable" no comparison was possible: no pin, tool absent, definition unreadable
   *   "finding"     a comparison ran; something OTHER than a diff fired
   *   "internal"    our own code failed
   *   "withheld"    the call ran; its result is held
   *   "approval"    the contract is FINE; the ACTION CLASS needs a human
   * Python twin: `PreflightVerdict.hold_class`. */
  readonly holdClass?: HoldClass;
  readonly descBefore: string | null;
  readonly descAfter: string | null;
  /** Tier 0a advisory block — the blast radius of the call (action type, resource,
   * side-effect, reversibility, egress, static autonomy ceiling). Computed locally
   * from the live definition by the gate (default-on; opt out with
   * `MCPINDEX_ACTION_CLASSIFICATION_ENABLED=0`), or carried from a hosted verdict.
   * null when the live definition is unavailable or the flag is off. Advisory: it
   * rides alongside the decision and never moves PROCEED/HOLD (AD-1). */
  readonly actionClassification: ActionClassification | null;
  /** Fleet drift advisory (M3) — set when the public fleet has CORROBORATED drift for this
   * tool (the central crawl saw a contract/safety drift, or >=2 installs did). ADVISORY: it
   * rides alongside the decision and NEVER moves PROCEED/HOLD (AD-6) — a contract-diff
   * observation across the fleet, not a safety claim. null when the fleet query is off
   * (opt-in), the tool is clean, or the answer is unknown. */
  readonly fleetAdvisory: FleetAdvisory | null;
  /** Set when the baseline file could not be read. Posture must not downgrade it. */
  readonly tamperEvidence?: boolean;
}

export function makeVerdict(
  v: Pick<PreflightVerdict, "serverId" | "toolName" | "decision" | "reason"> &
    Partial<PreflightVerdict>,
): PreflightVerdict {
  return {
    serverId: v.serverId,
    toolName: v.toolName,
    decision: v.decision,
    reason: v.reason,
    drift: v.drift ?? [],
    failOpenWarning: v.failOpenWarning ?? false,
    isContractDiff: v.isContractDiff ?? true,
    // NOTE for anyone adding a field to PreflightVerdict: this builder WHITELISTS. A field
    // omitted here is silently dropped, and a renderer reading it sees the default - which
    // is how a result-withhold verdict rendered as a pre-flight hold in the TS suite while
    // Python was correct.
    alreadyExecuted: v.alreadyExecuted ?? false,
    // UNSET, not "drift". A producer that forgot this field used to be indistinguishable
    // from one that chose "drift", so it silently shipped prose asserting a contract change
    // that never happened. The renderer fails closed on UNSET and the suite fails the build.
    holdClass: v.holdClass ?? HoldClass.UNSET,
    descBefore: v.descBefore ?? null,
    descAfter: v.descAfter ?? null,
    actionClassification: v.actionClassification ?? null,
    fleetAdvisory: v.fleetAdvisory ?? null,
    tamperEvidence: v.tamperEvidence ?? false,
  };
}

export function isProceed(v: PreflightVerdict): boolean {
  return v.decision === Decision.PROCEED;
}

export function safetyRelevantDrift(v: PreflightVerdict): Change[] {
  return v.drift.filter((c) => c.safetyRelevant);
}

/** A human one-liner, render-safe (attacker-derived ids/detail escaped). Honest
 * voice: no safe/verified/clean/pass words. Port of `PreflightVerdict.render`.
 * Appends the M3 fleet advisory when present (AD-6-safe contract-diff note) — most
 * valuable on a PROCEED that matches your pin but drifted for the fleet. */
export function renderVerdict(v: PreflightVerdict): string {
  const body = renderVerdictBody(v);
  if (v.fleetAdvisory === null) return body;
  const a = v.fleetAdvisory;
  // Honest attribution: every surfaced drift is CRAWL-SEEN, so sources=1 is mcpindex's own
  // crawler (NOT an "independent observer"); sources>1 adds corroborating installs.
  const who =
    a.sources <= 1
      ? "mcpindex's crawler observed this tool's contract drift"
      : `mcpindex's crawler + ${a.sources - 1} independent install(s) corroborated this tool's contract drift`;
  return (
    body +
    `\n  ⚠ FLEET: ${who}${a.safetyRelevant ? " (safety-relevant)" : ""} — a contract diff, ` +
    "not a safety claim; review before relying on it."
  );
}

function renderVerdictBody(v: PreflightVerdict): string {
  const sid = mdText(v.serverId);
  const tool = mdText(v.toolName);
  if (v.decision === Decision.PROCEED && v.drift.length === 0) {
    const note = v.failOpenWarning ? " (fail-open: check could not run)" : "";
    return `PROCEED ${sid}/${tool} — contract matches your pin${note}`;
  }
  if (v.decision === Decision.PROCEED && v.failOpenWarning) {
    return `PROCEED ${sid}/${tool} — WARNING fail-open: ${mdText(v.reason)}`;
  }
  if (v.decision === Decision.INCONCLUSIVE) {
    let head =
      `INCONCLUSIVE ${sid}/${tool} — static analysis inconclusive: ` +
      `behavioral validation needed before use. ${mdText(v.reason)}`;
    for (const c of v.drift) {
      const flag = c.safetyRelevant ? "[safety-relevant] " : "";
      head += `\n  - ${flag}${c.kind} @ ${mdText(c.path)}: ${mdText(c.detail)}`;
    }
    return head;
  }
  if (v.drift.length > 0 || v.descBefore !== null || v.descAfter !== null) {
    const nSafety = safetyRelevantDrift(v).length;
    let head =
      `HOLD ${sid}/${tool} — DRIFTED from your pin ` +
      `(${v.drift.length} change(s), ${nSafety} safety-relevant). ` +
      "This is a CONTRACT DIFF, not a safety verdict — review and re-pin if expected.";
    for (const c of v.drift) {
      const flag = c.safetyRelevant ? "[safety-relevant] " : "";
      head += `\n  - ${flag}${c.kind} @ ${mdText(c.path)}: ${mdText(c.detail)}`;
    }
    if (v.descBefore !== null || v.descAfter !== null) {
      head +=
        `\n  description BEFORE: ${mdText(v.descBefore ?? "")}` +
        `\n  description AFTER:  ${mdText(v.descAfter ?? "")}`;
    }
    return head;
  }
  return `HOLD ${sid}/${tool} — ${mdText(v.reason)}`;
}

/** Pin store keyed by `(serverId, toolName)`. Stores ONLY hashes (+ optional
 * PUBLIC schema). A path argument persists to JSON under a sibling flock so a
 * Python CLI approval and another process cannot lose each other's writes. */
export class PreflightPin {
  private index = new Map<string, PinnedTool>();
  private taintedReason: string | null = null;
  private newerFormat = false;
  private diskSig: { ino: number; mtimeNs: number } | null = null;
  /** On-disk baseline, or null for an in-memory pin. */
  readonly path: string | null;

  constructor(path?: string | null) {
    this.path = path ?? null;
    if (this.path !== null) {
      const st = this.lstatStore(this.path);
      if (st === null) {
        if (wasEverPinned(this.path)) {
          this.taintedReason = "baseline file is missing but this server was pinned before";
        }
      } else if (!st.isFile()) {
        this.taintedReason = "baseline path is not a regular file";
      } else {
        this.loadIntoIndex();
        // An empty-but-valid store after we have pinned here is not a first run.
        if (
          this.index.size === 0 &&
          this.taintedReason === null &&
          !this.newerFormat &&
          wasEverPinned(this.path)
        ) {
          this.taintedReason =
            "baseline file has no pins for a server that was pinned before";
        }
        this.diskSig = this.signature();
      }
    }
  }

  /**
   * Taint the store when it holds no pins for `serverId` but has before.
   *
   * The constructor check only sees the whole file. A valid store that holds
   * another server's pins passes it, so the per-server check runs once the
   * server id is known (the Gate calls this). An index written before server
   * ids were recorded never taints here.
   */
  expectServer(serverId: string): void {
    if (this.path === null || this.taintedReason !== null || this.newerFormat) return;
    for (const pin of this.index.values()) {
      if (pin.serverId === serverId) return;
    }
    if (wasEverPinnedServer(this.path, serverId)) {
      this.taintedReason = "baseline file has no pins for a server that was pinned before";
    }
  }

  /** Closed reason when a baseline that should have been readable was not. */
  get tainted(): string | null {
    return this.taintedReason;
  }

  get unsupportedVersion(): boolean {
    return this.newerFormat;
  }

  private key(serverId: string, toolName: string): string {
    // \u001f (UNIT SEPARATOR), not a literal NUL. A raw NUL byte makes git classify this file
    // as BINARY, so `git diff` printed "Bin 8426 -> 9318 bytes" and FIVE rounds of security
    // review never saw a line of this file's changes - including the field and whitelist edits
    // this branch makes. Both are equally collision-safe (neither is legal in a tool name);
    // only one is reviewable. Python's twin keys on a tuple and needs no separator at all.
    return `${serverId}\u001f${toolName}`;
  }

  private lstatStore(path: string): { isFile(): boolean; ino: number; mtimeMs: number } | null {
    try {
      const st = lstatSync(path);
      return {
        isFile: () => st.isFile(),
        ino: Number(st.ino),
        mtimeMs: Number(st.mtimeMs),
      };
    } catch {
      return null;
    }
  }

  private signature(): { ino: number; mtimeNs: number } | null {
    if (this.path === null) return null;
    const st = this.lstatStore(this.path);
    if (st === null || !st.isFile()) return null;
    return { ino: st.ino, mtimeNs: Math.trunc(st.mtimeMs * 1_000_000) };
  }

  private parsePin(row: Record<string, unknown>): PinnedTool | null {
    const sid = row["server_id"];
    const tname = row["tool_name"];
    const dh = row["definition_hash"];
    const pinnedAt = row["pinned_at"];
    if (
      typeof sid !== "string" ||
      typeof tname !== "string" ||
      typeof dh !== "string" ||
      typeof pinnedAt !== "string"
    ) {
      return null;
    }
    const schema = row["schema"];
    const via = row["via"];
    const launchKey = row["launch_key"];
    return {
      serverId: sid,
      toolName: tname,
      definitionHash: dh,
      pinnedAt,
      schema:
        schema !== null && typeof schema === "object" && !Array.isArray(schema)
          ? (schema as ToolDef)
          : null,
      via: typeof via === "string" && via.length > 0 ? via : "tofu",
      classification: row["classification"],
      launchKey:
        typeof launchKey === "string" && launchKey.length > 0 ? launchKey : undefined,
    };
  }

  private loadIntoIndex(): void {
    const path = this.path;
    if (path === null) return;
    let raw: unknown;
    try {
      raw = JSON.parse(readFileSync(path, "utf8"));
    } catch {
      this.taintedReason = "baseline file is present but unreadable";
      return;
    }
    if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
      this.taintedReason = "baseline file is not a pin store";
      return;
    }
    const body = raw as Record<string, unknown>;
    const version = body["version"];
    if (typeof version === "number" && version > PIN_STORE_VERSION) {
      this.newerFormat = true;
      return;
    }
    const records = body["pins"] ?? [];
    if (!Array.isArray(records)) {
      this.taintedReason = "baseline file has no readable pin list";
      return;
    }
    for (const rec of records) {
      if (rec === null || typeof rec !== "object" || Array.isArray(rec)) {
        this.taintedReason = "baseline file contains an unreadable record";
        continue;
      }
      const pin = this.parsePin(rec as Record<string, unknown>);
      if (pin === null) {
        this.taintedReason = "baseline file contains an unreadable record";
        continue;
      }
      this.index.set(this.key(pin.serverId, pin.toolName), pin);
    }
  }

  private emptyStoreIsUnreadable(
    records: PinnedTool[],
    savedIndex: Map<string, PinnedTool>,
  ): boolean {
    const ever = this.path !== null && wasEverPinned(this.path);
    if (records.length === 0 && (ever || savedIndex.size > 0)) return true;
    const serversMem = new Set<string>();
    for (const pin of savedIndex.values()) serversMem.add(pin.serverId);
    if (serversMem.size === 0) return false;
    const serversDisk = new Set(records.map((p) => p.serverId));
    for (const sid of serversMem) {
      if (!serversDisk.has(sid)) return true;
    }
    return false;
  }

  private recordsFromDisk(): PinnedTool[] | null {
    if (this.path === null) return [];
    const st = this.lstatStore(this.path);
    if (st === null) {
      if (wasEverPinned(this.path) || this.index.size > 0) {
        this.taintedReason =
          "baseline file is missing but this server was pinned before";
        return null;
      }
      return [];
    }
    if (!st.isFile()) {
      this.taintedReason = "baseline path is not a regular file";
      return null;
    }
    const savedIndex = this.index;
    const savedTaint = this.taintedReason;
    const savedUnsupported = this.newerFormat;
    this.index = new Map();
    this.taintedReason = null;
    this.newerFormat = false;
    this.loadIntoIndex();
    if (this.newerFormat || this.taintedReason !== null) {
      const loadTaint = this.taintedReason;
      this.index = savedIndex;
      this.taintedReason = loadTaint ?? savedTaint;
      this.newerFormat = savedUnsupported || this.newerFormat;
      return null;
    }
    const records = [...this.index.values()];
    this.index = savedIndex;
    this.taintedReason = savedTaint;
    this.newerFormat = savedUnsupported;
    if (this.emptyStoreIsUnreadable(records, savedIndex)) {
      this.taintedReason =
        "baseline file has no pins for a server that was pinned before";
      return null;
    }
    return records;
  }

  private reloadHoldingLock(): void {
    if (this.path === null) return;
    const sig = this.signature();
    if (
      sig !== null &&
      this.diskSig !== null &&
      sig.ino === this.diskSig.ino &&
      sig.mtimeNs === this.diskSig.mtimeNs
    ) {
      return;
    }
    withExclusiveLock(this.path, () => {
      const again = this.signature();
      if (
        again !== null &&
        this.diskSig !== null &&
        again.ino === this.diskSig.ino &&
        again.mtimeNs === this.diskSig.mtimeNs
      ) {
        return;
      }
      const records = this.recordsFromDisk();
      if (records === null) return;
      this.index = new Map(records.map((p) => [this.key(p.serverId, p.toolName), p]));
      this.diskSig = this.signature();
    });
  }

  /** Reload when another process replaced the file. No-op for an in-memory pin. */
  reloadIfChanged(): void {
    this.reloadHoldingLock();
  }

  get(serverId: string, toolName: string): PinnedTool | null {
    this.reloadHoldingLock();
    return this.index.get(this.key(serverId, toolName)) ?? null;
  }

  put(pin: PinnedTool): void {
    if (this.path === null) {
      this.index.set(this.key(pin.serverId, pin.toolName), pin);
      return;
    }
    if (this.taintedReason !== null) {
      throw new Error("pin store is tainted");
    }
    withExclusiveLock(this.path, () => {
      if (this.taintedReason !== null) {
        throw new Error("pin store is tainted");
      }
      const records = this.recordsFromDisk();
      if (records === null) throw new Error("pin store is unreadable");
      this.index = new Map(records.map((p) => [this.key(p.serverId, p.toolName), p]));
      this.index.set(this.key(pin.serverId, pin.toolName), pin);
      this.flush();
      this.diskSig = this.signature();
    });
  }

  private flush(): void {
    const path = this.path;
    if (path === null) return;
    if (this.taintedReason !== null) {
      throw new Error("pin store is tainted");
    }
    const pins = [...this.index.values()].map((p) => {
      const row: Record<string, unknown> = {
        server_id: p.serverId,
        tool_name: p.toolName,
        definition_hash: p.definitionHash,
        pinned_at: p.pinnedAt,
      };
      if (p.schema !== null) row["schema"] = p.schema;
      if (p.via !== undefined && p.via !== "tofu") row["via"] = p.via;
      if (p.classification !== undefined) row["classification"] = p.classification;
      if (p.launchKey !== undefined && p.launchKey.length > 0) row["launch_key"] = p.launchKey;
      return row;
    });
    const payload = { version: PIN_STORE_VERSION, pins };
    const directory = dirname(path) || ".";
    mkdirSync(directory, { recursive: true });
    const suffix = randomBytes(8).toString("hex");
    const tmp = join(directory, `.${basename(path)}.${process.pid}.${suffix}.tmp`);
    const encoded = Buffer.from(stableStringify(payload), "utf8");
    let flags = constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL;
    if (typeof constants.O_NOFOLLOW === "number") {
      flags |= constants.O_NOFOLLOW;
    }
    const fd = openSync(tmp, flags, 0o600);
    try {
      writeSync(fd, encoded);
      fsyncSync(fd);
      closeSync(fd);
      chmodSync(tmp, 0o600);
      renameSync(tmp, path);
    } catch (err) {
      try {
        unlinkSync(tmp);
      } catch {
        // the temp file may already be gone
      }
      throw err;
    }
    recordEverPinned(path, new Set([...this.index.values()].map((p) => p.serverId)));
  }

  toolsFor(serverId: string): PinnedTool[] {
    this.reloadHoldingLock();
    return [...this.index.values()].filter((p) => p.serverId === serverId);
  }

  allPins(): PinnedTool[] {
    this.reloadHoldingLock();
    return [...this.index.values()];
  }
}

function stableStringify(value: unknown): string {
  return JSON.stringify(sortKeys(value), null, 2) + "\n";
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      out[key] = sortKeys((value as Record<string, unknown>)[key]);
    }
    return out;
  }
  return value;
}

function everPinnedPath(storePath: string): string {
  return join(dirname(storePath) || ".", EVER_PINNED_NAME);
}

function wasEverPinned(storePath: string): boolean {
  try {
    const raw = JSON.parse(readFileSync(everPinnedPath(storePath), "utf8")) as unknown;
    if (raw === null || typeof raw !== "object" || Array.isArray(raw)) return false;
    const stores = (raw as Record<string, unknown>)["stores"];
    return Array.isArray(stores) && stores.includes(basename(storePath));
  } catch {
    return false;
  }
}

type EverPinned = { stores: string[]; servers: Record<string, string[]> };

function readEverPinned(indexPath: string): EverPinned {
  const out: EverPinned = { stores: [], servers: {} };
  try {
    const raw = JSON.parse(readFileSync(indexPath, "utf8")) as unknown;
    if (raw === null || typeof raw !== "object" || Array.isArray(raw)) return out;
    const stores = (raw as Record<string, unknown>)["stores"];
    if (Array.isArray(stores)) out.stores = stores.filter((s): s is string => typeof s === "string");
    const servers = (raw as Record<string, unknown>)["servers"];
    if (servers !== null && typeof servers === "object" && !Array.isArray(servers)) {
      for (const [key, ids] of Object.entries(servers as Record<string, unknown>)) {
        if (Array.isArray(ids)) out.servers[key] = ids.filter((i): i is string => typeof i === "string");
      }
    }
  } catch {
    // an absent or unreadable index is no evidence
  }
  return out;
}

/** True iff this store has held pins for `serverId`. Fails open like `wasEverPinned`. */
function wasEverPinnedServer(storePath: string, serverId: string): boolean {
  const { servers } = readEverPinned(everPinnedPath(storePath));
  return (servers[basename(storePath)] ?? []).includes(serverId);
}

function writeEverPinnedStores(
  indexPath: string,
  stores: string[],
  servers: Record<string, string[]> = {},
): void {
  const directory = dirname(indexPath) || ".";
  mkdirSync(directory, { recursive: true });
  const suffix = randomBytes(8).toString("hex");
  const tmp = join(directory, `.ever-pinned.${process.pid}.${suffix}.tmp`);
  let flags = constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL;
  if (typeof constants.O_NOFOLLOW === "number") {
    flags |= constants.O_NOFOLLOW;
  }
  const fd = openSync(tmp, flags, 0o600);
  try {
    const body: Record<string, unknown> = { stores: [...stores].sort() };
    const keys = Object.keys(servers).filter((k) => servers[k]!.length > 0);
    if (keys.length > 0) {
      const sorted: Record<string, string[]> = {};
      for (const key of keys.sort()) sorted[key] = [...new Set(servers[key])].sort();
      body["servers"] = sorted;
    }
    writeSync(fd, Buffer.from(stableStringify(body), "utf8"));
    fsyncSync(fd);
    closeSync(fd);
    chmodSync(tmp, 0o600);
    renameSync(tmp, indexPath);
  } catch (err) {
    try {
      unlinkSync(tmp);
    } catch {
      // already removed
    }
    throw err;
  }
}

function recordEverPinned(storePath: string, serverIds: Set<string> = new Set()): void {
  const indexPath = everPinnedPath(storePath);
  const name = basename(storePath);
  try {
    const { stores, servers } = readEverPinned(indexPath);
    const known = new Set(servers[name] ?? []);
    const wanted = new Set([...known, ...serverIds]);
    if (stores.includes(name) && wanted.size === known.size) return;
    if (!stores.includes(name)) stores.push(name);
    if (wanted.size > 0) servers[name] = [...wanted].sort();
    writeEverPinnedStores(indexPath, stores, servers);
  } catch {
    return;
  }
}

/** Remove ``storePath`` from the ever-pinned index. */
export function clearEverPinned(storePath: string): void {
  const indexPath = everPinnedPath(storePath);
  const name = basename(storePath);
  try {
    let raw: unknown;
    try {
      raw = JSON.parse(readFileSync(indexPath, "utf8")) as unknown;
    } catch {
      return;
    }
    if (raw === null || typeof raw !== "object" || Array.isArray(raw)) return;
    const found = (raw as Record<string, unknown>)["stores"];
    if (!Array.isArray(found)) return;
    const stores = found.filter((s): s is string => typeof s === "string" && s !== name);
    const { servers } = readEverPinned(indexPath);
    delete servers[name];
    if (stores.length > 0) {
      writeEverPinnedStores(indexPath, stores, servers);
    } else {
      try {
        unlinkSync(indexPath);
      } catch {
        // best effort
      }
    }
  } catch {
    return;
  }
}

export function sanitizeServerId(serverId: string): string {
  const safe = serverId
    .replace(/[^A-Za-z0-9._-]/g, "_")
    .replace(/^[._]+|[._]+$/g, "")
    .slice(0, 128);
  return safe.length > 0 ? safe : "_";
}

/** Pin file for one server. `MCPINDEX_STATE_DIR/pins/<id>.json`, else `~/.mcpindex/pins/<id>.json`. */
export function defaultPinStorePath(serverId: string): string {
  const fromEnv = process.env.MCPINDEX_STATE_DIR;
  let root: string;
  if (typeof fromEnv === "string" && fromEnv.trim().length > 0) {
    root = fromEnv;
  } else if (process.execArgv.includes("--test") || process.argv.includes("--test")) {
    root = join(tmpdir(), "mcpindex-sdk-test", String(process.pid));
  } else {
    root = join(homedir(), ".mcpindex");
  }
  return join(root, "pins", `${sanitizeServerId(serverId)}.json`);
}

export { hashTool, approvalDigest } from "./canonical.js";
