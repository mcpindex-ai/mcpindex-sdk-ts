/**
 * Pre-flight drift INTERCEPTOR — the TypeScript SDK-wrapper surface, at parity
 * with Python `tooling/cse/preflight_intercept.py`.
 *
 * `wrap(session)` returns a transparent JS `Proxy` over the real
 * `@modelcontextprotocol/sdk` `Client`: every method/prop passes through the
 * get-trap UNTOUCHED, EXCEPT the three gated seams:
 *   - `listTools`  — TOFU-pin every observed tool's PUBLIC contract.
 *   - `callTool`   — run the shared Gate before delegating; HOLD on drift.
 *   - `request`    — the low-level RPC chokepoint (the TS analog of Python's
 *     `send_request`). `callTool` is sugar over `request({method:'tools/call'})`,
 *     so a caller can invoke any tool straight through `request`; we gate a
 *     `tools/call` there too, or the pre-flight check is a paper wall.
 *   - `requestStream` — the EXPERIMENTAL streaming chokepoint. The SDK's task
 *     surface (`client.experimental.tasks.callToolStream`) invokes a tool via
 *     `requestStream({method:'tools/call'})`, a SECOND RPC path that does NOT go
 *     through `request`. `requestStream` is also reachable directly on the
 *     session. We gate a `tools/call` on BOTH the session-level `requestStream`
 *     AND a wrapped `experimental` accessor (whose `tasks.callToolStream` /
 *     `tasks.requestStream` desugar to it), or the streaming surface is a hole
 *     in the wall. The gate runs PRE-FLIGHT: a HELD verdict yields a throwing
 *     async generator that NEVER touches the upstream stream (fail-closed).
 *
 * NO CREDENTIAL (structural): the wrapper holds NO token, NO auth, opens NO
 * connection. It reuses the wrapped session's own authenticated transport. The
 * shared Gate reads only the PUBLIC contract.
 */

import {
  Gate,
  Ownership,
  Posture,
  HELD_PROVENANCE_UNAVAILABLE_BANNER,
  HELD_PROVENANCE_UNAVAILABLE_MESSAGE,
  INTERNAL_ERROR_HELD_MESSAGE,
  isInternalErrorVerdict,
  renderHoldBanner,
  renderHoldMessage,
  behaviourObserved,
} from "./gate.js";
import type { BehavioralVerifier } from "./gate.js";
import { Decision, HoldClass, PreflightPin, defaultPinStorePath, makeVerdict, utcNowIso } from "./preflight.js";
import {
  MAX_LISTED_TOOLS,
  WITHHELD_CALL_REASON,
  filterListing,
  rawToolEntries,
  replaceToolList,
} from "./listingFilter.js";
import type { PinnedTool, PreflightVerdict, ToolDef } from "./preflight.js";
import { scanResult } from "./scan.js";
import type { ResultScan } from "./scan.js";
import { ChangeKind } from "./schemaDiff.js";
import { ErrorStore, Operation } from "./errors.js";
import { Action, LocalStats, OutcomeStore } from "./outcomes.js";
import { surfaceProvenance } from "./provenance.js";
import type { Provenance } from "./provenance.js";
import { AmbientNotifier } from "./ambient.js";
import type { AmbientObserver } from "./ambient.js";

const DEFAULT_BEHAVIORAL_MANDATED_KINDS: ReadonlySet<ChangeKind> = new Set([
  ChangeKind.OUTPUT_SCHEMA_CHANGED,
  ChangeKind.ANNOTATION_FLIP_TO_DESTRUCTIVE,
]);

/** A HOLD raised before delegating to the wrapped session. Carries the structured
 * verdict + (when a complete provenance backs the finding) the provenance. Honest
 * voice: a HOLD is a CONTRACT DIFF, not a safety verdict. */
export class PreflightHold extends Error {
  readonly verdict: PreflightVerdict;
  readonly provenance: Provenance | null;
  /** The human brand-moment banner, kept OFF `message` since 2026-08-05: `String(err)` is
   * what a builder is most likely to hand to a model, and a model reads this channel as
   * attacker-controlled. Render this when the reader is a person. */
  readonly presentation!: string | null;

  constructor(
    verdict: PreflightVerdict,
    provenance: Provenance | null,
    message: string,
    presentation: string | null = null,
  ) {
    super(message);
    this.name = "PreflightHold";
    this.verdict = verdict;
    this.provenance = provenance;
    // NON-ENUMERABLE on purpose. `Error.prototype.message` is non-enumerable, so an
    // enumerable `presentation` made `JSON.stringify(err)` emit the branded banner and DROP
    // the agent message - inverting the split for anyone who logs or forwards a caught error,
    // which is the dominant Node idiom.
    Object.defineProperty(this, "presentation", {
      value: presentation,
      enumerable: false,
      writable: false,
      configurable: false,
    });
  }
}

/** Default logical id the tools are pinned under when the caller passes no
 * `serverId`. The pin store is an EPHEMERAL in-memory baseline (see the default
 * `pin` below), so this namespace is process-local — a stable label is all the
 * TOFU baseline needs. Pass an explicit `serverId` for a durable/fleet setup. */
export const DEFAULT_SERVER_ID = "mcp";

export interface WrapOptions {
  /** The pin store the tools are checked against. Optional: when omitted and a
   * `serverId` is given, pins are kept in a file under the state directory and
   * survive a process restart. With no `serverId` the default stays in memory.
   * Pass `pinStore: "memory"` for a store that dies with the process, or pass
   * your own `PreflightPin`. */
  pin?: PreflightPin;
  /** `"memory"` keeps pins in this process only. `"file"` forces the file store
   * even without a `serverId`. The default is a file when `serverId` is set. */
  pinStore?: "memory" | "file";
  /** Called when a tool is left out of a list: server id, tool, reason, live hash. */
  onWithheld?: ((serverId: string, tool: string, reason: string, definitionHash: string) => void) | null;
  /** Logical id the tools are pinned under. Optional: defaults to
   * `DEFAULT_SERVER_ID` ("mcp"), which is correct for the ephemeral in-memory
   * baseline. Pass a stable id when you persist pins or opt into fleet telemetry. */
  serverId?: string;
  failOpen?: boolean;
  autoAcceptBenign?: boolean;
  onHold?: ((verdict: PreflightVerdict) => unknown) | null;
  now?: () => string;
  ownership?: Ownership;
  behavioralMandatedKinds?: ReadonlySet<ChangeKind>;
  verifier?: BehavioralVerifier | null;
  autoValidateBehavior?: boolean;
  posture?: Posture;
  stats?: LocalStats | null;
  outcomes?: OutcomeStore | null;
  errors?: ErrorStore | null;
  /** Optional sink for the ambient "mcpindex is watching this" signal — the SDK-UI
   * seam (the TS analog of Python `on_invocation`). The notifier is default-on, built
   * from the env via `AmbientNotifier.fromEnv`; the signal rides stderr + this observer
   * ONLY, never stdout, and never changes a gate decision or the call's return value. */
  onInvocation?: AmbientObserver | null;
  /** Opt-in (default FALSE -> zero behavior change, pure passthrough) runtime
   * RESULT-content scan. On a PROCEED, scan what the tool RETURNED for hostile
   * markers (injection / exfil / credential) and, under GUARD (default) / STRICT,
   * WITHHOLD a tainted result (a HOLD whose verdict is NOT a contract diff). The
   * call already executed — the WITHHOLD keeps the tainted content from hijacking
   * the agent's NEXT action. MONITOR notifies (stderr) and proceeds. The TS twin
   * of Python `wrap(..., scan_results=...)`. */
  scanResults?: boolean;
}

// Raw transport seams we REFUSE to delegate (defense-in-depth) — so a caller
// cannot hand-assemble a tools/call frame straight to the socket, bypassing the
// gated `callTool` / `request` / `requestStream` chokepoints. Mirrors the Python
// `_DENY_DELEGATION` set, but adapted to the TS SDK's ACTUAL seams.
//
// CRITICAL (audit H1): the TS SDK `Protocol` base exposes a PUBLIC `get transport()`
// returning the live `Transport`, whose `.send(message)` accepts ANY JSONRPCMessage.
// Left delegated, a caller could do `wrapped.transport.send({...tools/call...})` and
// invoke a DRIFTED tool straight to the socket — a real bypass of the STATED defense
// in this file's docstring. So `transport` MUST be denied through the wrapper (returns
// undefined). This is SAFE: transport lifecycle (connect/close) is owned by whoever
// created the session — `Protocol.connect()` takes the transport as an ARGUMENT and
// writes the private `_transport`; `close()` reads `_transport` directly — neither
// reaches the wrapper's `transport` accessor. No legitimate tool-operation path in the
// integration tests or the documented public API needs `wrapped.transport`.
//
// `_transport` is denied for the same reason; `send` is denied defensively in case a
// future SDK surfaces a raw send on the session itself (no public `send` exists on the
// Protocol/Client today — it lives only on the `Transport` reached via `transport`).
// The Python SDK names (`_read_stream`/`_write_stream`/anyio readers) do NOT exist on
// the TS SDK — they were vestigial copies and are DROPPED (audit L1: keep the list
// honest, only real seams).
const DENY_DELEGATION: ReadonlySet<string> = new Set([
  "transport",
  "_transport",
  "send",
]);

type AnyFn = (...args: unknown[]) => unknown;

interface SessionLike {
  listTools(...args: unknown[]): unknown;
  callTool(...args: unknown[]): unknown;
  request?(...args: unknown[]): unknown;
  requestStream?(...args: unknown[]): AsyncGenerator<unknown>;
  [k: string]: unknown;
}

/** The SDK's `experimental` accessor shape — the only part we touch. `tasks`
 * exposes two tool-invoking stream surfaces (`callToolStream`, `requestStream`),
 * both desugaring to `requestStream({method:'tools/call'})` on the UNWRAPPED
 * client; we re-route both through the gate. */
interface ExperimentalTasksLike {
  callToolStream(...args: unknown[]): AsyncGenerator<unknown>;
  requestStream(...args: unknown[]): AsyncGenerator<unknown>;
  [k: string]: unknown;
}
interface ExperimentalLike {
  tasks: ExperimentalTasksLike;
  [k: string]: unknown;
}

/** Pull PUBLIC tool definitions out of whatever `listTools()` returned. Tolerant
 * (the listing is attacker-derived): a `{tools: [...]}` object, a bare list, each
 * entry a dict or an SDK Tool object. Normalizes to the PUBLIC-contract dict. */
function toolsFromResult(result: unknown): ToolDef[] {
  let raw: unknown;
  if (result !== null && typeof result === "object" && !Array.isArray(result)) {
    raw = (result as Record<string, unknown>)["tools"];
  } else {
    raw = result;
  }
  if (!Array.isArray(raw)) return [];
  const out: ToolDef[] = [];
  for (const entry of raw) {
    const defn = toolToDict(entry);
    if (defn !== null) out.push(defn);
  }
  return out;
}

function attrOrKey(entry: unknown, key: string): unknown {
  if (entry !== null && typeof entry === "object") {
    return (entry as Record<string, unknown>)[key];
  }
  return undefined;
}

function toolToDict(entry: unknown): ToolDef | null {
  const name = attrOrKey(entry, "name");
  if (typeof name !== "string" || !name) return null;
  const desc = attrOrKey(entry, "description");
  const schema = attrOrKey(entry, "inputSchema");
  const inSch = schema !== null && typeof schema === "object" && !Array.isArray(schema) ? schema : {};
  const record: ToolDef = {
    name,
    description: desc !== undefined && desc !== null ? String(desc) : "",
    inputSchema: inSch,
  };
  const ann = attrOrKey(entry, "annotations");
  if (ann !== null && typeof ann === "object" && !Array.isArray(ann)) record["annotations"] = ann;
  const outp = attrOrKey(entry, "outputSchema");
  if (outp !== null && typeof outp === "object" && !Array.isArray(outp)) record["outputSchema"] = outp;
  return record;
}

/** DUCK-TYPE a `request` argument -> (method, toolName). The TS SDK passes a
 * `{method, params}` request object. FAIL-CLOSED: a `tools/call` whose name
 * cannot be read runs under "" -> the no-pin path fail-closes. */
function requestMethodAndTool(request: unknown): [string | null, string] {
  try {
    const root = request as Record<string, unknown>;
    const method = root?.["method"];
    const methodStr = typeof method === "string" ? method : null;
    if (methodStr !== "tools/call") return [methodStr, ""];
    const params = root["params"] as Record<string, unknown> | undefined;
    const name = params?.["name"];
    return ["tools/call", typeof name === "string" ? name : ""];
  } catch {
    return ["tools/call", ""];
  }
}

function cursorOfList(args: unknown[]): string | null {
  const first = args[0];
  if (first !== null && typeof first === "object" && "cursor" in first) {
    return cursorText((first as { cursor?: unknown }).cursor);
  }
  return null;
}

function cursorOfRequest(request: unknown): string | null {
  if (request === null || typeof request !== "object") return null;
  const params = (request as { params?: unknown }).params;
  if (params === null || typeof params !== "object") return null;
  return cursorText((params as { cursor?: unknown }).cursor);
}

function cursorText(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function carriesTools(result: unknown): boolean {
  if (result === null || typeof result !== "object") return false;
  const obj = result as Record<string, unknown>;
  const inner = obj["result"];
  if (inner !== null && typeof inner === "object" && !Array.isArray(inner)) {
    return "tools" in inner;
  }
  return "tools" in obj;
}

function isThenable(v: unknown): v is Promise<unknown> {
  return v !== null && typeof v === "object" && typeof (v as { then?: unknown }).then === "function";
}

/** The intercepting core. Holds the shared Gate + the last-observed PUBLIC
 * contracts (so the Gate re-derives the live hash with no second round-trip) +
 * the optional on-device stores. NO token, NO transport. */
class Interceptor {
  private readonly gate: Gate;
  private readonly onHold: ((verdict: PreflightVerdict) => unknown) | null;
  private readonly autoValidateBehavior: boolean;
  // Opt-in (default OFF -> zero behavior change) runtime RESULT-content scan: on a
  // PROCEED, scan what the tool RETURNS for hostile markers and WITHHOLD a tainted
  // result under GUARD/STRICT. Posture is read off the shared gate (gate.posture) —
  // the pre-call decision already applied posture inside the gate.
  private readonly scanResults: boolean;
  private readonly stats: LocalStats | null;
  private readonly outcomes: OutcomeStore | null;
  // Ambient presence: a subtle "mcpindex is watching this" signal on the PROCEED path
  // (default-on, resolved from the env). NEVER touches stdout or the gate decision — it
  // rides stderr + the optional observer only. See `noteAmbient`.
  private readonly ambient: AmbientNotifier;
  private readonly observed = new Map<string, ToolDef>();
  private readonly withheldNames = new Set<string>();
  private listingNames = new Set<string>();
  private readonly onWithheld: WrapOptions["onWithheld"];
  private readonly lastSurface = new Map<string, string>();
  // The tier the LAST gated call for a tool ACTUALLY reached, for its provenance (mirrors the
  // Python wrapper's `_last_tier_reached`). AUDIT-LOW FLOOR FIX: tier_reached reflects what
  // RAN — an INCONCLUSIVE only OFFERED a behavioral check floors to 0 (→ STRUCTURAL_ONLY),
  // never a false BEHAVIORAL/3 stamp; 3 only when a behavioral verifier actually ran.
  private readonly lastTierReached = new Map<string, number>();

  constructor(
    readonly session: SessionLike,
    opts: WrapOptions,
  ) {
    this.onWithheld = opts.onWithheld ?? null;
    this.gate = new Gate({
      // With a serverId the default pin is a file under the state directory; without
      // one it stays in memory (see defaultPin). A fresh pin still pins on first observe.
      pin: opts.pin ?? this.defaultPin(opts),
      serverId: opts.serverId ?? DEFAULT_SERVER_ID,
      failOpen: opts.failOpen,
      autoAcceptBenign: opts.autoAcceptBenign,
      now: opts.now ?? utcNowIso,
      ownership: opts.ownership,
      behavioralMandatedKinds: opts.behavioralMandatedKinds ?? DEFAULT_BEHAVIORAL_MANDATED_KINDS,
      verifier: opts.verifier ?? null,
      posture: opts.posture,
      errors: opts.errors ?? null,
    });
    this.onHold = opts.onHold ?? null;
    this.autoValidateBehavior = opts.autoValidateBehavior ?? false;
    this.scanResults = opts.scanResults ?? false;
    this.stats = opts.stats ?? null;
    this.outcomes = opts.outcomes ?? null;
    // Ambient presence is default-ON (resolved from the env: master switch
    // MCPINDEX_AMBIENT_NOTICE, cadence MCPINDEX_AMBIENT_NOTICE_MODE; auto-quiet in CI /
    // under DO_NOT_TRACK). `onInvocation` lets an integrator render the signal in their
    // own UI. The notifier never touches stdout or the gate decision.
    this.ambient = AmbientNotifier.fromEnv({ observer: opts.onInvocation });
  }

  /** Emit the ambient "watching this tool" signal on the PROCEED path. Fully isolated and
   * best-effort: it writes ONLY to stderr + the observer (never stdout), never reads or
   * changes the gate decision or the call's return value, and never throws into the gated
   * call. The TS verdict carries the advisory Tier-0a `actionClassification` computed
   * locally by the gate from the live definition (default-on), or carried from a hosted
   * verdict; when neither is available it is null → "unknown", a faithful mirror of the
   * Python wrapper's fallback. */
  private noteAmbient(toolName: string, verdict: PreflightVerdict): void {
    try {
      this.ambient.noteInvocation(
        this.gate.serverId,
        toolName,
        verdict.actionClassification ?? undefined,
      );
    } catch {
      // an ambient signal must never perturb the gated call
    }
  }

  /** Emit the once-per-session ambient footer. Best-effort; never throws. */
  emitAmbientSummary(): void {
    try {
      this.ambient.sessionSummary();
    } catch {
      // exit cleanup must never raise
    }
  }

  private defaultPin(opts: WrapOptions): PreflightPin {
    if (opts.pinStore === "memory") return new PreflightPin();
    // Without a serverId every wrapped session would share one file under the
    // DEFAULT_SERVER_ID namespace, and two servers that both expose a tool named
    // `search` would collide. Keep that case in memory unless the caller opts in.
    if (opts.serverId === undefined && opts.pinStore !== "file") return new PreflightPin();
    return new PreflightPin(defaultPinStorePath(opts.serverId ?? DEFAULT_SERVER_ID));
  }

  // ------------------------------------------------------------- list_tools
  // The SDK client's listChanged handler calls listTools on the inner client,
  // so that refresh is not filtered here.
  listTools(target: SessionLike, args: unknown[]): unknown {
    const window = this.openListingWindow(cursorOfList(args));
    const result = (target.listTools as AnyFn).apply(target, args);
    if (isThenable(result)) return result.then((r) => this.filterList(r, window));
    return this.filterList(result, window);
  }

  private openListingWindow(cursor: string | null): Set<string> {
    if (cursor === null) this.listingNames = new Set();
    return this.listingNames;
  }

  private filterList(result: unknown, window: Set<string>): unknown {
    try {
      if (!carriesTools(result)) return result;
      const raw = rawToolEntries(result);
      if (raw.length > MAX_LISTED_TOOLS) {
        this.gate.captureError(new Error("listing over cap"), Operation.LIST_TOOLS, "wrap.listTools");
        return replaceToolList(result, []);
      }
      this.observe(result);
      if (this.gate.posture === Posture.MONITOR) return result;
      const outcome = filterListing(this.gate, raw, window);
      this.emitWithheld(outcome.withheld);
      if (outcome.kept.length === raw.length && outcome.kept.every((entry, i) => entry === raw[i])) {
        return result;
      }
      return replaceToolList(result, outcome.kept);
    } catch (exc) {
      this.gate.captureError(exc, Operation.LIST_TOOLS, "wrap.listTools");
      try {
        return replaceToolList(result, []);
      } catch (second) {
        this.gate.captureError(second, Operation.LIST_TOOLS, "wrap.listTools");
        return { tools: [] };
      }
    }
  }

  private emitWithheld(notices: { serverId: string; toolName: string; reason: string; definitionHash: string }[]): void {
    for (const notice of notices) {
      this.withheldNames.add(notice.toolName);
      if (this.onWithheld == null) continue;
      try {
        this.onWithheld(notice.serverId, notice.toolName, notice.reason, notice.definitionHash);
      } catch {
        // a hook must not break the list
      }
    }
  }

  private observe(result: unknown): void {
    try {
      const tools = toolsFromResult(result);
      for (const defn of tools) {
        const name = defn["name"] as string;
        this.observed.set(name, defn);
        this.gate.observe(name, defn);
      }
    } catch (exc) {
      this.gate.captureError(exc, Operation.LIST_TOOLS, "wrap.observe");
    }
  }

  // -------------------------------------------------------------- call_tool
  callTool(target: SessionLike, args: unknown[]): unknown {
    // SDK: callTool(params, resultSchema?, options?), params = {name, arguments}.
    const params = (args[0] ?? {}) as Record<string, unknown>;
    const name = typeof params["name"] === "string" ? (params["name"] as string) : "";
    const verdict = this.decideOrInternalHold(name, Operation.CALL_TOOL);
    if (verdict.decision === Decision.PROCEED) {
      if (verdict.failOpenWarning) warn(verdict);
      this.noteAmbient(name, verdict);
      return this.gateResult(name, (target.callTool as AnyFn).apply(target, args));
    }
    return this.refuseAsync(name, verdict);
  }

  // ----------------------------------------------------- post-call result scan
  /** Opt-in runtime RESULT scan on the PROCEED path. The tool call ALREADY ran (a
   * result-taint cannot un-ring that bell); this scans what it RETURNED for hostile
   * markers and, under GUARD/STRICT, WITHHOLDS a tainted result (a HOLD) so the
   * answer cannot hijack the agent's NEXT action. Default OFF (`this.scanResults`)
   * -> a pure pass-through. Both SDK seams (`callTool`/`request`) return a Promise,
   * so we attach to it: scan after it resolves, returning the result on clean and
   * applying posture on a taint. The TS twin of Python `_gate_result`. */
  private gateResult(name: string, result: unknown): unknown {
    if (!this.scanResults) return result;
    if (!isThenable(result)) {
      // Defensive: an SDK seam that returned a non-Promise still gets scanned (the
      // sync twin of Python's `_gate_result_sync`). Returns the result or throws a
      // synchronous PreflightHold under GUARD/STRICT.
      return this.gateResultValue(name, result);
    }
    return result.then((value) => this.gateResultValue(name, value));
  }

  /** Scan a concrete result; return it when clean, else apply posture. FAIL-CLOSED:
   * a bug in OUR scanner degrades to a withholding HOLD (under GUARD/STRICT) — it
   * never returns an unscanned result and never crashes the agent's call (matching
   * the gate's graceful-fail ethos). Mirrors Python `_gate_result_sync`. */
  private gateResultValue(name: string, result: unknown): unknown {
    let scan: ResultScan;
    try {
      scan = scanResult(attrOrKey(result, "content"), attrOrKey(result, "structuredContent"));
    } catch (exc) {
      this.gate.captureError(exc, Operation.CALL_TOOL, "wrap.gateResult");
      return this.withholdOrProceed(name, "result scanner internal error (fail-closed)", result);
    }
    if (scan.taint !== null) {
      return this.withholdOrProceed(name, `${scan.taint.reason} at ${scan.taint.location}`, result);
    }
    if (scan.truncated) {
      // Clean as far as read, but a string exceeded the scan cap so its tail was NOT scanned.
      // Never imply 'fully clean' — withhold under STRICT (strictOnly), notify under GUARD/MONITOR.
      return this.withholdOrProceed(
        name,
        "result exceeded the scan cap; tail unscanned",
        result,
        true,
      );
    }
    return result;
  }

  /** Posture decision for a tainted/unscannable result, reading the gate's LIVE
   * posture (single source of truth). A taint / scanner-error WITHHOLDS under
   * GUARD (default) + STRICT; a merely TRUNCATED-clean result (`strictOnly=true`)
   * withholds only under STRICT and notifies+proceeds under GUARD/MONITOR. (So:
   * notify+proceed when posture===MONITOR OR (posture===GUARD && strictOnly); else
   * withhold.) Withholding routes through the SAME provenance-choked HOLD surface
   * as a contract hold (so the over-claim guard still runs) — but the verdict is
   * NOT a contract diff (`isContractDiff: false`, the TS mirror of Python's
   * `is_contract_diff=False`). `markerNote` is SECRET-FREE (marker CLASS + json-path
   * location, never the raw returned payload). When an `onHold` callback is set we
   * return its result (mirroring `refuseAsync`); otherwise we throw the
   * PreflightHold so the caller's `.catch`/rejection sees the withhold. Mirrors
   * Python `_withhold_or_proceed`. */
  private withholdOrProceed(
    name: string,
    markerNote: string,
    result: unknown,
    strictOnly = false,
  ): unknown {
    const posture = this.gate.posture;
    const notifyAndProceed =
      posture === Posture.MONITOR || (posture === Posture.GUARD && strictOnly);
    if (notifyAndProceed) {
      this.noteResultTaint(name, markerNote);
      return result;
    }
    const verdict = makeVerdict({
      serverId: this.gate.serverId,
      toolName: name,
      decision: Decision.HOLD,
      reason:
        `tool RESULT WITHHELD (${markerNote}); the call already executed — the returned ` +
        `content is held so it cannot influence the agent (a result issue, NOT a contract diff)`,
      isContractDiff: false,
      // The ONLY place this is true: the tool ran and we are withholding what it returned.
      alreadyExecuted: true,
      holdClass: HoldClass.WITHHELD, // the call ran; its result is held
    });
    if (this.onHold !== null) return this.onHold(verdict);
    const [prov, banner, presentation] = this.heldSurface(name, verdict);
    throw new PreflightHold(verdict, prov, banner, presentation);
  }

  /** MONITOR-posture notice: surface the result-taint to stderr (never stdout, never
   * the gate decision), best-effort, then proceed. Mirrors the ambient channel's
   * stderr-only rule and Python `_note_result_taint`. */
  private noteResultTaint(name: string, markerNote: string): void {
    try {
      process.stderr.write(
        `⚡ mcpindex: tool '${name}' RESULT matched a hostile marker (${markerNote}) ` +
          `— MONITOR posture: proceeding. Use posture=GUARD to withhold.\n`,
      );
    } catch {
      // a notice must never perturb the call
    }
  }

  // ------------------------------------------------------------ request
  request(target: SessionLike, args: unknown[]): unknown {
    const reqFn = target.request;
    if (typeof reqFn !== "function") {
      throw new TypeError("wrapped session has no request() method");
    }
    const [method, toolName] = requestMethodAndTool(args[0]);
    if (method === "tools/list") {
      const window = this.openListingWindow(cursorOfRequest(args[0]));
      const result = (reqFn as AnyFn).apply(target, args);
      if (isThenable(result)) return result.then((r) => this.filterList(r, window));
      return this.filterList(result, window);
    }
    if (method !== "tools/call") {
      return (reqFn as AnyFn).apply(target, args);
    }
    const verdict = this.decideOrInternalHold(toolName, Operation.SEND_REQUEST);
    if (verdict.decision === Decision.PROCEED) {
      if (verdict.failOpenWarning) warn(verdict);
      this.noteAmbient(toolName, verdict);
      // Parity: scan the raw-RPC result too. `request({method:'tools/call'}, CallToolResultSchema)`
      // resolves a CallToolResult (the SAME shape `gateResult` extracts content/structuredContent
      // from). A transport/schema that resolves a raw envelope instead -> content/structuredContent
      // absent -> not scanned (v1 boundary, documented; the pre-call gate still covers the call).
      return this.gateResult(toolName, (reqFn as AnyFn).apply(target, args));
    }
    // The SDK `request()` is async (returns a Promise<SchemaOutput>), so — like
    // `callTool` — a HOLD must surface as a REJECTED Promise, not a sync throw,
    // or the wrapper is not a transparent drop-in (a caller's `await`/`.catch`
    // would miss the hold). Refusal goes through the SAME `refuseAsync` as
    // `callTool` (one shared block, mirroring Python's shared refusal): same
    // onHold dispatch, same provenance/banner, same PreflightHold; the wrapped
    // session is NEVER touched on this path.
    return this.refuseAsync(toolName, verdict);
  }

  // ------------------------------------------------------- requestStream
  /** Gate the EXPERIMENTAL streaming RPC chokepoint. `requestStream` takes the
   * same `{method, params}` request shape as `request`, so we parse + gate a
   * `tools/call` identically. The SDK signature returns an AsyncGenerator, so
   * the gate must surface PRE-FLIGHT: a HELD verdict returns a generator that
   * THROWS on first iteration WITHOUT ever delegating to the upstream stream
   * (the real `requestStream` is never called -> upstream touched 0 times,
   * fail-closed). A non-`tools/call` (or PROCEED) delegates the real generator
   * untouched. `streamFn` is the upstream `requestStream` bound to the right
   * receiver (the raw session for the session-level seam; the SDK's own
   * `_client` for the experimental seam, which it captured itself). */
  requestStream(streamFn: AnyFn, receiver: unknown, args: unknown[]): AsyncGenerator<unknown> {
    const [method, toolName] = requestMethodAndTool(args[0]);
    if (method !== "tools/call") {
      return streamFn.apply(receiver, args) as AsyncGenerator<unknown>;
    }
    const verdict = this.decideOrInternalHold(toolName, Operation.SEND_REQUEST);
    if (verdict.decision === Decision.PROCEED) {
      if (verdict.failOpenWarning) warn(verdict);
      return streamFn.apply(receiver, args) as AsyncGenerator<unknown>;
    }
    return this.refuseStream(toolName, verdict);
  }

  /** A HELD streaming seam: an async generator that raises the SAME
   * `PreflightHold` (or onHold result) as `refuseAsync`, on first iteration,
   * before the upstream stream is ever opened. Shares `heldSurface` / `onHold`
   * with the async refusal block so streaming and non-streaming holds are
   * byte-for-byte identical (same provenance, banner, PreflightHold). */
  private async *refuseStream(name: string, verdict: PreflightVerdict): AsyncGenerator<unknown> {
    if (this.onHold !== null) {
      yield await Promise.resolve(this.onHold(verdict));
      return;
    }
    const [prov, banner, presentation] = this.heldSurface(name, verdict);
    throw new PreflightHold(verdict, prov, banner, presentation);
  }

  /** Build a gated mirror of the SDK's `experimental` accessor. The SDK's
   * `experimental.tasks` holds the UNWRAPPED client, so its `callToolStream` /
   * `requestStream` bypass the proxy and hit `_client.requestStream` directly.
   * We re-route BOTH tool-invoking stream surfaces through `this.requestStream`
   * (the same gate as the session-level seam) by calling the SDK's own methods
   * — preserving their task-augmentation / output-schema-validation behaviour —
   * but only AFTER a PROCEED verdict; a HELD verdict throws before any upstream
   * stream is opened. Every non-stream member of `tasks` (getTask, listTasks,
   * cancelTask, …) and the rest of `experimental` delegate UNTOUCHED. */
  wrapExperimental(real: ExperimentalLike): ExperimentalLike {
    const self = this;
    const realTasks = real.tasks;
    const tasksProxy = new Proxy(realTasks, {
      get(t, prop, _recv) {
        if (prop === "callToolStream") {
          // callToolStream(params, resultSchema?, options?) desugars to
          // requestStream({method:'tools/call', params}, ...). Gate on params.name
          // PRE-FLIGHT; only on PROCEED do we invoke the SDK's real
          // callToolStream (so its task/output-schema logic is preserved).
          return (...a: unknown[]): AsyncGenerator<unknown> => {
            const params = (a[0] ?? {}) as Record<string, unknown>;
            const toolName = typeof params["name"] === "string" ? (params["name"] as string) : "";
            const verdict = self.decideOrInternalHold(toolName, Operation.SEND_REQUEST);
            if (verdict.decision === Decision.PROCEED) {
              if (verdict.failOpenWarning) warn(verdict);
              return (realTasks.callToolStream as AnyFn).apply(realTasks, a) as AsyncGenerator<unknown>;
            }
            return self.refuseStream(toolName, verdict);
          };
        }
        if (prop === "requestStream") {
          // tasks.requestStream(request, ...) takes the raw {method,params} shape —
          // route it through the SAME gate as the session-level seam, delegating
          // the real method (bound to realTasks) on PROCEED.
          return (...a: unknown[]): AsyncGenerator<unknown> =>
            self.requestStream(realTasks.requestStream as AnyFn, realTasks, a);
        }
        const v = Reflect.get(t, prop, t);
        return typeof v === "function" ? (v as AnyFn).bind(t) : v;
      },
    });
    return new Proxy(real, {
      get(t, prop, _recv) {
        if (prop === "tasks") return tasksProxy;
        const v = Reflect.get(t, prop, t);
        return typeof v === "function" ? (v as AnyFn).bind(t) : v;
      },
    }) as ExperimentalLike;
  }

  /** The SINGLE refusal path for BOTH gated async seams (`callTool` and the
   * low-level `request` chokepoint) — the TS analog of the one refusal block
   * Python's `call_tool` / `send_request` share. Both SDK seams return a Promise,
   * so a HOLD surfaces as a REJECTED Promise (never a sync throw), so the wrapper
   * stays a transparent drop-in: a caller's `await` / `.catch` sees the hold. The
   * wrapped session is NEVER touched on this path (fail-closed). When an `onHold`
   * callback is set we return its result resolved to a Promise, so a caller that
   * suppresses the throw still gets a thenable like the upstream would yield. */
  private refuseAsync(name: string, verdict: PreflightVerdict): Promise<unknown> {
    if (this.onHold !== null) return Promise.resolve(this.onHold(verdict));
    const [prov, banner, presentation] = this.heldSurface(name, verdict);
    return Promise.reject(new PreflightHold(verdict, prov, banner, presentation));
  }

  private decideOrInternalHold(name: string, operation: Operation): PreflightVerdict {
    if (this.withheldNames.has(name)) {
      const verdict = makeVerdict({
        serverId: this.gate.serverId,
        toolName: name,
        decision: Decision.HOLD,
        reason: WITHHELD_CALL_REASON,
        isContractDiff: false,
        holdClass: HoldClass.UNCHECKABLE,
      });
      this.recordCall(name, verdict, verdict);
      return verdict;
    }
    try {
      const assessed = this.gate.assess(name, this.observed.get(name) ?? null);
      const committed = this.gate.commit(assessed[0], assessed[2]);
      let stat = this.maybeAutoValidate(name, committed[0]);
      const verdict = this.gate.applyPosture(stat);
      this.recordCall(name, stat, verdict);
      return verdict;
    } catch (exc) {
      this.gate.captureError(exc, operation, "wrap.decideOrInternalHold");
      return this.gate.internalErrorVerdict(name);
    }
  }

  private maybeAutoValidate(name: string, stat: PreflightVerdict): PreflightVerdict {
    if (stat.decision === Decision.INCONCLUSIVE && this.autoValidateBehavior && this.gate.verifier !== null) {
      const [resolved, outcome] = this.gate.runBehavioralOutcome(
        name,
        this.observed.get(name) ?? null,
        stat,
        this.gate.verifier,
      );
      // Behaviour ACTUALLY ran. Record tier 3 ONLY for an OBSERVED result — CLEARED or FAILED.
      // UNAVAILABLE / DECLINED / never-consulted observed nothing → floor to 0. The tier is
      // keyed on the STRUCTURED outcome enum, NEVER on the verifier-controlled reason string (a
      // substring check there would let an UNAVAILABLE whose reason contains "behavioral
      // validation FAILED" forge a tier-3 stamp on evidence that never ran).
      this.lastTierReached.set(name, behaviourObserved(outcome) ? 3 : 0);
      return resolved;
    }
    // INCONCLUSIVE only OFFERED a behavioral check (no auto-validate / no verifier) → nothing
    // ran → floor to 0 (the audit-LOW floor fix). Any other static verdict is tier 0 too.
    this.lastTierReached.set(name, 0);
    return stat;
  }

  // ------------------------------------------------------------- stats record
  private recordCall(name: string, stat: PreflightVerdict, effective: PreflightVerdict): void {
    if (this.stats !== null) {
      if (effective.decision === Decision.HOLD || effective.decision === Decision.INCONCLUSIVE) {
        this.stats.recordHold();
      }
    }
    this.captureOutcome(name, stat, effective);
  }

  private captureOutcome(name: string, stat: PreflightVerdict, effective: PreflightVerdict): void {
    if (this.outcomes === null) return;
    if (isInternalErrorVerdict(effective) || isInternalErrorVerdict(stat)) return;
    if (effective.decision === Decision.HOLD || effective.decision === Decision.INCONCLUSIVE) {
      const prov = this.provenanceFor(name, effective);
      if (prov === null) return;
      this.lastSurface.set(name, this.outcomes.recordSurface(prov, this.gate.posture));
    } else if (
      effective.decision === Decision.PROCEED &&
      (stat.decision === Decision.HOLD || stat.decision === Decision.INCONCLUSIVE) &&
      stat.drift.length > 0
    ) {
      const prov = this.provenanceFor(name, stat);
      if (prov === null) return;
      const sid = this.outcomes.recordSurface(prov, this.gate.posture);
      this.lastSurface.set(name, sid);
      this.outcomes.recordResponse(sid, Action.OVERRIDE);
    }
  }

  private provenanceFor(name: string, verdict: PreflightVerdict): Provenance | null {
    const pinned = this.gate.pinFor(name);
    return surfaceProvenance(verdict, {
      serverId: this.gate.serverId,
      tool: name,
      oldSchema: pinned !== null ? pinned.schema : null,
      newSchema: this.observed.get(name) ?? null,
      tierReached: this.lastTierReached.get(name) ?? 0,
      source: "wrapper",
    });
  }

  private heldSurface(
    name: string,
    verdict: PreflightVerdict,
    sentKeys: readonly string[] | null = null,
  ): [Provenance | null, string, string | null] {
    if (isInternalErrorVerdict(verdict)) return [null, INTERNAL_ERROR_HELD_MESSAGE, null];
    const prov = this.provenanceFor(name, verdict);
    // BOTH slots, deliberately. Returning null for presentation would make `holdBanner()`
    // fall back to the AGENT string and orphan the human banner - which is what the first cut
    // of this fix did. Splitting one constant into two is only half the job; the consumer that
    // CHOOSES between them is the other half, and it is where this family keeps landing.
    if (prov === null) {
      return [null, HELD_PROVENANCE_UNAVAILABLE_MESSAGE, HELD_PROVENANCE_UNAVAILABLE_BANNER];
    }
    const tally = this.stats !== null ? this.stats.holdsThisMonth() : null;
    // Two readers, two strings: the agent gets evidence it can reconcile, the human keeps
    // the brand moment. See `renderHoldMessage`.
    // pinPath is null here BY DESIGN, not by omission: the TS `PreflightPin` is a pure
    // in-memory Map (see preflight.ts) with no on-disk location, so the "checkable locally"
    // anchor has nothing true to point at. The Python proxy, whose pin IS a file, renders
    // it. Naming a path that does not exist would forfeit exactly the credibility the line
    // is there to buy.
    return [
      prov,
      renderHoldMessage(verdict, sentKeys, this.gate.pinPath),
      renderHoldBanner(verdict, tally),
    ];
  }

  /** The HUMAN brand-moment banner. Unchanged surface, unchanged text - `holdBanner` has
   * always been the presentational one, and callers rendering it for a person still get
   * exactly what they got before. */
  holdBanner(verdict: PreflightVerdict): string {
    const [, agentMessage, presentation] = this.heldSurface(verdict.toolName, verdict);
    // FAIL-CLOSED, and the whole point of the provenance choke: a null presentation means
    // either an internal-error verdict or a provenance refusal. Falling back to
    // `renderHoldBanner` there would render the FULL detail banner for both - asserting a
    // specific contract change that, in the internal-error case, never happened. Return the
    // generic agent-channel string the choke already produced, exactly as Python does.
    return presentation ?? agentMessage;
  }

  // ----------------------------------------------------- behavioral validation
  validateBehaviorNow(toolName: string, verifier?: BehavioralVerifier): PreflightVerdict {
    const observed = this.observed.get(toolName) ?? null;
    const verdict = this.gate.evaluate(toolName, observed);
    if (verdict.decision === Decision.PROCEED) return verdict;
    const chosen = verifier ?? this.gate.verifier;
    if (chosen === null || chosen === undefined) return verdict;
    this.recordOutcomeResponse(toolName, Action.ESCALATE);
    const [resolved, outcome] = this.gate.runBehavioralOutcome(toolName, observed, verdict, chosen);
    // Behaviour ACTUALLY ran on demand (the third door) — record tier 3 ONLY for an OBSERVED
    // result (CLEARED or FAILED). UNAVAILABLE / DECLINED / never-consulted floor to 0. Keyed on
    // the STRUCTURED outcome enum, NEVER on the verifier-controlled reason string (mirrors the
    // Python wrapper).
    if (behaviourObserved(outcome)) {
      this.lastTierReached.set(toolName, 3);
    }
    if (resolved.decision === Decision.PROCEED) this.withheldNames.delete(toolName);
    return resolved;
  }

  // ------------------------------------------------------------------- repin
  repin(tool?: string): PinnedTool[] {
    const written: PinnedTool[] = [];
    const names = tool !== undefined ? [tool] : [...this.observed.keys()].sort();
    for (const name of names) {
      const observed = this.observed.get(name);
      if (observed === undefined) continue;
      written.push(this.gate.repinOne(name, observed));
      this.withheldNames.delete(name);
      if (this.stats !== null) this.stats.recordRepin();
      this.recordOutcomeResponse(name, Action.REPIN);
    }
    return written;
  }

  private recordOutcomeResponse(name: string, action: Action): void {
    if (this.outcomes === null) return;
    const sid = this.lastSurface.get(name);
    if (sid === undefined) return;
    this.outcomes.recordResponse(sid, action);
  }
}

function warn(verdict: PreflightVerdict): void {
  process.stderr.write(
    `preflight WARNING fail-open: PROCEED on un-checkable tool ` +
      `${verdict.serverId}/${verdict.toolName} — ${verdict.reason}\n`,
  );
}

// The wrapper's OWN management methods — names that shadow delegation.
const OWN_METHODS = new Set(["repin", "validateBehaviorNow", "holdBanner", "__interceptor__"]);

/** Wrap an already-authenticated MCP client session. Returns a TRANSPARENT
 * drop-in `Proxy` with the same surface: `listTools` / `callTool` are gated and
 * the low-level `request` chokepoint gates a `tools/call`; EVERY other method is
 * delegated UNTOUCHED. NO credential is read, stored, or transmitted.
 *
 * `T` is the wrapped session type (e.g. the SDK `Client`); the return type adds
 * the wrapper's management methods (`repin` / `validateBehaviorNow` /
 * `holdBanner`).
 *
 * `opts` is OPTIONAL. `wrap(session)` keeps pins in a file under the state
 * directory (see `defaultPinStorePath`) and HOLDs on drift. Pass
 * `{ pinStore: "memory" }` for an in-process store, or `{ pin, serverId }` to
 * supply the store. Pass `{ scanResults, onHold, onWithheld, posture }` to tune
 * the gate. Under guard and strict, `listTools` leaves out a tool whose
 * description or input-schema text changed. The SDK client's listChanged
 * refresh calls the inner client and is not filtered. */
export type Wrapped<T> = T & {
  repin(tool?: string): PinnedTool[];
  validateBehaviorNow(toolName: string, verifier?: BehavioralVerifier): PreflightVerdict;
  holdBanner(verdict: PreflightVerdict): string;
  readonly __interceptor__: unknown;
};

export function wrap<T extends object>(session: T, opts: WrapOptions = {}): Wrapped<T> {
  const sess = session as unknown as SessionLike;
  const interceptor = new Interceptor(sess, opts);

  const handler: ProxyHandler<SessionLike> = {
    get(target, prop, _receiver) {
      if (typeof prop !== "string") {
        return Reflect.get(target, prop, target);
      }
      if (prop === "__interceptor__") return interceptor;
      if (prop === "listTools") {
        return (...args: unknown[]): unknown => interceptor.listTools(target, args);
      }
      if (prop === "callTool") {
        return (...args: unknown[]): unknown => interceptor.callTool(target, args);
      }
      if (prop === "request") {
        return (...args: unknown[]): unknown => interceptor.request(target, args);
      }
      if (prop === "requestStream") {
        // The experimental streaming RPC chokepoint, reachable directly on the
        // session. Gate a tools/call here too (parity with `request`), binding
        // the real upstream `requestStream` to the raw target.
        return (...args: unknown[]): AsyncGenerator<unknown> => {
          const fn = Reflect.get(target, "requestStream", target);
          if (typeof fn !== "function") {
            throw new TypeError("wrapped session has no requestStream() method");
          }
          return interceptor.requestStream(fn as AnyFn, target, args);
        };
      }
      if (prop === "experimental") {
        // The SDK `experimental` accessor returns an object whose `tasks` holds
        // the UNWRAPPED client; left untouched it bypasses the gate. Return a
        // gated mirror so `tasks.callToolStream` / `tasks.requestStream` run
        // through the SAME gate as the session seams.
        const real = Reflect.get(target, "experimental", target);
        if (real === null || typeof real !== "object") return real;
        return interceptor.wrapExperimental(real as ExperimentalLike);
      }
      if (prop === "close") {
        // The SDK `Protocol.close()` is the wrapper's natural session-dispose hook (the
        // TS analog of Python's context-manager `__exit__`). Emit the once-per-session
        // ambient footer BEFORE delegating the real close — best-effort, never throws,
        // stderr/observer only. If the session exposes no `close`, delegate untouched.
        const realClose = Reflect.get(target, "close", target);
        if (typeof realClose !== "function") return realClose;
        return (...args: unknown[]): unknown => {
          interceptor.emitAmbientSummary();
          return (realClose as AnyFn).apply(target, args);
        };
      }
      if (prop === "repin") {
        return (tool?: string): PinnedTool[] => interceptor.repin(tool);
      }
      if (prop === "validateBehaviorNow") {
        return (toolName: string, verifier?: BehavioralVerifier): PreflightVerdict =>
          interceptor.validateBehaviorNow(toolName, verifier);
      }
      if (prop === "holdBanner") {
        return (verdict: PreflightVerdict): string => interceptor.holdBanner(verdict);
      }
      if (DENY_DELEGATION.has(prop)) {
        // Defense-in-depth: refuse to delegate the raw transport seams.
        return undefined;
      }
      // Delegate everything else UNTOUCHED. Bind methods to the real target so
      // `this` inside the SDK points at the real session, never the proxy.
      const value = Reflect.get(target, prop, target);
      if (typeof value === "function") {
        return (value as AnyFn).bind(target);
      }
      return value;
    },
    has(target, prop) {
      if (typeof prop === "string" && OWN_METHODS.has(prop)) return true;
      return Reflect.has(target, prop);
    },
  };

  return new Proxy(sess, handler) as unknown as Wrapped<T>;
}

/** Module-level convenience: re-pin observed contracts on a wrapped session. */
export function repin<T extends object>(wrapped: Wrapped<T>, tool?: string): PinnedTool[] {
  return wrapped.repin(tool);
}
