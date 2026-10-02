/**
 * The shared GATE core — the pure pre-flight decision, decoupled from any I/O
 * seam. A faithful port of Python `tooling/cse/gate.py`. Pin TOFU, derive the
 * live contract hash, compare to the pin, and on drift VALIDATE -> DECIDE
 * (benign auto-accept / behavioral-mandated INCONCLUSIVE / HOLD), then apply the
 * per-server POSTURE. NO credential, NO transport, NO network: the Gate reads
 * only the PUBLIC contract dict the caller observed.
 */

import {
  Decision,
  HoldClass,
  PreflightPin,
  hashTool,
  makeVerdict,
  utcNowIso,
} from "./preflight.js";
import type { PinnedTool, PreflightVerdict, ToolDef } from "./preflight.js";
import {
  ChangeKind,
  classifyChange,
  isNumericOnlyDescriptionChange,
  isSafetyRelevant,
} from "./schemaDiff.js";
import type { Change } from "./schemaDiff.js";
import { assess, blastRank } from "./risk.js";
import { classifyToolDef } from "./actionClass.js";
import { scanSchemaHasMarker } from "./scan.js";
import { plainProse, plainText, stripControl } from "./render.js";
import { redactGreenWords } from "./provenance.js";
import { ErrorStore, Operation } from "./errors.js";
import { driftTelemetry } from "./driftTelemetry.js";
import { driftQuery } from "./driftQuery.js";

// ----------------------------------------------------------- behavioral mandate
const DEFAULT_BEHAVIORAL_MANDATED_KINDS: ReadonlySet<ChangeKind> = new Set([
  ChangeKind.OUTPUT_SCHEMA_CHANGED,
  ChangeKind.ANNOTATION_FLIP_TO_DESTRUCTIVE,
]);

// --------------------------------------------------------------- benign allowlist
const BENIGN_AUTOACCEPT_KINDS: ReadonlySet<ChangeKind> = new Set([
  ChangeKind.ADDED_OPTIONAL_PARAM,
  ChangeKind.TOOL_ADDED,
  ChangeKind.OUTPUT_SCHEMA_ADDED,
]);

export enum Posture {
  MONITOR = "monitor",
  GUARD = "guard",
  STRICT = "strict",
}

// The change kinds GUARD treats as UNAMBIGUOUS-DANGEROUS (block even in the
// lenient default posture). The full genuinely-BREAKING set.
const GUARD_DANGEROUS_KINDS: ReadonlySet<ChangeKind> = new Set([
  ChangeKind.ANNOTATION_FLIP_TO_DESTRUCTIVE,
  ChangeKind.ADDED_REQUIRED_PARAM,
  ChangeKind.REQUIRED_SET_EXPANDED,
  ChangeKind.REMOVED_PARAM,
  ChangeKind.TYPE_CHANGED,
  ChangeKind.ENUM_VALUES_REMOVED,
  ChangeKind.CONSTRAINT_NARROWED,
  ChangeKind.TOOL_REMOVED,
  ChangeKind.OUTPUT_SCHEMA_CHANGED,
  ChangeKind.DEEP_SCHEMA_UNDIFFABLE,
]);

const BREAKING_KIND_REASON: Partial<Record<ChangeKind, string>> = {
  [ChangeKind.OUTPUT_SCHEMA_CHANGED]:
    "this tool's output format changed — code or agents parsing its result may break",
  [ChangeKind.ANNOTATION_FLIP_TO_DESTRUCTIVE]:
    "this tool now declares itself able to modify or delete data (it did not before)",
  [ChangeKind.ADDED_REQUIRED_PARAM]:
    "this tool now requires a new parameter — existing calls that omit it will fail",
  [ChangeKind.REQUIRED_SET_EXPANDED]:
    "a parameter that used to be optional is now required — existing calls may fail",
  [ChangeKind.REMOVED_PARAM]: "a parameter your calls may rely on was removed or renamed",
  [ChangeKind.TYPE_CHANGED]:
    "a parameter's type changed — values your calls send may no longer be accepted",
  [ChangeKind.ENUM_VALUES_REMOVED]:
    "an allowed value was removed — a value your calls send may now be rejected",
  [ChangeKind.CONSTRAINT_NARROWED]:
    "an input rule was tightened — a value your calls send may now be rejected",
  [ChangeKind.PARAM_MIRRORED_TO_HEADER]:
    "a parameter's VALUE is now copied into an HTTP header — every proxy, CDN and " +
    "gateway between you and this server can read and log it",
  [ChangeKind.TOOL_REMOVED]: "this tool was removed from the server",
  [ChangeKind.DEEP_SCHEMA_UNDIFFABLE]:
    "this tool's schema changed too deeply to diff automatically; held rather than guessed",
};

const DANGEROUS_REASON_MARKERS: readonly string[] = [
  "risk ESCALATED",
  "injection/exfil marker",
  "could not complete",
  "DESCRIPTION changed",
  "behavioral validation FAILED",
  "behavioral validation UNAVAILABLE",
  "behavioral validation DECLINED",
];

const BRAND_MARK = "⬡ mcpindex";

export const HELD_PROVENANCE_UNAVAILABLE_BANNER =
  `${BRAND_MARK} — held a call before your agent ran it (provenance unavailable; no detail shown).`;

/** The AGENT-facing twin of the banner above. Same fact, no brand glyph, no chrome.
 *
 * INSTANCE FOURTEEN, found in round 9 and present in both languages. `heldSurface` has two
 * early returns, one line apart, that both put a constant in the AGENT-message position and
 * bypass `renderHoldMessage` entirely. Round 7 fixed the internal-error one and left this
 * sibling, which shipped the brand glyph to the agent channel - the exact tell the suite's
 * first test bans, and one the 2026-08-05 model named when it read the hold as a UI trying to
 * persuade it. That test only ever ran against the renderer.
 *
 * The banner keeps its glyph: a HUMAN still reads it via `holdBanner()`. One fact, two
 * readers, two renderings - the same split this whole change is about. */
export const HELD_PROVENANCE_UNAVAILABLE_MESSAGE =
  'mcpindex — local contract gate — held this call before your agent ran it. The record ' +
  'behind it could not be assembled, so no detail is shown.';

// NO AFFORDANCE, NO GREEN WORD - see the Python twin. `[Override]` points at
// `Action.OVERRIDE`, which bypasses the gate entirely: strictly stronger than the repin
// chips that were removed from this channel for exactly this reason.
export const INTERNAL_ERROR_HELD_MESSAGE =
  "mcpindex — local contract gate — mcpindex's own code failed, so this call was NOT sent " +
  "to the server. Nothing ran. This is our failure, not a finding about the tool.";

const INTERNAL_ERROR_REASON_HOLD = "mcpindex internal error — held for safety";

export function isInternalErrorVerdict(verdict: PreflightVerdict): boolean {
  return verdict.reason === INTERNAL_ERROR_REASON_HOLD;
}

export function internalErrorHold(serverId: string, toolName: string): PreflightVerdict {
  return makeVerdict({
    serverId,
    toolName,
    decision: Decision.HOLD,
    reason: INTERNAL_ERROR_REASON_HOLD,
    holdClass: HoldClass.INTERNAL, // our own code failed
    isContractDiff: false,
  });
}

export enum Ownership {
  OSS = "oss",
  DEV_OWNED = "dev_owned",
  UNOWNED_THIRD_PARTY = "unowned_third_party",
}

export enum BehavioralMethod {
  SANDBOX_BATTERY = "sandbox_battery",
  READ_ONLY_PROBE = "read_only_probe",
  DECLINED = "declined",
}

export function chooseBehavioralMethod(ownership: Ownership): BehavioralMethod {
  if (ownership === Ownership.OSS) return BehavioralMethod.SANDBOX_BATTERY;
  if (ownership === Ownership.DEV_OWNED) return BehavioralMethod.READ_ONLY_PROBE;
  return BehavioralMethod.DECLINED;
}

export enum BehavioralOutcome {
  CLEARED = "cleared",
  FAILED = "failed",
  UNAVAILABLE = "unavailable",
  DECLINED = "declined",
}

/**
 * True IFF the verifier ACTUALLY observed the tool's behaviour (CLEARED or FAILED).
 * UNAVAILABLE / DECLINED / null (verifier never consulted) all mean behaviour did NOT run, so
 * the evidence tier floors to STRUCTURAL_ONLY (0) — never a false BEHAVIORAL/3 stamp. This is
 * the ONE place tier-3 eligibility is decided, keyed on the structured enum, never on a
 * verifier-controlled reason string. Python mirror: `Gate._behaviour_observed`.
 */
export function behaviourObserved(outcome: BehavioralOutcome | null): boolean {
  return outcome === BehavioralOutcome.CLEARED || outcome === BehavioralOutcome.FAILED;
}

export interface BehavioralResult {
  readonly outcome: BehavioralOutcome;
  readonly method: BehavioralMethod;
  readonly reason: string;
}

export interface BehavioralVerifier {
  verify(
    serverId: string,
    toolName: string,
    toolDef: ToolDef,
    ownership: Ownership,
    method: BehavioralMethod,
  ): BehavioralResult;
}

// ---------------------------------------------------------- banner rendering
function ordinal(n: number): string {
  const mod100 = n % 100;
  let suffix: string;
  if (mod100 >= 10 && mod100 <= 20) suffix = "th";
  else suffix = ({ 1: "st", 2: "nd", 3: "rd" } as Record<number, string>)[n % 10] ?? "th";
  return `${n}${suffix}`;
}

function friendlyBreakingClause(verdict: PreflightVerdict): string | null {
  const present = new Set(verdict.drift.map((c) => c.kind));
  for (const kind of [
    ChangeKind.OUTPUT_SCHEMA_CHANGED,
    ChangeKind.ANNOTATION_FLIP_TO_DESTRUCTIVE,
    // Ordered with the "this tool now DOES something new" kinds, not the
    // param-contract breaks: the consequence is not a failing call, it is a value
    // leaving the request body. Must stay byte-identical to the Python order in
    // gate.py `_friendly_breaking_clause` or the two clients explain the same
    // server differently.
    ChangeKind.PARAM_MIRRORED_TO_HEADER,
    ChangeKind.ADDED_REQUIRED_PARAM,
    ChangeKind.REQUIRED_SET_EXPANDED,
    ChangeKind.REMOVED_PARAM,
    ChangeKind.TYPE_CHANGED,
    ChangeKind.ENUM_VALUES_REMOVED,
    ChangeKind.CONSTRAINT_NARROWED,
    ChangeKind.TOOL_REMOVED,
    ChangeKind.DEEP_SCHEMA_UNDIFFABLE,
  ]) {
    if (present.has(kind)) return BREAKING_KIND_REASON[kind] ?? null;
  }
  return null;
}

function bannerWhatChanged(verdict: PreflightVerdict): string {
  if (verdict.descBefore !== null || verdict.descAfter !== null) {
    const base = "a tool's description changed (the agent-consumed channel)";
    if (
      verdict.descBefore !== null &&
      verdict.descAfter !== null &&
      isNumericOnlyDescriptionChange(verdict.descBefore, verdict.descAfter)
    ) {
      return base + "; only the numbers moved, the prose is identical";
    }
    return base;
  }
  const friendly = friendlyBreakingClause(verdict);
  if (friendly !== null) return `${plainText(verdict.toolName)} — ${friendly}`;
  const safety = verdict.drift.filter((c) => c.safetyRelevant);
  if (safety.length > 0) {
    const kinds = [...new Set(safety.map((c) => c.kind.toString()))].sort().join(", ");
    return `${plainText(verdict.toolName)} contract drifted (${kinds})`;
  }
  if (verdict.drift.length > 0) {
    const kinds = [...new Set(verdict.drift.map((c) => c.kind.toString()))].sort().join(", ");
    return `${plainText(verdict.toolName)} contract drifted (${kinds})`;
  }
  return plainProse(verdict.reason);
}

// ------------------------------------------------------------- agent-facing HOLD text
// Byte-for-byte parity with the Python side (`gate.render_hold_message`). Bounds exist
// because an attacker controls how many paths drift and what they are named: an unbounded
// render is a denial-of-legibility vector - the agent stops reading and falls back to
// "this looks like an attack".
const EVIDENCE_ROW_CAP = 6;
const SENT_KEY_CAP = 12;
// Row caps bound CARDINALITY; this bounds LENGTH. Truncate BEFORE escaping so a cut can
// never land mid-escape-sequence.
const VALUE_CHAR_CAP = 120;

/** Bound, escape, then redact one attacker-derived value. Order is load-bearing: redacting
 * before escaping would turn the `[redacted]` placeholder into `\[redacted\]`. Per-value
 * rather than over the joined message, so redaction can only touch attacker-derived spans -
 * over the whole render it also hit our own prose and the pin path. */
function untrusted(value: string): string {
  // Collapse whitespace RUNS first - see the Python twin. The block is column-aligned, so
  // preserved consecutive spaces let an attacker forge a second column.
  // Explicit class, NOT `\s` - the two languages' `\s` sets differ. See the Python twin.
  const flat = value.replace(/[ \t\n\r\f\v\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]+/gu, " ");
  // Code POINTS, not UTF-16 units: `.slice` can split a surrogate pair and diverges from
  // Python's codepoint slice, so the two SDKs would truncate at different offsets.
  const cp = [...flat];
  const bounded = cp.length > VALUE_CHAR_CAP ? `${cp.slice(0, VALUE_CHAR_CAP).join("")}...` : flat;
  return redactGreenWords(plainText(bounded));
}

/** `untrusted` for a FREE-FORM value rather than an identifier - same bound, same redaction,
 * but `_` stays escaped (see `plainProse`). Only `verdict.reason` takes this path: it is the
 * one field that interpolates a server-chosen taint location, so it is the one field where an
 * underscore is attacker syntax rather than part of a name. Python twin:
 * `gate._untrusted_prose`. */
function untrustedProse(value: string): string {
  const flat = value.replace(/[ \t\n\r\f\v\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]+/gu, " ");
  const cp = [...flat];
  const bounded = cp.length > VALUE_CHAR_CAP ? `${cp.slice(0, VALUE_CHAR_CAP).join("")}...` : flat;
  return redactGreenWords(plainProse(bounded));
}

// The line that would have prevented the 2026-08-05 incident on its own. A mid-session
// drift is caught against the LIVE contract, but the model's tool list is whatever it last
// fetched, so the agent's own view legitimately disagrees with us. Left unsaid, the agent
// experiences that as us asserting something demonstrably false - indistinguishable from
// being lied to, and it correctly refused. Said plainly, the mismatch becomes corroborating.
const STALE_LIST_NOTE =
  "Your cached tool list may still show the pinned contract; the change was observed at " +
  "the server after this session listed tools. That mismatch is expected and is what was " +
  "caught.";

const HONESTY_NOTE =
  "This is a contract diff, not a safety verdict: no claim is made about intent.";

// CONSTRAIN, NEVER EXPAND. This message travels on the wrapped server's own error channel -
// from the agent's seat it is attacker-controlled text, so it may only narrow what the agent
// does. It must never invite an action that CHANGES TRUST STATE: `[Review · Re-pin ·
// Validate]` pointed at `repin()`, which makes a changed contract the new trusted baseline -
// i.e. the gate was emitting, on an untrusted channel, precisely the text an attacker would
// forge to get a hostile contract blessed. A forged "stop and ask your human" earns an
// attacker nothing, which is what makes this direction safe to say here.
const DISPOSITION_NOTE =
  "Retrying will not clear this, and supplying the changed parameter does not either — " +
  "re-pinning is a trust decision for the person running this agent.";

// INCONCLUSIVE resolution stated as a FACT, never as an offer: the behavioral check can move
// a verdict, so inviting the agent to run it would be an action that changes trust state.
// The RESULT-WITHHELD hold fires AFTER the call executed, and only for high-blast tools.
// The contract-diff prose is false there - most dangerously the headline.
const RESULT_HEADLINE =
  "mcpindex — local contract gate — this call RAN and its side effect, if any, already " +
  "happened; only its RESULT was withheld. Do not retry.";
const RESULT_HONESTY_NOTE =
  "This is a result-content finding, not a safety verdict and not a contract diff: the " +
  "side effect, if any, has already happened.";
const RESULT_DISPOSITION_NOTE =
  "Retrying would run the call again. Whether to read the withheld content is a decision " +
  "for the person running this agent.";

// `isContractDiff === false` covers TWO shapes with OPPOSITE execution semantics: a
// result-withhold hold RAN, an internal-error hold did NOT - our own code failed before the
// call left the process. See the Python twin.
const INTERNAL_HEADLINE =
  "mcpindex — local contract gate — mcpindex's own code failed, so this call was NOT sent " +
  "to the server. Nothing ran.";
const INTERNAL_NOTE =
  "This is our failure, not a finding about the tool: no contract change was observed and " +
  "no claim is made about this tool. The gate fails closed, so the call was held rather " +
  "than let through unchecked.";
const DRILL_DISPOSITION_NOTE =
  "Nothing about this tool changed. The rehearsal is over - it is one-shot and has already " +
  "disarmed itself - so the next call to this tool proceeds normally.";

// The un-checkable pre-flight shapes: no pin, tool absent from the listing, derivation error.
// Nothing was COMPARED, and unlike a real drift the remedy is often just to list and retry.
// A comparison RAN; something other than a diff fired. Distinct from "uncheckable" (nothing
// was compared) and from "drift" (a difference was found).
const FINDING_NOTE =
  "The contract was checked and something other than a difference stopped this call - the " +
  "reason above says what. This is a finding about the tool's definition, not a claim " +
  "about intent, and not a safety verdict.";
const FINDING_DISPOSITION_NOTE =
  "Retrying will not clear this on its own. Whether to proceed is a decision for the " +
  "person running this agent.";

// The contract is FINE - this tool is held on what the call can DO, not on what it declares.
const APPROVAL_NOTE =
  "Nothing about this tool's contract changed - it matches the pinned baseline. It is held " +
  "because of what the call can do, not what it declares.";
const APPROVAL_DISPOSITION_NOTE =
  "This class of action is never run unattended. It needs a person, and no retry or " +
  "argument change reaches one.";

const UNCHECKABLE_NOTE =
  "No contract comparison was possible here - the reason above says why. The gate fails " +
  "closed rather than let an unverified call through.";
// NEVER NAME THE UNBLOCKING ACTION - see the Python twin. `observe()` TOFU-writes the pin
// store, so naming it here is an instruction for the one action that mints a trust baseline.
// "No baseline exists for this tool in this session" was asserted here as flat fact and is
// FALSE on six of the seven situations that reach this class - a pinned tool absent from the
// live listing, a hash-derivation error, a declined battery. Attacker-triggerable on one: a
// hostile server drops a PINNED tool from tools/list and the agent is told the tool was never
// pinned rather than that its pinned tool vanished, nine lines above an anchor naming the pin
// file. Fixed in the Python twin in round 7 and left live here for a release - which is why
// `holdMessage.test.ts` now pins these constants across both languages.
const UNCHECKABLE_DISPOSITION_NOTE =
  "Whether to establish or restore a baseline for this tool is a trust decision for the " +
  "person running this agent.";

const INTERNAL_DISPOSITION_NOTE =
  "Nothing has happened yet, so a retry repeats nothing - but it will likely fail the " +
  "same way until the gate is fixed or removed.";

const INCONCLUSIVE_NOTE =
  "Resolving this needs behavioral verification, which is a human-initiated action.";

// A staged drill MUST be distinguishable from a real hold on the agent channel, not just in
// `data.drill`. An agent that reads a rehearsal as a live security event escalates a false
// alarm to its user - which is how you train someone to ignore the real thing.
const DRILL_HEADLINE =
  "[DRILL] mcpindex — local contract gate — this is a STAGED REHEARSAL, not a real " +
  "contract change. The call was not forwarded.";
const DRILL_NOTE =
  "The change above is synthetic - nothing about this tool actually changed, and no " +
  "parameter needs supplying.";

function evidenceRows(
  verdict: PreflightVerdict,
  sentKeys: readonly string[] | null,
  drill = false,
): Array<[string, string]> {
  const rows: Array<[string, string]> = [["tool", untrusted(verdict.toolName)]];

  // Sort before capping so the same drift always renders the same rows - non-determinism
  // here would break cross-language parity with the Python renderer.
  const changes = [...verdict.drift].sort((a, b) => {
    if (a.safetyRelevant !== b.safetyRelevant) return a.safetyRelevant ? -1 : 1;
    // Codepoint compare, NOT localeCompare: the latter is locale/ICU-dependent and diverges
    // from Python's `sorted()`, so with a 6-row cap the two SDKs could display different
    // evidence for identical drift.
    const ak = a.kind.toString();
    const bk = b.kind.toString();
    if (ak !== bk) return ak < bk ? -1 : 1;
    const ap = a.path ?? "";
    const bp = b.path ?? "";
    return ap < bp ? -1 : ap > bp ? 1 : 0;
  });
  for (const change of changes.slice(0, EVIDENCE_ROW_CAP)) {
    // `kind` is a ChangeKind member - closed vocabulary. `path` IS attacker-derived and is
    // escaped, exactly as before: the defence is unchanged, only its location moved.
    const where = change.path ? ` at ${untrusted(change.path)}` : "";
    // On a drill the change is INVENTED - see the Python twin.
    rows.push([drill ? "staged change" : "change", `${change.kind.toString()}${where}`]);
  }
  if (changes.length > EVIDENCE_ROW_CAP) {
    rows.push([drill ? "staged change" : "change", `... and ${changes.length - EVIDENCE_ROW_CAP} more`]);
  }
  // `reason` on a non-contract-diff hold is OURS, not the server's: truncating it deletes
  // the corrective clause that distinguishes a result hold from a drift.
  // See the Python twin: on the internal-error shape the headline states the whole case and
  // the sentinel carries a green word, so the row is dropped rather than rendered.
  if (changes.length === 0 && verdict.holdClass !== HoldClass.INTERNAL) {
    rows.push([
      "reason",
      untrustedProse(verdict.reason),
    ]);
  }

  // Plain-language CONSEQUENCE of the most-severe breaking kind, from the closed curated
  // `BREAKING_KIND_REASON` vocabulary (never attacker-derived, so no escaping needed). An
  // agent reasoning about how to report a hold needs the effect, not just the label.
  // No `effect` row on a drill: the consequence it describes will never happen.
  const friendly = drill ? null : friendlyBreakingClause(verdict);
  if (friendly !== null) rows.push(["effect", friendly]);

  if (sentKeys !== null) {
    // NAMES ONLY, NEVER VALUES. Values can carry credentials and PII; names are
    // contract-level data already in the pinned schema and already held by the agent.
    const shown = [...sentKeys].sort().slice(0, SENT_KEY_CAP);
    const more = sentKeys.length - shown.length;
    let rendered = shown.length > 0 ? shown.map(untrusted).join(", ") : "(none)";
    if (more > 0) rendered += `, ... and ${more} more`;
    rows.push(["call sent", rendered]);
  }
  return rows;
}

/**
 * The AGENT-facing HOLD text: evidence over assertion, constrain never expand.
 *
 * `renderHoldBanner` is the HUMAN brand moment and is unchanged - it still renders for
 * hosts and operators. But it was ALSO the thrown message, which is read by a MODEL.
 * Observed 2026-08-05: Claude Opus 4.8 classified that banner as a prompt-injection
 * attempt, refused to act on it, retried the held call, and told the user something
 * suspicious was intercepting its tools.
 *
 * Its load-bearing objection was not tone - it was that it could not VERIFY us: the gate
 * diffs the pin against the LIVE contract, while the agent sees only its own cached tool
 * list, a third view that legitimately disagrees. Asserting a change the reader cannot
 * observe, then inviting it to act, is the exact shape of a manipulation attempt.
 *
 * Every defence is unchanged: `mdText` on each attacker-derived value, `redactGreenWords`
 * over the whole output, fail-closed behaviour untouched.
 */
export function renderHoldMessage(
  verdict: PreflightVerdict,
  sentKeys: readonly string[] | null = null,
  pinPath: string | null = null,
  drill = false,
): string {
  // SPLIT FROM `assembleHoldMessage` for the reason the Python twin documents: when
  // assembly and redaction were one function, `redactAgentUnsafe` stripped a banned token
  // from OUR OWN prose before any test could observe it, so a mutation restoring instance
  // twelve verbatim into a producer reason left the suite green. Redaction defends against
  // the attacker; our prose has to be clean before it runs, and the suite asserts that
  // against the RAW assembly.
  const text = redactAgentUnsafe(assembleHoldMessage(verdict, sentKeys, pinPath, drill));
  if (agentChannelViolation(verdict, text) !== null) return MINIMAL_HOLD_MESSAGE;
  return text;
}

/** The minimal HOLD text: claims nothing beyond "this did not complete normally". The
 * fail-closed fallback for a whole-message invariant no span redaction can repair. */
export const MINIMAL_HOLD_MESSAGE =
  "mcpindex — local contract gate — this call did not complete normally. " +
  "The structured error data carries the detail.";

// Wire-level names an agent can EMIT. Deliberately NARROWER than "any word about trust":
// the discriminator is whether a reader can ACT on the string. `list_tools` is a method the
// agent can send on its next turn, and `Gate.observe()` TOFU-writes the pin store when it
// does — so a HOLD carrying that word mints the very baseline the HOLD exists to withhold.
const AGENT_UNSAFE_TOKENS = ["list_tools", "listtools", "tools/list"] as const;

// Match through `mdText` escaping: `list_tools` also matches `list\_tools`. A plain
// substring scan is precisely why round 7's test passed while the string was LIVE.
const AGENT_UNSAFE_RE = new RegExp(
  AGENT_UNSAFE_TOKENS.map((t) =>
    [...t].map((ch) => `\\\\?${ch.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&")}`).join(""),
  ).join("|"),
  "gi",
);

// Bracketed affordance chips — `[Review · Re-pin · Validate]`, `[Override]`. UNESCAPED
// brackets only: our curated prose is never routed through `mdText` so OUR chips are
// literal `[`, while attacker values always are and arrive as `\[` — already neutralised,
// and worth SHOWING as evidence of an attempted forgery. The allowlist is our own state
// labels, which name nothing for the reader to do.
const AGENT_SAFE_BRACKETS = ["redacted", "DRILL"] as const;
const CHIP_RE = new RegExp(
  `(?<!\\\\)\\[(?!(?:${AGENT_SAFE_BRACKETS.join("|")})\\])[^\\]\\n]{1,60}(?<!\\\\)\\]`,
  "g",
);

/** The single boundary every agent-facing HOLD string crosses. REDACTS, never suppresses.
 *
 * Span-level, because the first cut returned a minimal message on any violation — which
 * handed a hostile server a SUPPRESSION PRIMITIVE: name a tool `[Override]` and the whole
 * detailed HOLD collapses to a sentence that says nothing. This module refuses that same
 * trade for the pin anchor ("drop only the poisoned span, never the whole line").
 * Python twin: `cse.gate.redact_agent_unsafe`. */
export function redactAgentUnsafe(text: string): string {
  return text.replace(AGENT_UNSAFE_RE, "[redacted]").replace(CHIP_RE, "[redacted]");
}

/** WHOLE-MESSAGE invariants no span redaction can repair. Returns a reason, or null.
 * Python twin: `cse.gate.agent_channel_violation`. */
export function agentChannelViolation(
  verdict: PreflightVerdict,
  text: string,
): string | null {
  const low = text.toLowerCase();
  // The execution claim decides whether retrying is safe, so it must match the producer's
  // fact in BOTH directions: a phantom side effect blocks a legitimate retry, and a missing
  // real one invites a double-send.
  const ran = low.includes("already ran") || low.includes("this call ran");
  if (verdict.alreadyExecuted === true && !ran)
    return "verdict says the call already ran; the message does not say so";
  if (verdict.alreadyExecuted !== true && ran)
    return "verdict says the call did not run; the message claims it did";
  return null;
}

function assertNever(x: never): never {
  throw new Error(`unhandled hold class: ${String(x)}`);
}

/** Raw assembly, before the channel boundary. Exported for the suite, which must see our
 * prose as written — handed the redacted output, a no-op assertion is vacuous. */
export function assembleHoldMessage(
  verdict: PreflightVerdict,
  sentKeys: readonly string[] | null = null,
  pinPath: string | null = null,
  drill = false,
): string {
  // ONE dispatch, on the ONE fact the producer set — the port of the Python rewrite.
  //
  // This was a chain of ternaries and `else if`s over `isContractDiff`, `drift.length`,
  // `isInternalErrorVerdict()` and two holdClass comparisons: a PRIORITY ORDER, not a set of
  // mutually exclusive facts. It disagreed with the producer on three of six classes and the
  // chain won — including a SELF-CONTRADICTION that a hostile server can trigger by dropping
  // a pinned tool from tools/list (holdClass=uncheckable WITH drift rows), which rendered
  // "the change was observed at the server" and "no contract comparison was possible" nine
  // lines apart in one message. `assertNever` makes an unhandled class a compile error.
  const holdClass = verdict.holdClass ?? HoldClass.UNSET;
  const headline = drill
    ? DRILL_HEADLINE
    : holdClass === HoldClass.INTERNAL
      ? INTERNAL_HEADLINE
      : holdClass === HoldClass.WITHHELD
        ? RESULT_HEADLINE
        : "mcpindex — local contract gate — did not forward this call to the server.";
  const lines: string[] = [headline, ""];
  const rows = evidenceRows(verdict, sentKeys, drill);
  const width = Math.max(...rows.map(([label]) => label.length));
  for (const [label, value] of rows) lines.push(`  ${label.padEnd(width)}   ${value}`);

  if (drill) {
    // Orthogonal to the class: a drill is a STAGED drift, so every claim below would
    // describe a change that was never made.
    lines.push("", DRILL_NOTE, "", DRILL_DISPOSITION_NOTE);
  } else {
    switch (holdClass) {
      case HoldClass.DRIFT:
        // STALE_LIST_NOTE belongs HERE and only here — it asserts "the change was observed
        // at the server", true on exactly this class. Keyed off `drift.length` instead, it
        // rode along on uncheckable and finding holds.
        lines.push("", STALE_LIST_NOTE, "", HONESTY_NOTE, "", DISPOSITION_NOTE);
        break;
      case HoldClass.WITHHELD:
        lines.push("", RESULT_HONESTY_NOTE, "", RESULT_DISPOSITION_NOTE);
        break;
      case HoldClass.INTERNAL:
        lines.push("", INTERNAL_NOTE, "", INTERNAL_DISPOSITION_NOTE);
        break;
      case HoldClass.APPROVAL:
        lines.push("", APPROVAL_NOTE, "", APPROVAL_DISPOSITION_NOTE);
        break;
      case HoldClass.UNCHECKABLE:
        lines.push("", UNCHECKABLE_NOTE, "", UNCHECKABLE_DISPOSITION_NOTE);
        break;
      case HoldClass.FINDING:
        // A comparison RAN and something other than a diff fired.
        lines.push("", FINDING_NOTE, "", FINDING_DISPOSITION_NOTE);
        break;
      case HoldClass.UNSET:
        // A producer forgot. That is a bug in OUR code; say only what is true of every hold
        // rather than guess a class — guessing is what the old "drift" default did.
        return MINIMAL_HOLD_MESSAGE;
      default:
        return assertNever(holdClass);
    }
  }

  if (verdict.decision === Decision.INCONCLUSIVE) lines.push("", INCONCLUSIVE_NOTE);

  if (pinPath) {
    // The anti-forgery anchor: a remote server can emit any string, but it cannot put a
    // file on the caller's disk or a binary on their PATH. `pinPath` is OURS.
    // Port of the Python hardening: neutralise, collapse $HOME, and drop only the poisoned
    // span if the path itself would carry banned reassurance - never the whole line, which
    // would hand an attacker a way to suppress the anchor by naming their server.
    // `stripControl` mirrors Python `_strip_unsafe`, which does NOT fold newlines - fold
    // them here so a newline in `pinPath` cannot inject a forged evidence row. Then collapse
    // $HOME, which the previous comment claimed and the code did not do: the absolute form
    // leaks the OS username AND names the exact file a hostile server would poison.
    const flat = stripControl(pinPath).replace(/[\r\n]+/g, " ");
    const home = typeof process !== "undefined" ? (process.env.HOME ?? "") : "";
    const safePin = home && flat.startsWith(`${home}/`) ? `~${flat.slice(home.length)}` : flat;
    const anchor =
      redactGreenWords(safePin) === safePin
        ? `the pin is a file at ${safePin}`
        : "the pin is a file under ~/.mcpindex/pins/";
    lines.push(
      "",
      `Checkable locally: ${anchor}, and \`mcpindex-report\` prints the record. ` +
        "A remote server can write neither.",
    );
  }

  // No whole-output redaction: every attacker-derived span already went through `untrusted`.
  // Re-running it over the join would corrupt our own curated prose while adding no defence.
  return lines.join("\n");
}

export function renderHoldBanner(
  verdict: PreflightVerdict,
  monthlyCount: number | null = null,
  chips = true,
): string {
  const what = bannerWhatChanged(verdict);
  let line = `${BRAND_MARK} — caught a silent change: ${what}. Held before your agent ran it.`;
  // See the Python twin: suppressed at the source for `data.presentation`, never by
  // splitting the rendered string.
  if (chips) line += "  [Review · Re-pin · Validate]";
  if (monthlyCount !== null && monthlyCount > 0) {
    line += `   · ${ordinal(monthlyCount)} silent change caught for you this month`;
  }
  // M3 (FIX 4): redact any green word — the only source is the attacker-derived
  // tool_name / reason interpolated by `bannerWhatChanged` — so an attacker cannot
  // smuggle banned reassurance (e.g. a tool named "all-clear-verified") into the HOLD
  // banner. We redact the offending token, NOT refuse the whole HOLD (a refusal would
  // let an attacker SUPPRESS a legitimate HOLD). Curated brand/action text carries none.
  return redactGreenWords(line);
}

function descriptionOf(defn: ToolDef | null): string {
  if (defn === null || typeof defn !== "object") return "";
  const desc = (defn as Record<string, unknown>)["description"];
  return desc !== undefined && desc !== null ? String(desc) : "";
}

// ===================================================================== the Gate
export interface GateOptions {
  pin: PreflightPin;
  serverId: string;
  failOpen?: boolean;
  autoAcceptBenign?: boolean;
  now?: () => string;
  ownership?: Ownership;
  behavioralMandatedKinds?: ReadonlySet<ChangeKind>;
  verifier?: BehavioralVerifier | null;
  posture?: Posture;
  errors?: ErrorStore | null;
}

export class Gate {
  private readonly pin: PreflightPin;
  private readonly _serverId: string;
  private readonly failOpen: boolean;
  private readonly autoAcceptBenign: boolean;
  private readonly now: () => string;
  private readonly _ownership: Ownership;
  private readonly behavioralMandatedKinds: ReadonlySet<ChangeKind>;
  private readonly _verifier: BehavioralVerifier | null;
  private readonly _posture: Posture;
  private readonly errors: ErrorStore | null;

  constructor(opts: GateOptions) {
    this.pin = opts.pin;
    this._serverId = opts.serverId;
    this.failOpen = opts.failOpen ?? false;
    this.autoAcceptBenign = opts.autoAcceptBenign ?? true;
    this.now = opts.now ?? utcNowIso;
    this._ownership = opts.ownership ?? Ownership.UNOWNED_THIRD_PARTY;
    this.behavioralMandatedKinds = opts.behavioralMandatedKinds ?? DEFAULT_BEHAVIORAL_MANDATED_KINDS;
    this._verifier = opts.verifier ?? null;
    this._posture = opts.posture ?? Posture.GUARD;
    this.errors = opts.errors ?? null;
  }

  get serverId(): string {
    return this._serverId;
  }
  get posture(): Posture {
    return this._posture;
  }
  get verifier(): BehavioralVerifier | null {
    return this._verifier;
  }
  get ownership(): Ownership {
    return this._ownership;
  }

  pinFor(name: string): PinnedTool | null {
    return this.pin.get(this._serverId, name);
  }

  /** TOFU-pin one observed tool if not already pinned. */
  observe(name: string, defn: ToolDef): void {
    if (this.pin.get(this._serverId, name) === null) {
      const definitionHash = hashTool(defn);
      this.pin.put({
        serverId: this._serverId,
        toolName: name,
        definitionHash,
        pinnedAt: this.now(),
        schema: defn,
      });
      // M1 drift telemetry — emit the COVERAGE (pin) signal once per first-seen tool.
      // Opt-in, fail-open, off-path: recordPin never throws and never touches the network
      // on this thread, so it cannot affect the pin or any later verdict.
      driftTelemetry.recordPin(this._serverId, name, definitionHash, this.now());
      // M3 fleet query — fire-and-forget ask the fleet whether THIS tool has corroborated
      // drift (off-path; warms the cache before the first call so evaluate() can warn on call 1).
      driftQuery.prefetch(this._serverId, name);
    }
  }

  repinOne(name: string, observed: ToolDef): PinnedTool {
    const p: PinnedTool = {
      serverId: this._serverId,
      toolName: name,
      definitionHash: hashTool(observed),
      pinnedAt: this.now(),
      schema: observed,
    };
    this.pin.put(p);
    return p;
  }

  // ---------------------------------------------------------------- evaluate
  /** Decide PROCEED/HOLD on the live contract, then attach the advisory Tier-0a
   * action classification (blast radius) computed locally from the live definition.
   * The classification rides ALONGSIDE the decision and never moves it (AD-1); it is
   * null when the live definition is unavailable or the flag is off. Mirrors the
   * Python wrapper's `build_action_classification`. */
  evaluate(name: string, observed: ToolDef | null): PreflightVerdict {
    const verdict = this.decideContract(name, observed);
    const ac = classifyToolDef(name, observed);
    const withAc = ac === null ? verdict : { ...verdict, actionClassification: ac };
    // M3 fleet advisory — if the fleet has corroborated drift for this tool (prefetched at
    // observe time), attach it. Sync cache read; AD-6-safe (never moves PROCEED/HOLD).
    const adv = driftQuery.lookup(this._serverId, name);
    return adv === null ? withAc : { ...withAc, fleetAdvisory: adv };
  }

  private decideContract(name: string, observed: ToolDef | null): PreflightVerdict {
    const pinned = this.pin.get(this._serverId, name);
    if (pinned === null) {
      return this.holdOrFailopen(
        name,
        // NO REMEDY IN THIS STRING - it is rendered verbatim to the agent, and `observe()`
        // TOFU-writes the pin store. See the Python twin.
        "no pin for this tool on this session; the contract has not been observed yet",
      );
    }
    if (observed === null) {
      return this.holdOrFailopen(
        name,
        "tool is pinned but ABSENT from the contracts observed this session; cannot verify the live contract",
      );
    }

    let liveHash: string;
    try {
      liveHash = hashTool(observed);
    } catch {
      return this.holdOrFailopen(name, "could not derive the current contract hash for this tool");
    }

    if (liveHash === pinned.definitionHash) {
      const unhashed = this.mandatedUnhashedDrift(pinned, observed);
      if (unhashed !== null) return unhashed;
      return makeVerdict({
        serverId: this._serverId,
        toolName: name,
        decision: Decision.PROCEED,
        reason: "contract matches your pin",
      });
    }

    // The canonical hash CHANGED — a real contract drift. Decide the verdict, then emit the
    // M1 drift telemetry OUTCOME signal (off-path, fail-open: it can never move the verdict).
    const verdict = this.validateDrift(name, pinned, observed);
    driftTelemetry.recordDrift(
      this._serverId,
      name,
      pinned.definitionHash,
      liveHash,
      verdict.drift,
      this.now(),
    );
    return verdict;
  }

  private classifyDrift(pinned: PinnedTool, observed: ToolDef): Change[] {
    if (pinned.schema !== null) {
      return classifyChange(pinned.schema, observed);
    }
    return [
      {
        kind: ChangeKind.DEEP_SCHEMA_UNDIFFABLE,
        path: "(tool)",
        safetyRelevant: true,
        detail:
          "definition_hash changed but no pinned schema to diff against; re-pin with schema capture to see what changed",
      },
    ];
  }

  private mandatedUnhashedDrift(pinned: PinnedTool, observed: ToolDef): PreflightVerdict | null {
    // STEP 1 (fail-closed, H1 / FIX 2) — independent of the structural diff and load-
    // bearing: scan the observed UNHASHED outputSchema for an injection/exfil marker
    // BEFORE the mandated-kind check. outputSchema is unhashed (so it never flips the
    // invocation hash) but agent-consumed and attacker-controllable, so a marker there
    // must HOLD — on the hash-MATCH path it would otherwise slip through as "contract
    // matches your pin". A scan THROW fails CLOSED to a HOLD. Mirrors `_unhashed_drift`.
    const outSch = (observed as Record<string, unknown>)["outputSchema"];
    if (outSch !== null && typeof outSch === "object" && !Array.isArray(outSch)) {
      const obj = outSch as Record<string, unknown>;
      if (Object.keys(obj).length > 0) {
        let marked: boolean;
        try {
          marked = scanSchemaHasMarker(obj);
        } catch {
          return this.driftHold(
            pinned.toolName,
            [],
            "outputSchema present but the content scan could not complete; fail-closed HOLD",
            "finding", // scan error: a comparison ran
          );
        }
        if (marked) {
          return this.driftHold(
            pinned.toolName,
            [],
            "an injection/exfil marker is present in the tool's outputSchema (an unhashed, agent-consumed channel)",
            "finding", // injection marker: a comparison ran
          );
        }
      }
    }

    if (pinned.schema === null) return null;
    let drift: Change[];
    try {
      drift = this.classifyDrift(pinned, observed);
    } catch {
      return null;
    }
    const mandated = drift.filter((c) => this.behavioralMandatedKinds.has(c.kind)).map((c) => c.kind.toString());
    if (mandated.length === 0) return null;
    return this.behavioralInconclusive(pinned.toolName, drift, mandated);
  }

  private validateDrift(name: string, pinned: PinnedTool, observed: ToolDef): PreflightVerdict {
    let drift: Change[];
    try {
      drift = this.classifyDrift(pinned, observed);
    } catch {
      return this.driftHold(
        name,
        [],
        "contract DRIFTED and validation could not complete; fail-closed HOLD",
        HoldClass.DRIFT, // the canonical hash CHANGED; only the CLASSIFIER failed
      );
    }

    // FIX 1 (fail-closed, H2): the canonical hash CHANGED (we only reach here on a hash
    // mismatch), yet the classifier produced NO change — UN-EXPLAINABLE drift (an
    // unmodeled inputSchema facet narrowed the contract and flipped the hash without
    // yielding a Change). An empty change list would otherwise read as "every change is
    // allowlisted" and clear as PROVEN BENIGN under ANY posture (incl STRICT) — a
    // fail-OPEN. We cannot prove a drift benign when we cannot say WHAT drifted, so we
    // fail CLOSED with a synthetic DEEP_SCHEMA_UNDIFFABLE. Mirrors gate.py FIX-1.
    if (drift.length === 0) {
      const synthetic: Change = {
        kind: ChangeKind.DEEP_SCHEMA_UNDIFFABLE,
        path: "(tool)",
        safetyRelevant: true,
        detail:
          "contract hash DRIFTED but no structured change could be classified (an unmodeled schema facet narrowed the contract); cannot prove benign",
      };
      return this.driftHold(
        name,
        [synthetic],
        "contract hash DRIFTED but no structured change could be classified; cannot prove benign — fail-closed HOLD",
        "finding", // classify error: a comparison ran, it just could not be structured
      );
    }

    const mandated = drift.filter((c) => this.behavioralMandatedKinds.has(c.kind)).map((c) => c.kind.toString());
    if (!this.autoAcceptBenign) {
      if (mandated.length > 0) return this.behavioralInconclusive(name, drift, mandated);
      return this.driftHold(name, drift, "contract DRIFTED from your pin", HoldClass.DRIFT);
    }

    if (mandated.length > 0) return this.behavioralInconclusive(name, drift, mandated);

    const oldDesc = descriptionOf(pinned.schema);
    const newDesc = descriptionOf(observed);
    if (oldDesc !== newDesc) {
      return this.descriptionHold(name, drift, oldDesc, newDesc);
    }

    const nonAllowlisted = [
      ...new Set(drift.filter((c) => !BENIGN_AUTOACCEPT_KINDS.has(c.kind)).map((c) => c.kind.toString())),
    ].sort();
    if (nonAllowlisted.length > 0) {
      return this.driftHold(
        name,
        drift,
        "contract DRIFTED; not in the benign allowlist (added-optional-param / tool-added with no description change): " +
          nonAllowlisted.join(", "),
        HoldClass.DRIFT,
      );
    }

    let escalation: string | null;
    try {
      escalation = this.riskEscalation(pinned, observed);
    } catch {
      return this.driftHold(
        name,
        drift,
        "contract DRIFTED and the risk assessment could not complete; fail-closed HOLD",
        HoldClass.DRIFT,
      );
    }
    if (escalation !== null) {
      return this.driftHold(
        name,
        drift,
        "contract DRIFTED; risk ESCALATED on an otherwise-allowlisted change: " + escalation,
        HoldClass.DRIFT,
      );
    }

    let hasMarker: boolean;
    try {
      hasMarker = this.markerIn(observed);
    } catch {
      return this.driftHold(
        name,
        drift,
        "contract DRIFTED and the content scan could not complete; fail-closed HOLD",
        HoldClass.DRIFT,
      );
    }
    if (hasMarker) {
      return this.driftHold(
        name,
        drift,
        "contract DRIFTED; an injection/exfil marker is present in the new definition (input schema or description)",
        HoldClass.DRIFT, // drift rows exist; the marker is WHY, carried in the reason
      );
    }

    this.repinOne(name, observed);
    return makeVerdict({
      serverId: this._serverId,
      toolName: name,
      decision: Decision.PROCEED,
      reason:
        "contract DRIFTED but PROVEN BENIGN (every change is an added-optional-param / tool-added, the description is unchanged, risk did not escalate, and no marker is present); auto-accepted and re-pinned",
      drift,
    });
  }

  private riskEscalation(pinned: PinnedTool, observed: ToolDef): string | null {
    if (pinned.schema === null) return "no pinned schema to compare risk against (fail-closed)";
    const oldRisk = Gate.riskOf(pinned.schema);
    const newRisk = Gate.riskOf(observed);
    if (blastRank(newRisk.blastRadius) > blastRank(oldRisk.blastRadius)) {
      return `blast radius escalated ${oldRisk.blastRadius} → ${newRisk.blastRadius}`;
    }
    if (newRisk.hasWritePayloadParam && !oldRisk.hasWritePayloadParam) {
      return "gained a write/actionable payload parameter";
    }
    if (newRisk.requiresCredential && !oldRisk.requiresCredential) {
      return "gained a credential-bearing parameter";
    }
    return null;
  }

  private static riskOf(defn: ToolDef): ReturnType<typeof assess> {
    return assess(
      String((defn as Record<string, unknown>)["name"] ?? ""),
      String((defn as Record<string, unknown>)["description"] ?? ""),
      (defn as Record<string, unknown>)["inputSchema"],
    );
  }

  private static markerIn(defn: ToolDef): boolean {
    const d = defn as Record<string, unknown>;
    const inSch = d["inputSchema"];
    if (inSch !== null && typeof inSch === "object" && !Array.isArray(inSch)) {
      const obj = inSch as Record<string, unknown>;
      if (Object.keys(obj).length > 0 && scanSchemaHasMarker(obj)) return true;
    }
    // outputSchema is INCLUDED (H1 / FIX 2): its field description / default / title /
    // pattern strings are attacker-controllable and agent-consumed, so the marker
    // tripwire must cover it too — same scanner, same regexes. Mirrors `_marker_in`.
    const outSch = d["outputSchema"];
    if (outSch !== null && typeof outSch === "object" && !Array.isArray(outSch)) {
      const obj = outSch as Record<string, unknown>;
      if (Object.keys(obj).length > 0 && scanSchemaHasMarker(obj)) return true;
    }
    const desc = d["description"];
    if (typeof desc === "string" && desc && scanSchemaHasMarker({ description: desc })) return true;
    return false;
  }

  private markerIn(defn: ToolDef): boolean {
    return Gate.markerIn(defn);
  }

  // -------------------------------------------------------------- verdicts
  private descriptionHold(name: string, drift: Change[], oldDesc: string, newDesc: string): PreflightVerdict {
    return makeVerdict({
      serverId: this._serverId,
      toolName: name,
      decision: Decision.HOLD,
      // APPEND, never rewrite: DANGEROUS_REASON_MARKERS matches the substring
      // "DESCRIPTION changed", so rewording would silently stop GUARD blocking.
      reason:
        "contract DRIFTED: the tool DESCRIPTION changed (the agent-consumed, attacker-controllable channel); review the before/after and re-pin if expected" +
        (isNumericOnlyDescriptionChange(oldDesc, newDesc)
          ? "; only the embedded numbers moved, the prose is identical"
          : ""),
      drift,
      holdClass: HoldClass.DRIFT, // description-poisoning: a comparison found a difference
      descBefore: oldDesc,
      descAfter: newDesc,
    });
  }

  private driftHold(
    name: string,
    drift: Change[],
    reason: string,
    // REQUIRED, no default. The claim in the comment this replaces — "every CALLER states
    // it" — was FALSE: `tsc` names 6 callers that inherited it silently, the same 10 that
    // mypy surfaced in the Python twin. A defaulted parameter on a helper reintroduces at
    // the call site exactly what removing the field default fixed at the constructor.
    holdClass: HoldClass,
  ): PreflightVerdict {
    return makeVerdict({ serverId: this._serverId, toolName: name, decision: Decision.HOLD, reason, drift, holdClass });
  }

  private behavioralInconclusive(name: string, drift: Change[], mandatedKinds: string[]): PreflightVerdict {
    const kinds = [...new Set(mandatedKinds)].sort().join(", ");
    return makeVerdict({
      serverId: this._serverId,
      toolName: name,
      decision: Decision.INCONCLUSIVE,
      reason: `contract DRIFTED in a class the declared contract cannot clear or condemn (${kinds}); behavioral validation needed before use`,
      drift,
      holdClass: HoldClass.DRIFT, // a comparison found a difference; behaviour must adjudicate
    });
  }

  private holdOrFailopen(name: string, reason: string): PreflightVerdict {
    if (this.failOpen) {
      return makeVerdict({
        serverId: this._serverId,
        toolName: name,
        decision: Decision.PROCEED,
        reason,
        failOpenWarning: true,
        isContractDiff: false,
        holdClass: HoldClass.UNCHECKABLE, // no comparison was possible
      });
    }
    return makeVerdict({
      serverId: this._serverId,
      toolName: name,
      decision: Decision.HOLD,
      reason,
      isContractDiff: false,
      holdClass: HoldClass.UNCHECKABLE, // no comparison was possible
    });
  }

  // ------------------------------------------------------------- posture layer
  applyPosture(stat: PreflightVerdict): PreflightVerdict {
    if (stat.decision === Decision.PROCEED) return stat;
    if (this._posture === Posture.STRICT) return stat;
    if (this._posture === Posture.MONITOR) return this.notifyOnly(stat);
    // GUARD
    if (!stat.isContractDiff) return stat;
    if (this.isUnambiguousDangerous(stat)) return stat;
    return this.notifyOnly(stat);
  }

  decide(name: string, observed: ToolDef | null): [PreflightVerdict, PreflightVerdict] {
    try {
      const stat = this.evaluate(name, observed);
      const eff = this.applyPosture(stat);
      return [stat, eff];
    } catch (exc) {
      this.captureError(exc, Operation.GATE_DECISION, "gate.decide");
      const verdict = this.internalErrorVerdict(name);
      return [verdict, verdict];
    }
  }

  internalErrorVerdict(name: string): PreflightVerdict {
    return internalErrorHold(this._serverId, name);
  }

  captureError(exc: unknown, operation: Operation, ourCodeLocation: string): void {
    if (this.errors === null) return;
    try {
      const className = exc instanceof Error ? exc.constructor.name : "Error";
      this.errors.capture(className, operation, ourCodeLocation);
    } catch {
      // capture must never break the graceful-fail path
    }
  }

  private isUnambiguousDangerous(verdict: PreflightVerdict): boolean {
    if (verdict.drift.some((c) => GUARD_DANGEROUS_KINDS.has(c.kind))) return true;
    return DANGEROUS_REASON_MARKERS.some((m) => verdict.reason.includes(m));
  }

  private notifyOnly(stat: PreflightVerdict): PreflightVerdict {
    return makeVerdict({
      serverId: stat.serverId,
      toolName: stat.toolName,
      decision: Decision.PROCEED,
      reason: `notify-only (${this._posture}): ${stat.reason}`,
      drift: stat.drift,
      isContractDiff: stat.isContractDiff,
      descBefore: stat.descBefore,
      descAfter: stat.descAfter,
      // The advisory blast-radius grade rides along through the posture rebuild so
      // the effective verdict (what consumers + the ambient line read) keeps it.
      actionClassification: stat.actionClassification,
    });
  }

  // ----------------------------------------------------- behavioral validation
  /**
   * Verdict-only public wrapper. Callers that must DERIVE the evidence tier
   * (`tierReached` / `verdictScope`) honestly use `runBehavioralOutcome`, which also surfaces
   * the STRUCTURED `BehavioralOutcome` so the tier is keyed on the enum and NEVER on the
   * verifier-controlled free-text reason string.
   */
  runBehavioral(
    toolName: string,
    observed: ToolDef | null,
    staticVerdict: PreflightVerdict,
    verifier: BehavioralVerifier,
  ): PreflightVerdict {
    return this.runBehavioralOutcome(toolName, observed, staticVerdict, verifier)[0];
  }

  /**
   * Like `runBehavioral`, but ALSO returns the structured `BehavioralOutcome` the verifier
   * produced (or `null` when the verifier was NEVER consulted — a missing observed contract or
   * a verifier that errored). Callers key the evidence tier on this enum, never on the reason
   * string: behaviour was OBSERVED iff the outcome is CLEARED or FAILED; UNAVAILABLE / DECLINED
   * / null mean behaviour did NOT run (tier 0). Keying on the enum closes a provenance-honesty
   * hole — the reason string embeds the verifier-controlled `result.reason`, so a verifier
   * returning UNAVAILABLE with a reason that merely CONTAINS the literal "behavioral validation
   * FAILED" must NOT forge a BEHAVIORAL/tier-3 stamp on a HOLD where behaviour was never seen.
   * Python mirror: `Gate.run_behavioral_outcome`.
   */
  runBehavioralOutcome(
    toolName: string,
    observed: ToolDef | null,
    staticVerdict: PreflightVerdict,
    verifier: BehavioralVerifier,
  ): [PreflightVerdict, BehavioralOutcome | null] {
    const method = chooseBehavioralMethod(this._ownership);
    if (method === BehavioralMethod.DECLINED) {
      return [
        this.holdOrFailopen(
          toolName,
          "behavioral validation DECLINED: a full behavioral battery is not permitted against an unowned third-party live server (no consent); stay HOLD",
        ),
        BehavioralOutcome.DECLINED,
      ];
    }
    if (observed === null) {
      return [
        this.holdOrFailopen(
          toolName,
          "no observed contract to behaviorally validate; no baseline to validate against",
        ),
        null,
      ];
    }

    let result: BehavioralResult;
    try {
      result = verifier.verify(this._serverId, toolName, observed, this._ownership, method);
    } catch {
      return [this.holdOrFailopen(toolName, "behavioral verifier errored; fail-closed HOLD"), null];
    }

    if (result.outcome === BehavioralOutcome.CLEARED) {
      // Behaviour WAS observed (CLEARED) regardless of the description re-check outcome, so the
      // outcome stays CLEARED even when description drift forces a HOLD — the tier honestly
      // reflects that behaviour ran (tier 3), while the decision stays HOLD.
      const pinned = this.pin.get(this._serverId, toolName);
      if (pinned === null || pinned.schema === null) {
        return [
          this.holdOrFailopen(
            toolName,
            "behavioral validation CLEARED but the pinned description could not be compared (no pin/schema); fail-closed HOLD",
          ),
          BehavioralOutcome.CLEARED,
        ];
      }
      const oldDesc = descriptionOf(pinned.schema);
      const newDesc = descriptionOf(observed);
      if (oldDesc !== newDesc) {
        return [
          this.descriptionHold(toolName, [...staticVerdict.drift], oldDesc, newDesc),
          BehavioralOutcome.CLEARED,
        ];
      }
      this.repinOne(toolName, observed);
      return [
        makeVerdict({
          serverId: this._serverId,
          toolName,
          decision: Decision.PROCEED,
          reason: `behavioral validation CLEARED (${method}); auto-accepted and re-pinned`,
        }),
        BehavioralOutcome.CLEARED,
      ];
    }

    const suffix = result.reason || method;
    const reason =
      result.outcome === BehavioralOutcome.FAILED
        ? `behavioral validation FAILED (${suffix})`
        : `behavioral validation UNAVAILABLE (${suffix}); stay HOLD`;
    return [this.driftHold(toolName, [...staticVerdict.drift], reason, HoldClass.DRIFT), result.outcome];
  }
}

export { isSafetyRelevant, DEFAULT_BEHAVIORAL_MANDATED_KINDS };
