/**
 * Provenance — the immutable record attached to EVERY surfaced finding, and the
 * load-bearing `requireProvenance` choke. A port of Python
 * `tooling/cse/provenance.py` + `guardrails.require_provenance`. NOTHING surfaces
 * without a COMPLETE provenance record (the over-claim guard, fail-closed).
 */

import { hashTool } from "./canonical.js";
import { mdText } from "./render.js";
import { Decision } from "./preflight.js";
import type { PreflightVerdict, ToolDef } from "./preflight.js";
import { ChangeKind } from "./schemaDiff.js";
import type { Change } from "./schemaDiff.js";

export enum VerdictScope {
  STRUCTURAL_ONLY = "structural_only",
  SEMANTIC_ONLY = "semantic_only",
  BEHAVIORAL = "behavioral",
}

export enum HonestFraming {
  CONTRACT_DIFF_NOT_SAFETY = "contract-diff not a safety verdict",
  BEHAVIORAL_NEEDED = "static inconclusive; behavioral validation needed",
  VISIBILITY_NOT_BLAME = "consumer-visibility not maintainer-blame",
  HEALTHY = "",
}

const MAX_EVIDENCE_FIELD = 4096;
const TRUNC_MARK = "…[truncated]";

function bounded(s: string): string {
  if (s.length <= MAX_EVIDENCE_FIELD) return s;
  return s.slice(0, MAX_EVIDENCE_FIELD) + TRUNC_MARK;
}

export interface Subject {
  readonly serverId: string;
  readonly tool: string;
  readonly definitionHashOld: string | null;
  readonly definitionHashNew: string | null;
  readonly capturedAt: string;
  readonly source: string;
}

export interface WhatFired {
  readonly changeKinds: readonly ChangeKind[];
  readonly classifierId: string;
  readonly tierReached: number;
  readonly verdict: Decision;
  readonly verdictScope: VerdictScope;
}

export interface EvidenceField {
  readonly path: string;
  readonly kind: ChangeKind;
  readonly before: string | null;
  readonly after: string | null;
}

export interface Provenance {
  readonly subject: Subject;
  readonly whatFired: WhatFired;
  readonly evidence: readonly EvidenceField[];
  readonly honestFraming: HonestFraming;
  readonly reproduceHandle: string;
}

/** The completeness predicate the load-bearing choke gates on (port of
 * `Provenance.is_complete`). Each string field is trimmed before the check, so a
 * whitespace-only value is rejected as empty. Evidence MAY be empty. */
export function isComplete(p: Provenance): boolean {
  const s = p.subject;
  const wf = p.whatFired;
  return Boolean(
    s.serverId.trim() &&
      s.tool.trim() &&
      s.capturedAt.trim() &&
      s.source.trim() &&
      wf.classifierId.trim() &&
      p.reproduceHandle.trim(),
  );
}

/** Render-safe one-line summary (does NOT emit raw evidence values). */
export function renderProvenance(p: Provenance): string {
  const sid = mdText(p.subject.serverId);
  const tool = mdText(p.subject.tool);
  const kinds = [...new Set(p.whatFired.changeKinds.map((k) => k.toString()))].sort().join(", ");
  const framing = p.honestFraming || "healthy";
  return (
    `${sid}/${tool} — ${p.whatFired.verdict} ` +
    `(tier ${p.whatFired.tierReached}, scope ${p.whatFired.verdictScope}): ` +
    `${kinds || "no change"} — ${framing}`
  );
}

export function provenanceAsDict(p: Provenance): Record<string, unknown> {
  return {
    subject: {
      server_id: p.subject.serverId,
      tool: p.subject.tool,
      definition_hash_old: p.subject.definitionHashOld,
      definition_hash_new: p.subject.definitionHashNew,
      captured_at: p.subject.capturedAt,
      source: p.subject.source,
    },
    what_fired: {
      change_kinds: p.whatFired.changeKinds.map((k) => k.toString()),
      classifier_id: p.whatFired.classifierId,
      tier_reached: p.whatFired.tierReached,
      verdict: p.whatFired.verdict,
      verdict_scope: p.whatFired.verdictScope,
    },
    evidence: p.evidence.map((e) => ({
      path: e.path,
      kind: e.kind.toString(),
      before: e.before,
      after: e.after,
    })),
    honest_framing: p.honestFraming,
    reproduce_handle: p.reproduceHandle,
  };
}

function scopeForTier(tier: number): VerdictScope {
  if (tier >= 3) return VerdictScope.BEHAVIORAL;
  if (tier === 2) return VerdictScope.SEMANTIC_ONLY;
  return VerdictScope.STRUCTURAL_ONLY;
}

function framingFor(verdict: PreflightVerdict): HonestFraming {
  if (verdict.decision === Decision.INCONCLUSIVE) return HonestFraming.BEHAVIORAL_NEEDED;
  if (verdict.decision === Decision.HOLD || verdict.drift.length > 0)
    return HonestFraming.CONTRACT_DIFF_NOT_SAFETY;
  return HonestFraming.HEALTHY;
}

function evidenceFromDrift(
  drift: readonly Change[],
  descBefore: string | null,
  descAfter: string | null,
): EvidenceField[] {
  const fields: EvidenceField[] = [];
  const hasDescChange = drift.some((c) => c.kind === ChangeKind.DESCRIPTION_ONLY);
  for (const c of drift) {
    let before: string | null = null;
    let after: string | null = null;
    if (c.kind === ChangeKind.DESCRIPTION_ONLY) {
      before = descBefore !== null ? bounded(descBefore) : null;
      after = descAfter !== null ? bounded(descAfter) : null;
    }
    if (after === null && before === null) {
      after = bounded(c.detail);
    }
    fields.push({ path: c.path, kind: c.kind, before, after });
  }
  if (!hasDescChange && (descBefore !== null || descAfter !== null)) {
    fields.push({
      path: "description",
      kind: ChangeKind.DESCRIPTION_ONLY,
      before: descBefore !== null ? bounded(descBefore) : null,
      after: descAfter !== null ? bounded(descAfter) : null,
    });
  }
  return fields;
}

function hashOrNull(defn: ToolDef | null): string | null {
  if (defn === null) return null;
  try {
    return hashTool(defn);
  } catch {
    return null;
  }
}

/** Build a COMPLETE Provenance from a verdict + the contracts that produced it.
 * Port of `provenance.from_verdict`. */
export function fromVerdict(
  verdict: PreflightVerdict,
  opts: {
    serverId: string;
    tool: string;
    oldSchema: ToolDef | null;
    newSchema: ToolDef | null;
    tierReached: number;
    classifierId?: string;
    source?: string;
    capturedAt?: string;
  },
): Provenance {
  const classifierId = opts.classifierId ?? "gate.static-drift";
  const source = opts.source ?? "gate";
  const oldHash = hashOrNull(opts.oldSchema);
  const newHash = hashOrNull(opts.newSchema);
  const scope = scopeForTier(opts.tierReached);
  const now = opts.capturedAt ?? new Date().toISOString();
  const kinds = verdict.drift.map((c) => c.kind);
  const evidence = evidenceFromDrift(verdict.drift, verdict.descBefore, verdict.descAfter);
  const handle =
    `${classifierId}|tier=${opts.tierReached}|` +
    `old=${oldHash ?? "∅"}|new=${newHash ?? "∅"}|` +
    `verdict=${verdict.decision}`;
  return {
    subject: {
      serverId: opts.serverId,
      tool: opts.tool,
      definitionHashOld: oldHash,
      definitionHashNew: newHash,
      capturedAt: now,
      source,
    },
    whatFired: {
      changeKinds: kinds,
      classifierId,
      tierReached: opts.tierReached,
      verdict: verdict.decision,
      verdictScope: scope,
    },
    evidence,
    honestFraming: framingFor(verdict),
    reproduceHandle: handle,
  };
}

export class GuardrailError extends Error {}

/** THE choke every surface path passes through. Returns the COMPLETE Provenance,
 * or THROWS `GuardrailError` (fail-closed -> nothing surfaces). Port of
 * `guardrails.require_provenance`. */
export function requireProvenance(prov: Provenance | null | undefined): Provenance {
  if (prov === null || prov === undefined) {
    throw new GuardrailError(
      "no provenance attached — fail-closed: nothing may surface without a complete provenance record",
    );
  }
  if (!isComplete(prov)) {
    throw new GuardrailError(
      "provenance record is INCOMPLETE (missing a load-bearing field) — fail-closed, nothing surfaces",
    );
  }
  return prov;
}

/** Build provenance for a USER-FACING surface and run it through the choke.
 * Returns the COMPLETE record, or null when it cannot be built / the choke
 * refuses (fail-closed). Port of `provenance.surface_provenance`. */
export function surfaceProvenance(
  verdict: PreflightVerdict,
  opts: {
    serverId: string;
    tool: string;
    oldSchema: ToolDef | null;
    newSchema: ToolDef | null;
    tierReached: number;
    source: string;
  },
): Provenance | null {
  try {
    const prov = fromVerdict(verdict, opts);
    return requireProvenance(prov);
  } catch {
    return null;
  }
}

const GREEN_WORDS = ["safe", "verified", "clean", "pass", "passed", "all clear", "all-clear", "secure", "trusted"];
const GREEN_RE = new RegExp(
  // `_` IS A BOUNDARY, `-` IS NOT. Spelled out rather than `\w`, which INCLUDES `_` and so
  // made every underscore-joined green word invisible here: `gate_verified_this` and
  // `x_safe_y` were never redacted. That was masked while `mdText` backslash-escaped `_`;
  // `plainText` no longer mangles identifiers, so the boundary has to do the work the
  // escaping was accidentally doing. EXACT parity with Python `guardrails._GREEN_RE` -
  // hyphen stays excluded so `all-clear-verified-scanner` is still left alone.
  "(?<![0-9A-Za-z-])(" + GREEN_WORDS.map((w) => w.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|") + ")(?![0-9A-Za-z-])",
  "i",
);

/** Fail-closed honest-voice check: throw if a consumer string uses a banned
 * green word. Port of `guardrails.assert_no_green_words`. */
export function assertNoGreenWords(text: string): void {
  const m = GREEN_RE.exec(text);
  if (m !== null) {
    throw new GuardrailError(`consumer output contains a banned 'green word': '${m[1]}'`);
  }
}

// The neutral placeholder a green word is REDACTED to (FIX 4 / M3). An attacker can
// NAME a tool with a green word ("all-clear-verified-scanner") to smuggle banned
// reassurance into a HOLD banner. We REDACT the offending token (NOT refuse the whole
// HOLD — a refusal would let an attacker SUPPRESS a legitimate HOLD by naming their
// tool "safe"). The placeholder carries no green word itself.
const REDACTED_GREEN_WORD = "[redacted]";

// A GLOBAL variant of the green-word matcher, built from the SAME `GREEN_WORDS`
// source so the redaction word-list can never drift from `assertNoGreenWords`. A
// separate object (with the `g` flag) is used for `.replace`, keeping the stateful
// `lastIndex` of a global regex out of `assertNoGreenWords`'s `.exec`.
const GREEN_RE_GLOBAL = new RegExp(GREEN_RE.source, "gi");

/** Replace every banned green word in a consumer-facing string with a neutral
 * placeholder, so an ATTACKER-DERIVED token (a tool name interpolated into a HOLD
 * banner) cannot surface banned reassurance verbatim (M3). Whole-word,
 * case-insensitive — reuses the SAME word-list as `assertNoGreenWords`, so the two
 * can never disagree. The output passes `assertNoGreenWords`. Port of
 * `gate.redact_green_words`. */
export function redactGreenWords(text: string): string {
  return text.replace(GREEN_RE_GLOBAL, REDACTED_GREEN_WORD);
}
