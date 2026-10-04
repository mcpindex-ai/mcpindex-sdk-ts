/**
 * mcpindex — the TypeScript/JS SDK port of the pre-flight drift interceptor.
 *
 * One line wraps an already-authenticated MCP client session and HOLDs a tool
 * call before your agent runs it if the tool's contract drifted from your pin.
 * The wrapper never holds a credential and never opens a connection — it reuses
 * the wrapped session's own authenticated transport.
 */

export { wrap, repin, PreflightHold, DEFAULT_SERVER_ID } from "./wrap.js";
export type { Wrapped, WrapOptions } from "./wrap.js";

export { AmbientMode, AmbientNotifier, resolveMode } from "./ambient.js";
export type {
  AmbientNote,
  AmbientObserver,
  AmbientNotifierOptions,
  AmbientFromEnvOptions,
} from "./ambient.js";

export {
  PreflightPin,
  Decision,
  isProceed,
  renderVerdict,
  safetyRelevantDrift,
  hashTool,
} from "./preflight.js";
export type { PinnedTool, PreflightVerdict, ToolDef, ActionClassification } from "./preflight.js";

export {
  Gate,
  Posture,
  Ownership,
  BehavioralMethod,
  BehavioralOutcome,
  chooseBehavioralMethod,
  renderHoldBanner,
  renderHoldMessage,
  isInternalErrorVerdict,
} from "./gate.js";
export type { BehavioralVerifier, BehavioralResult, GateOptions } from "./gate.js";

export { ChangeKind, classifyChange, isSafetyRelevant, MAX_DEPTH } from "./schemaDiff.js";
export type { Change } from "./schemaDiff.js";

export { canonicalBytes, contractBytes, toolHash } from "./canonical.js";

export { assess, BlastRadius, DomainClass, blastRank } from "./risk.js";
export type { RiskAssessment } from "./risk.js";

export {
  classify as classifyAction,
  classifyToolDef,
  actionClassificationEnabled,
  ActionType,
  SideEffectClass,
  Reversibility,
  Egress,
  ScopeHint,
  PatternShape,
  AutonomyCeiling,
  NoteClass,
  Severity,
  EvidenceRefType,
} from "./actionClass.js";

export { scanSchemaHasMarker, scanResult } from "./scan.js";
export type { ResultTaint, ResultScan } from "./scan.js";
export { mdText } from "./render.js";

export {
  VerdictScope,
  HonestFraming,
  GuardrailError,
  requireProvenance,
  surfaceProvenance,
  fromVerdict,
  isComplete,
  renderProvenance,
  assertNoGreenWords,
} from "./provenance.js";
export type { Provenance, Subject, WhatFired, EvidenceField } from "./provenance.js";

export { ErrorStore, Operation, CLIENT_VERSION, ERROR_RECORD_KEYS } from "./errors.js";

// Opt-in drift telemetry — the consent notice is the only public surface; the emitter is wired
// internally by the gate. Default OFF; enable with MCPINDEX_DRIFT_TELEMETRY=detection.
export { DRIFT_TELEMETRY_NOTICE } from "./driftTelemetry.js";
export type { DriftMode } from "./driftTelemetry.js";

// M3 fleet query — "warns you on call 1". The gate prefetches on pin + attaches the advisory
// to the verdict (`fleetAdvisory`); opt-in (same telemetry gate), fail-open, AD-6-safe.
export { driftQuery } from "./driftQuery.js";
export type { FleetAdvisory } from "./driftQuery.js";

export {
  OutcomeStore,
  LocalStats,
  Action,
  OverrideReason,
  AGGREGATE_ROW_KEYS,
  verdictHash,
} from "./outcomes.js";
