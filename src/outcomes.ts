/**
 * Outcomes — the local capture substrate (surface + response tracking). A port
 * of the in-memory core of Python `tooling/cse/outcomes.py`. Local FULL detail;
 * the ONLY projection that may ever leave is `aggregateRows()`:
 * `{verdict_hash, action, reason_class}` per response — NEVER a tool name, an
 * argument, data, or a credential.
 */

import { createHash, randomUUID } from "node:crypto";
import { utcNowIso } from "./preflight.js";
import type { Provenance } from "./provenance.js";

export enum Action {
  OVERRIDE = "override",
  HONOR = "honor",
  REPIN = "repin",
  ESCALATE = "escalate",
  DISABLE = "disable",
  LOWER_POSTURE = "lower_posture",
  UNINSTALL = "uninstall",
  IGNORE = "ignore",
}

export enum OverrideReason {
  FALSE_ALARM = "false_alarm",
  REVIEWED_FINE = "reviewed_fine",
  NEED_NOW = "need_now",
  OTHER = "other",
}

export const AGGREGATE_ROW_KEYS: ReadonlySet<string> = new Set(["verdict_hash", "action", "reason_class"]);

/** SHA-256 over the provenance reproduce-handle, hex-truncated to 16. Identifies
 * the JUDGMENT (public contract), not the tool args. Port of `verdict_hash`. */
export function verdictHash(provenance: Provenance): string {
  return createHash("sha256").update(provenance.reproduceHandle, "utf-8").digest("hex").slice(0, 16);
}

interface SurfaceRecord {
  readonly surfaceId: string;
  readonly at: string;
  readonly posture: string;
  readonly provenance: Provenance;
}

interface ResponseRecord {
  readonly surfaceId: string;
  readonly at: string;
  readonly action: Action;
  readonly reason: OverrideReason | null;
}

const MAX_EVENTS = 50_000;
// Retention window in days (mirrors Python `outcomes._RETENTION_DAYS`). The card reads a
// 30-day summary; we keep a generous trailing window so an offline replay over the recent
// past still has its events, then the hard `MAX_EVENTS` cap backstops a same-day burst.
const RETENTION_DAYS = 62;
const DAY_SECONDS = 86_400;

/** Best-effort ISO-8601 → epoch seconds for the retention window (port of Python
 * `outcomes._parse_iso`). Tolerant of a trailing `Z`. Returns null on an unparseable
 * stamp — kept in-window by the date prune (only the hard cap can evict it), never
 * silently dropped. */
function parseIsoSeconds(s: string): number | null {
  const ms = Date.parse(s.replace(/Z$/, "+00:00"));
  return Number.isNaN(ms) ? null : ms / 1000;
}

/** On-device append-only capture store; ZERO egress of detail. */
export class OutcomeStore {
  private readonly surfaces = new Map<string, SurfaceRecord>();
  private responses: ResponseRecord[] = [];

  constructor(private readonly now: () => string = utcNowIso) {}

  recordSurface(provenance: Provenance, posture: string): string {
    const surfaceId = randomUUID().replace(/-/g, "");
    this.surfaces.set(surfaceId, { surfaceId, at: this.now(), posture, provenance });
    this.prune();
    return surfaceId;
  }

  recordResponse(surfaceId: string, action: Action, reason: OverrideReason | null = null): void {
    this.responses.push({ surfaceId, at: this.now(), action, reason });
    this.prune();
  }

  /** Bound the store so a long-lived session cannot grow it without limit (port of Python
   * `OutcomeStore._prune_locked`). Two passes on the SURFACE store, both anchored on the
   * LATEST surface timestamp so a deterministic test/replay does not depend on wall-clock
   * now: (1) DATE-PRUNE drops surfaces older than `RETENTION_DAYS` (an unparseable stamp is
   * KEPT — only the hard cap can evict it); (2) RING-BUFFER enforces the `MAX_EVENTS` cap,
   * oldest-first. Responses linked to an evicted surface are then dropped (a response that
   * can no longer be anonymize-linked carries no signal — `aggregateRows` would drop it
   * anyway); the response list is independently hard-capped so a flood of externally-minted
   * ids cannot grow the store either. */
  private prune(): void {
    const keys = [...this.surfaces.keys()];
    let keptIds = keys;
    // (1) Date-prune, anchored on the latest parseable surface stamp.
    const stamps: number[] = [];
    for (const s of this.surfaces.values()) {
      const t = parseIsoSeconds(s.at);
      if (t !== null) stamps.push(t);
    }
    if (stamps.length > 0) {
      const cutoff = Math.max(...stamps) - RETENTION_DAYS * DAY_SECONDS;
      keptIds = keys.filter((k) => {
        const t = parseIsoSeconds(this.surfaces.get(k)!.at);
        return t === null || t >= cutoff; // unparseable kept; only the hard cap evicts it
      });
    }
    // (2) Ring-buffer hard cap (oldest-first; Map preserves insertion order).
    if (keptIds.length > MAX_EVENTS) {
      keptIds = keptIds.slice(-MAX_EVENTS);
    }
    if (keptIds.length !== this.surfaces.size) {
      const keepSet = new Set(keptIds);
      const evicted = new Set(keys.filter((k) => !keepSet.has(k)));
      for (const k of evicted) this.surfaces.delete(k);
      // Drop ONLY responses linked to an evicted surface; a response against an
      // externally-minted id never in-store is preserved (it was never evicted).
      this.responses = this.responses.filter((r) => !evicted.has(r.surfaceId));
    }
    // (3) Independently hard-cap the response list (oldest-first).
    if (this.responses.length > MAX_EVENTS) {
      this.responses = this.responses.slice(-MAX_EVENTS);
    }
  }

  surfaceCount(): number {
    return this.surfaces.size;
  }

  responseCount(): number {
    return this.responses.length;
  }

  /** The ONLY projection that may ever leave the device. One row per response,
   * `{verdict_hash, action, reason_class}` only; a response with no resolvable
   * surface is DROPPED (fail-closed). Port of `aggregate_rows`. */
  aggregateRows(): Array<Record<string, string>> {
    const rows: Array<Record<string, string>> = [];
    for (const r of this.responses) {
      const surf = this.surfaces.get(r.surfaceId);
      if (surf === undefined) continue;
      rows.push({
        verdict_hash: verdictHash(surf.provenance),
        action: r.action,
        reason_class: r.reason !== null ? r.reason : "",
      });
    }
    return rows;
  }
}

/** Local on-device counters — the analog of Python `LocalStats`, narrowed to what
 * the wrapper records (gate calls + a 30-day HOLD tally for the banner). */
export class LocalStats {
  private holds = 0;
  private repins = 0;
  private overCap = 0;

  recordHold(): void {
    this.holds += 1;
  }

  recordRepin(): void {
    this.repins += 1;
  }

  recordOverCap(): void {
    this.overCap += 1;
  }

  holdsThisMonth(): number {
    return this.holds;
  }

  repinCount(): number {
    return this.repins;
  }

  overCapCount(): number {
    return this.overCap;
  }
}
