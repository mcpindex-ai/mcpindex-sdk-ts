/**
 * Fleet drift query (M3, SDK side) — the "warns you on call 1" client.
 *
 * On the FIRST pin of a tool (`observe`, i.e. list_tools), fire-and-forget a GET to the public
 * `/api/v1/drift/any?fp=<tool_fp>` asking whether the fleet has CORROBORATED drift for this tool
 * (the central crawl saw the drift; install reports are corpus-only, never public). Cache it; the
 * gate reads it at `evaluate` time and attaches it as an ADVISORY on the verdict. Because pins
 * happen at session start and calls come later, the cache is warm by the first call — so a user
 * is warned about a tool that drifted for OTHERS before they're ever burned themselves.
 *
 * Discipline (mirrors driftTelemetry):
 *   - Opt-in: gated on `driftTelemetry.readEnabled()` (lookup/detection/contribute; off sends
 *     nothing). The queried `tool_fp` is the exact salted fingerprint used on the wire in send
 *     modes; lookup mode sends only this fp to the public ledger.
 *   - Fail-OPEN + never blocks: the query is async/off-thread; the gate never awaits it. A miss
 *     or error caches nothing (retried next session). `drifted:null` ("unknown") is never a warn.
 *   - AD-6-safe: the advisory rides ALONGSIDE the decision and never moves PROCEED/HOLD. It is a
 *     contract-diff observation ("this tool's contract drifted for the fleet"), not a safety claim.
 */

import { driftTelemetry, toolFp } from "./driftTelemetry.js";

const QUERY_URL = "https://mcpindex.ai/api/v1/drift/any";
const QUERY_TIMEOUT_MS = 4_000;
const MAX_CACHE = 4_096; // bound the per-process cache

/** The advisory the gate attaches when the fleet has corroborated this tool's contract drift.
 * `provenance:'crawl'` = mcpindex's own crawler observed the drift (sources=1, the unforgeable
 * first-party observer). `provenance:'installs'` = a dark-surface tool the crawler cannot see,
 * where N>=2 reputable authenticated installs independently corroborated the same transition
 * (sources=N, the distinct reputable count). A `null`/absent advisory means "not corroborated
 * drifting" — NOT a verified all-clear (the crawl only covers public-registry servers). */
export interface FleetAdvisory {
  readonly drifted: true;
  readonly provenance: "crawl" | "installs";
  // crawl: 1 = mcpindex's crawler. installs: N = distinct reputable install corroborators (>=2).
  readonly sources: number;
  readonly safetyRelevant: boolean;
}

interface AnyResponse {
  drifted: boolean | null;
  provenance?: string;
  sources?: number;
  safety_relevant?: boolean;
}

export type FleetTransport = (fp: string) => Promise<AnyResponse | null>;

async function httpGet(fp: string): Promise<AnyResponse | null> {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), QUERY_TIMEOUT_MS);
  try {
    const res = await fetch(`${QUERY_URL}?fp=${fp}`, {
      method: "GET",
      headers: { "user-agent": "mcpindex-sdk" },
      signal: ctl.signal,
      // Hard-off redirects: a 3xx off mcpindex's origin must never forward the fp elsewhere.
      // An opaque redirect has ok=false, so it's treated as a miss.
      redirect: "manual",
    });
    if (!res.ok) return null;
    return (await res.json()) as AnyResponse;
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

/** Process-wide singleton. The Gate calls prefetch (on pin) + lookup (on evaluate). */
class DriftQuery {
  // fp -> advisory (drifted) | "clean" sentinel. Absent = not yet known / unknown.
  private cache = new Map<string, FleetAdvisory | "clean">();
  private inflight = new Set<string>();
  private transport: FleetTransport = httpGet;

  /** Fire-and-forget: query the fleet for this tool's fp and cache the result. Never blocks,
   * never throws. Gated on readEnabled (lookup/detection/contribute). */
  prefetch(serverId: string, toolName: string): void {
    try {
      if (!driftTelemetry.readEnabled()) return;
      const fp = toolFp(serverId, toolName);
      if (this.cache.has(fp) || this.inflight.has(fp)) return;
      this.inflight.add(fp);
      void this.fetch(fp);
    } catch {
      /* fail-open */
    }
  }

  private async fetch(fp: string): Promise<void> {
    try {
      const res = await this.transport(fp);
      if (res && res.drifted === true) {
        if (this.cache.size >= MAX_CACHE) this.cache.clear();
        this.cache.set(fp, {
          drifted: true,
          provenance: res.provenance === "installs" ? "installs" : "crawl",
          sources: typeof res.sources === "number" && res.sources >= 1 ? res.sources : 1,
          safetyRelevant: res.safety_relevant === true,
        });
      } else if (res && res.drifted === false) {
        if (this.cache.size >= MAX_CACHE) this.cache.clear();
        this.cache.set(fp, "clean");
      }
      // drifted:null (unknown) => cache nothing; retry on a later session
    } catch {
      /* fail-open */
    } finally {
      this.inflight.delete(fp);
    }
  }

  /** Sync cache read used by the gate at evaluate time. Returns the advisory ONLY for a
   * corroborated-drifted tool; null otherwise (clean, unknown, or query disabled). */
  lookup(serverId: string, toolName: string): FleetAdvisory | null {
    try {
      if (!driftTelemetry.readEnabled()) return null;
      const hit = this.cache.get(toolFp(serverId, toolName));
      return hit && hit !== "clean" ? hit : null;
    } catch {
      return null;
    }
  }

  // ---- test seams ----
  _setTransport(t: FleetTransport): void {
    this.transport = t;
  }
  _reset(): void {
    this.cache.clear();
    this.inflight.clear();
  }
  /** Await all in-flight fetches (test only — production never awaits). */
  async _settle(): Promise<void> {
    for (let i = 0; i < 100; i++) {
      await Promise.resolve();
      if (this.inflight.size === 0) return;
    }
  }
}

export const driftQuery = new DriftQuery();
