/**
 * Drift telemetry — the detection-tier emit (M1 of the usage-log drift flywheel).
 *
 * Opt-in (`MCPINDEX_DRIFT_TELEMETRY` ∈ {off,lookup,detection,contribute}, default off),
 * fire-and-forget, fail-OPEN. On a TOFU pin (coverage) or a classified drift (outcome),
 * emit a CLOSED, privacy-by-construction signal: fingerprints (a KEY over a public
 * registry, not anonymity) + change enums +
 * content hashes ONLY — NEVER a schema, an argument, a URL, or a plaintext server/tool
 * name. Mirrors the `outcomes.ts` discipline: the only thing that ever leaves the device
 * is a safe projection built by construction, not a redaction of a richer record.
 *
 * PRIVACY INVARIANT (enforced by construction + the leak test): the DriftSignal has no
 * field that can hold a raw string from the tool's schema/args/description.
 *   - server_fp / tool_fp are HMAC-SHA256 fingerprints under a GLOBAL salt. Global salt =>
 *     a public server_id is de-anonymizable by anyone who can guess it (ACCEPTED — public
 *     servers are public); a private/internal server_id is unreversible (PROTECTED).
 *   - prev_hash / new_hash are the gate's own `definition_hash` — already a SHA over the
 *     canonical contract, public-by-design (it is what the verdict is keyed on).
 *   - change_kinds is the closed `ChangeKind` enum vocabulary; safety_relevant is a bool.
 *   - at_hour is coarsened to the hour (no sub-hour timing fingerprint).
 *
 * The emit path NEVER blocks on the network and NEVER throws: it appends to a bounded ring
 * buffer and returns; a single unref'd timer flushes batches in the background. A flush
 * failure DROPS the batch (no retry) — losing telemetry is always preferable to perturbing
 * a tool call. Telemetry is a SINGLETON across every Gate (one buffer, one timer).
 *
 * Byte-identical fingerprints to the Python port `tooling/cse/drift_telemetry.py` — the
 * cross-language parity test pins this.
 */

import { createHmac } from "node:crypto";
import { homedir } from "node:os";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import type { Change } from "./schemaDiff.js";

const GLOBAL_SALT = "mcpindex-drift-v1";
const SEP = "\x1f";
const INGEST_URL = "https://mcpindex.ai/api/v1/drift";
const FLUSH_THRESHOLD = 16; // flush eagerly once the buffer reaches this depth
const FLUSH_INTERVAL_MS = 30_000; // …else the timer flushes a partial batch
const MAX_BUFFER = 256; // hard ring-buffer cap; oldest dropped on overflow
const POST_TIMEOUT_MS = 5_000;
const SDK_TAG = "ts";
const VALID_MODES = new Set(["off", "lookup", "detection", "contribute"]);

export type DriftMode = "off" | "lookup" | "detection" | "contribute";

/** The canonical human-readable consent notice — the single source of truth for the README
 * and the future first-run prompt (M5). Byte-identical to the Python `DRIFT_TELEMETRY_NOTICE`. */
export const DRIFT_TELEMETRY_NOTICE =
  "mcpindex drift telemetry is OFF by default (zero egress). MCPINDEX_DRIFT_TELEMETRY=lookup is " +
  "warnings-only and low-egress, not zero-egress: each tool sends one fingerprint to " +
  "query the public fleet drift ledger and nothing else - never your gate's catches, contract " +
  "hashes, or drift signals. When you enable detection (MCPINDEX_DRIFT_TELEMETRY=detection), " +
  "each tool you pin and each contract drift sends one one-way signal: fingerprints of " +
  "the server/tool id, the contract hashes, the change type (a fixed vocabulary), a safety flag, " +
  "an hour-rounded time, a random install id, and a client SDK tag (py or ts). It NEVER sends " +
  "tool schemas, arguments, descriptions, URLs, or your data. The fingerprints carry no " +
  "plaintext name and they are NOT anonymity: the salt is a constant in this client and the " +
  "registry is public, so a listed server's fingerprint reverses. The install id " +
  "is a random token (not derived from you) that links one machine's signals so distinct " +
  "installs can be counted. It exists to catch drift on servers we cannot reach ourselves. " +
  "On the SDK path, unset " +
  "the variable any time to stop. After a `mcpindex-config-wire` install, run " +
  "`mcpindex-config-wire wire --repin --drift-telemetry off` instead, which clears the " +
  "key from the wired config entry. A shell that exports MCPINDEX_DRIFT_TELEMETRY " +
  "still reaches the proxy, so unset it there too.";

/** The CLOSED wire payload. Every field is a fingerprint, a content hash, a closed enum,
 * a bool, an hour-stamp, or the opaque install id — never a raw tool string. */
export interface DriftSignal {
  readonly v: 1;
  readonly event: "pin" | "drift";
  readonly server_fp: string;
  readonly tool_fp: string;
  readonly prev_hash: string | null;
  readonly new_hash: string;
  readonly change_kinds: string[] | null;
  readonly safety_relevant: boolean;
  readonly at_hour: string;
  readonly sdk: string;
  readonly install_id: string;
}

export type DriftTransport = (batch: DriftSignal[]) => Promise<void>;

/** HMAC-SHA256(GLOBAL_SALT, msg) hex, truncated to 16 bytes (32 hex chars). Byte-identical
 * to the Python `_fingerprint`. */
export function fingerprint(msg: string): string {
  return createHmac("sha256", GLOBAL_SALT).update(msg, "utf-8").digest("hex").slice(0, 32);
}

export function serverFp(serverId: string): string {
  return fingerprint(serverId);
}

export function toolFp(serverId: string, toolName: string): string {
  return fingerprint(serverId + SEP + toolName);
}

// Distinct HMAC key for server-scoped context-surface fingerprints (drain plane). A distinct
// key is a distinct PRF, so no (serverId, toolName) pair under GLOBAL_SALT can collide with
// it. No client mints this fp; the export exists for cross-language parity pinning with the
// Python `context_fp`.
const CTX_SALT = "mcpindex-drift-ctx-v1";

export function contextFp(serverId: string): string {
  return createHmac("sha256", CTX_SALT).update(serverId, "utf-8").digest("hex").slice(0, 32);
}

/** Coarsen an ISO-8601 stamp to the hour: "2026-06-09T05:09:46.123Z" → "2026-06-09T05:00:00Z".
 * Returns "" on any unexpected shape (never leaks sub-hour precision; never throws). Mirrors
 * the Python `_at_hour`. */
export function atHour(nowIso: string): string {
  const head = nowIso.slice(0, 13); // YYYY-MM-DDTHH
  if (head.length === 13 && head[4] === "-" && head[7] === "-" && head[10] === "T") {
    return head + ":00:00Z";
  }
  return "";
}

/** Build the coverage (pin) signal. Pure — exported for the leak/parity tests. */
export function buildPinSignal(
  serverId: string,
  toolName: string,
  definitionHash: string,
  nowIso: string,
  installId: string,
): DriftSignal {
  return {
    v: 1,
    event: "pin",
    server_fp: serverFp(serverId),
    tool_fp: toolFp(serverId, toolName),
    prev_hash: null,
    new_hash: definitionHash,
    change_kinds: null,
    safety_relevant: false,
    at_hour: atHour(nowIso),
    sdk: SDK_TAG,
    install_id: installId,
  };
}

/** Build the outcome (drift) signal. Pure — exported for the leak/parity tests. The change
 * details (path/detail strings, which CAN carry tool text) are DROPPED here by construction;
 * only the closed `kind` enum and the `safetyRelevant` bool survive. */
export function buildDriftSignal(
  serverId: string,
  toolName: string,
  prevHash: string,
  newHash: string,
  changes: readonly Change[],
  nowIso: string,
  installId: string,
): DriftSignal {
  const kindsSeen = new Set<string>();
  let safety = false;
  for (const c of changes) {
    kindsSeen.add(String(c.kind));
    if (c.safetyRelevant) safety = true;
  }
  // Sort + dedupe: downstream uses only kind MEMBERSHIP (never order/multiplicity), so a
  // sorted unique list is lossless for us AND denies a hostile server the attacker-chosen
  // ordering/count of change_kinds as a covert-channel field. Deterministic across the
  // TS/Python ports (ASCII lowercase+hyphen sort identically).
  const kinds = [...kindsSeen].sort();
  return {
    v: 1,
    event: "drift",
    server_fp: serverFp(serverId),
    tool_fp: toolFp(serverId, toolName),
    prev_hash: prevHash,
    new_hash: newHash,
    change_kinds: kinds,
    safety_relevant: safety,
    at_hour: atHour(nowIso),
    sdk: SDK_TAG,
    install_id: installId,
  };
}

/** Default transport: POST the batch to the fixed mcpindex ingest URL. The destination is a
 * HARD-CODED constant (no attacker influence → no SSRF surface). Best-effort, bounded. */
async function httpPost(batch: DriftSignal[]): Promise<void> {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), POST_TIMEOUT_MS);
  try {
    await fetch(INGEST_URL, {
      method: "POST",
      headers: { "content-type": "application/json", "user-agent": "mcpindex-sdk" },
      body: JSON.stringify({ signals: batch }),
      signal: ctl.signal,
    });
  } finally {
    clearTimeout(t);
  }
}

function readMode(): DriftMode {
  const raw = (process.env.MCPINDEX_DRIFT_TELEMETRY ?? "off").trim().toLowerCase();
  return (VALID_MODES.has(raw) ? raw : "off") as DriftMode;
}

/** Read (or first-time create) the opaque, persistent install id at ~/.mcpindex/install_id.
 * A random hex token — NOT derived from any host/user identifier — used only to count
 * distinct installs server-side. Fail-open: any fs error → an ephemeral per-process id. */
function readOrCreateInstallId(): string {
  try {
    const dir = join(homedir(), ".mcpindex");
    const file = join(dir, "install_id");
    try {
      const existing = readFileSync(file, "utf-8").trim();
      if (existing) return existing.slice(0, 32); // writer + ingest schema agree on exactly 32 hex
    } catch {
      /* not yet created */
    }
    mkdirSync(dir, { recursive: true });
    const id = randomBytes(16).toString("hex");
    writeFileSync(file, id, { encoding: "utf-8", mode: 0o600 });
    return id;
  } catch {
    return randomBytes(16).toString("hex"); // ephemeral; never crash the host
  }
}

/** The singleton emit engine. One per process; every Gate shares it. */
class DriftTelemetry {
  private buffer: DriftSignal[] = [];
  private timer: ReturnType<typeof setInterval> | null = null;
  private flushing = false; // in-flight guard: serialize flushes, never fan out parallel POSTs
  private mode: DriftMode | null = null;
  private cachedInstallId: string | null = null;
  private transport: DriftTransport = httpPost;

  private resolveMode(): DriftMode {
    if (this.mode === null) this.mode = readMode();
    return this.mode;
  }

  readEnabled(): boolean {
    return this.resolveMode() !== "off";
  }

  sendEnabled(): boolean {
    const m = this.resolveMode();
    return m === "detection" || m === "contribute";
  }

  enabled(): boolean {
    return this.readEnabled();
  }

  private installId(): string {
    if (this.cachedInstallId === null) this.cachedInstallId = readOrCreateInstallId();
    return this.cachedInstallId;
  }

  private enqueue(sig: DriftSignal): void {
    // Defense-in-depth re-check (parity with Python _enqueue): callers gate on
    // sendEnabled(), but the enqueue boundary must hold on its own.
    if (!this.sendEnabled()) return;
    this.buffer.push(sig);
    if (this.buffer.length > MAX_BUFFER) this.buffer.shift(); // drop oldest, fail-open
    if (this.timer === null) {
      this.timer = setInterval(() => void this.flush(), FLUSH_INTERVAL_MS);
      // Do not keep the host process alive for a telemetry timer.
      this.timer.unref?.();
    }
    if (this.buffer.length >= FLUSH_THRESHOLD) void this.flush();
  }

  /** Drain the buffer and POST it. Best-effort: a transport failure drops the batch with no
   * retry (fail-open). Never throws. */
  async flush(): Promise<void> {
    // In-flight guard: only one flush at a time. A threshold enqueue while a POST is pending
    // does NOT spawn a parallel fetch (which under a flood would fan out unbounded sockets);
    // the buffered signals ride the next flush. Ingest counters are commutative, so serializing
    // costs nothing. Mirrors the Python single-daemon serialization.
    if (this.flushing || this.buffer.length === 0) return;
    this.flushing = true;
    const batch = this.buffer;
    this.buffer = [];
    try {
      await this.transport(batch);
    } catch {
      /* drop the batch; never perturb the host */
    } finally {
      this.flushing = false;
    }
  }

  recordPin(serverId: string, toolName: string, definitionHash: string, nowIso: string): void {
    try {
      if (!this.sendEnabled()) return;
      this.enqueue(buildPinSignal(serverId, toolName, definitionHash, nowIso, this.installId()));
    } catch {
      /* fail-open: telemetry must never affect the gate */
    }
  }

  recordDrift(
    serverId: string,
    toolName: string,
    prevHash: string,
    newHash: string,
    changes: readonly Change[],
    nowIso: string,
  ): void {
    try {
      if (!this.sendEnabled()) return;
      this.enqueue(
        buildDriftSignal(serverId, toolName, prevHash, newHash, changes, nowIso, this.installId()),
      );
    } catch {
      /* fail-open */
    }
  }

  // ---- test seams (underscore-prefixed; not part of the public SDK surface) ----
  _setTransport(t: DriftTransport): void {
    this.transport = t;
  }
  _reset(): void {
    this.buffer = [];
    this.flushing = false;
    if (this.timer !== null) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.mode = null;
    this.cachedInstallId = "test-install";
  }
  _drainForTest(): DriftSignal[] {
    const b = this.buffer;
    this.buffer = [];
    return b;
  }
}

/** Process-wide singleton. The Gate calls `driftTelemetry.recordPin/recordDrift`. */
export const driftTelemetry = new DriftTelemetry();
