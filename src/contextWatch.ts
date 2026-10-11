/**
 * The server's `instructions`, observed and pinned (port of Python
 * `context_observe` / `context_pin`, observation only).
 *
 * MCP hosts put a server's `instructions` into the agent's context on connect.
 * The tool hash does not cover them, so a server can keep every tool identical
 * and rewrite the text the model reads first. The wrapper reads them after
 * connect, pins them on first sight beside the tool pins, and reports a change.
 * It never changes what `getInstructions()` returns: stripping the text removes
 * the server's own guidance, replaying a pinned copy freezes first-connect text,
 * and holding calls is a denial of service whoever controls the text can aim.
 *
 * The file is the same format the Python store writes
 * (`.<stem>.context.json`, schema_version 1, a map of server id to pin), so a
 * proxy and a wrapper on one server share a baseline. Limits against Python: no
 * digit-budget carve-out (a numbers-only change is reported as
 * `numeric-unbounded`), and the store is not recorded in the ever-pinned index,
 * so a deleted TS-written store reads as a first run.
 */

import { createHash, randomBytes } from "node:crypto";
import {
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
import { basename, dirname, join } from "node:path";

import { ChangeKind, isNumericOnlyDescriptionChange } from "./schemaDiff.js";

const CONTEXT_STORE_VERSION = 1;
const MAX_INSTRUCTIONS_CHARS = 16_384;
const LEG = "instructions";
const SAFETY_KINDS = new Set<string>([ChangeKind.INSTRUCTIONS_ADDED, ChangeKind.INSTRUCTIONS_CHANGED]);

export type ContextOutcome =
  | "pinned"
  | "unchanged"
  | "numeric-unbounded"
  | "drifted"
  | "cosmetic"
  | "unobserved"
  | "tainted"
  | "skewed";

export interface ContextObservation {
  readonly outcome: ContextOutcome;
  readonly serverId: string;
  readonly kinds: readonly string[];
  readonly safetyRelevant: boolean;
  readonly detail: string;
}

interface Leg {
  status: string;
  text: string | null;
  text_dropped: boolean;
  hash: string | null;
  len: number | null;
}

interface ContextPinJson {
  server_id: string;
  pinned_at: string;
  via: string;
  protocol_version: string | null;
  observed_via: string | null;
  legs: Record<string, Leg>;
  observed: Record<string, Leg>;
  observed_at: string | null;
}

/** `.<stem>.context.json` beside the tool pin file (Python `default_context_store_path`). */
export function defaultContextStorePath(pinStorePath: string): string {
  let stem = basename(pinStorePath);
  if (stem.endsWith(".json")) stem = stem.slice(0, -".json".length);
  return join(dirname(pinStorePath) || ".", `.${stem}.context.json`);
}

/** The instructions leg as Python `_instructions_from` shapes it: the hash is over
 * the full UTF-8 text, the length counts code points, and text over the cap is
 * dropped, never truncated. */
export function legFromInstructions(raw: unknown): Leg {
  if (typeof raw !== "string" || raw.length === 0) {
    return { status: "ok", text: null, text_dropped: false, hash: null, len: null };
  }
  const len = [...raw].length;
  const hash = "sha256:" + createHash("sha256").update(Buffer.from(raw, "utf8")).digest("hex");
  const text = len <= MAX_INSTRUCTIONS_CHARS ? raw : null;
  return { status: "ok", text, text_dropped: text === null, hash, len };
}

function parseLeg(raw: unknown): Leg | null {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) return null;
  const r = raw as Record<string, unknown>;
  if (typeof r["status"] !== "string") return null;
  const ln = r["len"];
  return {
    status: r["status"],
    text: typeof r["text"] === "string" ? r["text"] : null,
    text_dropped: r["text_dropped"] === true,
    hash: typeof r["hash"] === "string" ? r["hash"] : null,
    len: Number.isInteger(ln) && (ln as number) >= 0 ? (ln as number) : null,
  };
}

function parsePin(raw: unknown): ContextPinJson | null {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) return null;
  const r = raw as Record<string, unknown>;
  const sid = r["server_id"];
  const at = r["pinned_at"];
  if (typeof sid !== "string" || sid.length === 0 || typeof at !== "string") return null;
  const legs: Record<string, Leg> = {};
  const rawLegs = r["legs"];
  if (rawLegs !== undefined && rawLegs !== null) {
    if (typeof rawLegs !== "object" || Array.isArray(rawLegs)) return null;
    for (const [name, value] of Object.entries(rawLegs as Record<string, unknown>)) {
      const leg = parseLeg(value);
      if (leg === null) return null; // a pin with a hole in it would re-pin
      legs[name] = leg;
    }
  }
  const observed: Record<string, Leg> = {};
  const rawObs = r["observed"];
  if (rawObs !== null && typeof rawObs === "object" && !Array.isArray(rawObs)) {
    for (const [name, value] of Object.entries(rawObs as Record<string, unknown>)) {
      const leg = parseLeg(value);
      if (leg === null) return null;
      observed[name] = leg;
    }
  }
  const str = (v: unknown): string | null => (typeof v === "string" ? v : null);
  return {
    server_id: sid,
    pinned_at: at,
    via: r["via"] === "manual" ? "manual" : "tofu",
    protocol_version: str(r["protocol_version"]),
    observed_via: str(r["observed_via"]),
    legs,
    observed,
    observed_at: str(r["observed_at"]),
  };
}

/** One stem's context pins. Unreadable, non-regular or newer-format files are
 * tainted and never written. */
class ContextStore {
  private pins = new Map<string, ContextPinJson>();
  tainted: string | null = null;

  constructor(readonly path: string) {
    this.load();
  }

  private regular(): boolean | null {
    try {
      return lstatSync(this.path).isFile();
    } catch {
      return null; // absent
    }
  }

  private readDisk(): Map<string, ContextPinJson> | null {
    const regular = this.regular();
    if (regular === null) return new Map();
    if (!regular) {
      this.tainted = "context store is not a regular file";
      return null;
    }
    let raw: unknown;
    try {
      raw = JSON.parse(readFileSync(this.path, "utf8"));
    } catch {
      this.tainted = "context store is unreadable";
      return null;
    }
    if (raw === null || typeof raw !== "object" || (raw as Record<string, unknown>)["schema_version"] !== CONTEXT_STORE_VERSION) {
      this.tainted = "context store has an unsupported format";
      return null;
    }
    const out = new Map<string, ContextPinJson>();
    const servers = (raw as Record<string, unknown>)["servers"];
    if (servers !== null && typeof servers === "object" && !Array.isArray(servers)) {
      for (const [key, value] of Object.entries(servers as Record<string, unknown>)) {
        const pin = parsePin(value);
        if (pin === null) {
          this.tainted = "context store holds an unreadable record";
          continue;
        }
        out.set(key, pin);
      }
    }
    return out;
  }

  private load(): void {
    const disk = this.readDisk();
    if (disk !== null) this.pins = disk;
  }

  get(serverId: string): ContextPinJson | null {
    return this.pins.get(serverId) ?? null;
  }

  put(pin: ContextPinJson): void {
    if (this.tainted !== null) return;
    const disk = this.readDisk();
    if (disk === null) return;
    for (const [key, value] of disk) if (!this.pins.has(key)) this.pins.set(key, value);
    this.pins.set(pin.server_id, pin);
    const servers: Record<string, ContextPinJson> = {};
    for (const key of [...this.pins.keys()].sort()) servers[key] = this.pins.get(key)!;
    const body = JSON.stringify({ schema_version: CONTEXT_STORE_VERSION, servers }, null, 2) + "\n";
    const directory = dirname(this.path) || ".";
    mkdirSync(directory, { recursive: true });
    const tmp = join(directory, `.ctxpin.${process.pid}.${randomBytes(8).toString("hex")}.tmp`);
    const flags =
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0);
    const fd = openSync(tmp, flags, 0o600);
    try {
      writeSync(fd, body);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    try {
      renameSync(tmp, this.path);
    } catch (exc) {
      try {
        unlinkSync(tmp);
      } catch {
        // already gone
      }
      throw exc;
    }
  }
}

/** Classify one observation against the pin (Python `observe`). Pure. */
export function classifyInstructions(
  pinned: ContextPinJson | null,
  observed: Leg,
  serverId: string,
  observedVia: string,
  storeTainted: boolean,
): ContextObservation {
  const obs = (outcome: ContextOutcome, kinds: string[] = [], detail = ""): ContextObservation => ({
    outcome,
    serverId,
    kinds,
    safetyRelevant: kinds.some((k) => SAFETY_KINDS.has(k)),
    detail,
  });
  if (storeTainted) return obs("tainted", [], "context store unreadable");
  const leg = pinned?.legs[LEG] ?? null;
  if (leg === null) return obs("pinned");
  if (leg.hash === observed.hash) return obs("unchanged");
  let kind: string;
  if (leg.hash === null) kind = ChangeKind.INSTRUCTIONS_ADDED;
  else if (observed.hash === null) kind = ChangeKind.INSTRUCTIONS_REMOVED;
  else if (leg.text !== null && observed.text !== null && isNumericOnlyDescriptionChange(leg.text, observed.text)) {
    kind = ChangeKind.INSTRUCTIONS_NUMERIC;
  } else kind = ChangeKind.INSTRUCTIONS_CHANGED;
  if (pinned !== null && pinned.observed_via !== null && pinned.observed_via !== observedVia) {
    return obs("skewed", [kind], `pinned via ${pinned.observed_via}, observed via ${observedVia}`);
  }
  if (kind === ChangeKind.INSTRUCTIONS_NUMERIC) {
    return obs("numeric-unbounded", [kind], "numeric-only change; this SDK does not apply the digit budget");
  }
  return obs(SAFETY_KINDS.has(kind) ? "drifted" : "cosmetic", [kind]);
}

/** Owns one server's context pin and turns observations into reports. */
export class ContextWatcher {
  private readonly store: ContextStore | null;
  private storeError: string | null = null;

  constructor(
    path: string,
    private readonly serverId: string,
    private readonly onEvent: (obs: ContextObservation) => void,
    private readonly now: () => string,
  ) {
    let store: ContextStore | null = null;
    try {
      store = new ContextStore(path);
    } catch (exc) {
      this.storeError = exc instanceof Error ? exc.name : "Error";
    }
    this.store = store;
  }

  get path(): string | null {
    return this.store?.path ?? null;
  }

  observe(instructions: unknown, observedVia: string, protocolVersion: string | null): ContextObservation {
    const leg = legFromInstructions(instructions);
    if (this.store === null) {
      const failed: ContextObservation = {
        outcome: "unobserved",
        serverId: this.serverId,
        kinds: [],
        safetyRelevant: false,
        detail: this.storeError ?? "context store unavailable",
      };
      this.emit(failed);
      return failed;
    }
    const pin = this.store.get(this.serverId);
    const result = classifyInstructions(pin, leg, this.serverId, observedVia, this.store.tainted !== null);
    try {
      if (result.outcome === "pinned") {
        this.store.put({
          server_id: this.serverId,
          pinned_at: this.now(),
          via: "tofu",
          protocol_version: protocolVersion,
          observed_via: observedVia,
          legs: { [LEG]: leg },
          observed: {},
          observed_at: null,
        });
      } else if (pin !== null && result.outcome !== "unchanged" && result.outcome !== "tainted") {
        // Record what was seen without moving the baseline.
        this.store.put({ ...pin, observed: { [LEG]: leg }, observed_at: this.now() });
      }
    } catch {
      // A failed write costs the record, never the session.
    }
    this.emit(result);
    return result;
  }

  private emit(obs: ContextObservation): void {
    if (obs.outcome === "unchanged") return;
    try {
      this.onEvent(obs);
    } catch {
      // a report must never perturb the session
    }
  }
}
