/**
 * Ambient presence — a subtle, low-frequency "mcpindex is watching this" signal.
 * A faithful TS port of Python `tooling/cse/ambient.py`.
 *
 * WHAT THIS IS. A read and an irreversible delete look identical to an agent until
 * something labels them. The gate already labels the dangerous ones loudly (a HOLD).
 * This adds the OTHER half: a quiet, ambient trace on the *normal* (PROCEED) path so
 * a user remembers mcpindex is doing its job — without it ever being in their face.
 *
 * WHAT IT IS NOT. It does NOT change a single gate decision, and it is NOT spam.
 * Default cadence is FIRST-TOUCH: one dim line the first time each tool is used in a
 * session, then silence for every repeat call, plus an optional once-per-session summary.
 *
 * CHANNEL SAFETY (load-bearing). The signal goes ONLY to stderr (`process.stderr`) and
 * an optional observer callback — NEVER stdout (that is the JSON-RPC / agent-output
 * channel; writing there would corrupt the protocol or pollute the model's context and
 * change behavior). This module never writes stdout and never returns anything a caller
 * is meant to put on stdout.
 *
 * PRIVACY (deny-by-construction). A note carries only the server id, the tool NAME
 * (public contract, not an argument), and closed-vocabulary enum strings from the
 * Tier-0a classification. No argument value can ride along — there is no field for one.
 *
 * HONEST VOICE. Never the words protected / secured / safe in any emitted line.
 */

const AMBIENT_ENV = "MCPINDEX_AMBIENT_NOTICE"; // master switch (default ON)
const AMBIENT_MODE_ENV = "MCPINDEX_AMBIENT_NOTICE_MODE"; // cadence tune
const UNKNOWN = "unknown";
// Shown ONCE per session (appended to the first emitted line) so a user can always
// discover how to turn the signal off without reading source or docs.
const SILENCE_HINT = `silence: ${AMBIENT_ENV}=off`;
const MAX_LABEL = 128; // bound a remote-controlled name before it reaches a terminal / log
const SEEN_CAP = 4096; // bound the per-session dedupe set (a hostile server can't grow it unbounded)

// eslint-disable-next-line no-control-regex
// Includes U+2028/U+2029 (LINE / PARAGRAPH SEPARATOR) for parity with Python str.isprintable()
// (which drops Zl/Zp): both can forge an apparent newline in JS / log-viewer contexts.
const CONTROL_CHARS = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g;

/** Sanitize a remote-server-controlled label (tool/server name) before it is rendered into a
 * stderr line: drop ANSI escapes / CR / LF / other control bytes and bound the length. Defends
 * the terminal and any downstream log parser against forged-line / escape-sequence injection. */
function safeLabel(value: unknown): string {
  const text = typeof value === "string" ? value : String(value);
  return text.replace(CONTROL_CHARS, "").slice(0, MAX_LABEL);
}

/** Cadence. FIRST_TOUCH (default): one line per distinct tool, then silent + a session
 * summary. SUMMARY: no per-call lines, only the end-of-session footer. EVERY: a line on
 * every call (loud — opt-in only). OFF: nothing. */
export enum AmbientMode {
  FIRST_TOUCH = "first_touch",
  SUMMARY = "summary",
  EVERY = "every",
  OFF = "off",
}

type EnvLike = Record<string, string | undefined>;

const FALSEY = new Set(["0", "false", "no", "off"]);
const EXPLICIT_ON = new Set(["1", "true", "yes", "on", "first_touch", "summary", "every"]);

function lower(value: string | undefined): string {
  return (value ?? "").trim().toLowerCase();
}

/** Resolve the cadence from the environment. The master switch wins: if
 * `MCPINDEX_AMBIENT_NOTICE` is a falsey string the result is OFF regardless of the tune.
 * Otherwise `MCPINDEX_AMBIENT_NOTICE_MODE` picks the cadence; default FIRST_TOUCH.
 * Quiet by default in CI or when DO_NOT_TRACK is set (strong "no chatter" signals — an
 * ambient line is noise in automated logs), UNLESS the user explicitly turned it on. */
export function resolveMode(env?: EnvLike): AmbientMode {
  const source: EnvLike = env ?? process.env;
  const master = lower(source[AMBIENT_ENV]);
  if (FALSEY.has(master)) return AmbientMode.OFF;
  const explicitOn = EXPLICIT_ON.has(master);
  const ci = lower(source["CI"]);
  const ciTruthy = ci !== "" && !FALSEY.has(ci);
  if (!explicitOn && (source["DO_NOT_TRACK"] !== undefined || ciTruthy)) {
    return AmbientMode.OFF;
  }
  const tune = lower(source[AMBIENT_MODE_ENV]);
  for (const mode of Object.values(AmbientMode)) {
    if (tune === mode) return mode;
  }
  return AmbientMode.FIRST_TOUCH;
}

/** One ambient observation. `text` is the rendered, secret-free line; the structured
 * fields let an observer (an SDK integrator's UI) render its own surface. */
export interface AmbientNote {
  readonly serverId: string;
  readonly toolName: string;
  readonly action: string; // closed-vocab action_type, or "unknown"
  readonly reversible: string; // "reversible" | "irreversible" | "unknown"
  readonly text: string;
}

/** An optional sink an SDK integrator wires to surface the signal in their OWN UI — the
 * only way the in-path library can reach a chat end-user. Best-effort: it must not raise
 * (the notifier swallows it if it does). */
export type AmbientObserver = (note: AmbientNote) => void;

/** A minimal stderr sink (a `process.stderr`-like object). Tests inject a capture. */
export interface WritableLike {
  write(chunk: string): unknown;
}

/** The Tier-0a classification block this module reads from — tolerant by design (it may
 * be a hand-built dict, a server-derived `ActionClassification`, null, or undefined).
 * Anything that is not a readable object → "unknown". Mirrors the Python `Any` param. */
export type ClassificationLike = unknown;

function enumField(classification: ClassificationLike, key: string): string {
  if (classification === null || classification === undefined || typeof classification !== "object") {
    return UNKNOWN;
  }
  const value = (classification as Record<string, unknown>)[key];
  return typeof value === "string" && value ? value : UNKNOWN;
}

/** Map the classification's reversibility onto a plain 'reversible'/'irreversible' word.
 * Conservative: only a clearly-reversible signal reads 'reversible'; anything else that
 * is a known irreversible/destructive shape reads 'irreversible'; unknown stays unknown. */
function reversibleWord(classification: ClassificationLike): string {
  const raw = enumField(classification, "reversibility").toLowerCase();
  if (raw.includes("irreversible")) return "irreversible";
  if (raw.includes("hard-to-reverse") || raw.includes("hard_to_reverse")) return "hard-to-reverse";
  if (raw.includes("reversible")) return "reversible";
  return UNKNOWN;
}

export interface AmbientNotifierOptions {
  mode?: AmbientMode;
  stderr?: WritableLike;
  observer?: AmbientObserver | null;
}

export interface AmbientFromEnvOptions {
  env?: EnvLike;
  stderr?: WritableLike;
  observer?: AmbientObserver | null;
}

/** Per-session ambient signal. Dedupe is per (server, tool); state is in-memory only
 * (a session is the natural unit — a new process re-announces, which is correct). Holds
 * no secret, touches no disk, makes no network call. */
export class AmbientNotifier {
  private readonly mode: AmbientMode;
  private readonly stderr: WritableLike;
  private readonly observer: AmbientObserver | null;
  private readonly seen = new Set<string>();
  private readonly servers = new Set<string>();
  private tools = 0;
  private hinted = false; // the silence hint is appended to the FIRST emitted line only

  constructor(options: AmbientNotifierOptions = {}) {
    this.mode = options.mode ?? AmbientMode.FIRST_TOUCH;
    this.stderr = options.stderr ?? process.stderr;
    this.observer = options.observer ?? null;
  }

  static fromEnv(options: AmbientFromEnvOptions = {}): AmbientNotifier {
    return new AmbientNotifier({
      mode: resolveMode(options.env),
      stderr: options.stderr,
      observer: options.observer,
    });
  }

  get enabled(): boolean {
    return this.mode !== AmbientMode.OFF;
  }

  /** Render the structured note + its one-line text. Pure (no emit), so the wording is
   * directly testable. Honest voice: 'watching', never 'protected'/'safe'. */
  buildNote(serverId: string, toolName: string, classification?: ClassificationLike): AmbientNote {
    // The Tier-0a block serializes the single derived type as `effective_action_type`;
    // fall back to `action_type` so a hand-built classification (tests/integrators) works.
    let action = enumField(classification, "effective_action_type");
    if (action === UNKNOWN) action = enumField(classification, "action_type");
    const reversible = reversibleWord(classification);
    // Drop the "— action, reversible" clause when the blast radius is unknown (e.g. the TS
    // SDK has no local classifier yet) so the line reads clean instead of "— unknown, unknown".
    const detail = action === UNKNOWN && reversible === UNKNOWN ? "" : ` — ${action}, ${reversible}`;
    const text = `mcpindex · noted ${safeLabel(serverId)}/${safeLabel(toolName)}${detail}`;
    return { serverId, toolName, action, reversible, text };
  }

  /** Record one PROCEED-path invocation; emit per the cadence. Returns the note IFF a
   * line was emitted (else null). Never throws — an ambient signal must not perturb the
   * gate path it rides. */
  noteInvocation(serverId: string, toolName: string, classification?: ClassificationLike): AmbientNote | null {
    if (this.mode === AmbientMode.OFF) return null;
    const key = `${serverId}\x00${toolName}`;
    let first = !this.seen.has(key);
    if (first) {
      if (this.seen.size >= SEEN_CAP) {
        first = false; // cap reached → treat as seen so a hostile server can't grow it unbounded
      } else {
        this.seen.add(key);
        this.servers.add(serverId);
        this.tools += 1;
      }
    }
    const note = this.buildNote(serverId, toolName, classification);
    const emit = this.mode === AmbientMode.EVERY || (this.mode === AmbientMode.FIRST_TOUCH && first);
    if (emit) this.emit(note.text, note);
    return emit ? note : null;
  }

  /** The once-per-session footer. Emits + returns the line (or null when OFF, or when
   * nothing was ever watched). `drift`/`flagged` are included ONLY when the caller passes
   * real counts — never fabricated, so a caller without counters omits them honestly. */
  sessionSummary(counts: { drift?: number; flagged?: number } = {}): string | null {
    if (this.mode === AmbientMode.OFF || this.tools === 0) return null;
    let base = `mcpindex noted ${this.tools} tool(s) / ${this.servers.size} server(s) this session`;
    const { drift, flagged } = counts;
    if (drift !== undefined && flagged !== undefined) {
      base += ` — ${drift} drift, ${flagged} flagged`;
    }
    const text = `${base} · mcpindex.ai`;
    this.emit(text, null);
    return text;
  }

  // -------------------------------------------------------------- emit (stderr ONLY)
  /** The ONLY output path. stderr (reliable) + the observer (best-effort). NEVER stdout.
   * Every sink is guarded so a broken stream/observer cannot perturb the gate. */
  private emit(text: string, note: AmbientNote | null): void {
    let line = text;
    if (!this.hinted) {
      line = `${text}  (${SILENCE_HINT})`;
      this.hinted = true;
    }
    try {
      this.stderr.write(`${line}\n`);
    } catch {
      // a broken stderr must not surface into the gate
    }
    if (this.observer !== null && note !== null) {
      try {
        this.observer(note);
      } catch {
        // a broken observer is the integrator's bug, never the gate's
      }
    }
  }
}
