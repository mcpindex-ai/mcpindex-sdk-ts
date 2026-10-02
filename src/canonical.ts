/**
 * The canonical serialization + per-tool hash — a BYTE-FOR-BYTE port of the
 * Python `trust.contract.canonical_bytes` / `_canonicalize` and the connector's
 * `_tool_hash`. A TS-pinned hash MUST equal a Python-pinned hash for the SAME
 * contract, or the cross-language pin chain breaks.
 *
 * CONFORMANCE RULES (from contract.py, load-bearing):
 *  - Objects: keys NFC-normalized, sorted by their string form, separators
 *    `(",",":")`, `ensure_ascii=True` (every non-ASCII char escaped as \uXXXX).
 *  - Strings/keys: Unicode NFC.
 *  - Floats: Python `%.17e` form (`1.50000000000000000e-01`) — exponent sign
 *    ALWAYS present, exponent ALWAYS >= 2 digits zero-padded. JS
 *    `toExponential(17)` does NOT zero-pad the exponent, so we re-pad.
 *  - Integers stay integers; -0.0 collapses to 0.0; non-finite floats raise.
 *  - Depth-capped at 64.
 *
 * NOTE the hash preimage key is `input_schema` (snake_case) — the Python
 * `_hash_tool` maps the public `inputSchema` field onto `input_schema` before
 * hashing. We replicate that exactly.
 */

import { createHash } from "node:crypto";

const FLOAT_DIGITS = 17;
const MAX_CANON_DEPTH = 64;

/** A JSON-ish value the canonicalizer accepts. */
export type Json =
  | null
  | boolean
  | number
  | string
  | Json[]
  | { [k: string]: Json };

function nfc(s: string): string {
  return s.normalize("NFC");
}

/**
 * KNOWN CROSS-LANGUAGE GAP (audit H2) — integral-valued floats.
 *
 * Python's canonicalizer keys off the RUNTIME TYPE: a Python `int` stays an int,
 * a Python `float` becomes the `%.17e` string. Python `json.loads` PRESERVES that
 * distinction off the wire — `0.0` parses to `float`, `0` to `int` — so Python
 * `_hash_tool` gives DIFFERENT hashes for `minimum:0.0` vs `minimum:0`.
 *
 * JS `JSON.parse` does NOT: it collapses `0.0` -> the Number `0`, and the decimal
 * is GONE before `wrap()` (or this canonicalizer) ever sees the Tool object — the
 * SDK parsed it. A bare JS `number` carries no int/float tag, and the wrapper does
 * NOT control the SDK's parse step, so the distinction is UNRECOVERABLE at this layer.
 *
 * We therefore emit INTEGRAL-VALUED numbers (`Number.isInteger(n)` true — includes
 * `0.0`, `1.0`, `-0.0`, `1e300`, `1.5e10`) as integers, matching a Python `int`, and
 * route only genuinely NON-INTEGRAL values through the `%.17e` float path. Consequence:
 *   - A schema bound/default authored as an integral-valued FLOAT (e.g. `minimum:0.0`)
 *     hashes in TS as if it were the int `0`, DIVERGING from Python's float hash.
 *   - This degrades to a tier-1 cross-language definition_hash MISS, which is
 *     FAIL-CLOSED-SAFE: the tier-0-INCONCLUSIVE -> tier-1-lookup-by-hash flow MISSES,
 *     stays INCONCLUSIVE, and HOLDS on the wire. It NEVER produces a wrong PROCEED —
 *     it only loses the cross-language cache/flywheel benefit on that one contract.
 *   - The TS client's OWN in-session drift detection is UNAFFECTED: pin and live are
 *     BOTH computed with this same TS `hashTool`, so an integral-valued float pins and
 *     re-derives identically within TS. The gap is purely cross-LANGUAGE.
 *
 * Genuinely non-integral floats (`0.5`, `0.1`, `3.14`, `1.5`, ...) ARE recoverable
 * (JS keeps them as non-integral numbers) and hash BYTE-IDENTICAL to Python via
 * `pythonFloatRepr` below — pinned in test/parity.test.ts against live-Python refs.
 *
 * True cross-language parity on integral-valued floats would need a VALUE-BASED (not
 * type-based) canonicalization decision ON THE PYTHON SIDE — a corpus-migration /
 * hash-format one-way door, out of this slice's scope. Tracked in tasks/todo-s6-ts.md.
 */
function isIntegral(n: number): boolean {
  return Number.isInteger(n);
}

function pythonFloatRepr(n: number): string {
  if (Number.isNaN(n) || !Number.isFinite(n)) {
    throw new Error("non-finite float is not canonicalizable");
  }
  let v = n;
  if (v === 0) v = 0; // collapse -0.0 -> 0.0
  // toExponential(17): "d.<17 digits>e±X" but the exponent is NOT zero-padded.
  const raw = v.toExponential(FLOAT_DIGITS);
  const m = /^(-?\d\.\d+)e([+-])(\d+)$/.exec(raw);
  if (m === null) {
    throw new Error(`unexpected exponential form: ${raw}`);
  }
  const mantissa = m[1];
  const sign = m[2];
  let exp = m[3];
  if (exp.length < 2) exp = exp.padStart(2, "0");
  return `${mantissa}e${sign}${exp}`;
}

function canonicalize(o: unknown, depth: number): Json {
  if (depth > MAX_CANON_DEPTH) {
    throw new Error("canonical depth exceeded");
  }
  if (o === null || o === undefined) {
    return null;
  }
  if (typeof o === "boolean") {
    return o;
  }
  if (typeof o === "number") {
    if (isIntegral(o)) {
      if (!Number.isFinite(o)) {
        throw new Error("non-finite number is not canonicalizable");
      }
      return o; // emitted as an integer, matching a Python int
    }
    return pythonFloatRepr(o);
  }
  if (typeof o === "bigint") {
    return Number(o);
  }
  if (typeof o === "string") {
    return nfc(o);
  }
  if (Array.isArray(o)) {
    return o.map((v) => canonicalize(v, depth + 1));
  }
  if (typeof o === "object") {
    const src = o as Record<string, unknown>;
    // NFC-normalize keys, then sort by the normalized string (Python sorts by
    // `str(k)`; all our keys are already strings).
    const entries: Array<[string, unknown]> = Object.keys(src).map((k) => [
      nfc(k),
      src[k],
    ]);
    entries.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
    const out: { [k: string]: Json } = {};
    for (const [k, v] of entries) {
      out[k] = canonicalize(v, depth + 1);
    }
    return out;
  }
  throw new Error(`non-canonicalizable type ${typeof o}`);
}

/** ensure_ascii=True JSON encoder with `(",",":")` separators over an already-
 * canonicalized (key-sorted) value. We escape every non-ASCII char as \uXXXX to
 * match Python's `json.dumps(ensure_ascii=True)`. */
function encodeAscii(v: Json): string {
  if (v === null) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") {
    // Only integers reach here as numbers (floats are pre-stringified).
    return String(v);
  }
  if (typeof v === "string") return encodeAsciiString(v);
  if (Array.isArray(v)) {
    return "[" + v.map(encodeAscii).join(",") + "]";
  }
  // object: keys already canonical-sorted; preserve insertion order.
  const parts: string[] = [];
  for (const k of Object.keys(v)) {
    parts.push(encodeAsciiString(k) + ":" + encodeAscii(v[k]));
  }
  return "{" + parts.join(",") + "}";
}

function encodeAsciiString(s: string): string {
  let out = '"';
  for (const ch of s) {
    const cp = ch.codePointAt(0) as number;
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (ch === "\b") out += "\\b";
    else if (ch === "\f") out += "\\f";
    else if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (ch === "\t") out += "\\t";
    else if (cp < 0x20) out += "\\u" + cp.toString(16).padStart(4, "0");
    else if (cp < 0x7f) out += ch;
    else {
      // ensure_ascii: emit \uXXXX (surrogate pair for astral planes), matching
      // Python's json encoder.
      if (cp > 0xffff) {
        const c = cp - 0x10000;
        const hi = 0xd800 + (c >> 10);
        const lo = 0xdc00 + (c & 0x3ff);
        out +=
          "\\u" +
          hi.toString(16).padStart(4, "0") +
          "\\u" +
          lo.toString(16).padStart(4, "0");
      } else {
        out += "\\u" + cp.toString(16).padStart(4, "0");
      }
    }
  }
  return out + '"';
}

/** THE canonical serialization — every hash site MUST use this (port of
 * `contract.canonical_bytes`). */
export function canonicalBytes(obj: unknown): Buffer {
  return Buffer.from(encodeAscii(canonicalize(obj, 0)), "utf-8");
}

/** The connector's per-tool hash, byte-identical to Python `_tool_hash`. The
 * preimage is `{name, description, input_schema}` (snake_case schema key). */
export function toolHash(
  name: string,
  description: string,
  inputSchema: Record<string, unknown>,
): string {
  const bytes = canonicalBytes({
    name,
    description,
    input_schema: inputSchema,
  });
  return "sha256:" + createHash("sha256").update(bytes).digest("hex");
}

/** Hash a PUBLIC tool-definition dict (port of cse `_hash_tool`): coerces
 * name/description to strings, an absent/non-object inputSchema to `{}`.
 *
 * LATENT divergence (audit L2): on a `null` name/description we coerce to `""`,
 * whereas Python `_hash_tool` does `str(None)` -> `"None"`. This is UNREACHABLE
 * via the wrapper: `wrap.toolToDict` already normalizes a null/absent description
 * to `""` before this is ever called (and a tool with a null NAME is dropped), so
 * both languages hash `""`. The divergence only surfaces on a RAW-dict direct call
 * to `hashTool({description: null})` that bypasses the wrapper's normalization —
 * we keep the `""` coercion (it is the wrapper-faithful value) and note the gap. */
export function hashTool(defn: Record<string, unknown>): string {
  const name = defn.name === undefined || defn.name === null ? "" : String(defn.name);
  const desc =
    defn.description === undefined || defn.description === null
      ? ""
      : String(defn.description);
  const schema = defn.inputSchema;
  const inSch =
    schema !== null && typeof schema === "object" && !Array.isArray(schema)
      ? (schema as Record<string, unknown>)
      : {};
  return toolHash(name, desc, inSch);
}
