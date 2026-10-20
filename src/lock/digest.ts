/**
 * Tool Definition Digest, Tool Set Digest and instructions digest (lock draft 1,
 * section 2), over RFC 8785 (JCS) canonical JSON.
 *
 * The input is what JSON.parse returned for the raw message, never an SDK model.
 * The serializer walks own keys with Object.keys and writes the output string
 * directly, so a member named `__proto__` (which JSON.parse creates as an own
 * property) is covered like any other. Nothing here copies through object
 * spread or plain-object assignment, either of which would turn `__proto__`
 * into a prototype change and drop it from the digest.
 *
 * Separate from ../canonical.ts on purpose: that file is the legacy pin hash
 * (NFC, ensure_ascii, Python float repr). This one is plain RFC 8785 and does
 * not normalize Unicode.
 */

import { createHash } from "node:crypto";

export const DIGEST_PREFIX = "sha256:";

/** Numbers at or above this magnitude get no digest (checked on the parsed value). */
export const NUMBER_LIMIT = 2 ** 53;

/** Nesting deeper than this gets no digest rather than a stack overflow. */
const MAX_DEPTH = 512;

const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

export class CanonicalizationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CanonicalizationError";
  }
}

export function hasLoneSurrogate(text: string): boolean {
  return LONE_SURROGATE.test(text);
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function own(obj: Record<string, unknown>, key: string): unknown {
  return Object.getOwnPropertyDescriptor(obj, key)?.value;
}

/** True when every number is finite with magnitude below 2^53. */
function numbersInRange(value: unknown, depth: number): boolean {
  if (depth > MAX_DEPTH) return false;
  if (typeof value === "number") return Number.isFinite(value) && Math.abs(value) < NUMBER_LIMIT;
  if (Array.isArray(value)) return value.every((v) => numbersInRange(v, depth + 1));
  if (isObject(value)) {
    for (const key of Object.keys(value)) {
      if (!numbersInRange(own(value, key), depth + 1)) return false;
    }
  }
  return true;
}

/** False when any member name or string holds an unpaired UTF-16 surrogate. */
function wellFormed(value: unknown, depth: number): boolean {
  if (depth > MAX_DEPTH) return false;
  if (typeof value === "string") return !hasLoneSurrogate(value);
  if (Array.isArray(value)) return value.every((v) => wellFormed(v, depth + 1));
  if (isObject(value)) {
    for (const key of Object.keys(value)) {
      if (hasLoneSurrogate(key) || !wellFormed(own(value, key), depth + 1)) return false;
    }
  }
  return true;
}

function serializeString(text: string): string {
  if (hasLoneSurrogate(text)) throw new CanonicalizationError("unpaired surrogate");
  // For well-formed strings JSON.stringify escapes exactly what RFC 8785 asks:
  // quote, backslash, and controls below U+0020 (short forms for \b \f \n \r \t,
  // lower-case \u00xx otherwise). Everything else is written as is.
  return JSON.stringify(text);
}

function serializeNumber(n: number): string {
  if (!Number.isFinite(n)) throw new CanonicalizationError("non-finite number");
  // ECMAScript Number::toString is the RFC 8785 number form; -0 prints as 0.
  return String(n);
}

/** Key order is UTF-16 code unit order, which is what `<` on JS strings compares. */
function compareCodeUnits(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function serialize(value: unknown, depth: number, skipTopMeta: boolean): string {
  if (depth > MAX_DEPTH) throw new CanonicalizationError("nesting too deep");
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "number") return serializeNumber(value);
  if (typeof value === "string") return serializeString(value);
  if (Array.isArray(value)) {
    let out = "[";
    for (let i = 0; i < value.length; i++) {
      if (i > 0) out += ",";
      out += serialize(value[i], depth + 1, false);
    }
    return out + "]";
  }
  if (isObject(value)) {
    const keys = Object.keys(value)
      .filter((k) => !(skipTopMeta && k === "_meta"))
      .sort(compareCodeUnits);
    let out = "{";
    let first = true;
    for (const key of keys) {
      if (!first) out += ",";
      first = false;
      out += serializeString(key) + ":" + serialize(own(value, key), depth + 1, false);
    }
    return out + "}";
  }
  throw new CanonicalizationError(`not a JSON value: ${typeof value}`);
}

/** RFC 8785 text of a JSON value. Throws CanonicalizationError. */
export function canonicalize(value: unknown): string {
  return serialize(value, 0, false);
}

export function sha256Hex(data: string | Uint8Array): string {
  const hash = createHash("sha256");
  if (typeof data === "string") hash.update(data, "utf8");
  else hash.update(data);
  return hash.digest("hex");
}

function digestOf(text: string): string {
  return DIGEST_PREFIX + sha256Hex(text);
}

/** RFC 8785 text of the tool minus its top-level `_meta`, or null when it has no digest. */
function canonicalToolText(tool: unknown): string | null {
  if (!isObject(tool)) return null;
  for (const key of Object.keys(tool)) {
    if (key === "_meta") continue;
    if (hasLoneSurrogate(key)) return null;
    const v = own(tool, key);
    if (!wellFormed(v, 1) || !numbersInRange(v, 1)) return null;
  }
  try {
    return serialize(tool, 0, true);
  } catch {
    return null;
  }
}

/** Digest of one raw Tool object, or null when it has no digest (section 2.1). */
export function toolDigest(tool: unknown): string | null {
  const text = canonicalToolText(tool);
  return text === null ? null : digestOf(text);
}

/** Contract file bytes for a tool: sha256 of these is the tool digest. */
export function canonicalBody(tool: unknown): Buffer | null {
  const text = canonicalToolText(tool);
  return text === null ? null : Buffer.from(text, "utf8");
}

/** Digest of the server's instructions string (section 2.2), or null. */
export function instructionsDigest(instructions: unknown): string | null {
  if (typeof instructions !== "string" || hasLoneSurrogate(instructions)) return null;
  return digestOf(serializeString(instructions));
}

/** Compare by Unicode code point, as Python compares str. */
export function compareCodePoints(a: string, b: string): number {
  const ia = a[Symbol.iterator]();
  const ib = b[Symbol.iterator]();
  for (;;) {
    const x = ia.next();
    const y = ib.next();
    if (x.done || y.done) return x.done && y.done ? 0 : x.done ? -1 : 1;
    const cx = (x.value as string).codePointAt(0) as number;
    const cy = (y.value as string).codePointAt(0) as number;
    if (cx !== cy) return cx < cy ? -1 : 1;
  }
}

/**
 * Digest over every tool's digest, sorted by (name, digest) as Python sorts
 * tuples. Null if any tool has no digest.
 */
export function toolSetDigest(tools: readonly unknown[]): string | null {
  const pairs: Array<[string, string]> = [];
  for (const tool of tools) {
    const digest = toolDigest(tool);
    if (digest === null) return null;
    const name = isObject(tool) ? own(tool, "name") : undefined;
    // Python: str(tool.get("name", "")). Non-string names only matter for sort order.
    const key = typeof name === "string" ? name : name === undefined ? "" : name === null ? "None" : String(name);
    pairs.push([key, digest]);
  }
  pairs.sort((a, b) => compareCodePoints(a[0], b[0]) || compareCodePoints(a[1], b[1]));
  return digestOf(canonicalize(pairs.map((p) => p[1])));
}
