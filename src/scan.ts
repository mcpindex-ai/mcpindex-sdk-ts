/**
 * Static schema-content marker scan — a port of the boolean core of Python
 * `trust/schema_scan.py`. We only need "is a hostile marker present?" for the
 * Gate-4 marker check, so this returns a boolean rather than the full
 * DimensionFinding (the Python `scan_schema(...) is not None` predicate).
 *
 * A TRIPWIRE, not a calibrated detector: catches KNOWN hostile markers at high
 * precision, evadable by novel encodings. Same regexes, same string-key walk.
 */

const CREDENTIAL_PATH = new RegExp(
  "(?:[/\\\\~]\\.?(?:ssh|aws|gnupg)\\b)" +
    "|(?:[/\\\\](?:credentials?|secrets?|vault|keys?|private[_-]?keys?)\\b)" +
    "|(?:\\b(?:id_rsa|\\.pem|\\.env|/var/secrets|\\.config/credentials)\\b)",
  "i",
);

const EXFIL_INSTRUCTION = new RegExp(
  // An exfil VERB + a destination (word OR URL) within 48 chars. A BARE URL is NOT
  // flagged on its own: benign tools carry example/doc URLs in schema strings (a
  // web_url_reader's `url` param), which the prior bare `https?://` alternative
  // false-flagged CRITICAL on real data. Mirrors the tightened Python
  // `_EXFIL_INSTRUCTION` — a URL signals exfil only in a verb context.
  // Destination = an EXFIL-SPECIFIC channel word or a URL. The ubiquitous prepositions
  // to/into/server were DROPPED (real-data FP #2: a wallet tool's "scans forward … defaults
  // to NU6" tripped forward+`to`). Mirrors the Python `_EXFIL_INSTRUCTION`.
  "\\b(?:mirror|exfiltrat\\w*|forward|transmit|relay|smuggle|leak|harvest|replicate|stage)\\b" +
    ".{0,48}?(?:\\b(?:channel|webhook|endpoint|inbox|hook|outbound|operator)\\b|https?://)" +
    "|\\b(?:webhook-delta|slack-hook|discord-relay|teams-forward)\\b",
  "i",
);

const INJECTION = new RegExp(
  "\\b(?:ignore (?:all )?(?:previous|prior)|disregard (?:previous|prior|the above))\\b" +
    "|^\\s*(?:SYSTEM|ADMIN)\\s*:" +
    "|\\[(?:ADMIN|SYSTEM)\\]" +
    "|\\b(?:pre-?approved|mark (?:this|it) (?:as )?(?:safe|benign|trusted))\\b",
  "im",
);

// The schema sub-keys that carry literal strings a hostile author controls. We
// scan their string VALUES (not the structural keys themselves). MIRRORS the
// BROADENED Python `trust.schema_scan._STRING_KEYS` — broadened to also cover the
// agent-/judge-consumed annotation channels `examples`, `$comment`, and
// `markdownDescription` (a marker smuggled into any of them reaches the model just
// like one in `description`). Kept as a sorted, exported set so the parity test can
// assert TS covers EVERY key the live Python scanner covers (no fail-OPEN divergence).
export const STRING_KEYS: ReadonlySet<string> = new Set([
  "pattern",
  "default",
  "const",
  "title",
  "description",
  "examples",
  "$comment",
  "markdownDescription",
]);

function isDict(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function walkStrings(node: unknown, out: string[]): void {
  if (isDict(node)) {
    for (const [k, v] of Object.entries(node)) {
      if (STRING_KEYS.has(k)) {
        // A scanned key whose value is a bare string, OR a LIST of bare strings
        // (e.g. `examples: ["...", "..."]`, `enum`-style value arrays). A hostile
        // author can hide a marker in any list element, so scan each bare string.
        if (typeof v === "string") {
          out.push(v);
        } else if (Array.isArray(v)) {
          for (const item of v) if (typeof item === "string") out.push(item);
        } else {
          walkStrings(v, out);
        }
      } else if (k === "enum" && Array.isArray(v)) {
        for (const item of v) if (typeof item === "string") out.push(item);
      } else {
        walkStrings(v, out);
      }
    }
  } else if (Array.isArray(node)) {
    for (const item of node) walkStrings(item, out);
  }
}

/** True iff the input schema encodes a known hostile marker (credential-path,
 * exfil instruction, or injection directive). Port of
 * `scan_schema(...) is not None`. */
export function scanSchemaHasMarker(inputSchema: Record<string, unknown>): boolean {
  const strings: string[] = [];
  walkStrings(inputSchema, strings);
  for (const s of strings) {
    if (CREDENTIAL_PATH.test(s) || EXFIL_INSTRUCTION.test(s) || INJECTION.test(s)) {
      return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Runtime tool-RESULT content scanner — the TS twin of Python
// `trust/result_scan.py`. It reuses the EXACT SAME three marker regexes the
// schema scanner above uses (single source of truth within TS) and applies them
// to the content a tool RETURNED at call time: every TEXT block in `content[]`
// (shaped `{type:"text", text:"..."}`) PLUS every string anywhere in
// `structuredContent`. CRITICAL (credential/exfil) outranks HIGH (injection).
//
// HONEST FRAMING (same bar as the schema scan): a TRIPWIRE, not a calibrated
// detector — catches KNOWN hostile markers at high precision, evadable by a
// novel encoding; no recall bound. A taint is NOT a safety/truth verdict — it
// says "this returned text matches a hostile marker", nothing about whether the
// answer is true. The caller (the wrapper) WITHHOLDS the tainted result so it
// cannot hijack the agent's NEXT action — the call already executed (post-flight).
//
// MARKER PARITY: the regex SOURCES are byte-identical to Python's
// `trust.schema_scan._{CREDENTIAL_PATH,EXFIL_INSTRUCTION,INJECTION}`. The
// cross-language parity test reads the live Python patterns and asserts the
// exported `RESULT_MARKER_SOURCES` match, so the result scanner and the schema
// scanner can never silently diverge across languages. (Python compiles those
// markers with `re.ASCII`, which changes only the FLAGS, not the source
// strings; JS `\w`/`\b` are already ASCII-only, so no TS source change is
// needed and the parity test still passes.)

/** The marker-regex SOURCES (Python `.pattern` form), exported ONLY so the
 * cross-language parity test can assert byte-identity against the live Python
 * patterns. Not part of the runtime scan path. */
export const RESULT_MARKER_SOURCES: {
  readonly credential: string;
  readonly exfil: string;
  readonly injection: string;
} = {
  credential: CREDENTIAL_PATH.source,
  exfil: EXFIL_INSTRUCTION.source,
  injection: INJECTION.source,
};

/** Cap on how much of a single string we scan. A malicious result can be
 * arbitrarily large; we scan a bounded prefix (a marker meant to hijack an agent
 * must appear early enough to be read) and flag the tail as unscanned so the
 * caller never implies "fully clean" on a truncated scan. Generous (1 MiB) so
 * realistic tool results are scanned WHOLE. Measured + sliced by CODE POINT (via
 * the spread iterator), NOT UTF-16 unit, so astral-plane padding (emoji) can't
 * push a marker past the JS cut while staying inside Python's code-point cut —
 * the two engines see the SAME prefix. Mirrors Python `_MAX_SCAN_CHARS`. */
const MAX_SCAN_CHARS = 1_048_576;

/** structuredContent recursion bound: a cyclic / pathologically deep attacker
 * payload must stop the walk (returning a "hit bound" flag, NOT throwing a
 * RangeError) so a hostile result can't crash the scanner. Mirrors Python
 * `_MAX_DEPTH`. */
const MAX_DEPTH = 64;

/** Total collected-string bound: millions of tiny blocks must stop the walk
 * (same "hit bound" flag) rather than exhaust memory. Mirrors Python
 * `_MAX_STRINGS`. */
const MAX_STRINGS = 100_000;

/** Path-segment length cap. A structuredContent KEY NAME is only ever a
 * breadcrumb in `location`, never raw payload — so a key is sanitized to a safe
 * charset and capped. Mirrors Python `_MAX_SEG`. */
const MAX_SEG = 40;

/** Any whitespace EXCEPT newline (Unicode-aware via the `u` flag, on purpose).
 * JS `\s` is Unicode-aware while Python compiles the markers `re.ASCII` (ASCII
 * `\s` only), so an NBSP / em-space / ideographic space before a marker would
 * HOLD in TS but PASS in Python. Normalizing every non-newline Unicode space to
 * an ASCII space before matching makes the two engines AGREE. Mirrors Python
 * `_UNICODE_WS = re.compile(r"[^\S\n]")`. */
const UNICODE_WS = /[^\S\n]/gu;

/** Line terminators JS counts but Python does not (\r, U+2028, U+2029) ->
 * normalized to \n before matching. Built from escapes (no raw separator chars
 * embedded in source), mirroring Python `_TERMINATORS`. */
const TERMINATORS = new RegExp("[\r\u2028\u2029]", "g");

/** One hostile marker found in a tool's returned content. `severity` mirrors the
 * schema scanner: 'critical' = credential/exfil intent; 'high' = injection
 * directive. Mirrors Python `ResultTaint`: it carries NO raw payload — the
 * offending substring is DELIBERATELY dropped (it may hold a secret; a loaded
 * gun), so `location` (a secret-free json-path) + `reason` (a fixed marker-class
 * string) are all that surface. The truncation signal lives on `ResultScan`, not
 * here. */
export interface ResultTaint {
  readonly severity: "critical" | "high";
  /** json-path into the result (e.g. "content[0]" / "structuredContent.x"). */
  readonly location: string;
  /** Short, honest marker description (marker CLASS only — no raw payload). */
  readonly reason: string;
}

/** The outcome of scanning a result. `taint` is the worst marker found (or null
 * when clean); `truncated` is true when any scanned string exceeded
 * MAX_SCAN_CHARS so its tail was NOT scanned — a clean scan with `truncated:true`
 * means "clean as far as read", which the wrapper fail-closes under STRICT (and
 * never implies "fully clean"). `scanResult` ALWAYS returns a `ResultScan` (never
 * a bare null) so the truncation signal survives the clean path. Mirrors Python
 * `ResultScan`. */
export interface ResultScan {
  readonly taint: ResultTaint | null;
  readonly truncated: boolean;
}

function isString(v: unknown): v is string {
  return typeof v === "string";
}

/** Read `key` from a dict-or-object (a plain JS object IS the SDK shape — no
 * pydantic), returning undefined when absent. TARGETED access only — we never
 * walk an object's whole shape. Mirrors Python `_attr_or_key` (which also covers
 * an SDK model via getattr; in JS the SDK returns plain objects so a single
 * property read suffices). */
function attrOrKey(entry: unknown, key: string): unknown {
  if (entry !== null && typeof entry === "object") {
    return (entry as Record<string, unknown>)[key];
  }
  return undefined;
}

/** A path breadcrumb segment: keep a safe charset (`A-Za-z0-9_.-`), replace
 * everything else with `?`, and cap the length — so a hostile structuredContent
 * KEY NAME can never dump raw payload (or a secret) into a HOLD banner via
 * `location` (which flows into the user-facing reason). Mirrors Python
 * `_sanitize_seg`. */
function sanitizeSeg(seg: string): string {
  return seg.replace(/[^A-Za-z0-9_.-]/g, "?").slice(0, MAX_SEG);
}

/** Extract the AGENT-READABLE text strings from ONE content block (TARGETED — NOT
 * a walk of every field). Text block -> `.text`; EmbeddedResource (type
 * "resource") -> `.resource.text`; resource_link -> `.name`/`.description`/
 * `.title`; a bare string -> itself. Structural fields (uri/mimeType/type/data/
 * blob) are DELIBERATELY skipped: they are not agent directives and scanning them
 * only adds false positives (a benign resource URI like a forward-hook host, a
 * mimeType, base64 `data`). Mirrors Python `_block_texts`. */
function blockTexts(block: unknown, idx: number): [string, string][] {
  const base = `content[${idx}]`;
  if (isString(block)) return [[base, block]];
  const out: [string, string][] = [];
  const text = attrOrKey(block, "text");
  if (isString(text)) out.push([`${base}.text`, text]);
  const btype = attrOrKey(block, "type");
  if (btype === "resource") {
    const rtext = attrOrKey(attrOrKey(block, "resource"), "text");
    if (isString(rtext)) out.push([`${base}.resource.text`, rtext]);
  } else if (btype === "resource_link") {
    for (const field of ["name", "description", "title"] as const) {
      const val = attrOrKey(block, field);
      if (isString(val)) out.push([`${base}.${field}`, val]);
    }
  }
  return out;
}

/** Walk every string VALUE (NOT keys) in structuredContent, depth- and
 * count-bounded. Returns [strings, hitBound]. Key NAMES appear ONLY as SANITIZED
 * path breadcrumbs (`sanitizeSeg`), never as scanned strings and never raw in
 * `location` — so neither a key's content nor a secret in a key can reach a
 * marker or a banner. `budget` is a single-element box decremented across the
 * recursion (the JS analog of Python's `budget: list[int]`). Past `MAX_DEPTH` or
 * once `budget` is exhausted the walk stops and flags `hitBound` (a cyclic / deep
 * payload never throws a RangeError). Mirrors Python `_walk_values`. */
function walkValues(
  node: unknown,
  path: string,
  depth: number,
  budget: { n: number },
): [[string, string][], boolean] {
  if (depth > MAX_DEPTH || budget.n <= 0) return [[], true];
  const out: [string, string][] = [];
  let hit = false;
  if (isString(node)) {
    budget.n -= 1;
    out.push([path, node]);
  } else if (Array.isArray(node)) {
    for (let i = 0; i < node.length; i++) {
      const [sub, subHit] = walkValues(node[i], `${path}[${i}]`, depth + 1, budget);
      for (const x of sub) out.push(x);
      hit = hit || subHit;
    }
  } else if (node !== null && typeof node === "object") {
    for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
      const seg = sanitizeSeg(k);
      const [sub, subHit] = walkValues(v, `${path}.${seg}`, depth + 1, budget);
      for (const x of sub) out.push(x);
      hit = hit || subHit;
    }
  }
  return [out, hit];
}

/** Collect [json-path, string] for every agent-readable string in `content` (via
 * `blockTexts`, targeted) + `structuredContent` (via `walkValues`, values only,
 * bounded). Returns [strings, boundHit] where `boundHit` is true when the
 * value-walk stopped on the depth/count bound. Mirrors Python `_collect`. */
function collect(content: unknown, structuredContent: unknown): [[string, string][], boolean] {
  // ONE budget shared across content + structuredContent so a pathological content[] (millions
  // of blocks) also bounds out and flags truncated, not silently fully-clean (parity with Python).
  const strings: [string, string][] = [];
  const budget = { n: MAX_STRINGS };
  let boundHit = false;
  if (Array.isArray(content)) {
    for (let i = 0; i < content.length; i++) {
      if (budget.n <= 0) {
        boundHit = true;
        break;
      }
      const bt = blockTexts(content[i], i);
      for (const x of bt) strings.push(x);
      budget.n -= bt.length;
    }
  } else if (content !== undefined && content !== null) {
    for (const x of blockTexts(content, 0)) strings.push(x);
    budget.n -= 1;
  }
  if (structuredContent !== undefined && structuredContent !== null) {
    const [sub, hit] = walkValues(structuredContent, "structuredContent", 0, budget);
    for (const x of sub) strings.push(x);
    boundHit = boundHit || hit;
  }
  return [strings, boundHit || budget.n <= 0];
}

/** Code-point length of `s` (NOT UTF-16 unit length) — so the truncated flag
 * agrees with the code-point scan cap across engines (Python measures by code
 * point). */
function codePointLength(s: string): number {
  let n = 0;
  for (const _ of s) n += 1;
  return n;
}

/** Line-terminator + Unicode-whitespace normalization so the two regex engines
 * agree before matching. Mirrors Python `_normalize`:
 *   * slice by CODE POINT (`[...s]`), NOT UTF-16 unit, so astral-plane padding
 *     (an emoji = 2 UTF-16 units, 1 code point) can't push a marker past the JS
 *     cut while it stays inside Python's code-point cut — same prefix in both.
 *   * line terminators \r / U+2028 / U+2029 -> \n: JS counts these as line breaks
 *     (anchoring `^`/`m` and never matched by `.`) where Python does not.
 *   * every non-newline Unicode whitespace (NBSP, em-space, ideographic space, …)
 *     -> ASCII space: JS `\s` is Unicode-aware (the `u` flag on `UNICODE_WS`)
 *     while Python compiles the markers `re.ASCII`, so without this an
 *     `NBSP + "SYSTEM:"` would HOLD in TS but PASS in Python. Order matters:
 *     normalize terminators to \n FIRST, then collapse the remaining non-newline
 *     whitespace (so a real \n is preserved, matching `_UNICODE_WS`'s `[^\S\n]`). */
function normalize(s: string): string {
  const capped = [...s].slice(0, MAX_SCAN_CHARS).join("");
  return capped.replace(TERMINATORS, "\n").replace(UNICODE_WS, " ");
}

/** Apply the three reused markers to one normalized string. CRITICAL
 * (credential/exfil) takes precedence over HIGH (injection). Returns
 * [severity, reason] or null. Mirrors Python `_scan_one`. */
function scanOne(s: string): ["critical" | "high", string] | null {
  const probe = normalize(s);
  if (CREDENTIAL_PATH.test(probe)) return ["critical", "credential/secret path in tool result"];
  if (EXFIL_INSTRUCTION.test(probe)) return ["critical", "exfil/transmit directive in tool result"];
  if (INJECTION.test(probe)) return ["high", "injection directive in tool result"];
  return null;
}

/** Scan a tool's returned `content` (array of blocks) + `structuredContent` for a
 * hostile marker. Returns a `ResultScan` (the worst taint — CRITICAL
 * short-circuits — or null, plus a `truncated` flag). Deterministic, offline, no
 * model. Tolerant of malformed / attacker-shaped input by design (the result is
 * attacker-derived): anything it cannot interpret is simply not scanned, never
 * thrown on, and bounded against cyclic/deep payloads — the CALLER additionally
 * runs this inside a fail-closed guard. `truncated` is set when a string exceeded
 * the per-string cap OR the value-walk hit the depth/count bound. Port of Python
 * `scan_result`. */
export function scanResult(content: unknown, structuredContent?: unknown): ResultScan {
  const [strings, boundHit] = collect(content, structuredContent);
  const truncated = boundHit || strings.some(([, s]) => codePointLength(s) > MAX_SCAN_CHARS);
  let high: [string, string] | null = null; // [location, reason]
  for (const [loc, s] of strings) {
    const hit = scanOne(s);
    if (hit === null) continue;
    const [severity, reason] = hit;
    if (severity === "critical") {
      return { taint: { severity, location: loc, reason }, truncated };
    }
    if (high === null) high = [loc, reason];
  }
  if (high !== null) {
    const [loc, reason] = high;
    return { taint: { severity: "high", location: loc, reason }, truncated };
  }
  return { taint: null, truncated };
}
