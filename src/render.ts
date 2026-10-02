/**
 * Render-safe text neutralization — a port of Python `report._md_text` +
 * `_strip_control`. Strips ALL C0/C1/DEL control bytes (incl. ESC `\x1b`, the
 * ANSI cursor/colour-escape banner-forgery vector) FIRST, then HTML-escapes,
 * then backslash-escapes markdown metacharacters, then folds CR/LF to spaces.
 * Always embed the result mid-line.
 */

// C0/C1 + DEL, EXCLUDING \t \n \r (handled as whitespace). ESC (\x1b) is in set.
// eslint-disable-next-line no-control-regex
// EXACT parity with Python `report._UNSAFE_TEXT_CHARS`. Named for the property, not the
// encoding: this is every character unsafe to embed in a rendered line, not merely "control
// bytes". Widened 2026-08-05 - the previous class stopped at DEL, which was survivable while
// the only consumer was a single-line banner, but `renderHoldMessage` renders a multi-line
// evidence block containing an attacker-chosen JSON-Schema path. U+2028 there forges an
// extra row that can negate the disposition note; U+202E reorders the headline, [DRILL]
// label included.
// The `u` flag is LOAD-BEARING, not stylistic. Without it `[\ud800-\udfff]` matches each half
// of a VALID surrogate pair, so every non-BMP character was silently deleted: a hostile tool
// named `get_weather🙂` rendered identically to the real `get_weather`, and the rendered tool
// name is the agent's only handle on WHICH tool was held. With `u`, the range matches only
// UNPAIRED surrogates - which is exactly Python's behaviour ("printable text, including CJK,
// emoji and RTL script, is unchanged").
const CONTROL_BYTES =
  /[\x00-\x08\x0b-\x1f\x7f-\x9f\u2028\u2029\u202a-\u202e\u2066-\u2069\ud800-\udfff]/gu;

// Mirror Python report._MD_SPECIAL EXACTLY ("\\`*_[]()|~"). Escaping MORE than Python (e.g. `-`)
// breaks green-word redaction parity: `all-clear` would become `all\-clear`, which GREEN_RE no
// longer matches, so the green word survives un-redacted (TS diverging from Python). Keep this set
// identical to Python so both md-escaping AND green-word redaction stay in parity.
const MD_SPECIAL = ["\\", "`", "*", "_", "[", "]", "(", ")", "|", "~"];

// Mirror Python `report._PLAIN_SPECIAL` / `_PLAIN_PROSE_SPECIAL` EXACTLY. Same parity rule as
// above: escaping MORE or LESS than Python here silently diverges the two clients' HOLD text.
const PLAIN_SPECIAL = ["\\", "`", "*", "[", "]", "(", ")", "|", "~", "<", ">"];
const PLAIN_PROSE_SPECIAL = [...PLAIN_SPECIAL, "_"];

function escapeAll(s: string, chars: readonly string[]): string {
  let out = s;
  for (const ch of chars) out = out.split(ch).join("\\" + ch);
  return out;
}

function htmlEscape(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;");
}

/** Neutralise a string for embedding in a rendered line WITHOUT markdown-escaping it.
 * Exported for the HOLD message's pin-path anchor, which legitimately contains `_` and `.`
 * and must not be mangled. Python twin: `report._safe_text`. */
export function stripControl(s: string): string {
  return s.replace(CONTROL_BYTES, "").replace(/\t/g, " ");
}

/** Neutralize untrusted text for inline embedding in a markdown/terminal banner. */
export function mdText(s: string): string {
  let out = stripControl(s);
  out = htmlEscape(out);
  // backslash must be escaped via MD_SPECIAL (it's first in the list), but
  // htmlEscape already ran; replicate Python order (escape each MD special).
  out = escapeAll(out, MD_SPECIAL);
  return out.replace(/\r/g, " ").replace(/\n/g, " ");
}

/** Neutralize untrusted text for a channel that is READ, not rendered as HTML: the
 * JSON-RPC HOLD `error.message`. Python twin: `report._plain_text`.
 *
 * Two deliberate differences from `mdText`, each because this channel is not HTML and not a
 * document. NO HTML ESCAPING - nothing parses this as HTML, so entity-encoding only corrupts
 * it (our own "this tool's contract" reached agents as "this tool&#x27;s"); the raw-tag
 * vector it covered is kept by escaping `<`/`>` as metacharacters instead. And `_` IS NOT
 * ESCAPED, because this renders IDENTIFIERS - `send_message` arrived as `send\_message`, a
 * name that is not the tool's name. An intraword `_` opens no CommonMark emphasis, so it can
 * forge nothing; every character that CAN forge structure is still escaped. */
export function plainText(s: string): string {
  const out = escapeAll(stripControl(s), PLAIN_SPECIAL);
  return out.replace(/\r/g, " ").replace(/\n/g, " ");
}

/** `plainText` for FREE-FORM prose rather than an identifier: `_` stays escaped. Python
 * twin: `report._plain_prose`. Only `verdict.reason` takes this path - it is the one field
 * that interpolates a server-chosen taint location, so it is the one field where an
 * underscore is attacker syntax rather than part of a name. */
export function plainProse(s: string): string {
  const out = escapeAll(stripControl(s), PLAIN_PROSE_SPECIAL);
  return out.replace(/\r/g, " ").replace(/\n/g, " ");
}
