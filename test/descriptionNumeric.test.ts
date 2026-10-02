import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { isNumericOnlyDescriptionChange } from "../src/schemaDiff.js";

// The kind reports a fact, not a verdict, so the table asserts exactly that: did only
// digits move? Bound-shaped edits ARE numeric-only and are expected to say so - the
// decision about whether such a change deserves attention is history-based and lives
// elsewhere. See the note in corpus_eval/tooling/cse/schema_diff.py.
const CASES: Array<[string, string, boolean, string]> = [
  ["Returns 45 results.", "Returns 91 results.", true, "counter"],
  ["Data as of 2026-08-08.", "Data as of 2026-08-09.", true, "ISO date"],
  ["Updated 14:05 UTC.", "Updated 16:32 UTC.", true, "clock"],
  ["Indexed 1,204 docs (v3).", "Indexed 8,991 docs (v3).", true, "multi-number"],
  ["Limit: 100", "Limit: 500", true, "a bound is numeric-only too, and says so"],
  ["Compare 2-10 products.", "Compare 2-50 products.", true, "range is numeric-only"],
  ["Search the corpus.", "Search the archive.", false, "prose changed"],
  ["Fetch up to 5 rows.", "Fetch at most 5 rows.", false, "prose changed, digits identical"],
  ["Returns 5 rows.", "Returns 5 rows now.", false, "words added"],
  ["Returns  5  rows.", "Returns 5 rows.", false, "whitespace is NOT normalised (parity)"],
  // Cross-engine hazards. Python's \\d matches these; JS's never does. Both sides are
  // pinned to [0-9] so a non-ASCII digit reads as a prose change in BOTH, the safe side.
  ["Returns \u0664\u0665 results.", "Returns \u0669\u0661 results.", false, "arabic-indic digits"],
  ["Returns \uFF14\uFF15 results.", "Returns \uFF19\uFF11 results.", false, "fullwidth digits"],
  ["Returns \u0967\u0968 rows.", "Returns \u0969\u096A rows.", false, "devanagari digits"],
  // JS \\s matches U+FEFF, Python's does not. Neither side touches whitespace now.
  ["\uFEFFReturns 45 results.", "Returns 91 results.", false, "BOM prefix"],
];

test("isNumericOnlyDescriptionChange: behaviour table", () => {
  for (const [a, b, expected, why] of CASES) {
    assert.equal(isNumericOnlyDescriptionChange(a, b), expected, `${why}: ${a!} -> ${b!}`);
  }
});

// A local gate and the public ledger must not label the same event differently.
test("isNumericOnlyDescriptionChange: parity with Python on real corpus pairs", () => {
  const path = new URL(
    "../../../../corpus_eval/desc_behavior/parity_sample.json",
    import.meta.url,
  );
  if (!existsSync(path)) {
    // Local research artefact, not committed, so a fresh clone legitimately skips.
    // Say so out loud: a parity test that silently passes without its fixture is
    // worse than no parity test.
    console.log("  SKIP parity: no parity_sample.json (regenerate in corpus_eval/desc_behavior)");
    return;
  }
  const rows = JSON.parse(readFileSync(path, "utf8")) as Array<{
    a: string; b: string; py: boolean;
  }>;
  assert.ok(rows.length > 0, "parity sample is empty");
  console.log(`  parity: compared ${rows.length} real corpus pairs`);
  const bad = rows.filter((r) => isNumericOnlyDescriptionChange(r.a, r.b) !== r.py);
  assert.equal(bad.length, 0, `${bad.length}/${rows.length} disagree; first: ${JSON.stringify(bad[0])?.slice(0, 300)}`);
});

// --- gate behaviour, the twin of test_numeric_only_description_hold_names_the_shape
// in corpus_eval/tooling/smoke_preflight_intercept.py.
import { Gate } from "../src/gate.js";
import { renderHoldBanner } from "../src/gate.js";
import { PreflightPin, Decision } from "../src/preflight.js";
import type { ToolDef } from "../src/preflight.js";

const BASE: ToolDef = {
  name: "fetch",
  description: "Fetches data. Returns 45 results.",
  inputSchema: { type: "object", properties: { q: { type: "string" } } },
};

function holdFor(newDesc: string) {
  const gate = new Gate({ pin: new PreflightPin(), serverId: "srv" });
  gate.observe("fetch", BASE);
  return gate.evaluate("fetch", { ...BASE, description: newDesc });
}

test("gate: a numeric-only description change still HOLDs, and says which shape it is", () => {
  const numeric = holdFor("Fetches data. Returns 91 results.");
  const prose = holdFor("Fetches archived data only.");

  // Still blocked. The note is a fact, not a clearance - a moved price is numeric too.
  assert.equal(numeric.decision, Decision.HOLD);
  assert.equal(prose.decision, Decision.HOLD);

  // The regression risk: DANGEROUS_REASON_MARKERS matches the substring
  // "DESCRIPTION changed", so rewording the reason rather than appending to it would
  // silently stop GUARD blocking a description change.
  assert.match(numeric.reason, /DESCRIPTION changed/);
  assert.match(prose.reason, /DESCRIPTION changed/);

  assert.match(numeric.reason, /only the embedded numbers moved/);
  assert.doesNotMatch(prose.reason, /only the embedded numbers moved/);

  // The banner is where a human actually reads it.
  assert.match(renderHoldBanner(numeric), /only the numbers moved/);
  assert.doesNotMatch(renderHoldBanner(prose), /only the numbers moved/);
});
