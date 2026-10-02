/**
 * Structured schema-object diff classifier — a faithful port of Python
 * `tooling/cse/schema_diff.py`. Pure + deterministic + total: any structural
 * surprise degrades to "no signal" rather than throwing (inputs are attacker-
 * derived self-descriptions). The safety bit is DERIVED from the kind (single
 * source of truth), so the two can never disagree.
 */

export enum ChangeKind {
  ADDED_OPTIONAL_PARAM = "added-optional-param",
  ADDED_REQUIRED_PARAM = "added-required-param",
  REMOVED_PARAM = "removed-param",
  TYPE_CHANGED = "type-changed",
  ENUM_VALUES_REMOVED = "enum-values-removed",
  CONSTRAINT_NARROWED = "constraint-narrowed",
  REQUIRED_SET_EXPANDED = "required-set-expanded",
  ANNOTATION_FLIP_TO_DESTRUCTIVE = "annotation-flip-to-destructive",
  PARAM_MIRRORED_TO_HEADER = "param-mirrored-to-header",
  OUTPUT_SCHEMA_ADDED = "output-schema-added",
  OUTPUT_SCHEMA_CHANGED = "output-schema-changed",
  TOOL_ADDED = "tool-added",
  TOOL_REMOVED = "tool-removed",
  DESCRIPTION_ONLY = "description-only",
  DESCRIPTION_NUMERIC = "description-numeric",
  DEEP_SCHEMA_UNDIFFABLE = "deep-schema-undiffable",
  // Context-surface kinds (server-scoped: instructions + prompts metadata,
  // emitted under the sentinel tool "(server)"). The CLASSIFIER for these is
  // `classify_context_change` in corpus_eval/tooling/cse/schema_diff.py and is
  // deliberately Python-only for now: `classifyChange` here is per-tool, and
  // the TS client's job for these kinds is to EXPLAIN what the ledger says,
  // which needs the taxonomy and the safety bit, not a second differ.
  INSTRUCTIONS_ADDED = "instructions-added",
  INSTRUCTIONS_REMOVED = "instructions-removed",
  INSTRUCTIONS_CHANGED = "instructions-changed",
  INSTRUCTIONS_NUMERIC = "instructions-numeric",
  PROMPT_ADDED = "prompt-added",
  PROMPT_REMOVED = "prompt-removed",
  PROMPT_DESCRIPTION_CHANGED = "prompt-description-changed",
  PROMPT_ARGS_CHANGED = "prompt-args-changed",
}


// --- description numeric-only ------------------------------------------------
// Parity port of `is_numeric_only_description_change` in
// corpus_eval/tooling/cse/schema_diff.py. Measured 2026-08-09 over 30 live baseline
// snapshots, and DOMINATED BY ONE PUBLISHER'S FLEET (96.4% of pairs; outside it the
// ratio reverses - see the Python schema_diff note): 94.8% of tool pairs whose
// description changed while the input schema did
// not differed ONLY in digits - counters and timestamps re-rendered every crawl.
//
// States a FACT ("only numbers moved"), never a verdict ("this is noise"): a bound
// written "Limit: 100" is numeric-only too, and no local lexicon tells it apart from
// a counter. Deciding to stop showing one needs per-tool history, not this function.
// A local gate and the public ledger must agree on the label, so both sides mask
// identically: collapse whitespace, then replace digit runs.
// ASCII-only on purpose: JS `\d` is [0-9] but Python's matches Unicode decimal digits,
// and JS `\s` matches U+FEFF while Python's does not. Pinning to [0-9] with no
// whitespace handling makes both engines provably identical; measured on the
// 93,419-pair corpus it changes zero classifications.
function maskNumbers(text: string): string {
  return text.replace(/[0-9]+/g, "#");
}

export function isNumericOnlyDescriptionChange(oldDesc: string, newDesc: string): boolean {
  return maskNumbers(oldDesc) === maskNumbers(newDesc);
}

const SAFETY_RELEVANT: ReadonlySet<ChangeKind> = new Set([
  ChangeKind.ADDED_REQUIRED_PARAM,
  ChangeKind.REMOVED_PARAM,
  ChangeKind.TYPE_CHANGED,
  ChangeKind.ENUM_VALUES_REMOVED,
  ChangeKind.CONSTRAINT_NARROWED,
  ChangeKind.REQUIRED_SET_EXPANDED,
  ChangeKind.ANNOTATION_FLIP_TO_DESTRUCTIVE,
  ChangeKind.PARAM_MIRRORED_TO_HEADER,
  ChangeKind.OUTPUT_SCHEMA_CHANGED,
  ChangeKind.TOOL_REMOVED,
  ChangeKind.DEEP_SCHEMA_UNDIFFABLE,
  // Context-surface mapping: MUST mirror `_SAFETY_RELEVANT` in
  // corpus_eval/tooling/cse/schema_diff.py (PROVISIONAL there; rationale too).
  ChangeKind.INSTRUCTIONS_ADDED,
  ChangeKind.INSTRUCTIONS_CHANGED,
  ChangeKind.PROMPT_ARGS_CHANGED,
]);

export const MAX_DEPTH = 16;

export interface Change {
  readonly kind: ChangeKind;
  readonly path: string;
  readonly safetyRelevant: boolean;
  readonly detail: string;
}

export function isSafetyRelevant(kind: ChangeKind): boolean {
  return SAFETY_RELEVANT.has(kind);
}

function mk(kind: ChangeKind, path: string, detail: string): Change {
  return { kind, path, safetyRelevant: SAFETY_RELEVANT.has(kind), detail };
}

type Dict = Record<string, unknown>;

function isDict(v: unknown): v is Dict {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function props(schema: Dict): Dict {
  const p = schema["properties"];
  return isDict(p) ? p : {};
}

const COMBINATOR_KEYS = ["allOf", "anyOf", "oneOf"] as const;

function required(schema: Dict): Set<string> {
  // EFFECTIVE required set: the top-level `required` UNIONED with `required`
  // collected from combinator branches (allOf/anyOf/oneOf). A param made required
  // ONLY inside a branch is still required to call the tool; reading only the
  // top-level `required` would misclassify a newly-added such param as OPTIONAL and
  // auto-accept it (FIX 3). Fail SAFE: required in ANY branch -> treated as required.
  // Mirrors Python `schema_diff._required`.
  const out = new Set<string>();
  const r = schema["required"];
  if (Array.isArray(r)) {
    for (const x of r) if (typeof x === "string") out.add(x);
  }
  for (const key of COMBINATOR_KEYS) {
    const branches = schema[key];
    if (!Array.isArray(branches)) continue;
    for (const branch of branches) {
      if (!isDict(branch)) continue;
      const br = branch["required"];
      if (Array.isArray(br)) {
        for (const x of br) if (typeof x === "string") out.add(x);
      }
    }
  }
  return out;
}

/** Property schemas declared INSIDE a combinator branch (allOf/anyOf/oneOf), keyed
 * by name, so a param introduced only by a branch is still SEEN by the object differ
 * (FIX 3). Later branches win on a name clash (value unused for classification).
 * Mirrors Python `schema_diff._combinator_props`. */
function combinatorProps(schema: Dict): Dict {
  const out: Dict = {};
  for (const key of COMBINATOR_KEYS) {
    const branches = schema[key];
    if (!Array.isArray(branches)) continue;
    for (const branch of branches) {
      if (isDict(branch)) {
        const bp = branch["properties"];
        if (isDict(bp)) Object.assign(out, bp);
      }
    }
  }
  return out;
}

/** True iff the object schema carries any allOf/anyOf/oneOf combinator the top-level
 * property differ does not fully model — the signal to FAIL SAFE on an added param.
 * Mirrors Python `schema_diff._has_combinator`. */
function hasCombinator(schema: Dict): boolean {
  return COMBINATOR_KEYS.some((k) => Array.isArray(schema[k]));
}

type TypeSig = {
  t: string | string[] | null;
  // Keyed by the TYPE-TAGGED repr (so `1` and `"1"` stay distinct, matching
  // Python's `frozenset`); the value is the ORIGINAL enum member, kept so the
  // human-readable "removed" detail renders the untagged value (parity with Python's
  // `sorted(map(str, removed))`).
  enumSet: Map<string, unknown> | null;
  ref: unknown;
};

function reprValue(x: unknown): string {
  // A total, order-independent stringification of an enum member for set
  // membership. TYPE-TAGGED so distinct-typed primitives never collapse: Python's
  // `frozenset([1, "1"])` keeps `1` and `"1"` apart (hash by type), but JS
  // `String(1) === "1"` would merge them — fixing toward FLAGGING (a real
  // enum-narrowing on mixed-type enums is no longer masked as a no-op). The tag is
  // the JS `typeof` (or "null"/"array"); objects/arrays use JSON of their value.
  if (x === null) return "null:";
  if (Array.isArray(x)) {
    try {
      return `array:${JSON.stringify(x)}`;
    } catch {
      return `array:${String(x)}`;
    }
  }
  const tag = typeof x;
  if (tag === "object") {
    try {
      return `object:${JSON.stringify(x)}`;
    } catch {
      return `object:${String(x)}`;
    }
  }
  return `${tag}:${String(x)}`;
}

function typeSignature(prop: unknown): TypeSig {
  if (!isDict(prop)) return { t: null, enumSet: null, ref: null };
  const rawT = prop["type"];
  let t: string | string[] | null;
  if (Array.isArray(rawT)) {
    t = rawT.map((x) => String(x)).sort();
  } else {
    t = rawT === undefined ? null : (rawT as string);
  }
  const e = prop["enum"];
  let enumSet: Map<string, unknown> | null = null;
  if (Array.isArray(e)) {
    enumSet = new Map(e.map((x): [string, unknown] => [reprValue(x), x]));
  }
  const ref = prop["$ref"] ?? null;
  return { t, enumSet, ref };
}

function typeEqual(a: string | string[] | null, b: string | string[] | null): boolean {
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && a.every((v, i) => v === b[i]);
  }
  return a === b;
}

function strFacet(prop: unknown, key: string): unknown {
  if (!isDict(prop)) return null;
  return prop[key] ?? null;
}

function isRealNumber(v: unknown): v is number {
  return typeof v === "number" && Number.isFinite(v);
}

function classifyConstraintDelta(
  path: string,
  oldProp: unknown,
  newProp: unknown,
): Change | null {
  const oldPat = strFacet(oldProp, "pattern");
  const newPat = strFacet(newProp, "pattern");
  if (typeof newPat === "string" && newPat !== oldPat) {
    return mk(
      ChangeKind.CONSTRAINT_NARROWED,
      `${path}.pattern`,
      `string pattern added/tightened: ${reprPy(oldPat)} -> ${reprPy(newPat)}`,
    );
  }

  const oldMin = isDict(oldProp) ? oldProp["minLength"] : null;
  const newMin = isDict(newProp) ? newProp["minLength"] : null;
  if (isRealNumber(newMin)) {
    if (!isRealNumber(oldMin)) {
      return mk(ChangeKind.CONSTRAINT_NARROWED, `${path}.minLength`, `minLength added: ${newMin}`);
    }
    if (newMin > oldMin) {
      return mk(
        ChangeKind.CONSTRAINT_NARROWED,
        `${path}.minLength`,
        `minLength increased: ${oldMin} -> ${newMin}`,
      );
    }
  }

  const oldMax = isDict(oldProp) ? oldProp["maxLength"] : null;
  const newMax = isDict(newProp) ? newProp["maxLength"] : null;
  if (isRealNumber(newMax)) {
    if (!isRealNumber(oldMax)) {
      return mk(ChangeKind.CONSTRAINT_NARROWED, `${path}.maxLength`, `maxLength added: ${newMax}`);
    }
    if (newMax < oldMax) {
      return mk(
        ChangeKind.CONSTRAINT_NARROWED,
        `${path}.maxLength`,
        `maxLength decreased: ${oldMax} -> ${newMax}`,
      );
    }
  }

  const oldFmt = strFacet(oldProp, "format");
  const newFmt = strFacet(newProp, "format");
  if (typeof newFmt === "string" && newFmt !== oldFmt) {
    return mk(
      ChangeKind.CONSTRAINT_NARROWED,
      `${path}.format`,
      `string format added/changed: ${reprPy(oldFmt)} -> ${reprPy(newFmt)}`,
    );
  }

  // Numeric/array bound narrowing (FIX 1 defense-in-depth). The canonical hash
  // already includes these facets, so narrowing one CHANGES the hash and reaches the
  // gate — but if the differ does not MODEL the facet, classifyChange returns an EMPTY
  // list and the gate (mis)reads "all allowlisted -> PROVEN BENIGN". Modeling them
  // here makes the diff NON-EMPTY and explanatory; narrowing an input constraint can
  // break existing callers -> CONSTRAINT_NARROWED (breaking, NOT auto-accepted).
  const numeric = classifyNumericBoundDelta(path, oldProp, newProp);
  if (numeric !== null) return numeric;
  const array = classifyArrayBoundDelta(path, oldProp, newProp);
  if (array !== null) return array;

  // additionalProperties: true/absent -> false is a NARROWING (extra keys a caller
  // used to be allowed to send are now rejected). false/dict -> true is a loosening
  // (ignored). A dict additionalProperties is not modeled beyond true->false.
  const oldAp = isDict(oldProp) ? oldProp["additionalProperties"] : undefined;
  const newAp = isDict(newProp) ? newProp["additionalProperties"] : undefined;
  if (newAp === false && oldAp !== false) {
    return mk(
      ChangeKind.CONSTRAINT_NARROWED,
      `${path}.additionalProperties`,
      `additionalProperties narrowed: ${reprPy(oldAp ?? null)} -> False (extra properties no longer accepted)`,
    );
  }

  return null;
}

/** A numeric facet of a property schema as a real number, or null when absent /
 * non-numeric / boolean (a bool is not a numeric bound). Mirrors `_num_facet`. */
function numFacet(prop: unknown, key: string): number | null {
  if (!isDict(prop)) return null;
  const v = prop[key];
  if (typeof v === "boolean") return null;
  if (typeof v === "number" && Number.isFinite(v)) return v;
  return null;
}

/** Numeric-bound NARROWING (FIX 1): `minimum`/`exclusiveMinimum` added or increased;
 * `maximum`/`exclusiveMaximum` added or decreased; `multipleOf` added or changed.
 * Loosening returns null. Returns the single most-severe narrowing. Mirrors
 * `_classify_numeric_bound_delta`. */
function classifyNumericBoundDelta(path: string, oldProp: unknown, newProp: unknown): Change | null {
  for (const facet of ["minimum", "exclusiveMinimum"]) {
    const oldV = numFacet(oldProp, facet);
    const newV = numFacet(newProp, facet);
    if (newV !== null && (oldV === null || newV > oldV)) {
      return mk(ChangeKind.CONSTRAINT_NARROWED, `${path}.${facet}`, `${facet} added/raised: ${reprPy(oldV ?? null)} -> ${newV}`);
    }
  }
  for (const facet of ["maximum", "exclusiveMaximum"]) {
    const oldV = numFacet(oldProp, facet);
    const newV = numFacet(newProp, facet);
    if (newV !== null && (oldV === null || newV < oldV)) {
      return mk(ChangeKind.CONSTRAINT_NARROWED, `${path}.${facet}`, `${facet} added/lowered: ${reprPy(oldV ?? null)} -> ${newV}`);
    }
  }
  const oldMul = numFacet(oldProp, "multipleOf");
  const newMul = numFacet(newProp, "multipleOf");
  if (newMul !== null && newMul !== oldMul) {
    return mk(ChangeKind.CONSTRAINT_NARROWED, `${path}.multipleOf`, `multipleOf added/changed: ${reprPy(oldMul ?? null)} -> ${newMul}`);
  }
  return null;
}

/** Array-bound NARROWING (FIX 1): `minItems` added or increased; `maxItems` added or
 * decreased. Loosening returns null. Mirrors `_classify_array_bound_delta`. */
function classifyArrayBoundDelta(path: string, oldProp: unknown, newProp: unknown): Change | null {
  const oldMin = numFacet(oldProp, "minItems");
  const newMin = numFacet(newProp, "minItems");
  if (newMin !== null && (oldMin === null || newMin > oldMin)) {
    return mk(ChangeKind.CONSTRAINT_NARROWED, `${path}.minItems`, `minItems added/raised: ${reprPy(oldMin ?? null)} -> ${newMin}`);
  }
  const oldMax = numFacet(oldProp, "maxItems");
  const newMax = numFacet(newProp, "maxItems");
  if (newMax !== null && (oldMax === null || newMax < oldMax)) {
    return mk(ChangeKind.CONSTRAINT_NARROWED, `${path}.maxItems`, `maxItems added/lowered: ${reprPy(oldMax ?? null)} -> ${newMax}`);
  }
  return null;
}

/** A Python-`repr`-ish rendering for detail strings (so detail text matches the
 * Python classifier's `!r` formatting closely enough for human reading). */
function reprPy(v: unknown): string {
  if (v === null || v === undefined) return "None";
  if (typeof v === "string") return `'${v}'`;
  return String(v);
}

function classifyParamTypeDelta(
  path: string,
  oldProp: unknown,
  newProp: unknown,
): Change | null {
  const oldSig = typeSignature(oldProp);
  const newSig = typeSignature(newProp);

  if (oldSig.ref !== newSig.ref) {
    return mk(
      ChangeKind.TYPE_CHANGED,
      `${path}.$ref`,
      `$ref changed: ${reprPy(oldSig.ref)} -> ${reprPy(newSig.ref)}`,
    );
  }

  if (oldSig.enumSet !== null && newSig.enumSet !== null) {
    // Membership compared by TYPE-TAGGED key (so `1` !== `"1"`); the detail renders
    // the ORIGINAL value untagged (parity with Python's `sorted(map(str, removed))`).
    const newKeys = newSig.enumSet;
    const removed = [...oldSig.enumSet].filter(([k]) => !newKeys.has(k)).map(([, v]) => v);
    if (removed.length > 0) {
      return mk(
        ChangeKind.ENUM_VALUES_REMOVED,
        `${path}.enum`,
        `enum values removed: ${JSON.stringify(removed.map(String).sort())}`,
      );
    }
  }

  if (oldSig.enumSet === null && newSig.enumSet !== null) {
    return mk(ChangeKind.TYPE_CHANGED, path, "narrowed: free value constrained to an enum");
  }

  if (!typeEqual(oldSig.t, newSig.t)) {
    return mk(
      ChangeKind.TYPE_CHANGED,
      `${path}.type`,
      `type changed: ${reprPy(oldSig.t)} -> ${reprPy(newSig.t)}`,
    );
  }

  return classifyConstraintDelta(path, oldProp, newProp);
}

function jsonEqual(a: unknown, b: unknown): boolean {
  if (isDict(a) && isDict(b)) {
    const ak = Object.keys(a);
    const bk = Object.keys(b);
    if (ak.length !== bk.length) return false;
    const bs = new Set(bk);
    for (const k of ak) {
      if (!bs.has(k)) return false;
      if (!jsonEqual(a[k], b[k])) return false;
    }
    return true;
  }
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && a.every((x, i) => jsonEqual(x, b[i]));
  }
  return a === b;
}

function undiffableAtBound(oldV: unknown, newV: unknown, path: string): Change[] {
  if (jsonEqual(oldV, newV)) return [];
  return [
    mk(
      ChangeKind.DEEP_SCHEMA_UNDIFFABLE,
      path,
      `schema nesting exceeds MAX_DEPTH=${MAX_DEPTH} and the subtrees differ; ` +
        "deeper delta not classifiable, flagged conservatively",
    ),
  ];
}

function diffObjectSchema(
  oldSchema: Dict,
  newSchema: Dict,
  path: string,
  depth: number,
): Change[] {
  if (depth > MAX_DEPTH) return undiffableAtBound(oldSchema, newSchema, path);

  const changes: Change[] = [];
  // Combinator-scoped properties are folded into the name sets so a param introduced
  // ONLY by an allOf/anyOf/oneOf branch is still SEEN by the differ (FIX 3).
  const oldProps: Dict = { ...combinatorProps(oldSchema), ...props(oldSchema) };
  const newProps: Dict = { ...combinatorProps(newSchema), ...props(newSchema) };
  const oldReq = required(oldSchema);
  const newReq = required(newSchema);
  const oldNames = new Set(Object.keys(oldProps));
  const newNames = new Set(Object.keys(newProps));
  // FAIL-SAFE: the NEW schema uses a combinator the differ cannot fully model — an
  // added param under it is classified REQUIRED (the safe over-classification).
  const newHasCombinator = hasCombinator(newSchema);

  for (const name of [...oldNames].filter((n) => !newNames.has(n)).sort()) {
    changes.push(mk(ChangeKind.REMOVED_PARAM, `${path}.${name}`, "parameter removed (or renamed away)"));
  }

  for (const name of [...newNames].filter((n) => !oldNames.has(n)).sort()) {
    if (newReq.has(name)) {
      changes.push(
        mk(ChangeKind.ADDED_REQUIRED_PARAM, `${path}.${name}`, "new REQUIRED parameter; existing callers omit it"),
      );
    } else if (newHasCombinator) {
      changes.push(
        mk(
          ChangeKind.ADDED_REQUIRED_PARAM,
          `${path}.${name}`,
          "new parameter under an allOf/anyOf/oneOf combinator the differ cannot fully model; classified REQUIRED fail-safe (cannot prove optional)",
        ),
      );
    } else {
      changes.push(mk(ChangeKind.ADDED_OPTIONAL_PARAM, `${path}.${name}`, "new optional parameter"));
    }
  }

  for (const name of [...oldNames].filter((n) => newNames.has(n)).sort()) {
    const childPath = `${path}.${name}`;
    const oldP = oldProps[name];
    const newP = newProps[name];
    const delta = classifyParamTypeDelta(childPath, oldP, newP);
    if (delta !== null) changes.push(delta);
    if (isDict(oldP) && isDict(newP)) {
      changes.push(...diffNested(oldP, newP, childPath, depth + 1));
    }
  }

  const newlyRequired = [...newReq].filter(
    (n) => !oldReq.has(n) && oldNames.has(n) && newNames.has(n),
  );
  for (const name of newlyRequired.sort()) {
    changes.push(
      mk(ChangeKind.REQUIRED_SET_EXPANDED, `${path}.${name}.required`, "existing optional parameter became required"),
    );
  }

  return changes;
}

function diffNested(oldP: Dict, newP: Dict, path: string, depth: number): Change[] {
  if (depth > MAX_DEPTH) return undiffableAtBound(oldP, newP, path);

  const changes: Change[] = [];

  if (isDict(oldP["properties"]) && isDict(newP["properties"])) {
    changes.push(...diffObjectSchema(oldP, newP, `${path}.properties`, depth + 1));
  }

  const oldItems = oldP["items"];
  const newItems = newP["items"];
  if (isDict(oldItems) && isDict(newItems)) {
    const itemPath = `${path}.items`;
    const delta = classifyParamTypeDelta(itemPath, oldItems, newItems);
    if (delta !== null) changes.push(delta);
    changes.push(...diffNested(oldItems, newItems, itemPath, depth + 1));
  }

  return changes;
}

function annotationFlip(oldAnn: Dict, newAnn: Dict): Change | null {
  const oldDest = oldAnn["destructiveHint"];
  const newDest = newAnn["destructiveHint"];
  if (oldDest !== true && newDest === true) {
    return mk(
      ChangeKind.ANNOTATION_FLIP_TO_DESTRUCTIVE,
      "annotations.destructiveHint",
      "destructiveHint gained true (was absent/None/False)",
    );
  }
  const oldRo = oldAnn["readOnlyHint"];
  const newRo = newAnn["readOnlyHint"];
  if (oldRo === true && newRo !== true) {
    return mk(
      ChangeKind.ANNOTATION_FLIP_TO_DESTRUCTIVE,
      "annotations.readOnlyHint",
      "readOnlyHint dropped (was true, now absent/None/False)",
    );
  }
  return null;
}

function dictish(v: unknown): Dict {
  return isDict(v) ? v : {};
}

/** Map of `property path -> mirrored header name` for every `x-mcp-header` in a schema.
 * Parity port of `_header_mirrors` in corpus_eval/tooling/cse/schema_diff.py.
 *
 * Walks ONLY `properties` chains, which is the 2026-07-28 spec's own rule, not a
 * simplification: `x-mcp-header` "MUST only be applied to properties that are statically
 * reachable from the schema root" via a chain of `properties` keys - never through `items`,
 * `oneOf`/`anyOf`/`allOf`, `if`/`then`/`else` or `$ref`. An annotation anywhere else makes
 * the tool definition invalid, so walking further would report mirrors a conforming client
 * is required to reject. Depth-bounded like the rest of this module. */
function headerMirrors(schema: Dict, depth = 0, prefix = ""): Map<string, string> {
  const out = new Map<string, string>();
  if (depth >= MAX_DEPTH) return out;
  const props = schema["properties"];
  if (!isDict(props)) return out;
  for (const [name, sub] of Object.entries(props)) {
    if (!isDict(sub)) continue;
    const path = `${prefix}${name}`;
    const hdr = sub["x-mcp-header"];
    if (typeof hdr === "string" && hdr !== "") out.set(path, hdr);
    for (const [k, v] of headerMirrors(sub, depth + 1, `${path}.`)) out.set(k, v);
  }
  return out;
}

/** Parameters that NEWLY mirror their value into an HTTP header, or that changed WHICH
 * header they mirror into. Parity port of `_header_mirror_changes`.
 *
 * Only the dangerous direction, matching `annotationFlip`: a parameter that STOPS mirroring
 * is a value returning to body-only, which is an improvement and not something an operator
 * needs to review. A parameter that changes WHICH header it targets IS surfaced - the value
 * is still leaving the body and the destination an intermediary routes on has moved.
 *
 * WHY THIS EXISTS IN THE TS CLIENT AT ALL. Without it the hash still flipped (x-mcp-header
 * lives inside inputSchema, which is hashed wholesale) while `classifyChange` returned
 * nothing, so gate.ts fell to its empty-drift fail-closed path and told the user "an
 * unmodeled schema facet narrowed the contract". That HOLD was safe and its explanation was
 * WRONG: nothing narrowed, a parameter started leaking its value to every intermediary on
 * the path. Python classified this correctly and TS did not, so the two clients disagreed
 * about the same server. */
function headerMirrorChanges(oldSchema: Dict, newSchema: Dict): Change[] {
  const oldM = headerMirrors(oldSchema);
  const newM = headerMirrors(newSchema);
  const changes: Change[] = [];
  for (const path of [...newM.keys()].sort()) {
    const hdr = newM.get(path) as string;
    const prev = oldM.get(path);
    if (prev === undefined) {
      changes.push(
        mk(
          ChangeKind.PARAM_MIRRORED_TO_HEADER,
          path,
          `parameter value is now mirrored into HTTP header Mcp-Param-${hdr}, ` +
            "visible to network intermediaries",
        ),
      );
    } else if (prev !== hdr) {
      changes.push(
        mk(
          ChangeKind.PARAM_MIRRORED_TO_HEADER,
          path,
          `mirrored header changed Mcp-Param-${prev} -> Mcp-Param-${hdr}`,
        ),
      );
    }
  }
  return changes;
}

/** Classify every delta between two PUBLIC tool definitions into the taxonomy.
 * Total: a structural surprise degrades to no-signal. Mirrors
 * `schema_diff.classify_change`. */
export function classifyChange(
  oldTool: Record<string, unknown>,
  newTool: Record<string, unknown>,
): Change[] {
  const changes: Change[] = [];

  const oldIn = dictish(oldTool["inputSchema"]);
  const newIn = dictish(newTool["inputSchema"]);
  changes.push(...diffObjectSchema(oldIn, newIn, "properties", 0));

  changes.push(...headerMirrorChanges(oldIn, newIn));

  const ann = annotationFlip(dictish(oldTool["annotations"]), dictish(newTool["annotations"]));
  if (ann !== null) changes.push(ann);

  const oldOut = oldTool["outputSchema"];
  const newOut = newTool["outputSchema"];
  const oldOutPresent = oldOut !== undefined && oldOut !== null;
  const newOutPresent = newOut !== undefined && newOut !== null;
  if ((oldOutPresent || newOutPresent) && !jsonEqual(oldOut ?? null, newOut ?? null)) {
    if (!oldOutPresent) {
      changes.push(
        mk(
          ChangeKind.OUTPUT_SCHEMA_ADDED,
          "outputSchema",
          "result schema documented for the first time; additive, no prior shape for a parser to depend on",
        ),
      );
    } else {
      changes.push(
        mk(
          ChangeKind.OUTPUT_SCHEMA_CHANGED,
          "outputSchema",
          "result schema changed; structured-output parsers may break",
        ),
      );
    }
  }

  if (changes.length === 0) {
    const oldDesc = oldTool["description"] === undefined || oldTool["description"] === null ? "" : String(oldTool["description"]);
    const newDesc = newTool["description"] === undefined || newTool["description"] === null ? "" : String(newTool["description"]);
    if (oldDesc !== newDesc) {
      if (isNumericOnlyDescriptionChange(oldDesc, newDesc)) {
        changes.push(mk(ChangeKind.DESCRIPTION_NUMERIC, "description", "description differs only in embedded numbers; prose identical"));
      } else {
        changes.push(mk(ChangeKind.DESCRIPTION_ONLY, "description", "description text changed; no structural delta"));
      }
    }
  }

  return changes;
}
