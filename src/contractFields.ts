/**
 * Top-level tool fields that the definition hash does not cover (port of Python
 * `contract_fields`).
 *
 * The hash covers name, description and inputSchema. annotations and
 * outputSchema have their own rules in the gate. Every other top-level key a
 * server lists (title, icons, _meta, execution, and whatever a later spec adds)
 * reaches the host too, so a pin records it and the gate compares it on a hash
 * match.
 *
 * A pin written before this module has no `contractFields` marker. On such a
 * pin a key it lacks was never recorded, so it is filled in from the first
 * matching list instead of read as a change.
 */

// 3 since a non-string title is compared. Any marker from 2 up is complete.
export const CONTRACT_FIELDS_VERSION = 3;

/** Where a pin file keeps the marker: inside `schema`, which gate 0.18 and SDK
 * 0.16 keep whole when they rewrite a record. The store moves it out on load and
 * back on write; `extraFields` skips it so a server cannot supply it. */
export const SCHEMA_MARKER_KEY = "_mcpindex_contract_fields";

/** Set an own enumerable property. Plain assignment of a JSON `__proto__` key
 * would set the prototype instead and drop the key. */
export function setOwn(obj: Record<string, unknown>, key: string, value: unknown): void {
  Object.defineProperty(obj, key, { value, enumerable: true, writable: true, configurable: true });
}

export function assignOwn(target: Record<string, unknown>, source: Record<string, unknown>): void {
  for (const key of Object.keys(source)) setOwn(target, key, source[key]);
}

const HASHED_FIELDS = new Set(["name", "description", "inputSchema"]);
const CLASSIFIED_FIELDS = new Set(["annotations", "outputSchema"]);

/** The top-level fields outside the hash and the classified pair, as listed.
 * `undefined` and `null` are absent. An empty or non-string title is absent,
 * matching what pins written by 0.16 stored. */
export function extraFields(entry: unknown): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (entry === null || typeof entry !== "object" || Array.isArray(entry)) return out;
  for (const [key, value] of Object.entries(entry as Record<string, unknown>)) {
    if (HASHED_FIELDS.has(key) || CLASSIFIED_FIELDS.has(key) || key === SCHEMA_MARKER_KEY) continue;
    if (value === undefined || value === null) continue;
    if (key === "title" && !(typeof value === "string" && value.length > 0)) continue;
    setOwn(out, key, value);
  }
  return out;
}

// The boolean hints the gate classifies. Every other annotation key,
// annotations.title among them, is compared like a top-level field.
const ANNOTATION_HINTS = new Set(["readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"]);
// "annotations" itself: `extraFields` never carries a top-level "annotations",
// so no server key can collide with it.
export const ANNOTATION_TEXT_KEY = "annotations";

/** What a normalized definition and a pin keep: `extraFields` plus a title that
 * is present but not a string. The digest stays on `extraFields`. Mirrors Python
 * `listed_fields`. */
export function listedFields(entry: unknown): Record<string, unknown> {
  const out = extraFields(entry);
  if (entry === null || typeof entry !== "object" || Array.isArray(entry)) return out;
  const title = (entry as Record<string, unknown>)["title"];
  if (title !== undefined && title !== null && typeof title !== "string") setOwn(out, "title", title);
  return out;
}

/** What the gate compares on a hash match: the extra fields, plus the
 * annotation keys other than the four hints under one synthetic key that never
 * reaches a pin or a digest. Mirrors Python `compared_fields`. */
export function comparedFields(entry: unknown): Record<string, unknown> {
  const out = listedFields(entry);
  if (entry === null || typeof entry !== "object" || Array.isArray(entry)) return out;
  const ann = (entry as Record<string, unknown>)["annotations"];
  if (ann !== null && typeof ann === "object" && !Array.isArray(ann)) {
    const text: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(ann as Record<string, unknown>)) {
      if (ANNOTATION_HINTS.has(key) || value === undefined || value === null) continue;
      setOwn(text, key, value);
    }
    if (Object.keys(text).length > 0) setOwn(out, ANNOTATION_TEXT_KEY, text);
  }
  return out;
}

/** Which keys to compare. A marked pin compares the union. An old pin compares
 * the keys it recorded, plus the annotation text: pins have always stored
 * annotations whole. */
export function comparedKeys(
  pinnedSchema: Record<string, unknown>,
  observed: Record<string, unknown>,
  complete: boolean,
): string[] {
  const keys = new Set(Object.keys(comparedFields(pinnedSchema)));
  const live = Object.keys(comparedFields(observed));
  for (const key of live) {
    if (complete || key === ANNOTATION_TEXT_KEY) keys.add(key);
  }
  return [...keys].sort();
}

/** Extra fields the live entry has and an old pin never recorded. */
export function missingExtraFields(
  pinnedSchema: Record<string, unknown>,
  observed: Record<string, unknown>,
): Record<string, unknown> {
  const have = new Set(Object.keys(listedFields(pinnedSchema)));
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(extraFields(observed))) {
    if (!have.has(key)) setOwn(out, key, value);
  }
  return out;
}

// The first marker version that recorded every listed field.
const FIRST_COMPLETE_VERSION = 2;

/** Whether a pin's marker means it recorded every field listed at the time. */
export function isComplete(version: number | undefined): boolean {
  // No upper bound: a newer writer records a superset.
  return version !== undefined && Number.isInteger(version) && version >= FIRST_COMPLETE_VERSION;
}

/** What a pin at `version` may record once from a matching list (Python
 * `fields_to_backfill`): everything it lacks when unmarked, nothing when marked. */
export function fieldsToBackfill(
  pinnedSchema: Record<string, unknown>,
  observed: Record<string, unknown>,
  version: number | undefined,
): Record<string, unknown> {
  // A marked pin records nothing; a non-string title is never recorded.
  if (!isComplete(version)) return missingExtraFields(pinnedSchema, observed);
  return {};
}

/** A server-chosen key, quoted and escaped for a reason string (Python
 * `json.dumps(key, ensure_ascii=True)`). */
export function fieldLabel(key: string): string {
  const text = JSON.stringify(key).replace(
    /[\u007f-\uffff]/g,
    (ch) => "\\u" + ch.charCodeAt(0).toString(16).padStart(4, "0"),
  );
  return text.length <= 64 ? text : text.slice(0, 60) + '..."';
}
