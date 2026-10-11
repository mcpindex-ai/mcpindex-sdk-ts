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

export const CONTRACT_FIELDS_VERSION = 2;

const HASHED_FIELDS = new Set(["name", "description", "inputSchema"]);
const CLASSIFIED_FIELDS = new Set(["annotations", "outputSchema"]);

/** The top-level fields outside the hash and the classified pair, as listed.
 * `undefined` and `null` are absent. An empty or non-string title is absent,
 * matching what pins written by 0.16 stored. */
export function extraFields(entry: unknown): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (entry === null || typeof entry !== "object" || Array.isArray(entry)) return out;
  for (const [key, value] of Object.entries(entry as Record<string, unknown>)) {
    if (HASHED_FIELDS.has(key) || CLASSIFIED_FIELDS.has(key)) continue;
    if (value === undefined || value === null) continue;
    if (key === "title" && !(typeof value === "string" && value.length > 0)) continue;
    out[key] = value;
  }
  return out;
}

// The boolean hints the gate classifies. Every other annotation key,
// annotations.title among them, is compared like a top-level field.
const ANNOTATION_HINTS = new Set(["readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"]);
export const ANNOTATION_TEXT_KEY = "annotations (other than the four hints)";

/** What the gate compares on a hash match: the extra fields, plus the
 * annotation keys other than the four hints under one synthetic key that never
 * reaches a pin or a digest. Mirrors Python `compared_fields`. */
export function comparedFields(entry: unknown): Record<string, unknown> {
  const out = extraFields(entry);
  if (entry === null || typeof entry !== "object" || Array.isArray(entry)) return out;
  const ann = (entry as Record<string, unknown>)["annotations"];
  if (ann !== null && typeof ann === "object" && !Array.isArray(ann)) {
    const text: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(ann as Record<string, unknown>)) {
      if (ANNOTATION_HINTS.has(key) || value === undefined || value === null) continue;
      text[key] = value;
    }
    if (Object.keys(text).length > 0) out[ANNOTATION_TEXT_KEY] = text;
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
  const have = new Set(Object.keys(extraFields(pinnedSchema)));
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(extraFields(observed))) {
    if (!have.has(key)) out[key] = value;
  }
  return out;
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
