/**
 * Which tool-list entries a host is allowed to see.
 *
 * Under guard and strict, each entry is judged with `Gate.assess` and the
 * effects are discarded. An effective PROCEED stays. HOLD, INCONCLUSIVE, a
 * wrong JSON type on inputSchema / annotations / outputSchema, a repeated
 * name, or an exception on that entry is left out. Monitor returns every entry.
 *
 * The caller owns the name set. A wrapper passes the set for the current
 * cursorless list. The client's own listChanged refresh comes through here as
 * well: `wrap()` routes the inner client's listTools to the wrapper.
 */

import { assignOwn, listedFields } from "./contractFields.js";
import { approvalDigest } from "./canonical.js";
import { Gate, Posture } from "./gate.js";
import { Decision, HoldClass, makeVerdict, type PreflightVerdict, type ToolDef } from "./preflight.js";

export const MAX_LISTED_TOOLS = 2000;

const OBJECT_FIELDS = ["inputSchema", "annotations", "outputSchema"] as const;

export const WITHHELD_CALL_REASON =
  "withheld from the tool list; escalation was not attempted for a withheld tool";

export interface WithheldNotice {
  serverId: string;
  toolName: string;
  reason: string;
  definitionHash: string;
  definition: ToolDef | null;
  /** False for a duplicate name, a wrong JSON type, or a check that raised. */
  reviewable: boolean;
  /** The gate's effective verdict when a comparison withheld the tool; null when the entry
   * never reached the gate (duplicate, wrong JSON type, a check that raised). */
  verdict?: PreflightVerdict | null;
}

export interface ListingOutcome {
  kept: unknown[];
  withheld: WithheldNotice[];
}

/**
 * The HOLD for a call to a tool the listing withheld. It carries the listing's reason, and
 * when the gate compared and found a change, that verdict's class and drift, so the hold
 * message names the change instead of claiming no comparison was possible.
 */
export function withheldCallVerdict(
  serverId: string,
  toolName: string,
  listing: Pick<WithheldNotice, "reason" | "verdict"> | null = null,
): PreflightVerdict {
  const held = listing?.verdict ?? null;
  // The gate's own reason is the specific one ("inconclusive" in the notice is a summary).
  const why = held?.reason || listing?.reason || "";
  const reason =
    why.length > 0
      ? `withheld from the tool list (${why}); escalation was not attempted for a withheld tool`
      : WITHHELD_CALL_REASON;
  if (held === null) {
    return makeVerdict({
      serverId,
      toolName,
      decision: Decision.HOLD,
      reason,
      isContractDiff: false,
      holdClass: HoldClass.UNCHECKABLE,
    });
  }
  let holdClass = held.holdClass ?? HoldClass.UNSET;
  if (holdClass === HoldClass.UNSET) holdClass = held.isContractDiff ? HoldClass.DRIFT : HoldClass.UNCHECKABLE;
  return makeVerdict({ ...held, serverId, toolName, decision: Decision.HOLD, reason, holdClass });
}

export function rawToolEntries(result: unknown): unknown[] {
  if (result !== null && typeof result === "object") {
    const obj = result as Record<string, unknown>;
    const inner = obj["result"];
    if (inner !== null && typeof inner === "object" && !Array.isArray(inner) && "tools" in inner) {
      const raw = (inner as Record<string, unknown>)["tools"];
      if (!Array.isArray(raw)) throw new Error("tools");
      return [...raw];
    }
    if ("tools" in obj) {
      const raw = obj["tools"];
      if (!Array.isArray(raw)) throw new Error("tools");
      return [...raw];
    }
  }
  throw new Error("tools");
}

export function replaceToolList(result: unknown, tools: unknown[]): unknown {
  if (result !== null && typeof result === "object" && !Array.isArray(result)) {
    const obj = result as Record<string, unknown>;
    const inner = obj["result"];
    if (inner !== null && typeof inner === "object" && !Array.isArray(inner) && "tools" in inner) {
      return { ...obj, result: { ...(inner as Record<string, unknown>), tools: [...tools] } };
    }
    if ("tools" in obj) return { ...obj, tools: [...tools] };
  }
  return { tools: [...tools] };
}

export function filterListing(gate: Gate, entries: unknown[], seen: Set<string>): ListingOutcome {
  if (gate.posture === Posture.MONITOR) return { kept: [...entries], withheld: [] };
  const names = entries.map(toolName);
  const counts = new Map<string, number>();
  for (const name of names) {
    if (name === null) continue;
    counts.set(name, (counts.get(name) ?? 0) + 1);
  }
  const kept: unknown[] = [];
  const withheld: WithheldNotice[] = [];
  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];
    const name = names[i];
    if (name === null || name === undefined) continue;
    let notice: WithheldNotice | null;
    try {
      notice = judge(gate, entry, name, counts, seen);
    } catch {
      const contract = publicContract(entry);
      notice = {
        serverId: gate.serverId,
        toolName: name,
        reason: "listing check failed",
        definitionHash: hashOrBlank(contract),
        definition: contract,
        reviewable: false,
      };
    }
    if (notice === null) kept.push(entry);
    else withheld.push(notice);
  }
  for (const name of names) {
    if (name !== null && name !== undefined) seen.add(name);
  }
  return { kept, withheld };
}

function judge(
  gate: Gate,
  entry: unknown,
  name: string,
  counts: Map<string, number>,
  seen: Set<string>,
): WithheldNotice | null {
  const wrong = wrongObjectField(entry);
  if (wrong !== null) return notice(gate, name, wrong, entry);
  if ((counts.get(name) ?? 0) > 1 || seen.has(name)) {
    return notice(gate, name, "duplicate name in this tool list", entry);
  }
  const contract = publicContract(entry);
  if (contract === null) return notice(gate, name, "listing check failed", entry);
  const assessed = gate.assess(name, contract);
  const effective = assessed[1];
  if (effective.decision === Decision.PROCEED) return null;
  const reason = effective.decision === Decision.INCONCLUSIVE ? "inconclusive" : effective.reason || "held";
  return notice(gate, name, reason, entry, effective);
}

function notice(
  gate: Gate,
  name: string,
  reason: string,
  entry: unknown,
  verdict: PreflightVerdict | null = null,
): WithheldNotice {
  const contract = publicContract(entry);
  const reviewable =
    reason !== "listing check failed" &&
    reason !== "duplicate name in this tool list" &&
    !reason.endsWith("is not an object") &&
    !reason.endsWith("is not a string");
  return {
    serverId: gate.serverId,
    toolName: name,
    reason,
    definitionHash: hashOrBlank(contract),
    definition: contract,
    reviewable,
    verdict,
  };
}

function hashOrBlank(contract: ToolDef | null): string {
  if (contract === null) return "";
  try {
    return approvalDigest(contract);
  } catch {
    return "";
  }
}

function toolName(entry: unknown): string | null {
  if (entry === null || typeof entry !== "object") return null;
  const name = (entry as Record<string, unknown>)["name"];
  return typeof name === "string" && name.length > 0 ? name : null;
}

function wrongObjectField(entry: unknown): string | null {
  if (entry === null || typeof entry !== "object") return null;
  const obj = entry as Record<string, unknown>;
  for (const key of OBJECT_FIELDS) {
    if (!(key in obj)) continue;
    const value = obj[key];
    // undefined is absent: an in-process McpServer leaves `annotations: undefined` on a
    // tool registered without annotations, and JSON would drop the key.
    if (value === undefined) continue;
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
      return `${key} is not an object`;
    }
  }
  // The spec makes title a string; a host may still render an object or list as text.
  const title = obj["title"];
  if (title !== undefined && title !== null && typeof title !== "string") return "title is not a string";
  return null;
}

function publicContract(entry: unknown): ToolDef | null {
  const name = toolName(entry);
  if (name === null || entry === null || typeof entry !== "object") return null;
  const obj = entry as Record<string, unknown>;
  const schema = obj["inputSchema"];
  const ann = obj["annotations"];
  const outp = obj["outputSchema"];
  const record: ToolDef = {
    name,
    description: obj["description"] == null ? "" : String(obj["description"]),
    inputSchema: schema !== null && typeof schema === "object" && !Array.isArray(schema) ? schema : {},
  };
  if (ann !== null && typeof ann === "object" && !Array.isArray(ann)) record["annotations"] = ann;
  if (outp !== null && typeof outp === "object" && !Array.isArray(outp)) record["outputSchema"] = outp;
  assignOwn(record, listedFields(entry));
  return record;
}
