/**
 * Tools held for review, on disk under the gate state directory.
 *
 * Same file shape and lock as Python ``tooling.cse.pending_store`` so the
 * Python CLI and this SDK share one pending list. Approval tokens are the
 * full-contract ``approvalDigest``; a later list with a different digest is
 * kept alongside the first rather than overwriting it.
 */

import { CONTRACT_FIELDS_VERSION } from "./contractFields.js";
import { randomBytes } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { tmpdir, homedir } from "node:os";
import { basename, dirname, join } from "node:path";

import { withExclusiveLock } from "./fileLock.js";
import { approvalDigest, hashTool } from "./canonical.js";
import {
  PreflightPin,
  clearEverPinned,
  defaultPinStorePath,
  utcNowIso,
  type PinnedTool,
  type ToolDef,
} from "./preflight.js";

export const CLASS_CHANGED = "changed-without-upgrade";
export const CLASS_FLOATING = "floating";

const PENDING_VERSION = 1;
export const PER_SERVER_CAP = 64;
export const TOTAL_CAP = 512;
const NAME = "pending.json";

export interface PendingRecord {
  readonly serverId: string;
  readonly toolName: string;
  readonly definition: ToolDef;
  readonly definitionHash: string;
  readonly pendingClass: string;
  readonly firstSeen: string;
  readonly launchKey?: string;
  /** CONTRACT_FIELDS_VERSION when `definition` holds every listed field. Records
   * from 0.16 lack it; approving one leaves the pin unmarked. */
  readonly contractFields?: number;
}

export function pendingPath(stateDirectory: string): string {
  return join(stateDirectory, NAME);
}

/** State directory for pending.json. Mirrors ``defaultPinStorePath`` root. */
export function defaultStateDir(): string {
  const fromEnv = process.env.MCPINDEX_STATE_DIR;
  if (typeof fromEnv === "string" && fromEnv.trim().length > 0) return fromEnv;
  if (process.execArgv.includes("--test") || process.argv.includes("--test")) {
    return join(tmpdir(), "mcpindex-sdk-test", String(process.pid));
  }
  return join(homedir(), ".mcpindex");
}

export function pendingClass(prior: readonly PinnedTool[]): string {
  const keys = prior.map((pin) => pin.launchKey).filter((k): k is string => typeof k === "string" && k.length > 0);
  if (prior.length > 0 && keys.length === prior.length && new Set(keys).size === 1) {
    return CLASS_CHANGED;
  }
  return CLASS_FLOATING;
}

function parseRecord(row: unknown): PendingRecord | null {
  if (row === null || typeof row !== "object" || Array.isArray(row)) return null;
  const body = row as Record<string, unknown>;
  const server = body["server_id"];
  const tool = body["tool_name"];
  const definition = body["definition"];
  const digest = body["definition_hash"];
  const klass = body["class"];
  const seen = body["first_seen"];
  if (
    typeof server !== "string" ||
    !server ||
    typeof tool !== "string" ||
    !tool ||
    definition === null ||
    typeof definition !== "object" ||
    Array.isArray(definition) ||
    typeof digest !== "string" ||
    !digest ||
    (klass !== CLASS_CHANGED && klass !== CLASS_FLOATING) ||
    typeof seen !== "string" ||
    !seen
  ) {
    return null;
  }
  const key = body["launch_key"];
  const fieldsV = body["contract_fields"];
  return {
    serverId: server,
    toolName: tool,
    definition: definition as ToolDef,
    definitionHash: digest,
    pendingClass: klass,
    firstSeen: seen,
    launchKey: typeof key === "string" && key.length > 0 ? key : undefined,
    contractFields: Number.isInteger(fieldsV) ? (fieldsV as number) : undefined,
  };
}

function loadUnlocked(path: string): PendingRecord[] {
  try {
    const raw: unknown = JSON.parse(readFileSync(path, "utf8"));
    if (raw === null || typeof raw !== "object" || Array.isArray(raw)) return [];
    const rows = (raw as Record<string, unknown>)["records"];
    if (!Array.isArray(rows)) return [];
    const out: PendingRecord[] = [];
    for (const row of rows) {
      const rec = parseRecord(row);
      if (rec !== null) out.push(rec);
    }
    return out;
  } catch {
    return [];
  }
}

function stableStringify(value: unknown): string {
  return JSON.stringify(sortKeys(value), null, 2) + "\n";
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      out[key] = sortKeys((value as Record<string, unknown>)[key]);
    }
    return out;
  }
  return value;
}

function dumpUnlocked(path: string, records: PendingRecord[]): void {
  const payload = {
    version: PENDING_VERSION,
    records: records.map((rec) => {
      const row: Record<string, unknown> = {
        server_id: rec.serverId,
        tool_name: rec.toolName,
        definition: rec.definition,
        definition_hash: rec.definitionHash,
        class: rec.pendingClass,
        first_seen: rec.firstSeen,
      };
      if (rec.launchKey) row["launch_key"] = rec.launchKey;
      if (rec.contractFields !== undefined) row["contract_fields"] = rec.contractFields;
      return row;
    }),
  };
  const directory = dirname(path) || ".";
  mkdirSync(directory, { recursive: true });
  const suffix = randomBytes(8).toString("hex");
  const tmp = join(directory, `.pending.${process.pid}.${suffix}.tmp`);
  let flags = constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL;
  if (typeof constants.O_NOFOLLOW === "number") {
    flags |= constants.O_NOFOLLOW;
  }
  const fd = openSync(tmp, flags, 0o600);
  try {
    writeSync(fd, Buffer.from(stableStringify(payload), "utf8"));
    fsyncSync(fd);
    closeSync(fd);
    chmodSync(tmp, 0o600);
    renameSync(tmp, path);
  } catch (err) {
    try {
      unlinkSync(tmp);
    } catch {
      // already removed
    }
    throw err;
  }
}

function cap(records: PendingRecord[]): PendingRecord[] {
  const ordered = [...records].sort((a, b) => {
    if (a.firstSeen !== b.firstSeen) return a.firstSeen < b.firstSeen ? -1 : 1;
    if (a.serverId !== b.serverId) return a.serverId < b.serverId ? -1 : 1;
    return a.toolName < b.toolName ? -1 : a.toolName > b.toolName ? 1 : 0;
  });
  while (ordered.length > TOTAL_CAP) ordered.shift();
  const counts = new Map<string, number>();
  for (const rec of ordered) counts.set(rec.serverId, (counts.get(rec.serverId) ?? 0) + 1);
  while ([...counts.values()].some((n) => n > PER_SERVER_CAP)) {
    for (let i = 0; i < ordered.length; i++) {
      const rec = ordered[i]!;
      if ((counts.get(rec.serverId) ?? 0) > PER_SERVER_CAP) {
        counts.set(rec.serverId, (counts.get(rec.serverId) ?? 1) - 1);
        ordered.splice(i, 1);
        break;
      }
    }
  }
  return ordered;
}

export function recordPending(
  path: string,
  args: {
    serverId: string;
    toolName: string;
    definition: ToolDef;
    definitionHash: string;
    pendingClass: string;
    launchKey?: string;
  },
): void {
  if (args.pendingClass !== CLASS_CHANGED && args.pendingClass !== CLASS_FLOATING) return;
  if (!args.definitionHash) return;
  withExclusiveLock(path, () => {
    const rows = loadUnlocked(path);
    const kept: PendingRecord[] = [];
    let firstSeen = utcNowIso();
    for (const rec of rows) {
      if (
        rec.serverId === args.serverId &&
        rec.toolName === args.toolName &&
        rec.definitionHash === args.definitionHash
      ) {
        firstSeen = rec.firstSeen;
        continue;
      }
      kept.push(rec);
    }
    kept.push({
      serverId: args.serverId,
      toolName: args.toolName,
      definition: args.definition,
      definitionHash: args.definitionHash,
      pendingClass: args.pendingClass,
      firstSeen,
      launchKey: args.launchKey,
      contractFields: CONTRACT_FIELDS_VERSION,
    });
    dumpUnlocked(path, cap(kept));
  });
}

export function loadPending(path: string): PendingRecord[] {
  try {
    readFileSync(path);
  } catch {
    return [];
  }
  return withExclusiveLock(path, () => loadUnlocked(path));
}

function pinRecord(pin: PreflightPin, rec: PendingRecord): PinnedTool | null {
  try {
    if (approvalDigest(rec.definition as Record<string, unknown>) !== rec.definitionHash) {
      return null;
    }
  } catch {
    return null;
  }
  let pinHash: string;
  try {
    pinHash = hashTool(rec.definition as Record<string, unknown>);
  } catch {
    return null;
  }
  const written: PinnedTool = {
    serverId: rec.serverId,
    toolName: rec.toolName,
    definitionHash: pinHash,
    pinnedAt: utcNowIso(),
    schema: rec.definition,
    via: "approve",
    launchKey: rec.launchKey,
    // Only a record stamped by this version marks the pin complete.
    contractFields: rec.contractFields === CONTRACT_FIELDS_VERSION ? CONTRACT_FIELDS_VERSION : undefined,
  };
  pin.put(written);
  return written;
}

export function approveOne(
  pin: PreflightPin,
  path: string,
  serverId: string,
  toolName: string,
  definitionHash: string,
  opts?: { floatingOnly?: boolean },
): PinnedTool | null {
  const match = withExclusiveLock(path, () => {
    for (const rec of loadUnlocked(path)) {
      if (
        rec.serverId === serverId &&
        rec.toolName === toolName &&
        rec.definitionHash === definitionHash
      ) {
        if (opts?.floatingOnly && rec.pendingClass !== CLASS_FLOATING) return null;
        return rec;
      }
    }
    return null;
  });
  if (match === null) return null;
  const written = pinRecord(pin, match);
  if (written === null) return null;
  withExclusiveLock(path, () => {
    const remain = loadUnlocked(path).filter(
      (rec) =>
        !(
          rec.serverId === serverId &&
          rec.toolName === toolName &&
          rec.definitionHash === definitionHash
        ),
    );
    dumpUnlocked(path, remain);
  });
  return written;
}

/** Basename helper kept for tests that inspect the pending file name. */
export function pendingFileName(): string {
  return basename(NAME);
}

export type ResetPinsResult = {
  path: string;
  pinCount: number;
  tainted: string | null;
};

/**
 * Delete one server's pin store and its ever-pinned record, and drop its
 * pending rows. The next tools/list pins from the current contract.
 */
export function resetPins(
  serverId: string,
  opts?: { path?: string },
): ResetPinsResult {
  const path = opts?.path ?? defaultPinStorePath(serverId);
  const before = new PreflightPin(path);
  const pinCount = before.toolsFor(serverId).length;
  const tainted = before.tainted;
  withExclusiveLock(path, () => {
    try {
      unlinkSync(path);
    } catch {
      // absent is fine
    }
    clearEverPinned(path);
  });
  const pending = pendingPath(defaultStateDir());
  try {
    withExclusiveLock(pending, () => {
      const remain = loadUnlocked(pending).filter((rec) => rec.serverId !== serverId);
      dumpUnlocked(pending, remain);
    });
  } catch {
    // no pending file is fine
  }
  return { path, pinCount, tainted };
}
