/**
 * The LOCAL breadcrumb store for OUR-OWN code failures (graceful-fail capture) —
 * a port of Python `tooling/cse/errors.py`. A bug in our gate/wrapper must NEVER
 * crash the agent's call: the entry points catch it, fail closed to a generic
 * internal-error HOLD, and record a SCRUBBED breadcrumb here. A record carries
 * ONLY the exception CLASS NAME, a closed `Operation`, our-authored location, the
 * client version, and a dedup fingerprint — NEVER user data.
 */

import { createHash } from "node:crypto";
import { utcNowIso } from "./preflight.js";

export const CLIENT_VERSION = "0.1.0";

export const ERROR_RECORD_KEYS: ReadonlySet<string> = new Set([
  "error_class",
  "operation",
  "our_code_location",
  "client_version",
  "fingerprint",
]);

export enum Operation {
  CALL_TOOL = "call_tool",
  SEND_REQUEST = "send_request",
  LIST_TOOLS = "list_tools",
  GATE_DECISION = "gate_decision",
  PROXY_GATE = "proxy_gate",
  PROXY_RELAY = "proxy_relay",
}

function fingerprint(errorClass: string, ourCodeLocation: string): string {
  const pre = `${errorClass}|${ourCodeLocation}`;
  return createHash("sha256").update(pre, "utf-8").digest("hex").slice(0, 16);
}

export interface ErrorRecord {
  readonly at: string;
  readonly errorClass: string;
  readonly operation: Operation;
  readonly ourCodeLocation: string;
  readonly clientVersion: string;
  readonly fingerprint: string;
}

/** The SCRUBBED projection — only the `ERROR_RECORD_KEYS` allowlist. */
export function asRecord(r: ErrorRecord): Record<string, string> {
  return {
    error_class: r.errorClass,
    operation: r.operation,
    our_code_location: r.ourCodeLocation,
    client_version: r.clientVersion,
    fingerprint: r.fingerprint,
  };
}

const MAX_RECORDS = 10_000;

/** On-device append-only breadcrumb store; ZERO egress. */
export class ErrorStore {
  private readonly records: ErrorRecord[] = [];

  constructor(private readonly now: () => string = utcNowIso) {}

  capture(
    excClassName: string,
    operation: Operation,
    ourCodeLocation: string,
    clientVersion: string = CLIENT_VERSION,
  ): ErrorRecord {
    const rec: ErrorRecord = {
      at: this.now(),
      errorClass: excClassName,
      operation,
      ourCodeLocation,
      clientVersion,
      fingerprint: fingerprint(excClassName, ourCodeLocation),
    };
    this.records.push(rec);
    if (this.records.length > MAX_RECORDS) {
      this.records.splice(0, this.records.length - MAX_RECORDS);
    }
    return rec;
  }

  snapshot(): ErrorRecord[] {
    return [...this.records];
  }

  scrubbedRecords(): Array<Record<string, string>> {
    return this.records.map(asRecord);
  }

  fingerprintCounts(): Record<string, number> {
    const counts: Record<string, number> = {};
    for (const r of this.records) {
      counts[r.fingerprint] = (counts[r.fingerprint] ?? 0) + 1;
    }
    return counts;
  }
}
