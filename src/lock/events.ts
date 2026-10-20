/**
 * mcpindex.lock.event/1 records (section 10), handed to a sink the caller
 * passes in. Nothing here opens a network connection; the only file sink is
 * one the caller constructs with a path.
 *
 * Events carry tool names, digests and reason codes. They never carry call
 * arguments, call results, descriptions, instructions text or credentials:
 * builders take only those fields, so there is no object to leak from.
 */

import { appendFileSync } from "node:fs";
import { randomUUID } from "node:crypto";

import { identityH16, slug } from "./lock.js";
import type { Identity, LockErrorReason, Posture, Via } from "./lock.js";
import type { CallReason, Decision, MetaReason, ToolReason } from "./check.js";
import { nowRfc3339 } from "./store.js";

export const EVENT_SCHEMA = "mcpindex.lock.event/1";

export interface EventServer {
  readonly h16: string;
  readonly slug: string;
}

interface EventBase {
  readonly schema: typeof EVENT_SCHEMA;
  readonly id: string;
  readonly time: string;
  readonly host: string;
  readonly server: EventServer;
}

export interface ListingEvent extends EventBase {
  readonly type: "listing";
  readonly posture: Posture;
  readonly lockError: LockErrorReason | null;
  readonly counts: { readonly served: number; readonly shown: number; readonly withheld: number; readonly removed: number };
  readonly tools: ReadonlyArray<{
    readonly name: string;
    readonly served: string | null;
    readonly approved: string | null;
    readonly decision: "shown" | "withheld";
    readonly reason: ToolReason | LockErrorReason | null;
    readonly meta: MetaReason | null;
  }>;
  readonly removed: readonly string[];
  readonly instructions: string | null;
  /** The snapshot the decision used (optional in the spec, always set here). */
  readonly snapshotId: string;
}

export interface RefusalEvent extends EventBase {
  readonly type: "refusal";
  readonly tool: string;
  readonly reason: CallReason;
}

export interface ApprovalEvent extends EventBase {
  readonly type: "approval";
  readonly tool: string;
  readonly digest: string;
  readonly via: Via;
  readonly subject: string;
  readonly ref: string | null;
}

export type LockEvent = ListingEvent | RefusalEvent | ApprovalEvent;
export type LockEventSink = (event: LockEvent) => void;

export interface EventContext {
  readonly host: string;
  readonly identity: Identity;
  readonly now?: () => Date;
  readonly newId?: () => string;
}

function base(ctx: EventContext): EventBase {
  return {
    schema: EVENT_SCHEMA,
    id: (ctx.newId ?? randomUUID)(),
    time: nowRfc3339((ctx.now ?? (() => new Date()))()),
    host: ctx.host,
    server: { h16: identityH16(ctx.identity), slug: slug(ctx.identity) },
  };
}

export function listingEvent(ctx: EventContext, decision: Decision, snapshotId: string): ListingEvent {
  // As in the Python host: every served entry that is not shown counts as
  // withheld, entries without a string name included.
  const withheld = decision.served - decision.shown.length;
  return {
    ...base(ctx),
    type: "listing",
    posture: decision.posture,
    lockError: decision.lockError,
    counts: { served: decision.served, shown: decision.shown.length, withheld, removed: decision.removed.length },
    tools: decision.tools.map((t) => ({
      name: t.name,
      served: t.served,
      approved: t.approved,
      decision: t.decision,
      reason: t.reason,
      meta: t.meta,
    })),
    removed: [...decision.removed],
    // Under a whole-lock failure the instructions are withheld with everything
    // else and the event carries no instructions code, as in the Python host.
    instructions: decision.lockError !== null ? null : decision.instructions,
    snapshotId,
  };
}

export function refusalEvent(ctx: EventContext, tool: string, reason: CallReason): RefusalEvent {
  return { ...base(ctx), type: "refusal", tool, reason };
}

export function approvalEvent(
  ctx: EventContext,
  approval: { tool: string; digest: string; via: Via; subject: string; ref?: string },
): ApprovalEvent {
  return {
    ...base(ctx),
    type: "approval",
    tool: approval.tool,
    digest: approval.digest,
    via: approval.via,
    subject: approval.subject,
    ref: approval.ref ?? null,
  };
}

/** Call the sink and swallow its errors: an event failure never changes a decision. */
export function emit(sink: LockEventSink | undefined, event: LockEvent): void {
  if (sink === undefined) return;
  try {
    sink(event);
  } catch {
    // sink errors are the sink's problem
  }
}

/** Append one JSON line per event to `path`. Only used when a caller builds it. */
export function jsonlFileSink(path: string): LockEventSink {
  return (event) => {
    appendFileSync(path, JSON.stringify(event) + "\n", { encoding: "utf8", mode: 0o600 });
  };
}
