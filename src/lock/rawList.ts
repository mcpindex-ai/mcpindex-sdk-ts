/**
 * Lock mode for the official MCP TypeScript client, at the transport.
 *
 * `Client.listTools()` returns tools after its zod schema has stripped unknown
 * members, so a digest over that result is not a digest over what the server
 * sent. LockedTransport sits between the Client and its real Transport and
 * works on the parsed JSON-RPC message instead. The transports parse each
 * message with JSON.parse and check only the envelope, so every member inside
 * `result.tools`, `__proto__` included, is still there as sent.
 *
 * For a `tools/list` request from the client it:
 *   - matches the response by request id (a response whose id is missing, not
 *     outstanding, or already answered is dropped and reported to onerror);
 *   - follows `nextCursor` itself, sending its own page requests under private
 *     ids, so one listing is every page (section 9.2). The client gets one
 *     response with every shown tool and no cursor. A client request that
 *     carries a cursor is answered with an error, since there is no partial
 *     listing in lock mode;
 *   - loads a lock snapshot, runs checkListing on the raw tools, installs the
 *     decision in the CallGate, emits a listing event, and passes on only the
 *     shown raw entries. The client then parses exactly those.
 *
 * Every outgoing `tools/call` goes through the CallGate first. A refused call
 * is never sent; the client gets a -32011 error with data.reason. This covers
 * callTool, request, requestStream and the task helpers alike, because they
 * all end in Transport.send.
 *
 * `notifications/tools/list_changed` is passed on and marks a listing as due.
 * Until the next listing completes the previous allow-list stays, so a name
 * the server just added is not callable. A listing that fails (an error
 * response, a result with no tools array, a page that cannot be requested, a
 * page or tool limit exceeded) is different: every call is then refused with
 * `unreachable` until a listing completes (section 9.5). Server instructions arrive in the
 * initialize result; they are checked there and stripped when the check says so.
 *
 * Lock mode has no auto-accept, first-use pin or re-pin, and this adapter
 * takes no option that would add one.
 */

import type { JSONRPCMessage, MessageExtraInfo } from "@modelcontextprotocol/sdk/types.js";
import type { Transport, TransportSendOptions } from "@modelcontextprotocol/sdk/shared/transport.js";

import { CallGate, checkInstructions, checkListing, isPosture, refusalError } from "./check.js";
import type { CallReason, Decision } from "./check.js";
import { listingEvent, refusalEvent, emit } from "./events.js";
import type { EventContext, LockEventSink } from "./events.js";
import { LockError, validateIdentity } from "./lock.js";
import type { Identity, Posture } from "./lock.js";
import { snapshotOfError } from "./store.js";
import type { LockSnapshot, LockStore } from "./store.js";

/** Pages and tools one listing may span before the server is treated as unreachable. */
export const MAX_LIST_PAGES = 100;
export const MAX_LIST_TOOLS = 10_000;
/** Unanswered client requests tracked at once. */
export const MAX_OUTSTANDING = 4_096;
/** Default age after which a call first reloads the snapshot (see LockOptions.maxStalenessMs). */
export const DEFAULT_MAX_STALENESS_MS = 60_000;

const FORBIDDEN_OPTIONS = ["autoAccept", "autoApprove", "tofu", "newTools", "repin", "migrate"];

export interface LockOptions {
  readonly store: LockStore;
  /** This server's identity (section 3), from host configuration. */
  readonly identity: Identity;
  readonly posture: Posture;
  /** The host name written into events. */
  readonly host?: string;
  readonly sink?: LockEventSink;
  /**
   * Age after which a call reloads the snapshot, so a revoke reaches a live
   * connection; if the reload fails the call gets lock-stale. Default 60 s.
   */
  readonly maxStalenessMs?: number;
  readonly now?: () => number;
}

type Rpc = Record<string, unknown>;
type RequestId = string | number;

function isObj(v: unknown): v is Rpc {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function own(obj: Rpc, key: string): unknown {
  return Object.getOwnPropertyDescriptor(obj, key)?.value;
}

function idKey(id: unknown): string | null {
  if (typeof id === "number" && Number.isFinite(id)) return `n:${id}`;
  if (typeof id === "string") return `s:${id}`;
  return null;
}

/** Copy a result object member by member, leaving out `drop`. */
function copyWithout(result: Rpc, drop: readonly string[]): Rpc {
  const out: Rpc = {};
  for (const key of Object.keys(result)) {
    if (drop.includes(key)) continue;
    Object.defineProperty(out, key, { value: own(result, key), enumerable: true, writable: true, configurable: true });
  }
  return out;
}

interface Collecting {
  readonly clientId: RequestId;
  readonly first: Rpc;
  readonly tools: unknown[];
  readonly cursors: Set<string>;
  pages: number;
}

export class LockedTransport implements Transport {
  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: <T extends JSONRPCMessage>(message: T, extra?: MessageExtraInfo) => void;

  readonly gate: CallGate;
  readonly #inner: Transport;
  readonly #store: LockStore;
  readonly #identity: Identity;
  readonly #posture: Posture;
  readonly #sink: LockEventSink | undefined;
  readonly #events: EventContext;
  readonly #now: () => number;
  /** Client request id key to method, for every request still unanswered. */
  readonly #outstanding = new Map<string, string>();
  /** Private page request id key to the listing it belongs to. */
  readonly #pages = new Map<string, Collecting>();
  #queue: Promise<void> = Promise.resolve();
  #served: unknown = undefined;
  #lastTools: readonly unknown[] | null = null;
  #listingDue = false;
  #seq = 0;
  readonly #tag = Math.random().toString(36).slice(2, 10);

  constructor(inner: Transport, options: LockOptions) {
    for (const key of FORBIDDEN_OPTIONS) {
      if (key in (options as object)) throw new Error(`lock mode does not accept ${key}`);
    }
    if (!isPosture(options.posture)) throw new Error(`unknown posture ${String(options.posture)}`);
    this.#inner = inner;
    this.#store = options.store;
    this.#identity = validateIdentity(options.identity);
    this.#posture = options.posture;
    this.#sink = options.sink;
    this.#now = options.now ?? Date.now;
    this.gate = new CallGate({ maxStalenessMs: options.maxStalenessMs ?? DEFAULT_MAX_STALENESS_MS, now: this.#now });
    this.#events = { host: options.host ?? "mcpindex-sdk", identity: this.#identity };
  }

  get sessionId(): string | undefined {
    return this.#inner.sessionId;
  }

  setProtocolVersion(version: string): void {
    this.#inner.setProtocolVersion?.(version);
  }

  /** True after a list_changed notification until the next listing completes. */
  get listingDue(): boolean {
    return this.#listingDue;
  }

  /** The decision for the latest complete listing on this connection, or null. */
  get decision(): Decision | null {
    return this.gate.decision;
  }

  async start(): Promise<void> {
    this.#inner.onmessage = (message: JSONRPCMessage, extra?: MessageExtraInfo) => {
      this.#queue = this.#queue
        .then(() => this.#incoming(message as unknown, extra))
        .catch((exc: unknown) => this.onerror?.(exc instanceof Error ? exc : new Error(String(exc))));
    };
    this.#inner.onerror = (error: Error) => this.onerror?.(error);
    this.#inner.onclose = () => this.onclose?.();
    await this.#inner.start();
  }

  async close(): Promise<void> {
    await this.#inner.close();
  }

  async send(message: JSONRPCMessage, options?: TransportSendOptions): Promise<void> {
    const msg = message as unknown;
    if (Array.isArray(msg)) throw new Error("lock mode does not send JSON-RPC batches");
    if (isObj(msg) && own(msg, "method") === "tools/call" && idKey(own(msg, "id")) === null) {
      throw new Error("lock mode refuses a tools/call without a valid request id");
    }
    if (isObj(msg) && typeof own(msg, "method") === "string" && idKey(own(msg, "id")) !== null) {
      const method = own(msg, "method") as string;
      const id = own(msg, "id") as RequestId;
      const params = own(msg, "params");
      if (method === "tools/call") {
        const name = isObj(params) ? own(params, "name") : undefined;
        const verdict = typeof name === "string" ? await this.#checkCall(name) : ("not-listed" as CallReason);
        if (verdict !== "allow") {
          const tool = typeof name === "string" ? name : String(name);
          emit(this.#sink, refusalEvent(this.#events, tool, verdict));
          this.#deliverLater({ jsonrpc: "2.0", id, error: refusalError(tool, verdict) });
          return;
        }
      }
      if (method === "tools/list" && isObj(params) && own(params, "cursor") !== undefined) {
        this.#deliverLater({
          jsonrpc: "2.0",
          id,
          error: { code: -32602, message: "lock mode collects every page itself; send tools/list without a cursor" },
        });
        return;
      }
      if (this.#outstanding.size >= MAX_OUTSTANDING) {
        throw new Error("lock mode: too many requests without a response");
      }
      this.#outstanding.set(idKey(id) as string, method);
    }
    await this.#inner.send(message, options);
  }

  async #checkCall(name: string): Promise<"allow" | CallReason> {
    if (this.gate.isStale()) await this.#refresh();
    return this.gate.check(name);
  }

  /** Reload the snapshot and re-check the last listing; the allow-list can only shrink. */
  async #refresh(): Promise<void> {
    const previous = this.gate.decision;
    const tools = this.#lastTools;
    if (previous === null || tools === null || this.gate.unreachable) return;
    let snapshot: LockSnapshot;
    try {
      snapshot = await this.#store.loadSnapshot();
    } catch {
      return; // stays stale; calls get lock-stale
    }
    // A listing that completed or failed during the await is newer; never overwrite it.
    if (this.gate.decision !== previous || this.gate.unreachable) return;
    const fresh = checkListing(snapshot.lock, this.#identity, { tools, instructions: this.#served }, this.#posture);
    const callable = new Set([...fresh.callable].filter((n) => previous.callable.has(n)));
    this.gate.record(Object.freeze({ ...fresh, callable }), snapshot);
  }

  #deliver(message: Rpc, extra?: MessageExtraInfo): void {
    this.onmessage?.(message as unknown as JSONRPCMessage, extra);
  }

  #deliverLater(message: Rpc): void {
    queueMicrotask(() => this.#deliver(message));
  }

  async #snapshot(): Promise<LockSnapshot> {
    try {
      return await this.#store.loadSnapshot();
    } catch (exc) {
      return snapshotOfError(new LockError("lock-unreadable", (exc as Error).message ?? "store failed"), this.#now());
    }
  }

  async #incoming(message: unknown, extra?: MessageExtraInfo): Promise<void> {
    if (!isObj(message)) {
      this.onerror?.(new Error("dropped a message that is not a JSON-RPC object"));
      return;
    }
    const method = own(message, "method");
    if (typeof method === "string") {
      if (method === "notifications/tools/list_changed" && own(message, "id") === undefined) this.#listingDue = true;
      this.#deliver(message, extra);
      return;
    }
    const hasResult = own(message, "result") !== undefined;
    const hasError = own(message, "error") !== undefined;
    if (!hasResult && !hasError) {
      this.#deliver(message, extra); // not a response; the client reports what it is
      return;
    }
    const key = idKey(own(message, "id"));
    if (key === null) {
      this.onerror?.(new Error("dropped a response with a missing or invalid id"));
      return;
    }
    const page = this.#pages.get(key);
    if (page !== undefined) {
      this.#pages.delete(key);
      await this.#onPage(page, message);
      return;
    }
    const pending = this.#outstanding.get(key);
    if (pending === undefined) {
      this.onerror?.(new Error("dropped a response that matches no outstanding request"));
      return;
    }
    this.#outstanding.delete(key);
    if (pending === "initialize" && hasResult) {
      await this.#onInitialize(message, extra);
      return;
    }
    if (pending === "tools/list" && hasResult) {
      const result = own(message, "result");
      if (!isObj(result)) {
        this.#listingFailed(own(message, "id") as RequestId, "tools/list result is not an object");
        return;
      }
      const collecting: Collecting = {
        clientId: own(message, "id") as RequestId,
        first: result,
        tools: [],
        cursors: new Set(),
        pages: 0,
      };
      await this.#onPage(collecting, message);
      return;
    }
    if (pending === "tools/list") this.gate.markUnreachable(); // an error response: the listing failed
    this.#deliver(message, extra);
  }

  async #onInitialize(message: Rpc, extra?: MessageExtraInfo): Promise<void> {
    const result = own(message, "result");
    if (!isObj(result)) {
      this.#deliver(message, extra);
      return;
    }
    this.#served = own(result, "instructions");
    const snapshot = await this.#snapshot();
    const verdict = checkInstructions(snapshot.lock, this.#identity, this.#served, this.#posture);
    if (!verdict.strip) {
      this.#deliver(message, extra);
      return;
    }
    this.#deliver({ ...copyWithout(message, ["result"]), result: copyWithout(result, ["instructions"]) }, extra);
  }

  #listingFailed(clientId: RequestId, why: string): void {
    // The server sent something that is not a listing. Fail closed: no call
    // proceeds until a listing completes.
    this.gate.markUnreachable();
    this.#deliver({ jsonrpc: "2.0", id: clientId, error: { code: -32603, message: `lock mode: ${why}` } });
  }

  async #onPage(collecting: Collecting, message: Rpc): Promise<void> {
    const error = own(message, "error");
    if (error !== undefined) {
      // A failed page means the listing failed; no earlier allow-list is used.
      this.gate.markUnreachable();
      this.#deliver({ jsonrpc: "2.0", id: collecting.clientId, error });
      return;
    }
    const result = own(message, "result");
    const tools = isObj(result) ? own(result, "tools") : undefined;
    if (!Array.isArray(tools)) {
      this.#listingFailed(collecting.clientId, "tools/list result has no tools array");
      return;
    }
    collecting.pages += 1;
    for (const t of tools) collecting.tools.push(t);
    if (collecting.pages > MAX_LIST_PAGES || collecting.tools.length > MAX_LIST_TOOLS) {
      this.#listingFailed(collecting.clientId, "listing exceeds the page or tool limit");
      return;
    }
    const cursor = isObj(result) ? own(result, "nextCursor") : undefined;
    if (typeof cursor === "string" && cursor !== "") {
      if (collecting.cursors.has(cursor)) {
        this.#listingFailed(collecting.clientId, "server repeated a cursor");
        return;
      }
      collecting.cursors.add(cursor);
      this.#seq += 1;
      const pid = `mcplock:${this.#tag}:${this.#seq}`;
      this.#pages.set(idKey(pid) as string, collecting);
      try {
        await this.#inner.send({ jsonrpc: "2.0", id: pid, method: "tools/list", params: { cursor } } as JSONRPCMessage);
      } catch (exc) {
        this.#pages.delete(idKey(pid) as string);
        this.gate.markUnreachable();
        this.#deliver({
          jsonrpc: "2.0",
          id: collecting.clientId,
          error: { code: -32603, message: `lock mode: page request failed: ${(exc as Error).message}` },
        });
      }
      return;
    }
    await this.#finish(collecting);
  }

  async #finish(collecting: Collecting): Promise<void> {
    const tools = collecting.tools;
    const snapshot = await this.#snapshot();
    const decision = checkListing(snapshot.lock, this.#identity, { tools, instructions: this.#served }, this.#posture);
    this.gate.record(decision, snapshot);
    this.#lastTools = tools;
    this.#listingDue = false;
    emit(this.#sink, listingEvent(this.#events, decision, snapshot.snapshotId));
    const result = copyWithout(collecting.first, ["tools", "nextCursor"]);
    result.tools = decision.shownIndexes.map((i) => tools[i]);
    this.#deliver({ jsonrpc: "2.0", id: collecting.clientId, result });
  }
}

/** Anything with the Client.connect signature. */
export interface ConnectableClient {
  connect(transport: Transport): Promise<void>;
}

/** Wrap `transport` in lock mode and connect `client` through it. */
export async function lockClient(
  client: ConnectableClient,
  transport: Transport,
  options: LockOptions,
): Promise<LockedTransport> {
  const locked = new LockedTransport(transport, options);
  await client.connect(locked);
  return locked;
}
