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
 *   - starts a listing (section 9.2.1) when it sends the request. Until the
 *     listing is decided or fails, every `tools/call` is refused with
 *     `no-listing`. A second cursorless `tools/list` abandons the first, whose
 *     request is answered with an error;
 *   - classifies every frame from the server as section 9.2.2 says
 *     (classifyFrame): only the response to an unanswered `tools/list`,
 *     matched by id with exact JSON type and value, can carry tools, and only
 *     that or the `initialize` or `server/discover` response can carry
 *     instructions. Anything else that carries them, or has both a method and
 *     a result or error, is dropped and reported to onerror. A client request
 *     whose id it matches is answered with an error under that id and is no
 *     longer pending; when that request is the listing's, or one of its page
 *     requests, the listing fails. A response whose id matches no request is
 *     dropped too;
 *   - follows `nextCursor` itself, sending its own page requests under private
 *     ids, so one listing is every page (section 9.2). The client gets one
 *     response with every shown tool and no cursor. A client request that
 *     carries a cursor is answered with an error, since there is no partial
 *     listing in lock mode;
 *   - loads a lock snapshot, runs checkListing on the raw tools, installs the
 *     decision in the CallGate, emits a listing event, and passes on only the
 *     shown raw entries, without a top-level `_meta` that the decision removes
 *     (section 9.2.3). The client then parses exactly those.
 *
 * Every outgoing `tools/call` goes through the CallGate first. A refused call
 * is never sent; the client gets a -32011 error with data.reason. This covers
 * callTool, request, requestStream and the task helpers alike, because they
 * all end in Transport.send. A call on a snapshot older than maxStalenessMs
 * (default 60 s) reloads it first; the reload can only shrink the allow-list,
 * and if it fails the call gets `lock-stale` and the next call tries again.
 *
 * `notifications/tools/list_changed` is passed on and marks a listing as due.
 * It does not change the allow-list, and this adapter does not start a
 * listing on its own (the spec's SHOULD); the client asks for one. A listing
 * that fails (an error response, a result with no tools array, a page that
 * cannot be requested or gets no response, a page or tool limit exceeded)
 * refuses every call with `unreachable` until a listing completes (section
 * 9.5). Server instructions arrive in the initialize or server/discover
 * result; they are checked there and stripped when the check says so.
 *
 * Unanswered requests are tracked in bounded maps. An entry leaves on its
 * response, on the client's notifications/cancelled, after REQUEST_TTL_MS, or,
 * when the map is full, oldest first. If that entry is the listing in
 * progress, the listing fails.
 *
 * Lock mode has no auto-accept, first-use pin or re-pin, and this adapter
 * takes no option that would add one.
 */

import type { JSONRPCMessage, MessageExtraInfo } from "@modelcontextprotocol/sdk/types.js";
import type { Transport, TransportSendOptions } from "@modelcontextprotocol/sdk/shared/transport.js";

import { CallGate, DEFAULT_MAX_STALENESS_MS, checkInstructions, checkListing, isPosture, refusalError } from "./check.js";
import type { CallReason, Decision, ToolReason } from "./check.js";
import { listingEvent, refusalEvent, emit } from "./events.js";
import type { EventContext, LockEventSink } from "./events.js";
import { LockError, validateIdentity } from "./lock.js";
import type { Identity, LockErrorReason, Posture } from "./lock.js";
import { snapshotOfError } from "./store.js";
import type { LockSnapshot, LockStore } from "./store.js";

/** Pages and tools one listing may span before the server is treated as unreachable. */
export const MAX_LIST_PAGES = 100;
export const MAX_LIST_TOOLS = 10_000;
/** Unanswered requests tracked at once; past this the oldest is forgotten. */
export const MAX_OUTSTANDING = 4_096;
/** Age after which an unanswered request is forgotten (its late response is dropped). */
export const REQUEST_TTL_MS = 600_000;
export { DEFAULT_MAX_STALENESS_MS };

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

function hasOwn(obj: Rpc, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(obj, key);
}

/** Map key for a request id: JSON type and value. Null, booleans and the rest have none. */
function idKey(id: unknown): string | null {
  if (typeof id === "number" && Number.isFinite(id)) return `n:${id}`;
  if (typeof id === "string") return `s:${id}`;
  return null;
}

/** Section 9.2.2: `id` equals one of `ids` in JSON type and value. Null matches nothing. */
export function idMatches(id: unknown, ids: readonly unknown[]): boolean {
  const key = idKey(id);
  return key !== null && ids.some((i) => idKey(i) === key);
}

/** Requests whose response may carry instructions (section 9.2.2). */
export const HANDSHAKE_METHODS: readonly string[] = Object.freeze(["initialize", "server/discover"]);

export type FrameKind = "listing" | "handshake" | "drop" | "relay";

/**
 * What the host does with one frame from the server (section 9.2.2):
 * `listing` (a page of the listing whose request it answers), `handshake`
 * (the initialize or server/discover response; its instructions are
 * checked), `drop`, or `relay`. `isInflight` and `isHandshake` say whether an
 * id matches an unanswered tools/list or handshake request; unanswered
 * tools/list requests are matched first.
 */
export function classifyFrame(
  frame: unknown,
  isInflight: (id: unknown) => boolean,
  isHandshake: (id: unknown) => boolean,
): FrameKind {
  if (!isObj(frame)) return "drop";
  const result = own(frame, "result");
  const carriesTools = isObj(result) && hasOwn(result, "tools");
  const carriesInstructions = isObj(result) && hasOwn(result, "instructions");
  if (hasOwn(frame, "method")) return hasOwn(frame, "result") || hasOwn(frame, "error") ? "drop" : "relay";
  if (!hasOwn(frame, "id")) return carriesTools || carriesInstructions ? "drop" : "relay";
  const id = own(frame, "id");
  if (isInflight(id)) return "listing";
  if (carriesTools) return "drop";
  if (isHandshake(id)) return "handshake";
  if (carriesInstructions) return "drop";
  return "relay";
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
  readonly first: Rpc;
  readonly tools: unknown[];
  readonly cursors: Set<string>;
  pages: number;
}

/** The listing in progress: the client's request, and its pages once the first is in. */
interface Listing {
  readonly clientId: RequestId;
  readonly clientKey: string;
  collecting: Collecting | null;
}

interface Pending<T> {
  readonly value: T;
  readonly at: number;
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
  readonly #outstanding = new Map<string, Pending<string>>();
  /** Private page request id key to the listing it belongs to. */
  readonly #pages = new Map<string, Pending<Listing>>();
  #current: Listing | null = null;
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
    this.#expire();
    if (isObj(msg) && own(msg, "method") === "notifications/cancelled") {
      const params = own(msg, "params");
      const key = isObj(params) ? idKey(own(params, "requestId")) : null;
      if (key !== null) this.#forget(key, "the client cancelled the listing request");
    }
    if (isObj(msg) && own(msg, "method") === "tools/call" && idKey(own(msg, "id")) === null) {
      throw new Error("lock mode refuses a tools/call without a valid request id");
    }
    if (isObj(msg) && typeof own(msg, "method") === "string" && idKey(own(msg, "id")) !== null) {
      const method = own(msg, "method") as string;
      const id = own(msg, "id") as RequestId;
      const key = idKey(id) as string;
      const params = own(msg, "params");
      if (method === "tools/call") {
        const name = isObj(params) ? own(params, "name") : undefined;
        const verdict = await this.#checkCall(typeof name === "string" ? name : null);
        if (verdict !== "allow") {
          const tool = typeof name === "string" ? name : null;
          // As in the Python host: the event names "" and data.tool is left out.
          emit(this.#sink, refusalEvent(this.#events, tool ?? "", verdict));
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
      this.#forget(key, "the listing request id was reused");
      while (this.#outstanding.size >= MAX_OUTSTANDING) {
        this.#forget(this.#outstanding.keys().next().value as string, "too many requests without a response");
      }
      this.#outstanding.set(key, { value: method, at: this.#now() });
      if (method === "tools/list") {
        // Section 9.2.1: the listing starts now; an earlier one is abandoned.
        if (this.#current !== null) this.#abandon(this.#current);
        this.#current = { clientId: id, clientKey: key, collecting: null };
        this.gate.beginListing();
        try {
          await this.#inner.send(message, options);
        } catch (exc) {
          this.#outstanding.delete(key);
          if (this.#current?.clientKey === key) {
            this.#current = null;
            this.gate.markUnreachable();
          }
          throw exc;
        }
        return;
      }
    }
    await this.#inner.send(message, options);
  }

  /** Stop tracking a client request. If it is the listing in progress, that listing fails. */
  #forget(key: string, why: string): void {
    if (!this.#outstanding.delete(key)) return;
    const current = this.#current;
    if (current !== null && current.clientKey === key) this.#fail(current, why);
  }

  /** A newer cursorless tools/list replaced this listing. */
  #abandon(listing: Listing): void {
    this.#dropPages(listing);
    this.#outstanding.delete(listing.clientKey);
    if (this.#current === listing) this.#current = null;
    this.#deliverLater({
      jsonrpc: "2.0",
      id: listing.clientId,
      error: { code: -32603, message: "lock mode: a newer tools/list replaced this listing" },
    });
  }

  #dropPages(listing: Listing): void {
    for (const [key, entry] of this.#pages) if (entry.value === listing) this.#pages.delete(key);
  }

  /**
   * The listing failed. Fail closed: every call is refused with unreachable
   * until a listing completes, and the client's request gets an error.
   */
  #fail(listing: Listing, why: string, error?: unknown): void {
    if (this.#current !== listing) return;
    this.#current = null;
    this.#dropPages(listing);
    this.#outstanding.delete(listing.clientKey);
    this.gate.markUnreachable();
    this.#deliver({ jsonrpc: "2.0", id: listing.clientId, error: error ?? { code: -32603, message: `lock mode: ${why}` } });
  }

  async #checkCall(name: string | null): Promise<"allow" | CallReason> {
    const decision = this.gate.decision;
    if (
      this.gate.isStale() &&
      !this.gate.listingInProgress &&
      !this.gate.unreachable &&
      decision !== null &&
      decision.lockError === null
    ) {
      // Section 9.8: a decided whole-lock failure never reloads; it keeps its reason.
      await this.#refresh();
    }
    const verdict = this.gate.check(name ?? "");
    // A name that is not a string is never on an allow-list.
    if (name === null && verdict === "allow") return "not-listed";
    return verdict;
  }

  /** Forget requests older than REQUEST_TTL_MS. A forgotten page request fails its listing. */
  #expire(): void {
    const cutoff = this.#now() - REQUEST_TTL_MS;
    for (const [key, entry] of this.#outstanding) {
      if (entry.at > cutoff) break;
      this.#forget(key, "the listing request got no response");
    }
    for (const [key, entry] of this.#pages) {
      if (entry.at > cutoff) break;
      this.#pages.delete(key);
      this.#fail(entry.value, "page request got no response");
    }
  }

  /**
   * Reload the snapshot and re-check the last listing (section 9.8). The
   * allow-list keeps only names allowed both before and after; a name the
   * reload drops takes its new reason. A reload whose lock does not load
   * changes nothing, so the call gets lock-stale and the next one retries.
   */
  async #refresh(): Promise<void> {
    const previous = this.gate.decision;
    const tools = this.#lastTools;
    if (previous === null || tools === null) return;
    let snapshot: LockSnapshot;
    try {
      snapshot = await this.#store.loadSnapshot();
    } catch {
      return;
    }
    if (snapshot.lock instanceof LockError) return;
    // A listing that started, completed or failed during the await is newer; never overwrite it.
    if (this.gate.decision !== previous || this.gate.unreachable || this.gate.listingInProgress) return;
    const fresh = checkListing(snapshot.lock, this.#identity, { tools, instructions: this.#served }, this.#posture);
    const callable = new Set([...previous.callable].filter((n) => fresh.callable.has(n)));
    const withheld = new Map<string, ToolReason | LockErrorReason>(previous.withheld);
    for (const name of previous.callable) {
      const reason = callable.has(name) ? undefined : fresh.withheld.get(name);
      if (reason !== undefined) withheld.set(name, reason); // otherwise checkCall says not-listed
    }
    this.gate.record(Object.freeze({ ...previous, callable, withheld }), snapshot);
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

  #isInflight(id: unknown): boolean {
    const key = idKey(id);
    return key !== null && (this.#pages.has(key) || this.#outstanding.get(key)?.value === "tools/list");
  }

  #isHandshake(id: unknown): boolean {
    const key = idKey(id);
    const method = key === null ? undefined : this.#outstanding.get(key)?.value;
    return method !== undefined && HANDSHAKE_METHODS.includes(method);
  }

  async #incoming(message: unknown, extra?: MessageExtraInfo): Promise<void> {
    this.#expire();
    const kind = classifyFrame(
      message,
      (id) => this.#isInflight(id),
      (id) => this.#isHandshake(id),
    );
    if (kind === "drop") {
      this.#drop(message);
      return;
    }
    const msg = message as Rpc;
    if (kind === "relay" && hasOwn(msg, "method")) {
      if (own(msg, "method") === "notifications/tools/list_changed" && !hasOwn(msg, "id")) this.#listingDue = true;
      this.#deliver(msg, extra);
      return;
    }
    const key = idKey(own(msg, "id"));
    if (kind === "relay" && key === null) {
      this.#deliver(msg, extra); // a response without a usable id and without tools; the client reports it
      return;
    }
    const page = key === null ? undefined : this.#pages.get(key);
    if (page !== undefined) {
      this.#pages.delete(key as string);
      await this.#onPage(page.value, msg);
      return;
    }
    const entry = key === null ? undefined : this.#outstanding.get(key);
    if (entry === undefined) {
      this.onerror?.(new Error("dropped a response that matches no outstanding request"));
      return;
    }
    this.#outstanding.delete(key as string);
    if (kind === "handshake") {
      await this.#onInitialize(msg, extra);
      return;
    }
    if (kind === "listing") {
      const listing = this.#current;
      if (listing === null || listing.clientKey !== key) return; // abandoned or failed already
      const error = own(msg, "error");
      if (error !== undefined) {
        this.#fail(listing, "tools/list failed", error);
        return;
      }
      const result = own(msg, "result");
      if (!isObj(result)) {
        this.#fail(listing, "tools/list result is not an object");
        return;
      }
      listing.collecting = { first: result, tools: [], cursors: new Set(), pages: 0 };
      await this.#onPage(listing, msg);
      return;
    }
    this.#deliver(msg, extra);
  }

  /** Report a dropped frame, and answer the client request it matched so the client does not wait. */
  #drop(message: unknown): void {
    this.onerror?.(new Error("dropped a frame from the server that section 9.2.2 does not allow to reach the client"));
    if (!isObj(message)) return;
    const key = idKey(own(message, "id"));
    if (key === null) return;
    const page = this.#pages.get(key);
    if (page !== undefined) {
      this.#pages.delete(key);
      this.#fail(page.value, "the server answered a page request with a frame that was dropped");
      return;
    }
    const entry = this.#outstanding.get(key);
    if (entry === undefined) return;
    const current = this.#current;
    if (current !== null && current.clientKey === key) {
      this.#fail(current, "the server answered tools/list with a frame that was dropped");
      return;
    }
    this.#outstanding.delete(key);
    this.#deliver({
      jsonrpc: "2.0",
      id: own(message, "id") as RequestId,
      error: { code: -32603, message: `lock mode: the response to ${entry.value} was dropped` },
    });
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

  async #onPage(listing: Listing, message: Rpc): Promise<void> {
    const collecting = listing.collecting;
    if (this.#current !== listing || collecting === null) return;
    const error = own(message, "error");
    if (error !== undefined) {
      // A failed page means the listing failed; no earlier allow-list is used.
      this.#fail(listing, "a page request failed", error);
      return;
    }
    const result = own(message, "result");
    const tools = isObj(result) ? own(result, "tools") : undefined;
    if (!Array.isArray(tools)) {
      this.#fail(listing, "tools/list result has no tools array");
      return;
    }
    collecting.pages += 1;
    for (const t of tools) collecting.tools.push(t);
    if (collecting.pages > MAX_LIST_PAGES || collecting.tools.length > MAX_LIST_TOOLS) {
      this.#fail(listing, "listing exceeds the page or tool limit");
      return;
    }
    const cursor = isObj(result) ? own(result, "nextCursor") : undefined;
    if (typeof cursor === "string" && cursor !== "") {
      if (collecting.cursors.has(cursor)) {
        this.#fail(listing, "server repeated a cursor");
        return;
      }
      collecting.cursors.add(cursor);
      this.#seq += 1;
      const pid = `mcplock:${this.#tag}:${this.#seq}`;
      const pkey = idKey(pid) as string;
      this.#pages.set(pkey, { value: listing, at: this.#now() });
      try {
        await this.#inner.send({ jsonrpc: "2.0", id: pid, method: "tools/list", params: { cursor } } as JSONRPCMessage);
      } catch (exc) {
        this.#pages.delete(pkey);
        this.#fail(listing, `page request failed: ${(exc as Error).message}`);
      }
      return;
    }
    await this.#finish(listing, collecting);
  }

  async #finish(listing: Listing, collecting: Collecting): Promise<void> {
    const tools = collecting.tools;
    const snapshot = await this.#snapshot();
    if (this.#current !== listing) return; // abandoned or failed while the snapshot loaded
    const decision = checkListing(snapshot.lock, this.#identity, { tools, instructions: this.#served }, this.#posture);
    this.#current = null;
    this.gate.record(decision, snapshot);
    this.#lastTools = tools;
    this.#listingDue = false;
    emit(this.#sink, listingEvent(this.#events, decision, snapshot.snapshotId));
    const result = copyWithout(collecting.first, ["tools", "nextCursor"]);
    result.tools = decision.shownIndexes.map((i) => {
      const tool = tools[i];
      return decision.stripMeta.has(i) && isObj(tool) ? copyWithout(tool, ["_meta"]) : tool;
    });
    this.#deliver({ jsonrpc: "2.0", id: listing.clientId, result });
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
