/**
 * `@mcp-index/sdk/ai`: lock mode for the Vercel AI SDK MCP client
 * (`createMCPClient` from `@ai-sdk/mcp`).
 *
 * The AI SDK client parses `tools/list` with its own zod schema and builds
 * tools from what is left, so a digest over `client.listTools()` would not be
 * a digest over what the server sent. lockTransport wraps the transport the
 * client is given and works on JSON-RPC messages before the client sees them.
 * The message work is LockedTransport from `../lock/rawList.ts`: every page of
 * a listing is collected under private ids and digested raw, withheld tools
 * are dropped, and the client gets one result with no cursor. `client.tools()`
 * and `client.listTools()` + `toolsFromDefinitions()` both only ever see
 * approved tools (under guard).
 *
 * Every `tools/call` is checked against the allow-list from the latest
 * complete listing. A refused call is never sent; the client gets a JSON-RPC
 * -32011 error with data.reason. In @ai-sdk/mcp 2.0.74 that rejects
 * `callTool()` and the tool's `execute()` with an MCPClientError carrying
 * code -32011 and data { reason, tool }; it is not retried (the client never
 * retries an error with a JSON-RPC code). Inside generateText the throw
 * becomes a `tool-error` part, so the model sees the refusal as a tool error.
 *
 * Limits, all from the AI SDK client as of 2.0.74:
 *   - The client treats any server notification as "Unsupported message
 *     type" and reports it to onUncaughtError, so it never refetches on
 *     `notifications/tools/list_changed`. The wrapper still marks a listing
 *     as due (`listingDue`) and keeps the old allow-list until a new complete
 *     listing. The app has to call `tools()` again to see newly approved
 *     tools, and to drop ones the server removed.
 *   - The wrapper reports `supportsProtocolVersionDiscovery = false`, so the
 *     client uses the `initialize` handshake. Server instructions then arrive
 *     in the initialize result, where they are digested and, under guard,
 *     stripped when they differ from the lock. Instructions passed to the
 *     client as `initialInitializeResult` never cross the transport and are
 *     not checked.
 *   - The AI SDK's own stdio, SSE and HTTP transports parse with a secure
 *     JSON parser that throws on a `__proto__` key. Such a message never
 *     reaches the wrapper, so there is no listing and no tool is callable;
 *     the official SDK transports keep the key and the lock withholds the tool.
 *   - `@ai-sdk/mcp` needs Node >= 22. This module itself only imports types
 *     from it.
 *
 * The check covers the tool contract the model reads, and nothing about what
 * the server does when a tool runs.
 */

import type {
  JSONRPCMessage,
  MCPTransport,
  MCPTransportCloseOptions,
  MCPTransportSendOptions,
} from "@ai-sdk/mcp";
import type { Transport, TransportSendOptions } from "@modelcontextprotocol/sdk/shared/transport.js";
import type { JSONRPCMessage as SdkMessage } from "@modelcontextprotocol/sdk/types.js";

import type { CallGate, Decision } from "./lock/check.js";
import type { LockEventSink } from "./lock/events.js";
import type { Identity, Posture } from "./lock/lock.js";
import { LockedTransport } from "./lock/rawList.js";
import type { LockOptions } from "./lock/rawList.js";
import type { LockStore } from "./lock/store.js";

/** Host settings that are not about which lock or which server. */
export interface AiLockHostConfig {
  /** The host name written into events. Default "mcpindex-sdk". */
  readonly host?: string;
  /** Age after which a call reloads the snapshot. Default 60 s. */
  readonly maxStalenessMs?: number;
  readonly now?: () => number;
}

export interface AiLockOptions {
  readonly store: LockStore;
  /** This server's identity (section 3), from host configuration. */
  readonly identity: Identity;
  /** monitor, guard, or strict (behaves as guard in draft 1). */
  readonly posture: Posture;
  readonly sink?: LockEventSink;
  readonly hostConfig?: AiLockHostConfig;
}

/**
 * Adapts an AI SDK MCPTransport (or an official SDK transport, which has the
 * same shape) to the Transport that LockedTransport drives.
 */
class InnerAdapter implements Transport {
  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: <T extends SdkMessage>(message: T) => void;
  closeOptions: MCPTransportCloseOptions | undefined;

  constructor(readonly inner: MCPTransport) {}

  async start(): Promise<void> {
    this.inner.onmessage = (message: JSONRPCMessage) => this.onmessage?.(message as unknown as SdkMessage);
    this.inner.onerror = (error: unknown) => this.onerror?.(error instanceof Error ? error : new Error(String(error)));
    this.inner.onclose = () => this.onclose?.();
    await this.inner.start();
  }

  async send(message: SdkMessage, options?: TransportSendOptions): Promise<void> {
    const m = message as unknown as JSONRPCMessage;
    if (options === undefined) await this.inner.send(m);
    else await this.inner.send(m, options as MCPTransportSendOptions);
  }

  async close(): Promise<void> {
    const options = this.closeOptions;
    if (options === undefined) await this.inner.close();
    else await this.inner.close(options);
  }

  setProtocolVersion(version: string): void {
    if (typeof this.inner.setProtocolVersion === "function") this.inner.setProtocolVersion(version);
    else this.inner.protocolVersion = version;
  }
}

export class AiLockTransport implements MCPTransport {
  /** Forces the initialize handshake, where instructions are checked. */
  readonly supportsProtocolVersionDiscovery = false;
  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: (message: JSONRPCMessage) => void;

  readonly #adapter: InnerAdapter;
  readonly #locked: LockedTransport;

  constructor(inner: MCPTransport, options: AiLockOptions) {
    const { hostConfig, ...rest } = options;
    // hostConfig goes first so it cannot replace store, identity or posture.
    // Any key the core refuses (autoAccept, tofu, repin, ...) at either level
    // reaches the LockedTransport constructor and throws there.
    const lockOptions = { ...(hostConfig ?? {}), ...rest } as LockOptions;
    this.#adapter = new InnerAdapter(inner);
    this.#locked = new LockedTransport(this.#adapter, lockOptions);
  }

  get supportsMcpToolParameterHeaders(): boolean | undefined {
    return this.#adapter.inner.supportsMcpToolParameterHeaders;
  }

  get protocolVersion(): string | undefined {
    return this.#adapter.inner.protocolVersion;
  }

  set protocolVersion(version: string | undefined) {
    if (version !== undefined) this.#adapter.setProtocolVersion(version);
  }

  setProtocolVersion(version: string): void {
    this.#adapter.setProtocolVersion(version);
  }

  /** The per-connection allow-list. */
  get gate(): CallGate {
    return this.#locked.gate;
  }

  /** The decision for the latest complete listing, or null before one. */
  get decision(): Decision | null {
    return this.#locked.decision;
  }

  /** True after list_changed until the next complete listing (call tools() again). */
  get listingDue(): boolean {
    return this.#locked.listingDue;
  }

  async start(): Promise<void> {
    this.#locked.onmessage = (message) => this.onmessage?.(message as unknown as JSONRPCMessage);
    this.#locked.onerror = (error) => this.onerror?.(error);
    this.#locked.onclose = () => this.onclose?.();
    await this.#locked.start();
  }

  async send(message: JSONRPCMessage, options?: MCPTransportSendOptions): Promise<void> {
    await this.#locked.send(message as unknown as SdkMessage, options as TransportSendOptions | undefined);
  }

  async close(options?: MCPTransportCloseOptions): Promise<void> {
    this.#adapter.closeOptions = options;
    await this.#locked.close();
  }
}

/**
 * Wrap `inner` in lock mode for `createMCPClient({ transport })`.
 * Lock mode has no auto-accept, first-use pin or re-pin; the lock changes
 * only through LockStore.approve and revoke.
 */
export function lockTransport(inner: MCPTransport, options: AiLockOptions): AiLockTransport {
  return new AiLockTransport(inner, options);
}
