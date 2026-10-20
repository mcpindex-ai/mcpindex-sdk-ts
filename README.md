# @mcp-index/sdk

The TypeScript client of [mcpindex.ai](https://mcpindex.ai) - the drift-monitored
MCP server index with an in-path trust gate for agent tool calls.

Pre-flight MCP tool-contract drift interceptor. One line - `wrap()` an MCP client
session and the gate **HOLDs a tool call before your agent acts** the moment the
tool's contract silently changes from what you pinned. In-path, on your host; no
credentials, no egress.

## Install

```sh
npm i @mcp-index/sdk
```

Peer dependency: `@modelcontextprotocol/sdk` >=1.0.0 <2 (the wrapper gates by seam name; the cap holds until the 2.x client surface is audited).

## Use

```ts
import { wrap } from '@mcp-index/sdk';

// wrap an already-connected MCP client session
const guarded = wrap(session);   // in-memory pins for this process only

// use `guarded` exactly like `session`; a drifted contract is HELD before the call
// fires. A PreflightHold surfaces (Guard/Strict) so you can route the agent to
// Review / Re-pin / Validate.
```

`wrap(session)` with no server id keeps an **in-memory** pin baseline that dies
with the process. Pass a stable server id and the baseline is kept on disk and
survives restarts, under `MCPINDEX_STATE_DIR/pins/<server id>.json` or
`~/.mcpindex/pins/<server id>.json`:

```ts
import { wrap } from '@mcp-index/sdk';

const guarded = wrap(session, { serverId: 'my-mcp-server' }); // pins on disk
```

`pinStore: 'memory'` keeps pins in the process even with a server id, and
`pinStore: 'file'` forces the file store without one. You can also pass your own
`PreflightPin` as `pin`.

### New tools on an already-pinned server

Under `guard` and `strict`, when a server you already pinned adds a tool, that
tool is left out of the list and a call to it holds. It is not trusted mid-session on
first sight. A process running as you that rewrites the pin store with its own
well-formed pins is still trusted. `onWithheld` receives the definition digest. Pin
the stored definition with `approvePending(name, digest)` when you have reviewed it:

```ts
const guarded = wrap(session, {
  serverId: 'my-mcp-server',
  onWithheld: (_server, name, _reason, digest) => {
    // review the held tool, then:
    // guarded.approvePending(name, digest);
  },
});
```

Pass `newTools: 'tofu'` to restore first-sight trust for new tools on that
wrapper.

The MCP client's own `listChanged` refresh is filtered too: `wrap()` routes the
inner client's `listTools` through the gate, so `onChanged` receives only the
tools the list would show. After a `tools/list_changed` notification, calls hold
under guard and strict until the list is read again. `wrap()` throws under guard
and strict for a client object that rejects new properties (a frozen object).

The pin records every top-level field a server lists for a tool (`title`,
`icons`, `_meta`, `execution`, and any later field) and annotation keys other
than the four hints. A change to one of them on a pinned tool leaves the tool
out under guard and strict. A pin written before 0.17.0 records those fields
once, from the first matching list. A first `outputSchema` is held the same way when it
carries any string or property name, which covers most structured output: expect
one review per tool when a server starts returning it.

With a file pin store, the wrapper also reads the server's `instructions` after
connect, pins them, and reports a first pin or a change through
`onContextDrift`. `getInstructions()` still returns what the server sent.

## Sign in (optional) - `mcpindex login`

Signs you in with GitHub and stores a free API key at `~/.mcpindex/credentials.json`
(mode `0600`), used to authenticate deeper trust checks. Optional - `wrap()` needs no
account and sends nothing on its own.

```sh
npm i -g @mcp-index/sdk   # then:
mcpindex login            # opens your browser; captures the key on a loopback listener
mcpindex login --provider google   # sign in with Google instead of GitHub (default: github)
mcpindex whoami           # shows sign-in state (never prints the key)

# or without a global install:
npx -p @mcp-index/sdk mcpindex login
```

The key is minted server-side after GitHub OAuth and handed to a one-shot HTTP listener
bound to `127.0.0.1` - it never transits a third party. Point `MCPINDEX_WEB_BASE` at a
different host to override the default (`https://mcpindex.ai`).

## What it does

- Pins each MCP tool's contract on first sight in an empty store. With a `serverId`
  (or `pinStore: 'file'`), those pins are kept on disk and survive restarts. Without
  one they stay in memory for the process only.
- Under `guard` and `strict`, a new tool on an already-pinned server is left out of
  the list until you review it (`approvePending`). `newTools: 'tofu'` restores
  first-sight trust for that wrapper.
- Runs a **deterministic** contract-diff (the ChangeKind taxonomy: added-required-param,
  constraint-narrowed, annotation-flip-to-destructive, output-schema-changed,
  type/enum/removed, ...) plus an injection/exfil marker scan over input and output schema.
- **HOLDs** the call with the mcpindex hold banner when the contract drifted; **PROCEEDs** silently
  on a benign change (no false alarm).
- Postures: `Monitor` (notify + proceed) / `Guard` (default; hold dangerous) /
  `Strict` (hold any drift).
- Grades each call's **blast radius** (Tier-0a action classification) on the verdict:
  action type (read / write / delete / send / ...), reversibility, egress, and a static
  autonomy ceiling, computed locally from the live contract. **Advisory** - it rides
  alongside the decision and never moves HOLD/PROCEED. On by default; opt out with
  `MCPINDEX_ACTION_CLASSIFICATION_ENABLED=0`.

## What it is NOT

The verdict is a **contract-diff, not a safety oracle** - it tells you the contract
*changed* versus your pin, not that the new contract is safe. It does not "block attacks"
or "guarantee safe." You decide what a HOLD means for your agent.

## Result-content scanning (opt-in, OFF by default)

Beyond the contract diff, the SDK can scan a tool's **returned result** (text blocks and
`structuredContent`) for prompt-injection / exfiltration / credential-path markers - the
attack where a *compromised result*, not a changed contract, tries to steer your agent. It
is **off by default** (zero behavior change) and enabled per-wrap:

```ts
const safe = wrap(session, { scanResults: true, onHold: (v) => { /* ... */ } });
```

Once on, a tainted result is **withheld under `Guard` / `Strict`** and **passes through
under `Monitor`** (flag-only), mirroring the contract-diff postures; an optional `onHold`
callback receives the verdict instead of throwing. Added in 0.7.0; parity with the Python
client's `wrap(..., scan_results=...)`.

## Drift telemetry (opt-in, OFF by default)

The SDK can report **that** a tool's contract drifted - so mcpindex can track drift on servers
it can't crawl itself (private / auth-gated). It is **off by default and sends nothing** unless
you turn it on:

```sh
export MCPINDEX_DRIFT_TELEMETRY=detection   # off (default) | detection | contribute
```

When enabled, each tool you pin and each contract drift sends **one one-way signal**:

- **What it sends:** fingerprints (HMAC) of the server/tool id, the contract hashes, the
  change type (the fixed ChangeKind vocabulary), a safety flag, an **hour-rounded** timestamp,
  a random install id (a token that links one machine's signals so distinct installs can be
  counted - not derived from you), and a client SDK tag (`py` or `ts`).
- **What it NEVER sends:** tool schemas, arguments, descriptions, URLs, or any of your data.
  The fingerprints carry no plaintext name and they are **not anonymity**: the salt is a
  constant in this client and the registry is public, so a listed server's fingerprint
  reverses. The payload has no free-text field by construction, and the ingest rejects
  anything that isn't the closed shape.
- **Fail-open:** telemetry never blocks, slows, or changes a tool call. Losing a signal is always
  preferred to perturbing the gate.

`detection` enables the closed signal above; `contribute` is reserved for a future, separately
opt-in richer tier (it behaves identically today). The full notice is exported as
`DRIFT_TELEMETRY_NOTICE`. Unset the variable any time to stop.

## Lock mode (`@mcp-index/sdk/lock`)

Lock mode checks every `tools/list` against an mcp.lock kept in your repository
(`.mcp/lock/` and `.mcp/contracts/`, format: mcp.lock draft 1, revision 1d). The model sees
only tools whose definition digest matches an approval, and a call to anything else is
refused with JSON-RPC error -32011 before it reaches the server. Lock mode is opt-in and
draft 1 is not stable. Nothing here runs unless you construct it, and the root
`@mcp-index/sdk` import does not load it.

Connect the official MCP client through `lockClient`:

```ts
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { FileLockStore, lockClient } from "@mcp-index/sdk/lock";
import type { Identity } from "@mcp-index/sdk/lock";

const identity: Identity = { kind: "stdio", package: "npm:@example/docs-server" };
const store = new FileLockStore({ root: process.cwd() }); // the directory that holds .mcp/
const client = new Client({ name: "my-host", version: "1.0.0" });
const transport = new StdioClientTransport({ command: "npx", args: ["-y", "@example/docs-server"] });
const locked = await lockClient(client, transport, { store, identity, posture: "guard" });

const { tools } = await client.listTools(); // approved tools only
console.log(tools.map((t) => t.name), locked.decision?.withheld);
```

`posture` is `monitor` (show everything, report what does not match), `guard` (withhold it)
or `strict` (same as guard in draft 1). Lock mode never approves a tool on first sight and
never re-pins. The lock changes only through `store.approve` and `store.revoke`, or a
reviewed edit to the lock files:

```ts
import { readFileSync } from "node:fs";

// The Tool object exactly as the server sent it, saved for review. Not an SDK-parsed copy:
// the SDK drops members it does not know, and the digest covers every member.
const tool: unknown = JSON.parse(readFileSync("review/search.json", "utf8"));
await store.approve({ identity, tool, subject: "github:you", via: "api", ref: "pr-42" });
```

The identity names the server, in one of three forms:

```ts
const remote: Identity = { kind: "remote", url: "https://mcp.example.com/v1/mcp" };
const pkg: Identity = { kind: "stdio", package: "npm:@example/docs-server" }; // npm, pypi or oci
const cmd: Identity = { kind: "stdio", command: "uvx", args: ["git+https://github.com/example/server"] };
```

`remoteIdentity`, `packageIdentity` and `commandIdentity` build them in normalized form.
`commandIdentity` throws when an argument looks like a credential.

A signed lock verifies `.mcp/lock/MANIFEST.json.sigstore` against a signer from your host
configuration. It needs the optional `sigstore` peer, a trust root file, and a sequence file
where the host keeps the highest manifest sequence it accepted, so an older signed manifest
is refused after a newer one:

```ts
const signed = new FileLockStore({
  root: "/srv/app",
  signer: {
    issuer: "https://token.actions.githubusercontent.com",
    san: "https://github.com/acme/app/.github/workflows/lock.yml@refs/heads/main",
  },
  trustedRootPath: "/etc/mcplock/trusted_root.json",
  sequencePath: "/var/lib/mcplock/sequence",
});
```

Both paths must lie outside the repository that holds the lock (the nearest directory with
a `.git` entry at or above `root`, else `root`), or the constructor throws
`HostConfigError`. A signer without a sequence store makes every load
`lock-signature-invalid`.

## Postgres lock store (`@mcp-index/sdk/lock/pg`)

`PgLockStore` keeps approvals in Postgres instead of files: append-only, hash-chained
records per tenant, with row-level security on both tables. `pg` is an optional peer.

The schema owner runs the migrations once. They are exported as SQL text:

```ts
import { writeFileSync } from "node:fs";
import { MIGRATION_SQL, ROLE_BOUND_SQL, ROLE_SQL } from "@mcp-index/sdk/lock/pg";

writeFileSync("mcplock-schema.sql", MIGRATION_SQL + ROLE_SQL);
writeFileSync("mcplock-role-bound.sql", ROLE_BOUND_SQL); // only for role-bound tenancy
// psql -v ON_ERROR_STOP=1 -f mcplock-schema.sql
```

`ROLE_SQL` creates two roles without login. `mcplock_runtime` may only read, and is what hosts
in lock mode connect as. `mcplock_approver` may also append records and move the head, and
belongs to the approval path only. Neither may update or delete a record. Grant each to its
own login, and never connect as a superuser, since a superuser bypasses row-level security:

```sql
GRANT mcplock_runtime TO host_login;
GRANT mcplock_approver TO approver_login;
```

Two tenancy modes:

- `app-scoped` (the default, `MIGRATION_SQL` alone). The store sets the tenant from the
  principal at the start of each transaction. This stops a query bug from reaching another
  tenant. It does not stop someone holding a shared login, who can set any tenant.
- `role-bound` (`ROLE_BOUND_SQL` after the other two). Each tenant gets its own logins, and
  the administrator maps each login to its tenant in `mcplock.tenant_logins`. The policies
  read the tenant from the login, so a login reaches only its own tenant. Use this before
  sharing one database between tenants that do not trust each other.

```ts
import { PgLockStore, createPgPool } from "@mcp-index/sdk/lock/pg";

const pool = await createPgPool(process.env.MCPLOCK_PG_URL ?? "postgres://host_login@127.0.0.1/app");
const store = new PgLockStore({
  pool,
  principal: { tenantId: "acme", subject: "svc:docs-host" }, // from your own auth, never a header
  tenancy: "app-scoped",
});
const snapshot = await store.loadSnapshot();
console.log(snapshot.snapshotId);
```

With `headVerifier` set, each load checks a signature over the head row, and the store must
also get a `sequenceStore`, for example `fileSequenceStore("/var/lib/mcplock/pg-sequence")`
from `@mcp-index/sdk/lock`, or every load is `lock-signature-invalid`. Without a head
signature, whoever can write the tables can rewrite the chain. Errors never carry the
connection string unredacted.

## Lock mode for the Vercel AI SDK (`@mcp-index/sdk/ai`)

Wrap the transport you hand to `createMCPClient` from `@ai-sdk/mcp` (an optional peer). The
wrapper reads the raw `tools/list` exchange, checks every tool against your mcp.lock, and the
client only ever sees approved tools, through `tools()` or `listTools()` alike:

```ts
import { createMCPClient } from "@ai-sdk/mcp";
import { Experimental_StdioMCPTransport } from "@ai-sdk/mcp/mcp-stdio";
import { lockTransport } from "@mcp-index/sdk/ai";
import { FileLockStore } from "@mcp-index/sdk/lock";
import type { Identity } from "@mcp-index/sdk/lock";

const identity: Identity = { kind: "stdio", package: "npm:@example/docs-server" };
const store = new FileLockStore({ root: process.cwd() });
const inner = new Experimental_StdioMCPTransport({ command: "npx", args: ["-y", "@example/docs-server"] });
const transport = lockTransport(inner, { store, identity, posture: "guard" });
const client = await createMCPClient({ transport });
const tools = await client.tools(); // approved tools only
console.log(Object.keys(tools));
```

A call to a withheld or unlisted tool never reaches the server. `callTool()` and the tool's
`execute()` reject with an `MCPClientError` whose `code` is -32011 and `data.reason` says why;
inside `generateText` that shows up as a `tool-error` part.

Limits:

- A digest says whether the contract changed. It says nothing about what the server does
  when a tool runs.
- The AI SDK client does not refetch on `notifications/tools/list_changed`. After an approval
  or a server change, call `tools()` again; until then the previous allow-list holds. While a
  listing is being collected, every call is refused with `no-listing`.
- A tool's top-level `_meta` is not part of its digest. It reaches the client only when it
  matches the `metaDigest` recorded at approval; otherwise, under guard, the tool is shown
  without it and the decision reports `meta-changed` or `meta-unapproved`.
- `@mcp-index/sdk/ai` imports only types from `@ai-sdk/mcp`, so loading it needs nothing at
  runtime. The `@ai-sdk/mcp` peer itself needs Node >= 22; that is the only part with that
  requirement, and the rest of the package runs on Node 20.
- The AI SDK's own transports reject any message carrying a `__proto__` key before the wrapper
  sees it, so such a listing never arrives and nothing is callable. The official SDK transports
  pass it through and the lock withholds the tool. Instructions given to the client as
  `initialInitializeResult` never cross the transport and are not checked.

## Related packages

Three ways to bring mcpindex into an agent, for different surfaces:

| Package | Install | What it does |
| --- | --- | --- |
| **`@mcp-index/sdk`** *(this package)* | `npm i @mcp-index/sdk` | In-path drift gate: `wrap()` an MCP session and HOLD a call when a tool's contract drifts from your pin. |
| **`mcp-server-mcpindex`** | `npm i -g mcp-server-mcpindex` | Directory + advisory screen as an MCP server: find servers by task, and `check_tool_trust` before a call. |
| **`@mcp-index/mastra`** | `npm i @mcp-index/mastra` | The advisory screen wired into Mastra as a `beforeToolCall` hook (warn / enforce). |

**Drift gate vs advisory screen:** this package asks a local question - "did this tool's contract change since I pinned it?" (no network verdict). The other two ask mcpindex "has this tool been vetted?" They are complementary, and none depends on another.

## License

PolyForm Noncommercial 1.0.0 - (c) Bhartis LLC. Free for noncommercial use; commercial use
requires a separate license. See [`LICENSE`](./LICENSE) and https://mcpindex.ai.
