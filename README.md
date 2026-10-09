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
const guarded = wrap(session);   // pins each tool's contract on first use (TOFU)

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

- Pins each MCP tool's contract trust-on-first-use (TOFU), persisted across restarts.
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
