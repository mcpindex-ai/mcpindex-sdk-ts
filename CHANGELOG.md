# Changelog - @mcp-index/sdk

All notable changes to the TypeScript SDK. Versioning is semver (0.x: minor =
additive feature, patch = fix). Backward-compatible additions only in 0.2.0.

## [Unreleased]

## 0.15.0 - 2026-10-05

### Changed

- Under guard and strict, a tool whose description or input-schema text changed is left out of the tool list, and a call to that tool holds until it is reviewed.
- Monitor still shows the full list.
- When you pass a `serverId`, pins are kept on disk by default, under `MCPINDEX_STATE_DIR/pins/<server id>.json` or `~/.mcpindex/pins/<server id>.json`, and survive a restart. Without a `serverId` they stay in memory, as before, so unnamed sessions never share a pin file. `pinStore: "memory"` or `pinStore: "file"` overrides either default.
- These fields are not yet covered, so a change in only one of them still reaches the host: tool title, icons, _meta, annotations.title, a new annotation key, and first-time outputSchema text on an otherwise unchanged tool.
- The SDK client's listChanged refresh calls the inner client, so that refresh is not filtered.
- A list longer than 2,000 tools, or a list the gate cannot filter, comes back with every tool left out. It does not throw.

## 0.14.1 - 2026-10-04

### Security

- Fixes GHSA-g737-65vx-q7qm (https://github.com/mcpindex-ai/mcpindex-sdk-ts/security/advisories/GHSA-g737-65vx-q7qm), cases where a changed tool contract was treated as unchanged or auto-accepted. Affected: @mcp-index/sdk < 0.14.1 and mcpindex-gate < 0.16.1.

### Changed

- Some changes that used to auto-accept now hold for review.
- Tool hashes for existing pins are unchanged.

## 0.14.0 - 2026-10-02

### Changed

- Guard now holds a newly header-mirrored parameter, and users who want the old behaviour can run monitor.

## 0.13.1 - 2026-10-01

### Changed

- Source moved to https://github.com/mcpindex-ai/mcpindex-sdk-ts. This release
  is built from that public repository and carries an npm provenance attestation.
  No SDK behavior changed.

## 0.13.0 - 2026-09-30

### Added

- **Context-surface `ChangeKind`s.** `instructions-added`, `instructions-removed`,
  `instructions-changed`, `instructions-numeric`, `prompt-added`, `prompt-removed`,
  `prompt-description-changed`, `prompt-args-changed`, with safety bits mirroring the
  Python `_SAFETY_RELEVANT` set. These describe server-scoped drift the ledger now
  carries; the classifier stays Python-only and `classifyChange` is unchanged.
- **`contextFp(serverId)`**, for cross-language parity with the Python `context_fp`. No
  client mints it.

### Corrected

- **A fingerprint is not anonymity.** The README, the consent text and the notice said
  "salted fingerprints" and listed names among what is never sent, which reads as
  anonymity. The salt is a constant in this client and the registry is public, so a listed
  server's fingerprint reverses. The copy now says so.
- **The off-switch.** The notice said to unset `MCPINDEX_DRIFT_TELEMETRY`; after a
  `mcpindex-config-wire` install that is not enough. It now names
  `mcpindex-config-wire wire --repin --drift-telemetry off`.

<!-- correction-marker: numeric-drift-denominator -->

- **The 0.3.0 note's "buried roughly 20:1" describes one publisher's fleet, not the
  registry.** That entry justified splitting `description-numeric` off `description-only`
  with "94.8% of description changes (88,564 of 93,419 tool pairs) move only digits" and
  "a genuine edit was buried roughly 20:1". Both figures are arithmetically right and the
  denominator is not the ecosystem. Re-measured 2026-08-24 on the same corpus:
  `io.github.pipeworx-io` supplies 90,101 of the 93,419 pairs (96.4%) and 88,036 of the
  88,564 numeric-only ones (99.4%). Excluding that fleet, 528 of 3,318 pairs across the
  other 415 publishers are numeric-only, which is 15.9%.

  The burial ratio does not soften, it reverses. Whole corpus 88,564 numeric against 4,855
  genuine is 18.2:1; the fleet alone is 42.6:1; **excluding the fleet, genuine edits
  outnumber numeric churn 5.3 to 1**. So for a client not wired to that fleet, the original
  sentence is backwards.

  **The 0.3.0 entry is left as published.** A changelog records what a release said when it
  shipped, and amending a dated entry is worse than superseding it. Nothing about the kind
  itself changes: it still states a fact rather than a clearance, and the gate's description
  HOLD is byte-exact and kind-independent, so no verdict moves either way. What is corrected
  is the stated reason. The split earns its keep for clients exposed to a high-churn
  publisher, where the 42.6:1 is real and is what they experience; it is not a property of
  the public registry.

### Audited

- **2026-08-18, against the 2.x client stack.** `@modelcontextprotocol/sdk` has no
  2.x; the 2026-07-28-era client ships as a separate package,
  `@modelcontextprotocol/client` 2.0.0. The wrapper was audited against it:
  `callTool` and `request({method:'tools/call'})` are gated (the Protocol base
  keeps `request` public, so that seam is live), `transport`/`send` stay denied,
  and 2.0.0 REMOVED `requestStream` and the whole `experimental.tasks` surface -
  the wrapper's seams for those are inert there, not bypassed. The only wire
  method that executes a tool in the 2.0.0 registry remains `tools/call` (tasks
  augment it; they do not replace it). The `<2` peer cap on the sdk package
  stands because no sdk 2.x exists to audit installs against, not because the
  wrapper fails on the new stack.

## 0.12.1 - 2026-08-17

### Changed

- **`@modelcontextprotocol/sdk` peer range capped at `<2`** (was `>=1.0.0`,
  unbounded across the major). The wrapper gates by seam NAME (`listTools`,
  `callTool`, `request`, `requestStream`, the `experimental` accessor); an SDK
  2.x that renames or relocates any of them would turn the `Proxy` into a
  transparent pass-through - a silent gate bypass with no error. The other two
  published packages were already capped below 2. Lift the cap only after the
  wrapper's seams are audited against the actual 2.x client surface.

## 0.11.0 - 2026-08-11

**A description change that moves only digits now carries its own ChangeKind.**
`description-numeric` splits off `description-only`.

Minor, not patch, because it is observable for consumers: an event that used to be
labelled `description-only` is now labelled `description-numeric` whenever the two
descriptions differ only in digit runs. Anything filtering on `description-only` will
see far fewer events - measured across 30 daily snapshots of the public registry,
94.8% of description changes (88,564 of 93,419 tool pairs) move only digits, because
vendors template a counter or a timestamp into the description and it re-renders on
every crawl. A genuine edit was buried roughly 20:1.

**Nothing new is surfaced and no verdict changed.** Neither description kind is
surfaceable, and the gate's description HOLD is byte-exact and kind-independent, so a
numeric-only change still HOLDs exactly as before. The new kind states a FACT ("only the
numbers moved"), never a clearance: a moved price, port, IP or limit is numeric too.

**The HOLD text now says which one you have.** The reason and banner append "only the
embedded numbers moved, the prose is identical" when that is true, so you are not
eyeball-diffing two long strings to find out. The existing wording is appended to, never
rewritten, because GUARD matches the substring "DESCRIPTION changed".

Masking is ASCII-only (`[0-9]`) and does not touch whitespace, deliberately: Python's
`\d` matches Unicode decimal digits and JavaScript's never does, and JS `\s` matches
U+FEFF while Python's does not. Either divergence would make the crawler and the gate
in your agent describe one event differently. Pinning both to `[0-9]` changes zero
classifications on the measured corpus.

New export: `isNumericOnlyDescriptionChange(before, after)`.

## 0.10.0 - 2026-08-05

**The HOLD text an agent reads is now separate from the one a human reads.** Behaviour
change on a shipped surface: `PreflightHold.message` (and the proxy's JSON-RPC error
`message`) no longer carry the brand banner.

Why: on 2026-08-05 a frontier model met a real HOLD, classified the banner as a
prompt-injection attempt, refused to act on it, retried the held call, and told the user
something suspicious was intercepting its tools. Its load-bearing objection was not tone -
it could not verify us. The gate diffs the pin against the LIVE contract while the agent
sees only its own cached tool list, a third view that legitimately disagrees. We were
asserting a change the reader could not observe and then inviting it to act, which is the
shape of a manipulation attempt. Refusing was correct behaviour.

- **Added** `renderHoldMessage()` - the agent-facing text. Renders the drift as an evidence
  block (tool / change + path / effect / call sent), names the stale-tool-list mismatch
  before the agent trips over it, and states the disposition without inviting any action.
- **Added** `PreflightHold.presentation` - the human brand banner, kept off `message`.
  `String(err)` is what a builder is most likely to hand to a model.
- **Unchanged** `renderHoldBanner()` and `holdBanner()` - same text, same meaning, for
  humans and hosts.
- **Security:** the agent-facing message may only CONSTRAIN. `[Review | Re-pin | Validate]`
  invited the reader toward `repin()` - the one action that makes a changed contract the
  new trusted baseline - on a channel the agent must treat as attacker-controlled. That is
  the text an attacker would forge; forging "stop and ask your human" earns them nothing.
- **Security:** no defence was traded away to get there. `mdText` escaping and
  `redactGreenWords` now run per untrusted value rather than over the whole render, so they
  can only touch attacker-derived spans. Values are truncated before escaping
  (`VALUE_CHAR_CAP`), closing an unbounded-render vector a security audit measured at 5.2 MB
  from a 1.6 MB hostile tool name.
- **Fixed** (audit HIGH) `holdBanner()` fell through to the full detail banner when the
  provenance choke refused or on an internal-error verdict - asserting a specific contract
  change that, in the latter case, never happened. It now returns the generic notice, as
  Python always did.
- **Fixed** evidence rows sort by codepoint, not `localeCompare`, so the two SDKs cannot
  render different evidence for identical drift.

## 0.9.2 - 2026-07-29

Copy only, no behaviour change.

- README opens with a link to [mcpindex.ai](https://mcpindex.ai) and names the
  category ("drift-monitored MCP server index"). The live npm page previously had
  no mcpindex.ai link above the fold; the package pages rank for discovery queries
  the domain does not yet, so they should funnel there.
- `package.json` description likewise names mcpindex.ai + the category; added
  `mcpindex` keyword. Lockfile version resynced (was stale at 0.7.0).

## 0.9.1 - 2026-07-18

### Fixed
- **`wrap(session)` now works with no options - the README quickstart is honest
  again.** `pin` and `serverId` are now OPTIONAL: when omitted, `wrap()` creates an
  ephemeral in-memory `PreflightPin()` under the new `DEFAULT_SERVER_ID` ("mcp") and
  pins each tool trust-on-first-use. Previously `wrap(session)` threw
  `TypeError: Cannot read properties of undefined (reading 'pin')`, and
  `wrap(session, { scanResults: true, onHold })` (no pin/serverId) HELD **every** call
  with the internal-error banner. Security posture is unchanged: a missing pin
  pins-on-first-use (TOFU) and HOLDs on drift - it never fails open. Pass an explicit
  `{ pin, serverId }` for a durable/shared baseline or fleet telemetry.
- Exported `DEFAULT_SERVER_ID` for callers that want to reference the default pin
  namespace explicitly.

## 0.9.0 - 2026-07-14

### Added
- **`mcpindex login` CLI.** New `mcpindex` bin with `login` / `whoami`. `login` opens
  the browser for GitHub OAuth (`read:user` only), captures the server-minted free API
  key on a one-shot loopback listener bound to `127.0.0.1`, and stores it at
  `~/.mcpindex/credentials.json` (`0600`, atomic write, never through a symlink). The
  callback is bound to a per-session nonce carried in the loopback path (closes
  key-fixation); the key never transits a third party. `MCPINDEX_WEB_BASE` overrides the
  default host. `whoami` reports sign-in state without ever printing the key.
- **`--provider github|google`** on `mcpindex login` (default `github`) - selects the
  identity provider; the loopback/nonce handoff is provider-agnostic.

## 0.7.0 - 2026-07-12

### Added
- **Result-content scanning (`scanResults`).** New opt-in gate that scans tool
  RESULT content - text blocks and `structuredContent` - for prompt-injection,
  exfiltration, and credential-path markers, giving TS parity with the Python
  client. **Default OFF** (zero behavior change): a hostile result passes through
  untouched unless enabled. When ON, a tainted result is WITHHELD under `GUARD`/
  `STRICT`, PROCEEDS under `MONITOR`, and an optional `onHold` callback receives
  the withhold verdict instead of throwing. Cross-engine line-terminator
  normalization (CR/CRLF -> LF) so a `SYSTEM:` injection can't hide behind a bare
  carriage return.

### Fixed
- **Scan hardening (three review rounds).** Location paths are sanitized (no raw
  key characters leak into a finding); marker counting is by Unicode code point
  (astral-plane / emoji parity with Python); Unicode-whitespace parity (e.g.
  NBSP-prefixed `SYSTEM:` is caught); cyclic or malformed `structuredContent`
  never throws and is flagged `truncated` under depth/count bounds; a marker past
  the scan cap is missed-but-flagged rather than silently dropped; a benign
  `resource_link` URI is no longer a false positive; the scan budget is shared
  across `content[]` + structured so a large result can't evade the cap.

## 0.6.1 - 2026-06-11

### Added
- **Read-only `lookup` telemetry mode.** `MCPINDEX_DRIFT_TELEMETRY` gains `lookup`
  (vocabulary is now `off | lookup | detection | contribute`). `lookup` RECEIVES fleet
  drift warnings (the salted-fingerprint query) while SENDING nothing - the gate splits the
  former single switch into `readEnabled()` (any non-off mode) and `sendEnabled()`
  (detection/contribute only), with a re-check at the enqueue boundary. Cross-language
  parity with the Python client. Default stays `off` (zero egress).

### Changed
- **Consent notice completeness.** `DRIFT_TELEMETRY_NOTICE` (and the README "What it sends"
  list) now name the `sdk` tag (`py`/`ts`) that the wire payload already includes, and
  document `lookup` as low-egress (not zero-egress). Kept byte-identical to the Python notice.

## 0.6.0 - 2026-06-09

### Added
- **Fleet drift query (M3, "warns you on call 1").** On first pin the gate fire-and-forgets a
  query to the public fleet; if a tool's contract has CORROBORATED drift for others (the central
  crawl saw it, or >=2 installs did), the verdict carries a `fleetAdvisory` so you're warned
  *before* the tool drifts on you. Opt-in (same `MCPINDEX_DRIFT_TELEMETRY` gate; the queried
  fingerprint is the one already emitted), fail-open, AD-6-safe (never moves PROCEED/HOLD;
  redirects hard-off). Exported: `driftQuery`, `FleetAdvisory`; surfaced by `renderVerdict`.

## 0.5.0 - 2026-06-09

### Added
- **Drift telemetry (M1, opt-in, OFF by default).** On a tool pin or a contract drift the
  gate can emit one one-way signal - salted (HMAC) fingerprints of the server/tool id, the
  contract hashes, the change type, a safety flag, an hour-rounded time, and a random install
  id. Never a schema, argument, description, URL, or server/tool name. Enable with
  `MCPINDEX_DRIFT_TELEMETRY=detection`; fail-open (never blocks or changes a tool call). The
  consent string is exported as `DRIFT_TELEMETRY_NOTICE`.

### Docs
- README "What it does" now documents the default-on blast-radius grade (Tier-0a action
  classification) shipped in 0.4.0, with the `MCPINDEX_ACTION_CLASSIFICATION_ENABLED=0`
  opt-out. (0.4.0 published before the README caught up.)

## 0.4.0 - 2026-06-08

### Added
- **Local Tier-0a action classification (blast radius).** The gate now COMPUTES the
  advisory `actionClassification` block locally from the live tool definition - action
  type, resource, side-effect, reversibility, egress, and a static autonomy ceiling -
  instead of leaving it `null` until a hosted verdict supplied one. So the blast-radius
  grade is on by default in the SDK, at parity with the Python `mcpindex-gate`
  client. Default-on; opt out with `MCPINDEX_ACTION_CLASSIFICATION_ENABLED=0`. Pure,
  deterministic, total, and a byte-for-byte port of the Python `cse.action_class.classify`
  (12-case cross-language golden parity test). **Advisory only** - it rides alongside the
  decision and never moves `PROCEED`/`HOLD` (AD-1). New exports: `classifyAction`,
  `classifyToolDef`, `actionClassificationEnabled`, and the `ActionType` /
  `SideEffectClass` / `Reversibility` / `Egress` / `ScopeHint` / `PatternShape` /
  `AutonomyCeiling` / `NoteClass` / `Severity` / `EvidenceRefType` enums.

## 0.3.2 - 2026-06-08

### Fixed
- **Schema-content scanner no longer false-flags benign URLs** - the exfil tripwire
  (`scanSchemaHasMarker`) had a bare `https?://` rule that flagged any URL in a tool's
  declared schema as a CRITICAL exfil marker. A real crawl tripped it on a benign
  `web_url_reader` whose `url` param carried example URLs. A URL now signals exfil only
  in an exfil-verb context (`forward ... https://...`); example/doc URLs are clean.
  Credential-path and injection detection unchanged. Mirrors the Python `schema_scan` fix.

## 0.3.1 - 2026-06-08

### Changed
- **Ambient line reworded `watching` -> `noted`** - `mcpindex | noted <server>/<tool> - ...`.
  The previous "watching" read like surveillance *of the user*; "noted" frames it as
  mcpindex quietly keeping track on your behalf. Copy-only; behavior identical.

## 0.3.0 - 2026-06-08

### Added
- **Ambient presence (default-on).** A subtle, low-frequency `mcpindex | watching
  <server>/<tool>` line on the gate's PROCEED path so a user remembers mcpindex is
  working - first-touch per tool (one line per distinct tool, silent on repeats) plus a
  once-per-session summary. New `onInvocation` option on `wrap()` lets an integrator
  render the signal in their own UI. The first line carries `(silence:
  MCPINDEX_AMBIENT_NOTICE=off)` so the off-switch is always discoverable; cadence tunes
  via `MCPINDEX_AMBIENT_NOTICE_MODE` (first_touch | summary | every | off); auto-quiet in
  CI / under `DO_NOT_TRACK`.
- Safe by construction: writes **only** to stderr + the observer, **never stdout** (the
  JSON-RPC channel); makes no network call, persists nothing, and never changes a gate
  decision or a tool call's result (a HOLD emits nothing; a broken notifier is swallowed).
  New `ambient.ts` + 12 tests (incl. a stdout-stays-empty channel-safety assertion).

## 0.2.0 - 2026-06-07

### Added
- **`actionClassification` on `PreflightVerdict`** - the read-side mirror of the
  server's Tier 0a advisory action-classification block: the *blast radius* of a tool
  call (action type, resource, side-effect, reversibility, egress, and a static
  autonomy ceiling). New exported `ActionClassification` type. Lets TS/JS consumers
  read the block off a verdict.
  - **Advisory only** - it rides *alongside* the decision and never alters
    `PROCEED`/`HOLD` (`isProceed` reads only `decision`).
  - **Read-side only in this release** - the SDK does **not** yet *compute* the block
    locally; the field is populated from a server/hosted verdict, else `null`. The
    local `classify()` port lands with the in-process interceptor (deferred).
  - **Backward-compatible** - the field defaults to `null` in `makeVerdict`, so existing
    consumers are unaffected. The nested block uses the snake_case wire keys (the server
    JSON contract); the envelope stays camelCase.

### Notes
- No breaking changes. No new runtime dependencies. `node >= 20`.
- Wire-contract parity with the Python `model_dump` payload is enforced by the test
  suite (`parity.test.ts`).

## 0.1.0

- Initial release: pre-flight MCP tool-contract drift interceptor - `wrap()` over an
  MCP client session that HOLDs a tool call when the contract drifted from your pin.
  No credential handling.
