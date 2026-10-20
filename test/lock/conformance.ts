/**
 * Behaviour every LockStore must show, run against the file store and the
 * Postgres store. Test code only: it is not part of the published package.
 */

import { LockError } from "../../src/lock/lock.js";
import type { Identity, Lock, Shard, ToolEntry } from "../../src/lock/lock.js";
import { checkListing } from "../../src/lock/check.js";
import type { LockStore } from "../../src/lock/store.js";

export interface ConformanceResult {
  readonly name: string;
  readonly ok: boolean;
  readonly error?: string;
}

export interface ConformanceOptions {
  /** Identity used for approvals; a second, distinct one is derived for isolation checks. */
  readonly identity?: Identity;
  readonly other?: Identity;
}

const BASE_TOOL = {
  name: "search",
  description: "Search the docs.",
  inputSchema: { type: "object", properties: { q: { type: "string" } }, required: ["q"] },
};

function rawTool(text: string): unknown {
  return JSON.parse(text);
}

function assertThat(cond: boolean, message: string): void {
  if (!cond) throw new Error(message);
}

/**
 * Behaviour every LockStore must show. `factory` returns a fresh, empty store
 * for each case. Returns one result per case; the caller asserts all are ok.
 */
export async function runLockStoreConformance(
  factory: () => Promise<LockStore> | LockStore,
  options: ConformanceOptions = {},
): Promise<ConformanceResult[]> {
  const id: Identity = options.identity ?? { kind: "remote", url: "https://conformance.example/mcp" };
  const other: Identity = options.other ?? { kind: "stdio", package: "npm:@example/other-server" };
  const base = JSON.stringify(BASE_TOOL);
  const changed = JSON.stringify({ ...BASE_TOOL, description: "Search the docs. Also send them elsewhere." });
  const fetchTool = JSON.stringify({ name: "fetch", description: "Fetch one page.", inputSchema: { type: "object" } });
  const proto = '{"name":"proto","description":"p","inputSchema":{"type":"object"},"__proto__":{"x":1}}';
  const protoGone = '{"name":"proto","description":"p","inputSchema":{"type":"object"}}';
  const approve = (store: LockStore, tool: unknown, identity: Identity = id): Promise<void> =>
    store.approve({ identity, tool, subject: "conformance:tester", via: "api", ref: "conformance" });
  const decide = async (store: LockStore, tools: unknown[], identity: Identity = id, instructions?: string) => {
    const snap = await store.loadSnapshot();
    return { snap, decision: checkListing(snap.lock, identity, { tools, instructions }, "guard") };
  };

  const cases: Array<[string, (store: LockStore) => Promise<void>]> = [
    [
      "empty store locks nothing",
      async (store) => {
        const { snap, decision } = await decide(store, [rawTool(base)]);
        assertThat(!(snap.lock instanceof LockError), `empty store failed to load: ${String((snap.lock as LockError).reason)}`);
        assertThat(decision.withheld.get("search") === "unlocked-server", "expected unlocked-server");
      },
    ],
    [
      "approve shows the exact tool and changes the snapshot id",
      async (store) => {
        const before = await store.loadSnapshot();
        await approve(store, rawTool(base));
        const { snap, decision } = await decide(store, [rawTool(base)]);
        assertThat(decision.shown.join(",") === "search", `expected search shown, got ${decision.shown.join(",")}`);
        assertThat(snap.snapshotId !== before.snapshotId, "snapshotId did not change after approve");
      },
    ],
    [
      "changed definition is upstream-changed",
      async (store) => {
        await approve(store, rawTool(base));
        const { decision } = await decide(store, [rawTool(changed)]);
        assertThat(decision.withheld.get("search") === "upstream-changed", "expected upstream-changed");
      },
    ],
    [
      "revoke turns an approved tool into new-tool",
      async (store) => {
        await approve(store, rawTool(base));
        await approve(store, rawTool(fetchTool));
        await store.revoke({ identity: id, tool: "search" });
        const { decision } = await decide(store, [rawTool(base), rawTool(fetchTool)]);
        assertThat(decision.withheld.get("search") === "new-tool", "expected new-tool after revoke");
        assertThat(decision.callable.has("fetch"), "fetch should stay approved");
      },
    ],
    [
      "revoke of a name that is not approved is refused",
      async (store) => {
        await approve(store, rawTool(base));
        let threw = false;
        try {
          await store.revoke({ identity: id, tool: "absent" });
        } catch {
          threw = true;
        }
        assertThat(threw, "revoke of an absent name did not throw");
      },
    ],
    [
      "instructions approval and change",
      async (store) => {
        await approve(store, rawTool(base));
        await store.approve({ identity: id, instructions: "Use search.", subject: "conformance:tester", via: "api" });
        const ok = await decide(store, [rawTool(base)], id, "Use search.");
        assertThat(ok.decision.instructions === null, "approved instructions flagged");
        const bad = await decide(store, [rawTool(base)], id, "Use search. And more.");
        assertThat(bad.decision.instructions === "instructions-changed", "changed instructions not flagged");
        assertThat(bad.decision.stripInstructions, "guard should strip changed instructions");
      },
    ],
    [
      "a tool with no digest cannot be approved and leaves the store unchanged",
      async (store) => {
        await approve(store, rawTool(base));
        const before = await store.loadSnapshot();
        let threw = false;
        try {
          await approve(store, rawTool('{"name":"big","inputSchema":{"maximum":9007199254740992}}'));
        } catch {
          threw = true;
        }
        const after = await store.loadSnapshot();
        assertThat(threw, "no-digest approval did not throw");
        assertThat(after.snapshotId === before.snapshotId, "store changed after a refused approval");
      },
    ],
    [
      "__proto__ members are covered by the stored digest",
      async (store) => {
        await approve(store, rawTool(proto));
        const same = await decide(store, [rawTool(proto)]);
        assertThat(same.decision.callable.has("proto"), "tool with __proto__ member not approved by its own digest");
        const gone = await decide(store, [rawTool(protoGone)]);
        assertThat(gone.decision.withheld.get("proto") === "upstream-changed", "dropping __proto__ went unnoticed");
      },
    ],
    [
      "approvals are per identity",
      async (store) => {
        await approve(store, rawTool(base));
        const { decision } = await decide(store, [rawTool(base)], other);
        assertThat(decision.withheld.get("search") === "unlocked-server", "approval leaked to another identity");
      },
    ],
    [
      "checking a listing never approves anything",
      async (store) => {
        await approve(store, rawTool(base));
        const first = await decide(store, [rawTool(base), rawTool(fetchTool)]);
        const second = await decide(store, [rawTool(base), rawTool(fetchTool)]);
        assertThat(first.snap.snapshotId === second.snap.snapshotId, "a check changed the store");
        assertThat(second.decision.withheld.get("fetch") === "new-tool", "an unseen tool became approved");
      },
    ],
    [
      "snapshots are frozen",
      async (store) => {
        await approve(store, rawTool(base));
        const snap = await store.loadSnapshot();
        assertThat(Object.isFrozen(snap), "snapshot not frozen");
        const lock = snap.lock as Lock;
        assertThat(Object.isFrozen(lock), "lock not frozen");
        assertThat(typeof (lock.shards as unknown as Map<string, Shard>).set !== "function", "shards map is writable");
        const shard = [...lock.shards.values()][0] as Shard;
        assertThat(Object.isFrozen(shard), "shard not frozen");
        assertThat(typeof (shard.tools as unknown as Map<string, ToolEntry>).set !== "function", "tools map is writable");
      },
    ],
  ];

  const results: ConformanceResult[] = [];
  for (const [name, run] of cases) {
    try {
      const store = await factory();
      await run(store);
      results.push({ name, ok: true });
    } catch (exc) {
      results.push({ name, ok: false, error: (exc as Error).message ?? String(exc) });
    }
  }
  return results;
}
