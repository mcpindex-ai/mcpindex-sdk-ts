/**
 * Postgres LockStore. Runs only against a local throwaway database named by
 * MCPLOCK_TEST_PG_URL (a superuser URL for that scratch instance, for example
 * a postgres:16 container on 127.0.0.1). The test creates the schema, the two
 * roles and two login users with random passwords, then connects as those
 * users, so row-level security and grants are exercised as in production.
 * It refuses to run against anything but localhost. The role-bound test makes
 * its own scratch database, since it replaces the policies, and drops it.
 */

import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import test from "node:test";

import {
  MIGRATION_SQL,
  PgLockStore,
  ROLE_BOUND_SQL,
  ROLE_SQL,
  createPgPool,
  redactDsn,
} from "../../src/lock/pg.js";
import type { HeadSigner, HeadVerifier, PgPoolLike } from "../../src/lock/pg.js";
import { runLockStoreConformance } from "../../src/lock/store.js";
import { checkListing } from "../../src/lock/check.js";
import { LockError } from "../../src/lock/lock.js";
import type { Identity, Lock } from "../../src/lock/lock.js";
import { createHmac } from "node:crypto";

const URL_ENV = process.env.MCPLOCK_TEST_PG_URL;
const ID: Identity = { kind: "remote", url: "https://mcp.example.com/v1/mcp" };
const TOOL = { name: "search", description: "Search the docs.", inputSchema: { type: "object" } };

function localOnly(url: string): string | null {
  try {
    const u = new URL(url);
    return ["127.0.0.1", "localhost", "[::1]"].includes(u.hostname) ? null : `host ${u.hostname} is not local`;
  } catch {
    return "not a URL";
  }
}

const skip = URL_ENV === undefined ? "MCPLOCK_TEST_PG_URL is not set (point it at a local throwaway Postgres)" : localOnly(URL_ENV);

test("redactDsn hides passwords in URL and keyword forms", () => {
  assert.equal(redactDsn("postgres://user:hunter2@db.local:5432/x"), "postgres://***@db.local:5432/x");
  assert.equal(redactDsn("postgresql://u:p@h/db?sslmode=require&password=hunter2"), "postgresql://***@h/db?sslmode=require&password=***");
  assert.equal(redactDsn("host=h user=u password=hunter2 dbname=x"), "host=h user=u password=*** dbname=x");
  assert.ok(!redactDsn("host=h password='a b c'").includes("a b c"));
  assert.equal(redactDsn("postgres://u:p@ss@db/x"), "postgres://***@db/x");
});

test("PgLockStore needs an authenticated principal with a tenant id", () => {
  const pool = { connect: async () => Promise.reject(new Error("unused")) } as PgPoolLike;
  assert.throws(() => new PgLockStore({ pool, principal: { tenantId: "", subject: "s" } }));
  assert.throws(() => new PgLockStore({ pool, principal: { tenantId: "a b", subject: "s" } }));
  assert.throws(() => new PgLockStore({ pool, principal: { tenantId: "t", subject: "" } }));
});

test("an unreachable database surfaces without the DSN", async () => {
  const dsn = "postgres://user:hunter2@127.0.0.1:1/none";
  const pool = await createPgPool(dsn, { connectionTimeoutMillis: 500 });
  const store = new PgLockStore({ pool, principal: { tenantId: "t", subject: "s" }, dsn });
  await assert.rejects(store.loadSnapshot(), (exc: Error) => !exc.message.includes("hunter2"));
  await (pool as unknown as { end(): Promise<void> }).end();
});

test("Postgres store", { skip: skip ?? false }, async (t) => {
  const admin = (await createPgPool(URL_ENV as string)) as PgPoolLike & { end(): Promise<void> };
  const pools: Array<{ end(): Promise<void> }> = [admin];
  const suffix = randomBytes(4).toString("hex");
  const runtimeUser = `mcplock_rt_${suffix}`;
  const approverUser = `mcplock_ap_${suffix}`;
  const rtPass = randomBytes(12).toString("hex");
  const apPass = randomBytes(12).toString("hex");
  const exec = async (sql: string, values?: unknown[]): Promise<Array<Record<string, unknown>>> => {
    const c = await admin.connect();
    try {
      return (await c.query(sql, values)).rows;
    } finally {
      c.release();
    }
  };
  await exec(MIGRATION_SQL);
  await exec(MIGRATION_SQL); // idempotent
  await exec(ROLE_SQL);
  await exec(`CREATE ROLE ${runtimeUser} LOGIN PASSWORD '${rtPass}' IN ROLE mcplock_runtime`);
  await exec(`CREATE ROLE ${approverUser} LOGIN PASSWORD '${apPass}' IN ROLE mcplock_approver`);
  const asUser = async (user: string, pass: string) => {
    const u = new URL(URL_ENV as string);
    u.username = user;
    u.password = pass;
    const pool = (await createPgPool(u.toString())) as PgPoolLike & { end(): Promise<void> };
    pools.push(pool);
    return pool;
  };
  const runtime = await asUser(runtimeUser, rtPass);
  const approver = await asUser(approverUser, apPass);
  const tenant = () => `t-${randomBytes(6).toString("hex")}`;

  try {
    await t.test("conformance suite as the approver role", async () => {
      const results = await runLockStoreConformance(() => new PgLockStore({ pool: approver, principal: { tenantId: tenant(), subject: "pg:approver" } }));
      for (const r of results) assert.ok(r.ok, `${r.name}: ${r.error}`);
    });

    await t.test("runtime role reads but cannot approve", async () => {
      const tid = tenant();
      await new PgLockStore({ pool: approver, principal: { tenantId: tid, subject: "pg:approver" } }).approve({ identity: ID, tool: TOOL, via: "api" });
      const reader = new PgLockStore({ pool: runtime, principal: { tenantId: tid, subject: "pg:runtime" } });
      const snap = await reader.loadSnapshot();
      assert.ok(!(snap.lock instanceof LockError));
      assert.ok(checkListing(snap.lock, ID, { tools: [TOOL] }, "guard").callable.has("search"));
      await assert.rejects(reader.approve({ identity: ID, tool: { ...TOOL, name: "other" }, via: "api" }), /permission denied/);
    });

    await t.test("tenants are isolated by row-level security", async () => {
      const a = tenant();
      const b = tenant();
      await new PgLockStore({ pool: approver, principal: { tenantId: a, subject: "pg:approver" } }).approve({ identity: ID, tool: TOOL, via: "api" });
      const snapB = await new PgLockStore({ pool: runtime, principal: { tenantId: b, subject: "x" } }).loadSnapshot();
      assert.equal((snapB.lock as Lock).shards.size, 0);
      // Even a raw query as the runtime user sees nothing without the tenant setting.
      const c = await runtime.connect();
      try {
        const rows = (await c.query("SELECT count(*)::int AS n FROM mcplock.records")).rows;
        assert.equal(rows[0]?.n, 0);
      } finally {
        c.release();
      }
      // And the approver cannot write a row for another tenant.
      const w = await approver.connect();
      try {
        await w.query("BEGIN");
        await w.query("SELECT set_config('mcplock.tenant_id', $1, true)", [a]);
        await assert.rejects(
          w.query(
            "INSERT INTO mcplock.heads (tenant_id, seq, head_hash) VALUES ($1, 0, 'x')",
            [b],
          ),
          /row-level security/,
        );
        await w.query("ROLLBACK");
      } finally {
        w.release();
      }
    });

    await t.test("approver cannot update or delete records", async () => {
      const tid = tenant();
      await new PgLockStore({ pool: approver, principal: { tenantId: tid, subject: "pg:approver" } }).approve({ identity: ID, tool: TOOL, via: "api" });
      for (const sql of ["UPDATE mcplock.records SET subject = 'x'", "DELETE FROM mcplock.records"]) {
        const c = await approver.connect();
        try {
          await c.query("BEGIN");
          await c.query("SELECT set_config('mcplock.tenant_id', $1, true)", [tid]);
          await assert.rejects(c.query(sql), /permission denied/);
          await c.query("ROLLBACK");
        } finally {
          c.release();
        }
      }
    });

    await t.test("tampering is detected: edited, deleted and trailing-deleted records", async () => {
      const fresh = async () => {
        const tid = tenant();
        const s = new PgLockStore({ pool: approver, principal: { tenantId: tid, subject: "pg:approver" } });
        await s.approve({ identity: ID, tool: TOOL, via: "api" });
        await s.approve({ identity: ID, tool: { ...TOOL, name: "fetch" }, via: "api" });
        await s.approve({ identity: ID, tool: { ...TOOL, name: "third" }, via: "api" });
        return { tid, reader: new PgLockStore({ pool: runtime, principal: { tenantId: tid, subject: "r" } }) };
      };
      const reason = async (r: PgLockStore) => {
        const snap = await r.loadSnapshot();
        return snap.lock instanceof LockError ? snap.lock.reason : null;
      };
      // Superuser edits stand in for an attacker with write access to the tables.
      const edit = await fresh();
      assert.equal(await reason(edit.reader), null);
      await exec("UPDATE mcplock.records SET digest = $2 WHERE tenant_id = $1 AND seq = 1", [edit.tid, "sha256:" + "1".repeat(64)]);
      assert.equal(await reason(edit.reader), "lock-unreadable");

      const contract = await fresh();
      await exec("UPDATE mcplock.records SET contract = $2 WHERE tenant_id = $1 AND seq = 2", [contract.tid, Buffer.from("{}")]);
      assert.equal(await reason(contract.reader), "lock-unreadable");

      const gap = await fresh();
      await exec("DELETE FROM mcplock.records WHERE tenant_id = $1 AND seq = 2", [gap.tid]);
      assert.equal(await reason(gap.reader), "lock-unreadable");

      const tail = await fresh();
      await exec("DELETE FROM mcplock.records WHERE tenant_id = $1 AND seq = 3", [tail.tid]);
      assert.equal(await reason(tail.reader), "lock-unreadable");

      // Trailing delete with the head rewound to match: caught by the reader's floor.
      const rewind = await fresh();
      assert.equal(await reason(rewind.reader), null); // floor is now 3
      const rows = await exec("SELECT record_hash FROM mcplock.records WHERE tenant_id = $1 AND seq = 2", [rewind.tid]);
      await exec("DELETE FROM mcplock.records WHERE tenant_id = $1 AND seq = 3", [rewind.tid]);
      await exec("UPDATE mcplock.heads SET seq = 2, head_hash = $2 WHERE tenant_id = $1", [rewind.tid, rows[0]?.record_hash]);
      assert.equal(await reason(rewind.reader), "lock-unreadable");
    });

    await t.test("signed heads: a verifier refuses an unsigned or re-signed head", async () => {
      const key = randomBytes(32);
      const signer: HeadSigner = { sign: async (p) => createHmac("sha256", key).update(p).digest("hex") };
      const verifier: HeadVerifier = { verify: async (p, s) => createHmac("sha256", key).update(p).digest("hex") === s };
      const tid = tenant();
      await new PgLockStore({ pool: approver, principal: { tenantId: tid, subject: "a" }, headSigner: signer }).approve({ identity: ID, tool: TOOL, via: "api" });
      const reader = new PgLockStore({ pool: runtime, principal: { tenantId: tid, subject: "r" }, headVerifier: verifier });
      assert.ok(!((await reader.loadSnapshot()).lock instanceof LockError));
      await exec("UPDATE mcplock.heads SET signature = 'forged' WHERE tenant_id = $1", [tid]);
      const snap = await reader.loadSnapshot();
      assert.ok(snap.lock instanceof LockError && snap.lock.reason === "lock-signature-invalid");
      const unsigned = new PgLockStore({ pool: runtime, principal: { tenantId: tenant(), subject: "r" }, headVerifier: verifier });
      const empty = await unsigned.loadSnapshot();
      assert.ok(empty.lock instanceof LockError && empty.lock.reason === "lock-signature-invalid");
    });

    await t.test("snapshot id is the head hash and changes on every approval", async () => {
      const tid = tenant();
      const s = new PgLockStore({ pool: approver, principal: { tenantId: tid, subject: "a" } });
      const a = (await s.loadSnapshot()).snapshotId;
      await s.approve({ identity: ID, tool: TOOL, via: "api" });
      const b = (await s.loadSnapshot()).snapshotId;
      assert.notEqual(a, b);
      assert.match(b, /^sha256:[0-9a-f]{64}$/);
    });
  } finally {
    for (const p of pools.reverse()) await p.end();
    const cleanup = (await createPgPool(URL_ENV as string)) as PgPoolLike & { end(): Promise<void> };
    const c = await cleanup.connect();
    try {
      await c.query(`DROP ROLE IF EXISTS ${runtimeUser}`);
      await c.query(`DROP ROLE IF EXISTS ${approverUser}`);
    } finally {
      c.release();
      await cleanup.end();
    }
  }
});

test("role-bound tenancy: a login reads and writes only its mapped tenant", { skip: skip ?? false }, async (t) => {
  const suffix = randomBytes(4).toString("hex");
  const dbName = `mcplock_rb_${suffix}`;
  const admin = (await createPgPool(URL_ENV as string)) as PgPoolLike & { end(): Promise<void> };
  const run = async (pool: PgPoolLike, sql: string, values?: unknown[]): Promise<Array<Record<string, unknown>>> => {
    const c = await pool.connect();
    try {
      return (await c.query(sql, values)).rows;
    } finally {
      c.release();
    }
  };
  await run(admin, `CREATE DATABASE ${dbName}`);
  const dbUrl = (user?: string, pass?: string): string => {
    const u = new URL(URL_ENV as string);
    u.pathname = `/${dbName}`;
    if (user !== undefined) {
      u.username = user;
      u.password = pass ?? "";
    }
    return u.toString();
  };
  const pools: Array<PgPoolLike & { end(): Promise<void> }> = [];
  const roles: string[] = [];
  const db = (await createPgPool(dbUrl())) as PgPoolLike & { end(): Promise<void> };
  pools.push(db);
  const login = async (inRole: "mcplock_runtime" | "mcplock_approver", tenantId: string | null) => {
    const name = `mcplock_rb_${inRole === "mcplock_runtime" ? "rt" : "ap"}_${randomBytes(4).toString("hex")}`;
    const pass = randomBytes(12).toString("hex");
    await run(admin, `CREATE ROLE ${name} LOGIN PASSWORD '${pass}' IN ROLE ${inRole}`);
    roles.push(name);
    if (tenantId !== null) await run(db, "INSERT INTO mcplock.tenant_logins (login, tenant_id) VALUES ($1, $2)", [name, tenantId]);
    const pool = (await createPgPool(dbUrl(name, pass))) as PgPoolLike & { end(): Promise<void> };
    pools.push(pool);
    return pool;
  };
  try {
    await run(db, MIGRATION_SQL);
    await run(db, ROLE_SQL);
    await run(db, ROLE_BOUND_SQL);
    await run(db, MIGRATION_SQL); // re-running the base migration keeps the role-bound policies

    const A = `t-a-${suffix}`;
    const B = `t-b-${suffix}`;
    const apA = await login("mcplock_approver", A);
    const rtA = await login("mcplock_runtime", A);
    const apB = await login("mcplock_approver", B);
    const rtB = await login("mcplock_runtime", B);
    const bound = (pool: PgPoolLike, tenantId: string) =>
      new PgLockStore({ pool, principal: { tenantId, subject: "rb" }, tenancy: "role-bound" });

    await t.test("each login works on its own tenant", async () => {
      await bound(apA, A).approve({ identity: ID, tool: TOOL, via: "api" });
      const snap = await bound(rtA, A).loadSnapshot();
      assert.ok(!(snap.lock instanceof LockError));
      assert.ok(checkListing(snap.lock, ID, { tools: [TOOL] }, "guard").callable.has("search"));
      const other = await bound(rtB, B).loadSnapshot();
      assert.equal((other.lock as Lock).shards.size, 0);
    });

    await t.test("setting another tenant's session value reads nothing of it", async () => {
      for (const pool of [rtB, apB]) {
        const c = await pool.connect();
        try {
          await c.query("BEGIN");
          await c.query("SELECT set_config('mcplock.tenant_id', $1, true)", [A]);
          const recs = (await c.query("SELECT count(*)::int AS n FROM mcplock.records")).rows;
          const heads = (await c.query("SELECT count(*)::int AS n FROM mcplock.heads WHERE tenant_id = $1", [A])).rows;
          assert.equal(recs[0]?.n, 0);
          assert.equal(heads[0]?.n, 0);
          await c.query("ROLLBACK");
          // Session-level too, not only SET LOCAL.
          await c.query("SET mcplock.tenant_id = '" + A + "'");
          assert.equal((await c.query("SELECT count(*)::int AS n FROM mcplock.records")).rows[0]?.n, 0);
          await c.query("RESET mcplock.tenant_id");
        } finally {
          c.release();
        }
      }
      // An app-scoped store on B's login, told it is tenant A, sets the value and still sees nothing.
      const spoof = await new PgLockStore({ pool: rtB, principal: { tenantId: A, subject: "x" } }).loadSnapshot();
      assert.equal((spoof.lock as Lock).shards.size, 0);
    });

    await t.test("setting another tenant's session value writes nothing to it", async () => {
      const c = await apB.connect();
      try {
        await c.query("BEGIN");
        await c.query("SELECT set_config('mcplock.tenant_id', $1, true)", [A]);
        await assert.rejects(
          c.query("INSERT INTO mcplock.heads (tenant_id, seq, head_hash) VALUES ($1, 0, 'x')", [A]),
          /row-level security/,
        );
        await c.query("ROLLBACK");
        await c.query("BEGIN");
        await c.query("SELECT set_config('mcplock.tenant_id', $1, true)", [A]);
        const updated = await c.query("UPDATE mcplock.heads SET signature = 'x' WHERE tenant_id = $1", [A]).then(
          (r) => (r as unknown as { rowCount: number }).rowCount,
          () => -1,
        );
        assert.ok(updated === 0 || updated === -1, "an UPDATE reached tenant A's head");
        await c.query("ROLLBACK");
      } finally {
        c.release();
      }
      // An app-scoped store on B's approver login, told it is tenant A, cannot append to A.
      await assert.rejects(
        new PgLockStore({ pool: apB, principal: { tenantId: A, subject: "x" } }).approve({ identity: ID, tool: { ...TOOL, name: "evil" }, via: "api" }),
      );
      const a = await bound(rtA, A).loadSnapshot();
      assert.deepEqual([...((a.lock as Lock).shards.values().next().value?.tools.keys() ?? [])], ["search"]);
    });

    await t.test("a role-bound store refuses a principal its login is not mapped to", async () => {
      await assert.rejects(bound(rtB, A).loadSnapshot(), /mapped to a different tenant/);
      await assert.rejects(bound(apB, A).approve({ identity: ID, tool: TOOL, via: "api" }), /mapped to a different tenant/);
      const unmapped = await login("mcplock_runtime", null);
      await assert.rejects(bound(unmapped, A).loadSnapshot(), /not mapped to a tenant/);
      const c = await unmapped.connect();
      try {
        assert.equal((await c.query("SELECT count(*)::int AS n FROM mcplock.records")).rows[0]?.n, 0);
        await assert.rejects(c.query("SELECT * FROM mcplock.tenant_logins"), /permission denied/);
      } finally {
        c.release();
      }
      const w = await apB.connect();
      try {
        await assert.rejects(w.query("INSERT INTO mcplock.tenant_logins (login, tenant_id) VALUES (session_user, $1)", [A]), /permission denied/);
      } finally {
        w.release();
      }
    });

    await t.test("conformance suite in role-bound mode", async () => {
      const results = await runLockStoreConformance(async () => {
        const tenantId = `t-c-${randomBytes(6).toString("hex")}`;
        return bound(await login("mcplock_approver", tenantId), tenantId);
      });
      for (const r of results) assert.ok(r.ok, `${r.name}: ${r.error}`);
    });
  } finally {
    for (const p of pools.reverse()) await p.end();
    await run(admin, `DROP DATABASE IF EXISTS ${dbName}`);
    for (const r of roles) await run(admin, `DROP ROLE IF EXISTS ${r}`);
    await admin.end();
  }
});
