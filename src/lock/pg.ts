/**
 * Postgres LockStore (`@mcp-index/sdk/lock/pg`). `pg` is an optional peer
 * dependency: pass your own pool, or call createPgPool, which imports `pg` on
 * first use.
 *
 * Tenancy. The tenant comes from an AuthenticatedPrincipal the host passes in
 * after it has authenticated the caller. It is never read from a header or a
 * request body. Every statement runs in a transaction that first sets
 * `mcplock.tenant_id` with set_config(..., true), and row-level security on
 * both tables (FORCE, so the table owner is held to it too) limits every row
 * to that tenant. A superuser bypasses RLS; do not connect as one.
 *
 * Roles. ROLE_SQL creates two NOLOGIN roles: `mcplock_runtime` may only
 * SELECT, and is what hosts in lock mode connect as; `mcplock_approver` may
 * also INSERT records and INSERT or UPDATE the head row, and is a separate
 * credential held by the approval path. Neither role may UPDATE or DELETE a
 * record.
 *
 * Integrity. Records are append-only and hash-chained: each record_hash is
 * sha256 over the previous hash and the record's canonical fields, tenant
 * included. The head row holds the last seq and hash, and an optional
 * signature from a host-supplied signer. A load recomputes the chain, checks
 * seq is contiguous from 1, that the head matches the last record, and that
 * every contract hashes to its digest; any failure is lock-unreadable (or
 * contract-mismatch, or lock-signature-invalid for the head signature). A load
 * whose head seq is below one this store already accepted is lock-unreadable,
 * which catches deletes of trailing records together with the head update.
 * Deleting every row for a tenant cannot be told apart from a new tenant
 * without an external anchor: keep the last seq, or require a head signature.
 *
 * Staleness. Each snapshot carries snapshotId (the head hash) and loadedAt.
 * Hosts pass maxStalenessMs to the CallGate (LockOptions in rawList.ts); calls
 * on a decision older than that are refused with `lock-stale` unless a reload
 * succeeds.
 *
 * SQL is parameterized throughout. A DSN never reaches a log or an error
 * message unredacted; see redactDsn.
 */

import { canonicalize, instructionsDigest, sha256Hex } from "./digest.js";
import { FrozenMap, LockError, identityKey, validateIdentity } from "./lock.js";
import type { Approval, Identity, Lock, Shard, ToolEntry, Via } from "./lock.js";
import { checkApprovalFields, prepareTool, snapshotOfError } from "./store.js";
import type { ApproveRequest, LockSnapshot, LockStore, RevokeRequest } from "./store.js";

export interface PgQueryResult {
  readonly rows: Array<Record<string, unknown>>;
}

export interface PgClientLike {
  query(text: string, values?: unknown[]): Promise<PgQueryResult>;
  release(err?: Error | boolean): void;
}

export interface PgPoolLike {
  connect(): Promise<PgClientLike>;
}

/** The authenticated caller. The host fills this in after its own auth; never from a header. */
export interface AuthenticatedPrincipal {
  readonly tenantId: string;
  /** Recorded as the approval subject. */
  readonly subject: string;
}

/** Optional head signing. The payload is the canonical {tenant, seq, head} text. */
export interface HeadSigner {
  sign(payload: Uint8Array): Promise<string>;
}
export interface HeadVerifier {
  verify(payload: Uint8Array, signature: string): Promise<boolean>;
}

export const SCHEMA_VERSION = 1;
export const GENESIS = "sha256:" + "0".repeat(64);

/** Tables, constraints and RLS policies. Idempotent; run once as the schema owner. */
export const MIGRATION_SQL = `
CREATE SCHEMA IF NOT EXISTS mcplock;

CREATE TABLE IF NOT EXISTS mcplock.records (
  tenant_id    text   NOT NULL,
  seq          bigint NOT NULL CHECK (seq > 0),
  op           text   NOT NULL CHECK (op IN ('approve', 'revoke')),
  identity_key text   NOT NULL,
  tool_name    text,
  digest       text   CHECK (digest IS NULL OR digest ~ '^sha256:[0-9a-f]{64}$'),
  contract     bytea,
  subject      text   NOT NULL,
  via          text   NOT NULL CHECK (via IN ('pr', 'runtime', 'api', 'migrated')),
  ref          text,
  at           text   NOT NULL,
  prev_hash    text   NOT NULL,
  record_hash  text   NOT NULL,
  PRIMARY KEY (tenant_id, seq)
);

CREATE TABLE IF NOT EXISTS mcplock.heads (
  tenant_id  text        PRIMARY KEY,
  seq        bigint      NOT NULL CHECK (seq >= 0),
  head_hash  text        NOT NULL,
  signature  text,
  updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE mcplock.records ENABLE ROW LEVEL SECURITY;
ALTER TABLE mcplock.records FORCE ROW LEVEL SECURITY;
ALTER TABLE mcplock.heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE mcplock.heads FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'mcplock' AND tablename = 'records' AND policyname = 'tenant_records') THEN
    CREATE POLICY tenant_records ON mcplock.records
      USING (tenant_id = current_setting('mcplock.tenant_id', true))
      WITH CHECK (tenant_id = current_setting('mcplock.tenant_id', true));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'mcplock' AND tablename = 'heads' AND policyname = 'tenant_heads') THEN
    CREATE POLICY tenant_heads ON mcplock.heads
      USING (tenant_id = current_setting('mcplock.tenant_id', true))
      WITH CHECK (tenant_id = current_setting('mcplock.tenant_id', true));
  END IF;
END $$;
`;

/**
 * The two roles. Run once by a database administrator, then grant each role
 * to its own login: hosts get mcplock_runtime, the approval service gets
 * mcplock_approver. No role gets UPDATE or DELETE on records.
 */
export const ROLE_SQL = `
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mcplock_runtime') THEN
    CREATE ROLE mcplock_runtime NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mcplock_approver') THEN
    CREATE ROLE mcplock_approver NOLOGIN;
  END IF;
END $$;
GRANT USAGE ON SCHEMA mcplock TO mcplock_runtime, mcplock_approver;
GRANT SELECT ON mcplock.records, mcplock.heads TO mcplock_runtime;
GRANT SELECT, INSERT ON mcplock.records TO mcplock_approver;
GRANT SELECT, INSERT, UPDATE ON mcplock.heads TO mcplock_approver;
`;

/** Replace any password or userinfo in a connection string before it is shown. */
export function redactDsn(dsn: string): string {
  return dsn
    .replace(/^([a-z][a-z0-9+.-]*:\/\/)[^@/?#]*@/i, "$1***@")
    .replace(/([?&](?:password|sslpassword|passfile|sslkey)=)[^&#]*/gi, "$1***")
    .replace(/(\bpassword\s*=\s*)('[^']*'|\S+)/gi, "$1***");
}

function scrub(message: string, dsn: string | undefined): string {
  let out = message;
  if (dsn) out = out.split(dsn).join(redactDsn(dsn));
  return redactDsn(out);
}

/** Build a pg Pool, importing `pg` on first use. Errors never carry the DSN. */
export async function createPgPool(connectionString: string, extra: Record<string, unknown> = {}): Promise<PgPoolLike> {
  let mod: Record<string, unknown>;
  try {
    const name = "pg";
    mod = (await import(name)) as Record<string, unknown>;
  } catch {
    throw new Error("the optional peer dependency `pg` is not installed");
  }
  const pg = (mod.default ?? mod) as { Pool: new (cfg: Record<string, unknown>) => PgPoolLike & { on?: (event: string, fn: () => void) => void } };
  const pool = new pg.Pool({ ...extra, connectionString });
  // pg emits idle-client errors on the pool; keep the DSN out of them.
  pool.on?.("error", () => undefined);
  return pool;
}

const TENANT = /^[\x21-\x7e]{1,128}$/;

interface RecordRow {
  seq: number;
  op: "approve" | "revoke";
  identityKey: string;
  toolName: string | null;
  digest: string | null;
  contract: Buffer | null;
  subject: string;
  via: Via;
  ref: string | null;
  at: string;
  prevHash: string;
  recordHash: string;
}

function recordHash(tenant: string, r: Omit<RecordRow, "recordHash">): string {
  const body = canonicalize({
    tenant,
    seq: r.seq,
    op: r.op,
    identityKey: r.identityKey,
    tool: r.toolName,
    digest: r.digest,
    contract: r.contract === null ? null : sha256Hex(r.contract),
    subject: r.subject,
    via: r.via,
    ref: r.ref,
    at: r.at,
  });
  return "sha256:" + sha256Hex(`${r.prevHash}\n${body}`);
}

function headPayload(tenant: string, seq: number, head: string): Buffer {
  return Buffer.from(canonicalize({ tenant, seq, head }), "utf8");
}

function toRow(raw: Record<string, unknown>): RecordRow {
  const contract = raw.contract;
  return {
    seq: Number(raw.seq),
    op: raw.op as RecordRow["op"],
    identityKey: String(raw.identity_key),
    toolName: raw.tool_name === null ? null : String(raw.tool_name),
    digest: raw.digest === null ? null : String(raw.digest),
    contract: contract === null || contract === undefined ? null : Buffer.from(contract as Uint8Array),
    subject: String(raw.subject),
    via: raw.via as Via,
    ref: raw.ref === null ? null : String(raw.ref),
    at: String(raw.at),
    prevHash: String(raw.prev_hash),
    recordHash: String(raw.record_hash),
  };
}

interface Head {
  seq: number;
  hash: string;
  signature: string | null;
}

export interface PgLockStoreOptions {
  readonly pool: PgPoolLike;
  readonly principal: AuthenticatedPrincipal;
  readonly headSigner?: HeadSigner;
  /** With a verifier set, a head without a valid signature is lock-signature-invalid. */
  readonly headVerifier?: HeadVerifier;
  /** Lowest head seq to accept, from the host's own state. Raised in memory on each load. */
  readonly lastSeq?: number;
  /** For messages only: replaced by its redacted form in any error text. */
  readonly dsn?: string;
  readonly now?: () => number;
}

export class PgLockStore implements LockStore {
  readonly #pool: PgPoolLike;
  readonly #tenant: string;
  readonly #subject: string;
  readonly #signer: HeadSigner | undefined;
  readonly #verifier: HeadVerifier | undefined;
  readonly #dsn: string | undefined;
  readonly #now: () => number;
  #lastSeq: number;

  constructor(options: PgLockStoreOptions) {
    const p = options.principal;
    if (p === null || typeof p !== "object" || typeof p.tenantId !== "string" || !TENANT.test(p.tenantId)) {
      throw new Error("principal.tenantId must be 1-128 printable ASCII characters");
    }
    if (typeof p.subject !== "string" || p.subject.length === 0) throw new Error("principal.subject is required");
    this.#pool = options.pool;
    this.#tenant = p.tenantId;
    this.#subject = p.subject;
    this.#signer = options.headSigner;
    this.#verifier = options.headVerifier;
    this.#dsn = options.dsn;
    this.#now = options.now ?? Date.now;
    this.#lastSeq = options.lastSeq ?? 0;
  }

  async #tx<T>(mode: "read" | "write", fn: (c: PgClientLike) => Promise<T>): Promise<T> {
    let client: PgClientLike;
    try {
      client = await this.#pool.connect();
    } catch (exc) {
      throw new Error(`lock store unreachable: ${scrub((exc as Error).message ?? "", this.#dsn)}`);
    }
    try {
      await client.query(mode === "read" ? "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY" : "BEGIN ISOLATION LEVEL SERIALIZABLE");
      await client.query("SELECT set_config('mcplock.tenant_id', $1, true)", [this.#tenant]);
      const out = await fn(client);
      await client.query("COMMIT");
      client.release();
      return out;
    } catch (exc) {
      try {
        await client.query("ROLLBACK");
      } catch {
        // connection may be gone
      }
      client.release(true);
      if (exc instanceof LockError) throw exc;
      const err = new Error(scrub((exc as Error).message ?? String(exc), this.#dsn));
      (err as { code?: unknown }).code = (exc as { code?: unknown }).code;
      throw err;
    }
  }

  async #readState(c: PgClientLike, forUpdate: boolean): Promise<{ head: Head | null; rows: RecordRow[] }> {
    const headRes = await c.query(
      `SELECT seq, head_hash, signature FROM mcplock.heads WHERE tenant_id = $1${forUpdate ? " FOR UPDATE" : ""}`,
      [this.#tenant],
    );
    const h = headRes.rows[0];
    const head: Head | null =
      h === undefined
        ? null
        : { seq: Number(h.seq), hash: String(h.head_hash), signature: h.signature === null ? null : String(h.signature) };
    const recRes = await c.query(
      `SELECT seq, op, identity_key, tool_name, digest, contract, subject, via, ref, at, prev_hash, record_hash
         FROM mcplock.records WHERE tenant_id = $1 ORDER BY seq`,
      [this.#tenant],
    );
    return { head, rows: recRes.rows.map(toRow) };
  }

  /** Verify the chain and fold it into a Lock. Throws LockError. */
  async #fold(head: Head | null, rows: RecordRow[]): Promise<{ lock: Lock; snapshotId: string; seq: number }> {
    if (head === null) {
      if (rows.length > 0) throw new LockError("lock-unreadable", "records without a head row");
      if (this.#lastSeq > 0) throw new LockError("lock-unreadable", `head missing; last accepted seq ${this.#lastSeq}`);
      if (this.#verifier !== undefined) throw new LockError("lock-signature-invalid", "no signed head");
      const empty: Lock = Object.freeze({ shards: new FrozenMap<string, Shard>([]), aliases: new FrozenMap<string, Identity>([]), sequence: 0 });
      return { lock: empty, snapshotId: GENESIS, seq: 0 };
    }
    let prev = GENESIS;
    const shards = new Map<string, { identity: Identity; instructions: string | null; tools: Map<string, ToolEntry> }>();
    rows.forEach((r, i) => {
      if (r.seq !== i + 1) throw new LockError("lock-unreadable", `record seq gap at ${i + 1}`);
      if (r.prevHash !== prev) throw new LockError("lock-unreadable", `record ${r.seq} does not chain`);
      const { recordHash: stored, ...rest } = r;
      if (recordHash(this.#tenant, rest) !== stored) throw new LockError("lock-unreadable", `record ${r.seq} hash mismatch`);
      prev = stored;
      let identity: Identity;
      try {
        identity = validateIdentity(JSON.parse(r.identityKey));
      } catch (exc) {
        if (exc instanceof LockError) throw exc;
        throw new LockError("lock-unreadable", `record ${r.seq} identity is not JSON`);
      }
      if (identityKey(identity) !== r.identityKey) throw new LockError("lock-unreadable", `record ${r.seq} identity key not canonical`);
      let shard = shards.get(r.identityKey);
      if (shard === undefined) {
        shard = { identity, instructions: null, tools: new Map() };
        shards.set(r.identityKey, shard);
      }
      if (r.op === "approve") {
        if (r.digest === null) throw new LockError("lock-unreadable", `record ${r.seq} approves without a digest`);
        if (r.toolName === null) {
          shard.instructions = r.digest;
          return;
        }
        if (r.contract === null || "sha256:" + sha256Hex(r.contract) !== r.digest) {
          throw new LockError("contract-mismatch", `record ${r.seq} contract differs from digest`);
        }
        const approval: Approval =
          r.ref === null
            ? Object.freeze({ subject: r.subject, at: r.at, via: r.via })
            : Object.freeze({ subject: r.subject, at: r.at, via: r.via, ref: r.ref });
        shard.tools.set(
          r.toolName,
          Object.freeze({ digest: r.digest, contract: `sha256-${r.digest.slice(7)}.json`, approval }),
        );
      } else if (r.toolName === null) {
        shard.instructions = null;
      } else {
        shard.tools.delete(r.toolName);
      }
    });
    const lastSeq = rows.length;
    if (head.seq !== lastSeq || head.hash !== prev) throw new LockError("lock-unreadable", "head does not match the last record");
    if (head.seq < this.#lastSeq) throw new LockError("lock-unreadable", `head seq ${head.seq} < last accepted ${this.#lastSeq}`);
    if (this.#verifier !== undefined) {
      let ok = false;
      try {
        ok = head.signature !== null && (await this.#verifier.verify(headPayload(this.#tenant, head.seq, head.hash), head.signature));
      } catch {
        ok = false;
      }
      if (!ok) throw new LockError("lock-signature-invalid", "head signature missing or invalid");
    }
    const frozen = new Map<string, Shard>();
    for (const [key, s] of shards) {
      frozen.set(key, Object.freeze({ identity: s.identity, attributes: null, instructions: s.instructions, tools: new FrozenMap(s.tools) }));
    }
    const lock: Lock = Object.freeze({ shards: new FrozenMap(frozen), aliases: new FrozenMap<string, Identity>([]), sequence: head.seq });
    return { lock, snapshotId: head.hash, seq: head.seq };
  }

  async loadSnapshot(): Promise<LockSnapshot> {
    const loadedAt = this.#now();
    const state = await this.#tx("read", (c) => this.#readState(c, false));
    try {
      const { lock, snapshotId, seq } = await this.#fold(state.head, state.rows);
      if (seq > this.#lastSeq) this.#lastSeq = seq;
      return Object.freeze({ snapshotId, loadedAt, lock });
    } catch (exc) {
      if (exc instanceof LockError) return snapshotOfError(exc, loadedAt);
      throw exc;
    }
  }

  async #append(
    identity: Identity,
    record: { op: "approve" | "revoke"; toolName: string | null; digest: string | null; contract: Buffer | null; approval: Approval },
    precondition: (lock: Lock) => void,
  ): Promise<void> {
    const ident = validateIdentity(identity);
    const key = identityKey(ident);
    await this.#tx("write", async (c) => {
      await c.query(
        "INSERT INTO mcplock.heads (tenant_id, seq, head_hash) VALUES ($1, 0, $2) ON CONFLICT (tenant_id) DO NOTHING",
        [this.#tenant, GENESIS],
      );
      const state = await this.#readState(c, true);
      // Never extend a chain that does not verify. A fresh head row has seq 0
      // and no records; fold accepts that as empty only without a verifier, so
      // treat it as empty here directly.
      const fresh = state.head !== null && state.head.seq === 0 && state.rows.length === 0;
      const folded = fresh
        ? { lock: Object.freeze({ shards: new FrozenMap<string, Shard>([]), aliases: new FrozenMap<string, Identity>([]), sequence: 0 }) as Lock, seq: 0 }
        : await this.#fold(state.head, state.rows);
      precondition(folded.lock);
      const prevHash = fresh ? GENESIS : (state.head as Head).hash;
      const seq = folded.seq + 1;
      const row = {
        seq,
        op: record.op,
        identityKey: key,
        toolName: record.toolName,
        digest: record.digest,
        contract: record.contract,
        subject: record.approval.subject,
        via: record.approval.via,
        ref: record.approval.ref ?? null,
        at: record.approval.at,
        prevHash,
      };
      const hash = recordHash(this.#tenant, row);
      await c.query(
        `INSERT INTO mcplock.records
           (tenant_id, seq, op, identity_key, tool_name, digest, contract, subject, via, ref, at, prev_hash, record_hash)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
        [this.#tenant, seq, row.op, key, row.toolName, row.digest, row.contract, row.subject, row.via, row.ref, row.at, prevHash, hash],
      );
      const signature = this.#signer ? await this.#signer.sign(headPayload(this.#tenant, seq, hash)) : null;
      await c.query(
        "UPDATE mcplock.heads SET seq = $2, head_hash = $3, signature = $4, updated_at = now() WHERE tenant_id = $1",
        [this.#tenant, seq, hash, signature],
      );
    });
  }

  async approve(request: ApproveRequest): Promise<void> {
    // The subject is the authenticated principal, whatever the request says.
    const approval = checkApprovalFields(request, this.#subject);
    if ("tool" in request) {
      const p = prepareTool(request.tool);
      await this.#append(request.identity, { op: "approve", toolName: p.name, digest: p.digest, contract: p.body, approval }, () => undefined);
      return;
    }
    const digest = instructionsDigest(request.instructions);
    if (digest === null) throw new Error("instructions have no digest; they cannot be approved");
    await this.#append(request.identity, { op: "approve", toolName: null, digest, contract: null, approval }, () => undefined);
  }

  async revoke(request: RevokeRequest): Promise<void> {
    const ident = validateIdentity(request.identity);
    const key = identityKey(ident);
    const approval = checkApprovalFields({ identity: ident, via: "api" }, this.#subject);
    const toolName = "tool" in request ? request.tool : null;
    await this.#append(ident, { op: "revoke", toolName, digest: null, contract: null, approval }, (lock) => {
      const shard = lock.shards.get(key);
      if (shard === undefined) throw new Error("no approvals for this identity");
      if (toolName === null ? shard.instructions === null : !shard.tools.has(toolName)) {
        throw new Error(toolName === null ? "instructions are not approved" : `tool ${JSON.stringify(toolName)} is not approved`);
      }
    });
  }
}
