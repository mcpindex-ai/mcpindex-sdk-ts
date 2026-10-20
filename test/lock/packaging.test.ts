/**
 * Packaging for the lock subpaths: exports resolve, the root import is
 * untouched, runtime dependencies stay zero, optional peers stay optional and
 * load lazily, and every new dist file is on the ship allowlist.
 */

import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const ROOT = fileURLToPath(new URL("../../..", import.meta.url));
const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")) as Record<string, any>;

test("subpath exports ./lock and ./lock/pg, with types and import", () => {
  assert.deepEqual(pkg.exports["./lock"], { types: "./dist/src/lock/index.d.ts", import: "./dist/src/lock/index.js" });
  assert.deepEqual(pkg.exports["./lock/pg"], { types: "./dist/src/lock/pg.d.ts", import: "./dist/src/lock/pg.js" });
  assert.deepEqual(pkg.exports["."], { types: "./dist/src/index.d.ts", import: "./dist/src/index.js" });
});

test("no runtime dependencies; pg and sigstore are optional peers", () => {
  assert.equal(pkg.dependencies, undefined);
  assert.equal(pkg.peerDependenciesMeta?.pg?.optional, true);
  assert.equal(pkg.peerDependenciesMeta?.sigstore?.optional, true);
  assert.match(pkg.peerDependencies.sigstore, /^\^4\.1/);
  assert.equal(pkg.engines.node, ">=20");
});

test("the root module does not load lock mode", () => {
  const index = readFileSync(join(ROOT, "dist", "src", "index.js"), "utf8");
  assert.ok(!/lock\//.test(index));
});

test("compiled lock modules import no optional peer or MCP SDK code statically", () => {
  const dir = join(ROOT, "dist", "src", "lock");
  for (const f of readdirSync(dir).filter((n) => n.endsWith(".js"))) {
    const text = readFileSync(join(dir, f), "utf8");
    for (const m of text.matchAll(/^import\s[^;]*?from\s+"([^"]+)"/gm)) {
      const spec = m[1] as string;
      assert.ok(spec.startsWith("./") || spec.startsWith("../") || spec.startsWith("node:"), `${f} imports ${spec}`);
    }
  }
});

test("every dist/src/lock output is on the ship allowlist", () => {
  const allow = new Set((JSON.parse(readFileSync(join(ROOT, "scripts", "ship-allowlist.json"), "utf8")) as { allow: string[] }).allow);
  const srcs = readdirSync(join(ROOT, "src", "lock")).filter((n) => n.endsWith(".ts"));
  for (const s of srcs) {
    const base = s.slice(0, -3);
    for (const ext of [".js", ".js.map", ".d.ts", ".d.ts.map"]) {
      assert.ok(allow.has(`dist/src/lock/${base}${ext}`), `missing dist/src/lock/${base}${ext}`);
    }
  }
});

test("the package resolves its own subpaths", async () => {
  const lock = (await import("@mcp-index/sdk/lock")) as Record<string, unknown>;
  assert.equal(typeof lock.lockClient, "function");
  assert.equal(typeof lock.toolDigest, "function");
  const pg = (await import("@mcp-index/sdk/lock/pg")) as Record<string, unknown>;
  assert.equal(typeof pg.PgLockStore, "function");
  assert.equal(typeof pg.MIGRATION_SQL, "string");
});

test("subpath ./ai: types and import entries, @ai-sdk/mcp an optional peer, engines floor unchanged", () => {
  assert.deepEqual(pkg.exports["./ai"], { types: "./dist/src/ai.d.ts", import: "./dist/src/ai.js" });
  assert.equal(pkg.peerDependenciesMeta?.["@ai-sdk/mcp"]?.optional, true);
  assert.ok(typeof pkg.peerDependencies["@ai-sdk/mcp"] === "string");
  assert.match(pkg.devDependencies["@ai-sdk/mcp"], /^\d+\.\d+\.\d+$/);
  assert.match(pkg.devDependencies.ai, /^\d+\.\d+\.\d+$/);
  assert.equal(pkg.engines.node, ">=20");
  assert.equal(pkg.dependencies, undefined);
});

test("compiled ai module imports only relative modules at runtime, and is on the ship allowlist", () => {
  const text = readFileSync(join(ROOT, "dist", "src", "ai.js"), "utf8");
  for (const m of text.matchAll(/^import\s[^;]*?from\s+"([^"]+)"/gm)) {
    assert.ok((m[1] as string).startsWith("./"), `ai.js imports ${m[1]}`);
  }
  const allow = new Set((JSON.parse(readFileSync(join(ROOT, "scripts", "ship-allowlist.json"), "utf8")) as { allow: string[] }).allow);
  for (const ext of [".js", ".js.map", ".d.ts", ".d.ts.map"]) assert.ok(allow.has(`dist/src/ai${ext}`), `missing dist/src/ai${ext}`);
  const index = readFileSync(join(ROOT, "dist", "src", "index.js"), "utf8");
  assert.ok(!/\.\/ai\.js/.test(index));
});

test("the package resolves @mcp-index/sdk/ai", async () => {
  const ai = (await import("@mcp-index/sdk/ai")) as Record<string, unknown>;
  assert.equal(typeof ai.lockTransport, "function");
  assert.equal(typeof ai.AiLockTransport, "function");
});
