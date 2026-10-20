/**
 * Reader rules the vectors do not reach on their own: the duplicate-key
 * scanner, encoding, directory symlinks, and signing with a fake verifier.
 */

import assert from "node:assert/strict";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, renameSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { LockError, findDuplicateKey, loadLock, strictJson } from "../../src/lock/lock.js";
import type { ManifestVerifier, ReaderConfig, SignerIdentity } from "../../src/lock/lock.js";
import { anchoredPattern, sigstoreVerifier } from "../../src/lock/signing.js";

const VECTORS = join(fileURLToPath(new URL("../../..", import.meta.url)), "test", "fixtures", "mcp-lock-vectors", "lock");
const SIGNER: SignerIdentity = {
  issuer: "https://token.actions.githubusercontent.com",
  san: "https://github.com/example/lock/.github/workflows/sign.yml@refs/heads/main",
};

function copyCase(name: string): { root: string; done: () => void } {
  const tmp = mkdtempSync(join(tmpdir(), "mcplock-reader-"));
  const root = join(tmp, name);
  cpSync(join(VECTORS, name), root, { recursive: true });
  return { root, done: () => rmSync(tmp, { recursive: true, force: true }) };
}

async function reason(root: string, config: ReaderConfig = {}): Promise<string | null> {
  try {
    await loadLock(root, config);
    return null;
  } catch (exc) {
    assert.ok(exc instanceof LockError, String(exc));
    return exc.reason;
  }
}

test("duplicate member names are found at any depth and after escape decoding", () => {
  assert.equal(findDuplicateKey('{"a":1,"b":{"c":1,"c":2}}'), "c");
  assert.equal(findDuplicateKey('{"a":1,"\\u0061":2}'), "a");
  assert.equal(findDuplicateKey('[{"a":1},{"a":2}]'), null);
  assert.equal(findDuplicateKey('{"a":"{\\"a\\":1,\\"a\\":2}"}'), null);
  assert.equal(findDuplicateKey('{"__proto__":1,"__proto__":2}'), "__proto__");
  assert.equal(findDuplicateKey('{"x":[1,{"y":1}],"y":2}'), null);
  assert.throws(() => strictJson(Buffer.from('{"a":1,"a":2}'), "f"), /duplicate member name/);
});

test("lock files must be UTF-8 JSON without a BOM, NaN or Infinity", () => {
  assert.throws(() => strictJson(Buffer.from([0xef, 0xbb, 0xbf, 0x7b, 0x7d]), "f"), LockError);
  assert.throws(() => strictJson(Buffer.from([0x22, 0xff, 0x22]), "f"), LockError);
  assert.throws(() => strictJson(Buffer.from('{"a":NaN}'), "f"), LockError);
  assert.throws(() => strictJson(Buffer.from('{"a":Infinity}'), "f"), LockError);
  assert.deepEqual(strictJson(Buffer.from('{"a":1}'), "f"), { a: 1 });
});

test("a symlinked .mcp/lock or .mcp/contracts is lock-unreadable", async () => {
  const c = copyCase("all-approved");
  try {
    renameSync(join(c.root, ".mcp", "lock"), join(c.root, "real-lock"));
    symlinkSync(join(c.root, "real-lock"), join(c.root, ".mcp", "lock"));
    assert.equal(await reason(c.root), "lock-unreadable");
  } finally {
    c.done();
  }
  const d = copyCase("all-approved");
  try {
    renameSync(join(d.root, ".mcp", "contracts"), join(d.root, "real-contracts"));
    symlinkSync(join(d.root, "real-contracts"), join(d.root, ".mcp", "contracts"));
    assert.equal(await reason(d.root), "lock-unreadable");
  } finally {
    d.done();
  }
});

test("a symlinked contract file is lock-unreadable; a subdirectory in .mcp/lock too", async () => {
  const c = copyCase("all-approved");
  try {
    const dir = join(c.root, ".mcp", "contracts");
    const name = readdirFirst(dir);
    renameSync(join(dir, name), join(c.root, "moved.json"));
    symlinkSync(join(c.root, "moved.json"), join(dir, name));
    assert.equal(await reason(c.root), "lock-unreadable");
  } finally {
    c.done();
  }
  const d = copyCase("all-approved");
  try {
    mkdirSync(join(d.root, ".mcp", "lock", "sub"));
    assert.equal(await reason(d.root), "lock-unreadable");
  } finally {
    d.done();
  }
});

test("missing .mcp/lock is lock-unreadable; an empty .mcp/lock is a valid empty lock", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mcplock-empty-"));
  try {
    mkdirSync(join(tmp, ".mcp"));
    assert.equal(await reason(tmp), "lock-unreadable");
    mkdirSync(join(tmp, ".mcp", "lock"));
    const loaded = await loadLock(tmp);
    assert.equal(loaded.lock.shards.size, 0);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

function readdirFirst(dir: string): string {
  return readdirSync(dir).sort()[0] as string;
}

const okVerifier: ManifestVerifier = { verify: async () => true };

test("signer configured: a good fake signature passes; missing bundle, bad bundle, throw, or no verifier fail", async () => {
  const c = copyCase("manifest-ok");
  try {
    const lockDir = join(c.root, ".mcp", "lock");
    // No bundle.
    assert.equal(await reason(c.root, { signer: SIGNER, verifier: okVerifier }), "lock-signature-invalid");
    writeFileSync(join(lockDir, "MANIFEST.json.sigstore"), "{}");
    // The manifest lists every file, and now there is a bundle it does not list:
    // the bundle is excluded from the manifest by definition.
    assert.equal(await reason(c.root, { signer: SIGNER, verifier: okVerifier }), null);
    assert.equal(await reason(c.root, { signer: SIGNER, verifier: { verify: async () => false } }), "lock-signature-invalid");
    assert.equal(
      await reason(c.root, {
        signer: SIGNER,
        verifier: {
          verify: async () => {
            throw new Error("boom");
          },
        },
      }),
      "lock-signature-invalid",
    );
    assert.equal(await reason(c.root, { signer: SIGNER }), "lock-signature-invalid");
    // Without a signer nothing is verified and the bundle is ignored.
    assert.equal(await reason(c.root), null);
  } finally {
    c.done();
  }
});

test("the verifier sees the exact manifest bytes the reader then parses", async () => {
  const c = copyCase("manifest-ok");
  try {
    const lockDir = join(c.root, ".mcp", "lock");
    writeFileSync(join(lockDir, "MANIFEST.json.sigstore"), "bundle-bytes");
    const onDisk = readFileSync(join(lockDir, "MANIFEST.json"));
    let seen: Buffer | null = null;
    let seenBundle: Buffer | null = null;
    await loadLock(c.root, {
      signer: SIGNER,
      verifier: {
        verify: async (m, b, s) => {
          seen = Buffer.from(m);
          seenBundle = Buffer.from(b);
          assert.deepEqual(s, SIGNER);
          return true;
        },
      },
    });
    assert.deepEqual(seen, onDisk);
    assert.equal(String(seenBundle), "bundle-bytes");
  } finally {
    c.done();
  }
});

test("sequence rollback with a valid signature is lock-signature-invalid; equal or higher passes", async () => {
  const c = copyCase("manifest-ok");
  try {
    writeFileSync(join(c.root, ".mcp", "lock", "MANIFEST.json.sigstore"), "{}");
    const seq = (JSON.parse(readFileSync(join(c.root, ".mcp", "lock", "MANIFEST.json"), "utf8")) as { sequence: number }).sequence;
    const cfg = (last: number): ReaderConfig => ({ signer: SIGNER, verifier: okVerifier, lastSequence: last });
    assert.equal(await reason(c.root, cfg(seq + 1)), "lock-signature-invalid");
    assert.equal(await reason(c.root, cfg(seq)), null);
    assert.equal(await reason(c.root, cfg(0)), null);
  } finally {
    c.done();
  }
});

test("sigstore verifier fails closed when the optional module is missing or the bundle is garbage", async () => {
  const missing = sigstoreVerifier({
    trustedRootPath: "/nonexistent/trusted_root.json",
    load: () => {
      throw new Error("Cannot find module 'sigstore'");
    },
  });
  assert.equal(await missing.verify(Buffer.from("{}"), Buffer.from("{}"), SIGNER), false);
  // The real loader: sigstore is not a dev dependency here, so this is the
  // missing-module path in this repo, and a garbage bundle anywhere else.
  const real = sigstoreVerifier({ trustedRootPath: "/nonexistent/trusted_root.json" });
  assert.equal(await real.verify(Buffer.from("{}"), Buffer.from("not json"), SIGNER), false);
  assert.equal(await real.verify(Buffer.from("{}"), Buffer.from("{}"), { issuer: "", san: "" }), false);
});

test("sigstore verifier: exact issuer and SAN match on the returned signer, anchored SAN policy", async () => {
  const policies: Array<Record<string, unknown>> = [];
  const fake = (identity: { subjectAlternativeName?: string; extensions?: { issuer?: string } }) =>
    sigstoreVerifier({
      trustedRootPath: join(VECTORS, "manifest-ok", "config.json"), // any regular JSON file
      load: (name) => {
        if (name === "sigstore") return {};
        if (name === "@sigstore/protobuf-specs") return { TrustedRoot: { fromJSON: (j: unknown) => j } };
        if (name === "@sigstore/bundle") return { bundleFromJSON: (j: unknown) => j };
        return {
          toSignedEntity: (b: unknown) => b,
          toTrustMaterial: (r: unknown) => r,
          Verifier: class {
            verify(_e: unknown, policy: Record<string, unknown>) {
              policies.push(policy);
              return { identity };
            }
          },
        };
      },
    });
  const good = fake({ subjectAlternativeName: SIGNER.san, extensions: { issuer: SIGNER.issuer } });
  assert.equal(await good.verify(Buffer.from("m"), Buffer.from("{}"), SIGNER), true);
  assert.equal(policies[0]?.subjectAlternativeName, anchoredPattern(SIGNER.san));
  assert.ok(new RegExp(anchoredPattern(SIGNER.san)).test(SIGNER.san));
  assert.ok(!new RegExp(anchoredPattern(SIGNER.san)).test(SIGNER.san + "x"));
  assert.ok(!new RegExp(anchoredPattern("a.b")).test("axb"));
  const prefix = fake({ subjectAlternativeName: SIGNER.san + "/evil", extensions: { issuer: SIGNER.issuer } });
  assert.equal(await prefix.verify(Buffer.from("m"), Buffer.from("{}"), SIGNER), false);
  const issuer = fake({ subjectAlternativeName: SIGNER.san, extensions: { issuer: SIGNER.issuer + ".evil" } });
  assert.equal(await issuer.verify(Buffer.from("m"), Buffer.from("{}"), SIGNER), false);
});

test("real Sigstore bundle verification", { skip: "no valid Sigstore bundle in vectors-draft-1b; needs a signed MANIFEST.json and an operator trusted_root.json" }, () => {
  // Intentionally empty.
});
