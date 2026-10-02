import { strict as assert } from "node:assert";
import test from "node:test";
import { existsSync, lstatSync, mkdtempSync, statSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  buildStartUrl,
  extractKeyFromCallback,
  loadApiKey,
  newLoginState,
  parseProvider,
  runLogin,
  saveApiKey,
} from "../src/login.js";

const S = "nonce_abc123";

test("extractKeyFromCallback returns an mcpk_ key only when the path matches the state nonce", () => {
  assert.equal(extractKeyFromCallback(`/${S}?key=mcpk_abc123`, S), "mcpk_abc123");
  assert.equal(extractKeyFromCallback(`/${S}?key=notaprefix`, S), null, "rejects wrong prefix");
  assert.equal(extractKeyFromCallback(`/${S}`, S), null, "no key param");
  assert.equal(extractKeyFromCallback(`/${S}?state=x`, S), null, "unrelated param");
  assert.equal(extractKeyFromCallback("%%%not a url", S), null, "malformed does not throw");
});

test("extractKeyFromCallback rejects a forged key on a wrong/absent path (fixation guard)", () => {
  // A webpage the victim has open that guesses the port but NOT the nonce path is rejected.
  assert.equal(extractKeyFromCallback("/?key=mcpk_attacker", S), null, "root path (no nonce)");
  assert.equal(extractKeyFromCallback("/wrongnonce?key=mcpk_attacker", S), null, "wrong nonce");
  assert.equal(extractKeyFromCallback(`/${S}?key=mcpk_x`, ""), null, "empty state never matches");
});

test("newLoginState is url-safe and unpredictable", () => {
  const a = newLoginState();
  assert.ok(/^[A-Za-z0-9_-]+$/.test(a), "url-safe (base64url) so it survives a path segment");
  assert.ok(a.length >= 24, "enough entropy to resist guessing within the login window");
  assert.notEqual(a, newLoginState(), "fresh per call");
});

test("buildStartUrl targets /api/auth/login/start with the nonce in the loopback callback path", () => {
  const u = buildStartUrl("https://mcpindex.ai", 51234, S);
  assert.equal(
    u,
    `https://mcpindex.ai/api/auth/login/start?cli_callback=http%3A%2F%2F127.0.0.1%3A51234%2F${S}`,
  );
  // trailing slash on the base is normalized (no double slash)
  assert.ok(buildStartUrl("https://mcpindex.ai/", 80, S).includes("mcpindex.ai/api/auth"));
});

test("buildStartUrl appends &provider=google only for the non-default provider", () => {
  const gh = buildStartUrl("https://mcpindex.ai", 51234, S, "github");
  assert.ok(!gh.includes("provider="), "github (default) omits the param - byte-for-byte back-compat");
  const goog = buildStartUrl("https://mcpindex.ai", 51234, S, "google");
  assert.ok(goog.endsWith("&provider=google"), "google appends the provider param");
  assert.ok(goog.includes("cli_callback="), "still carries the loopback callback");
});

test("parseProvider defaults to github and validates the flag value", () => {
  assert.equal(parseProvider([]), "github", "no flag -> github default");
  assert.equal(parseProvider(["--provider", "github"]), "github");
  assert.equal(parseProvider(["--provider", "google"]), "google");
  assert.equal(parseProvider(["--provider", "gitlab"]), null, "unknown provider rejected");
  assert.equal(parseProvider(["--provider"]), null, "missing value rejected");
});

test("runLogin --provider google drives the browser to the Google start url", async () => {
  const home = mkdtempSync(join(tmpdir(), "mcpi-home-"));
  const prevHome = process.env.HOME;
  process.env.HOME = home;
  let openedUrl = "";
  try {
    const open = (url: string) => {
      openedUrl = url;
      const cb = decodeURIComponent(new URL(url).searchParams.get("cli_callback") ?? "");
      void fetch(`${cb}?key=mcpk_real`).catch(() => {});
    };
    const r = await runLogin({
      webBase: "https://example.test",
      print: () => {},
      open,
      provider: "google",
      timeoutMs: 4000,
    });
    assert.equal(r.apiKey, "mcpk_real");
    assert.ok(openedUrl.includes("provider=google"), "start url carries provider=google");
  } finally {
    if (prevHome === undefined) delete process.env.HOME;
    else process.env.HOME = prevHome;
  }
});

test("saveApiKey round-trips and writes 0600", () => {
  const dir = mkdtempSync(join(tmpdir(), "mcpi-login-"));
  const path = join(dir, "credentials.json");
  saveApiKey("mcpk_stored", path);
  assert.equal(loadApiKey(path), "mcpk_stored");
  const mode = statSync(path).mode & 0o777;
  assert.equal(mode, 0o600, `expected 0600, got ${mode.toString(8)}`);
});

test("loadApiKey returns null for a missing or malformed file", () => {
  assert.equal(loadApiKey(join(tmpdir(), "does-not-exist-xyz.json")), null);
  const dir = mkdtempSync(join(tmpdir(), "mcpi-login-"));
  const path = join(dir, "creds.json");
  saveApiKey("", path); // empty key -> treated as absent
  assert.equal(loadApiKey(path), null, "empty stored key reads as null");
});

test("saveApiKey does not follow a pre-staged symlink at the target path", () => {
  const dir = mkdtempSync(join(tmpdir(), "mcpi-sym-"));
  const target = join(dir, "credentials.json");
  const outside = join(dir, "outside.json");
  symlinkSync(outside, target); // attacker pre-stages a symlink pointing elsewhere
  saveApiKey("mcpk_safe", target);
  assert.equal(loadApiKey(target), "mcpk_safe");
  assert.ok(!existsSync(outside), "must NOT write the key through the symlink to the outside path");
  assert.ok(!lstatSync(target).isSymbolicLink(), "target is now a real file, not the symlink");
});

test("runLogin: full loopback happy path stores the key and binds 127.0.0.1 only", async () => {
  const home = mkdtempSync(join(tmpdir(), "mcpi-home-"));
  const prevHome = process.env.HOME;
  process.env.HOME = home;
  let boundAddress = "";
  try {
    const open = (url: string) => {
      const cb = decodeURIComponent(new URL(url).searchParams.get("cli_callback") ?? "");
      void fetch(`${cb}?key=mcpk_real`).catch(() => {}); // the real callback: correct nonce path + key
    };
    const r = await runLogin({
      webBase: "https://example.test",
      print: () => {},
      open,
      timeoutMs: 4000,
      onListen: (info) => {
        boundAddress = info.address;
      },
    });
    assert.equal(r.apiKey, "mcpk_real");
    assert.equal(boundAddress, "127.0.0.1", "listener MUST bind loopback only (regression to 0.0.0.0 fails here)");
    assert.equal(loadApiKey(join(home, ".mcpindex", "credentials.json")), "mcpk_real", "key persisted under HOME");
  } finally {
    if (prevHome === undefined) delete process.env.HOME;
    else process.env.HOME = prevHome;
  }
});

test("runLogin: an attacker key on the wrong nonce path is ignored; the real key wins", async () => {
  const home = mkdtempSync(join(tmpdir(), "mcpi-home-"));
  const prevHome = process.env.HOME;
  process.env.HOME = home;
  try {
    const open = (url: string) => {
      const cb = decodeURIComponent(new URL(url).searchParams.get("cli_callback") ?? "");
      const u = new URL(cb);
      void fetch(`http://127.0.0.1:${u.port}/?key=mcpk_attacker`).catch(() => {}); // wrong (root) path
      setTimeout(() => void fetch(`${cb}?key=mcpk_real`).catch(() => {}), 60); // correct nonce path
    };
    const r = await runLogin({ webBase: "https://example.test", print: () => {}, open, timeoutMs: 4000 });
    assert.equal(r.apiKey, "mcpk_real", "forged key on the wrong path must be rejected");
  } finally {
    if (prevHome === undefined) delete process.env.HOME;
    else process.env.HOME = prevHome;
  }
});

test("runLogin rejects on timeout when no callback arrives", async () => {
  await assert.rejects(
    runLogin({ webBase: "https://example.test", print: () => {}, open: () => {}, timeoutMs: 150 }),
    /timed out/,
  );
});

test("runLogin rejects a non-http(s) web base (malformed MCPINDEX_WEB_BASE)", async () => {
  await assert.rejects(
    runLogin({ webBase: "ftp://x/evil", print: () => {}, open: () => {}, timeoutMs: 1000 }),
    /web base/i,
  );
});
