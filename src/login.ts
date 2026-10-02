/**
 * `mcpindex login` - self-serve GitHub login that mints a free api_key and stores it.
 *
 * Flow (the gh/vercel-login pattern): start a LOOPBACK http listener on a random port, open the
 * browser to `<web>/api/auth/login/start?cli_callback=http://127.0.0.1:<port>`, the web callback
 * redirects the browser back to the loopback listener with `?key=...`, we capture it, store it at
 * `~/.mcpindex/credentials.json` (mode 0600), and tell the browser to close.
 *
 * The api_key never transits a third party: GitHub sees only the OAuth code; the web mints the
 * key and hands it to THIS machine's loopback. Storage is 0600 so other users can't read it.
 */

import { randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { chmodSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { homedir, platform } from "node:os";
import { dirname, join } from "node:path";

const DEFAULT_WEB_BASE = "https://mcpindex.ai";

/** Self-serve identity providers the web login supports. Default is github. */
export type LoginProvider = "github" | "google";

export function credentialsPath(): string {
  return join(homedir(), ".mcpindex", "credentials.json");
}

/**
 * Persist the api_key (0600). Only the key is stored; never the raw OAuth code/token.
 * Write to a fresh temp file (`wx`, never through a pre-staged symlink) then atomic-rename into
 * place, so the key never lands in a world-readable inode and no partial-write window exists.
 */
export function saveApiKey(apiKey: string, path: string = credentialsPath()): void {
  const dir = dirname(path);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  try {
    chmodSync(dir, 0o700); // tighten even if the dir pre-existed at a wider mode (mkdir mode only applies on create)
  } catch {
    /* best-effort */
  }
  const tmp = `${path}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`;
  try {
    unlinkSync(tmp);
  } catch {
    /* no stale temp - expected */
  }
  try {
    // `wx` = O_CREAT|O_EXCL: fails rather than following a pre-staged symlink/file at `tmp`.
    writeFileSync(tmp, JSON.stringify({ api_key: apiKey }) + "\n", { encoding: "utf8", flag: "wx", mode: 0o600 });
    try {
      chmodSync(tmp, 0o600);
    } catch {
      /* best-effort on platforms without POSIX modes */
    }
    renameSync(tmp, path); // atomic; replaces any pre-existing file/symlink at the destination name
  } catch (e) {
    try {
      unlinkSync(tmp); // never leave a key-bearing temp behind on a failed write/rename
    } catch {
      /* nothing to clean */
    }
    throw e;
  }
}

/** Load the stored api_key, or null if absent/unreadable. */
export function loadApiKey(path: string = credentialsPath()): string | null {
  try {
    const raw = JSON.parse(readFileSync(path, "utf8")) as { api_key?: unknown };
    return typeof raw.api_key === "string" && raw.api_key ? raw.api_key : null;
  } catch {
    return null;
  }
}

/**
 * Extract the minted key from the loopback callback URL, but only if the request path matches the
 * session nonce (`/<state>`). The nonce binds the callback to the login this process started: a
 * webpage the victim has open cannot forge it (it never learns the path), which closes the
 * key-fixation window on a shared loopback port. Returns null on any mismatch/malformed input.
 */
export function extractKeyFromCallback(reqUrl: string, state: string): string | null {
  try {
    const u = new URL(reqUrl, "http://127.0.0.1");
    if (!state || u.pathname !== `/${state}`) return null;
    const key = u.searchParams.get("key");
    return typeof key === "string" && key.startsWith("mcpk_") ? key : null;
  } catch {
    return null;
  }
}

/** A url-safe one-time nonce that rides in the loopback callback path. */
export function newLoginState(): string {
  return randomBytes(24).toString("base64url");
}

/** Parse an optional `--provider <github|google>` from the login args. Returns null on a bad value. */
export function parseProvider(args: string[]): LoginProvider | null {
  const i = args.indexOf("--provider");
  if (i === -1) return "github"; // default
  const v = args[i + 1];
  if (v === "github" || v === "google") return v;
  return null;
}

export function buildStartUrl(
  webBase: string,
  port: number,
  state: string,
  provider: LoginProvider = "github",
): string {
  const cb = encodeURIComponent(`http://127.0.0.1:${port}/${state}`);
  let url = `${webBase.replace(/\/+$/, "")}/api/auth/login/start?cli_callback=${cb}`;
  // The web defaults to github when the param is absent; only append for the non-default provider
  // so the github URL stays byte-for-byte identical (backward-compat).
  if (provider === "google") url += `&provider=google`;
  return url;
}

/** True only for a well-formed http(s) URL. Guards against a malformed MCPINDEX_WEB_BASE. */
function isHttpUrl(s: string): boolean {
  try {
    const u = new URL(s);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

function openBrowser(url: string): void {
  let cmd: string;
  let args: string[];
  if (platform() === "darwin") {
    cmd = "open";
    args = [url];
  } else if (platform() === "win32") {
    // rundll32 FileProtocolHandler opens the default browser WITHOUT routing the URL through
    // cmd.exe's parser (which would interpret &, ^, |, % in the URL). No shell on any platform.
    cmd = "rundll32";
    args = ["url.dll,FileProtocolHandler", url];
  } else {
    cmd = "xdg-open";
    args = [url];
  }
  try {
    spawn(cmd, args, { stdio: "ignore", detached: true }).unref();
  } catch {
    /* headless / no browser -> the caller prints the URL to open manually */
  }
}

export interface LoginResult {
  apiKey: string;
  path: string;
}

/**
 * Run the interactive login. Resolves with the stored key, or rejects on timeout. `print` and
 * `open` are injectable for tests; by default the browser opens automatically.
 */
export function runLogin(
  opts: {
    webBase?: string;
    timeoutMs?: number;
    print?: (msg: string) => void;
    open?: (url: string) => void;
    /** Identity provider to sign in with (default github). */
    provider?: LoginProvider;
    /** Test seam: observe the bound address/port. Purely observational — never changes the bind. */
    onListen?: (info: { address: string; port: number }) => void;
  } = {},
): Promise<LoginResult> {
  const webBase = opts.webBase ?? process.env.MCPINDEX_WEB_BASE ?? DEFAULT_WEB_BASE;
  const provider = opts.provider ?? "github";
  const timeoutMs = opts.timeoutMs ?? 180_000;
  const print = opts.print ?? ((m: string) => process.stderr.write(m + "\n"));
  const open = opts.open ?? openBrowser;

  if (!isHttpUrl(webBase)) {
    return Promise.reject(new Error(`invalid login web base (MCPINDEX_WEB_BASE): ${webBase}`));
  }

  const state = newLoginState();

  return new Promise<LoginResult>((resolve, reject) => {
    let settled = false; // one-shot: guards resolve/reject and the credential write against re-entry

    const server = createServer((req: IncomingMessage, res: ServerResponse) => {
      const key = extractKeyFromCallback(req.url ?? "", state);
      if (!key) {
        res.writeHead(400, { "content-type": "text/plain" });
        res.end("no key");
        return;
      }
      if (settled) {
        // A second valid callback must NOT overwrite the stored key or double-resolve.
        res.writeHead(409, { "content-type": "text/plain" });
        res.end("already completed");
        return;
      }
      settled = true;
      // Save BEFORE claiming success, so a storage failure surfaces as an error page + non-zero
      // exit rather than a "Signed in" page that contradicts a failed CLI.
      try {
        saveApiKey(key);
      } catch (e) {
        cleanup();
        res.writeHead(500, { "content-type": "text/html; charset=utf-8" });
        res.end("<!doctype html><p>Could not store your key. Return to your terminal.</p>");
        reject(e instanceof Error ? e : new Error(String(e)));
        return;
      }
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end("<!doctype html><p>Signed in. You can close this tab and return to your terminal.</p>");
      cleanup();
      print("Signed in. Your mcpindex key is stored.");
      resolve({ apiKey: key, path: credentialsPath() });
    });

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(new Error("login timed out"));
    }, timeoutMs);

    function cleanup(): void {
      clearTimeout(timer);
      server.close();
    }

    server.on("error", (e) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(e);
    });

    // Loopback ONLY: binding all interfaces would make the key listener reachable off-host.
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      const address = typeof addr === "object" && addr ? addr.address : "";
      if (!port) {
        settled = true;
        cleanup();
        reject(new Error("could not bind a loopback port"));
        return;
      }
      opts.onListen?.({ address, port });
      const url = buildStartUrl(webBase, port, state, provider);
      print(`Opening your browser to sign in:\n  ${url}\nIf it does not open, paste that URL into your browser.`);
      open(url);
    });
  });
}
