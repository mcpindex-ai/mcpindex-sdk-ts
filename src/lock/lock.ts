/**
 * Lock format draft 1 (spec/mcp-lock-draft-1.md in mcp-tool-pinning): server
 * identity, the strict reader for `.mcp/lock` and `.mcp/contracts`, and a
 * writer whose bytes match the Python generator (json.dumps indent=2 with
 * ensure_ascii, trailing newline).
 *
 * The reader mirrors mcp_tool_pinning.lockref check for check and in the same
 * order, so a lock with one fault gives the same reason code in both. Every
 * file is read once; the manifest, signature and parse all use those bytes.
 */

import { closeSync, constants, fstatSync, lstatSync, openSync, readSync, readdirSync, realpathSync } from "node:fs";
import { join } from "node:path";

import { canonicalize, compareCodePoints, hasLoneSurrogate, sha256Hex } from "./digest.js";

export const LOCK_VERSION = "1-draft";
export const POSTURES = ["monitor", "guard", "strict"] as const;
export type Posture = (typeof POSTURES)[number];
export const REGISTRIES = ["npm", "pypi", "oci"] as const;
export type Registry = (typeof REGISTRIES)[number];

export const MANIFEST = "MANIFEST.json";
export const SIGNATURE = "MANIFEST.json.sigstore";
export const ALIASES = "aliases.json";
export const SLUG_MAX = 48;
/** Largest manifest sequence; every reader parses it exactly. */
export const SEQUENCE_MAX = Number.MAX_SAFE_INTEGER;

export const SHARD_NAME = /^([a-z0-9]+(?:-[a-z0-9]+)*)--([0-9a-f]{16})\.json$/;
export const CONTRACT_NAME = /^sha256-([0-9a-f]{64})\.json$/;
export const DIGEST_FORM = /^sha256:([0-9a-f]{64})$/;
// ASCII digits only. lockref.py uses \d, which in a Python str pattern also
// matches non-ASCII digits, and its `$` also matches before a final newline.
const RFC3339 = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})$/;
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;

const SHARD_KEYS = new Set(["lockVersion", "identity", "attributes", "instructions", "tools"]);
const ATTRIBUTE_KEYS = new Set(["version", "audience", "command", "args", "env"]);
const ENTRY_KEYS = ["digest", "contract", "approval"];
/** Optional tool entry members (draft 1c). */
const ENTRY_OPTIONAL = ["metaDigest"];
const APPROVAL_KEYS = new Set(["subject", "at", "via", "ref"]);
export const VIA = ["pr", "runtime", "api", "migrated"] as const;
export type Via = (typeof VIA)[number];

/** Whole-lock reason codes, plus `lock-stale` for a snapshot past its age limit. */
export type LockErrorReason =
  | "lock-unreadable"
  | "lock-unsupported"
  | "lock-signature-invalid"
  | "contract-mismatch"
  | "lock-stale";

export class LockError extends Error {
  readonly reason: LockErrorReason;
  readonly detail: string;
  constructor(reason: LockErrorReason, detail: string) {
    super(`${reason}: ${detail}`);
    this.name = "LockError";
    this.reason = reason;
    this.detail = detail;
  }
}

const unreadable = (detail: string): LockError => new LockError("lock-unreadable", detail);
const unsupported = (detail: string): LockError => new LockError("lock-unsupported", detail);

// Small helpers ------------------------------------------------------------

/** Read-only Map view. Snapshots hand these out so a holder cannot edit them. */
export class FrozenMap<K, V> implements ReadonlyMap<K, V> {
  readonly #inner: Map<K, V>;
  constructor(entries: Iterable<readonly [K, V]>) {
    this.#inner = new Map(entries);
    Object.freeze(this);
  }
  get size(): number {
    return this.#inner.size;
  }
  get(key: K): V | undefined {
    return this.#inner.get(key);
  }
  has(key: K): boolean {
    return this.#inner.has(key);
  }
  forEach(fn: (value: V, key: K, map: ReadonlyMap<K, V>) => void): void {
    this.#inner.forEach((v, k) => fn(v, k, this));
  }
  entries(): MapIterator<[K, V]> {
    return this.#inner.entries();
  }
  keys(): MapIterator<K> {
    return this.#inner.keys();
  }
  values(): MapIterator<V> {
    return this.#inner.values();
  }
  [Symbol.iterator](): MapIterator<[K, V]> {
    return this.#inner[Symbol.iterator]();
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function own(obj: Record<string, unknown>, key: string): unknown {
  return Object.getOwnPropertyDescriptor(obj, key)?.value;
}

function hasOwn(obj: Record<string, unknown>, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(obj, key);
}

function isAscii(text: string): boolean {
  return /^[\x00-\x7f]*$/.test(text);
}

function sortedKeys(obj: Record<string, unknown>): string[] {
  return Object.keys(obj).sort(compareCodePoints);
}

function repr(value: unknown): string {
  try {
    return JSON.stringify(value) ?? String(value);
  } catch {
    return String(value);
  }
}

// Identity -----------------------------------------------------------------

export type RemoteIdentity = { readonly kind: "remote"; readonly url: string };
export type PackageIdentity = { readonly kind: "stdio"; readonly package: string };
export type CommandIdentity = { readonly kind: "stdio"; readonly command: string; readonly args: readonly string[] };
export type Identity = RemoteIdentity | PackageIdentity | CommandIdentity;

const DEFAULT_PORTS: Record<string, number> = { http: 80, https: 443 };

interface SplitUrl {
  scheme: string;
  netloc: string;
  path: string;
}

/** The parts of Python's urllib.parse.urlsplit that section 3.1 needs. */
function splitUrl(raw: string): SplitUrl {
  // urlsplit strips leading C0 controls and spaces and drops tab, CR and LF.
  const url = raw.replace(/^[\x00-\x20]+/, "").replace(/[\t\r\n]/g, "");
  let rest = url;
  let scheme = "";
  const colon = url.indexOf(":");
  if (colon > 0 && /^[A-Za-z][A-Za-z0-9+.-]*$/.test(url.slice(0, colon))) {
    scheme = url.slice(0, colon).toLowerCase();
    rest = url.slice(colon + 1);
  }
  let netloc = "";
  if (rest.startsWith("//")) {
    const after = rest.slice(2);
    const end = after.search(/[/?#]/);
    netloc = end === -1 ? after : after.slice(0, end);
    rest = end === -1 ? "" : after.slice(end);
    if (netloc.includes("[") !== netloc.includes("]")) throw new Error("invalid IPv6 URL");
  }
  const cut = rest.search(/[?#]/);
  const path = cut === -1 ? rest : rest.slice(0, cut);
  return { scheme, netloc, path };
}

function hostAndPort(netloc: string): { host: string; port: number | null } {
  const hostinfo = netloc.slice(netloc.lastIndexOf("@") + 1);
  let host: string;
  let portText: string;
  if (hostinfo.startsWith("[")) {
    const close = hostinfo.indexOf("]");
    if (close === -1) throw new Error("invalid IPv6 URL");
    host = hostinfo.slice(1, close);
    if (!/^[0-9A-Fa-f:.]+(%.+)?$/.test(host) || !host.includes(":")) {
      throw new Error("invalid IPv6 literal");
    }
    const tail = hostinfo.slice(close + 1);
    portText = tail.startsWith(":") ? tail.slice(1) : "";
  } else {
    const c = hostinfo.indexOf(":");
    host = c === -1 ? hostinfo : hostinfo.slice(0, c);
    portText = c === -1 ? "" : hostinfo.slice(c + 1);
  }
  host = host.toLowerCase();
  if (portText === "") return { host, port: null };
  if (!/^[0-9]+$/.test(portText)) throw new Error(`invalid port ${repr(portText)}`);
  const port = Number(portText);
  if (port > 65535) throw new Error("port out of range");
  return { host, port };
}

/** Section 3.1. Throws Error on a URL that cannot be an identity. */
export function normalizeUrl(url: string): string {
  if (!isAscii(url)) throw new Error("URL must be ASCII; convert the host to its A-label first");
  const parts = splitUrl(url);
  const scheme = parts.scheme;
  if (!(scheme in DEFAULT_PORTS)) throw new Error(`unsupported scheme ${repr(scheme)}`);
  const { host, port } = hostAndPort(parts.netloc);
  if (host === "") throw new Error("URL has no host");
  const shownHost = host.includes(":") ? `[${host}]` : host;
  const netloc = port === null || port === DEFAULT_PORTS[scheme] ? shownHost : `${shownHost}:${port}`;
  return `${scheme}://${netloc}${parts.path}`;
}

function validPackageName(name: string): boolean {
  return name.length > 0 && /^[\x21-\x7e]+$/.test(name);
}

function validCommand(name: string): boolean {
  return validPackageName(name) && !name.includes("/") && !name.includes("\\") && name !== "." && name !== "..";
}

export function remoteIdentity(url: string): RemoteIdentity {
  return { kind: "remote", url: normalizeUrl(url) };
}

export function packageIdentity(registry: string, name: string): PackageIdentity {
  if (!(REGISTRIES as readonly string[]).includes(registry)) throw new Error(`unknown registry ${repr(registry)}`);
  let n = name;
  if (registry === "pypi") {
    n = n.replace(/[-_.]+/g, "-").toLowerCase();
  } else if (registry === "oci") {
    const at = n.indexOf("@");
    if (at !== -1) n = n.slice(0, at);
    const slash = n.lastIndexOf("/");
    const head = slash === -1 ? "" : n.slice(0, slash);
    let last = slash === -1 ? n : n.slice(slash + 1);
    const colon = last.indexOf(":");
    if (colon !== -1) last = last.slice(0, colon);
    n = ((head ? `${head}/` : "") + last).toLowerCase();
  }
  if (!validPackageName(n)) throw new Error(`invalid package name ${repr(n)}`);
  return { kind: "stdio", package: `${registry}:${n}` };
}

/**
 * Section 3.2 command form: the basename of the command and every argument
 * verbatim. Throws for a command that is not a basename once its path is
 * removed, and for secret-looking arguments (section 3.2.1), which an identity
 * can neither keep nor strip. The message names the rule, never the value.
 */
export function commandIdentity(command: string, args: readonly string[] = []): CommandIdentity {
  const parts = command.replace(/\\/g, "/").split("/");
  const base = parts[parts.length - 1] ?? "";
  if (!validCommand(base)) throw new Error(`invalid command ${repr(command)}`);
  if (!Array.isArray(args) || !args.every((a) => typeof a === "string" && !hasLoneSurrogate(a))) {
    throw new Error("args must be strings without unpaired surrogates");
  }
  const problem = secretArgProblem(args);
  if (problem !== null) {
    throw new Error(`cannot form a server identity: ${problem}; move it to an env var or configure an alias`);
  }
  return Object.freeze({ kind: "stdio", command: base, args: Object.freeze([...args]) });
}

// Section 3.2.1. ASCII-only and case-insensitive; without the u flag, \b and
// the i flag work on ASCII only, as in the Python port with re.ASCII.
const SECRET_SEGMENTS = new Set([
  "token", "secret", "password", "passwd", "pwd", "apikey", "auth", "authorization",
  "credential", "credentials", "bearer", "cookie", "key", "pat", "privatekey", "session",
]);
const SECRET_VALUE = new RegExp(
  [
    "^(bearer|basic|token)[ \\t]+[^ \\t]",
    "\\bsk-[A-Za-z0-9_-]{16,}",
    "\\bsk_(live|test)_[A-Za-z0-9]{10,}",
    "\\bgh[pousr]_[A-Za-z0-9]{20,}",
    "\\bgithub_pat_[A-Za-z0-9_]{20,}",
    "\\bglpat-[A-Za-z0-9_-]{16,}",
    "\\bxox[abprs]-[A-Za-z0-9-]{10,}",
    "\\bAKIA[0-9A-Z]{16}\\b",
    "\\bAIza[0-9A-Za-z_-]{30,}",
    "\\bnpm_[A-Za-z0-9]{30,}",
    "-----BEGIN [A-Z ]*PRIVATE KEY",
    "\\beyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.",
  ].join("|"),
  "i",
);

function secretName(name: string): boolean {
  const segments = name.replace(/^-+/, "").toLowerCase().split(/[-_.]+/);
  return segments.some((s) => SECRET_SEGMENTS.has(s)) || SECRET_SEGMENTS.has(segments.join(""));
}

function urlProblem(arg: string): string | null {
  const at = arg.indexOf("://");
  if (at === -1) return null;
  const rest = arg.slice(at + 3);
  const end = rest.search(/[/?#]/);
  const authority = end === -1 ? rest : rest.slice(0, end);
  const lastAt = authority.lastIndexOf("@");
  if (lastAt !== -1 && authority.slice(0, lastAt).includes(":")) return "a URL argument carries a password in its userinfo";
  const q = rest.indexOf("?");
  if (q !== -1) {
    const hash = rest.indexOf("#", q);
    const query = rest.slice(q + 1, hash === -1 ? undefined : hash);
    for (const part of query.split("&")) {
      const eq = part.indexOf("=");
      if (secretName(eq === -1 ? part : part.slice(0, eq))) return "a URL argument carries a credential in its query";
    }
  }
  return null;
}

/** null if no argument is secret-looking under section 3.2.1, else what was found. */
export function secretArgProblem(args: readonly string[]): string | null {
  let valueOf: string | null = null;
  for (const arg of args) {
    if (valueOf !== null && !arg.startsWith("-")) return `the value of ${valueOf} looks like a credential`;
    valueOf = null;
    if (SECRET_VALUE.test(arg)) return "an argument matches a credential pattern";
    const url = urlProblem(arg);
    if (url !== null) return url;
    const eq = arg.indexOf("=");
    const head = eq === -1 ? arg : arg.slice(0, eq);
    if (arg.startsWith("-")) {
      if (secretName(head)) {
        if (eq !== -1 && arg.length > eq + 1) return `${head} carries a credential`;
        if (eq === -1) valueOf = head;
      }
      continue;
    }
    if (eq !== -1 && ENV_NAME.test(head) && secretName(head)) return `${head}= carries a credential`;
  }
  return null;
}

/** Validate a parsed identity object. Returns a fresh frozen copy or throws LockError. */
export function validateIdentity(value: unknown): Identity {
  if (!isObject(value)) throw unreadable("identity must be an object");
  const keys = Object.keys(value);
  if (!keys.every((k) => k === "args" || typeof own(value, k) === "string")) {
    throw unreadable("identity members must be strings, args an array of strings");
  }
  const has = (...names: string[]): boolean => keys.length === names.length && names.every((n) => keys.includes(n));
  const kind = own(value, "kind");
  if (kind === "remote") {
    if (!has("kind", "url")) throw unsupported(`remote identity members ${repr(keys.sort())}`);
    const url = own(value, "url") as string;
    let ok: boolean;
    try {
      ok = normalizeUrl(url) === url;
    } catch {
      ok = false;
    }
    if (!ok) throw unreadable(`identity url is not normalized: ${repr(url)}`);
    return Object.freeze({ kind: "remote", url });
  }
  if (kind === "stdio") {
    if (has("kind", "package")) {
      const pkg = own(value, "package") as string;
      const colon = pkg.indexOf(":");
      const registry = colon === -1 ? pkg : pkg.slice(0, colon);
      const name = colon === -1 ? "" : pkg.slice(colon + 1);
      if (!(REGISTRIES as readonly string[]).includes(registry) || !validPackageName(name)) {
        throw unreadable(`invalid package ${repr(pkg)}`);
      }
      return Object.freeze({ kind: "stdio", package: pkg });
    }
    if (has("kind", "command", "args")) {
      const command = own(value, "command") as string;
      const args = own(value, "args");
      if (!Array.isArray(args) || !args.every((a) => typeof a === "string")) {
        throw unreadable("identity args must be an array of strings");
      }
      let derived: CommandIdentity;
      try {
        derived = commandIdentity(command, args as string[]);
      } catch {
        throw unreadable("identity command is not a basename, or its args cannot form an identity");
      }
      if (derived.command !== command) throw unreadable(`command must be a basename: ${repr(command)}`);
      return derived;
    }
    throw unsupported(`stdio identity members ${repr(keys.sort())}`);
  }
  throw unsupported(`identity kind ${repr(kind)}`);
}

function identityFields(identity: Identity): Array<[string, string | readonly string[]]> {
  if (identity.kind === "remote") return [["kind", "remote"], ["url", identity.url]];
  if ("package" in identity) return [["kind", "stdio"], ["package", identity.package]];
  return [["kind", "stdio"], ["command", identity.command], ["args", identity.args]];
}

/** RFC 8785 text of the identity (section 3.3). Compare identities by this string. */
export function identityKey(identity: Identity): string {
  const obj: Record<string, string | readonly string[]> = Object.create(null) as Record<string, string | readonly string[]>;
  for (const [k, v] of identityFields(identity)) obj[k] = v;
  return canonicalize(obj);
}

export function identityH16(identity: Identity): string {
  return sha256Hex(identityKey(identity)).slice(0, 16);
}

export function slug(identity: Identity): string {
  let source: string;
  if (identity.kind === "remote") {
    const parts = splitUrl(identity.url);
    let host = "";
    try {
      host = hostAndPort(parts.netloc).host;
    } catch {
      host = "";
    }
    source = host + parts.path;
  } else if ("package" in identity) {
    const pkg = identity.package;
    const colon = pkg.indexOf(":");
    source = colon === -1 ? "" : pkg.slice(colon + 1);
  } else {
    source = identity.command;
  }
  // Python str.lower() also folds non-ASCII letters, but they are then replaced
  // by `-` with everything else outside a-z0-9, so the result is the same.
  const text = source.toLowerCase().replace(/[^a-z0-9]+/g, "-");
  const cut = text.replace(/^-+|-+$/g, "").slice(0, SLUG_MAX).replace(/-+$/, "");
  return cut || "server";
}

export function shardFilename(identity: Identity): string {
  return `${slug(identity)}--${identityH16(identity)}.json`;
}

// Strict JSON --------------------------------------------------------------

const UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/**
 * Find a member name repeated within one object. JSON.parse keeps the last
 * value silently, so this scans the text, which JSON.parse has already
 * accepted, and compares decoded names (so "a" and "a" collide).
 */
/**
 * Section 4.3: every number in a lock file is an integer token. JSON.parse
 * turns 1.0 and 1e0 into 1, so the raw text is checked. Returns the first
 * offending token, or null. Outside strings, a number is the only token that
 * starts with `-` or a digit.
 */
export function findNonIntegerNumber(text: string): string | null {
  let i = 0;
  while (i < text.length) {
    const ch = text[i] as string;
    if (ch === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"') j += text[j] === "\\" ? 2 : 1;
      i = j + 1;
      continue;
    }
    if (ch === "-" || (ch >= "0" && ch <= "9")) {
      let j = i + 1;
      while (j < text.length && /[0-9.eE+-]/.test(text[j] as string)) j++;
      const token = text.slice(i, j);
      if (!/^-?[0-9]+$/.test(token)) return token;
      i = j;
      continue;
    }
    i++;
  }
  return null;
}

export function findDuplicateKey(text: string): string | null {
  const stack: Array<{ keys: Set<string> | null; expectKey: boolean }> = [];
  let i = 0;
  while (i < text.length) {
    const ch = text[i];
    if (ch === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"') j += text[j] === "\\" ? 2 : 1;
      const top = stack[stack.length - 1];
      if (top !== undefined && top.keys !== null && top.expectKey) {
        const key = JSON.parse(text.slice(i, j + 1)) as string;
        if (top.keys.has(key)) return key;
        top.keys.add(key);
        top.expectKey = false;
      }
      i = j + 1;
      continue;
    }
    if (ch === "{") stack.push({ keys: new Set(), expectKey: true });
    else if (ch === "[") stack.push({ keys: null, expectKey: false });
    else if (ch === "}" || ch === "]") stack.pop();
    else if (ch === ",") {
      const top = stack[stack.length - 1];
      if (top !== undefined && top.keys !== null) top.expectKey = true;
    }
    i++;
  }
  return null;
}

/**
 * Parse lock file bytes: UTF-8 (a BOM is kept and so rejected), JSON, no repeated
 * member names, integer number tokens only. JSON.parse has no NaN or Infinity,
 * so that rule needs no code.
 */
export function strictJson(data: Uint8Array, what: string): unknown {
  let text: string;
  try {
    text = UTF8.decode(data);
  } catch {
    throw unreadable(`${what}: not UTF-8`);
  }
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch (exc) {
    throw unreadable(`${what}: ${(exc as Error).message}`);
  }
  const dup = findDuplicateKey(text);
  if (dup !== null) throw unreadable(`${what}: duplicate member name ${repr(dup)}`);
  const num = findNonIntegerNumber(text);
  if (num !== null) throw unreadable(`${what}: number ${num} is not an integer token`);
  return value;
}

// Parsed lock --------------------------------------------------------------

export interface Approval {
  readonly subject: string;
  readonly at: string;
  readonly via: Via;
  readonly ref?: string;
}

export interface ToolEntry {
  readonly digest: string;
  readonly contract: string;
  /** Digest of the top-level `_meta` approved with the tool, when it had one. */
  readonly metaDigest?: string;
  readonly approval: Approval;
}

export interface Attributes {
  readonly version?: string;
  readonly audience?: string;
  readonly command?: string;
  readonly args?: readonly string[];
  readonly env?: readonly string[];
}

export interface Shard {
  readonly identity: Identity;
  readonly attributes: Attributes | null;
  /** Instructions digest, or null when the shard has none. */
  readonly instructions: string | null;
  /** Tool name to entry, in file order. */
  readonly tools: ReadonlyMap<string, ToolEntry>;
}

export interface Lock {
  /** Identity key to shard. */
  readonly shards: ReadonlyMap<string, Shard>;
  readonly aliases: ReadonlyMap<string, Identity>;
  /** Manifest sequence, or null without a manifest. */
  readonly sequence: number | null;
}

export interface SignerIdentity {
  /** Certificate issuer, compared exactly. */
  readonly issuer: string;
  /** Certificate subject alternative name, compared exactly. */
  readonly san: string;
}

/** Verifies a Sigstore bundle over the exact manifest bytes. Any throw counts as false. */
export interface ManifestVerifier {
  verify(manifest: Uint8Array, bundle: Uint8Array, signer: SignerIdentity): Promise<boolean>;
}

/** Host configuration. Never read from the lock repository or the environment. */
export interface ReaderConfig {
  readonly requireManifest?: boolean;
  readonly signer?: SignerIdentity | null;
  /**
   * Section 8.2: true when the host keeps a sequence store. Required with a
   * signer; `lastSequence` is the floor read from it (null when it holds none).
   */
  readonly sequenceStore?: boolean;
  readonly lastSequence?: number | null;
  readonly verifier?: ManifestVerifier | null;
}

// File access --------------------------------------------------------------

function errCode(exc: unknown): string {
  return exc !== null && typeof exc === "object" && "code" in exc ? String((exc as { code: unknown }).code) : "";
}

/** A directory as it was when checked: its path, where it really is, and its dev/ino. */
interface DirStamp {
  readonly path: string;
  readonly real: string;
  readonly dev: number;
  readonly ino: number;
}

function checkDir(path: string, name: string, required: boolean): DirStamp | null {
  let st;
  try {
    st = lstatSync(path);
  } catch (exc) {
    if (errCode(exc) === "ENOENT") {
      if (required) throw unreadable(`${name} is missing`);
      return null;
    }
    throw unreadable(`${name}: ${errCode(exc) || "unreadable"}`);
  }
  if (st.isSymbolicLink() || !st.isDirectory()) throw unreadable(`${name} is not a plain directory`);
  let real: string;
  try {
    real = realpathSync(path);
  } catch (exc) {
    throw unreadable(`${name}: ${errCode(exc) || "unreadable"}`);
  }
  return { path, real, dev: st.dev, ino: st.ino };
}

/**
 * O_NOFOLLOW guards only the last path component. After a file is open, check
 * that its directory is still the plain directory that was checked (same
 * dev/ino, same real path) and that the open file is the entry of that name
 * in it. A directory swapped for a symlink between the check and the open, or
 * swapped back after it, is refused.
 */
function confirmInDir(fd: number, dir: DirStamp, entry: string, name: string): void {
  const moved = (): LockError => unreadable(`${name}: its directory changed while it was read`);
  let st;
  let real: string;
  let inDir;
  try {
    st = lstatSync(dir.path);
    real = realpathSync(dir.path);
    inDir = lstatSync(join(real, entry));
  } catch {
    throw moved();
  }
  if (st.isSymbolicLink() || !st.isDirectory() || st.dev !== dir.dev || st.ino !== dir.ino || real !== dir.real) {
    throw moved();
  }
  const fst = fstatSync(fd);
  if (inDir.dev !== fst.dev || inDir.ino !== fst.ino) throw moved();
}

class MissingFile extends Error {}

/**
 * lstat, then open with O_NOFOLLOW, check the directory (confirmInDir) and
 * fstat the descriptor, then read it once.
 */
function readRegular(dir: DirStamp, entry: string, name: string): Buffer {
  const path = join(dir.path, entry);
  let st;
  try {
    st = lstatSync(path);
  } catch (exc) {
    if (errCode(exc) === "ENOENT") throw new MissingFile(name);
    throw unreadable(`${name}: ${errCode(exc) || "unreadable"}`);
  }
  if (st.isSymbolicLink() || !st.isFile()) throw unreadable(`${name} is not a regular file`);
  let flags = constants.O_RDONLY;
  if (typeof constants.O_NOFOLLOW === "number") flags |= constants.O_NOFOLLOW;
  let fd: number;
  try {
    fd = openSync(path, flags);
  } catch (exc) {
    if (errCode(exc) === "ENOENT") throw new MissingFile(name);
    throw unreadable(`${name} is not a regular file (${errCode(exc)})`);
  }
  try {
    const fst = fstatSync(fd);
    if (!fst.isFile()) throw unreadable(`${name} is not a regular file`);
    confirmInDir(fd, dir, entry, name);
    const chunks: Buffer[] = [];
    const buf = Buffer.alloc(64 * 1024);
    for (;;) {
      const n = readSync(fd, buf, 0, buf.length, null);
      if (n === 0) break;
      chunks.push(Buffer.from(buf.subarray(0, n)));
    }
    return Buffer.concat(chunks);
  } finally {
    closeSync(fd);
  }
}

/** Every file in `.mcp/lock`, read once. Names are checked as raw bytes for ASCII. */
export function readLockDir(lockDir: string): Map<string, Buffer> {
  return readLockFiles(checkDir(lockDir, ".mcp/lock", true) as DirStamp);
}

function readLockFiles(dir: DirStamp): Map<string, Buffer> {
  const lockDir = dir.path;
  const names = readdirSync(lockDir, { encoding: "buffer" });
  for (const raw of names) {
    if (raw.some((b) => b > 0x7f)) throw unreadable(`non-ASCII filename ${repr(raw.toString("utf8"))}`);
  }
  const ascii = names.map((b) => b.toString("latin1")).sort(compareCodePoints);
  const files = new Map<string, Buffer>();
  for (const name of ascii) {
    const shard = SHARD_NAME.exec(name);
    if (!(name === MANIFEST || name === SIGNATURE || name === ALIASES || (shard !== null && (shard[1] as string).length <= SLUG_MAX))) {
      throw unreadable(`unexpected file ${repr(name)}`);
    }
    try {
      files.set(name, readRegular(dir, name, name));
    } catch (exc) {
      if (exc instanceof MissingFile) throw unreadable(`${name} vanished while reading`);
      throw exc;
    }
  }
  return files;
}

// Checks -------------------------------------------------------------------

/** Section 8.2 steps 1 and 2: with a signer configured, both files and a good signature. */
async function verifySignature(files: ReadonlyMap<string, Buffer>, config: ReaderConfig): Promise<boolean> {
  const signer = config.signer ?? null;
  if (signer === null) return false;
  if (config.sequenceStore !== true) {
    throw new LockError("lock-signature-invalid", "a signer is configured but the host config names no sequence store");
  }
  const raw = files.get(MANIFEST);
  if (raw === undefined) throw new LockError("lock-signature-invalid", "signer configured but no MANIFEST.json");
  const bundle = files.get(SIGNATURE);
  const verifier = config.verifier ?? null;
  let ok = false;
  if (bundle !== undefined && verifier !== null) {
    try {
      ok = (await verifier.verify(raw, bundle, signer)) === true;
    } catch {
      ok = false;
    }
  }
  if (!ok) throw new LockError("lock-signature-invalid", "MANIFEST.json signature missing or invalid");
  return true;
}

/** Section 8.1 and 8.2 step 3. `signed` says the signature over these bytes was verified. */
function checkManifest(files: ReadonlyMap<string, Buffer>, config: ReaderConfig, signed: boolean): number | null {
  const raw = files.get(MANIFEST);
  if (raw === undefined) {
    if (config.requireManifest) throw unreadable("MANIFEST.json required by host configuration");
    return null;
  }
  const manifest = strictJson(raw, MANIFEST);
  if (!isObject(manifest)) throw unreadable("MANIFEST.json is not an object");
  if (own(manifest, "lockVersion") !== LOCK_VERSION) {
    throw unsupported(`MANIFEST.json lockVersion ${repr(own(manifest, "lockVersion"))}`);
  }
  if (Object.keys(manifest).some((k) => !["lockVersion", "sequence", "files"].includes(k))) {
    throw unsupported(`MANIFEST.json members ${repr(sortedKeys(manifest))}`);
  }
  const sequence = own(manifest, "sequence");
  const listed = own(manifest, "files");
  // strictJson already refused 1.0 and 1e0 in the raw text (section 4.3).
  if (typeof sequence !== "number" || !Number.isSafeInteger(sequence) || sequence < 0 || sequence > SEQUENCE_MAX || !isObject(listed)) {
    throw unreadable("MANIFEST.json sequence or files malformed");
  }
  const last = config.lastSequence ?? null;
  if (signed && last !== null && sequence < last) {
    throw new LockError("lock-signature-invalid", `sequence ${sequence} < ${last}`);
  }
  const onDisk = [...files.keys()].filter((n) => n !== MANIFEST && n !== SIGNATURE);
  const listedNames = Object.keys(listed);
  const diff = [
    ...onDisk.filter((n) => !hasOwn(listed, n)),
    ...listedNames.filter((n) => !files.has(n) || n === MANIFEST || n === SIGNATURE),
  ];
  if (diff.length > 0) throw unreadable(`file set differs from MANIFEST.json: ${repr(diff.sort(compareCodePoints))}`);
  for (const name of onDisk.sort(compareCodePoints)) {
    if (own(listed, name) !== "sha256:" + sha256Hex(files.get(name) as Buffer)) {
      throw unreadable(`${name} does not match MANIFEST.json`);
    }
  }
  return sequence;
}

function checkAliases(raw: Buffer): Map<string, Identity> {
  const doc = strictJson(raw, ALIASES);
  if (!isObject(doc)) throw unreadable("aliases.json is not an object");
  if (own(doc, "lockVersion") !== LOCK_VERSION) {
    throw unsupported(`aliases.json lockVersion ${repr(own(doc, "lockVersion"))}`);
  }
  const keys = Object.keys(doc);
  if (keys.length !== 2 || !keys.includes("lockVersion") || !keys.includes("aliases")) {
    throw unsupported(`aliases.json members ${repr(sortedKeys(doc))}`);
  }
  const aliases = own(doc, "aliases");
  if (!isObject(aliases)) throw unreadable("aliases must be an object");
  const out = new Map<string, Identity>();
  for (const name of Object.keys(aliases)) out.set(name, validateIdentity(own(aliases, name)));
  return out;
}

function checkAttributes(attributes: unknown): Attributes {
  if (!isObject(attributes)) throw unreadable("attributes must be an object");
  const keys = Object.keys(attributes);
  if (keys.some((k) => !ATTRIBUTE_KEYS.has(k))) throw unsupported(`attributes members ${repr(sortedKeys(attributes))}`);
  const out: { -readonly [K in keyof Attributes]: Attributes[K] } = {};
  for (const key of ["version", "audience", "command"] as const) {
    if (hasOwn(attributes, key)) {
      const v = own(attributes, key);
      if (typeof v !== "string") throw unreadable(`attributes.${key} must be a string`);
      out[key] = v;
    }
  }
  for (const key of ["args", "env"] as const) {
    const v = hasOwn(attributes, key) ? own(attributes, key) : [];
    if (!Array.isArray(v) || !v.every((s) => typeof s === "string")) {
      throw unreadable(`attributes.${key} must be an array of strings`);
    }
    if (hasOwn(attributes, key)) out[key] = Object.freeze([...(v as string[])]);
  }
  if (!(out.env ?? []).every((v) => ENV_NAME.test(v))) throw unreadable("attributes.env holds names only");
  return Object.freeze(out);
}

/** Section 6 binding: contract filename, presence, and sha256 of the bytes. */
export type ContractReader = (filename: string) => Buffer | null;

function checkEntry(name: string, entry: unknown, readContract: ContractReader): ToolEntry {
  const label = repr(name);
  if (!isObject(entry)) throw unreadable(`tool ${label} entry is not an object`);
  const keys = Object.keys(entry);
  if (keys.some((k) => !ENTRY_KEYS.includes(k) && !ENTRY_OPTIONAL.includes(k))) throw unsupported(`tool ${label} members ${repr(sortedKeys(entry))}`);
  if (!ENTRY_KEYS.every((k) => hasOwn(entry, k))) {
    throw unreadable(`tool ${label} lacks ${repr(ENTRY_KEYS.filter((k) => !hasOwn(entry, k)).sort())}`);
  }
  const approval = own(entry, "approval");
  if (!isObject(approval)) throw unreadable(`tool ${label} approval is not an object`);
  if (Object.keys(approval).some((k) => !APPROVAL_KEYS.has(k))) {
    throw unsupported(`tool ${label} approval members ${repr(sortedKeys(approval))}`);
  }
  const subject = own(approval, "subject");
  const at = own(approval, "at");
  const via = own(approval, "via");
  if (typeof subject !== "string" || typeof at !== "string" || typeof via !== "string") {
    throw unreadable(`tool ${label} approval lacks subject, at or via`);
  }
  const ref = own(approval, "ref");
  if (hasOwn(approval, "ref") && typeof ref !== "string") throw unreadable(`tool ${label} approval ref must be a string`);
  if (!RFC3339.test(at)) throw unreadable(`tool ${label} approval time is not RFC 3339`);
  if (!(VIA as readonly string[]).includes(via)) throw unsupported(`tool ${label} approval via ${repr(via)}`);
  const digest = own(entry, "digest");
  const contract = own(entry, "contract");
  const m = typeof digest === "string" ? DIGEST_FORM.exec(digest) : null;
  if (m === null) throw unreadable(`tool ${label} digest malformed`);
  if (typeof contract !== "string" || !CONTRACT_NAME.test(contract)) {
    throw unreadable(`tool ${label} contract is not a contract filename: ${repr(contract)}`);
  }
  const hex = m[1] as string;
  if (contract !== `sha256-${hex}.json`) {
    throw new LockError("contract-mismatch", `tool ${label} contract filename differs from digest`);
  }
  const meta = own(entry, "metaDigest");
  if (hasOwn(entry, "metaDigest") && (typeof meta !== "string" || !DIGEST_FORM.test(meta))) {
    throw unreadable(`tool ${label} metaDigest malformed`);
  }
  const data = readContract(contract);
  if (data === null) throw new LockError("contract-mismatch", `tool ${label} contract file missing`);
  if (sha256Hex(data) !== hex) throw new LockError("contract-mismatch", `tool ${label} contract bytes differ from digest`);
  const appr: Approval =
    typeof ref === "string"
      ? Object.freeze({ subject, at, via: via as Via, ref })
      : Object.freeze({ subject, at, via: via as Via });
  return typeof meta === "string"
    ? Object.freeze({ digest: digest as string, contract, metaDigest: meta, approval: appr })
    : Object.freeze({ digest: digest as string, contract, approval: appr });
}

/** Parse and check one shard (section 5). `filename` must already match SHARD_NAME. */
export function parseShard(filename: string, raw: Uint8Array, readContract: ContractReader): Shard {
  const doc = strictJson(raw, filename);
  if (!isObject(doc)) throw unreadable(`${filename} is not an object`);
  if (!hasOwn(doc, "lockVersion")) throw unreadable(`${filename} has no lockVersion`);
  if (own(doc, "lockVersion") !== LOCK_VERSION) {
    throw unsupported(`${filename} lockVersion ${repr(own(doc, "lockVersion"))}`);
  }
  const extra = Object.keys(doc).filter((k) => !SHARD_KEYS.has(k));
  if (extra.length > 0) throw unsupported(`${filename} members ${repr(extra.sort(compareCodePoints))}`);
  if (!hasOwn(doc, "identity") || !hasOwn(doc, "tools")) throw unreadable(`${filename} lacks identity or tools`);
  const identity = validateIdentity(own(doc, "identity"));
  const match = SHARD_NAME.exec(filename);
  if (match === null) throw unreadable(`${filename} is not a shard filename`);
  if (identityH16(identity) !== match[2]) throw unreadable(`${filename} identity does not hash to its filename`);
  const attributes = hasOwn(doc, "attributes") ? checkAttributes(own(doc, "attributes")) : null;
  let instructions: string | null = null;
  if (hasOwn(doc, "instructions")) {
    const block = own(doc, "instructions");
    if (!isObject(block)) throw unreadable(`${filename} instructions is not an object`);
    if (Object.keys(block).some((k) => k !== "digest")) {
      throw unsupported(`${filename} instructions members ${repr(sortedKeys(block))}`);
    }
    const d = own(block, "digest");
    if (typeof d !== "string" || !DIGEST_FORM.test(d)) throw unreadable(`${filename} instructions digest malformed`);
    instructions = d;
  }
  const tools = own(doc, "tools");
  if (!isObject(tools)) throw unreadable(`${filename} tools is not an object`);
  const entries: Array<[string, ToolEntry]> = [];
  for (const name of Object.keys(tools)) entries.push([name, checkEntry(name, own(tools, name), readContract)]);
  return Object.freeze({ identity, attributes, instructions, tools: new FrozenMap(entries) });
}

export interface LoadedLock {
  readonly lock: Lock;
  /** sha256 over the sorted (name, sha256) list of every file in `.mcp/lock`. */
  readonly snapshotId: string;
}

/** Hash of the lock directory contents; contracts are bound through the shards. */
export function lockFilesId(files: ReadonlyMap<string, Uint8Array>): string {
  let text = "";
  for (const name of [...files.keys()].sort(compareCodePoints)) {
    text += `${name}\u0000${sha256Hex(files.get(name) as Uint8Array)}\n`;
  }
  return "sha256:" + sha256Hex(text);
}

interface LockBytes {
  readonly files: Map<string, Buffer>;
  readonly readContract: ContractReader;
}

/** Directory checks and one read of every file in `.mcp/lock`. */
function readLockBytes(root: string): LockBytes {
  const mcp = join(root, ".mcp");
  checkDir(mcp, ".mcp", true);
  const lockDir = checkDir(join(mcp, "lock"), ".mcp/lock", true) as DirStamp;
  const contractsDir = checkDir(join(mcp, "contracts"), ".mcp/contracts", false);
  const files = readLockFiles(lockDir);
  const readContract: ContractReader = (filename) => {
    if (contractsDir === null) return null;
    try {
      return readRegular(contractsDir, filename, filename);
    } catch (exc) {
      if (exc instanceof MissingFile) return null;
      throw exc;
    }
  };
  return { files, readContract };
}

function parseLock(bytes: LockBytes, config: ReaderConfig, signed: boolean): LoadedLock {
  const { files, readContract } = bytes;
  const sequence = checkManifest(files, config, signed);
  const aliasBytes = files.get(ALIASES);
  const aliases = aliasBytes !== undefined ? checkAliases(aliasBytes) : new Map<string, Identity>();
  const shards = new Map<string, Shard>();
  for (const name of [...files.keys()].sort(compareCodePoints)) {
    if (!SHARD_NAME.test(name)) continue;
    const shard = parseShard(name, files.get(name) as Buffer, readContract);
    const key = identityKey(shard.identity);
    if (shards.has(key)) throw unreadable(`two shards for one identity: ${name}`);
    shards.set(key, shard);
  }
  const lock: Lock = Object.freeze({
    shards: new FrozenMap(shards),
    aliases: new FrozenMap(aliases),
    sequence,
  });
  return Object.freeze({ lock, snapshotId: lockFilesId(files) });
}

/** Read and verify the whole lock under `root`. Any failure throws LockError. */
export async function loadLock(root: string, config: ReaderConfig = {}): Promise<LoadedLock> {
  const bytes = readLockBytes(root);
  const signed = await verifySignature(bytes.files, config);
  return parseLock(bytes, config, signed);
}

/**
 * Synchronous read for writers holding the file lock. Refuses a config with a
 * signer, since signature checks are asynchronous; a writer does not need them.
 */
export function loadLockSync(root: string, config: ReaderConfig = {}): LoadedLock {
  if ((config.signer ?? null) !== null) throw new Error("loadLockSync does not verify signatures");
  return parseLock(readLockBytes(root), config, false);
}

/** The identity an alias names, if the lock maps it. */
export function resolveAlias(lock: Lock, alias: string): Identity | null {
  return lock.aliases.get(alias) ?? null;
}

// Writer -------------------------------------------------------------------

/** An ordered JSON object for the writer: entries are written in this order. */
export type Ordered = { readonly entries: ReadonlyArray<readonly [string, WriterValue]> };
export type WriterValue = null | boolean | number | string | readonly WriterValue[] | Ordered;

function ordered(entries: Array<readonly [string, WriterValue]>): Ordered {
  return { entries };
}

function isOrdered(v: WriterValue): v is Ordered {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

/** Python json.dumps string form with ensure_ascii=True. */
function pyString(text: string): string {
  if (hasLoneSurrogate(text)) throw new Error("unpaired surrogate in lock text");
  let out = '"';
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    const ch = text[i] as string;
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (ch === "\t") out += "\\t";
    else if (ch === "\b") out += "\\b";
    else if (ch === "\f") out += "\\f";
    else if (c < 0x20 || c > 0x7e) out += "\\u" + c.toString(16).padStart(4, "0");
    else out += ch;
  }
  return out + '"';
}

function pyDump(value: WriterValue, indent: string): string {
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new Error("lock files hold integers only");
    return String(value);
  }
  if (typeof value === "string") return pyString(value);
  const inner = indent + "  ";
  if (Array.isArray(value)) {
    const arr = value as readonly WriterValue[];
    if (arr.length === 0) return "[]";
    return "[\n" + arr.map((v) => inner + pyDump(v, inner)).join(",\n") + "\n" + indent + "]";
  }
  if (!isOrdered(value)) throw new Error("unsupported writer value");
  if (value.entries.length === 0) return "{}";
  return (
    "{\n" +
    value.entries.map(([k, v]) => inner + pyString(k) + ": " + pyDump(v, inner)).join(",\n") +
    "\n" +
    indent +
    "}"
  );
}

/** Bytes for a lock file: json.dumps(doc, indent=2) + "\n". */
export function formatLockFile(doc: WriterValue): Buffer {
  return Buffer.from(pyDump(doc, "") + "\n", "utf8");
}

function identityValue(identity: Identity): Ordered {
  return ordered(identityFields(identity).map(([k, v]) => [k, typeof v === "string" ? v : [...v]] as const));
}

function attributesValue(a: Attributes): Ordered {
  const e: Array<readonly [string, WriterValue]> = [];
  if (a.version !== undefined) e.push(["version", a.version]);
  if (a.audience !== undefined) e.push(["audience", a.audience]);
  if (a.command !== undefined) e.push(["command", a.command]);
  if (a.args !== undefined) e.push(["args", [...a.args]]);
  if (a.env !== undefined) e.push(["env", [...a.env]]);
  return ordered(e);
}

function approvalValue(a: Approval): Ordered {
  const e: Array<readonly [string, WriterValue]> = [
    ["subject", a.subject],
    ["at", a.at],
    ["via", a.via],
  ];
  if (a.ref !== undefined) e.push(["ref", a.ref]);
  return ordered(e);
}

/**
 * Shard bytes. Member order is lockVersion, identity, attributes, instructions,
 * tools; tools keep the order of `shard.tools` (a writer appends a newly approved
 * name at the end), which is the order the Python generator writes.
 */
export function formatShard(shard: Shard): Buffer {
  const e: Array<readonly [string, WriterValue]> = [
    ["lockVersion", LOCK_VERSION],
    ["identity", identityValue(shard.identity)],
  ];
  if (shard.attributes !== null) e.push(["attributes", attributesValue(shard.attributes)]);
  if (shard.instructions !== null) e.push(["instructions", ordered([["digest", shard.instructions]])]);
  const tools: Array<readonly [string, WriterValue]> = [];
  for (const [name, entry] of shard.tools) {
    tools.push([
      name,
      ordered([
        ["digest", entry.digest],
        ["contract", entry.contract],
        ["approval", approvalValue(entry.approval)],
        // After approval, where the reference generator writes it.
        ...(entry.metaDigest !== undefined ? [["metaDigest", entry.metaDigest] as const] : []),
      ]),
    ]);
  }
  e.push(["tools", ordered(tools)]);
  return formatLockFile(ordered(e));
}

export function formatAliases(aliases: ReadonlyMap<string, Identity>): Buffer {
  const e: Array<readonly [string, WriterValue]> = [];
  for (const [name, identity] of aliases) e.push([name, identityValue(identity)]);
  return formatLockFile(
    ordered([
      ["lockVersion", LOCK_VERSION],
      ["aliases", ordered(e)],
    ]),
  );
}

/** Manifest bytes over `files` (name to bytes), names sorted. */
export function formatManifest(sequence: number, files: ReadonlyMap<string, Uint8Array>): Buffer {
  const e: Array<readonly [string, WriterValue]> = [];
  for (const name of [...files.keys()].sort(compareCodePoints)) {
    if (name === MANIFEST || name === SIGNATURE) continue;
    e.push([name, "sha256:" + sha256Hex(files.get(name) as Uint8Array)]);
  }
  return formatLockFile(
    ordered([
      ["lockVersion", LOCK_VERSION],
      ["sequence", sequence],
      ["files", ordered(e)],
    ]),
  );
}
