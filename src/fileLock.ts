/**
 * Exclusive lock for a pin or pending file.
 *
 * Sibling path ``<path>.lck``, created with ``O_CREAT | O_EXCL`` (and
 * ``O_NOFOLLOW`` where it exists). The holder writes its pid and an ISO
 * timestamp, then closes the file. Another process that sees the file waits
 * and retries. A lock older than the stale threshold is broken by renaming it
 * aside and unlinking the aside name; only the rename winner proceeds. Release
 * unlinks the file when it still carries our pid and timestamp.
 *
 * Built from the Node standard library only. No native addons. An empty
 * leftover ``<path>.lock`` from an older flock-based build is ignored.
 */

import {
  closeSync,
  constants,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { dirname } from "node:path";

const SUFFIX = ".lck";
const STALE_MS = 30_000;
const DEADLINE_MS = 5_000;
const SLEEP_MS = 50;

export class LockTimeoutError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LockTimeoutError";
  }
}

export function lockPathFor(path: string): string {
  return `${path}${SUFFIX}`;
}

function nowIso(): string {
  return new Date().toISOString();
}

function sleepSync(ms: number): void {
  const buf = new Int32Array(new SharedArrayBuffer(4));
  Atomics.wait(buf, 0, 0, ms);
}

function createLock(lockPath: string, pid: number, stamp: string): void {
  let flags = constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL;
  if (typeof constants.O_NOFOLLOW === "number") {
    flags |= constants.O_NOFOLLOW;
  }
  const fd = openSync(lockPath, flags, 0o600);
  try {
    writeSync(fd, Buffer.from(`${pid}\n${stamp}\n`, "ascii"));
  } finally {
    closeSync(fd);
  }
}

function tryBreakStale(lockPath: string): void {
  let st;
  try {
    st = lstatSync(lockPath);
  } catch {
    return;
  }
  if (!st.isFile()) return;
  if (Date.now() - st.mtimeMs < STALE_MS) return;
  const aside = `${lockPath}.stale.${process.pid}.${process.hrtime.bigint()}`;
  try {
    renameSync(lockPath, aside);
  } catch {
    return;
  }
  try {
    unlinkSync(aside);
  } catch {
    // best effort
  }
}

function stillOurs(lockPath: string, pid: number, stamp: string): boolean {
  try {
    const text = readFileSync(lockPath, "ascii");
    const lines = text.split(/\r?\n/);
    if (lines.length < 2) return false;
    return Number(lines[0]) === pid && lines[1] === stamp;
  } catch {
    return false;
  }
}

function release(lockPath: string, pid: number, stamp: string): void {
  if (!stillOurs(lockPath, pid, stamp)) return;
  try {
    unlinkSync(lockPath);
  } catch {
    // best effort
  }
}

/** Hold an exclusive create-excl lock on ``path + '.lck'`` for ``fn``. */
export function withExclusiveLock<T>(path: string, fn: () => T): T {
  const lockPath = lockPathFor(path);
  const directory = dirname(lockPath) || ".";
  mkdirSync(directory, { recursive: true });
  const pid = process.pid;
  const stamp = nowIso();
  const deadline = Date.now() + DEADLINE_MS;
  for (;;) {
    try {
      createLock(lockPath, pid, stamp);
      break;
    } catch (err) {
      const code =
        err !== null && typeof err === "object" && "code" in err
          ? String((err as { code?: unknown }).code)
          : "";
      if (code !== "EEXIST") throw err;
      tryBreakStale(lockPath);
      if (Date.now() >= deadline) {
        throw new LockTimeoutError(`timed out waiting for pin store lock ${lockPath}`);
      }
      sleepSync(SLEEP_MS);
    }
  }
  try {
    return fn();
  } finally {
    release(lockPath, pid, stamp);
  }
}
