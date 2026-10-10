/**
 * Exclusive lock for a pin or pending file.
 *
 * Sibling path ``<path>.lock``, held with libc ``flock`` (LOCK_EX). Matches
 * Python ``tooling.cse.file_lock.exclusive_lock`` so a Python approval and a
 * TypeScript process cannot pass each other on the same store.
 */

import { closeSync, mkdirSync, openSync } from "node:fs";
import { dirname } from "node:path";
import koffi from "koffi";

const LOCK_EX = 2;
const LOCK_UN = 8;

type FlockFn = (fd: number, op: number) => number;

let flockFn: FlockFn | null = null;

function libcName(): string {
  if (process.platform === "darwin") return "libc.dylib";
  if (process.platform === "linux") return "libc.so.6";
  throw new Error(`pin store lock is not supported on ${process.platform}`);
}

function flock(): FlockFn {
  if (flockFn !== null) return flockFn;
  const lib = koffi.load(libcName());
  flockFn = lib.func("int flock(int fd, int op)") as FlockFn;
  return flockFn;
}

/** Hold an exclusive flock on ``path + '.lock'`` for the duration of ``fn``. */
export function withExclusiveLock<T>(path: string, fn: () => T): T {
  const lockPath = `${path}.lock`;
  const directory = dirname(lockPath) || ".";
  mkdirSync(directory, { recursive: true });
  const fd = openSync(lockPath, "a+", 0o600);
  const call = flock();
  const locked = call(fd, LOCK_EX);
  if (locked !== 0) {
    closeSync(fd);
    throw new Error(`flock failed on ${lockPath}`);
  }
  try {
    return fn();
  } finally {
    try {
      call(fd, LOCK_UN);
    } finally {
      closeSync(fd);
    }
  }
}
