/**
 * Where the live Python twin lives, and whether it is here.
 *
 * The cross-language parity tests read or run the Python gate in mcpindex-trust, where this
 * package is checked out at clients/ts. Compiled tests run from dist/test, so that tree's
 * root is four directories up. In the standalone public repo it is not there, and those
 * tests skip with a reason naming the path they looked for, so `npm test` passes on a fresh
 * clone and the skip is printed in the summary instead of passing silently.
 *
 * Set MCPINDEX_PARITY_REQUIRED=1 to turn the skip back into a failure (a run that is meant
 * to have the tree must not lose it quietly).
 */

import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

export const PY_TREE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");

const MARKERS = [join("corpus_eval", "tooling", "cse", "gate.py"), join("src", "trust")];

const present = MARKERS.every((m) => existsSync(join(PY_TREE_ROOT, m)));
const required = process.env.MCPINDEX_PARITY_REQUIRED === "1";

/** `false` when the parity tests must run; otherwise the skip reason node:test prints. */
export const PY_TREE_SKIP: string | false =
  present || required
    ? false
    : `no Python twin at ${PY_TREE_ROOT} (looked for ${MARKERS.join(", ")}); ` +
      "this parity check runs in mcpindex-trust, where this repo is clients/ts";
