"""Release gate: every file in the @mcp-index/sdk npm tarball must be on a committed list.

`files` in package.json picks whole directories (dist/src), so anything tsc or a stray copy
leaves there ships. This runs `npm pack` (the same packing step `npm publish` does), reads
the tarball, and fails on:
  - a file that matches no pattern in scripts/ship-allowlist.json "allow"
  - a file that matches a "deny" pattern, even if an allow pattern also matches it
  - a literal (non-glob) allow entry that is absent, so the list cannot rot

The deny patterns name the private mcpindex-trust material that must never reach npm:
Python sources, the trust engine, corpus_eval, smoke tests, judge and prompt files. This
check is path-only. The judge prompt text lives in the private repo and is not copied
here; mcpindex-trust's own check scans file contents for it.

Run after `npm run build` (the release job runs it after scripts/ci-test.sh, which builds):
  python3 scripts/check_shipped_files.py
  python3 scripts/check_shipped_files.py --tarball mcp-index-sdk-X.Y.Z.tgz
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
ALLOWLIST = ROOT / "scripts" / "ship-allowlist.json"
GLOB_CHARS = set("*?[")


def pack(outdir: Path) -> Path:
    # Lifecycle scripts stay on: pack runs prepack/prepare like publish does. publish also
    # runs prepublishOnly (`npm run build`), which is why the caller must build first.
    res = subprocess.run(
        ["npm", "pack", "--json", "--pack-destination", str(outdir)],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if res.returncode != 0:
        sys.exit(f"FAIL: npm pack failed:\n{res.stdout}\n{res.stderr}")
    info: list[dict[str, Any]] = json.loads(res.stdout)
    return outdir / info[0]["filename"]


def tar_names(tarball: Path) -> list[str]:
    with tarfile.open(tarball, "r:gz") as tf:
        names = []
        for m in tf.getmembers():
            if m.isdir():
                continue
            # npm puts every entry under package/; strip it so patterns read like the repo.
            name = m.name.split("/", 1)[1] if m.name.startswith("package/") else m.name
            names.append(name)
    return sorted(names)


def check(names: list[str], allow: list[str], deny: list[str]) -> list[str]:
    problems: list[str] = []
    for n in names:
        # Deny is case-insensitive (judgePrompt.js must hit *prompt*); allow is exact.
        hit = [p for p in deny if fnmatch.fnmatchcase(n.lower(), p.lower())]
        if hit:
            problems.append(f"DENY  {n}  (matches {', '.join(hit)})")
        elif not any(fnmatch.fnmatchcase(n, p) for p in allow):
            problems.append(f"EXTRA {n}  (no allow pattern matches)")
    for p in allow:
        if not (GLOB_CHARS & set(p)) and p not in names:
            problems.append(f"MISSING {p}  (literal allow entry not in the tarball)")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description="Check the npm tarball against scripts/ship-allowlist.json")
    ap.add_argument("--tarball", help="check this .tgz instead of running npm pack")
    args = ap.parse_args()

    cfg = json.loads(ALLOWLIST.read_text(encoding="utf-8"))
    allow: list[str] = cfg["allow"]
    deny: list[str] = cfg["deny"]

    with tempfile.TemporaryDirectory() as tmp:
        tarball = Path(args.tarball) if args.tarball else pack(Path(tmp))
        if not tarball.is_file():
            sys.exit(f"FAIL: no such tarball: {tarball}")
        names = tar_names(tarball)
        label = tarball.name

    print(f"{label}: {len(names)} files, {len(allow)} allow patterns, {len(deny)} deny patterns")
    for n in names:
        print(f"  {n}")
    problems = check(names, allow, deny)
    if problems:
        print(f"\nFAIL: {len(problems)} problem(s) in {label}:")
        for p in problems:
            print(f"  {p}")
        print("\nIf a new file is meant to ship, add it to scripts/ship-allowlist.json in the same PR.")
        return 1
    print(f"\nok: every file in {label} is allowlisted; nothing denied")
    return 0


if __name__ == "__main__":
    sys.exit(main())
