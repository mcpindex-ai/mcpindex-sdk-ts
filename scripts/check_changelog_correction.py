"""Release gate: a staged correction must ship in a released section, not sit in Unreleased.

A correction written into [Unreleased] and then left there while a version is
cut never ships, and everyone believes it did. This fails the release until
the marker sits under a real version heading.

Once the marker is in a released section the check stays green with no further
edits. Do not remove a row from REQUIRED.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

CHANGELOG = Path(__file__).resolve().parent.parent / "CHANGELOG.md"

REQUIRED: tuple[tuple[str, str], ...] = (
    (
        "<!-- correction-marker: numeric-drift-denominator -->",
        "the 0.3.0 '20:1' burial ratio is one publisher's fleet and reverses without it",
    ),
)


_HEADING = re.compile(r"^## +(.+?)\s*$", re.MULTILINE)


def released_sections(text: str) -> str:
    """Everything under a `## <version>` heading, excluding `## [Unreleased]`.

    A heading is treated as unreleased when it is bracketed. Anything else
    (`## 0.13.1 - 2026-10-01`) is a shipped entry.
    """
    out: list[str] = []
    matches = list(_HEADING.finditer(text))
    for i, m in enumerate(matches):
        title = m.group(1).strip()
        if title.startswith("["):
            continue
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        out.append(text[m.end() : end])
    return "\n".join(out)


def main() -> int:
    if not CHANGELOG.is_file():
        print(f"FAIL: {CHANGELOG} not found", file=sys.stderr)
        return 1

    text = CHANGELOG.read_text()
    shipped = released_sections(text)

    failures = []
    for marker, why in REQUIRED:
        if marker in shipped:
            print(f"ok   shipped: {why}")
            continue
        where = "staged in [Unreleased]" if marker in text else "NOT PRESENT AT ALL"
        failures.append((marker, why, where))

    for marker, why, where in failures:
        print(
            f"FAIL a required correction is {where}, not in a released section.\n"
            f"     marker: {marker}\n"
            f"     what:   {why}\n"
            f"     fix:    move it out of '## [Unreleased]' into this release's\n"
            f"             '## <version> - <date>' section in CHANGELOG.md,\n"
            f"             then re-tag.",
            file=sys.stderr,
        )

    if failures:
        return 1
    print(f"changelog-correction gate: {len(REQUIRED)}/{len(REQUIRED)} shipped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
