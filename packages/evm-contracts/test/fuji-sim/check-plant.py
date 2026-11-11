#!/usr/bin/env python3
"""Pass only when a planted feed fault was caught, and caught for that reason alone.

The planted run blanks one feed row on the wallets' side. A red run proves nothing unless its
mismatches come from that row: a wallet missing the note at that leaf, and the pool-solvency rows
that follow from the missing value. Any other mismatch means the run failed for another reason.

  check-plant.py <mismatches.jsonl> <planted row>
"""

import json
import sys

# the Fuji harness stamps every row with its wave
SOLVENCY_KEYS = {"wave", "step", "label", "asset", "notes", "memos", "held"}


def leaf_of(entry):
    return int(entry.split(":", 1)[0])


def check(rows, planted):
    """Return (missing-note rows, solvency rows, problems)."""
    hits, solvency, problems = 0, 0, []
    for i, row in enumerate(rows, 1):
        if "missing" in row or "extra" in row:
            missing, extra = row.get("missing", []), row.get("extra", [])
            stray = [m for m in missing if leaf_of(m) != planted] + list(extra)
            if stray or not missing:
                problems.append(f"row {i}: not the planted leaf: {row}")
            else:
                hits += 1
        elif set(row) <= SOLVENCY_KEYS and "asset" in row:
            solvency += 1
        else:
            problems.append(f"row {i}: unexpected mismatch: {row}")
    if hits == 0:
        problems.append(f"no wallet missed the note at the planted leaf {planted}")
    return hits, solvency, problems


def main():
    path, planted = sys.argv[1], int(sys.argv[2])
    try:
        with open(path, encoding="utf-8") as f:
            rows = [json.loads(line) for line in f if line.strip()]
    except FileNotFoundError:
        print(f"check-plant: {path} is missing, so the run failed before grading", file=sys.stderr)
        return 1
    hits, solvency, problems = check(rows, planted)
    for p in problems[:10]:
        print(f"check-plant: {p}", file=sys.stderr)
    if len(problems) > 10:
        print(f"check-plant: {len(problems) - 10} more", file=sys.stderr)
    if problems:
        return 1
    print(f"check-plant: red for the plant only: {hits} missing-note rows at leaf {planted}, "
          f"{solvency} solvency rows, {len(rows)} in all")
    return 0


if __name__ == "__main__":
    sys.exit(main())
