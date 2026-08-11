"""Compute the theoretical maximum purity achievable by ANY stack-based
crash-deduplication method on the Igor/GPTrace ground-truth corpus.

Why this exists
---------------
AutoFTE's own pooled ("micro") purity on this corpus sits just under 0.90,
and it is fair to ask whether that is a defect we could tune away. This
script answers that question from the data alone, and it is deliberately
INDEPENDENT of AutoFTE: it imports nothing from `autofte`, parses the raw
sanitizer text itself, and therefore cannot be flattered by a bug in our
own dedup implementation. Its conclusion is a property of the corpus, not
of this tool.

The argument
------------
Purity is maximized by the finest possible bucketing. The finest bucketing
any stack-based method can ever produce is "one bucket per distinct raw
stack" -- if two reports have byte-identical stacks, no frame count, no
normalization, and no denylist can separate them. For each such bucket the
best possible case is that it is credited with its majority label; every
non-majority report in it is irreducibly impure. So:

    max_purity = sum(largest_label_count_per_distinct_stack) / total_reports

Any method that looks only at the stack is bounded above by this number.

Two aggregations are reported, matching `autofte bench`:
  * micro -- pooled over every report in the corpus at once.
  * macro -- per-target mean, each target weighted equally. This is the
    basis the GPTrace ICSE'26 paper itself uses (see benchmarks/results.md
    "Analysis 1"), so it is the one to compare published baselines against.

Usage
-----
    python3 scripts/purity_ceiling.py [--target TARGET]

Requires the corpus: scripts/fetch_bench_corpus.sh
"""

import argparse
import hashlib
import re
from collections import Counter, defaultdict
from pathlib import Path

CORPUS_ROOT = Path.home() / ".cache" / "autofte" / "bench" / "data_sources"
POC_LABEL_RE = re.compile(r"^poc_([A-Za-z0-9]+)")
# Raw ASan frame lines, verbatim, e.g.
#     #0 0x81efa3b in xmlParseCharDataComplex /libxml2-2.9.0/parser.c:4592:2
FRAME_RE = re.compile(r"^\s*#\d+\s+.*$")


def collect(root, target_filter=None):
    """target -> {stack_sha1: Counter(ground_truth_label)}."""
    per_target = defaultdict(lambda: defaultdict(Counter))

    for asan_logs in sorted(root.rglob("asan_logs")):
        target = asan_logs.parent.name
        if target_filter and target != target_filter:
            continue
        for label_dir in sorted(p for p in asan_logs.iterdir() if p.is_dir()):
            match = POC_LABEL_RE.match(label_dir.name)
            if not match:
                continue
            label = f"{target}::{match.group(1)}"
            for report in label_dir.iterdir():
                if not report.is_file():
                    continue
                try:
                    text = report.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                frames = [ln.rstrip("\n") for ln in text.splitlines() if FRAME_RE.match(ln)]
                if not frames:
                    continue
                digest = hashlib.sha1("\n".join(frames).encode("utf-8")).hexdigest()
                per_target[target][digest][label] += 1

    return per_target


def ceiling(stacks):
    """(best_case_pure_reports, total_reports, max_purity) for one target."""
    total = sum(sum(counter.values()) for counter in stacks.values())
    best = sum(max(counter.values()) for counter in stacks.values())
    return best, total, (best / total if total else 0.0)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--target", help="Restrict to a single corpus target")
    parser.add_argument(
        "--corpus-root",
        type=Path,
        default=CORPUS_ROOT,
        help=f"Corpus location (default: {CORPUS_ROOT})",
    )
    args = parser.parse_args()

    if not args.corpus_root.is_dir():
        raise SystemExit(
            f"Corpus not found at {args.corpus_root}\n"
            "Fetch it first: scripts/fetch_bench_corpus.sh"
        )

    per_target = collect(args.corpus_root, args.target)
    if not per_target:
        raise SystemExit("No reports found (wrong --target, or corpus incomplete?)")

    print("Theoretical max purity for ANY stack-based method\n")
    print(f"{'target':<40} {'reports':>9} {'stacks':>8} {'max purity':>11}")
    print("-" * 71)

    rows = []
    for target, stacks in per_target.items():
        _best, total, purity = ceiling(stacks)
        rows.append((purity, target, total, len(stacks)))

    for purity, target, total, n_stacks in sorted(rows):
        flag = "  <-- capped below 0.95" if purity < 0.95 else ""
        print(f"{target:<40} {total:>9} {n_stacks:>8} {purity:>11.4f}{flag}")

    pooled = defaultdict(Counter)
    for stacks in per_target.values():
        for digest, counter in stacks.items():
            pooled[digest].update(counter)

    best, total, micro = ceiling(pooled)
    macro = sum(row[0] for row in rows) / len(rows)

    print()
    print(f"MICRO ceiling (pooled over all reports): {micro:.4f}  ({best}/{total})")
    print(f"MACRO ceiling (per-target mean):         {macro:.4f}")
    print()
    print(
        "Compare against `autofte bench --corpus igor`, which reports measured\n"
        "purity on both bases. A measured value at or near these numbers means\n"
        "the remaining gap is a property of the corpus -- two ground-truth bugs\n"
        "sharing byte-identical stacks -- and not something dedup tuning can fix."
    )


if __name__ == "__main__":
    main()
