"""Root-cause `libxml2__xmllint`'s purity-0.8294 problem found by W3
(`benchmarks/results.md` "W3 -- per-target accuracy breakdown") against the
"xmllint purity root-cause -- HYPOTHESIS" entry appended right after it.

Loads only the `libxml2__xmllint` subset of the real Igor corpus already
cached at `~/.cache/autofte/bench/data_sources/libxml2__xmllint/`, computes
each item's real (major_hash, minor_hash) via `dedup.stack_hashes` exactly
as `bench.run_bench` does, finds every bucket that actually mixes items
from more than one ground-truth label (a real purity violation, not a
guess), and prints the real significant/normalized frames that produced
that bucket's major hash for a representative item of each contributing
label -- so the predicted mechanism (a shared generic dispatch frame
dominating the window) can be checked against real data instead of assumed.
"""

import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from autofte import dedup
from autofte.bench import iter_igor_corpus
from autofte.sanitizers import parse_sanitizer_output

IGOR_DATA_DIR = Path.home() / ".cache" / "autofte" / "bench" / "data_sources"


def main():
    target_dir = IGOR_DATA_DIR / "libxml2__xmllint"
    if not target_dir.is_dir():
        print(f"not found: {target_dir}")
        return 1

    items = list(iter_igor_corpus(target_dir))
    print(f"loaded {len(items)} items for libxml2__xmllint")

    bucket_labels = defaultdict(set)
    bucket_items = defaultdict(list)
    parse_failures = 0
    nohash = 0

    for item_id, label, text in items:
        record = parse_sanitizer_output(text)
        if record is None:
            parse_failures += 1
            continue
        major_hash, minor_hash = dedup.stack_hashes(
            record["crash_stack"], extra_context=[record["bug_class"]]
        )
        if major_hash is None:
            nohash += 1
            continue
        bucket_labels[major_hash].add(label)
        bucket_items[major_hash].append((item_id, label, record))

    print(f"parse_failures={parse_failures} nohash={nohash}")
    print(f"n_buckets={len(bucket_labels)}")

    mixed_buckets = {h: labels for h, labels in bucket_labels.items() if len(labels) > 1}
    print(f"n_mixed_buckets (purity violations)={len(mixed_buckets)}")
    print()

    for major_hash, _labels in sorted(mixed_buckets.items()):
        items_in_bucket = bucket_items[major_hash]
        counts = defaultdict(int)
        for _item_id, label, _record in items_in_bucket:
            counts[label] += 1

        print("=" * 100)
        print(f"BUCKET major_hash={major_hash}")
        print(f"  labels/counts: {dict(sorted(counts.items()))}")
        print(f"  total items in bucket: {len(items_in_bucket)}")

        seen_labels = set()
        for item_id, label, record in items_in_bucket:
            if label in seen_labels:
                continue
            seen_labels.add(label)

            crash_stack = record["crash_stack"]
            sig_frames = dedup.significant_frames(crash_stack)
            collapsed = dedup.collapse_recursive_cycles(sig_frames)
            major_keys = dedup.normalized_keys(collapsed, include_line=False)
            minor_keys = dedup.normalized_keys(collapsed, include_line=True)

            print(f"  --- representative item for label {label!r}: {item_id}")
            print(f"      bug_class={record['bug_class']!r}")
            print(f"      raw crash_stack frames ({len(crash_stack)}):")
            for frame in crash_stack[:12]:
                print(f"        {frame}")
            print(f"      significant_frames after noise-filter ({len(sig_frames)}):")
            for frame in sig_frames[:12]:
                print(f"        {frame}")
            print(f"      major_frame_keys (windowed to MAJOR_FRAME_COUNT="
                  f"{dedup.MAJOR_FRAME_COUNT}): {major_keys[:dedup.MAJOR_FRAME_COUNT]}")
            print(f"      full normalized major-key list (no window): {major_keys[:10]}")
            print(f"      minor_frame_keys (windowed to MINOR_FRAME_COUNT="
                  f"{dedup.MINOR_FRAME_COUNT}): {minor_keys[:dedup.MINOR_FRAME_COUNT]}")
        print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
