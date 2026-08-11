"""Classify WHY each no-hash-fallback report in the real Igor corpus produced
no hashable frame, per planning/V1-RELEASE.md W2. Standalone, run-once
diagnostic script -- not part of the package, not imported by anything else.

Usage: micromamba run -n autofte python scripts/classify_nohash_fallbacks.py
"""

import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from autofte import bench, dedup, sanitizers

EXAMPLES_PER_CATEGORY = 4


def classify(record):
    crash_stack = record["crash_stack"]
    if not crash_stack:
        return "a_empty_crash_stack"

    sig_frames = dedup.significant_frames(crash_stack)
    if not sig_frames:
        return "b_all_frames_denylisted"

    collapsed = dedup.collapse_recursive_cycles(sig_frames)
    keys = dedup.normalized_keys(collapsed)
    if not keys:
        return "c_unsymbolized_no_func_no_file"

    return "d_other_unexplained"


def main():
    corpus_path, corpus_kind = bench.resolve_corpus("igor")
    resolved_kind, items = bench.load_corpus(corpus_path, corpus_kind)
    print(f"Loaded {len(items)} items from {corpus_path} (kind={resolved_kind})")

    counts = Counter()
    examples = defaultdict(list)
    detect_none_examples = []
    parse_none_examples = []

    total = 0
    nohash_total = 0
    detect_none_count = 0
    parse_fail_but_detected_count = 0

    for item_id, label, text in items:
        detected = sanitizers.detect_sanitizer_output(text)
        if detected is None:
            detect_none_count += 1
            if len(detect_none_examples) < EXAMPLES_PER_CATEGORY:
                detect_none_examples.append((item_id, label, text[:1500]))
            continue

        record = sanitizers.parse_sanitizer_output(text)
        if record is None:
            parse_fail_but_detected_count += 1
            if len(parse_none_examples) < EXAMPLES_PER_CATEGORY:
                parse_none_examples.append((item_id, label, detected, text[:1500]))
            continue

        total += 1
        major_hash, minor_hash = dedup.stack_hashes(
            record["crash_stack"], extra_context=[record["bug_class"]]
        )
        if major_hash is not None:
            continue

        nohash_total += 1
        category = classify(record)
        counts[category] += 1
        if len(examples[category]) < EXAMPLES_PER_CATEGORY:
            examples[category].append((item_id, label, record, text[:2000]))

    print()
    print(f"Total items: {len(items)}")
    print(f"detect_sanitizer_output() returned None: {detect_none_count}")
    print(f"detected but parse_sanitizer_output() returned None: {parse_fail_but_detected_count}")
    print(f"Successfully parsed records: {total}")
    print(f"No-hash fallbacks among parsed records: {nohash_total}")
    print(f"nohash_rate (of parsed): {nohash_total / total:.4f}" if total else "n/a")
    print()
    print("=== Category breakdown (of no-hash fallbacks) ===")
    for cat, n in counts.most_common():
        pct = 100.0 * n / nohash_total if nohash_total else 0.0
        print(f"  {cat:<40} {n:>8}  ({pct:5.2f}%)")

    print()
    print("=== detect_sanitizer_output() == None: examples ===")
    for item_id, label, snippet in detect_none_examples:
        print(f"--- {item_id} (label={label}) ---")
        print(snippet)
        print()

    print()
    print("=== detected-but-parse-failed: examples ===")
    for item_id, label, detected, snippet in parse_none_examples:
        print(f"--- {item_id} (label={label}, detected={detected}) ---")
        print(snippet)
        print()

    for cat in sorted(counts):
        print()
        print(f"=== Category {cat}: examples ===")
        for item_id, label, record, snippet in examples[cat]:
            print(f"--- {item_id} (label={label}, bug_class={record['bug_class']}) ---")
            print(f"crash_stack frame count: {len(record['crash_stack'])}")
            for f in record["crash_stack"][:8]:
                print(f"    {f}")
            print("--- raw text (first 2000 chars) ---")
            print(snippet)
            print()


if __name__ == "__main__":
    main()
