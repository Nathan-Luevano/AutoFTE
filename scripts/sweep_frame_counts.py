"""Sweep `dedup.MAJOR_FRAME_COUNT` x `dedup.MINOR_FRAME_COUNT` over the
igor corpus for `planning/V1-RELEASE.md` W1.

Parses the full igor corpus exactly once via
`bench.resolve_corpus`/`bench.load_corpus` and
`sanitizers.parse_sanitizer_output` -- the same loading path
`bench.run_bench` uses. The expensive parts of `dedup.stack_hashes` --
`significant_frames` (the ~410-pattern vendored noise-frame check) and
`collapse_recursive_cycles` -- do not depend on `MAJOR_FRAME_COUNT`/
`MINOR_FRAME_COUNT` at all, so they are computed exactly ONCE per record
here, along with the two `normalized_keys` variants (with and without the
line number). Each grid point then only slices those precomputed key lists
to `[:major]`/`[:minor]` and hashes them -- the cheap part -- instead of
recomputing the noise filter 325,044 times per grid point across ~90 grid
points. An earlier version of this script did not precompute, and measured
~190s per grid point (would have been ~5 hours for the full sweep); this
version's per-record precompute pass plus ~90 cheap re-slices runs in well
under a minute after the corpus is parsed.

Bucket ids are namespaced by target for the igor corpus kind, identical to
`bench.run_bench`. Results are scored with `metrics.compute_metrics` and
written to `bench-sweep-results.json` (summary stats only -- the full
per-label/per-bucket breakdown is not needed for the sweep and would bloat
the file across ~90 grid points).

Usage: `micromamba run -n autofte python scripts/sweep_frame_counts.py`
"""

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from autofte import bench, dedup  # noqa: E402
from autofte.metrics import compute_metrics  # noqa: E402
from autofte.sanitizers import parse_sanitizer_output  # noqa: E402

RESULTS_PATH = Path(__file__).resolve().parent.parent / "bench-sweep-results.json"
MAJOR_RANGE = range(1, 9)
MINOR_RANGE = range(3, 16)


def load_parsed_corpus():
    corpus_path, corpus_kind = bench.resolve_corpus("igor")
    resolved_kind, items = bench.load_corpus(corpus_path, corpus_kind)
    parsed = []
    parse_failures = 0
    for item_id, label, text in items:
        record = parse_sanitizer_output(text)
        if record is None:
            parse_failures += 1
            continue
        parsed.append((item_id, label, record))
    return resolved_kind, parsed, parse_failures


def precompute_keys(parsed):
    precomputed = []
    for item_id, label, record in parsed:
        crash_stack = record.get("crash_stack") or []
        context = [record["bug_class"]] if record.get("bug_class") else []
        frames = dedup.collapse_recursive_cycles(dedup.significant_frames(crash_stack))
        minor_keys_full = dedup.normalized_keys(frames, include_line=True)
        major_keys_full = dedup.normalized_keys(frames, include_line=False)
        fallback_key = bench._fallback_bucket_key(record)
        precomputed.append(
            (item_id, label, context, major_keys_full, minor_keys_full, fallback_key)
        )
    return precomputed


def run_grid_point(resolved_kind, precomputed, major, minor):
    assignments = []
    nohash_count = 0
    for item_id, label, context, major_keys_full, minor_keys_full, fallback_key in precomputed:
        if not minor_keys_full:
            major_hash = None
        else:
            major_hash = dedup._hash(context + major_keys_full[:major])
        if major_hash is not None:
            bucket = f"hash:{major_hash}"
        else:
            bucket = f"nohash:{fallback_key}"
            nohash_count += 1
        if resolved_kind == "igor":
            target = label.split("::", 1)[0]
            bucket = f"{target}::{bucket}"
        assignments.append((item_id, label, bucket))
    metrics = compute_metrics(assignments)
    return {
        "purity": metrics["purity"],
        "inverse_purity": metrics["inverse_purity"],
        "f_measure": metrics["f_measure"],
        "n_buckets": metrics["n_buckets"],
        "n_labels": metrics["n_labels"],
        "n_items": metrics["n_items"],
        "nohash_count": nohash_count,
        "nohash_rate": nohash_count / metrics["n_items"],
    }


def sweep(major_range, minor_range):
    load_start = time.time()
    resolved_kind, parsed, parse_failures = load_parsed_corpus()
    load_elapsed = time.time() - load_start
    print(
        f"loaded and parsed {len(parsed)} reports "
        f"({parse_failures} parse failures) in {load_elapsed:.1f}s",
        flush=True,
    )

    precompute_start = time.time()
    precomputed = precompute_keys(parsed)
    precompute_elapsed = time.time() - precompute_start
    print(
        f"precomputed noise-filtered/normalized keys for {len(precomputed)} "
        f"records in {precompute_elapsed:.1f}s",
        flush=True,
    )

    grid = []
    sweep_start = time.time()
    for major in major_range:
        for minor in minor_range:
            if minor < major:
                continue
            point_start = time.time()
            point = run_grid_point(resolved_kind, precomputed, major, minor)
            point["major"] = major
            point["minor"] = minor
            point["elapsed_s"] = time.time() - point_start
            grid.append(point)
            print(
                f"major={major:2d} minor={minor:2d}  "
                f"purity={point['purity']:.4f}  "
                f"inverse_purity={point['inverse_purity']:.4f}  "
                f"f_measure={point['f_measure']:.4f}  "
                f"n_buckets={point['n_buckets']:5d}  "
                f"nohash_rate={point['nohash_rate']:.4f}  "
                f"({point['elapsed_s']:.2f}s)",
                flush=True,
            )

    total_elapsed = time.time() - sweep_start
    print(
        f"sweep complete: {len(grid)} grid points in {total_elapsed:.1f}s",
        flush=True,
    )

    output = {
        "corpus_kind": resolved_kind,
        "n_reports": len(parsed),
        "parse_failures": parse_failures,
        "load_elapsed_s": load_elapsed,
        "precompute_elapsed_s": precompute_elapsed,
        "sweep_elapsed_s": total_elapsed,
        "grid": grid,
    }
    RESULTS_PATH.write_text(json.dumps(output, indent=2, sort_keys=True))
    print(f"wrote {RESULTS_PATH}")
    return output


if __name__ == "__main__":
    sweep(MAJOR_RANGE, MINOR_RANGE)
