"""`autofte bench` -- score AutoFTE's dedup bucketing against a labeled
corpus of captured sanitizer reports.

This is the "ground truth" harness described in
`planning/research/05-accuracy-and-ground-truth.md` SS6 and
`planning/HARDENING.md` Part 2: it never re-fuzzes or re-runs a target.
Each item in a corpus is *already-captured report text* paired with a
ground-truth bug label; the pipeline here is exactly parse -> hash ->
score, independent of the live gdb/subprocess triage flow in `triage.py`.

Two corpus shapes are supported:

- **micro** -- the small, checked-in, hand-labeled corpus at
  `tests/fixtures/bench_micro_corpus/<label>/<case>.txt`. One directory
  per ground-truth label, one report per file. Fast, no network, this is
  what runs on every PR.
- **igor** -- the GPTrace/Igor `data_sources.tar.gz` corpus (Apache-2.0,
  Zenodo record 10.5281/zenodo.18708473), fetched by
  `scripts/fetch_bench_corpus.sh` into `~/.cache/autofte/bench/`. Its real
  on-disk shape, inspected directly rather than assumed from the paper, is

      data_sources/<vendor>__<target>/asan_logs/poc_<LABEL>_raw/<poc-file>

  where `<poc-file>` is plain ASan report text saved under the original
  fuzzer testcase's filename (so it may have a misleading extension like
  `.ttf` or `.pdf` -- it is text, not the testcase itself; the testcase
  bytes live in the sibling `traces/` and `crashwalk/` directories
  instead). `<LABEL>` is the ground-truth bug id Igor/GPTrace assigned
  (a single letter for Igor's own SCIs, or a Magma-style id like `AAH010`
  for the forward-ported CVEs). There is no separate label-mapping file
  inside `data_sources.tar.gz` -- the label is the directory name itself.
  Labels are namespaced by target (`target::LABEL`) when scoring, since
  the same letter (e.g. `A`) is reused across unrelated targets.

For each report: `sanitizers.parse_sanitizer_output` -> (on success)
`dedup.stack_hashes(record["crash_stack"], extra_context=[record["bug_class"]])`.
A report that fails to parse is counted in `parse_failures` and excluded
from scoring rather than aborting the run. A report that parses but has
no hashable frames (e.g. a genuinely frameless allocator-out-of-memory
report -- V1-RELEASE.md W2 closed the far larger, and far more common,
case where `sanitizers.py` simply failed to recognize the crash-stack
boundary) still gets a bucket, keyed on its bug class, so it isn't
silently dropped from the corpus; this mirrors the same "fall back to a
raw label when there's nothing to hash" property `triage.py` relies on,
without importing anything from `triage.py`.
"""

import json
import re
from collections import defaultdict
from pathlib import Path

from .dedup import stack_hashes
from .metrics import compute_metrics
from .sanitizers import parse_sanitizer_output

MICRO_CORPUS_DIR = (
    Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "bench_micro_corpus"
)
IGOR_CACHE_DIR = Path.home() / ".cache" / "autofte" / "bench"
IGOR_DATA_DIR_NAME = "data_sources"

_POC_LABEL_RE = re.compile(r"^poc_(.+)_raw$")

METRIC_KEYS = (
    "purity",
    "inverse_purity",
    "f_measure",
    "overcounting_mean",
    "undercounting_mean",
)

MACRO_METRIC_KEYS = ("purity", "inverse_purity", "f_measure")

# TASK 1 (planning/V1-RELEASE.md E2/E3 aggregation question, resolved
# 2026-08-08, see benchmarks/results.md "TASK 1 -- aggregation methodology
# settled"): the GPTrace ICSE'26 paper (arXiv 2512.01609) defines
# purity/inverse-purity/F "for a fixed target program" (N scoped per
# target, not to the pooled corpus) and its Table 3 reports one row per
# target plus an unweighted "Average" row -- i.e. MACRO aggregation
# (per-target metric, then averaged across targets), not micro/pooled.
# Confirmed independently by a fresh adversarial review; the one open
# caveat is that the paper never states in prose whether its own Average
# row is a weighted or unweighted mean -- that is inferred, not quoted.
# AutoFTE's E2/E3 exit criteria never specified an aggregation (a real
# spec bug, fixed in planning/V1-RELEASE.md alongside this change) --
# report both so nobody has to guess which one a number means.
AGGREGATION_NOTE = (
    "Micro = pooled over all reports (one purity/IP/F computed on the whole "
    "corpus at once). Macro = per-target mean (metric computed separately "
    "per target, then averaged across targets, each target weighted "
    "equally regardless of size). The GPTrace ICSE'26 paper (arXiv "
    "2512.01609) scopes its purity/inverse-purity/F formulas 'for a fixed "
    "target program' and reports one row per target plus an Average row -- "
    "i.e. MACRO. Its own prose never states whether that Average row is a "
    "weighted or unweighted mean, so treat that one detail as inferred, "
    "not quoted -- see benchmarks/results.md 'TASK 1' for the full citation "
    "and the adversarial review that checked it."
)


class CorpusNotFoundError(Exception):
    pass


def resolve_corpus(spec):
    if spec == "micro":
        if not MICRO_CORPUS_DIR.is_dir():
            raise CorpusNotFoundError(f"micro corpus not found at {MICRO_CORPUS_DIR}")
        return MICRO_CORPUS_DIR, "micro"
    if spec == "igor":
        data_dir = IGOR_CACHE_DIR / IGOR_DATA_DIR_NAME
        if not data_dir.is_dir():
            raise CorpusNotFoundError(
                f"Igor/GPTrace corpus not found at {data_dir}. "
                "Run scripts/fetch_bench_corpus.sh first."
            )
        return data_dir, "igor"
    path = Path(spec)
    if not path.is_dir():
        raise CorpusNotFoundError(f"corpus path not found: {path}")
    return path, "auto"


def detect_corpus_kind(path):
    path = Path(path)
    if next(path.rglob("asan_logs"), None) is not None:
        return "igor"
    return "micro"


def iter_micro_corpus(path):
    path = Path(path)
    if not path.is_dir():
        raise CorpusNotFoundError(f"micro corpus path not found: {path}")
    for label_dir in sorted(p for p in path.iterdir() if p.is_dir()):
        label = label_dir.name
        for report_path in sorted(label_dir.glob("*.txt")):
            item_id = f"{label}/{report_path.name}"
            text = report_path.read_text(encoding="utf-8", errors="replace")
            yield item_id, label, text


def iter_igor_corpus(path):
    path = Path(path)
    if not path.is_dir():
        raise CorpusNotFoundError(f"Igor corpus path not found: {path}")
    for asan_logs_dir in sorted(path.rglob("asan_logs")):
        target = asan_logs_dir.parent.name
        for label_dir in sorted(p for p in asan_logs_dir.iterdir() if p.is_dir()):
            match = _POC_LABEL_RE.match(label_dir.name)
            if not match:
                continue
            label = f"{target}::{match.group(1)}"
            for report_path in sorted(label_dir.iterdir()):
                if not report_path.is_file():
                    continue
                item_id = f"{target}/{label_dir.name}/{report_path.name}"
                text = report_path.read_text(encoding="utf-8", errors="replace")
                yield item_id, label, text


def _fallback_bucket_key(record):
    parts = [record["bug_class"]]
    if record["access_type"]:
        size = f" {record['access_size']}" if record["access_size"] is not None else ""
        parts.append(f"({record['access_type']}{size})")
    crash_stack = record["crash_stack"]
    if crash_stack:
        top = crash_stack[0]
        ident = top.get("func") or top.get("addr")
        if ident:
            parts.append(f"in {ident}")
    return " ".join(parts)


def load_corpus(corpus_path, corpus_kind):
    kind = corpus_kind
    if kind == "auto":
        kind = detect_corpus_kind(corpus_path)
    if kind == "micro":
        return kind, list(iter_micro_corpus(corpus_path))
    if kind == "igor":
        return kind, list(iter_igor_corpus(corpus_path))
    raise ValueError(f"unknown corpus kind: {corpus_kind}")


def run_bench(corpus_path, corpus_kind="auto"):
    resolved_kind, items = load_corpus(corpus_path, corpus_kind)

    assignments = []
    parse_failures = 0
    nohash_count = 0
    for item_id, label, text in items:
        record = parse_sanitizer_output(text)
        if record is None:
            parse_failures += 1
            continue

        major_hash, _minor_hash = stack_hashes(
            record["crash_stack"], extra_context=[record["bug_class"]]
        )
        if major_hash is not None:
            bucket = f"hash:{major_hash}"
        else:
            bucket = f"nohash:{_fallback_bucket_key(record)}"
            nohash_count += 1

        if resolved_kind == "igor":
            # Bucket ids are namespaced by target: a real triage run only ever
            # dedups crashes from one target's crash directory at a time, so
            # pooling all 14 targets into one bench run must not let an
            # unrelated bug in a different target collide into the same
            # bucket just because it shares a generic bug_class.
            target = label.split("::", 1)[0]
            bucket = f"{target}::{bucket}"
        assignments.append((item_id, label, bucket))

    result = {
        "corpus_path": str(corpus_path),
        "corpus_kind": resolved_kind,
        "n_reports": len(items),
        "parse_failures": parse_failures,
        "nohash_count": nohash_count,
        "metrics": None,
    }
    if not assignments:
        result["error"] = "no reports could be parsed and hashed; nothing to score"
        return result

    result["metrics"] = compute_metrics(assignments)
    if resolved_kind == "igor":
        result["per_target"] = _per_target_metrics(assignments)
        result["macro_metrics"] = _macro_metrics(result["per_target"])
    return result


def _per_target_metrics(assignments):
    """Split igor-corpus assignments by target (the `target::LABEL` namespace
    `iter_igor_corpus` already applies to labels) and run `compute_metrics`
    separately on each target's subset, so a target that is hiding a
    disaster behind a healthy pooled/aggregate score (V1-RELEASE.md W3)
    shows up on its own.
    """
    by_target = defaultdict(list)
    for item_id, label, bucket in assignments:
        target = label.split("::", 1)[0]
        by_target[target].append((item_id, label, bucket))
    return {target: compute_metrics(items) for target, items in sorted(by_target.items())}


def _macro_metrics(per_target):
    """Unweighted mean of purity/inverse_purity/f_measure across targets --
    the macro aggregation the GPTrace ICSE'26 paper's own Table 3 uses (see
    AGGREGATION_NOTE and benchmarks/results.md 'TASK 1'). Each target counts
    once regardless of its report volume, unlike the pooled/micro metric in
    `result["metrics"]` where a large target (e.g. xmllint at 58% of the
    igor corpus by item count) dominates the number.
    """
    targets = sorted(per_target)
    n = len(targets)
    if n == 0:
        return None
    macro = {"n_targets": n}
    for key in MACRO_METRIC_KEYS:
        macro[key] = sum(per_target[t][key] for t in targets) / n
    return macro


def render_table(result):
    lines = []
    lines.append(f"Corpus: {result['corpus_path']} ({result['corpus_kind']})")
    lines.append(
        f"Reports: {result['n_reports']}  "
        f"Parse failures: {result['parse_failures']}  "
        f"No-hash fallbacks: {result['nohash_count']}"
    )
    metrics = result.get("metrics")
    if metrics is None:
        lines.append(f"No metrics: {result.get('error', 'unknown error')}")
        return "\n".join(lines)

    lines.append("")
    lines.append(f"{'metric':<20}{'value':>10}")
    lines.append(f"{'-' * 30}")
    lines.append(f"{'n_items':<20}{metrics['n_items']:>10}")
    lines.append(f"{'n_labels':<20}{metrics['n_labels']:>10}")
    lines.append(f"{'n_buckets':<20}{metrics['n_buckets']:>10}")
    lines.append(f"{'purity':<20}{metrics['purity']:>10.4f}")
    lines.append(f"{'inverse_purity':<20}{metrics['inverse_purity']:>10.4f}")
    lines.append(f"{'f_measure':<20}{metrics['f_measure']:>10.4f}")
    lines.append(
        f"{'overcounting':<20}"
        f"{metrics['overcounting_mean']:>10.4f} (std {metrics['overcounting_std']:.4f})"
    )
    lines.append(
        f"{'undercounting':<20}"
        f"{metrics['undercounting_mean']:>10.4f} (std {metrics['undercounting_std']:.4f})"
    )
    return "\n".join(lines)


def render_per_target_table(result):
    """Render the igor corpus's per-target breakdown, worst f_measure first.

    Sorted on f_measure rather than purity or inverse_purity alone: F is
    the only column here that is low whenever *either* purity or inverse
    purity is bad for that target, so it surfaces both failure shapes at
    the top in one pass -- the literature's cited "825 buckets for 8
    bugs" disaster (an inverse-purity failure, one bug shattered across
    hundreds of buckets) and a silent-bug-merging purity failure would
    both rise to the top under this ordering, whereas sorting on inverse
    purity alone could leave a target whose real problem is purity
    buried further down the table.
    """
    per_target = result.get("per_target")
    if not per_target:
        return "No per-target metrics (per-target breakdown is igor-corpus only)."

    lines = []
    lines.append("Per-target breakdown, worst f_measure first:")
    lines.append("")
    header = (
        f"{'target':<45}{'n_items':>9}{'n_labels':>9}{'n_buckets':>10}"
        f"{'purity':>9}{'inv_purity':>11}{'f_measure':>10}"
    )
    lines.append(header)
    lines.append("-" * len(header))
    for target, metrics in sorted(per_target.items(), key=lambda kv: kv[1]["f_measure"]):
        lines.append(
            f"{target:<45}{metrics['n_items']:>9}{metrics['n_labels']:>9}"
            f"{metrics['n_buckets']:>10}{metrics['purity']:>9.4f}"
            f"{metrics['inverse_purity']:>11.4f}{metrics['f_measure']:>10.4f}"
        )
    return "\n".join(lines)


def render_aggregation_table(result):
    """Print micro (pooled) and macro (per-target mean) purity/IP/F side by
    side, labelled, with a one-line note on which one the published
    baselines use. Igor-corpus only -- the micro corpus has no per-target
    axis to average over. See planning/V1-RELEASE.md E2/E3 and
    benchmarks/results.md 'TASK 1'/'TASK 2'.
    """
    metrics = result.get("metrics")
    macro = result.get("macro_metrics")
    if metrics is None or macro is None:
        return "No micro/macro comparison (igor corpus only)."

    lines = []
    lines.append(f"Aggregation comparison ({macro['n_targets']} targets):")
    lines.append("")
    header = f"{'aggregation':<28}{'purity':>10}{'inv_purity':>12}{'f_measure':>11}"
    lines.append(header)
    lines.append("-" * len(header))
    lines.append(
        f"{'micro (pooled)':<28}{metrics['purity']:>10.4f}"
        f"{metrics['inverse_purity']:>12.4f}{metrics['f_measure']:>11.4f}"
    )
    lines.append(
        f"{'macro (per-target mean)':<28}{macro['purity']:>10.4f}"
        f"{macro['inverse_purity']:>12.4f}{macro['f_measure']:>11.4f}"
    )
    lines.append("")
    lines.append(AGGREGATION_NOTE)
    return "\n".join(lines)


def diff_against_baseline(result, baseline):
    result_metrics = result.get("metrics")
    baseline_metrics = baseline.get("metrics")
    if result_metrics is None or baseline_metrics is None:
        return []

    lines = []
    for key in METRIC_KEYS:
        current = result_metrics.get(key)
        previous = baseline_metrics.get(key)
        if current is None or previous is None:
            continue
        delta = current - previous
        sign = "+" if delta >= 0 else ""
        lines.append(f"{key:<20}{previous:>10.4f} -> {current:>10.4f}  (delta {sign}{delta:.4f})")
    return lines


def check_regression(result, baseline, fail_purity_drop_points, fail_under_f):
    result_metrics = result.get("metrics")
    reasons = []

    if fail_under_f is not None and result_metrics is not None:
        if result_metrics["f_measure"] < fail_under_f:
            reasons.append(
                f"f_measure {result_metrics['f_measure']:.4f} is below "
                f"--fail-under-f {fail_under_f:.4f}"
            )

    if baseline is not None and result_metrics is not None:
        baseline_metrics = baseline.get("metrics")
        if baseline_metrics is not None:
            purity_drop = baseline_metrics["purity"] - result_metrics["purity"]
            threshold = fail_purity_drop_points / 100.0
            if purity_drop > threshold:
                reasons.append(
                    f"purity dropped {purity_drop * 100:.2f} points "
                    f"(baseline {baseline_metrics['purity']:.4f} -> "
                    f"{result_metrics['purity']:.4f}), exceeds "
                    f"--fail-purity-drop {fail_purity_drop_points:.2f}"
                )
            f_delta = result_metrics["f_measure"] - baseline_metrics["f_measure"]
            if f_delta < 0:
                reasons.append(
                    f"f_measure dropped from {baseline_metrics['f_measure']:.4f} "
                    f"to {result_metrics['f_measure']:.4f}"
                )

    return reasons


def write_results(path, result):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2, sort_keys=True)


def load_results(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)
