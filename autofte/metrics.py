"""Purity / inverse-purity / F-measure and per-bug over/under-counting for
AutoFTE's crash dedup buckets, scored against a ground-truth bug labeling.

This is the standard clustering-quality machinery used by Igor (CCS'21) and
GPTrace (ICSE'26) to grade a stack-hash bucketer: `L_1..L_n` are the
ground-truth bugs a labeled crash corpus was split into, `C_1..C_m` are the
buckets AutoFTE's dedup produced, and purity/inverse-purity/F-measure are
computed over that `label x bucket` cross-tabulation exactly as defined in
the project methodology (citing Amigo
et al.; GPTrace SS4.1, SS4.7):

    Precision(L_i, C_j) = |L_i n C_j| / |C_j|
    Recall(L_i, C_j)    = |L_i n C_j| / |L_i|
    Purity        = sum_j (|C_j| / N) * max_i Precision(L_i, C_j)
    InversePurity = sum_i (|L_i| / N) * max_j Recall(L_i, C_j)
    F(L_i, C_j)   = 2*P*R / (P + R), 0 when both are 0
    F-measure     = sum_i (|L_i| / N) * max_j F(L_i, C_j)

    Overcounting(l)  = |{buckets containing >=1 item labeled l}| - 1
    Undercounting(l) = |{labels l' != l sharing a bucket with some item
                         labeled l}|

Purity falling means AutoFTE is silently merging two different bugs into
one bucket (Klees et al.: a real bug can be lost entirely this way).
Inverse purity falling means AutoFTE is shattering one bug across many
buckets -- the analyst wades through dozens of "unique" crashes that are
one fix. Both baselines are degenerate on purpose and are the sanity check
a broken implementation of this module should fail: one bucket per crash
drives inverse purity's numerator (bucket-local counts) to the point where
every bucket is 100% pure, so Purity = 100%; one bucket for everything
makes every label's best-matching bucket *the* bucket, so InversePurity =
100%.

Matches the rest of the codebase's convention of returning plain dicts from
structured-data functions (see `assess_crash_difficulty` in `severity.py`
and the sanitizer record built by `sanitizers.py`) rather than introducing
a dataclass. `compute_metrics` takes an iterable of
`(item_id, ground_truth_label, bucket_id)` tuples -- one per crash -- and
returns:

    {
        "n_items": int,
        "n_labels": int,
        "n_buckets": int,
        "purity": float,             # 0.0-1.0
        "inverse_purity": float,     # 0.0-1.0
        "f_measure": float,          # 0.0-1.0
        "overcounting_mean": float,
        "overcounting_std": float,   # population stdev over labels
        "undercounting_mean": float,
        "undercounting_std": float,  # population stdev over labels
        "overcounting_by_label": {label: int, ...},
        "undercounting_by_label": {label: int, ...},
        "per_label": {
            label: {
                "size": int,             # |L_i|
                "n_buckets": int,        # distinct buckets holding this label
                "best_recall": float,    # max_j Recall(L_i, C_j)
                "best_f": float,         # max_j F(L_i, C_j)
                "overcounting": int,
                "undercounting": int,
            },
            ...
        },
        "label_sizes": {label: int, ...},
        "bucket_sizes": {bucket_id: int, ...},
    }

`per_label`, `label_sizes`, and `bucket_sizes` are carried through
unaggregated so a bench-report renderer can build a per-target/per-bug
table without recomputing the cross-tabulation.
"""

import statistics
from collections import Counter, defaultdict


def compute_metrics(assignments):
    label_bucket_counts = defaultdict(Counter)
    bucket_label_counts = defaultdict(Counter)
    label_sizes = Counter()
    bucket_sizes = Counter()

    n_items = 0
    for _item_id, label, bucket in assignments:
        label_bucket_counts[label][bucket] += 1
        bucket_label_counts[bucket][label] += 1
        label_sizes[label] += 1
        bucket_sizes[bucket] += 1
        n_items += 1

    if n_items == 0:
        raise ValueError(
            "compute_metrics requires at least one (item_id, label, bucket) assignment"
        )

    purity = 0.0
    for bucket, label_counts in bucket_label_counts.items():
        bucket_size = bucket_sizes[bucket]
        best_precision = max(count / bucket_size for count in label_counts.values())
        purity += (bucket_size / n_items) * best_precision

    per_label = {}
    for label, bucket_counts in label_bucket_counts.items():
        label_size = label_sizes[label]
        best_recall = 0.0
        best_f = 0.0
        for bucket, intersection in bucket_counts.items():
            bucket_size = bucket_sizes[bucket]
            precision = intersection / bucket_size
            recall = intersection / label_size
            f_score = 0.0
            if precision + recall > 0:
                f_score = 2 * precision * recall / (precision + recall)
            best_recall = max(best_recall, recall)
            best_f = max(best_f, f_score)

        buckets_with_label = set(bucket_counts.keys())
        other_labels = set()
        for bucket in buckets_with_label:
            other_labels.update(bucket_label_counts[bucket].keys())
        other_labels.discard(label)

        per_label[label] = {
            "size": label_size,
            "n_buckets": len(buckets_with_label),
            "best_recall": best_recall,
            "best_f": best_f,
            "overcounting": len(buckets_with_label) - 1,
            "undercounting": len(other_labels),
        }

    inverse_purity = sum(
        (detail["size"] / n_items) * detail["best_recall"] for detail in per_label.values()
    )
    f_measure = sum(
        (detail["size"] / n_items) * detail["best_f"] for detail in per_label.values()
    )

    overcounting_by_label = {label: detail["overcounting"] for label, detail in per_label.items()}
    undercounting_by_label = {
        label: detail["undercounting"] for label, detail in per_label.items()
    }
    overcounting_values = list(overcounting_by_label.values())
    undercounting_values = list(undercounting_by_label.values())

    return {
        "n_items": n_items,
        "n_labels": len(label_sizes),
        "n_buckets": len(bucket_sizes),
        "purity": purity,
        "inverse_purity": inverse_purity,
        "f_measure": f_measure,
        "overcounting_mean": statistics.fmean(overcounting_values),
        "overcounting_std": statistics.pstdev(overcounting_values),
        "undercounting_mean": statistics.fmean(undercounting_values),
        "undercounting_std": statistics.pstdev(undercounting_values),
        "overcounting_by_label": overcounting_by_label,
        "undercounting_by_label": undercounting_by_label,
        "per_label": per_label,
        "label_sizes": dict(label_sizes),
        "bucket_sizes": dict(bucket_sizes),
    }
