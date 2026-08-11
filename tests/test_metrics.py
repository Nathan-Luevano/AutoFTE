import pytest

from autofte.metrics import compute_metrics


def _assignments(label_bucket_pairs):
    return [
        (f"item{index}", label, bucket)
        for index, (label, bucket) in enumerate(label_bucket_pairs)
    ]


def test_one_bucket_per_crash_gives_perfect_purity_and_bad_inverse_purity():
    """Degenerate baseline #1 (research/05 SS2.1): one bucket per crash trivially
    makes every bucket 100% pure (it holds exactly one label), so Purity must be
    exactly 1.0 regardless of the label distribution -- but since a label with
    more than one item never gets all its items into one bucket, InversePurity
    collapses to n_labels / N.
    """
    assignments = _assignments(
        [
            ("A", "c0"),
            ("A", "c1"),
            ("A", "c2"),
            ("B", "c3"),
            ("B", "c4"),
        ]
    )

    result = compute_metrics(assignments)

    assert result["purity"] == pytest.approx(1.0)
    assert result["inverse_purity"] == pytest.approx(2 / 5)
    assert result["n_items"] == 5
    assert result["n_labels"] == 2
    assert result["n_buckets"] == 5


def test_one_bucket_per_crash_with_one_item_per_label_is_also_perfect():
    """The stated exception to baseline #1: when every label also has exactly
    one item, one-bucket-per-crash is simultaneously perfect on both axes.
    """
    assignments = _assignments(
        [
            ("A", "c0"),
            ("B", "c1"),
            ("C", "c2"),
            ("D", "c3"),
            ("E", "c4"),
        ]
    )

    result = compute_metrics(assignments)

    assert result["purity"] == pytest.approx(1.0)
    assert result["inverse_purity"] == pytest.approx(1.0)


def test_one_bucket_for_everything_gives_perfect_inverse_purity_and_bad_purity():
    """Degenerate baseline #2 (research/05 SS2.1): one bucket for every crash
    trivially recovers every label's items entirely within that bucket, so
    InversePurity must be exactly 1.0 -- but Purity collapses to the largest
    label's share of N, since that bucket's best-matching label can only ever
    be the plurality label.
    """
    assignments = _assignments(
        [
            ("A", "everything"),
            ("A", "everything"),
            ("A", "everything"),
            ("B", "everything"),
            ("B", "everything"),
        ]
    )

    result = compute_metrics(assignments)

    assert result["inverse_purity"] == pytest.approx(1.0)
    assert result["purity"] == pytest.approx(3 / 5)


def test_one_bucket_for_everything_with_one_label_is_also_perfect():
    """The stated exception to baseline #2: with only one ground-truth label,
    one-bucket-for-everything is simultaneously perfect on both axes.
    """
    assignments = _assignments([("A", "everything")] * 4)

    result = compute_metrics(assignments)

    assert result["purity"] == pytest.approx(1.0)
    assert result["inverse_purity"] == pytest.approx(1.0)


def test_worked_example_matches_hand_computed_purity_inverse_purity_and_f_measure():
    """Hand-computed ground truth for a 2-label, 3-bucket, 6-item assignment.

    Ground truth: label A has 4 items, label B has 2 items (N = 6).
    Bucketing: bucket1 = {A, A, A} (size 3, pure-A), bucket2 = {A, B}
    (size 2, mixed), bucket3 = {B} (size 1, pure-B).

    Purity:
      bucket1: precision_A = 3/3 = 1.0   -> (3/6) * 1.0    = 1/2
      bucket2: max(precision_A, precision_B) = 1/2 -> (2/6) * 1/2 = 1/6
      bucket3: precision_B = 1/1 = 1.0   -> (1/6) * 1.0    = 1/6
      Purity = 1/2 + 1/6 + 1/6 = 5/6

    InversePurity:
      label A: recall in bucket1 = 3/4, in bucket2 = 1/4 -> best = 3/4
               -> (4/6) * 3/4 = 1/2
      label B: recall in bucket2 = 1/2, in bucket3 = 1/2 -> best = 1/2
               -> (2/6) * 1/2 = 1/6
      InversePurity = 1/2 + 1/6 = 2/3

    F-measure:
      label A best F: bucket1 P=1.0 R=3/4 -> F=2*1*0.75/1.75 = 6/7
                       bucket2 P=0.5 R=0.25 -> F=1/3
                       best = 6/7 -> (4/6) * 6/7 = 4/7
      label B best F: bucket2 P=0.5 R=0.5 -> F=0.5
                       bucket3 P=1.0 R=0.5 -> F=2/3
                       best = 2/3 -> (2/6) * 2/3 = 2/9
      F-measure = 4/7 + 2/9 = 50/63

    Overcounting: label A spans {bucket1, bucket2} -> 2 - 1 = 1.
                  label B spans {bucket2, bucket3} -> 2 - 1 = 1.
    Undercounting: label A shares a bucket (bucket2) with B -> 1.
                   label B shares a bucket (bucket2) with A -> 1.
    """
    assignments = _assignments(
        [
            ("A", "bucket1"),
            ("A", "bucket1"),
            ("A", "bucket1"),
            ("A", "bucket2"),
            ("B", "bucket2"),
            ("B", "bucket3"),
        ]
    )

    result = compute_metrics(assignments)

    assert result["purity"] == pytest.approx(5 / 6)
    assert result["inverse_purity"] == pytest.approx(2 / 3)
    assert result["f_measure"] == pytest.approx(50 / 63)

    assert result["overcounting_by_label"] == {"A": 1, "B": 1}
    assert result["undercounting_by_label"] == {"A": 1, "B": 1}
    assert result["overcounting_mean"] == pytest.approx(1.0)
    assert result["overcounting_std"] == pytest.approx(0.0)
    assert result["undercounting_mean"] == pytest.approx(1.0)
    assert result["undercounting_std"] == pytest.approx(0.0)


def test_matches_published_crashwalk_error_profile_shape():
    """Sanity check against the HARDENING.md / research/05 SS2.4 published
    Crashwalk baseline shape (Purity ~98%, InversePurity ~69%): a stack-hash
    bucketer almost never merges two different bugs (high purity) but
    shatters one bug across many buckets (low inverse purity).

    Construction: 50 items total. Label "Bug1" has 33 items, all correctly
    landing in one bucket "B1". Label "BUG" has 17 items: one lands (stray)
    in "B1" alongside Bug1's items, and the other 16 are each split into
    their own singleton bucket. Purity = (N - 1) / N = 49/50 = 0.98 exactly
    (only one item, the stray BUG item, sits outside its label's plurality
    bucket anywhere in the corpus). InversePurity = (N - 17 + 1) / N =
    34/50 = 0.68, in the ~69% neighborhood of the published number, because
    "BUG"'s best bucket only ever holds 1 of its 17 items.
    """
    assignments = _assignments(
        [("Bug1", "B1")] * 33
        + [("BUG", "B1")]
        + [("BUG", f"S{i}") for i in range(16)]
    )

    result = compute_metrics(assignments)

    assert result["n_items"] == 50
    assert result["purity"] == pytest.approx(0.98)
    assert result["inverse_purity"] == pytest.approx(0.68)
    assert 0.95 <= result["purity"] <= 1.0
    assert 0.6 <= result["inverse_purity"] <= 0.75

    assert result["per_label"]["BUG"]["n_buckets"] == 17
    assert result["per_label"]["BUG"]["overcounting"] == 16


def test_empty_assignments_raise_value_error():
    with pytest.raises(ValueError):
        compute_metrics([])


def test_per_label_and_size_detail_present_for_bench_reporting():
    assignments = _assignments(
        [
            ("A", "bucket1"),
            ("A", "bucket1"),
            ("B", "bucket2"),
        ]
    )

    result = compute_metrics(assignments)

    assert result["label_sizes"] == {"A": 2, "B": 1}
    assert result["bucket_sizes"] == {"bucket1": 2, "bucket2": 1}
    assert set(result["per_label"].keys()) == {"A", "B"}
    assert result["per_label"]["A"]["size"] == 2
    assert result["per_label"]["A"]["best_recall"] == pytest.approx(1.0)
    assert result["per_label"]["A"]["best_f"] == pytest.approx(1.0)
