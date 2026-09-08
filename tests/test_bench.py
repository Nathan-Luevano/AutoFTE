import json

import pytest

from autofte import bench


def _asan_report(serial, func, line, addr="0x50200000001a"):
    return f"""\
=================================================================
=={serial}==ERROR: AddressSanitizer: heap-buffer-overflow on address {addr}
READ of size 1 at {addr} thread T0
    #0 0x6320d8604225 in {func} /x/f.c:{line}
    #1 0x70a71cc29d8f  (/lib/x86_64-linux-gnu/libc.so.6+0x29d8f)
SUMMARY: AddressSanitizer: heap-buffer-overflow /x/f.c:{line} in {func}
==\
{serial}==ABORTING
"""


def _garbage_report():
    return "this is not a sanitizer report at all\njust some text\n"


def test_resolve_corpus_micro_returns_checked_in_dir():
    path, kind = bench.resolve_corpus("micro")
    assert kind == "micro"
    assert path == bench.MICRO_CORPUS_DIR
    assert path.is_dir()


def test_resolve_corpus_igor_raises_when_cache_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(bench, "IGOR_CACHE_DIR", tmp_path / "nonexistent")
    with pytest.raises(bench.CorpusNotFoundError, match="fetch_bench_corpus.sh"):
        bench.resolve_corpus("igor")


def test_resolve_corpus_path_spec_requires_existing_dir(tmp_path):
    missing = tmp_path / "nope"
    with pytest.raises(bench.CorpusNotFoundError):
        bench.resolve_corpus(str(missing))

    path, kind = bench.resolve_corpus(str(tmp_path))
    assert kind == "auto"
    assert path == tmp_path


def test_detect_corpus_kind_micro_vs_igor(tmp_path):
    micro_dir = tmp_path / "micro"
    (micro_dir / "some-bug").mkdir(parents=True)
    (micro_dir / "some-bug" / "case.txt").write_text("x")
    assert bench.detect_corpus_kind(micro_dir) == "micro"

    igor_dir = tmp_path / "igor"
    (igor_dir / "vendor__target" / "asan_logs" / "poc_A_raw").mkdir(parents=True)
    assert bench.detect_corpus_kind(igor_dir) == "igor"


def test_iter_micro_corpus_reads_label_directories(tmp_path):
    corpus = tmp_path / "corpus"
    (corpus / "bug-one").mkdir(parents=True)
    (corpus / "bug-two").mkdir(parents=True)
    (corpus / "bug-one" / "a.txt").write_text("report a")
    (corpus / "bug-one" / "b.txt").write_text("report b")
    (corpus / "bug-two" / "c.txt").write_text("report c")

    items = sorted(bench.iter_micro_corpus(corpus))

    assert items == [
        ("bug-one/a.txt", "bug-one", "report a"),
        ("bug-one/b.txt", "bug-one", "report b"),
        ("bug-two/c.txt", "bug-two", "report c"),
    ]


def test_iter_igor_corpus_extracts_target_and_poc_label(tmp_path):
    corpus = tmp_path / "data_sources"
    poc_dir = corpus / "vendor__target" / "asan_logs" / "poc_XYZ_raw"
    poc_dir.mkdir(parents=True)
    (poc_dir / "id-input.bin").write_text(_asan_report(1, "vuln_func", 42))

    items = list(bench.iter_igor_corpus(corpus))

    assert len(items) == 1
    item_id, label, text = items[0]
    assert item_id == "vendor__target/poc_XYZ_raw/id-input.bin"
    assert label == "vendor__target::XYZ"
    assert "vuln_func" in text


def test_iter_igor_corpus_skips_non_poc_directories(tmp_path):
    corpus = tmp_path / "data_sources"
    asan_logs = corpus / "vendor__target" / "asan_logs"
    (asan_logs / "poc_A_raw").mkdir(parents=True)
    (asan_logs / "poc_A_raw" / "f.bin").write_text(_asan_report(1, "f", 1))
    (asan_logs / "not_a_poc_dir").mkdir(parents=True)
    (asan_logs / "not_a_poc_dir" / "f.bin").write_text(_asan_report(2, "f", 1))

    items = list(bench.iter_igor_corpus(corpus))

    assert len(items) == 1
    assert items[0][1] == "vendor__target::A"


def test_run_bench_on_micro_fixture_corpus_matches_known_shape():
    result = bench.run_bench(bench.MICRO_CORPUS_DIR, "micro")

    assert result["corpus_kind"] == "micro"
    assert result["n_reports"] == 7
    assert result["parse_failures"] == 0
    # V1-RELEASE.md W2: the 3 strcpy-param-overlap fixtures used to have an
    # empty crash_stack (sanitizers.py did not recognize the ERROR summary
    # line as the start of the crash stack for that bug class) and fell
    # back to a shared label-only bucket; they now hash on their real
    # frames like everything else.
    assert result["nohash_count"] == 0

    metrics = result["metrics"]
    assert metrics["n_items"] == 7
    assert metrics["n_labels"] == 1
    assert metrics["n_buckets"] == 2
    assert metrics["purity"] == pytest.approx(1.0)
    assert metrics["inverse_purity"] == pytest.approx(4 / 7)
    assert metrics["f_measure"] == pytest.approx(2 * 1.0 * (4 / 7) / (1.0 + 4 / 7))


def test_run_bench_counts_parse_failures_without_crashing(tmp_path):
    corpus = tmp_path / "corpus"
    (corpus / "bug-one").mkdir(parents=True)
    (corpus / "bug-one" / "good.txt").write_text(_asan_report(1, "vuln", 8))
    (corpus / "bug-one" / "bad.txt").write_text(_garbage_report())

    result = bench.run_bench(corpus, "micro")

    assert result["n_reports"] == 2
    assert result["parse_failures"] == 1
    assert result["metrics"]["n_items"] == 1


def test_run_bench_returns_error_when_nothing_parses(tmp_path):
    corpus = tmp_path / "corpus"
    (corpus / "bug-one").mkdir(parents=True)
    (corpus / "bug-one" / "bad.txt").write_text(_garbage_report())

    result = bench.run_bench(corpus, "micro")

    assert result["metrics"] is None
    assert result["parse_failures"] == 1
    assert "error" in result


def test_run_bench_perfect_dedup_scores_one_across_metrics(tmp_path):
    corpus = tmp_path / "corpus"
    (corpus / "bug-one").mkdir(parents=True)
    (corpus / "bug-one" / "a.txt").write_text(_asan_report(1, "vuln", 8))
    (corpus / "bug-one" / "b.txt").write_text(_asan_report(2, "vuln", 8))

    result = bench.run_bench(corpus, "micro")
    metrics = result["metrics"]

    assert metrics["purity"] == pytest.approx(1.0)
    assert metrics["inverse_purity"] == pytest.approx(1.0)
    assert metrics["f_measure"] == pytest.approx(1.0)
    assert metrics["n_buckets"] == 1


def test_run_bench_igor_corpus_namespaces_buckets_by_target(tmp_path):
    corpus = tmp_path / "data_sources"
    for target in ("vendor__alpha", "vendor__beta"):
        poc_dir = corpus / target / "asan_logs" / "poc_A_raw"
        poc_dir.mkdir(parents=True)
        (poc_dir / "f.bin").write_text(_garbage_report())
        (poc_dir / "asan.bin").write_text(
            "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1\n"
            "SEGV on unknown address 0x1\n"
        )

    result = bench.run_bench(corpus, "igor")
    metrics = result["metrics"]

    assert metrics["n_labels"] == 2
    assert metrics["purity"] == pytest.approx(1.0)
    assert metrics["n_buckets"] == 2


def test_run_bench_micro_corpus_has_no_per_target_key():
    result = bench.run_bench(bench.MICRO_CORPUS_DIR, "micro")

    assert "per_target" not in result


def test_run_bench_igor_corpus_computes_per_target_metrics(tmp_path):
    corpus = tmp_path / "data_sources"

    # alpha: one real bug (label A), split across 2 different-frame buckets
    # by AutoFTE -- a known-by-hand inverse-purity failure for this target.
    alpha_dir = corpus / "vendor__alpha" / "asan_logs" / "poc_A_raw"
    alpha_dir.mkdir(parents=True)
    (alpha_dir / "a1.bin").write_text(_asan_report(1, "func_one", 10))
    (alpha_dir / "a2.bin").write_text(_asan_report(2, "func_two", 20))

    # beta: one real bug (label B), two crashes on the same frame -- AutoFTE
    # gets this one perfectly right.
    beta_dir = corpus / "vendor__beta" / "asan_logs" / "poc_B_raw"
    beta_dir.mkdir(parents=True)
    (beta_dir / "b1.bin").write_text(_asan_report(3, "func_beta", 30))
    (beta_dir / "b2.bin").write_text(_asan_report(4, "func_beta", 30))

    result = bench.run_bench(corpus, "igor")

    assert set(result["per_target"].keys()) == {"vendor__alpha", "vendor__beta"}

    alpha_metrics = result["per_target"]["vendor__alpha"]
    assert alpha_metrics["n_items"] == 2
    assert alpha_metrics["n_labels"] == 1
    assert alpha_metrics["n_buckets"] == 2
    assert alpha_metrics["purity"] == pytest.approx(1.0)
    assert alpha_metrics["inverse_purity"] == pytest.approx(0.5)
    assert alpha_metrics["f_measure"] == pytest.approx(2 * 1.0 * 0.5 / (1.0 + 0.5))

    beta_metrics = result["per_target"]["vendor__beta"]
    assert beta_metrics["n_items"] == 2
    assert beta_metrics["n_labels"] == 1
    assert beta_metrics["n_buckets"] == 1
    assert beta_metrics["purity"] == pytest.approx(1.0)
    assert beta_metrics["inverse_purity"] == pytest.approx(1.0)
    assert beta_metrics["f_measure"] == pytest.approx(1.0)

    # the pooled/aggregate metrics are unaffected by adding per_target.
    assert result["metrics"]["n_items"] == 4
    assert result["metrics"]["n_labels"] == 2


def test_run_bench_igor_corpus_computes_macro_metrics(tmp_path):
    corpus = tmp_path / "data_sources"

    # alpha: purity 1.0, inverse_purity 0.5 (see the per-target test above).
    alpha_dir = corpus / "vendor__alpha" / "asan_logs" / "poc_A_raw"
    alpha_dir.mkdir(parents=True)
    (alpha_dir / "a1.bin").write_text(_asan_report(1, "func_one", 10))
    (alpha_dir / "a2.bin").write_text(_asan_report(2, "func_two", 20))

    # beta: purity 1.0, inverse_purity 1.0.
    beta_dir = corpus / "vendor__beta" / "asan_logs" / "poc_B_raw"
    beta_dir.mkdir(parents=True)
    (beta_dir / "b1.bin").write_text(_asan_report(3, "func_beta", 30))
    (beta_dir / "b2.bin").write_text(_asan_report(4, "func_beta", 30))

    result = bench.run_bench(corpus, "igor")
    macro = result["macro_metrics"]

    # unweighted mean across the two targets, regardless of item count --
    # this is what distinguishes macro from the pooled/micro metric.
    assert macro["n_targets"] == 2
    assert macro["purity"] == pytest.approx(1.0)
    assert macro["inverse_purity"] == pytest.approx((0.5 + 1.0) / 2)
    alpha_f = 2 * 1.0 * 0.5 / (1.0 + 0.5)
    assert macro["f_measure"] == pytest.approx((alpha_f + 1.0) / 2)


def test_run_bench_micro_corpus_has_no_macro_metrics_key():
    result = bench.run_bench(bench.MICRO_CORPUS_DIR, "micro")

    assert "macro_metrics" not in result


def test_render_aggregation_table_shows_micro_and_macro_rows(tmp_path):
    corpus = tmp_path / "data_sources"
    alpha_dir = corpus / "vendor__alpha" / "asan_logs" / "poc_A_raw"
    alpha_dir.mkdir(parents=True)
    (alpha_dir / "a1.bin").write_text(_asan_report(1, "func_one", 10))
    (alpha_dir / "a2.bin").write_text(_asan_report(2, "func_two", 20))
    beta_dir = corpus / "vendor__beta" / "asan_logs" / "poc_B_raw"
    beta_dir.mkdir(parents=True)
    (beta_dir / "b1.bin").write_text(_asan_report(3, "func_beta", 30))
    (beta_dir / "b2.bin").write_text(_asan_report(4, "func_beta", 30))

    result = bench.run_bench(corpus, "igor")
    table = bench.render_aggregation_table(result)

    assert "micro (pooled)" in table
    assert "macro (per-target mean)" in table
    assert "GPTrace" in table  # the literature-aggregation note is included


def test_render_aggregation_table_reports_none_for_micro_result():
    result = bench.run_bench(bench.MICRO_CORPUS_DIR, "micro")

    table = bench.render_aggregation_table(result)

    assert "No micro/macro comparison" in table


def test_render_per_target_table_sorts_worst_f_measure_first(tmp_path):
    corpus = tmp_path / "data_sources"
    alpha_dir = corpus / "vendor__alpha" / "asan_logs" / "poc_A_raw"
    alpha_dir.mkdir(parents=True)
    (alpha_dir / "a1.bin").write_text(_asan_report(1, "func_one", 10))
    (alpha_dir / "a2.bin").write_text(_asan_report(2, "func_two", 20))
    beta_dir = corpus / "vendor__beta" / "asan_logs" / "poc_B_raw"
    beta_dir.mkdir(parents=True)
    (beta_dir / "b1.bin").write_text(_asan_report(3, "func_beta", 30))
    (beta_dir / "b2.bin").write_text(_asan_report(4, "func_beta", 30))

    result = bench.run_bench(corpus, "igor")
    table = bench.render_per_target_table(result)

    alpha_pos = table.index("vendor__alpha")
    beta_pos = table.index("vendor__beta")
    assert alpha_pos < beta_pos  # worse f_measure (alpha) listed before beta


def test_render_per_target_csv_has_header_and_rows(tmp_path):
    corpus = tmp_path / "data_sources"
    alpha_dir = corpus / "vendor__alpha" / "asan_logs" / "poc_A_raw"
    alpha_dir.mkdir(parents=True)
    (alpha_dir / "a1.bin").write_text(_asan_report(1, "func_one", 10))
    (alpha_dir / "a2.bin").write_text(_asan_report(2, "func_two", 20))

    result = bench.run_bench(corpus, "igor")
    csv_text = bench.render_per_target_csv(result)

    lines = csv_text.strip().splitlines()
    assert lines[0] == "target,n_items,n_labels,n_buckets,purity,inverse_purity,f_measure"
    assert any(line.startswith("vendor__alpha,") for line in lines[1:])


def test_render_per_target_csv_empty_for_micro_result():
    result = bench.run_bench(bench.MICRO_CORPUS_DIR, "micro")
    assert bench.render_per_target_csv(result) == ""


def test_render_per_target_table_reports_none_for_micro_result():
    result = bench.run_bench(bench.MICRO_CORPUS_DIR, "micro")

    table = bench.render_per_target_table(result)

    assert "No per-target metrics" in table


def test_render_table_reports_error_when_no_metrics():
    result = {
        "corpus_path": "x",
        "corpus_kind": "micro",
        "n_reports": 1,
        "parse_failures": 1,
        "nohash_count": 0,
        "metrics": None,
        "error": "no reports could be parsed and hashed; nothing to score",
    }

    table = bench.render_table(result)

    assert "No metrics" in table
    assert "nothing to score" in table


def test_diff_against_baseline_reports_deltas():
    baseline = {"metrics": {"purity": 0.9, "inverse_purity": 0.5, "f_measure": 0.6,
                             "overcounting_mean": 2.0, "undercounting_mean": 0.0}}
    current = {"metrics": {"purity": 0.85, "inverse_purity": 0.7, "f_measure": 0.65,
                            "overcounting_mean": 1.0, "undercounting_mean": 0.0}}

    lines = bench.diff_against_baseline(current, baseline)

    assert any("purity" in line and "0.9000" in line and "0.8500" in line for line in lines)
    assert len(lines) == 5


def test_check_regression_flags_purity_drop_beyond_threshold():
    baseline = {"metrics": {"purity": 0.98, "f_measure": 0.76}}
    current = {"metrics": {"purity": 0.90, "f_measure": 0.76}}

    reasons = bench.check_regression(
        current, baseline, fail_purity_drop_points=2.0, fail_under_f=None
    )

    assert any("purity dropped" in reason for reason in reasons)


def test_check_regression_flags_any_f_measure_drop():
    baseline = {"metrics": {"purity": 0.98, "f_measure": 0.80}}
    current = {"metrics": {"purity": 0.98, "f_measure": 0.79}}

    reasons = bench.check_regression(
        current, baseline, fail_purity_drop_points=2.0, fail_under_f=None
    )

    assert any("f_measure dropped" in reason for reason in reasons)


def test_check_regression_passes_when_baseline_omitted():
    current = {"metrics": {"purity": 0.10, "f_measure": 0.10}}

    reasons = bench.check_regression(current, None, fail_purity_drop_points=2.0, fail_under_f=None)

    assert reasons == []


def test_check_regression_fail_under_f_is_absolute():
    current = {"metrics": {"purity": 1.0, "f_measure": 0.5}}

    reasons = bench.check_regression(current, None, fail_purity_drop_points=2.0, fail_under_f=0.75)

    assert any("below --fail-under-f" in reason for reason in reasons)


def test_write_and_load_results_round_trip(tmp_path):
    result = bench.run_bench(bench.MICRO_CORPUS_DIR, "micro")
    out_path = tmp_path / "bench-results.json"

    bench.write_results(out_path, result)
    loaded = bench.load_results(out_path)

    assert loaded["metrics"]["n_items"] == result["metrics"]["n_items"]
    with open(out_path) as handle:
        json.load(handle)
