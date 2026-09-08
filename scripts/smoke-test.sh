#!/usr/bin/env bash
# End-to-end smoke test: exercises the actual `autofte` CLI the way a user
# would, not just the unit-test suite. `pytest` mocks most of its subprocess
# and filesystem boundaries; this script instead runs the real binary,
# the real bundled vuln-demo target, and the real dashboard/report writers,
# so a change that passes `pytest` but breaks the CLI wiring itself (a
# renamed flag, a broken default path, a template that no longer renders)
# still gets caught. Run it from the repo root after `pip install -e .`.
#
# Every step here is independent of a running Ollama server -- LLM-backed
# steps are either run with --skip-llm, or (the `demo` steps, which attempt
# an LLM write-up best-effort) bounded with --llm-timeout so a *real* local
# Ollama daemon can never turn this into a hang: `autofte`'s own default is
# an unbounded LLM call (see config.resolve_timeout's docstring), which is
# the right default for interactive use but wrong for a script that needs
# to finish deterministically in CI/offline. See CONTRIBUTING.md for the
# (separately documented, LLM-dependent) demo-recording flow.
#
# Usage: scripts/smoke-test.sh [--keep]
#   --keep   don't delete the scratch output directory on exit (for debugging)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

KEEP=0
if [[ "${1:-}" == "--keep" ]]; then
    KEEP=1
fi

WORKDIR="$(mktemp -d -t autofte-smoke.XXXXXX)"
cleanup() {
    if [[ "$KEEP" -eq 1 ]]; then
        echo "Keeping scratch dir: $WORKDIR"
    else
        rm -rf "$WORKDIR"
    fi
}
trap cleanup EXIT

PASS=0
FAIL=0
STEP=""

step() {
    STEP="$1"
    echo
    echo "==> $STEP"
}

ok() {
    PASS=$((PASS + 1))
    echo "    OK"
}

fail() {
    FAIL=$((FAIL + 1))
    echo "    FAIL: $STEP: $1"
}

require_file() {
    local path="$1" desc="$2"
    if [[ ! -s "$path" ]]; then
        fail "expected $desc at $path, but it's missing or empty"
        return 1
    fi
    return 0
}

require_substring() {
    local haystack="$1" needle="$2" desc="$3"
    if [[ "$haystack" != *"$needle"* ]]; then
        fail "expected $desc to contain '$needle'"
        return 1
    fi
    return 0
}

# 1. Cheap checks first -- fail fast before touching real binaries.
step "ruff check"
if ruff check autofte tests scripts >"$WORKDIR/ruff.log" 2>&1; then
    ok
else
    fail "ruff check failed"
    cat "$WORKDIR/ruff.log"
fi

step "pytest"
if pytest -q >"$WORKDIR/pytest.log" 2>&1; then
    ok
else
    fail "pytest failed"
    tail -n 60 "$WORKDIR/pytest.log"
fi

# 2. autofte doctor -- environment sanity check, always exit 0 (it reports
# missing optional tools rather than failing on them).
step "autofte doctor"
if DOCTOR_OUT=$(autofte doctor 2>&1); then
    require_substring "$DOCTOR_OUT" "gdb" "doctor output" || true
    ok
else
    fail "autofte doctor exited non-zero"
    echo "$DOCTOR_OUT"
fi

# 3. autofte demo -- the bundled zero-setup path. Builds the demo target
# (if needed), triages, binscans, attempts an LLM write-up best-effort,
# writes the report and dashboard, all in one command. --llm-timeout bounds
# that best-effort write-up: `autofte`'s own default is an unbounded LLM
# call (the right default for interactive use), which would otherwise hang
# this script for as long as a *real* local Ollama daemon takes to answer.
DEMO_LLM_TIMEOUT=20
step "autofte demo (default, quiet)"
DEMO_DIR="$WORKDIR/demo-default"
if DEMO_OUT=$(autofte demo --output-dir "$DEMO_DIR" --llm-timeout "$DEMO_LLM_TIMEOUT" 2>&1); then
    require_substring "$DEMO_OUT" "root cause" "demo summary line" || true
    require_file "$DEMO_DIR/crash_triage.json" "demo triage output"
    require_file "$DEMO_DIR/dashboard/index.html" "demo dashboard"
    ok
else
    fail "autofte demo exited non-zero"
    echo "$DEMO_OUT"
fi

step "autofte demo --verbose"
DEMO_VERBOSE_DIR="$WORKDIR/demo-verbose"
if DEMO_VERBOSE_OUT=$(autofte demo --verbose --output-dir "$DEMO_VERBOSE_DIR" --llm-timeout "$DEMO_LLM_TIMEOUT" 2>&1); then
    require_substring "$DEMO_VERBOSE_OUT" "AutoFTE local pipeline" "verbose demo trace" || true
    require_file "$DEMO_VERBOSE_DIR/analysis_summary.md" "verbose demo report"
    ok
else
    fail "autofte demo --verbose exited non-zero"
    echo "$DEMO_VERBOSE_OUT"
fi

# 4. Direct triage / binscan / crash-info against vuln-demo, independent
# of the `demo` wrapper -- these are the commands a real user runs by hand
# against their own fuzzing output.
VULN_DEMO="$REPO_ROOT/examples/vuln-demo"
TARGET_ASAN="$VULN_DEMO/target_asan"
CRASHES_DIR="$VULN_DEMO/crashes"

if [[ ! -x "$TARGET_ASAN" ]]; then
    step "build examples/vuln-demo target_asan"
    if (cd "$VULN_DEMO" && make target_asan >"$WORKDIR/build.log" 2>&1); then
        ok
    else
        fail "make target_asan failed"
        cat "$WORKDIR/build.log"
    fi
fi

step "autofte triage"
TRIAGE_JSON="$WORKDIR/crash_triage.json"
if autofte triage --crashes-dir "$CRASHES_DIR" --target-binary "$TARGET_ASAN" \
    --output "$TRIAGE_JSON" --quiet >"$WORKDIR/triage.log" 2>&1; then
    require_file "$TRIAGE_JSON" "triage JSON"
    ok
else
    fail "autofte triage exited non-zero"
    cat "$WORKDIR/triage.log"
fi

step "autofte binscan"
BINSCAN_JSON="$WORKDIR/binary_analysis.json"
if autofte binscan "$TARGET_ASAN" -o "$BINSCAN_JSON" >"$WORKDIR/binscan.log" 2>&1; then
    require_file "$BINSCAN_JSON" "binscan JSON"
    ok
else
    fail "autofte binscan exited non-zero"
    cat "$WORKDIR/binscan.log"
fi

step "autofte crash-info"
# Run with cwd at the fuzzing project root (parent of crashes/), matching
# real usage: pick_crash_dir() looks for a "crashes" subdir under cwd, not
# for crash files directly in cwd.
if CRASH_INFO_OUT=$(cd "$VULN_DEMO" && autofte crash-info 2>&1); then
    [[ -n "$CRASH_INFO_OUT" ]] && ok || fail "autofte crash-info produced no output"
else
    fail "autofte crash-info exited non-zero"
    echo "$CRASH_INFO_OUT"
fi

# 5. Regression-gate bench run -- confirms the checked-in micro corpus and
# baseline still score as expected end-to-end through the real CLI.
step "autofte bench --corpus micro --baseline benchmarks/baseline.json"
if BENCH_OUT=$(autofte bench --corpus micro --baseline benchmarks/baseline.json 2>&1); then
    ok
else
    fail "autofte bench exited non-zero"
    echo "$BENCH_OUT"
fi

# 6. Full pipeline wiring, deterministically (no Ollama dependency).
step "autofte pipeline --skip-llm"
PIPELINE_DIR="$WORKDIR/pipeline"
mkdir -p "$PIPELINE_DIR"
if (
    cd "$PIPELINE_DIR" && autofte pipeline "$TARGET_ASAN" "$VULN_DEMO/vuln.c" \
        --crashes-dir "$CRASHES_DIR" --skip-llm --quiet
) >"$WORKDIR/pipeline.log" 2>&1; then
    require_file "$PIPELINE_DIR/crash_triage.json" "pipeline triage output"
    require_file "$PIPELINE_DIR/analysis_summary.md" "pipeline report"
    require_file "$PIPELINE_DIR/dashboard/index.html" "pipeline dashboard"
    ok
else
    fail "autofte pipeline --skip-llm exited non-zero"
    cat "$WORKDIR/pipeline.log"
fi

EMPTY_LLM_JSON="$WORKDIR/empty-llm.json"
echo '{}' >"$EMPTY_LLM_JSON"

step "autofte summary --format json"
SUMMARY_JSON="$WORKDIR/summary.json"
if autofte summary --triage-json "$TRIAGE_JSON" --binary-analysis "$BINSCAN_JSON" \
    --llm-analysis "$EMPTY_LLM_JSON" --format json --output "$SUMMARY_JSON" \
    >"$WORKDIR/summary.log" 2>&1; then
    require_file "$SUMMARY_JSON" "summary JSON" && \
        require_substring "$(cat "$SUMMARY_JSON")" "autofte-summary/1" "summary schema" && ok
else
    fail "autofte summary exited non-zero"
    cat "$WORKDIR/summary.log"
fi

step "autofte summary (table)"
if SUMMARY_TABLE=$(autofte summary --triage-json "$TRIAGE_JSON" \
    --binary-analysis "$BINSCAN_JSON" --llm-analysis "$EMPTY_LLM_JSON" 2>&1); then
    require_substring "$SUMMARY_TABLE" "DIFFICULTY" "summary table header" && ok
else
    fail "autofte summary (table) exited non-zero"
    echo "$SUMMARY_TABLE"
fi

# 7. Dashboard generation directly, off the triage/binscan artifacts from
# step 4, to isolate dashboard.py from the pipeline/demo wrappers.
step "autofte dashboard"
DASHBOARD_DIR="$WORKDIR/dashboard"
if autofte dashboard --triage-json "$TRIAGE_JSON" --binary-analysis "$BINSCAN_JSON" \
    --output-dir "$DASHBOARD_DIR" >"$WORKDIR/dashboard.log" 2>&1; then
    require_file "$DASHBOARD_DIR/index.html" "dashboard index.html"
    SIZE=$(wc -c <"$DASHBOARD_DIR/index.html")
    if [[ "$SIZE" -lt 1000 ]]; then
        fail "dashboard index.html looks too small ($SIZE bytes)"
    else
        ok
    fi
else
    fail "autofte dashboard exited non-zero"
    cat "$WORKDIR/dashboard.log"
fi

echo
echo "======================================"
echo "smoke test: $PASS passed, $FAIL failed"
echo "======================================"

if [[ "$FAIL" -gt 0 ]]; then
    exit 1
fi
