#!/usr/bin/env bash
set -euo pipefail

TARGET_BINARY=${1:-./target}
SOURCE_FILE=${2:-vuln.c}
TRIAGE_JSON=${TRIAGE_JSON:-crash_triage.json}
BINARY_ANALYSIS_JSON=${BINARY_ANALYSIS_JSON:-binary_analysis.json}
LLM_ANALYSIS_JSON=${LLM_ANALYSIS_JSON:-llm_analysis.json}
SUMMARY_MD=${SUMMARY_MD:-analysis_summary.md}
DASHBOARD_DIR=${DASHBOARD_DIR:-dashboard}

pick_crash_dir() {
    local candidate
    for candidate in "out/default/crashes" "out/crashes" "crashes"; do
        if [[ -d "$candidate" ]]; then
            echo "$candidate"
            return 0
        fi
    done
    return 1
}

write_json_stub() {
    local path=$1
    local message=$2
    python3 - "$path" "$message" <<'PY'
import json
import sys

path = sys.argv[1]
message = sys.argv[2]

with open(path, "w", encoding="utf-8") as handle:
    json.dump({"status": "skipped", "summary": message}, handle, indent=2)
PY
}

if [[ ! -x "$TARGET_BINARY" ]]; then
    echo "Error: target binary not found or not executable: $TARGET_BINARY"
    echo "Build it first with: make"
    exit 1
fi

CRASHES_DIR=${CRASHES_DIR:-$(pick_crash_dir || true)}
if [[ -z "${CRASHES_DIR:-}" ]]; then
    echo "Error: no crash directory found"
    echo "Expected one of: out/default/crashes, out/crashes, crashes"
    exit 1
fi

echo "AutoFTE local pipeline"
echo "Target: $TARGET_BINARY"
echo "Source: $SOURCE_FILE"
echo "Crashes: $CRASHES_DIR"
echo ""

python3 triage.py \
    --crashes-dir "$CRASHES_DIR" \
    --target-binary "$TARGET_BINARY" \
    --output "$TRIAGE_JSON"

if python3 binary_analyzer.py "$TARGET_BINARY" --output "$BINARY_ANALYSIS_JSON"; then
    :
else
    write_json_stub "$BINARY_ANALYSIS_JSON" "Binary analysis did not complete cleanly."
fi

LLM_ARGS=(
    --triage-json "$TRIAGE_JSON"
    --binary-analysis "$BINARY_ANALYSIS_JSON"
    --output "$LLM_ANALYSIS_JSON"
)

if [[ -f "$SOURCE_FILE" ]]; then
    LLM_ARGS+=(--source-file "$SOURCE_FILE")
fi

if python3 llm_analyzer.py "${LLM_ARGS[@]}"; then
    :
else
    write_json_stub "$LLM_ANALYSIS_JSON" "Ollama was not available, so this run only includes local analysis."
fi

python3 report_builder.py \
    --target-binary "$TARGET_BINARY" \
    --source-file "$SOURCE_FILE" \
    --triage-json "$TRIAGE_JSON" \
    --binary-analysis "$BINARY_ANALYSIS_JSON" \
    --llm-analysis "$LLM_ANALYSIS_JSON" \
    --output "$SUMMARY_MD"

python3 sec_dash.py \
    --triage-json "$TRIAGE_JSON" \
    --binary-analysis "$BINARY_ANALYSIS_JSON" \
    --llm-analysis "$LLM_ANALYSIS_JSON" \
    --output-dir "$DASHBOARD_DIR"

echo ""
echo "Done."
echo "  Triage: $TRIAGE_JSON"
echo "  Binary analysis: $BINARY_ANALYSIS_JSON"
echo "  LLM notes: $LLM_ANALYSIS_JSON"
echo "  Summary: $SUMMARY_MD"
echo "  Dashboard: $DASHBOARD_DIR/index.html"
