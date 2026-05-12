#!/usr/bin/env bash
set -euo pipefail

TARGET=${1:-examples/vuln-demo/target}
INPUT_DIR=${2:-examples/vuln-demo/in}
OUTPUT_DIR=${3:-out}

if ! command -v afl-fuzz >/dev/null 2>&1; then
    echo "Error: afl-fuzz was not found in PATH"
    exit 1
fi

if [[ ! -x "$TARGET" ]]; then
    echo "Error: target binary not found or not executable: $TARGET"
    exit 1
fi

if [[ ! -d "$INPUT_DIR" ]]; then
    echo "Error: input directory not found: $INPUT_DIR"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"
rm -rf "$OUTPUT_DIR"/*

export AFL_SKIP_CPUFREQ=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_SKIP_BIN_CHECK=1

afl-fuzz -i "$INPUT_DIR" -o "$OUTPUT_DIR" -m none -t 1000+ -d -p fast -- "$TARGET" @@
