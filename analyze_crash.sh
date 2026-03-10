#!/usr/bin/env bash
set -euo pipefail

pick_crash_file() {
    local dir
    for dir in "out/default/crashes" "out/crashes" "crashes"; do
        if [[ -d "$dir" ]]; then
            find "$dir" -type f ! -name "README.txt" | sort | tail -n 1
            return 0
        fi
    done
    return 1
}

if [[ $# -gt 0 ]]; then
    CRASH_FILE=$1
else
    CRASH_FILE=$(pick_crash_file || true)
fi

if [[ -z "${CRASH_FILE:-}" || ! -f "$CRASH_FILE" ]]; then
    echo "Error: crash file not found"
    exit 1
fi

SIZE=$(stat --printf="%s" "$CRASH_FILE" 2>/dev/null || stat -f "%z" "$CRASH_FILE")
TYPE=$(file -b "$CRASH_FILE")

echo "Crash file: $CRASH_FILE"
echo "Size: $SIZE bytes"
echo "Type: $TYPE"
echo ""

if file "$CRASH_FILE" | grep -qi text; then
    echo "Preview:"
    head -n 12 "$CRASH_FILE"
else
    echo "Hex preview:"
    hexdump -C "$CRASH_FILE" | head -n 12
fi
