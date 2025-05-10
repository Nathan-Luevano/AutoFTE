if [ $# -eq 0 ]; then
    CRASH_FILE=$(ls -1 out/default/crashes/id* 2>/dev/null | head -n 1)
    if [ -z "$CRASH_FILE" ]; then
        echo "No crash files found in out/default/crashes/"
        exit 1
    fi
else
    CRASH_FILE="$1"
fi

echo "Analyzing crash file: $CRASH_FILE"
echo "==========================="

echo "Crash input content (first 100 bytes):"
hexdump -C "$CRASH_FILE" | head -n 7
echo "..."

SIZE=$(stat --printf="%s" "$CRASH_FILE")
echo -e "\nCrash file size: $SIZE bytes"
