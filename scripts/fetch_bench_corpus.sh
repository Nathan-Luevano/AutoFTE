#!/usr/bin/env bash
set -euo pipefail

RECORD_URL="https://zenodo.org/api/records/18708473/files/data_sources.tar.gz/content"
EXPECTED_MD5="791ae75152a42be2831999af06a630e4"
CACHE_DIR="${AUTOFTE_BENCH_CACHE_DIR:-$HOME/.cache/autofte/bench}"
ARCHIVE_PATH="$CACHE_DIR/data_sources.tar.gz"

mkdir -p "$CACHE_DIR"

if [[ -d "$CACHE_DIR/data_sources" ]]; then
    echo "Corpus already extracted at $CACHE_DIR/data_sources -- nothing to do."
    echo "Remove that directory (or set AUTOFTE_BENCH_CACHE_DIR) to re-fetch."
    exit 0
fi

echo "Downloading data_sources.tar.gz (92.6 MB, Apache-2.0) from Zenodo record 18708473..."
curl -sL --fail -o "$ARCHIVE_PATH" "$RECORD_URL"

echo "Verifying checksum..."
ACTUAL_MD5=$(md5sum "$ARCHIVE_PATH" | awk '{print $1}')
if [[ "$ACTUAL_MD5" != "$EXPECTED_MD5" ]]; then
    echo "Error: checksum mismatch for $ARCHIVE_PATH"
    echo "  expected: $EXPECTED_MD5"
    echo "  actual:   $ACTUAL_MD5"
    rm -f "$ARCHIVE_PATH"
    exit 1
fi
echo "Checksum OK ($ACTUAL_MD5)."

echo "Extracting to $CACHE_DIR..."
tar xzf "$ARCHIVE_PATH" -C "$CACHE_DIR"

echo "Done. Corpus is at $CACHE_DIR/data_sources"
echo "Run: autofte bench --corpus igor"
