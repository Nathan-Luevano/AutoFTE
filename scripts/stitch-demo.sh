#!/usr/bin/env bash
# Stitches autofte-demo.gif (terminal recording) and autofte-dashboard.png
# (dashboard screenshot) into one combined autofte-demo-combined.gif for the
# README's hero embed. Checked in so the combined asset is reproducible --
# see CONTRIBUTING.md. Requires ffmpeg (and ffprobe, part of the same
# package) on PATH.
#
# The two source assets have very different aspect ratios (a landscape
# terminal recording vs. a tall full-page dashboard screenshot), so this
# doesn't just concatenate them -- it:
#   1. scales/crops the terminal GIF to a shared WxH canvas
#   2. turns the static dashboard PNG into a short clip that holds on the
#      top, middle, and bottom of the page (a stepped scroll, not a smooth
#      continuous pan) on the same canvas
#   3. concatenates the two clips
#   4. re-encodes the result to GIF with ffmpeg's two-pass palette technique
#
# The stepped hold in step 2 matters for file size: an earlier attempt at a
# smooth, continuously-panning scroll produced a ~10MB GIF, because every
# frame of a continuous pan is visually unique and compresses poorly.
# Holding on 3 waypoints means most consecutive frames are near-identical,
# which the palette/GIF encoder compresses far better -- the same content,
# under 1MB.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

TERM_GIF="${1:-autofte-demo.gif}"
DASH_PNG="${2:-autofte-dashboard.png}"
OUT_GIF="${3:-autofte-demo-combined.gif}"

WIDTH="${STITCH_WIDTH:-640}"
HEIGHT="${STITCH_HEIGHT:-452}"
FPS="${STITCH_FPS:-8}"
HOLD="${STITCH_HOLD_SECONDS:-2}"          # seconds held at each dashboard waypoint
DASH_DURATION=$((HOLD * 3))

for tool in ffmpeg ffprobe; do
  command -v "$tool" >/dev/null 2>&1 || { echo "error: $tool not found on PATH" >&2; exit 1; }
done

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "-> terminal segment (${WIDTH}x${HEIGHT}, ${FPS}fps) from $TERM_GIF"
ffmpeg -y -v error -i "$TERM_GIF" \
  -vf "scale=${WIDTH}:-2,crop=${WIDTH}:${HEIGHT}:0:(ih-${HEIGHT})/2" \
  -r "$FPS" "$tmp/term_seg.mp4"

echo "-> dashboard segment (stepped top/middle/bottom hold, ${DASH_DURATION}s) from $DASH_PNG"
mid=$((HOLD))
end=$((HOLD * 2))
ffmpeg -y -v error -loop 1 -i "$DASH_PNG" -t "$DASH_DURATION" -r "$FPS" \
  -vf "scale=${WIDTH}:-2,crop=${WIDTH}:${HEIGHT}:0:'if(lt(t\,${mid})\,0\,if(lt(t\,${end})\,(ih-${HEIGHT})/2\,ih-${HEIGHT}))'" \
  "$tmp/dash_seg.mp4"

echo "-> concatenating"
ffmpeg -y -v error -i "$tmp/term_seg.mp4" -i "$tmp/dash_seg.mp4" \
  -filter_complex "[0:v][1:v]concat=n=2:v=1:a=0[v]" -map "[v]" "$tmp/combined.mp4"

echo "-> two-pass palette GIF encode -> $OUT_GIF"
ffmpeg -y -v error -i "$tmp/combined.mp4" \
  -vf "fps=${FPS},scale=${WIDTH}:-1:flags=lanczos,palettegen=stats_mode=diff" \
  "$tmp/palette.png"
ffmpeg -y -v error -i "$tmp/combined.mp4" -i "$tmp/palette.png" \
  -filter_complex "fps=${FPS},scale=${WIDTH}:-1:flags=lanczos[x];[x][1:v]paletteuse=dither=bayer" \
  "$OUT_GIF"

echo "Wrote $OUT_GIF ($(du -h "$OUT_GIF" | cut -f1))"
