#!/usr/bin/env bash
# Records autofte-demo.cast: a narrated terminal walkthrough of `autofte demo`.
#
# This is the script asciinema executes (via `asciinema rec -c`) to produce
# the .cast that gets converted to autofte-demo.gif for the README. It is
# checked in so the recording is reproducible -- see CONTRIBUTING.md.
#
# Requires: autofte installed, an Ollama server with a working model
# (default glm-4.7-flash:latest -- see the benchmark record for why
# gpt-oss:20b is excluded), and the vuln-demo target already built.
set -euo pipefail

MODEL="${AUTOFTE_DEMO_MODEL:-glm-4.7-flash:latest}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

type_line() {
  # Prints a line instantly (asciinema just records real terminal output;
  # we're not simulating keystrokes, just pacing narration with sleeps).
  printf '%s\n' "$1"
}

pause() { sleep "$1"; }

clear
type_line "\$ # AutoFTE: turn a pile of crash files into triaged, explained bugs."
pause 1.2
type_line "\$ # We'll feed it a deliberately vulnerable target with 4 distinct bugs"
type_line "\$ # and 12 pre-generated crashes, and let it sort them out."
pause 1.8
echo
type_line "\$ sed -n '38,41p' examples/vuln-demo/vuln.c   # one of the 4 bugs it'll find"
sed -n '38,41p' examples/vuln-demo/vuln.c
pause 2.2
echo
type_line "\$ ls examples/vuln-demo/crashes | wc -l"
ls examples/vuln-demo/crashes | wc -l
pause 1.5
echo
type_line "\$ autofte demo --verbose --model $MODEL"
pause 0.8
autofte demo --verbose --model "$MODEL"
pause 1.5
echo
type_line "\$ # A static dashboard (no server needed) also got written:"
type_line "\$ ls autofte-demo-output/dashboard/"
ls autofte-demo-output/dashboard/
pause 2.5
