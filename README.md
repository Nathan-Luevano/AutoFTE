# AutoFTE

<p align="center">
  <img src="AutoFTE.jpg" alt="AutoFTE logo" width="220">
</p>

<p align="center">
  <b>Local-first crash triage, binary mitigation analysis, and LLM-assisted write-ups for fuzzing runs.</b>
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
  <img alt="Python 3.9+" src="https://img.shields.io/badge/python-3.9%2B-blue.svg">
  <img alt="Platform: Linux" src="https://img.shields.io/badge/platform-Linux-lightgrey.svg">
  <img alt="Status: Alpha" src="https://img.shields.io/badge/status-alpha-orange.svg">
</p>

---

AutoFTE turns a pile of AFL++ crash files into a readable answer to *"what probably broke, and how bad is it?"* It groups crashes by root cause, checks the target binary's exploit mitigations, and — optionally — asks a local LLM via [Ollama](https://ollama.com) for a plain-language write-up and fix ideas. Everything runs on your machine; nothing is sent anywhere.

It started as a weekend AFL++ triage script. It's now an installable CLI with a real test suite, and the direction is toward genuinely useful local crash-triage tooling rather than a one-off.

## Contents

- [Features](#features)
- [Install](#install)
- [Quick start](#quick-start-with-the-bundled-demo-target)
- [CLI reference](#cli-reference)
- [Fuzzing helpers](#fuzzing-helpers)
- [Choosing an LLM model](#choosing-an-llm-model)
- [Repo layout](#repo-layout)
- [Development](#development)
- [Roadmap](#roadmap)

## Features

| | |
|---|---|
| 🧩 **Triage** | Groups crash files by gdb backtrace frame (or by exit signal if `gdb` isn't installed), so you're looking at root causes, not 500 individual files. |
| 🛡️ **Binscan** | Checks a binary for NX, PIE, RELRO, stack canaries, FORTIFY_SOURCE, and dangerous libc calls (`strcpy`, `gets`, ...), then estimates exploit difficulty. |
| 🤖 **LLM notes** *(optional)* | Asks a local Ollama model to summarize a run and suggest fix ideas. No hard-coded model — it auto-detects what you have installed. Skips cleanly if Ollama isn't running. |
| 📄 **Report + dashboard** | A markdown run summary and a static HTML dashboard, ready to read or drop into CI artifacts. |
| 🩺 **Doctor** | One command that tells you exactly which required/optional tools are missing on this machine. |

## Install

```bash
git clone https://github.com/Nathan-Luevano/AutoFTE.git
cd AutoFTE
python3 -m pip install -e .
```

Or with conda/micromamba, which also pulls in `gdb`/`binutils`:

```bash
micromamba create -f environment.yml
micromamba activate autofte
```

Then check what your machine actually has available:

```bash
autofte doctor
```

`readelf`, `objdump`, `nm`, `ldd`, `file`, and `strings` are required for binary analysis. `gdb`, `checksec`, and AFL++ are optional — everything degrades gracefully without them.

## Quick start with the bundled demo target

```bash
make -C examples/vuln-demo
mkdir -p out/default/crashes && cp examples/vuln-demo/in/seed1 out/default/crashes/  # or run a real AFL++ session

autofte pipeline examples/vuln-demo/target examples/vuln-demo/vuln.c
```

Outputs land in the repo root:

- `crash_triage.json` — crashes grouped by root cause
- `binary_analysis.json` — mitigation report
- `llm_analysis.json` — LLM write-up, if Ollama is reachable
- `analysis_summary.md` — human-readable run summary
- `dashboard/index.html` — static dashboard

## CLI reference

Every step also runs standalone:

| Command | What it does |
|---|---|
| `autofte triage` | Group crash files by frame/signal → JSON |
| `autofte binscan <binary>` | Exploit mitigation report → JSON |
| `autofte llm` | Local-LLM write-up from the triage + binscan output |
| `autofte report` | Markdown summary from the JSON artifacts |
| `autofte dashboard` | Static HTML dashboard from the JSON artifacts |
| `autofte crash-info [file]` | Quick size/type/preview of one crash file |
| `autofte doctor` | Report which required/optional tools are installed |
| `autofte pipeline [binary] [source]` | Runs all of the above in order |

Run `autofte <command> --help` for the full flag list on any of them.

## Fuzzing helpers

`scripts/fuzz.sh` and `scripts/minimize.sh` are thin wrappers around `afl-fuzz` and `afl-cmin` — AutoFTE doesn't reimplement a fuzzer, it consumes AFL++'s output.

```bash
scripts/fuzz.sh examples/vuln-demo/target examples/vuln-demo/in out
scripts/minimize.sh examples/vuln-demo/target out/default/crashes out/default/crashes_min
```

## Choosing an LLM model

There's no hard-coded default model — different machines have different models pulled. AutoFTE resolves one at runtime, in order:

1. `--model` flag
2. `AUTOFTE_LLM_MODEL` environment variable
3. auto-detect: pick an installed Ollama model with "coder" in the name, falling back to whatever's installed first

```bash
autofte llm --model qwen3-coder:30b
# or
export AUTOFTE_LLM_MODEL=qwen3-coder:30b
```

`OLLAMA_HOST` (or `--host`) controls where AutoFTE looks for Ollama; defaults to `http://localhost:11434`.

## Repo layout

```
autofte/             installable package: triage, binary_analysis, llm, report, dashboard, doctor, config, cli
examples/vuln-demo/  intentionally vulnerable demo target + Makefile + seed corpus
scripts/             thin AFL++ wrappers (fuzz.sh, minimize.sh)
tests/               pytest suite
```

## Development

```bash
python3 -m pip install -e ".[dev]"
pytest
ruff check .
```

140 tests, ~94% coverage: mocked subprocess calls for the tool-parsing logic, plus a real end-to-end pass against a compiled binary. See [CONTRIBUTING.md](CONTRIBUTING.md) for the commit convention and how to add a new binscan check.

## Roadmap

- Support fuzzer backends beyond AFL++ (libFuzzer, honggfuzz)
- Pluggable analysis backends (angr/radare2 checks alongside static mitigation checks)
- Exportable, structured findings (SARIF) for CI pipelines
- A real crash-similarity metric beyond "same top frame" (stack hash, coverage-based clustering)

## Notes

- Standard binutils tools (`readelf`, `objdump`, `nm`, `ldd`, `file`, `strings`) are required for binary analysis; run `autofte doctor` to check.
- `gdb` and AFL++ are optional. If `gdb` is missing, crash grouping falls back to signal-based buckets.
- Ollama is optional; if it's not running, the rest of the pipeline still finishes.

## License

[MIT](LICENSE)
