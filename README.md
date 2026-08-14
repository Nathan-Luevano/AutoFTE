# AutoFTE

<p align="center">
  <img src="AutoFTE.png" alt="AutoFTE logo" width="220">
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

You fuzzed something and now you have a directory full of crash files. AutoFTE groups them by root cause, checks the target binary's exploit mitigations, and — optionally — asks a local LLM to explain what actually broke and whether it's worth your time. One command, fully offline, nothing ever leaves your machine.

<p align="center">
  <img src="autofte-demo-combined.gif" alt="Terminal recording of autofte demo --verbose, followed by a scroll through the dashboard it produces." width="760">
</p>

### Install, one line

```bash
pipx install autofte
```

> This is the headline install and it's what's live the moment a release is tagged — but no release has shipped yet, so `pipx install autofte` doesn't resolve on PyPI today. Until then, use the dev install in [Install](#install), which works right now.

### Look what it found

Real output from `autofte demo` — zero arguments, no fuzzing campaign needed. The bundled demo target has four distinct, deliberately reachable bugs (stack overflow, heap overflow, use-after-free, NULL deref); 12 pre-generated crashes are spread across all four, so the run has something real to collapse:

```
$ autofte demo
AutoFTE demo: building and triaging the bundled vuln-demo target (vuln-demo/target_asan)


→ 12 crashes · 4 root causes · #1 stack-buffer-overflow (write 66) in vuln_stack_overflow at vuln.c:39 (3 crashes) — Medium · 3/3 reproducible

Artifacts written to autofte-demo-output/
```

That's the whole default output — quiet on purpose. Run `autofte demo --verbose` for the full trace (shown in the recording above), or open `autofte-demo-output/dashboard/index.html` / `analysis_summary.md` for the other three groups AutoFTE found — a heap overflow, a use-after-free, and a NULL deref — each correctly separated with the real function/line, an honest difficulty + confidence, and (with Ollama reachable) a grounded, evidence-cited LLM write-up like this real one:

> Heap buffer overflow (write 65) in vuln_heap_overflow function. Unbounded
> memcpy in vuln_heap_overflow function.
> *(fix idea: "Add bounds checking on payload_len before calling memcpy in
> vuln_heap_overflow"; exploitability_class: `insufficient_evidence` — the
> model isn't guessing at exploitability it can't demonstrate.)*

No crash data, source, or binary ever leaves your machine — the LLM step is optional and local, and skips cleanly if Ollama isn't reachable.

### AutoFTE vs. the alternatives

| | Manual `gdb` loop | `exploitable` (GDB plugin) | [CASR](https://github.com/ispras/casr) | AutoFTE |
|---|---|---|---|---|
| Setup | None — but 100% by hand | GDB + plugin | Rust toolchain, Docker, ptrace caps | `pipx install autofte` |
| Groups crashes by root cause | You eyeball it | No — one crash at a time | Yes, major/minor stack-hash dedup | Yes, major/minor stack-hash dedup (ASLR-shifted duplicates collapse; on the measured corpus, ~1 in 10 reports lands in a bucket dominated by a *different* bug — see [Measured, not assumed](#measured-not-assumed)) |
| Reads sanitizer (ASan/UBSan) reports | Manually | No | Yes | Yes — bug class, read/write, access size, alloc/free stacks, normalized into every group |
| Fuses fault type with mitigation posture into a difficulty signal | Manually | Some | Some | Yes, with an explicit confidence and rationale — never a bare verdict |
| Plain-language write-up of what broke | Never | Never | Never | Optional, via a local Ollama model, grounded in the real sanitizer record and severity assessment |
| SARIF / CI code-scanning output | No | No | Yes | Yes (`--format sarif`, `--sarif <path>`, or the bundled [GitHub Action](#github-action)) |
| Sends anything off-box | No | No | No | No — the LLM step is local-only (Ollama) or skipped entirely |

CASR is the more mature competitor on triage and severity. AutoFTE's differentiator is the offline, plain-language explanation step grounded in that same structured evidence, plus a one-command `pipx` install with no Docker/ptrace setup.

### The dashboard

`autofte demo` (and `autofte dashboard`) writes a static `dashboard/index.html` you can open directly or drop into CI artifacts — no server required. It's a single self-contained page with:

- a stat strip (crash file count, crash group count, protection level, likely bug type)
- a ranked crash-groups table — bug class/signature, crash count, and a crash-aware difficulty label with its confidence, with the reasoning behind it one click away in a `<details>` disclosure
- a binary-notes card (ASLR/NX/PIE/canaries/RELRO, protection level, exploit difficulty)
- the LLM's grounded narrative, if it ran, including its "what would confirm this" list
- "next checks" and "fix ideas" lists pulled from the LLM write-up

This is the same run from the recording above, continued — the terminal half ends by writing this dashboard, and the recording's second half is a scroll through it, top to bottom.

### Measured, not assumed

Most crash-triage tools never publish how often their dedup is actually right. AutoFTE does, against the same real ground-truth corpus the published literature uses — the [GPTrace/Igor benchmark](https://zenodo.org/records/18708473) (325,044 labeled ASan reports, 50 real bugs, 14 real C/C++ targets, Apache-2.0). `autofte bench --corpus igor` reproduces this on demand (`scripts/fetch_bench_corpus.sh` downloads and MD5-verifies the corpus first); the full history of every change and its measured effect is in [`benchmarks/results.md`](benchmarks/results.md), not just the snapshot below.

The GPTrace paper averages its 14 targets unweighted (macro). AutoFTE reports both that basis and the stricter whole-corpus pooled number (micro) the paper never computes:

| | Purity | Inverse purity | F-measure |
|---|---|---|---|
| Crashwalk (published, macro) | 98% | 69% | 76 |
| GPTrace (published, macro) | 98% | 94% | 94 |
| **AutoFTE, macro (per-target mean)** | **97.7%** | **90.5%** | **91.9%** |
| **AutoFTE, micro (pooled, all 325,044 reports)** | **89.9%** | **80.3%** | **78.3%** |

On the paper's own basis, AutoFTE is close behind GPTrace and ahead of Crashwalk on every metric. On the stricter pooled basis it is not — that's the honest floor, not a footnote. Purity measures whether two *different* bugs ever get silently merged into one bucket, the worst failure mode a triage tool can have, since the merged-away bug doesn't show up as a wrong answer anywhere. Inverse purity measures the opposite: one real bug shattered across many "unique" buckets. Pooled purity (89.9%) sits right at the information-theoretic ceiling a stack hash can achieve on this corpus (89.4%, per [`scripts/purity_ceiling.py`](scripts/purity_ceiling.py), which imports nothing from AutoFTE) — AutoFTE isn't leaving purity on the table, it's out of signal a stack hash can give it.

The aggregate hides real per-target spread, so it isn't the only number published: `autofte bench --corpus igor --per-target` reports all 14 real targets separately (see [`benchmarks/results.md`](benchmarks/results.md)). `libxml2__xmllint` — the published literature's own worst case — has purity of only 83% (real bugs measurably merging); `php__exif` shatters its one real bug into 18 buckets (inverse purity 48%). Six of the 14 targets score at or near a perfect 1.0.

`xmllint`'s purity problem is root-caused, not just measured: [`scripts/diagnose_xmllint_purity.py`](scripts/diagnose_xmllint_purity.py) found that 89% of its purity loss sits in one bucket where two ground-truth labels share a byte-identical 4-frame crash-site stack, diverging only in recursion-depth frames — no stack-hash dedup can split that apart. That's a real, disclosed limit of the corpus's labeling at that one target, not a gap in what AutoFTE measures.

`autofte bench` also prints a `No-hash fallbacks` count on every run (currently 7 of 325,044 reports — crashes that never reached stack-hash dedup at all) so that stays auditable too. Nothing on this page is asserted; it's run.

---

## Contents

- [Features](#features)
- [Install](#install)
- [Quick start](#quick-start)
- [CLI reference](#cli-reference)
- [Fuzzing helpers](#fuzzing-helpers)
- [GitHub Action](#github-action)
- [Choosing an LLM model](#choosing-an-llm-model)
- [Repo layout](#repo-layout)
- [Development](#development)
- [Roadmap](#roadmap)
- [Notes](#notes)
- [License](#license)

## Features

| | |
|---|---|
| 🎬 **Demo** | `autofte demo` — zero arguments. Builds the bundled 4-bug target if needed, triages its 12 pre-seeded crashes, prints a one-line verdict in well under a minute. `--verbose` shows the full trace. |
| 🧩 **Triage** | Groups crash files by major/minor stack-hash dedup — ASan/UBSan reports when the target is sanitizer-built, gdb backtraces otherwise, exit-signal grouping as a last resort. |
| 🧪 **Sanitizer ingestion** | Parses ASan/UBSan reports into a normalized record — bug class, read/write, access size, fault address, alloc/free stacks — feeding both dedup and the LLM write-up. |
| 🛡️ **Binscan** | Checks a binary for NX, PIE, RELRO, stack canaries, FORTIFY_SOURCE, and dangerous libc calls (`strcpy`, `gets`, ...). |
| ⚖️ **Crash-aware severity** | Fuses the crash's fault signature with the mitigation posture into a difficulty label, with an explicit confidence and rationale — never a bare verdict. |
| 🤖 **LLM notes** *(optional)* | Local Ollama model writes a plain-language summary grounded in the real sanitizer record and severity assessment. Auto-detects an installed model; skips cleanly if Ollama isn't running. |
| 📄 **Report + dashboard + SARIF** | A markdown run summary, a static HTML dashboard, and SARIF output (`--format sarif` / `--sarif <path>`) for code-scanning tools and CI. |
| 🩺 **Doctor** | One command that tells you exactly which required/optional tools are missing on this machine. |

## Install

**Headline install (once a release is tagged):**

```bash
pipx install autofte
autofte doctor
```

`autofte` isn't on PyPI yet — the publish workflow (`.github/workflows/release.yml`) is wired up and will run the moment a `v0.x.0` tag is pushed, but that hasn't happened. Use the source install below until then.

**Works today — install from source:**

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

**Docker (build it yourself — no image is published to a registry yet):**

```bash
git clone https://github.com/Nathan-Luevano/AutoFTE.git
cd AutoFTE
docker build -t autofte .
docker run --rm autofte demo
```

**Single-file binary:** a PyInstaller build (`pyinstaller.spec`) is wired into the release workflow and will be attached to every GitHub Release once one exists, for machines with no Python at all. Not available yet — same "wired up, not shipped" status as PyPI.

Then, whichever install you used, check what your machine actually has available:

```bash
autofte doctor
```

`readelf`, `objdump`, `nm`, `ldd`, `file`, and `strings` are required for binary analysis. `gdb`, `checksec`, and AFL++ are optional — everything degrades gracefully without them.

## Quick start

### Zero setup

```bash
autofte demo
```

No arguments needed. This is the command behind the ["look what it found"](#look-what-it-found) output above — it builds the bundled ASan-instrumented `examples/vuln-demo` target if it isn't built yet, triages the 12 crash files shipped in the repo, runs `binscan`, attempts an LLM write-up, and ends on a verdict line. Add `--verbose` for the full step-by-step trace; artifacts land in `./autofte-demo-output/`, not your bare working directory.

### On your own crashes

```bash
make -C examples/vuln-demo
mkdir -p out/default/crashes && cp examples/vuln-demo/in/seed1 out/default/crashes/  # or run a real AFL++ session

autofte pipeline examples/vuln-demo/target examples/vuln-demo/vuln.c
```

Point `pipeline` at your own binary/source/crash directory the same way. Outputs land in the repo root:

- `crash_triage.json` — crashes grouped by root cause
- `binary_analysis.json` — mitigation report
- `llm_analysis.json` — LLM write-up, if Ollama is reachable
- `analysis_summary.md` — human-readable run summary
- `dashboard/index.html` — static dashboard

## CLI reference

Every step also runs standalone:

| Command | What it does |
|---|---|
| `autofte demo` | Zero-setup: build/triage the bundled vuln-demo target and print a verdict |
| `autofte triage` | Group crash files (sanitizer-aware stack-hash dedup, gdb, or signal fallback) → JSON |
| `autofte binscan <binary>` | Exploit mitigation report → JSON |
| `autofte llm` | Local-LLM write-up from the triage + binscan output, grounded in the real crash record |
| `autofte report [--format markdown\|sarif]` | Markdown summary (default) or SARIF findings from the JSON artifacts |
| `autofte dashboard` | Static HTML dashboard from the JSON artifacts |
| `autofte crash-info [file]` | Quick size/type/preview of one crash file |
| `autofte doctor` | Report which required/optional tools are installed |
| `autofte bench [--corpus micro\|igor\|<path>]` | Measure dedup accuracy (purity/inverse-purity/F-measure) against a labeled ground-truth corpus |
| `autofte pipeline [binary] [source] [--sarif <path>]` | Runs triage → binscan → llm → report → dashboard in order, optionally also writing SARIF |

Run `autofte <command> --help` for the full flag list on any of them.

## Fuzzing helpers

`scripts/fuzz.sh` and `scripts/minimize.sh` are thin wrappers around `afl-fuzz` and `afl-cmin` — AutoFTE doesn't reimplement a fuzzer, it consumes AFL++'s output.

```bash
scripts/fuzz.sh examples/vuln-demo/target examples/vuln-demo/in out
scripts/minimize.sh examples/vuln-demo/target out/default/crashes out/default/crashes_min
```

## GitHub Action

`action.yml` at the repo root is a reusable composite Action that runs the
same `autofte pipeline` command against a CI crash-artifact directory and
uploads the result to GitHub code scanning via
`github/codeql-action/upload-sarif`. Minimal usage in a consumer's
workflow:

```yaml
- uses: Nathan-Luevano/AutoFTE@<ref>
  with:
    target-binary: ./target
    crashes-dir: out/default/crashes
```

> `@<ref>` needs to be a real tag once one exists — same "wired up, not
> shipped yet" caveat as the `pipx install autofte` line above. Point it at
> a commit SHA or `main` to use it before a tag exists.

The LLM write-up step is opt-in: pass `model`/`host` if a runner can reach
an Ollama instance, otherwise the action runs with `--skip-llm` by default
so it never hangs or fails on a runner with no local LLM. See
[`.github/workflows/example-fuzzing-triage.yml`](.github/workflows/example-fuzzing-triage.yml)
for a full example workflow to copy into your own project (it's a
reference file, not something that runs on AutoFTE's own CI — this repo
has no real fuzzing crash corpus to triage).

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

There's no timeout on the model call by default — a cold model load or CPU-only inference can legitimately take a while, and a hard cap just turns "slow" into "silently skipped." Set `AUTOFTE_LLM_TIMEOUT` (or pass `--llm-timeout`, in seconds) if you'd rather it give up after a bound you choose.

## Repo layout

```
autofte/                  installable package: triage, dedup, sanitizers, binary_analysis, severity, llm, sarif,
                           report, dashboard, doctor, config, cli, bench, metrics, io_utils, paths,
                           vendored_ignore_lists, crash_display
autofte/demo_assets/      packaged copy of the vuln-demo target so `autofte demo` works from a wheel/pipx/Docker
                           install, not just a source checkout — kept in sync with examples/vuln-demo/
examples/vuln-demo/       intentionally vulnerable demo target + Makefile + seed corpus + pre-generated crashes
                           (the source-of-truth dev copy)
benchmarks/                accuracy regression gate: micro corpus baseline, dedup baseline.json, and sweep
                           results consumed by `autofte bench` (see benchmarks/results.md)
scripts/                  AFL++ wrappers (fuzz.sh, minimize.sh), the PyInstaller entry point, the end-to-end
                           smoke-test.sh, demo-recording helpers (record-demo.sh, screenshot-dashboard.mjs,
                           stitch-demo.sh), and one-off accuracy investigation scripts
tests/                    pytest suite
Dockerfile                container image; build locally with `docker build -t autofte .` (not published)
pyinstaller.spec          single-file binary build spec, used by the release workflow
action.yml                reusable GitHub Action: runs the pipeline on CI crash artifacts, uploads SARIF
.github/workflows/        CI (tests + lint), release (PyPI publish + binary attach on `v*` tags), and an example
                           consumer workflow for action.yml
```

## Development

```bash
python3 -m pip install -e ".[dev]"
pytest
ruff check .
```

491 tests: mocked subprocess calls for the tool-parsing logic, plus real end-to-end passes against compiled binaries (including real multi-compiler ASan builds), a real local Ollama call exercising the evidence-cited/schema-constrained LLM path, and `autofte bench` runs against a real, independently-downloaded 325,000-report ground-truth corpus (see [`benchmarks/results.md`](benchmarks/results.md) for the measured accuracy numbers). [`scripts/smoke-test.sh`](scripts/smoke-test.sh) is a separate, manually-run end-to-end check against the real CLI — see [CONTRIBUTING.md](CONTRIBUTING.md#before-opening-a-pr) for when to run it. See [CONTRIBUTING.md](CONTRIBUTING.md) for the commit convention and how to add a new binscan check.

## Roadmap

- Disassembly around the faulting instruction, fed into the LLM prompt (the prompt already accepts it — `llm.build_prompt`'s `disassembly` param — nothing produces it yet)
- Support fuzzer backends beyond AFL++ (libFuzzer, honggfuzz)
- macOS support (depends on gdb/binutils availability there)
- Distro packaging (BlackArch, Kali) once PyPI + binary releases exist

## Notes

- Standard binutils tools (`readelf`, `objdump`, `nm`, `ldd`, `file`, `strings`) are required for binary analysis; run `autofte doctor` to check.
- `gdb` and AFL++ are optional. If `gdb` is missing, crash grouping falls back to signal-based buckets.
- Ollama is optional; if it's not running, the rest of the pipeline still finishes.
- Everything runs locally. AutoFTE makes no network calls except to a local (or explicitly configured) Ollama host — nothing about a crash, a binary, or its source is ever sent anywhere else.

## License

[MIT](LICENSE)
