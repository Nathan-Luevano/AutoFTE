# Changelog

All notable changes to AutoFTE are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - 2026-09-09

### Added
- **Crash-state exploitability analysis** (`autofte/crash_state.py`): a
  representative crash of each group is re-run under GDB, and the actual
  crashed process is read -- signal, registers, the faulting instruction,
  and the corrupted return address / frame pointer -- to detect
  `exploitable`-style exploitation primitives: `instruction-pointer-control`,
  `return-address-overwrite`, `indirect-branch-through-register`,
  `memory-write`, `memory-read`.
- The detected primitive is **fused into the severity score** (a strong,
  direct-observation signal that also raises confidence; `basis` gains an
  `_and_crash_state` suffix), surfaced in the markdown report, HTML
  dashboard, `summary` (table + JSON + CSV), and SARIF
  (`properties.exploit_primitives`), and fed to the LLM prompt as cited
  evidence (registers, faulting instruction, primitives).
- `autofte triage` / `autofte pipeline` gain `--no-crash-state` to skip the
  per-group GDB capture (it is on by default).

## [0.4.0] - 2026-09-08

### Added
- Disassembly grounding: the LLM write-up is now fed the objdump disassembly
  of the faulting function (windowed around the fault, sanitizer/libc
  interceptor frames skipped), via `autofte/disasm.py`. `autofte llm` gains
  `--target-binary` for this; the disassembly used is saved to
  `llm_analysis.json` as `disassembly_context` and rendered in the markdown
  report and HTML dashboard.
- Source grounding: for large source files the LLM prompt now receives only
  a numbered excerpt window around each faulting line (`autofte/source_context.py`)
  instead of the whole file, keeping the prompt tight and the grounding sharp.
- `autofte summary` subcommand: a severity-ranked crash-group table, with
  `--format {table,json,csv}` and a `--fail-on-difficulty` gate.
- `autofte report --format json`: a consolidated machine-readable summary
  fusing triage, binary posture, per-group severity, and LLM notes into one
  ranked artifact (`autofte-summary/1` schema).
- `autofte pipeline --summary-json PATH` and `--fail-on-difficulty {easy,medium,hard}`
  (exit code 2 when a crash group meets or exceeds the threshold) for CI gating.
- LeakSanitizer, MemorySanitizer, and ThreadSanitizer report parsing
  (`memory-leak`, `use-of-uninitialized-value`, `data-race` bug classes),
  each with a severity profile and LLM contradiction-validator coverage.
- UndefinedBehaviorSanitizer reports now capture the full `#N` stacktrace when
  the runtime emits one, instead of a single source line.
- `autofte --version`.
- `autofte doctor --json` for machine-readable environment reports.
- `autofte triage` / `autofte pipeline` `--reproduction-runs N` flag
  (`1` skips reproducibility verification for speed on large corpora).
- `autofte report` / `autofte dashboard` `--top N` to cap displayed crash groups.
- `autofte bench --csv PATH` exports the per-target metrics table as CSV.
- Stable per-group `group_id`, surfaced as SARIF `partialFingerprints` so
  GitHub Code Scanning can track a finding across runs.
- SARIF rules now carry `security-severity` and a `security` tag for
  GitHub Code Scanning severity badges.
- GitHub Action: `summary-json` / `fail-on-difficulty` inputs and
  `summary-json-path` / `top-difficulty` outputs.

### Changed
- Crash groups are now ranked by crash-aware exploit difficulty (most severe
  first, crash count breaking ties) consistently across the markdown report,
  the HTML dashboard, and `summary`. Shared ranking logic lives in
  `crash_display.ranked_groups`.
- Severity scoring now factors in the sanitizer access size (large writes
  rank more exploitable, single-byte writes less) and FORTIFY_SOURCE
  (previously detected but excluded from the mitigation score).
- The markdown report and dashboard surface per-group reproducibility.

## [0.2.1] - 2026-08-22

Initial public releases: installable package, single CLI, bundled demo,
offline LLM design, SARIF export, GitHub Action, empirically benchmarked
deduplication accuracy.
