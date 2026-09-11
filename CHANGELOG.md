# Changelog

All notable changes to AutoFTE are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.2] - 2026-09-11

### Fixed
- 4 Dependabot security advisories (2 high, 2 moderate) against `requests`,
  `urllib3`, and `pytest` on the Python 3.9 dependency resolution --
  `requests>=2.33.0` no longer supports 3.9, and 3.9 is EOL, so the fix is
  dropping it: `requires-python` is now `>=3.10`. `uv.lock` regenerated to a
  single resolution on patched versions across 3.10/3.11/3.12.
- CI matrix, ruff `target-version`, and README/PYPI.md version claims
  updated to match.
- Bumped `actions/checkout`, `actions/setup-python`, and
  `softprops/action-gh-release` off their deprecated Node.js 20 runtime in
  all workflows.
- Enabled `zip(..., strict=False)` (newly available under the 3.10 ruff
  target) on the `crash-info` preview reader in `cli.py` to make the
  intentional short-read explicit.

## [0.9.1] - 2026-09-11

### Fixed
- An overlong, duplicated-phrase docstring line in `autofte/llm.py` was
  failing `ruff` (E501), which was breaking the tag-guard job on the release
  workflow. No behavior change; docstring text only.

## [0.9.0] - 2026-09-10

### Added
- **CASR-compatible export** (`autofte/casr.py`): `autofte casr` and `autofte
  pipeline --casr-dir DIR` write one CASR-style `.casrep` JSON report per crash
  group. Each report carries the normalized stacktrace, crash line, registers
  and faulting instruction (from the GDB crash-state capture), the raw
  sanitizer report (`AsanReport` / `UbsanReport`), objdump disassembly and
  source context when a target binary and source file are given, the minimized
  input path, and a `CrashSeverity` block whose `Type`
  (`EXPLOITABLE` / `PROBABLY_EXPLOITABLE` / `NOT_EXPLOITABLE` / `UNDEFINED`)
  and `ShortDescription` are mapped from AutoFTE's crash-state primitive, bug
  class, or terminating signal, with the fused difficulty and confidence spelled
  out in `Explanation` (and flagged as an interop mapping, not a verdict).
- `autofte casr` subcommand (`--output-dir`, `--target-binary`, `--source-file`,
  `--triage-json`, `--binary-analysis`).

## [0.8.0] - 2026-09-10

### Added
- **Incremental campaign triage** (`autofte triage --incremental`, `autofte
  pipeline --incremental`): merge a triage run into an existing
  `crash_triage.json` instead of starting over. Crash files are tracked by
  content hash in a `seen` map; a re-run executes only the files not already
  recorded, then folds the new crashes into their existing groups (by
  `group_id`), adds groups that are new, and accumulates the reproduction,
  no-crash, and timeout tallies. Merged output carries `incremental`,
  `previous_total_crashes`, and `new_crashes_this_run`. Keeps re-triage of an
  ever-growing fuzzing corpus proportional to the new crashes, not the whole
  set.
- Crash-state capture and minimization now skip groups that already carry a
  result, so an incremental re-run does not redo that work.

## [0.7.0] - 2026-09-10

### Added
- **Exploitability brief** (`autofte/brief.py`): `exploitability_brief.md` -- a
  plain-language write-up of the top findings. Each section covers what the bug
  is, what the crashed process showed (crash-state primitive, in prose), what
  mitigations stand in the way, how to reproduce it (sample input, minimized
  PoC, re-run command), and AutoFTE's fused read with its confidence and the
  standing "prioritisation aid, not a verdict" caveat. The local-model narrative
  (tidied of evidence-ID citations) is attached to the top finding.
- `autofte brief` subcommand (`--top`, `--output`, `--target-binary`, ...).
- `autofte pipeline` / `autofte demo` write `exploitability_brief.md` by default;
  `--no-brief`, `--brief-output`, `--brief-top` control it.

## [0.6.0] - 2026-09-09

### Added
- **Crash input minimization** (`autofte/minimize.py`): shrink a crash file to
  the smallest bytes that still reproduce the *same* crash (same sanitizer bug
  class + faulting function, or same signal + top frame). Uses `afl-tmin` when
  it is installed and its result still reproduces; otherwise falls back to a
  built-in delta-debugging (ddmin) reducer with no external dependency.
- `autofte minimize <crash_file>` subcommand (`--target-binary`, `--output`,
  `--no-afl-tmin`, `--json`).
- `autofte triage --minimize` / `autofte pipeline --minimize` minimize a
  representative crash of every group into `--minimize-dir` (default
  `minimized/`) and record the result (`tool`, sizes, `reduction_percent`,
  path) on the group; surfaced in the markdown report, HTML dashboard, and
  `summary` JSON.
- `autofte doctor` now also checks for `afl-tmin`.

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
