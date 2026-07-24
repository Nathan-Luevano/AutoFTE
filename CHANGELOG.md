# Changelog

## Unreleased

### Changed
- Restructured the project from flat top-level scripts into an installable `autofte` package with a single `autofte` CLI (`triage`, `binscan`, `llm`, `report`, `dashboard`, `crash-info`, `doctor`, `pipeline` subcommands).
- Moved the demo target (`vuln.c`, `Makefile`, seed corpus) into `examples/vuln-demo/`.
- Moved AFL++ wrapper scripts into `scripts/`.
- LLM model selection no longer hard-codes `codellama:7b-instruct`. Resolution order is now `--model` → `AUTOFTE_LLM_MODEL` → auto-detected installed Ollama model.
- Added `autofte doctor` to report which required/optional tools (readelf/objdump/nm/ldd/file/strings, gdb, checksec, afl-fuzz/afl-cmin, Ollama) are available.

### Fixed
- `binscan`'s NX-bit check read the `GNU_STACK` program header's permission flags (`RWE`/`RW`) from the wrong line of `readelf -l` output (they're on the continuation line, not the `GNU_STACK` line itself), which made the NX result unreliable. It's now parsed correctly.
- `triage`'s direct-run fallback (used when `gdb` isn't installed) had a dead branch that returned the identical value on both sides of an `if`.
- The markdown report could emit an LLM bug-type bullet with no `## LLM notes` section header above it when the model returned `likely_bug_type` without a `summary`.
- Binary analysis subprocess calls (`readelf`, `objdump`, `nm`, `ldd`, `strings`, `checksec`) now have timeouts and consistent "tool not installed" error handling instead of ad hoc per-check exception handling.
- The FORTIFY_SOURCE symbol regex (`__\w+_chk`) had no trailing word boundary, so it partial-matched `__stack_chk_fail` as `__stack_chk` and misreported a stack-canary symbol as a fortified libc function. Confirmed against a real binary built with both `-fstack-protector-all` and `-D_FORTIFY_SOURCE=2`.

### Removed
- `mythic_integrator.py` — dead code, already marked as not part of the normal flow.

## 0.1.0

Initial local triage pipeline: crash grouping, binary mitigation checks, optional Ollama write-up, markdown + HTML output.
