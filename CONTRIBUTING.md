# Contributing to AutoFTE

Thanks for taking a look. This is a young project — the bar for small, focused PRs is low.

## Setup

```bash
git clone <your fork>
cd AutoFTE
python3 -m pip install -e ".[dev]"
```

## Before opening a PR

```bash
ruff check .
pytest
```

Both need to pass. CI runs the same two checks.

## Commit style

This repo uses [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` a new capability (new subcommand, new check, new analysis backend)
- `fix:` a bug fix
- `docs:` README/CONTRIBUTING/docstrings only
- `chore:` packaging, CI, repo hygiene, dependency bumps
- `style:` formatting-only changes, no behavior change
- `refactor:` restructuring without changing behavior
- `test:` test-only changes

Keep commits scoped — one logical change per commit is easier to review and revert than one giant one.

## Adding a new check to `binscan`

Each protection check in `autofte/binary_analysis.py` is a small `_check_*` method on `BinaryAnalyzer` that shells out via the shared `_run_tool()` helper (handles missing tools/timeouts consistently) and returns a plain dict. Add a new method, wire it into `analyze_all_protections()`, and add a test in `tests/` that mocks `subprocess.run` with crafted tool output rather than depending on a real binary where possible.

## Reporting bugs / proposing features

Open an issue. For anything nontrivial, a quick issue before a big PR saves everyone time.
