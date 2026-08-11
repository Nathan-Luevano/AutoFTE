"""Golden-file regression tests over real, multi-compiler sanitizer output.

Fixtures under `tests/fixtures/reports/asan/` are genuine ASan reports
captured from `examples/vuln-demo/vuln.c`'s strcpy stack overflow. Two
source vintages are present, both named after this: `gcc-11.txt` and
`clang-22.1.8.txt` are the original pair, captured from the single-bug
`vuln.c` that existed at the time (function `vuln`, see
`planning/AGENT_CHANGELOG.md`'s "HARDENING Part 6" entry for the exact
build commands). The four `*-multibug.txt` fixtures were captured later,
after `vuln.c` was rewritten to dispatch on a marker byte to four distinct
bugs (function `vuln_stack_overflow` for this one) -- same bug, same
trigger shape (marker `'1'` + a payload over 64 bytes), different source
line/function name, captured across every compiler available in this
sandbox at the time: system gcc-11.4.0 (Ubuntu), and three added via
micromamba -- conda-forge gcc-12.4.0 (isolated `gcc12` env, installed
fresh for this task), conda-forge gcc-14.4.0 (already present as a
transitive dependency in the `autofte` env), and conda-forge clang-22.1.8
(already present in the `autofte` env from a prior session). See
`planning/AGENT_CHANGELOG.md`'s entry for this task for the exact build
commands. `tests/fixtures/reports/ubsan/` holds four more real captures
(a throwaway signed-integer-overflow snippet, not `vuln.c` -- `vuln.c` has
nothing UBSan flags -- built with `-fsanitize=undefined` under the same
four compilers).

Because the two ASan source vintages use different function/line
identities for what is conceptually the same bug, their major hashes are
NOT expected to match each other -- only fixtures captured from the same
source snapshot are "the same logical bug" in the sense stack hashing can
recognize, so invariance is checked within each vintage's group, not
across the two.

Three things are asserted:

1. The parser (`autofte.sanitizers.parse_sanitizer_output`) still parses
   every fixture into a usable record -- this is the "parser changes must
   not regress captured real-world output" net from HARDENING.md Part 6,
   now covering both ASan and UBSan.
2. Within each same-source-vintage group of fixtures, the major stack hash
   (`autofte.dedup.stack_hashes`, called the same way `triage.py`'s
   `_classify_crash` calls it) is identical across every compiler that
   captured it -- the cross-compiler drift detector called out in
   research/05-accuracy-and-ground-truth.md Sec 5.2.
3. Same as 2, but for the minor hash, within the `*-multibug.txt` and
   ubsan groups (the original 2-fixture group only ever asserted the major
   hash; left as-is here).

The original 2-fixture assertion used to be a documented `xfail`: gcc's
`__interceptor_strcpy` frame and clang's `strcpy.part.0` frame weren't both
filtered by the old 9-pattern denylist, and the major hash still included
the line number, so the two compilers' captures of the same bug hashed
differently. Three fixes closed this, landed one at a time and
bench-measured against the real Igor/GPTrace corpus (see
`benchmarks/results.md`): dropping the line number from the major hash,
vendoring ClusterFuzz/CASR's noise-frame denylists (which catches
`strcpy.part.0`), and fixing `sanitizers.FRAME_LOCATION_RE`'s greedy
pattern, which mis-split clang's `file:line:col` frame text into
file='vuln.c:8', line=3 instead of file='vuln.c', line=8.

The four-compiler `*-multibug.txt` group re-tests the same fix on fresh,
independently captured real output (including gcc-14.4.0, whose interceptor
frame is named plain `strcpy` rather than `__interceptor_strcpy` or
`strcpy.part.0` -- a third real naming variant) and the four-compiler UBSan
group is new coverage entirely (`sanitizers.parse_ubsan` had zero fixtures
before this). Both are all-passing, not `xfail`: run against every fixture,
all major and minor hashes within each group are byte-identical, so no new
cross-compiler drift was found -- see the task's `planning/AGENT_CHANGELOG.md`
entry for the actual computed hash values.
"""

from pathlib import Path

import pytest

from autofte import dedup
from autofte.sanitizers import parse_sanitizer_output

ASAN_FIXTURES_DIR = Path(__file__).parent / "fixtures" / "reports" / "asan"
UBSAN_FIXTURES_DIR = Path(__file__).parent / "fixtures" / "reports" / "ubsan"
FIXTURES_DIR = ASAN_FIXTURES_DIR  # kept for the pre-existing test below
FIXTURE_PATHS = sorted(ASAN_FIXTURES_DIR.glob("*.txt")) + sorted(
    UBSAN_FIXTURES_DIR.glob("*.txt")
)

MULTIBUG_FIXTURE_NAMES = [
    "gcc-11.4.0-multibug.txt",
    "gcc-12.4.0-multibug.txt",
    "gcc-14.4.0-multibug.txt",
    "clang-22.1.8-multibug.txt",
]
UBSAN_FIXTURE_NAMES = [
    "gcc-11.4.0.txt",
    "gcc-12.4.0.txt",
    "gcc-14.4.0.txt",
    "clang-22.1.8.txt",
]


@pytest.mark.parametrize("fixture_path", FIXTURE_PATHS, ids=lambda p: p.name)
def test_fixture_parses_successfully(fixture_path):
    text = fixture_path.read_text()
    record = parse_sanitizer_output(text)
    assert record is not None
    assert record["bug_class"]
    assert record["crash_stack"]


def _record_hashes(text):
    record = parse_sanitizer_output(text)
    return dedup.stack_hashes(record["crash_stack"], extra_context=[record["bug_class"]])


def test_major_hash_is_stable_across_compilers():
    gcc_text = (FIXTURES_DIR / "gcc-11.txt").read_text()
    clang_text = (FIXTURES_DIR / "clang-22.1.8.txt").read_text()

    gcc_record = parse_sanitizer_output(gcc_text)
    clang_record = parse_sanitizer_output(clang_text)

    gcc_major, _ = dedup.stack_hashes(
        gcc_record["crash_stack"], extra_context=[gcc_record["bug_class"]]
    )
    clang_major, _ = dedup.stack_hashes(
        clang_record["crash_stack"], extra_context=[clang_record["bug_class"]]
    )

    assert gcc_major == clang_major


def test_major_and_minor_hash_stable_across_four_compilers_multibug_vuln():
    hashes = {
        name: _record_hashes((ASAN_FIXTURES_DIR / name).read_text())
        for name in MULTIBUG_FIXTURE_NAMES
    }
    majors = {name: major for name, (major, _minor) in hashes.items()}
    minors = {name: minor for name, (_major, minor) in hashes.items()}

    assert len(set(majors.values())) == 1, majors
    assert len(set(minors.values())) == 1, minors


def test_major_and_minor_hash_stable_across_four_compilers_ubsan():
    hashes = {
        name: _record_hashes((UBSAN_FIXTURES_DIR / name).read_text())
        for name in UBSAN_FIXTURE_NAMES
    }
    majors = {name: major for name, (major, _minor) in hashes.items()}
    minors = {name: minor for name, (_major, minor) in hashes.items()}

    assert len(set(majors.values())) == 1, majors
    assert len(set(minors.values())) == 1, minors
