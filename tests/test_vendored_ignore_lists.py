import re

import pytest

from autofte.dedup import _NOISE_FUNC_RE
from autofte.vendored_ignore_lists import (
    ALL_FILEPATH_IGNORE_REGEXES,
    ALL_FUNCTION_IGNORE_REGEXES,
    CASR_CPP_FILEPATH_IGNORE_REGEXES,
    CASR_CPP_FUNCTION_IGNORE_REGEXES,
    CLUSTERFUZZ_FUNCTION_IGNORE_REGEXES,
    CLUSTERFUZZ_FUNCTION_IGNORE_REGEXES_IF_SYMBOLIZED,
    EXTRA_FUNCTION_IGNORE_REGEXES,
    is_vendored_noise_filepath,
    is_vendored_noise_function,
)


def test_lists_have_the_real_verified_counts():
    assert len(CLUSTERFUZZ_FUNCTION_IGNORE_REGEXES) == 210
    assert len(CLUSTERFUZZ_FUNCTION_IGNORE_REGEXES_IF_SYMBOLIZED) == 5
    assert len(CASR_CPP_FUNCTION_IGNORE_REGEXES) == 156
    assert len(CASR_CPP_FILEPATH_IGNORE_REGEXES) == 43
    assert len(EXTRA_FUNCTION_IGNORE_REGEXES) == 4


def test_every_pattern_compiles():
    for pattern in ALL_FUNCTION_IGNORE_REGEXES:
        re.compile(pattern)
    for pattern in ALL_FILEPATH_IGNORE_REGEXES:
        re.compile(pattern)


def test_extra_patterns_are_not_duplicates_of_ported_entries():
    ported = set(CLUSTERFUZZ_FUNCTION_IGNORE_REGEXES) | set(
        CLUSTERFUZZ_FUNCTION_IGNORE_REGEXES_IF_SYMBOLIZED
    ) | set(CASR_CPP_FUNCTION_IGNORE_REGEXES)
    for pattern in EXTRA_FUNCTION_IGNORE_REGEXES:
        assert pattern not in ported


# --------------------------------------------------------------------------
# is_vendored_noise_function -- known ClusterFuzz/CASR-covered names ARE noise
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "func_name",
    [
        "__cxa_throw",
        "operator new",
        "operator delete",
        "std::__1::basic_string::basic_string",
        "_Unwind_Resume",
        "abort",
        "raise",
        "__GI_raise",
        "__GI_abort",
        "gsignal",
        "malloc",
        "free",
        "calloc",
        "realloc",
        "__asan_report_error",
        "__interceptor_memset",
        "__sanitizer_print_stack_trace",
        "fuzzer::Fuzzer::ExecuteCallback",
        "LLVMFuzzerTestOneInput",
        "clone",
        "__pthread_kill",
        "__libc_start_main",
        "_start",
    ],
)
def test_known_noise_function_names_are_flagged(func_name):
    assert is_vendored_noise_function(func_name) is True


def test_real_asan_interceptor_frame_names_from_fixtures_are_flagged():
    """`__interceptor_strcpy` (gcc-11 fixture) and `strcpy.part.0` (clang-22.1.8
    fixture) are the same interceptor call, symbolized differently per-compiler --
    see tests/fixtures/reports/asan/{gcc-11,clang-22.1.8}.txt frame #0. Both must
    be recognized as noise for the major hash to be compiler-invariant."""
    assert is_vendored_noise_function("__interceptor_strcpy") is True
    assert is_vendored_noise_function("strcpy.part.0") is True


def test_vendored_list_catches_strcpy_part_0_where_current_denylist_does_not():
    """Documents the concrete gap this task closes: `dedup._NOISE_FUNC_RE` (today's
    live 9-pattern denylist) does not recognize Clang's `strcpy.part.0` interceptor
    frame as noise, but the vendored ClusterFuzz list (`^(|__)strcpy`, a startswith
    match) does. This vendored matcher is not wired into dedup.py yet (see module
    docstring) -- this test only proves the data exists to fix it later."""
    assert bool(_NOISE_FUNC_RE.match("strcpy.part.0")) is False
    assert is_vendored_noise_function("strcpy.part.0") is True


# --------------------------------------------------------------------------
# is_vendored_noise_function -- real, non-noise application code is NOT noise
# --------------------------------------------------------------------------

def test_real_demo_target_vuln_function_is_not_flagged():
    """`vuln` is examples/vuln-demo/vuln.c's actual buggy function and appears as
    frame #1 in both tests/fixtures/reports/asan/*.txt fixtures -- it must never
    be treated as noise."""
    assert is_vendored_noise_function("vuln") is False


def test_other_plausible_application_function_names_are_not_flagged():
    assert is_vendored_noise_function("parse_header") is False
    assert is_vendored_noise_function("handle_packet") is False


def test_main_is_flagged_noise_by_the_real_ported_clusterfuzz_list():
    """Documented, verified finding -- NOT the outcome one might naively expect.

    `examples/vuln-demo/vuln.c`'s `main` is real, legitimate application code and
    appears as frame #2 in both ASan fixtures. But ClusterFuzz's real, verbatim
    `STACK_FRAME_IGNORE_REGEXES` (fetched live from GitHub for this task, not
    reconstructed from memory) contains the literal entry `r'^main'`, a startswith
    match -- so `is_vendored_noise_function("main")` is True by design of the
    ported upstream data, not a bug introduced here. This matches
    planning/research/05-accuracy-and-ground-truth.md SS3.7's own framing: harness
    frames including driver `main` are denylisted "but only if at least one
    non-noise frame survives" -- that survival guard lives in dedup.py's existing
    `stack_hashes` fallback (returns (None, None) / falls back to label-grouping
    when nothing significant remains), not in this matcher, which is why this
    module intentionally does not special-case `main` back out of the ported list.
    CASR's equivalent C++ list explicitly disagrees -- its source has `r"^main"`
    commented out (`//r"^main",`) -- which is exactly why this module keeps the
    two upstream lists distinct (`CLUSTERFUZZ_FUNCTION_IGNORE_REGEXES` vs.
    `CASR_CPP_FUNCTION_IGNORE_REGEXES`) rather than silently reconciling them.
    """
    assert is_vendored_noise_function("main") is True
    assert "^main" not in CASR_CPP_FUNCTION_IGNORE_REGEXES


def test_empty_or_none_function_name_is_not_noise():
    assert is_vendored_noise_function(None) is False
    assert is_vendored_noise_function("") is False


# --------------------------------------------------------------------------
# is_vendored_noise_filepath
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "file_path",
    [
        "/usr/include/c++/11/bits/stl_vector.h",
        "/lib/x86_64-linux-gnu/libasan.so.8",
        "/usr/lib/x86_64-linux-gnu/libc.so.6",
        "/build/src/compiler-rt/lib/asan/asan_interceptors.cpp",
        "[vdso]",
    ],
)
def test_known_noise_filepaths_are_flagged(file_path):
    assert is_vendored_noise_filepath(file_path) is True


def test_real_demo_target_source_file_is_not_flagged():
    assert is_vendored_noise_filepath("vuln.c") is False
    assert (
        is_vendored_noise_filepath(
            "/home/natedawg/repos/AutoFTE/examples/vuln-demo/vuln.c"
        )
        is False
    )


def test_empty_or_none_filepath_is_not_noise():
    assert is_vendored_noise_filepath(None) is False
    assert is_vendored_noise_filepath("") is False
