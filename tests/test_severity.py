import pathlib
import subprocess

import pytest

from autofte import binary_analysis, sanitizers
from autofte.severity import (
    BASE_CONFIDENCE_NO_CRASH,
    CONFIDENCE_CEILING,
    CONFIDENCE_FLOOR,
    assess_crash_difficulty,
)

from .conftest import ASAN_AVAILABLE, compile_vuln_asan_binary

# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------


def _mitigation_analysis(*, canary, pie, nx, aslr, relro_status):
    protections = {
        "aslr_system": {"enabled": aslr},
        "nx_bit": {"enabled": nx},
        "stack_canaries": {"enabled": canary},
        "pie": {"enabled": pie},
        "relro": {"status": relro_status},
    }
    analyzer = binary_analysis.BinaryAnalyzer("bin")
    analyzer.protections = protections
    protections["exploit_mitigation_summary"] = analyzer._summarize_mitigations()
    return protections


WEAK_ANALYSIS = _mitigation_analysis(
    canary=False, pie=False, nx=False, aslr=False, relro_status="No RELRO"
)

STRONG_ANALYSIS = _mitigation_analysis(
    canary=True, pie=True, nx=True, aslr=True, relro_status="Full RELRO"
)


def _crash_record(
    bug_class, access_type, *, func="vuln", alloc_stack=None, free_stack=None, access_size=8
):
    return {
        "sanitizer": "AddressSanitizer",
        "bug_class": bug_class,
        "access_type": access_type,
        "access_size": access_size,
        "fault_addr": "0xdeadbeef",
        "crash_stack": [
            {"frame": 0, "addr": "0x1", "func": func, "file": "vuln.c", "line": 8}
        ],
        "alloc_stack": alloc_stack or [],
        "free_stack": free_stack or [],
        "sanitizer_raw": f"=={bug_class}==",
    }


# --------------------------------------------------------------------------
# Return shape: always the same keys, regardless of crash_record presence
# --------------------------------------------------------------------------


def test_return_shape_is_consistent_with_and_without_crash_record():
    with_crash = assess_crash_difficulty(
        WEAK_ANALYSIS, _crash_record("stack-buffer-overflow", "write")
    )
    without_crash = assess_crash_difficulty(WEAK_ANALYSIS, None)

    expected_keys = {
        "difficulty",
        "confidence",
        "rationale",
        "would_increase_confidence",
        "would_decrease_confidence",
        "basis",
        "score",
    }
    assert set(with_crash) == expected_keys
    assert set(without_crash) == expected_keys

    for result in (with_crash, without_crash):
        assert result["difficulty"] in {"Easy", "Medium", "Hard"}
        assert CONFIDENCE_FLOOR <= result["confidence"] <= CONFIDENCE_CEILING
        assert isinstance(result["rationale"], str) and result["rationale"]
        assert isinstance(result["would_increase_confidence"], list)
        assert result["would_increase_confidence"]
        assert isinstance(result["would_decrease_confidence"], list)
        assert result["would_decrease_confidence"]


def test_no_result_ever_reads_as_a_bare_verdict():
    """PLAN.md §7's honesty requirement: never a definitive verdict."""
    result = assess_crash_difficulty(WEAK_ANALYSIS, _crash_record("double-free", "write"))
    assert "verdict" in result["rationale"].lower()
    assert result["confidence"] < 1.0


# --------------------------------------------------------------------------
# Core fusion: crash-aware assessment differs meaningfully from mitigation-only
# --------------------------------------------------------------------------


def test_stack_write_no_mitigations_scores_easier_than_heap_read_full_mitigations():
    stack_write_weak = assess_crash_difficulty(
        WEAK_ANALYSIS, _crash_record("stack-buffer-overflow", "write")
    )
    heap_read_strong = assess_crash_difficulty(
        STRONG_ANALYSIS, _crash_record("heap-buffer-overflow", "read")
    )

    assert stack_write_weak["difficulty"] == "Easy"
    assert heap_read_strong["difficulty"] == "Hard"
    assert stack_write_weak["score"] < heap_read_strong["score"]
    assert "no stack canary" in stack_write_weak["rationale"].lower()
    assert "with no pie" in stack_write_weak["rationale"].lower()


def test_same_bug_class_write_vs_read_on_identical_mitigations():
    write_result = assess_crash_difficulty(
        WEAK_ANALYSIS, _crash_record("heap-buffer-overflow", "write")
    )
    read_result = assess_crash_difficulty(
        WEAK_ANALYSIS, _crash_record("heap-buffer-overflow", "read")
    )
    assert write_result["score"] < read_result["score"]


def test_stack_buffer_overflow_write_gets_extra_penalty_over_heap_write():
    stack_write = assess_crash_difficulty(
        WEAK_ANALYSIS, _crash_record("stack-buffer-overflow", "write")
    )
    heap_write = assess_crash_difficulty(
        WEAK_ANALYSIS, _crash_record("heap-buffer-overflow", "write")
    )
    assert stack_write["score"] < heap_write["score"]
    assert "saved registers" in stack_write["rationale"].lower()


def test_large_write_scores_more_severe_than_single_byte_write():
    large = assess_crash_difficulty(
        WEAK_ANALYSIS, _crash_record("heap-buffer-overflow", "write", access_size=64)
    )
    tiny = assess_crash_difficulty(
        WEAK_ANALYSIS, _crash_record("heap-buffer-overflow", "write", access_size=1)
    )
    assert large["score"] < tiny["score"]


def test_access_size_ignored_for_reads():
    big_read = assess_crash_difficulty(
        WEAK_ANALYSIS, _crash_record("heap-buffer-overflow", "read", access_size=64)
    )
    small_read = assess_crash_difficulty(
        WEAK_ANALYSIS, _crash_record("heap-buffer-overflow", "read", access_size=1)
    )
    assert big_read["score"] == small_read["score"]


def test_rationale_omits_direction_qualifier_when_access_type_is_unknown():
    result = assess_crash_difficulty(
        WEAK_ANALYSIS, _crash_record("stack-buffer-overflow", None)
    )
    assert "unknown-direction" not in result["rationale"]
    assert "()" not in result["rationale"]
    assert "stack-buffer-overflow --" in result["rationale"]


def test_canary_flips_the_stack_write_rationale_not_just_the_score():
    canary_analysis = _mitigation_analysis(
        canary=True, pie=False, nx=False, aslr=False, relro_status="No RELRO"
    )
    result = assess_crash_difficulty(
        canary_analysis, _crash_record("stack-buffer-overflow", "write")
    )
    assert "caught before it is used" in result["rationale"].lower()

    no_canary_result = assess_crash_difficulty(
        WEAK_ANALYSIS, _crash_record("stack-buffer-overflow", "write")
    )
    assert "would go undetected" in no_canary_result["rationale"].lower()
    assert result["score"] > no_canary_result["score"]


# --------------------------------------------------------------------------
# Use-after-free / double-free are treated seriously
# --------------------------------------------------------------------------


def test_use_after_free_write_is_treated_seriously():
    result = assess_crash_difficulty(
        WEAK_ANALYSIS,
        _crash_record(
            "heap-use-after-free",
            "write",
            alloc_stack=[{"frame": 0, "addr": "0x1", "func": "malloc", "file": None, "line": None}],
            free_stack=[{"frame": 0, "addr": "0x1", "func": "free", "file": None, "line": None}],
        ),
    )
    assert result["difficulty"] == "Easy"
    assert result["score"] < 0
    assert "reliably exploitable" in result["rationale"].lower()


def test_double_free_is_treated_seriously():
    result = assess_crash_difficulty(WEAK_ANALYSIS, _crash_record("double-free", None))
    assert result["difficulty"] in {"Easy", "Medium"}
    assert result["score"] < WEAK_ANALYSIS["exploit_mitigation_summary"]["protection_count"]


def test_heap_use_after_free_with_alloc_free_stacks_more_confident_than_without():
    with_stacks = assess_crash_difficulty(
        WEAK_ANALYSIS,
        _crash_record(
            "heap-use-after-free",
            "write",
            alloc_stack=[{"frame": 0, "addr": "0x1", "func": "malloc", "file": None, "line": None}],
            free_stack=[{"frame": 0, "addr": "0x1", "func": "free", "file": None, "line": None}],
        ),
    )
    without_stacks = assess_crash_difficulty(
        WEAK_ANALYSIS, _crash_record("heap-use-after-free", "write")
    )
    assert with_stacks["confidence"] > without_stacks["confidence"]


# --------------------------------------------------------------------------
# Low-severity / logic-only bug classes are not overclaimed as dangerous
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bug_class",
    ["null-pointer-dereference", "division-by-zero", "misaligned-pointer", "shift-out-of-bounds"],
)
def test_dos_only_bug_classes_score_harder_than_a_stack_write(bug_class):
    dos_only = assess_crash_difficulty(WEAK_ANALYSIS, _crash_record(bug_class, None))
    stack_write = assess_crash_difficulty(
        WEAK_ANALYSIS, _crash_record("stack-buffer-overflow", "write")
    )
    assert dos_only["score"] > stack_write["score"]


# --------------------------------------------------------------------------
# Ambiguous / no-sanitizer-data crashes still get a sane, honestly lower
# confidence assessment
# --------------------------------------------------------------------------


def test_bare_null_deref_segv_with_no_sanitizer_data_falls_back_gracefully():
    """No sanitizer record at all -- e.g. a bare gdb/signal grouping for a
    NULL-deref SEGV. Must still return the full shape, from mitigations
    alone, with a confidence lower than any crash-aware assessment.
    """
    result = assess_crash_difficulty(WEAK_ANALYSIS, None)

    assert result["basis"] == "mitigation_only"
    assert result["difficulty"] in {"Easy", "Medium", "Hard"}
    assert result["confidence"] == BASE_CONFIDENCE_NO_CRASH

    crash_aware = assess_crash_difficulty(
        WEAK_ANALYSIS, _crash_record("stack-buffer-overflow", "write")
    )
    assert result["confidence"] < crash_aware["confidence"]
    assert "no sanitizer crash record" in result["rationale"].lower()


def test_segv_bug_class_with_unknown_access_direction_is_low_confidence():
    ambiguous = _crash_record("SEGV", None)
    result = assess_crash_difficulty(WEAK_ANALYSIS, ambiguous)
    confident = assess_crash_difficulty(
        WEAK_ANALYSIS, _crash_record("stack-buffer-overflow", "write")
    )
    assert result["confidence"] < confident["confidence"]
    assert any("read or a write" in item for item in result["would_increase_confidence"])


def test_unknown_bug_class_does_not_crash_and_is_neutral():
    record = _crash_record("some-new-sanitizer-class", "write")
    result = assess_crash_difficulty(WEAK_ANALYSIS, record)
    assert result["difficulty"] in {"Easy", "Medium", "Hard"}
    assert 0.0 <= result["confidence"] <= 1.0


# --------------------------------------------------------------------------
# Mitigation tool failures reduce confidence and are surfaced honestly
# --------------------------------------------------------------------------


def test_mitigation_tool_error_reduces_confidence_and_is_named():
    broken = dict(WEAK_ANALYSIS)
    broken["nx_bit"] = {"error": "readelf timed out after 15s"}
    result = assess_crash_difficulty(broken, None)
    clean = assess_crash_difficulty(WEAK_ANALYSIS, None)

    assert result["confidence"] < clean["confidence"]
    assert any("nx_bit check failed" in item for item in result["would_decrease_confidence"])


def test_missing_exploit_mitigation_summary_does_not_crash():
    result = assess_crash_difficulty({}, _crash_record("heap-buffer-overflow", "write"))
    assert result["difficulty"] in {"Easy", "Medium", "Hard"}


# --------------------------------------------------------------------------
# Real ASan-compiled binary + real analyze_binary() integration test
# --------------------------------------------------------------------------


@pytest.mark.skipif(not ASAN_AVAILABLE, reason="gcc -fsanitize=address not available")
def test_assess_crash_difficulty_against_real_asan_target(tmp_path):
    repo_root = pathlib.Path(__file__).resolve().parents[1]
    src_path = repo_root / "examples" / "vuln-demo" / "vuln.c"
    assert src_path.exists()

    target = compile_vuln_asan_binary(tmp_path, src_path)
    crash_input = tmp_path / "crash_input"
    # marker byte '1' selects vuln.c's stack-buffer-overflow path (see vuln.c's
    # module docstring for the full marker -> bug mapping).
    crash_input.write_bytes(b"1" + b"A" * 200)

    proc = subprocess.run(
        [str(target), str(crash_input)], capture_output=True, text=True, timeout=10
    )
    record = sanitizers.parse_sanitizer_output(proc.stdout + proc.stderr)
    assert record is not None
    assert record["bug_class"] == "stack-buffer-overflow"
    assert record["access_type"] == "write"

    analysis = binary_analysis.analyze_binary(str(target))
    assert "exploit_mitigation_summary" in analysis

    result = assess_crash_difficulty(analysis, record)

    assert result["basis"] == "mitigation_and_crash"
    assert result["difficulty"] in {"Easy", "Medium", "Hard"}
    assert "stack-buffer-overflow" in result["rationale"]
    assert CONFIDENCE_FLOOR <= result["confidence"] <= CONFIDENCE_CEILING

    fallback = assess_crash_difficulty(analysis, None)
    assert fallback["basis"] == "mitigation_only"
    assert fallback["confidence"] < result["confidence"]
