"""Pure unit tests for the LLM trust layer's deterministic checkers.

No Ollama, no network -- pushes handcrafted (mostly adversarial) fake
model-response dicts through `validate_response` and `_apply_validators`
and asserts each bad one is caught, and that a fully-compliant response
passes cleanly. Per research/06 §5.4/§7d, this is the test that protects
users and needs no model at all.
"""

import json

import pytest

from autofte.llm import (
    LLMResponseError,
    _apply_validators,
    _contains_weaponized_content,
    _sample_agreement,
    analyze,
    validate_response,
)


def _heap_overflow_crash_record():
    return {
        "sanitizer": "AddressSanitizer",
        "bug_class": "heap-buffer-overflow",
        "access_type": "read",
        "access_size": 4,
        "fault_addr": "0xdeadbeef",
        "crash_stack": [{"frame": 0, "addr": "0x1", "func": "parse", "file": "p.c", "line": 8}],
        "alloc_stack": [],
        "free_stack": [],
        "sanitizer_raw": "== ERROR ==",
    }


def _uaf_crash_record(with_heap_timeline):
    record = {
        "sanitizer": "AddressSanitizer",
        "bug_class": "heap-use-after-free",
        "access_type": "write",
        "access_size": 8,
        "fault_addr": "0xdeadbeef",
        "crash_stack": [{"frame": 0, "addr": "0x1", "func": "use", "file": "u.c", "line": 3}],
        "alloc_stack": [],
        "free_stack": [],
        "sanitizer_raw": "== ERROR ==",
    }
    if with_heap_timeline:
        record["alloc_stack"] = [
            {"frame": 0, "addr": "0x2", "func": "new_conn", "file": "c.c", "line": 12},
        ]
        record["free_stack"] = [
            {"frame": 0, "addr": "0x3", "func": "release_conn", "file": "c.c", "line": 45},
        ]
    return record


def _double_free_crash_record():
    return {
        "sanitizer": "AddressSanitizer",
        "bug_class": "double-free",
        "access_type": None,
        "access_size": None,
        "fault_addr": None,
        "crash_stack": [{"frame": 0, "addr": "0x1", "func": "cleanup", "file": "c.c", "line": 5}],
        "alloc_stack": [],
        "free_stack": [],
        "sanitizer_raw": "== ERROR ==",
    }


def _compliant_response(**overrides):
    response = {
        "reasoning": "E2 says bug_class heap-buffer-overflow; E3 shows a read.",
        "summary": "A heap buffer was read out of bounds.",
        "summary_evidence": ["E2"],
        "likely_bug_type": "heap-buffer-overflow",
        "likely_bug_type_evidence": ["E2"],
        "root_cause": "A read went past the end of a heap allocation.",
        "root_cause_evidence": ["E2"],
        "exploitability_class": "read_primitive_indicated",
        "exploitability_evidence": ["E3"],
        "fix_ideas": ["bounds-check the read"],
        "next_checks": ["confirm the allocation size"],
        "what_would_confirm": ["the exact object size"],
        "unknowns": ["whether the offset is attacker-controlled"],
    }
    response.update(overrides)
    return response


_VALID_IDS = {"E1", "E2", "E3", "E4", "E5"}


# --------------------------------------------------------------------------
# validate_response -- schema/shape adversarial cases (drive the retry ladder)
# --------------------------------------------------------------------------

def test_rejects_missing_reasoning_field():
    bad = _compliant_response()
    del bad["reasoning"]
    with pytest.raises(LLMResponseError, match="reasoning"):
        validate_response(bad)


def test_rejects_missing_unknowns_field():
    bad = _compliant_response()
    del bad["unknowns"]
    with pytest.raises(LLMResponseError, match="unknowns"):
        validate_response(bad)


def test_rejects_verdict_shaped_exploitability_class():
    bad = _compliant_response(exploitability_class="exploitable")
    with pytest.raises(LLMResponseError, match="exploitability_class"):
        validate_response(bad)


def test_rejects_empty_claim_evidence_array():
    bad = _compliant_response(root_cause_evidence=[])
    with pytest.raises(LLMResponseError, match="root_cause_evidence"):
        validate_response(bad)


def test_rejects_capped_list_over_four_items():
    bad = _compliant_response(fix_ideas=["a", "b", "c", "d", "e"])
    with pytest.raises(LLMResponseError, match="fix_ideas"):
        validate_response(bad)


def test_rejects_placeholder_summary_text():
    bad = _compliant_response(summary="short label")
    with pytest.raises(LLMResponseError, match="summary"):
        validate_response(bad)


def test_rejects_degenerate_all_empty_string_array():
    bad = _compliant_response(next_checks=["", ""])
    with pytest.raises(LLMResponseError, match="next_checks"):
        validate_response(bad)


def test_accepts_unknown_likely_bug_type_as_valid_abstention():
    validate_response(_compliant_response(likely_bug_type="unknown"))


# --------------------------------------------------------------------------
# Validator #1 -- bug-class contradiction (reject + substitute ground truth)
# --------------------------------------------------------------------------

def test_rejects_heap_bug_stated_as_stack():
    crash_record = _heap_overflow_crash_record()
    response = _compliant_response(
        likely_bug_type="stack-buffer-overflow",
        likely_bug_type_evidence=["E2"],
    )
    result, breakdown = _apply_validators(response, crash_record, _VALID_IDS, 0.9)
    assert result["likely_bug_type"] == "heap-buffer-overflow"
    assert any("contradicts" in r for r in breakdown["rejections"])


def test_rejects_double_free_stated_as_use_after_free():
    crash_record = _double_free_crash_record()
    response = _compliant_response(
        likely_bug_type="use-after-free",
        likely_bug_type_evidence=["E2"],
        exploitability_class="insufficient_evidence",
        exploitability_evidence=["E2"],
    )
    result, breakdown = _apply_validators(response, crash_record, _VALID_IDS, 0.9)
    assert result["likely_bug_type"] == "double-free"
    assert any("contradicts" in r for r in breakdown["rejections"])


def test_does_not_reject_matching_bug_class_phrased_differently():
    crash_record = _uaf_crash_record(with_heap_timeline=True)
    response = _compliant_response(
        likely_bug_type="use after free",
        likely_bug_type_evidence=["E2"],
        exploitability_class="insufficient_evidence",
        exploitability_evidence=["E2"],
    )
    result, breakdown = _apply_validators(response, crash_record, _VALID_IDS, 0.9)
    assert result["likely_bug_type"] == "use after free"
    assert not any("contradicts" in r for r in breakdown["rejections"])


def test_unmapped_ground_truth_bug_class_is_not_contradicted():
    crash_record = _heap_overflow_crash_record()
    crash_record["bug_class"] = "some-future-sanitizer-class"
    response = _compliant_response(
        likely_bug_type="totally different phrase",
        likely_bug_type_evidence=["E2"],
        exploitability_class="insufficient_evidence",
        exploitability_evidence=["E2"],
    )
    result, breakdown = _apply_validators(response, crash_record, _VALID_IDS, 0.9)
    assert result["likely_bug_type"] == "totally different phrase"
    assert not any("contradicts" in r for r in breakdown["rejections"])


# --------------------------------------------------------------------------
# Validator #2 -- evidence-ID validity (fabricated citations)
# --------------------------------------------------------------------------

def test_drops_fabricated_evidence_id():
    crash_record = _heap_overflow_crash_record()
    response = _compliant_response(root_cause_evidence=["E2", "E14"])
    result, breakdown = _apply_validators(response, crash_record, _VALID_IDS, 0.9)
    assert result["root_cause_evidence"] == ["E2"]
    assert any("E14" in r for r in breakdown["rejections"])


def test_drops_all_fabricated_evidence_leaves_field_uncited():
    crash_record = _heap_overflow_crash_record()
    response = _compliant_response(summary_evidence=["E97", "E98"])
    result, breakdown = _apply_validators(response, crash_record, _VALID_IDS, 0.9)
    assert result["summary_evidence"] == []
    assert any("no valid citation left" in r for r in breakdown["rejections"])


def test_valid_citations_are_never_flagged():
    crash_record = _heap_overflow_crash_record()
    response = _compliant_response()
    result, breakdown = _apply_validators(response, crash_record, _VALID_IDS, 0.9)
    assert result["summary_evidence"] == ["E2"]
    assert breakdown["rejections"] == []


# --------------------------------------------------------------------------
# Validator #4 -- exploitability ceiling (clamp down, never up)
# --------------------------------------------------------------------------

def test_clamps_exploitability_when_no_crash_record_at_all():
    response = _compliant_response(
        exploitability_class="control_flow_influence_indicated",
        exploitability_evidence=["E2"],
    )
    result, breakdown = _apply_validators(response, None, _VALID_IDS, 0.1)
    assert result["exploitability_class"] == "insufficient_evidence"
    assert any("no sanitizer crash record" in r for r in breakdown["rejections"])


def test_clamps_write_primitive_claim_on_read_only_access():
    crash_record = _heap_overflow_crash_record()
    assert crash_record["access_type"] == "read"
    response = _compliant_response(
        exploitability_class="write_primitive_indicated",
        exploitability_evidence=["E3"],
    )
    result, breakdown = _apply_validators(response, crash_record, _VALID_IDS, 0.9)
    assert result["exploitability_class"] == "read_primitive_indicated"
    assert any("read-only access" in r for r in breakdown["rejections"])


def test_clamps_uaf_control_flow_claim_with_no_heap_timeline():
    crash_record = _uaf_crash_record(with_heap_timeline=False)
    response = _compliant_response(
        exploitability_class="control_flow_influence_indicated",
        exploitability_evidence=["E2"],
    )
    result, breakdown = _apply_validators(response, crash_record, _VALID_IDS, 0.9)
    assert result["exploitability_class"] == "memory_safety_violation_no_primitive_shown"
    assert any("heap timeline" in r for r in breakdown["rejections"])


def test_allows_uaf_control_flow_claim_with_heap_timeline_present():
    crash_record = _uaf_crash_record(with_heap_timeline=True)
    response = _compliant_response(
        likely_bug_type="heap-use-after-free",
        likely_bug_type_evidence=["E2"],
        exploitability_class="control_flow_influence_indicated",
        exploitability_evidence=["E2"],
    )
    result, breakdown = _apply_validators(response, crash_record, _VALID_IDS, 0.9)
    assert result["exploitability_class"] == "control_flow_influence_indicated"
    assert breakdown["rejections"] == []


# --------------------------------------------------------------------------
# Weaponization filter
# --------------------------------------------------------------------------

def test_detects_pwntools_and_p64_markers():
    assert _contains_weaponized_content("use pwntools to build the exploit")
    assert _contains_weaponized_content("call p64(0xdeadbeef) to build the chain")


def test_detects_long_base64_blob():
    blob = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB"
    assert _contains_weaponized_content(blob)


def test_clean_narrative_text_is_not_flagged():
    assert not _contains_weaponized_content(
        "This is a heap buffer overflow. Add a bounds check before the copy."
    )


def test_redacts_rop_chain_from_fix_ideas_keeps_clean_items():
    crash_record = _heap_overflow_crash_record()
    response = _compliant_response(
        fix_ideas=[
            "bounds-check the copy",
            "ROPgadget --binary target to build p64(0x401234) chain",
        ]
    )
    result, breakdown = _apply_validators(response, crash_record, _VALID_IDS, 0.9)
    assert result["fix_ideas"] == ["bounds-check the copy"]
    assert any("redacted" in w for w in breakdown["warnings"])


def test_redacts_shellcode_bytes_from_root_cause_keeps_other_fields():
    crash_record = _heap_overflow_crash_record()
    payload = "\\x90" * 20
    response = _compliant_response(
        root_cause=f"the shellcode {payload} overwrites the return address"
    )
    result, breakdown = _apply_validators(response, crash_record, _VALID_IDS, 0.9)
    assert result["root_cause"] == "[redacted: response contained exploit/payload-shaped content]"
    assert result["summary"] == response["summary"]
    assert any("redacted" in w for w in breakdown["warnings"])


# --------------------------------------------------------------------------
# Confidence computation
# --------------------------------------------------------------------------

def test_confidence_is_full_penalty_times_completeness_when_clean():
    crash_record = _heap_overflow_crash_record()
    response = _compliant_response()
    result, breakdown = _apply_validators(response, crash_record, _VALID_IDS, 0.8)
    assert breakdown["validator_penalty"] == 1.0
    assert breakdown["confidence"] == pytest.approx(0.8)


def test_confidence_drops_with_each_rejection():
    crash_record = _heap_overflow_crash_record()
    response = _compliant_response(
        likely_bug_type="stack-buffer-overflow", likely_bug_type_evidence=["E2"]
    )
    _result, breakdown = _apply_validators(response, crash_record, _VALID_IDS, 0.8)
    assert breakdown["validator_penalty"] == pytest.approx(0.5)
    assert breakdown["confidence"] == pytest.approx(0.4)


def test_confidence_floor_is_never_zero_from_penalty_alone():
    crash_record = _heap_overflow_crash_record()
    response = _compliant_response(
        likely_bug_type="stack-buffer-overflow",
        likely_bug_type_evidence=["E2"],
        root_cause_evidence=["E77"],
        summary_evidence=["E78"],
        exploitability_class="write_primitive_indicated",
    )
    _result, breakdown = _apply_validators(response, crash_record, _VALID_IDS, 1.0)
    assert breakdown["validator_penalty"] >= 0.1
    assert breakdown["confidence"] > 0.0


# --------------------------------------------------------------------------
# End-to-end true-negative: a fully compliant response passes cleanly
# --------------------------------------------------------------------------

class _FakeClient:
    model = "contract-test-model"

    def __init__(self, response):
        self.response = response

    def ask(self, prompt, **kwargs):
        return json.dumps(self.response)


def test_fully_compliant_response_passes_with_zero_rejections_and_warnings():
    triage_data = {
        "total_crashes": 4,
        "unique_crash_frames": 1,
        "triage_mode": "sanitizer",
        "groups": {
            "heap-buffer-overflow in parse at p.c:8": {
                "count": 4,
                "crashes": [{"file": "c1", "size": 12, "sanitizer": _heap_overflow_crash_record()}],
            }
        },
    }
    client = _FakeClient(_compliant_response())
    result = analyze(client, triage_data)
    assert result["confidence_breakdown"]["rejections"] == []
    assert result["confidence_breakdown"]["warnings"] == []
    assert result["confidence_breakdown"]["confidence"] > 0.0
    assert result["likely_bug_type"] == "heap-buffer-overflow"


# --------------------------------------------------------------------------
# Validator #3: function-name grounding (warn only)
# --------------------------------------------------------------------------

def test_warns_on_ungrounded_function_name_in_narrative():
    crash_record = _heap_overflow_crash_record()
    response = _compliant_response(
        root_cause="The bug is in totally_made_up_helper() which never appears in evidence."
    )
    _result, breakdown = _apply_validators(response, crash_record, _VALID_IDS, 0.8)
    assert any("totally_made_up_helper" in w for w in breakdown["warnings"])
    assert breakdown["rejections"] == []


def test_no_warning_for_function_name_present_in_crash_stack():
    crash_record = _heap_overflow_crash_record()
    response = _compliant_response(root_cause="The bug is inside parse() at p.c:8.")
    _result, breakdown = _apply_validators(response, crash_record, _VALID_IDS, 0.8)
    assert breakdown["warnings"] == []


def test_no_warning_for_common_libc_function_mentioned_generically():
    crash_record = _heap_overflow_crash_record()
    response = _compliant_response(
        summary="A read past the end of a buffer allocated via malloc()."
    )
    _result, breakdown = _apply_validators(response, crash_record, _VALID_IDS, 0.8)
    assert breakdown["warnings"] == []


# --------------------------------------------------------------------------
# Validator #5: mitigation-fact contradiction
# --------------------------------------------------------------------------

_CANARY_ENABLED_BINARY_ANALYSIS = {"stack_canaries": {"enabled": True}}
_CANARY_DISABLED_BINARY_ANALYSIS = {"stack_canaries": {"enabled": False}}


def test_rejects_no_canary_claim_when_canary_is_enabled():
    crash_record = _heap_overflow_crash_record()
    response = _compliant_response(reasoning="E2 says heap-buffer-overflow, no stack canary here.")
    _result, breakdown = _apply_validators(
        response, crash_record, _VALID_IDS, 0.8, binary_analysis=_CANARY_ENABLED_BINARY_ANALYSIS
    )
    assert any("stack canary" in r for r in breakdown["rejections"])


def test_rejects_canary_present_claim_when_canary_is_disabled():
    crash_record = _heap_overflow_crash_record()
    response = _compliant_response(reasoning="E2 says heap-buffer-overflow, has a stack canary.")
    _result, breakdown = _apply_validators(
        response, crash_record, _VALID_IDS, 0.8, binary_analysis=_CANARY_DISABLED_BINARY_ANALYSIS
    )
    assert any("stack canary" in r for r in breakdown["rejections"])


def test_no_contradiction_when_mitigation_claim_matches_reality():
    crash_record = _heap_overflow_crash_record()
    response = _compliant_response(reasoning="E2 says heap-buffer-overflow, has a stack canary.")
    _result, breakdown = _apply_validators(
        response, crash_record, _VALID_IDS, 0.8, binary_analysis=_CANARY_ENABLED_BINARY_ANALYSIS
    )
    assert breakdown["rejections"] == []


def test_no_contradiction_when_binary_analysis_not_supplied():
    crash_record = _heap_overflow_crash_record()
    response = _compliant_response(reasoning="E2 says heap-buffer-overflow, no stack canary here.")
    _result, breakdown = _apply_validators(response, crash_record, _VALID_IDS, 0.8)
    assert breakdown["rejections"] == []


# --------------------------------------------------------------------------
# Adversarial review (2026-08-08): the module defines a SECOND, more
# complete set of constants for validators #3/#5 --
# `_FUNCTION_CALL_RE`/`_FUNCTION_CALL_EXCLUDED_KEYWORDS`/
# `_COMMON_LIBC_FUNCTION_ALLOWLIST` and
# `_MITIGATION_ABSENT_PATTERNS`/`_MITIGATION_PRESENT_PATTERNS`/
# `_MITIGATION_HEDGE_RE` -- but `_warn_ungrounded_function_names` and
# `_reject_mitigation_contradictions` are wired to a DIFFERENT, narrower
# set (`_IDENTIFIER_CALL_RE`/`_COMMON_LIBC_FUNCTIONS`,
# `_MITIGATION_DISABLED_PATTERNS`/`_MITIGATION_ENABLED_PATTERNS`) that has
# no keyword exclusion and no hedge check at all. These three tests encode
# the behavior the dead constants and their own doc comments promise, and
# fail against the current wiring -- see the AGENT_CHANGELOG entry
# "Adversarial review: E9 LLM validators + self-consistency" for details.
# --------------------------------------------------------------------------

def test_no_warning_for_control_flow_keyword_shaped_prose():
    """`if(`, `for(`, `sizeof(` are control-flow/operator syntax, not
    function calls -- `_FUNCTION_CALL_EXCLUDED_KEYWORDS` documents exactly
    this exclusion, but that constant is dead code never referenced by
    `_warn_ungrounded_function_names`'s actual regex (`_IDENTIFIER_CALL_RE`
    has no keyword exclusion at all).
    """
    crash_record = _heap_overflow_crash_record()
    response = _compliant_response(
        root_cause=(
            "The overflow only triggers if(len > buf_size) is false, so the bound is "
            "never checked."
        )
    )
    _result, breakdown = _apply_validators(response, crash_record, _VALID_IDS, 0.8)
    assert breakdown["warnings"] == []


def test_no_reject_for_hedged_comparative_mitigation_language():
    """A hedged/comparative sentence ("despite ... in older builds ...")
    is not a claim about the real binary -- research/06 §7b's own worked
    example, and `_MITIGATION_HEDGE_RE` exists to encode it, but that
    constant is dead code never referenced by
    `_reject_mitigation_contradictions` (wired to
    `_MITIGATION_DISABLED_PATTERNS`, which has no hedge check).
    """
    crash_record = _heap_overflow_crash_record()
    response = _compliant_response(
        reasoning=(
            "E2 says heap-buffer-overflow. Despite there being no stack canary in older "
            "builds of similar programs, this one is different."
        )
    )
    _result, breakdown = _apply_validators(
        response, crash_record, _VALID_IDS, 0.8, binary_analysis=_CANARY_ENABLED_BINARY_ANALYSIS
    )
    assert breakdown["rejections"] == []


def test_rejects_lacks_a_canary_phrasing_when_canary_is_enabled():
    """A real, unhedged contradiction phrased as "lacks a canary" (rather
    than the narrower "no canary" the wired regex looks for) should still
    be caught -- `_MITIGATION_ABSENT_PATTERNS` (dead code) has a
    `lacks?|missing` alternative for exactly this phrasing, but
    `_MITIGATION_DISABLED_PATTERNS` (the one actually wired in) does not.
    """
    crash_record = _heap_overflow_crash_record()
    response = _compliant_response(
        reasoning=(
            "E2 says heap-buffer-overflow. The stack lacks a canary, so the overflow "
            "directly hits the saved return address."
        )
    )
    _result, breakdown = _apply_validators(
        response, crash_record, _VALID_IDS, 0.8, binary_analysis=_CANARY_ENABLED_BINARY_ANALYSIS
    )
    assert any("stack canary" in r for r in breakdown["rejections"])


# --------------------------------------------------------------------------
# Self-consistency sampling (agreement_score)
# --------------------------------------------------------------------------

class _VaryingClient:
    model = "contract-test-model"

    def __init__(self, responses):
        self._responses = list(responses)
        self._index = 0

    def ask(self, prompt, **kwargs):
        response = self._responses[self._index % len(self._responses)]
        self._index += 1
        return json.dumps(response)


def test_sample_agreement_is_one_when_all_samples_agree():
    client = _VaryingClient([_compliant_response()] * 5)
    score = _sample_agreement(client, "prompt", samples=5)
    assert score == pytest.approx(1.0)


def test_sample_agreement_drops_when_samples_disagree():
    client = _VaryingClient(
        [
            _compliant_response(),
            _compliant_response(),
            _compliant_response(
                likely_bug_type="stack-buffer-overflow",
                exploitability_class="write_primitive_indicated",
            ),
        ]
    )
    score = _sample_agreement(client, "prompt", samples=3)
    assert score == pytest.approx(2 / 3)


def test_sample_agreement_ignores_unparseable_samples():
    class _MostlyBrokenClient:
        model = "contract-test-model"

        def ask(self, prompt, **kwargs):
            return "not json at all"

    score = _sample_agreement(_MostlyBrokenClient(), "prompt", samples=3)
    assert score == pytest.approx(1.0)


def test_analyze_defaults_to_neutral_agreement_score_without_self_consistency():
    triage_data = {
        "total_crashes": 4,
        "unique_crash_frames": 1,
        "triage_mode": "sanitizer",
        "groups": {
            "heap-buffer-overflow in parse at p.c:8": {
                "count": 4,
                "crashes": [{"file": "c1", "size": 12, "sanitizer": _heap_overflow_crash_record()}],
            }
        },
    }
    client = _FakeClient(_compliant_response())
    result = analyze(client, triage_data)
    assert result["confidence_breakdown"]["agreement_score"] == pytest.approx(1.0)
