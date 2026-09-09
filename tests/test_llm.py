
import json

import pytest
import requests

from autofte.llm import (
    DEFAULT_MAX_TOKENS,
    RESPONSE_SCHEMA,
    EvidenceLedger,
    LLMResponseError,
    OllamaClient,
    _bug_class_family,
    _evidence_completeness,
    _normalize_bug_type_family,
    analyze,
    build_prompt,
    extract_json,
    validate_response,
)


def _sanitizer_record():
    return {
        "sanitizer": "AddressSanitizer",
        "bug_class": "heap-buffer-overflow",
        "access_type": "write",
        "access_size": 8,
        "fault_addr": "0xdeadbeef",
        "crash_stack": [
            {"frame": 0, "addr": "0x1", "func": "vuln", "file": "vuln.c", "line": 9},
            {"frame": 1, "addr": "0x2", "func": "main", "file": "vuln.c", "line": 20},
        ],
        "alloc_stack": [
            {"frame": 0, "addr": "0x3", "func": "malloc", "file": None, "line": None},
        ],
        "free_stack": [],
        "sanitizer_raw": "\n".join(f"line {i}" for i in range(40)),
    }


def _triage_data_with_sanitizer_record():
    return {
        "total_crashes": 5,
        "unique_crash_frames": 1,
        "triage_mode": "sanitizer",
        "groups": {
            "heap-buffer-overflow (write 8) in vuln at vuln.c:9": {
                "count": 5,
                "crashes": [
                    {"file": "c1", "size": 42, "sanitizer": _sanitizer_record()},
                ],
            }
        },
    }


# Evidence IDs for _triage_data_with_sanitizer_record() with no binary_analysis/
# severity/source/disassembly, in minting order: E1 sanitizer, E2 bug_class,
# E3 access_type/size, E4 fault_addr, E5 crash frame #0, E6 crash frame #1,
# E7 alloc frame #0 (free_stack is empty), E8 raw sanitizer report pointer.
FULL_RESPONSE = {
    "reasoning": "E2 states bug_class heap-buffer-overflow; E7 shows the allocation site.",
    "summary": "A heap buffer overflow was written past the allocation.",
    "summary_evidence": ["E2"],
    "likely_bug_type": "heap-buffer-overflow",
    "likely_bug_type_evidence": ["E2"],
    "root_cause": "An unbounded write went past the end of a heap buffer allocated in malloc.",
    "root_cause_evidence": ["E2", "E7"],
    "exploitability_class": "write_primitive_indicated",
    "exploitability_evidence": ["E3"],
    "fix_ideas": ["bounds-check the write before it happens"],
    "next_checks": ["confirm the allocation size against the write size"],
    "what_would_confirm": ["the exact allocation size at E7"],
    "unknowns": ["whether the overflow size is attacker-controlled"],
}


# --------------------------------------------------------------------------
# extract_json
# --------------------------------------------------------------------------

def test_extract_json_valid():
    text = '{"summary": "hi", "likely_bug_type": "x"}'
    assert extract_json(text) == {"summary": "hi", "likely_bug_type": "x"}


def test_extract_json_embedded_in_prose():
    text = (
        "Sure, here is my answer:\n"
        '{"summary": "buffer overflow"}\n'
        "Hope that helps!"
    )
    result = extract_json(text)
    assert result["summary"] == "buffer overflow"


def test_extract_json_empty_raises():
    with pytest.raises(LLMResponseError):
        extract_json("")


def test_extract_json_no_braces_raises():
    with pytest.raises(LLMResponseError):
        extract_json("no json here at all")


def test_extract_json_malformed_raises():
    with pytest.raises(LLMResponseError):
        extract_json('{"summary": "unterminated string}')


def test_extract_json_only_closing_brace_raises():
    with pytest.raises(LLMResponseError):
        extract_json("just text }")


def test_extract_json_end_before_start_raises():
    with pytest.raises(LLMResponseError):
        extract_json("} some text {")


# --------------------------------------------------------------------------
# EvidenceLedger
# --------------------------------------------------------------------------

def test_evidence_ledger_mints_sequential_ids():
    ledger = EvidenceLedger()
    assert ledger.add("sanitizer: AddressSanitizer") == "E1"
    assert ledger.add("bug_class: heap-buffer-overflow") == "E2"


def test_evidence_ledger_lines_format():
    ledger = EvidenceLedger()
    ledger.add("sanitizer: AddressSanitizer")
    assert ledger.lines() == ["[E1] sanitizer: AddressSanitizer"]


def test_evidence_ledger_ids_returns_set():
    ledger = EvidenceLedger()
    ledger.add("a")
    ledger.add("b")
    assert ledger.ids() == {"E1", "E2"}


# --------------------------------------------------------------------------
# OllamaClient
# --------------------------------------------------------------------------

def test_ollama_client_requires_model():
    with pytest.raises(ValueError):
        OllamaClient(model=None)


def test_ollama_client_strips_trailing_slash_from_host():
    client = OllamaClient(model="llama3", host="http://localhost:11434/")
    assert client.host == "http://localhost:11434"


class FakeResponse:
    def __init__(self, json_data=None, status_ok=True):
        self._json = json_data or {}
        self._status_ok = status_ok

    def raise_for_status(self):
        if not self._status_ok:
            raise requests.HTTPError("bad status")

    def json(self):
        return self._json


def test_ollama_client_check_model_installed(monkeypatch):
    client = OllamaClient(model="llama3", host="http://x")
    monkeypatch.setattr(
        client.session,
        "get",
        lambda url, timeout: FakeResponse({"models": [{"name": "llama3"}, {"name": "other"}]}),
    )
    ok, message = client.check()
    assert ok is True


def test_ollama_client_check_model_missing(monkeypatch):
    client = OllamaClient(model="llama3", host="http://x")
    monkeypatch.setattr(
        client.session, "get", lambda url, timeout: FakeResponse({"models": [{"name": "other"}]})
    )
    ok, message = client.check()
    assert ok is False
    assert "not installed" in message


def test_ollama_client_check_unreachable(monkeypatch):
    client = OllamaClient(model="llama3", host="http://x")

    def fake_get(url, timeout):
        raise requests.ConnectionError("refused")

    monkeypatch.setattr(client.session, "get", fake_get)
    ok, message = client.check()
    assert ok is False
    assert "not reachable" in message


def test_ollama_client_ask_returns_stripped_response(monkeypatch):
    client = OllamaClient(model="llama3", host="http://x")

    def fake_post(url, json, timeout):
        assert json["model"] == "llama3"
        assert json["prompt"] == "hello"
        return FakeResponse({"response": "  some answer  \n"})

    monkeypatch.setattr(client.session, "post", fake_post)
    result = client.ask("hello")
    assert result == "some answer"


def test_ollama_client_ask_defaults_to_instance_timeout(monkeypatch):
    # No `timeout` kwarg passed to `.ask()` -- it should fall back to
    # whatever timeout the client was constructed with, not a hard-coded
    # value. `None` (unbounded) is the client's own default.
    client = OllamaClient(model="llama3", host="http://x")
    captured = {}

    def fake_post(url, json, timeout):
        captured["timeout"] = timeout
        return FakeResponse({"response": "ok"})

    monkeypatch.setattr(client.session, "post", fake_post)
    client.ask("hello")
    assert captured["timeout"] is None


def test_ollama_client_ask_uses_configured_instance_timeout(monkeypatch):
    client = OllamaClient(model="llama3", host="http://x", timeout=30)
    captured = {}

    def fake_post(url, json, timeout):
        captured["timeout"] = timeout
        return FakeResponse({"response": "ok"})

    monkeypatch.setattr(client.session, "post", fake_post)
    client.ask("hello")
    assert captured["timeout"] == 30


def test_ollama_client_ask_explicit_timeout_overrides_instance(monkeypatch):
    client = OllamaClient(model="llama3", host="http://x", timeout=30)
    captured = {}

    def fake_post(url, json, timeout):
        captured["timeout"] = timeout
        return FakeResponse({"response": "ok"})

    monkeypatch.setattr(client.session, "post", fake_post)
    client.ask("hello", timeout=5)
    assert captured["timeout"] == 5


def test_ollama_client_ask_wraps_network_errors(monkeypatch):
    # `check()` only proves Ollama is reachable, not that `/api/generate`
    # will answer within `timeout` -- a cold model load can pass the
    # preflight and still time out here. Regression for the crash where an
    # uncaught `requests.exceptions.ReadTimeout` propagated all the way out
    # of `autofte demo`/`cmd_pipeline` instead of degrading gracefully like
    # the unreachable-Ollama case already does.
    client = OllamaClient(model="llama3", host="http://x")

    def fake_post(url, json, timeout):
        raise requests.exceptions.ReadTimeout("Read timed out. (read timeout=90)")

    monkeypatch.setattr(client.session, "post", fake_post)
    with pytest.raises(LLMResponseError, match="Ollama request failed"):
        client.ask("hello")


def test_ollama_client_ask_without_schema_omits_format(monkeypatch):
    client = OllamaClient(model="llama3", host="http://x")
    captured = {}

    def fake_post(url, json, timeout):
        captured["payload"] = json
        return FakeResponse({"response": "ok"})

    monkeypatch.setattr(client.session, "post", fake_post)
    client.ask("hello")
    assert "format" not in captured["payload"]
    assert captured["payload"]["options"]["temperature"] == 0.1


def test_ollama_client_ask_with_schema_defaults_temperature_zero(monkeypatch):
    client = OllamaClient(model="llama3", host="http://x")
    captured = {}

    def fake_post(url, json, timeout):
        captured["payload"] = json
        return FakeResponse({"response": "ok"})

    monkeypatch.setattr(client.session, "post", fake_post)
    client.ask("hello", schema=RESPONSE_SCHEMA)
    assert captured["payload"]["format"] == RESPONSE_SCHEMA
    assert captured["payload"]["options"]["temperature"] == 0.0


def test_ollama_client_ask_with_schema_honors_explicit_temperature(monkeypatch):
    client = OllamaClient(model="llama3", host="http://x")
    captured = {}

    def fake_post(url, json, timeout):
        captured["payload"] = json
        return FakeResponse({"response": "ok"})

    monkeypatch.setattr(client.session, "post", fake_post)
    client.ask("hello", schema=RESPONSE_SCHEMA, temperature=0.7)
    assert captured["payload"]["format"] == RESPONSE_SCHEMA
    assert captured["payload"]["options"]["temperature"] == 0.7


def test_ollama_client_ask_defaults_num_predict_to_default_max_tokens(monkeypatch):
    # Regression for the crash where hybrid-reasoning models (qwen3.x,
    # glm-4.7-flash, gpt-oss) exhausted a too-small shared token budget
    # entirely inside their hidden `thinking` phase and shipped an empty
    # `response`. 1200 was too small on real hardware; nothing should
    # pass that literal value anymore.
    client = OllamaClient(model="llama3", host="http://x")
    captured = {}

    def fake_post(url, json, timeout):
        captured["payload"] = json
        return FakeResponse({"response": "ok"})

    monkeypatch.setattr(client.session, "post", fake_post)
    client.ask("hello")
    assert captured["payload"]["options"]["num_predict"] == DEFAULT_MAX_TOKENS
    assert DEFAULT_MAX_TOKENS > 1200


def test_ollama_client_ask_explicit_max_tokens_overrides_default(monkeypatch):
    client = OllamaClient(model="llama3", host="http://x")
    captured = {}

    def fake_post(url, json, timeout):
        captured["payload"] = json
        return FakeResponse({"response": "ok"})

    monkeypatch.setattr(client.session, "post", fake_post)
    client.ask("hello", max_tokens=42)
    assert captured["payload"]["options"]["num_predict"] == 42


def test_ollama_client_ask_raises_actionable_error_when_thinking_starves_budget(monkeypatch):
    # Reproduces the exact shape of Ollama's response for a hybrid-
    # reasoning model that ran out of `num_predict` budget mid-thought:
    # `response` is empty, `done_reason` is "length", and `thinking` is
    # non-empty. This must be distinguished from a plain empty response
    # so the error tells the operator what actually happened.
    client = OllamaClient(model="llama3", host="http://x")

    def fake_post(url, json, timeout):
        return FakeResponse(
            {
                "response": "",
                "thinking": "Let me reconsider... actually let me reconsider again...",
                "done_reason": "length",
            }
        )

    monkeypatch.setattr(client.session, "post", fake_post)
    with pytest.raises(LLMResponseError, match="thinking"):
        client.ask("hello")


def test_ollama_client_ask_plain_empty_response_does_not_raise(monkeypatch):
    # A model that simply returns nothing at all (no `thinking` field
    # either) must still surface as a plain empty string -- that's
    # extract_json's job to reject, not ask()'s.
    client = OllamaClient(model="llama3", host="http://x")

    def fake_post(url, json, timeout):
        return FakeResponse({"response": ""})

    monkeypatch.setattr(client.session, "post", fake_post)
    assert client.ask("hello") == ""


def test_ollama_client_ask_falls_back_to_thinking_when_response_empty_and_done(monkeypatch):
    # Confirmed empirically against glm-4.7-flash and qwen3.5:27b on real
    # production prompts: the model finishes cleanly (done_reason "stop",
    # well under the token budget) but writes its whole answer into
    # `thinking` and leaves `response` empty. This is NOT the starved-
    # budget case (that's done_reason "length", tested above) -- here the
    # model is done, and `thinking` is the only place its answer landed.
    client = OllamaClient(model="llama3", host="http://x")

    def fake_post(url, json, timeout):
        return FakeResponse(
            {"response": "", "thinking": '{"summary": "ok"}', "done_reason": "stop"}
        )

    monkeypatch.setattr(client.session, "post", fake_post)
    assert client.ask("hello") == '{"summary": "ok"}'


# --------------------------------------------------------------------------
# RESPONSE_SCHEMA narrative field length caps
# --------------------------------------------------------------------------

def test_response_schema_reasoning_has_max_length():
    # Regression for the mechanism where a non-thinking model (gemma4)
    # degenerated into repeated tokens inside the unbounded `reasoning`
    # string under grammar-constrained decoding, consuming the whole
    # token budget before the JSON object could close.
    assert RESPONSE_SCHEMA["properties"]["reasoning"]["maxLength"] > 0


@pytest.mark.parametrize("field", ["reasoning", "summary", "root_cause", "likely_bug_type"])
def test_response_schema_narrative_fields_are_bounded(field):
    assert "maxLength" in RESPONSE_SCHEMA["properties"][field]


# --------------------------------------------------------------------------
# build_prompt
# --------------------------------------------------------------------------

def test_build_prompt_minimal():
    triage_data = {
        "total_crashes": 0,
        "unique_crash_frames": 0,
        "triage_mode": "empty",
        "groups": {},
    }
    prompt = build_prompt(triage_data)
    assert "Total crashes: 0" in prompt
    assert "Top crash group" not in prompt


def test_build_prompt_includes_guardrails():
    prompt = build_prompt({"groups": {}})
    assert "writing a defect report for the developer" in prompt
    assert "Answer ONLY from the numbered evidence below" in prompt
    assert "`insufficient_evidence` and `unknown` are correct answers" in prompt
    assert "Never describe steps to exploit it" in prompt
    assert "Put your reasoning in the `reasoning` field first" in prompt
    assert "Respond with JSON only, matching the provided schema." in prompt


def test_build_prompt_includes_top_group_and_binary_and_source():
    triage_data = {
        "total_crashes": 3,
        "unique_crash_frames": 1,
        "triage_mode": "direct",
        "groups": {"SIGSEGV": {"count": 3, "crashes": [{"file": "c1", "size": 42}]}},
    }
    binary_analysis = {
        "exploit_mitigation_summary": {"protection_level": "Low", "exploit_difficulty": "Easy"},
        "aslr_system": {"enabled": True},
        "nx_bit": {"enabled": False},
        "pie": {"enabled": False},
        "stack_canaries": {"enabled": False},
        "relro": {"status": "No RELRO"},
    }
    prompt = build_prompt(triage_data, source_code="int main(){}", binary_analysis=binary_analysis)
    assert "Top crash group: SIGSEGV" in prompt
    assert "Sample crash size: 42 bytes" in prompt
    assert "protection_level=Low" in prompt
    assert "NX=False" in prompt
    assert "int main(){}" in prompt


def test_build_prompt_includes_structured_crash_record_evidence():
    prompt = build_prompt(_triage_data_with_sanitizer_record())
    assert "[E1] sanitizer: AddressSanitizer" in prompt
    assert "[E2] bug_class: heap-buffer-overflow" in prompt
    assert "[E3] access_type: write, access_size: 8" in prompt
    assert "[E4] fault_addr: 0xdeadbeef" in prompt
    assert "[E5] crash frame #0: in vuln at vuln.c:9" in prompt
    assert "[E6] crash frame #1: in main at vuln.c:20" in prompt
    assert "[E7] alloc frame #0: in malloc" in prompt
    assert "[E8] raw sanitizer report: provided verbatim below (truncated)" in prompt


def test_build_prompt_states_ground_truth_precedence_for_bug_class():
    prompt = build_prompt(_triage_data_with_sanitizer_record())
    assert "Ground truth: [E2]'s bug_class comes from the sanitizer itself" in prompt


def test_build_prompt_caps_raw_sanitizer_report():
    prompt = build_prompt(_triage_data_with_sanitizer_record())
    assert "line 24" in prompt
    assert "line 25" not in prompt


def test_build_prompt_includes_severity_assessment_evidence():
    severity_assessment = {
        "difficulty": "Medium",
        "confidence": 0.62,
        "rationale": "heap-buffer-overflow (write) -- corrupts heap metadata",
    }
    prompt = build_prompt(
        _triage_data_with_sanitizer_record(), severity_assessment=severity_assessment
    )
    assert "severity.py: difficulty=Medium, confidence=0.62" in prompt
    assert (
        "severity.py rationale: heap-buffer-overflow (write) -- corrupts heap metadata" in prompt
    )


def test_build_prompt_omits_severity_evidence_when_not_supplied():
    prompt = build_prompt(_triage_data_with_sanitizer_record())
    assert "severity.py:" not in prompt


def test_build_prompt_includes_crash_state_evidence():
    crash_state = {
        "signal": "SIGSEGV",
        "pc": "0x4011bb",
        "pc_symbol": "parse+37",
        "faulting_instruction": "ret",
        "return_address": "0x4141414141414141",
        "frame_pointer": "0x4141414141414141",
        "primitives": ["return-address-overwrite"],
    }
    prompt = build_prompt(_triage_data_with_sanitizer_record(), crash_state=crash_state)
    assert "crash signal: SIGSEGV" in prompt
    assert "faulting instruction: ret at parse+37" in prompt
    assert "crash-state return_address: 0x4141414141414141" in prompt
    assert "exploitation primitive observed in crashed process: return-address-overwrite" in prompt


def test_build_prompt_omits_crash_state_evidence_when_not_supplied():
    prompt = build_prompt(_triage_data_with_sanitizer_record())
    assert "crash signal:" not in prompt
    assert "exploitation primitive observed" not in prompt


def test_build_prompt_includes_disassembly_when_given():
    prompt = build_prompt(
        _triage_data_with_sanitizer_record(), disassembly="0x401196: mov eax, [rbp-0x8]"
    )
    assert "disassembly: provided verbatim below" in prompt
    assert "0x401196: mov eax, [rbp-0x8]" in prompt


def test_build_prompt_omits_disassembly_section_when_not_given():
    prompt = build_prompt(_triage_data_with_sanitizer_record())
    assert "disassembly: provided verbatim below" not in prompt


def test_build_prompt_no_crash_record_when_group_has_none():
    triage_data = {
        "total_crashes": 3,
        "unique_crash_frames": 1,
        "triage_mode": "direct",
        "groups": {"SIGSEGV": {"count": 3, "crashes": [{"file": "c1", "size": 42}]}},
    }
    prompt = build_prompt(triage_data)
    assert "bug_class:" not in prompt
    assert "Ground truth:" not in prompt


# --------------------------------------------------------------------------
# _evidence_completeness
# --------------------------------------------------------------------------

def test_evidence_completeness_zero_with_nothing():
    assert _evidence_completeness(None, None, None) == 0.0


def test_evidence_completeness_sanitizer_record_only():
    record = {
        "bug_class": "heap-buffer-overflow",
        "crash_stack": [],
        "alloc_stack": [],
        "free_stack": [],
    }
    assert _evidence_completeness(record, None, None) == pytest.approx(0.35)


def test_evidence_completeness_symbolized_frame_bonus():
    record = {
        "bug_class": "heap-buffer-overflow",
        "crash_stack": [{"func": "vuln", "file": "vuln.c"}],
        "alloc_stack": [],
        "free_stack": [],
    }
    assert _evidence_completeness(record, None, None) == pytest.approx(0.55)


def test_evidence_completeness_uaf_heap_timeline_bonus():
    record = {
        "bug_class": "heap-use-after-free",
        "crash_stack": [],
        "alloc_stack": [{"func": "malloc", "file": None}],
        "free_stack": [],
    }
    assert _evidence_completeness(record, None, None) == pytest.approx(0.5)


def test_evidence_completeness_source_and_disassembly_bonus():
    assert _evidence_completeness(None, "int main(){}", "mov eax, ebx") == pytest.approx(0.3)


def test_evidence_completeness_caps_at_one():
    record = {
        "bug_class": "heap-use-after-free",
        "crash_stack": [{"func": "vuln", "file": "vuln.c"}],
        "alloc_stack": [{"func": "malloc", "file": "alloc.c"}],
        "free_stack": [{"func": "free_it", "file": "alloc.c"}],
    }
    assert _evidence_completeness(record, "int main(){}", "mov eax, ebx") == 1.0


# --------------------------------------------------------------------------
# validate_response
# --------------------------------------------------------------------------

def test_validate_response_accepts_full_response():
    validate_response(dict(FULL_RESPONSE))


def test_validate_response_rejects_missing_reasoning():
    incomplete = {k: v for k, v in FULL_RESPONSE.items() if k != "reasoning"}
    with pytest.raises(LLMResponseError, match="reasoning"):
        validate_response(incomplete)


def test_validate_response_rejects_missing_unknowns():
    incomplete = {k: v for k, v in FULL_RESPONSE.items() if k != "unknowns"}
    with pytest.raises(LLMResponseError, match="unknowns"):
        validate_response(incomplete)


def test_validate_response_rejects_confidence_field_not_required():
    # confidence is computed, never asked of the model -- its presence or
    # absence in the raw response must not affect validation either way.
    with_confidence = dict(FULL_RESPONSE)
    with_confidence["confidence"] = 0.9
    validate_response(with_confidence)


def test_validate_response_rejects_bad_exploitability_class():
    bad = dict(FULL_RESPONSE)
    bad["exploitability_class"] = "definitely_exploitable"
    with pytest.raises(LLMResponseError, match="exploitability_class"):
        validate_response(bad)


def test_validate_response_rejects_empty_evidence_list():
    bad = dict(FULL_RESPONSE)
    bad["summary_evidence"] = []
    with pytest.raises(LLMResponseError, match="summary_evidence"):
        validate_response(bad)


def test_validate_response_rejects_evidence_not_a_list():
    bad = dict(FULL_RESPONSE)
    bad["root_cause_evidence"] = "E2"
    with pytest.raises(LLMResponseError, match="root_cause_evidence"):
        validate_response(bad)


def test_validate_response_rejects_capped_list_over_limit():
    bad = dict(FULL_RESPONSE)
    bad["fix_ideas"] = ["a", "b", "c", "d", "e"]
    with pytest.raises(LLMResponseError, match="fix_ideas"):
        validate_response(bad)


def test_validate_response_rejects_placeholder_summary():
    bad = dict(FULL_RESPONSE)
    bad["summary"] = "short label"
    with pytest.raises(LLMResponseError, match="summary"):
        validate_response(bad)


def test_validate_response_allows_unknown_likely_bug_type_as_abstention():
    response = dict(FULL_RESPONSE)
    response["likely_bug_type"] = "unknown"
    validate_response(response)


# --------------------------------------------------------------------------
# analyze()
# --------------------------------------------------------------------------

class FakeClient:
    model = "fake-model"

    def __init__(self, response_text):
        self.response_text = response_text
        self.calls = []

    def ask(self, prompt, **kwargs):
        self.calls.append((prompt, kwargs))
        return self.response_text


def test_analyze_returns_parsed_result_with_metadata_and_confidence():
    client = FakeClient(json.dumps(FULL_RESPONSE))
    result = analyze(client, _triage_data_with_sanitizer_record())
    assert result["summary"] == FULL_RESPONSE["summary"]
    assert result["model_used"] == "fake-model"
    assert "timestamp" in result
    assert 0.0 <= result["confidence"] <= 1.0
    assert set(result["confidence_breakdown"]) == {
        "confidence",
        "agreement_score",
        "validator_penalty",
        "evidence_completeness",
        "rejections",
        "warnings",
    }


def test_analyze_passes_schema_and_temperature_zero_to_client():
    client = FakeClient(json.dumps(FULL_RESPONSE))
    analyze(client, _triage_data_with_sanitizer_record())
    _prompt, kwargs = client.calls[0]
    assert kwargs["schema"] is RESPONSE_SCHEMA
    assert kwargs["temperature"] == 0.0


class SequenceClient:
    model = "fake-model"

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def ask(self, prompt, **kwargs):
        self.calls.append((prompt, kwargs))
        return self.responses.pop(0)


def test_analyze_retries_once_on_bad_json_then_succeeds():
    client = SequenceClient(["not json at all", json.dumps(FULL_RESPONSE)])
    result = analyze(client, _triage_data_with_sanitizer_record())
    assert len(client.calls) == 2
    assert "first attempt was rejected and retried" in result["confidence_breakdown"]["warnings"][0]
    assert result["summary"] == FULL_RESPONSE["summary"]


def test_analyze_retry_prompt_includes_validation_error():
    client = SequenceClient(["not json at all", json.dumps(FULL_RESPONSE)])
    analyze(client, _triage_data_with_sanitizer_record())
    retry_prompt, _kwargs = client.calls[1]
    assert "Your previous response was rejected" in retry_prompt


def test_analyze_raises_after_two_failed_attempts():
    client = SequenceClient(["not json", "still not json"])
    with pytest.raises(LLMResponseError, match="after one retry"):
        analyze(client, _triage_data_with_sanitizer_record())
    assert len(client.calls) == 2


@pytest.mark.parametrize(
    "bug_class,family",
    [
        ("memory-leak", "memory-leak"),
        ("use-of-uninitialized-value", "uninitialized"),
        ("data-race", "data-race"),
    ],
)
def test_new_sanitizer_bug_classes_have_families(bug_class, family):
    assert _bug_class_family(bug_class) == family


@pytest.mark.parametrize(
    "text,family",
    [
        ("this is a memory leak", "memory-leak"),
        ("use of uninitialized value", "uninitialized"),
        ("a data race between threads", "data-race"),
    ],
)
def test_new_sanitizer_bug_type_keywords_normalize(text, family):
    assert _normalize_bug_type_family(text) == family


def test_analyze_substitutes_contradicted_bug_class():
    contradicting = dict(FULL_RESPONSE)
    contradicting["likely_bug_type"] = "stack-buffer-overflow"
    client = FakeClient(json.dumps(contradicting))
    result = analyze(client, _triage_data_with_sanitizer_record())
    assert result["likely_bug_type"] == "heap-buffer-overflow"
    assert any("contradicts" in item for item in result["confidence_breakdown"]["rejections"])


def test_analyze_drops_fabricated_evidence_citation():
    fabricated = dict(FULL_RESPONSE)
    fabricated["root_cause_evidence"] = ["E2", "E99"]
    client = FakeClient(json.dumps(fabricated))
    result = analyze(client, _triage_data_with_sanitizer_record())
    assert result["root_cause_evidence"] == ["E2"]
    rejections = result["confidence_breakdown"]["rejections"]
    assert any("unknown evidence id" in item for item in rejections)


def test_analyze_redacts_weaponized_fix_idea():
    weaponized = dict(FULL_RESPONSE)
    weaponized["fix_ideas"] = ["patch the bounds check", "use pwntools p64(0xdeadbeef) to pivot"]
    client = FakeClient(json.dumps(weaponized))
    result = analyze(client, _triage_data_with_sanitizer_record())
    assert result["fix_ideas"] == ["patch the bounds check"]
    assert any("redacted" in item for item in result["confidence_breakdown"]["warnings"])


def test_analyze_low_confidence_without_sanitizer_record():
    client = FakeClient(json.dumps(FULL_RESPONSE))
    triage_data = {
        "total_crashes": 1,
        "unique_crash_frames": 1,
        "triage_mode": "direct",
        "groups": {"SIGSEGV": {"count": 1, "crashes": [{"file": "c1", "size": 10}]}},
    }
    result = analyze(client, triage_data)
    assert result["confidence_breakdown"]["evidence_completeness"] == 0.0
    assert result["confidence"] == 0.0
