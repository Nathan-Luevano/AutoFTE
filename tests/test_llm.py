
import pytest
import requests

from autofte.llm import (
    LLMResponseError,
    OllamaClient,
    analyze,
    build_prompt,
    extract_json,
)

# --------------------------------------------------------------------------
# extract_json
# --------------------------------------------------------------------------

def test_extract_json_valid():
    text = '{"summary": "hi", "confidence": 0.5}'
    assert extract_json(text) == {"summary": "hi", "confidence": 0.5}


def test_extract_json_embedded_in_prose():
    text = (
        "Sure, here is my answer:\n"
        '{"summary": "buffer overflow", "confidence": 0.8}\n'
        "Hope that helps!"
    )
    result = extract_json(text)
    assert result["summary"] == "buffer overflow"


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
    # rfind('}') before find('{') should be treated as invalid
    with pytest.raises(LLMResponseError):
        extract_json("} some text {")


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
    assert "protection_level: Low" in prompt
    assert "int main(){}" in prompt
    assert "Respond with JSON only" in prompt


# --------------------------------------------------------------------------
# analyze()
# --------------------------------------------------------------------------

class FakeClient:
    model = "fake-model"

    def __init__(self, response_text):
        self.response_text = response_text

    def ask(self, prompt, **kwargs):
        return self.response_text


def test_analyze_returns_parsed_result_with_metadata():
    client = FakeClient('{"summary": "looks like a stack overflow", "confidence": 0.9}')
    result = analyze(client, {"groups": {}})
    assert result["summary"] == "looks like a stack overflow"
    assert result["model_used"] == "fake-model"
    assert "timestamp" in result


def test_analyze_raises_on_bad_model_response():
    client = FakeClient("not json at all")
    with pytest.raises(LLMResponseError):
        analyze(client, {"groups": {}})
