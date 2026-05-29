import pytest
import requests

from autofte import config
from autofte.config import (
    DEFAULT_HOST,
    ModelResolutionError,
    list_installed_models,
    resolve_host,
    resolve_model,
)

# --------------------------------------------------------------------------
# resolve_host
# --------------------------------------------------------------------------

def test_resolve_host_explicit_wins(monkeypatch):
    monkeypatch.setenv("OLLAMA_HOST", "http://env-host:1")
    assert resolve_host("http://explicit:2") == "http://explicit:2"


def test_resolve_host_env_var_fallback(monkeypatch):
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    monkeypatch.setenv("OLLAMA_HOST", "http://env-host:1")
    assert resolve_host() == "http://env-host:1"


def test_resolve_host_default(monkeypatch):
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    assert resolve_host() == DEFAULT_HOST


def test_resolve_host_strips_trailing_slash(monkeypatch):
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    assert resolve_host("http://x:1/") == "http://x:1"


# --------------------------------------------------------------------------
# list_installed_models
# --------------------------------------------------------------------------

class FakeResponse:
    def __init__(self, json_data, status_ok=True):
        self._json = json_data
        self._status_ok = status_ok

    def raise_for_status(self):
        if not self._status_ok:
            raise requests.HTTPError("bad status")

    def json(self):
        return self._json


def test_list_installed_models(monkeypatch):
    monkeypatch.setattr(
        config.requests,
        "get",
        lambda url, timeout: FakeResponse({"models": [{"name": "a"}, {"name": "b"}]}),
    )
    assert list_installed_models("http://x") == ["a", "b"]


def test_list_installed_models_raises_on_http_error(monkeypatch):
    monkeypatch.setattr(
        config.requests, "get", lambda url, timeout: FakeResponse({}, status_ok=False)
    )
    with pytest.raises(requests.HTTPError):
        list_installed_models("http://x")


# --------------------------------------------------------------------------
# resolve_model precedence chain
# --------------------------------------------------------------------------

def test_resolve_model_explicit_wins_over_everything(monkeypatch):
    monkeypatch.setenv("AUTOFTE_LLM_MODEL", "env-model")
    assert resolve_model(explicit="explicit-model") == "explicit-model"


def test_resolve_model_env_var_wins_over_autodetect(monkeypatch):
    monkeypatch.setenv("AUTOFTE_LLM_MODEL", "env-model")
    monkeypatch.setattr(
        config, "list_installed_models", lambda host, timeout=5: ["should-not-be-used"]
    )
    assert resolve_model() == "env-model"


def test_resolve_model_autodetect_prefers_coder_model(monkeypatch):
    monkeypatch.delenv("AUTOFTE_LLM_MODEL", raising=False)
    monkeypatch.setattr(
        config,
        "list_installed_models",
        lambda host, timeout=5: ["llama3:8b", "qwen2.5-coder:7b", "mistral"],
    )
    assert resolve_model(host="http://x") == "qwen2.5-coder:7b"


@pytest.mark.parametrize("hint", ["coder", "code", "codestral", "starcoder", "deepseek"])
def test_resolve_model_autodetect_matches_each_hint(monkeypatch, hint):
    monkeypatch.delenv("AUTOFTE_LLM_MODEL", raising=False)
    model_name = f"my-{hint}-model"
    monkeypatch.setattr(
        config, "list_installed_models", lambda host, timeout=5: ["plain-model", model_name]
    )
    assert resolve_model(host="http://x") == model_name


def test_resolve_model_autodetect_falls_back_to_first_installed(monkeypatch):
    monkeypatch.delenv("AUTOFTE_LLM_MODEL", raising=False)
    monkeypatch.setattr(
        config, "list_installed_models", lambda host, timeout=5: ["llama3", "mistral"]
    )
    assert resolve_model(host="http://x") == "llama3"


def test_resolve_model_raises_when_no_models_installed(monkeypatch):
    monkeypatch.delenv("AUTOFTE_LLM_MODEL", raising=False)
    monkeypatch.setattr(config, "list_installed_models", lambda host, timeout=5: [])
    with pytest.raises(ModelResolutionError):
        resolve_model(host="http://x")


def test_resolve_model_raises_when_host_unreachable(monkeypatch):
    monkeypatch.delenv("AUTOFTE_LLM_MODEL", raising=False)

    def fake_list(host, timeout=5):
        raise requests.ConnectionError("refused")

    monkeypatch.setattr(config, "list_installed_models", fake_list)
    with pytest.raises(ModelResolutionError):
        resolve_model(host="http://x")
