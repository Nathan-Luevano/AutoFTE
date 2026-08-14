"""Runtime configuration: mainly Ollama host/model resolution.

There is intentionally no hard-coded default model. Different machines
have different models pulled, so AutoFTE resolves one at runtime instead
of assuming e.g. codellama is installed:

1. an explicit ``--model`` flag, if the caller passed one
2. the ``AUTOFTE_LLM_MODEL`` environment variable
3. auto-detection: ask Ollama what is installed and prefer a model whose
   name looks code-focused (coder/code/codestral/...), otherwise take
   the first one Ollama reports
4. if nothing is installed, raise ModelResolutionError with a message
   that tells the user how to fix it instead of failing deep inside an
   HTTP call
"""

import os

import requests

DEFAULT_HOST = "http://localhost:11434"
_CODE_MODEL_HINTS = ("coder", "code", "codestral", "starcoder", "deepseek")


class ModelResolutionError(RuntimeError):
    """Raised when no usable Ollama model can be determined."""


def resolve_host(explicit=None):
    return (explicit or os.environ.get("OLLAMA_HOST") or DEFAULT_HOST).rstrip("/")


def resolve_timeout(explicit=None):
    """Seconds to wait for a single Ollama `/api/generate` call, or `None`
    for no timeout at all. There is no hard-coded cap by default: a cold
    model load or CPU-only/underpowered hardware can legitimately take far
    longer than a typical GPU box, and a slow answer should just take
    longer rather than get killed part way through. Resolution order:
    explicit ``--llm-timeout``, then ``AUTOFTE_LLM_TIMEOUT``, then
    unbounded. `0` (from either source) also means unbounded, since
    ``requests`` itself treats `timeout=0` as "fail instantly" rather than
    "no timeout" -- a `0` here is far more likely to be someone clearing
    the value than someone asking for that.
    """
    if explicit is not None:
        return explicit or None

    env_timeout = os.environ.get("AUTOFTE_LLM_TIMEOUT")
    if env_timeout:
        return float(env_timeout) or None

    return None


def list_installed_models(host, timeout=5):
    response = requests.get(f"{host}/api/tags", timeout=timeout)
    response.raise_for_status()
    return [item["name"] for item in response.json().get("models", [])]


def resolve_model(explicit=None, host=DEFAULT_HOST):
    """Pick a model name without assuming any particular model exists."""
    if explicit:
        return explicit

    env_model = os.environ.get("AUTOFTE_LLM_MODEL")
    if env_model:
        return env_model

    try:
        installed = list_installed_models(host)
    except requests.RequestException as exc:
        raise ModelResolutionError(
            f"Could not reach Ollama at {host} to auto-detect a model: {exc}\n"
            "Pass --model explicitly, or set AUTOFTE_LLM_MODEL."
        ) from exc

    if not installed:
        raise ModelResolutionError(
            f"No models are installed on the Ollama instance at {host}.\n"
            "Pull one first, e.g. `ollama pull qwen3-coder:30b`, "
            "or pass --model / set AUTOFTE_LLM_MODEL."
        )

    for name in installed:
        if any(hint in name.lower() for hint in _CODE_MODEL_HINTS):
            return name

    return installed[0]
