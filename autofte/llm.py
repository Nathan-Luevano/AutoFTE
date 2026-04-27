"""Optional local-LLM write-up of a triage run, via Ollama."""

import json
from datetime import datetime, timezone

import requests

from .config import DEFAULT_HOST


class LLMResponseError(RuntimeError):
    """Raised when the model didn't return something we could parse."""


class OllamaClient:
    def __init__(self, model, host=DEFAULT_HOST):
        if not model:
            raise ValueError("OllamaClient requires a model name")
        self.model = model
        self.host = host.rstrip("/")
        self.session = requests.Session()

    def check(self):
        try:
            response = self.session.get(f"{self.host}/api/tags", timeout=5)
            response.raise_for_status()
        except requests.RequestException as exc:
            return False, f"Ollama is not reachable at {self.host}: {exc}"

        models = [item["name"] for item in response.json().get("models", [])]
        if self.model not in models:
            return False, f"Model {self.model} is not installed on {self.host}"

        return True, "ok"

    def ask(self, prompt, max_tokens=1200, timeout=90):
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "num_predict": max_tokens,
                "temperature": 0.1,
                "top_p": 0.9,
            },
        }

        response = self.session.post(
            f"{self.host}/api/generate", json=payload, timeout=timeout
        )
        response.raise_for_status()
        return response.json().get("response", "").strip()


def extract_json(text):
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise LLMResponseError("model response did not contain a JSON object")

    try:
        return json.loads(text[start : end + 1])
    except json.JSONDecodeError as exc:
        raise LLMResponseError(f"model response was not valid JSON: {exc}") from exc


def build_prompt(triage_data, source_code=None, binary_analysis=None):
    groups = triage_data.get("groups", {})
    first_group = next(iter(groups.items()), None)

    lines = [
        "You are helping summarize a local fuzzing run.",
        "Keep the answer grounded and practical.",
        "Do not write an exploit or payload.",
        "",
        f"Total crashes: {triage_data.get('total_crashes', 0)}",
        f"Unique groups: {triage_data.get('unique_crash_frames', 0)}",
        f"Triage mode: {triage_data.get('triage_mode', 'unknown')}",
    ]

    if first_group:
        frame, data = first_group
        sample = data.get("crashes", [{}])[0]
        lines.extend(
            [
                f"Top crash group: {frame}",
                f"Group count: {data.get('count', 0)}",
                f"Sample crash size: {sample.get('size', 'unknown')} bytes",
            ]
        )

    if binary_analysis:
        summary = binary_analysis.get("exploit_mitigation_summary", {})
        lines.extend(
            [
                "",
                "Binary protection summary:",
                f"- protection_level: {summary.get('protection_level', 'Unknown')}",
                f"- exploit_difficulty: {summary.get('exploit_difficulty', 'Unknown')}",
                f"- ASLR: {binary_analysis.get('aslr_system', {}).get('enabled', 'Unknown')}",
                f"- NX: {binary_analysis.get('nx_bit', {}).get('enabled', 'Unknown')}",
                f"- PIE: {binary_analysis.get('pie', {}).get('enabled', 'Unknown')}",
                "- Canaries: "
                f"{binary_analysis.get('stack_canaries', {}).get('enabled', 'Unknown')}",
                f"- RELRO: {binary_analysis.get('relro', {}).get('status', 'Unknown')}",
            ]
        )

    if source_code:
        lines.extend(["", "Source code:", source_code])

    lines.extend(
        [
            "",
            "Respond with JSON only using this shape:",
            "{",
            '  "summary": "2-3 sentence run summary",',
            '  "likely_bug_type": "short label",',
            '  "confidence": 0.0,',
            '  "root_cause": "why this is probably happening",',
            '  "next_checks": ["short follow-up check"],',
            '  "fix_ideas": ["concrete patch idea"]',
            "}",
        ]
    )

    return "\n".join(lines)


def analyze(client, triage_data, source_code=None, binary_analysis=None):
    prompt = build_prompt(triage_data, source_code, binary_analysis)
    raw = client.ask(prompt)
    parsed = extract_json(raw)
    parsed["timestamp"] = datetime.now(timezone.utc).isoformat()
    parsed["model_used"] = client.model
    return parsed
