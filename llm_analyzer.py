import argparse
import json
import os
import sys
import time
from datetime import datetime

import requests


class OllamaClient:
    def __init__(self, model="codellama:7b-instruct", host="http://localhost:11434"):
        self.model = model
        self.host = host.rstrip("/")
        self.session = requests.Session()

    def check(self):
        try:
            response = self.session.get(f"{self.host}/api/tags", timeout=5)
            response.raise_for_status()
        except Exception as exc:
            return False, f"Ollama is not reachable: {exc}"

        models = [item["name"] for item in response.json().get("models", [])]
        if self.model not in models:
            return False, f"Model {self.model} is not installed"

        return True, "ok"

    def ask(self, prompt, max_tokens=1200):
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
            f"{self.host}/api/generate",
            json=payload,
            timeout=90,
        )
        response.raise_for_status()
        return response.json().get("response", "").strip()


def load_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def load_text(path):
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def extract_json(text):
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1:
        raise ValueError("response did not contain JSON")
    return json.loads(text[start : end + 1])


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
                f"- Canaries: {binary_analysis.get('stack_canaries', {}).get('enabled', 'Unknown')}",
                f"- RELRO: {binary_analysis.get('relro', {}).get('status', 'Unknown')}",
            ]
        )

    if source_code:
        lines.extend(
            [
                "",
                "Source code:",
                source_code,
            ]
        )

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
    parsed["timestamp"] = datetime.now().isoformat()
    parsed["model_used"] = client.model
    return parsed


def main():
    parser = argparse.ArgumentParser(description="Ask Ollama for a short analysis note")
    parser.add_argument("--triage-json", default="crash_triage.json")
    parser.add_argument("--source-file")
    parser.add_argument("--binary-analysis", default="binary_analysis.json")
    parser.add_argument("--output", default="llm_analysis.json")
    parser.add_argument("--model", default="codellama:7b-instruct")
    parser.add_argument("--host", default="http://localhost:11434")
    args = parser.parse_args()

    if not os.path.exists(args.triage_json):
        print(f"Error: triage file not found: {args.triage_json}")
        return 1

    triage_data = load_json(args.triage_json)
    source_code = load_text(args.source_file) if args.source_file and os.path.exists(args.source_file) else None
    binary_analysis = load_json(args.binary_analysis) if os.path.exists(args.binary_analysis) else None

    client = OllamaClient(model=args.model, host=args.host)
    ok, message = client.check()
    if not ok:
        print(message)
        return 1

    start = time.time()
    result = analyze(client, triage_data, source_code, binary_analysis)
    result["analysis_duration_seconds"] = round(time.time() - start, 2)

    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)

    print(f"Wrote {args.output}")
    print(result.get("summary", "No summary returned"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
