"""Optional local-LLM write-up of a triage run, via Ollama.

Design brief: the project methodology and the project methodology -- "LLM proposes, deterministic checker disposes." The model is never
trusted to author its own confidence, never trusted to cite evidence it
didn't actually see, and never trusted to contradict ground truth we already
parsed (`sanitizers.py`'s `bug_class`).

`build_prompt` mints a stable `[E#]` ID for every fact it injects (sanitizer
record fields, crash/alloc/free stack frames, the fused `severity.py`
assessment, the `binary_analysis.py` mitigation summary, and pointers to any
supplied source/disassembly) so every claim the model makes can be checked
with `set.issubset()` instead of trusted on faith. `analyze` asks Ollama for
a schema-constrained, temperature-0 response (`OllamaClient.ask(...,
schema=...)`), retries once with the validation error folded into the
prompt on failure, then runs the result through a small deterministic
validator stack (bug-class contradiction, evidence-ID validity,
exploitability ceiling, function-name grounding, mitigation-fact
contradiction, a weaponization filter) before computing a `confidence`
value itself -- the model is never asked for one. Verbalized confidence is
the worst-calibrated signal in the literature (research/06 §3.1, AUROC as
low as 0.42); `agreement_score * validator_penalty * evidence_completeness`
gives an honest, observable number instead. `agreement_score` defaults to
`1.0` (neutral) unless a caller opts into self-consistency sampling via
`analyze(..., self_consistency=True)` -- off by default because it costs
~5x local inference time (research/06 §3.2, §7c).
"""

import json
import re
from collections import Counter
from datetime import datetime, timezone

import requests

from .config import DEFAULT_HOST

SANITIZER_RAW_LINE_CAP = 25

EXPLOITABILITY_CLASSES = (
    "insufficient_evidence",
    "memory_safety_violation_no_primitive_shown",
    "read_primitive_indicated",
    "write_primitive_indicated",
    "control_flow_influence_indicated",
)

MAX_LIST_ITEMS = 4

SELF_CONSISTENCY_SAMPLES = 5
SELF_CONSISTENCY_TEMPERATURE = 0.7

REQUIRED_RESPONSE_FIELDS = (
    "reasoning",
    "summary",
    "summary_evidence",
    "likely_bug_type",
    "likely_bug_type_evidence",
    "root_cause",
    "root_cause_evidence",
    "exploitability_class",
    "exploitability_evidence",
    "fix_ideas",
    "next_checks",
    "what_would_confirm",
    "unknowns",
)

EVIDENCE_LIST_FIELDS = (
    "summary_evidence",
    "likely_bug_type_evidence",
    "root_cause_evidence",
    "exploitability_evidence",
)

CAPPED_LIST_FIELDS = ("fix_ideas", "next_checks", "what_would_confirm", "unknowns")

_PLACEHOLDER_STRINGS = {"", "short label", "0.0", "n/a", "todo", "tbd", "..."}


def _evidence_id_array(min_items=1):
    schema = {
        "type": "array",
        "items": {"type": "string", "pattern": "^E[0-9]{1,3}$"},
        "description": "IDs from the numbered evidence list, e.g. [\"E2\", \"E7\"].",
    }
    if min_items:
        schema["minItems"] = min_items
    return schema


def _capped_string_array(description):
    return {
        "type": "array",
        "items": {"type": "string"},
        "maxItems": MAX_LIST_ITEMS,
        "description": description,
    }


RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "reasoning": {
            "type": "string",
            # Ollama 0.20.2's schema-constrained decoder hard-fails --
            # `500 {"error":"failed to load model vocabulary required for
            # format"}` -- for ANY string maxLength >= 2048, reproducibly
            # across every model this project has installed (confirmed by
            # binary search: 2000 -> 200 OK, 2048 -> 500, on gpt-oss:20b,
            # glm-4.7-flash, and gemma4:26b alike). This is model-agnostic --
            # a limitation of this Ollama version's grammar/vocab compiler,
            # not of any one model -- so keep every maxLength in this schema
            # comfortably under that threshold. Do not raise this back
            # toward 2048 without re-checking that ceiling still holds.
            "maxLength": 1800,
            "description": (
                "Think here first, before any other field. Begin by restating, by ID, the "
                "exact evidence lines you are relying on."
            ),
        },
        "summary": {
            "type": "string",
            "maxLength": 600,
            "description": "2-3 sentence plain-language summary.",
        },
        "summary_evidence": _evidence_id_array(),
        "likely_bug_type": {
            "type": "string",
            "maxLength": 100,
            "description": "Short label, or 'unknown' if the evidence does not support one.",
        },
        "likely_bug_type_evidence": _evidence_id_array(),
        "root_cause": {
            "type": "string",
            "maxLength": 1200,
            "description": "Why this is probably happening.",
        },
        "root_cause_evidence": _evidence_id_array(),
        "exploitability_class": {
            "type": "string",
            "enum": list(EXPLOITABILITY_CLASSES),
            "description": "A reachability of a primitive, never a verdict.",
        },
        "exploitability_evidence": _evidence_id_array(),
        "fix_ideas": _capped_string_array("Concrete patch ideas, at most 4."),
        "next_checks": _capped_string_array("Follow-up checks a human should run, at most 4."),
        "what_would_confirm": _capped_string_array(
            "Specific evidence that would raise or lower confidence, at most 4."
        ),
        "unknowns": _capped_string_array(
            "What you could NOT determine from the evidence. Listing something here is a "
            "correct answer, not a failure."
        ),
    },
    "required": list(REQUIRED_RESPONSE_FIELDS),
}

BUG_CLASS_FAMILY = {
    "stack-buffer-overflow": "stack-overflow",
    "heap-buffer-overflow": "heap-overflow",
    "heap-use-after-free": "use-after-free",
    "double-free": "double-free",
    "bad-free": "bad-free",
    "array-index-out-of-bounds": "array-oob",
    "SEGV": "segv",
    "null-pointer-dereference": "null-deref",
    "division-by-zero": "divide-by-zero",
    "misaligned-pointer": "misaligned",
    "shift-out-of-bounds": "shift-oob",
    "signed-integer-overflow": "integer-overflow",
    "unsigned-integer-overflow": "integer-overflow",
    "undefined-behavior": "ub",
    "memory-leak": "memory-leak",
    "use-of-uninitialized-value": "uninitialized",
    "data-race": "data-race",
}

_BUG_TYPE_FAMILY_KEYWORDS = (
    ("double-free", ("double-free", "double free", "doublefree")),
    ("bad-free", ("invalid free", "bad-free", "bad free", "free of invalid", "wild free")),
    ("use-after-free", ("use-after-free", "use after free", "uaf")),
    (
        "heap-overflow",
        ("heap-buffer-overflow", "heap buffer overflow", "heap overflow", "heap-overflow"),
    ),
    (
        "stack-overflow",
        ("stack-buffer-overflow", "stack buffer overflow", "stack overflow", "stack-overflow"),
    ),
    (
        "array-oob",
        ("array-index-out-of-bounds", "index out of bounds", "array out of bounds"),
    ),
    ("integer-overflow", ("integer overflow", "integer-overflow")),
    ("null-deref", ("null pointer", "null-pointer", "nullptr", "null deref")),
    ("divide-by-zero", ("division by zero", "divide by zero", "division-by-zero")),
    ("misaligned", ("misaligned",)),
    ("shift-oob", ("shift exponent", "shift amount", "shift-out-of-bounds")),
    ("segv", ("segv", "segmentation fault", "seg fault")),
    ("memory-leak", ("memory leak", "memory-leak", "leaked memory")),
    ("uninitialized", ("uninitialized", "uninitialised", "use of uninitialized")),
    ("data-race", ("data race", "data-race", "race condition")),
)

_WEAPONIZATION_PATTERNS = (
    re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}"),
    re.compile(r"%n"),
    re.compile(r"pwntools", re.IGNORECASE),
    re.compile(r"ropgadget", re.IGNORECASE),
    re.compile(r"\bp64\("),
    re.compile(r"\bp32\("),
    re.compile(r"msfvenom", re.IGNORECASE),
    re.compile(r"shellcraft", re.IGNORECASE),
    re.compile(r"[A-Za-z0-9+/]{80,}={0,2}"),
)

_NARRATIVE_TEXT_FIELDS = ("reasoning", "summary", "root_cause")
_NARRATIVE_LIST_FIELDS = ("fix_ideas", "next_checks", "what_would_confirm", "unknowns")

# Validator #3 (research/06 §7b): narrative fields checked for grounding.
# Deliberately narrower than _NARRATIVE_TEXT_FIELDS -- `reasoning` is
# excluded because the prompt explicitly instructs the model to restate
# evidence lines there verbatim (e.g. "E7 free frame #0: in release_conn"),
# which would otherwise be double-counted as an ungrounded claim.
_FUNCTION_GROUNDING_FIELDS = ("summary", "root_cause")

# A token is only treated as a probable function name when it's used in
# call syntax (`name(`) -- plain English prose is full of capitalized and
# camelCase-looking words that are not function names, and requiring call
# syntax is a cheap, high-precision filter for the common false-positive
# shape research/06 §7b flags for this validator.
_FUNCTION_CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{2,})\s*\(")

# Control-flow keywords and operators that look like calls (`if (`, `for
# (`, `sizeof(`) but are never function names.
_FUNCTION_CALL_EXCLUDED_KEYWORDS = frozenset(
    {"if", "for", "while", "switch", "sizeof", "return", "else", "catch", "assert", "defined"}
)

# Extremely common libc/POSIX functions a model can reasonably reference
# generically (e.g. "malloc" as a class of function) without having been
# handed them as evidence -- never flagged even when not in any stack,
# source, or disassembly we supplied. Conceptually the same rough set
# `vendored_ignore_lists.py` treats as noise for stack-frame filtering,
# though that module serves a different purpose (dedup bucketing) and is
# not imported here.
_COMMON_LIBC_FUNCTION_ALLOWLIST = frozenset(
    {
        "malloc", "calloc", "realloc", "free", "memalign", "posix_memalign",
        "memcpy", "memmove", "memset", "memcmp",
        "strcpy", "strncpy", "strcat", "strncat", "strcmp", "strncmp",
        "strlen", "strdup", "strchr", "strrchr", "strstr", "strtok",
        "read", "write", "open", "close", "fopen", "fclose", "fread", "fwrite",
        "printf", "sprintf", "snprintf", "fprintf", "vprintf", "scanf", "sscanf",
        "exit", "abort", "raise", "kill", "main",
        "new", "delete",
        "recv", "send", "socket", "accept", "connect", "bind", "listen",
        "mmap", "munmap", "brk", "sbrk",
    }
)

# Validator #5 (research/06 §7b): assertion phrases about a mitigation's
# ABSENCE. Anchored to natural-language claim shapes ("no X", "X disabled",
# "without X") rather than bare keyword co-occurrence, so a sentence merely
# mentioning the mitigation's name isn't treated as an assertion about its
# state.
_MITIGATION_ABSENT_PATTERNS = {
    "stack canary": re.compile(
        r"\bno\s+(?:stack\s+)?(?:canary|cookie)\b"
        r"|\b(?:lacks?|missing)\s+(?:a\s+)?(?:stack\s+)?(?:canary|cookie)\b"
        r"|\bwithout\s+a\s+(?:stack\s+)?(?:canary|cookie)\b"
        r"|\b(?:stack\s+)?(?:canary|cookie)\s+(?:is\s+)?"
        r"(?:disabled|absent|missing|not\s+(?:present|enabled))\b",
        re.IGNORECASE,
    ),
    "NX": re.compile(
        r"\bno\s+nx\b|\bnx\s+(?:bit\s+)?(?:is\s+)?disabled\b|\bwithout\s+nx\b"
        r"|\bstack\s+is\s+executable\b|\bexecutable\s+stack\b",
        re.IGNORECASE,
    ),
    "PIE": re.compile(
        r"\bno\s+pie\b|\bnot\s+(?:built\s+as\s+)?pie\b|\bpie\s+(?:is\s+)?disabled\b"
        r"|\bnon[- ]pie\b|\bwithout\s+pie\b",
        re.IGNORECASE,
    ),
    "ASLR": re.compile(
        r"\bno\s+aslr\b|\baslr\s+(?:is\s+)?disabled\b|\bwithout\s+aslr\b",
        re.IGNORECASE,
    ),
    "RELRO": re.compile(
        r"\bno\s+relro\b|\brelro\s+(?:is\s+)?disabled\b|\bwithout\s+relro\b",
        re.IGNORECASE,
    ),
}

# Validator #5: assertion phrases about a mitigation's PRESENCE.
_MITIGATION_PRESENT_PATTERNS = {
    "stack canary": re.compile(
        r"\b(?:stack\s+)?(?:canary|cookie)\s+(?:is\s+)?(?:enabled|present|in\s+place)\b"
        r"|\bprotected\s+by\s+a\s+(?:stack\s+)?(?:canary|cookie)\b"
        r"|\b(?:with|has)\s+a\s+(?:stack\s+)?(?:canary|cookie)\b",
        re.IGNORECASE,
    ),
    "NX": re.compile(
        r"\bnx\s+(?:bit\s+)?(?:is\s+)?enabled\b|\bwith\s+nx\b|\bnon[- ]executable\s+stack\b",
        re.IGNORECASE,
    ),
    "PIE": re.compile(
        r"\bpie\s+(?:is\s+)?enabled\b|\bbuilt\s+as\s+pie\b|\bwith\s+pie\b",
        re.IGNORECASE,
    ),
    "ASLR": re.compile(
        r"\baslr\s+(?:is\s+)?enabled\b|\bwith\s+aslr\b",
        re.IGNORECASE,
    ),
    "RELRO": re.compile(
        r"\b(?:full|partial)\s+relro\b|\brelro\s+(?:is\s+)?enabled\b|\bwith\s+relro\b",
        re.IGNORECASE,
    ),
}

# Hedged/hypothetical phrasing ("even with a canary present, ...") states a
# scenario, not a claim about the real binary -- a match preceded closely
# by one of these is not a contradiction, per research/06 §7b's own
# worked example.
_MITIGATION_HEDGE_RE = re.compile(
    r"\b(even|despite|regardless\s+of|although|though|hypothetically|suppose)\b",
    re.IGNORECASE,
)
_MITIGATION_HEDGE_WINDOW = 40

RETRY_INSTRUCTION_TEMPLATE = (
    "\n\nYour previous response was rejected for this reason: {error}\n"
    "Respond again with corrected JSON that strictly matches the schema. Return JSON only, "
    "no prose outside the object."
)


class LLMResponseError(RuntimeError):
    """Raised when the model didn't return something we could parse and trust."""


# Sentinel distinguishing "caller didn't pass timeout" (use self.timeout)
# from "caller explicitly passed timeout=None" (no timeout, on purpose).
_UNSET = object()

# `num_predict` on Ollama's `/api/generate` is ONE shared token budget --
# for hybrid-reasoning models (qwen3.x, glm-4.7-flash, gpt-oss, and others)
# it pays for the entire hidden `thinking` phase *and* the final answer.
# 1200 was sized for the answer alone; against real models it was
# routinely exhausted mid-thought, so `done_reason` came back "length"
# and `response` shipped empty -- "model response was empty" was a
# starved budget, not a broken model. Confirmed empirically (research/06
# follow-up) against every thinking-capable model this project has
# installed. Generous by design: unused budget costs nothing but a
# slightly higher worst-case latency, which is a fine trade against a
# guaranteed-empty response.
DEFAULT_MAX_TOKENS = 8192


class OllamaClient:
    def __init__(self, model, host=DEFAULT_HOST, timeout=None):
        if not model:
            raise ValueError("OllamaClient requires a model name")
        self.model = model
        self.host = host.rstrip("/")
        self.session = requests.Session()
        # `None` means "wait as long as it takes" -- there's no good
        # universal default here. A cold model load or CPU-only inference
        # can legitimately take far longer than a typical GPU box, and a
        # hard cap just turns "slow" into "silently skipped". See
        # config.resolve_timeout() for how callers pick this.
        self.timeout = timeout

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

    def ask(
        self, prompt, max_tokens=DEFAULT_MAX_TOKENS, timeout=_UNSET, schema=None, temperature=None
    ):
        """POST a prompt to `/api/generate`. When `schema` is given, it is
        passed as Ollama's `format` parameter for grammar-constrained
        decoding. If `temperature` was left at its default (`None`), the
        request temperature is forced to 0, per Ollama's own guidance for
        the canonical, deterministic answer. An explicitly supplied
        `temperature` is honored even with `schema` set -- schema-
        constrained decoding guarantees JSON *shape*, not determinism, and
        self-consistency sampling (research/06 §3.2) needs schema-
        constrained, temperature>0 samples at the same time.

        `timeout` defaults to the client's own `self.timeout` (see
        `OllamaClient.__init__`); pass it explicitly here to override that
        for a single call, including `None` for "no timeout".

        `max_tokens` defaults to `DEFAULT_MAX_TOKENS`, sized to cover a
        full hidden `thinking` phase plus the final answer (see that
        constant's comment) -- override it only if you know the model in
        play has no reasoning phase and want a tighter budget.
        """
        if timeout is _UNSET:
            timeout = self.timeout
        options = {
            "num_predict": max_tokens,
            "temperature": 0.1 if temperature is None else temperature,
            "top_p": 0.9,
        }
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": options,
        }
        if schema is not None:
            payload["format"] = schema
            if temperature is None:
                payload["options"]["temperature"] = 0.0

        try:
            response = self.session.post(
                f"{self.host}/api/generate", json=payload, timeout=timeout
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            # `check()` only proves Ollama is reachable, not that it will
            # answer within `timeout` (e.g. a cold model load can pass the
            # preflight and still time out here). Surface this as the same
            # `LLMResponseError` callers already handle instead of letting
            # a raw `requests` exception crash the whole CLI.
            raise LLMResponseError(f"Ollama request failed: {exc}") from exc

        data = response.json()
        text = (data.get("response") or "").strip()
        if not text:
            thinking = (data.get("thinking") or "").strip()
            if thinking and data.get("done_reason") == "length":
                # Hybrid-reasoning models (see DEFAULT_MAX_TOKENS above) put
                # their chain-of-thought in a separate `thinking` field.
                # Getting here with done_reason "length" means the model
                # was still inside that phase when `num_predict` ran out --
                # there's no telling whether `thinking` holds a finished
                # answer, so fail loudly instead of guessing.
                raise LLMResponseError(
                    "model exhausted its token budget "
                    f"(max_tokens={max_tokens}) inside its internal "
                    "`thinking` phase and never produced a response -- "
                    "raise max_tokens"
                )
            if thinking:
                # Confirmed empirically (research/06 follow-up) against
                # glm-4.7-flash and qwen3.5: these models can finish
                # generation cleanly -- done_reason "stop", well under
                # the token budget -- while writing their entire answer
                # into `thinking` and leaving `response` empty. Ollama
                # never promised `response` is where the answer ends up
                # for hybrid-reasoning models; treat `thinking` as the
                # candidate answer and let extract_json() try to parse
                # it, same as it would `response`.
                return thinking
        return text


class EvidenceLedger:
    """Mints stable `[E#]` IDs for facts injected into the prompt, in the
    order they're added, so citations can later be checked with plain
    `set.issubset()` (research/06 §4.3).
    """

    def __init__(self):
        self._entries = []

    def add(self, text):
        eid = f"E{len(self._entries) + 1}"
        self._entries.append((eid, text))
        return eid

    def lines(self):
        return [f"[{eid}] {text}" for eid, text in self._entries]

    def ids(self):
        return {eid for eid, _text in self._entries}


def extract_json(text):
    """Parse a model response as JSON. Tries a direct parse first (the
    expected shape under schema-constrained decoding), then falls back to
    brace-scraping recovery -- a defensive fallback, not a load-bearing
    path, since `format=` is not guaranteed unbreakable (research/06 §2.5).
    """
    text = (text or "").strip()
    if not text:
        raise LLMResponseError("model response was empty")

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise LLMResponseError("model response did not contain a JSON object")

    try:
        return json.loads(text[start : end + 1])
    except json.JSONDecodeError as exc:
        raise LLMResponseError(f"model response was not valid JSON: {exc}") from exc


def validate_response(parsed):
    """Shape/placeholder validation only -- the semantic checks (bug-class
    contradiction, evidence-ID validity, exploitability ceiling,
    weaponization) live in `_apply_validators` and run after this passes.
    Raising here is what drives the one-retry escalation ladder in
    `_get_validated_response`.
    """
    if not isinstance(parsed, dict):
        raise LLMResponseError("model response was not a JSON object")

    missing = [field for field in REQUIRED_RESPONSE_FIELDS if field not in parsed]
    if missing:
        raise LLMResponseError(
            "model response is missing required field(s): " + ", ".join(missing)
        )

    if parsed.get("exploitability_class") not in EXPLOITABILITY_CLASSES:
        raise LLMResponseError(
            "field `exploitability_class` must be one of: " + ", ".join(EXPLOITABILITY_CLASSES)
        )

    for field in EVIDENCE_LIST_FIELDS:
        value = parsed.get(field)
        if not isinstance(value, list) or not value:
            raise LLMResponseError(f"field `{field}` must be a non-empty list of evidence IDs")

    for field in CAPPED_LIST_FIELDS:
        value = parsed.get(field)
        if not isinstance(value, list):
            raise LLMResponseError(f"field `{field}` must be a list")
        if len(value) > MAX_LIST_ITEMS:
            raise LLMResponseError(f"field `{field}` exceeds the {MAX_LIST_ITEMS}-item cap")
        if value and all(isinstance(item, str) and not item.strip() for item in value):
            raise LLMResponseError(f"field `{field}` is degenerate (only empty strings)")

    for field in ("reasoning", "summary", "likely_bug_type", "root_cause"):
        value = parsed.get(field)
        if not isinstance(value, str) or value.strip().lower() in _PLACEHOLDER_STRINGS:
            raise LLMResponseError(f"field `{field}` looks empty or like placeholder text")


def _bug_class_family(bug_class):
    return BUG_CLASS_FAMILY.get(bug_class)


def _normalize_bug_type_family(text):
    if not text:
        return None
    lowered = text.lower()
    for family, keywords in _BUG_TYPE_FAMILY_KEYWORDS:
        if any(keyword in lowered for keyword in keywords):
            return family
    return None


def _contains_weaponized_content(text):
    return bool(text) and any(pattern.search(text) for pattern in _WEAPONIZATION_PATTERNS)


def _format_frame(frame):
    location = None
    if frame.get("file") and frame.get("line") is not None:
        location = f"{frame['file']}:{frame['line']}"
    elif frame.get("file"):
        location = frame["file"]

    func = frame.get("func")
    if func and location:
        return f"in {func} at {location}"
    if func:
        return f"in {func}"
    if location:
        return f"at {location}"
    return frame.get("addr") or "unknown"


def _is_symbolized_non_libc_frame(frame):
    # A frame we could resolve to a function name AND a source file is
    # almost never a bare libc/interceptor frame -- those consistently
    # come through `sanitizers.py` with `file` left as None. Cheap proxy,
    # good enough for a completeness score; not a noise-frame classifier.
    return bool(frame.get("func")) and bool(frame.get("file"))


def _find_representative_crash_record(triage_data):
    groups = triage_data.get("groups", {})
    first_group = next(iter(groups.items()), None)
    if not first_group:
        return None, None

    _label, data = first_group
    for crash in data.get("crashes", []):
        record = crash.get("sanitizer")
        if record:
            return data, record
    return data, None


def _mint_crash_record_evidence(ledger, crash_record):
    """Mint one evidence ID per crash-record fact/frame; returns the ID
    minted for `bug_class`, so the prompt can point at it explicitly when
    stating ground-truth precedence.
    """
    ledger.add(f"sanitizer: {crash_record.get('sanitizer', 'unknown')}")
    bug_class_id = ledger.add(f"bug_class: {crash_record.get('bug_class', 'unknown')}")
    ledger.add(
        f"access_type: {crash_record.get('access_type', 'unknown')}, "
        f"access_size: {crash_record.get('access_size', 'unknown')}"
    )

    fault_addr = crash_record.get("fault_addr")
    if fault_addr:
        ledger.add(f"fault_addr: {fault_addr}")

    for name, key in (("crash", "crash_stack"), ("free", "free_stack"), ("alloc", "alloc_stack")):
        for frame in crash_record.get(key) or []:
            ledger.add(f"{name} frame #{frame.get('frame', 0)}: {_format_frame(frame)}")

    if crash_record.get("sanitizer_raw"):
        ledger.add("raw sanitizer report: provided verbatim below (truncated)")

    return bug_class_id


def _mint_binary_analysis_evidence(ledger, binary_analysis):
    summary = binary_analysis.get("exploit_mitigation_summary", {}) or {}
    ledger.add(
        "mitigation: "
        f"NX={(binary_analysis.get('nx_bit') or {}).get('enabled', 'Unknown')}, "
        f"PIE={(binary_analysis.get('pie') or {}).get('enabled', 'Unknown')}, "
        f"ASLR={(binary_analysis.get('aslr_system') or {}).get('enabled', 'Unknown')}, "
        f"canary={(binary_analysis.get('stack_canaries') or {}).get('enabled', 'Unknown')}, "
        f"RELRO={(binary_analysis.get('relro') or {}).get('status', 'Unknown')}"
    )
    ledger.add(
        f"mitigation summary: protection_level={summary.get('protection_level', 'Unknown')}, "
        f"exploit_difficulty={summary.get('exploit_difficulty', 'Unknown')}"
    )


def _mint_severity_evidence(ledger, severity_assessment):
    ledger.add(
        f"severity.py: difficulty={severity_assessment.get('difficulty', 'unknown')}, "
        f"confidence={severity_assessment.get('confidence', 'unknown')}"
    )
    rationale = severity_assessment.get("rationale")
    if rationale:
        ledger.add(f"severity.py rationale: {rationale}")


def _evidence_completeness(crash_record, source_code, disassembly):
    """Deterministic, computed BEFORE the LLM call, from what AutoFTE
    actually has (research/06 §7c): a bare SEGV with a libc-only stack can
    never yield a high confidence, no matter how sure the model sounds.
    """
    score = 0.0
    if crash_record:
        score += 0.35
        crash_stack = crash_record.get("crash_stack") or []
        if any(_is_symbolized_non_libc_frame(frame) for frame in crash_stack):
            score += 0.2
        bug_class = crash_record.get("bug_class")
        if bug_class in ("heap-use-after-free", "double-free") and (
            crash_record.get("alloc_stack") or crash_record.get("free_stack")
        ):
            score += 0.15
    if source_code:
        score += 0.2
    if disassembly:
        score += 0.1
    return min(score, 1.0)


def _mint_crash_state_evidence(ledger, crash_state):
    if crash_state.get("signal"):
        ledger.add(f"crash signal: {crash_state['signal']}")
    if crash_state.get("faulting_instruction"):
        location = crash_state.get("pc_symbol") or crash_state.get("pc") or "unknown"
        ledger.add(
            f"faulting instruction: {crash_state['faulting_instruction']} at {location}"
        )
    for key in ("pc", "return_address", "frame_pointer"):
        if crash_state.get(key):
            ledger.add(f"crash-state {key}: {crash_state[key]}")
    for primitive in crash_state.get("primitives") or []:
        ledger.add(f"exploitation primitive observed in crashed process: {primitive}")


def _assemble_prompt(
    triage_data,
    source_code=None,
    binary_analysis=None,
    severity_assessment=None,
    disassembly=None,
    crash_state=None,
):
    ledger = EvidenceLedger()
    groups = triage_data.get("groups", {})
    first_group = next(iter(groups.items()), None)

    lines = [
        "You are writing a defect report for the developer who has to fix this crash. "
        "Output patch guidance and diagnostic next steps. Do not output exploit code, "
        "payloads, shellcode, ROP chains, heap-grooming sequences, or crafted inputs.",
        "Answer ONLY from the numbered evidence below. Every claim must cite the evidence "
        "IDs it rests on. If the evidence does not support a claim, do not make it -- put "
        "it in `unknowns` instead.",
        "`insufficient_evidence` and `unknown` are correct answers when the evidence is "
        "thin. Listing something in `unknowns` is a sign of good analysis, not a failure. "
        "You will not be penalized for it.",
        "Describe attacker capability only as a primitive that the evidence directly shows "
        "(e.g. '4-byte out-of-bounds read of adjacent heap data'). Never describe steps to "
        "exploit it and never state that something is exploitable -- give a qualified, "
        "evidence-scoped assessment, the same way you would skeptically read the "
        "`exploitable` GDB plugin's output.",
        "Put your reasoning in the `reasoning` field first, before any other field, and "
        "begin it by restating -- by ID -- the exact evidence lines you are relying on.",
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

    _group_data, crash_record = _find_representative_crash_record(triage_data)

    bug_class_id = None
    if crash_record:
        bug_class_id = _mint_crash_record_evidence(ledger, crash_record)
    if binary_analysis:
        _mint_binary_analysis_evidence(ledger, binary_analysis)
    if crash_state:
        _mint_crash_state_evidence(ledger, crash_state)
    if severity_assessment:
        _mint_severity_evidence(ledger, severity_assessment)
    if source_code:
        ledger.add("source code: provided verbatim below")
    if disassembly:
        ledger.add("disassembly: provided verbatim below")

    lines.extend(["", "Numbered evidence (everything you may draw on -- cite by ID):"])
    lines.extend(ledger.lines())

    if bug_class_id:
        lines.append(
            f"Ground truth: [{bug_class_id}]'s bug_class comes from the sanitizer itself, "
            "not from analysis. It is not a hypothesis -- if your reasoning disagrees with "
            "it, your reasoning is wrong. Never state a likely_bug_type that contradicts it."
        )

    if crash_record and crash_record.get("sanitizer_raw"):
        raw_lines = crash_record["sanitizer_raw"].splitlines()[:SANITIZER_RAW_LINE_CAP]
        lines.extend(["", "Raw sanitizer report referenced above (truncated):"])
        lines.extend(raw_lines)

    if source_code:
        lines.extend(["", "Source code referenced above:", source_code])

    if disassembly:
        lines.extend(["", "Disassembly around the faulting instruction, referenced above:"])
        lines.append(disassembly)

    lines.extend(
        [
            "",
            "Respond with JSON only, matching the provided schema.",
        ]
    )

    return "\n".join(lines), ledger


def build_prompt(
    triage_data,
    source_code=None,
    binary_analysis=None,
    severity_assessment=None,
    disassembly=None,
    crash_state=None,
):
    prompt, _ledger = _assemble_prompt(
        triage_data,
        source_code,
        binary_analysis,
        severity_assessment,
        disassembly,
        crash_state,
    )
    return prompt


def _reject_bug_class_contradiction(parsed, crash_record, rejections):
    """Validator #1 (research/06 §7b, the one to keep if only one lands):
    if the sanitizer's `bug_class` maps to a known bug family and the
    model's `likely_bug_type` maps to a different one, reject the field
    and substitute the parser's ground-truth value verbatim.
    """
    if not crash_record:
        return
    ground_truth = crash_record.get("bug_class")
    ground_family = _bug_class_family(ground_truth)
    if not ground_family:
        return

    stated = parsed.get("likely_bug_type")
    stated_family = _normalize_bug_type_family(stated)
    if stated_family and stated_family != ground_family:
        rejections.append(
            f"likely_bug_type '{stated}' contradicts the sanitizer's ground-truth bug_class "
            f"'{ground_truth}' -- substituted the parser's value"
        )
        parsed["likely_bug_type"] = ground_truth


def _reject_invalid_evidence_ids(parsed, valid_ids, rejections):
    """Validator #2: every cited evidence ID must be in the minted set."""
    for evidence_field in EVIDENCE_LIST_FIELDS:
        cited = parsed.get(evidence_field) or []
        kept = [eid for eid in cited if eid in valid_ids]
        dropped = [eid for eid in cited if eid not in valid_ids]
        if dropped:
            rejections.append(
                f"{evidence_field} cited unknown evidence id(s) {dropped} -- dropped"
            )
        parsed[evidence_field] = kept
        if not kept:
            rejections.append(f"{evidence_field} has no valid citation left")


def _clamp_exploitability(parsed, crash_record, rejections):
    """Validator #4: clamp claims down, never up (research/06 §7b). No
    crash record at all means the model has nothing to characterize from;
    a stated read cannot be a write primitive; a use-after-free/double-free
    control-flow claim needs a heap timeline (alloc/free stack) to back it.
    """
    stated = parsed.get("exploitability_class")

    if crash_record is None:
        if stated != "insufficient_evidence":
            rejections.append(
                "exploitability_class was claimed with no sanitizer crash record present -- "
                "clamped to insufficient_evidence"
            )
            parsed["exploitability_class"] = "insufficient_evidence"
        return

    if crash_record.get("access_type") == "read" and stated == "write_primitive_indicated":
        rejections.append(
            "exploitability_class 'write_primitive_indicated' contradicts a read-only access "
            "-- clamped to read_primitive_indicated"
        )
        parsed["exploitability_class"] = "read_primitive_indicated"
        stated = parsed["exploitability_class"]

    bug_family = _bug_class_family(crash_record.get("bug_class"))
    has_heap_timeline = bool(crash_record.get("alloc_stack")) or bool(
        crash_record.get("free_stack")
    )
    if (
        stated == "control_flow_influence_indicated"
        and bug_family in ("use-after-free", "double-free")
        and not has_heap_timeline
    ):
        rejections.append(
            "exploitability_class 'control_flow_influence_indicated' was claimed for a "
            "use-after-free/double-free with no alloc/free stack to confirm the heap "
            "timeline -- clamped to memory_safety_violation_no_primitive_shown"
        )
        parsed["exploitability_class"] = "memory_safety_violation_no_primitive_shown"


_MITIGATION_LABEL_TO_KEY = {
    "stack canary": "stack_canaries",
    "NX": "nx_bit",
    "PIE": "pie",
    "ASLR": "aslr_system",
    "RELRO": "relro",
}


def _grounded_function_names(crash_record, source_code, disassembly):
    names = set(_COMMON_LIBC_FUNCTION_ALLOWLIST)
    if crash_record:
        for key in ("crash_stack", "alloc_stack", "free_stack"):
            for frame in crash_record.get(key) or []:
                func = frame.get("func")
                if func:
                    names.add(func)
    for blob in (source_code, disassembly):
        if blob:
            names.update(_FUNCTION_CALL_RE.findall(blob))
    return names


def _warn_ungrounded_function_names(parsed, crash_record, source_code, disassembly, warnings):
    """Validator #3 (research/06 §7b): flag call-shaped identifiers in the
    model's free-text narrative that aren't grounded in any evidence it was
    actually given. `warn`, never `reject` -- prose is full of
    identifier-shaped words (control-flow keywords, `sizeof(...)`) that
    aren't fabricated function names, and a false positive here is a real
    cost the research doc explicitly flags.
    """
    grounded = _grounded_function_names(crash_record, source_code, disassembly)
    ungrounded = set()
    for field in ("summary", "root_cause"):
        text = parsed.get(field)
        if not isinstance(text, str):
            continue
        for name in _FUNCTION_CALL_RE.findall(text):
            if name in _FUNCTION_CALL_EXCLUDED_KEYWORDS or name in grounded:
                continue
            ungrounded.add(name)
    if ungrounded:
        warnings.append(
            "narrative mentions function call(s) not grounded in any supplied evidence: "
            + ", ".join(sorted(ungrounded))
        )


def _relro_ground_truth_present(binary_analysis):
    status = (binary_analysis.get("relro") or {}).get("status")
    if status is None:
        return None
    return status != "No RELRO"


def _mitigation_ground_truth(binary_analysis, key):
    if key == "relro":
        return _relro_ground_truth_present(binary_analysis)
    return (binary_analysis.get(key) or {}).get("enabled")


def _hedged_match(text, match):
    window_start = max(0, match.start() - _MITIGATION_HEDGE_WINDOW)
    return bool(_MITIGATION_HEDGE_RE.search(text[window_start : match.start()]))


def _reject_mitigation_contradictions(parsed, binary_analysis, rejections):
    """Validator #5 (research/06 §7b): the model's narrative must not
    assert a mitigation is present/absent when `binary_analysis` (real,
    already-parsed data) says the opposite. As cheaply and mechanically
    checkable as validator #1's bug-class contradiction. Hedged/
    hypothetical phrasing ("even without a canary...") within
    `_MITIGATION_HEDGE_WINDOW` characters before the match is not treated
    as a claim about the real binary.
    """
    if not binary_analysis:
        return
    text = " ".join(
        str(parsed.get(field, "")) for field in ("reasoning", "summary", "root_cause")
    )
    for label, key in _MITIGATION_LABEL_TO_KEY.items():
        real_present = _mitigation_ground_truth(binary_analysis, key)
        if real_present is None:
            continue
        absent_match = _MITIGATION_ABSENT_PATTERNS[label].search(text)
        present_match = _MITIGATION_PRESENT_PATTERNS[label].search(text)
        claims_absent = bool(absent_match) and not _hedged_match(text, absent_match)
        claims_present = bool(present_match) and not _hedged_match(text, present_match)
        if claims_absent and not claims_present and real_present:
            rejections.append(
                f"narrative claims {label} is disabled/absent but binary_analysis shows it "
                "is present"
            )
        elif claims_present and not claims_absent and not real_present:
            rejections.append(
                f"narrative claims {label} is enabled/present but binary_analysis shows it "
                "is absent"
            )


def _redact_weaponized_content(parsed, warnings):
    """Weaponization filter (HARDENING §6.1): drop the offending content,
    keep the rest, note the redaction. Never silently pass it through and
    never discard the whole (otherwise useful) analysis.
    """
    for field in _NARRATIVE_TEXT_FIELDS:
        value = parsed.get(field)
        if isinstance(value, str) and _contains_weaponized_content(value):
            warnings.append(
                f"field `{field}` was redacted -- looked like exploit/payload content"
            )
            parsed[field] = "[redacted: response contained exploit/payload-shaped content]"

    for field in _NARRATIVE_LIST_FIELDS:
        items = parsed.get(field)
        if not isinstance(items, list):
            continue
        cleaned = [
            item
            for item in items
            if not (isinstance(item, str) and _contains_weaponized_content(item))
        ]
        if len(cleaned) != len(items):
            warnings.append(
                f"field `{field}` had one or more items redacted -- exploit/payload-shaped "
                "content"
            )
            parsed[field] = cleaned


def _apply_validators(
    parsed, crash_record, valid_ids, completeness, binary_analysis=None,
    source_code=None, disassembly=None, agreement_score=1.0,
):
    """Run the full deterministic validator suite (research/06 §7b, all
    six: bug-class contradiction, evidence-ID validity, exploitability
    ceiling, function-name grounding, mitigation-fact contradiction, the
    weaponization filter) and compute the honest confidence value
    (research/06 §7c): `confidence = agreement_score * validator_penalty *
    evidence_completeness`. `agreement_score` defaults to `1.0` (neutral)
    unless the caller opted into self-consistency sampling.
    """
    rejections = []
    warnings = []

    _reject_bug_class_contradiction(parsed, crash_record, rejections)
    _reject_invalid_evidence_ids(parsed, valid_ids, rejections)
    _clamp_exploitability(parsed, crash_record, rejections)
    _warn_ungrounded_function_names(parsed, crash_record, source_code, disassembly, warnings)
    _reject_mitigation_contradictions(parsed, binary_analysis, rejections)
    _redact_weaponized_content(parsed, warnings)

    validator_penalty = max((0.5 ** len(rejections)) * (0.85 ** len(warnings)), 0.1)
    confidence = round(agreement_score * validator_penalty * completeness, 2)

    breakdown = {
        "confidence": confidence,
        "agreement_score": round(agreement_score, 2),
        "validator_penalty": round(validator_penalty, 2),
        "evidence_completeness": round(completeness, 2),
        "rejections": rejections,
        "warnings": warnings,
    }
    return parsed, breakdown


def _get_validated_response(client, prompt):
    """Escalation ladder (research/06 §2.5, simplified per HARDENING Part
    5.4 to two attempts): constrained decode at temperature 0, and on
    failure exactly one retry with the validation error folded into the
    prompt. A second failure is a hard `LLMResponseError` -- never a
    silent partial render.
    """
    raw = client.ask(prompt, schema=RESPONSE_SCHEMA, temperature=0.0)
    try:
        parsed = extract_json(raw)
        validate_response(parsed)
        return parsed, []
    except LLMResponseError as exc:
        retry_prompt = prompt + RETRY_INSTRUCTION_TEMPLATE.format(error=exc)
        raw2 = client.ask(retry_prompt, schema=RESPONSE_SCHEMA, temperature=0.0)
        try:
            parsed = extract_json(raw2)
            validate_response(parsed)
            return parsed, [f"first attempt was rejected and retried: {exc}"]
        except LLMResponseError as exc2:
            raise LLMResponseError(
                f"model output could not be validated after one retry: {exc2}"
            ) from exc2


def _sample_agreement(client, prompt, samples=SELF_CONSISTENCY_SAMPLES):
    """Self-consistency sampling (research/06 §3.2): verbalized confidence
    is the worst-calibrated signal in the literature (AUROC as low as
    0.42); agreement across independently-sampled answers reaches 0.78-
    0.86. Samples `samples` schema-constrained responses at temperature
    `SELF_CONSISTENCY_TEMPERATURE` (the canonical, emitted answer is still
    the separate temperature-0 call in `_get_validated_response` -- this
    only measures how stable the model's own answer is under resampling)
    and returns the mean modal-agreement fraction over `likely_bug_type`
    (family-normalized) and `exploitability_class`. A response that fails
    to parse/validate is simply excluded from that field's tally rather
    than penalized -- instability that manifests as invalid output is
    already captured by the validator/retry machinery elsewhere.
    """
    bug_types, exploitability_classes = [], []
    for _ in range(samples):
        try:
            raw = client.ask(
                prompt, schema=RESPONSE_SCHEMA, temperature=SELF_CONSISTENCY_TEMPERATURE
            )
            parsed = extract_json(raw)
        except LLMResponseError:
            continue
        bug_type = _normalize_bug_type_family(parsed.get("likely_bug_type"))
        if bug_type:
            bug_types.append(bug_type)
        exploitability = parsed.get("exploitability_class")
        if exploitability in EXPLOITABILITY_CLASSES:
            exploitability_classes.append(exploitability)

    fractions = []
    for values in (bug_types, exploitability_classes):
        if values:
            fractions.append(Counter(values).most_common(1)[0][1] / len(values))
    if not fractions:
        return 1.0
    return sum(fractions) / len(fractions)


def analyze(
    client,
    triage_data,
    source_code=None,
    binary_analysis=None,
    severity_assessment=None,
    disassembly=None,
    crash_state=None,
    self_consistency=False,
):
    prompt, ledger = _assemble_prompt(
        triage_data,
        source_code,
        binary_analysis,
        severity_assessment=severity_assessment,
        disassembly=disassembly,
        crash_state=crash_state,
    )
    _group_data, crash_record = _find_representative_crash_record(triage_data)
    completeness = _evidence_completeness(crash_record, source_code, disassembly)

    parsed, retry_warnings = _get_validated_response(client, prompt)
    agreement_score = _sample_agreement(client, prompt) if self_consistency else 1.0

    result, breakdown = _apply_validators(
        parsed, crash_record, ledger.ids(), completeness,
        binary_analysis=binary_analysis, source_code=source_code,
        disassembly=disassembly, agreement_score=agreement_score,
    )
    breakdown["warnings"] = retry_warnings + breakdown["warnings"]

    result["timestamp"] = datetime.now(timezone.utc).isoformat()
    result["model_used"] = client.model
    result["confidence"] = breakdown["confidence"]
    result["confidence_breakdown"] = breakdown
    return result
