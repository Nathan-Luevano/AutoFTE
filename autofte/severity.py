"""Fuse static mitigation posture (`binary_analysis.py`) with a crash's fault
signature (a normalized `sanitizers.py` record) into one honestly-labeled
prioritization signal.

Per the project methodology: "The exploit-difficulty estimate is heuristic,
like `exploitable` (which is widely known to lie a lot). Present it as a
prioritization aid with visible confidence, never a verdict." Every value
this module returns therefore carries an explicit numeric `confidence`
(0.0-1.0, chosen over a low/medium/high enum because the fusion below is
naturally additive/subtractive across several independent signals -- a
float composes and sorts better than three buckets, and downstream ranking
of many crashes wants a total order, not ties) plus a plain-language
`rationale` and two lists of what would move that confidence, so a caller
can never accidentally treat this as a bare, unqualified label.

`binary_analysis.py`'s existing `_summarize_mitigations` already scores
difficulty from mitigation posture alone (protection_count -> Easy/Medium/
Hard). This module does not replace that -- it is the "everyone runs
checksec OR classifies the crash, almost nobody fuses them" gap from
the project methodology 2.3: it starts from that same protection_count and
shifts it, in the same units, by what the crash itself was (bug class,
read vs. write, and -- only as an explicit, disclosed approximation, since
AutoFTE has no real stack-frame-layout analysis -- whether a write during a
stack-buffer-overflow plausibly lands near saved registers/the return
address on that frame).
"""

BUG_CLASS_PROFILES = {
    "stack-buffer-overflow": (
        -1.5,
        "corrupts memory on the same stack frame as saved registers and the return address",
        True,
    ),
    "heap-buffer-overflow": (
        -1.0,
        "corrupts heap metadata or adjacent heap objects -- a real but less direct primitive "
        "than smashing a return address",
        True,
    ),
    "heap-use-after-free": (
        -1.5,
        "hands an attacker a stale, potentially attacker-controlled reallocation -- "
        "historically one of the most reliably exploitable bug classes",
        True,
    ),
    "double-free": (
        -1.5,
        "corrupts heap allocator metadata directly and often chains into an arbitrary write",
        True,
    ),
    "bad-free": (
        -1.0,
        "frees an invalid pointer -- a real heap-corruption primitive, though weaker than a "
        "confirmed double-free",
        True,
    ),
    "array-index-out-of-bounds": (
        -0.5,
        "an out-of-bounds array access whose impact depends entirely on what sits next to it",
        True,
    ),
    "SEGV": (
        0.0,
        "a bare SEGV with no further detail -- could be a benign NULL dereference or a "
        "wild-pointer write, indistinguishable from this report alone",
        False,
    ),
    "use-of-uninitialized-value": (
        0.5,
        "reads uninitialized memory -- can leak stale contents or, if the value reaches a "
        "branch or index, cause attacker-influenced behavior",
        True,
    ),
    "memory-leak": (
        2.5,
        "leaks memory but does not corrupt it -- a resource-exhaustion or availability "
        "issue, not a memory-safety primitive",
        True,
    ),
    "null-pointer-dereference": (
        2.0,
        "the zero page is unmapped and rarely attacker-influenced -- almost always a "
        "crash-only bug",
        True,
    ),
    "division-by-zero": (
        2.0,
        "a logic bug that crashes but does not corrupt memory",
        True,
    ),
    "misaligned-pointer": (
        1.5,
        "a hardware alignment trap, not memory corruption",
        True,
    ),
    "shift-out-of-bounds": (
        1.5,
        "undefined behavior that rarely provides a memory-safety primitive",
        True,
    ),
    "signed-integer-overflow": (
        1.0,
        "only dangerous if the wrapped value later drives a size/index calculation, which "
        "this record does not establish",
        False,
    ),
    "unsigned-integer-overflow": (
        1.0,
        "only dangerous if the wrapped value later drives a size/index calculation, which "
        "this record does not establish",
        False,
    ),
    "undefined-behavior": (
        0.5,
        "an unclassified undefined-behavior report with no specific fault-type signal to fuse",
        False,
    ),
}

DEFAULT_BUG_CLASS_PROFILE = (
    0.0,
    "not a bug class AutoFTE has a severity profile for yet -- treated neutrally",
    False,
)

ACCESS_TYPE_DELTA = {"write": -0.5, "read": 0.5}

EASY_MEDIUM_BOUNDARY = 2.0
MEDIUM_HARD_BOUNDARY = 4.0

MITIGATION_KEYS = ("aslr_system", "nx_bit", "stack_canaries", "pie", "relro")

BASE_CONFIDENCE_NO_CRASH = 0.35
BASE_CONFIDENCE_WITH_CRASH = 0.55
CONFIDENCE_FLOOR = 0.05
CONFIDENCE_CEILING = 0.9

DIRECT_HIJACK_BUG_CLASSES = (
    "stack-buffer-overflow",
    "heap-buffer-overflow",
    "heap-use-after-free",
    "double-free",
    "bad-free",
    "array-index-out-of-bounds",
)


def _clamp(value, low, high):
    return max(low, min(high, value))


def _bug_class_profile(bug_class):
    return BUG_CLASS_PROFILES.get(bug_class, DEFAULT_BUG_CLASS_PROFILE)


def _difficulty_label(score):
    if score < EASY_MEDIUM_BOUNDARY:
        return "Easy"
    if score < MEDIUM_HARD_BOUNDARY:
        return "Medium"
    return "Hard"


def _mitigation_tool_errors(binary_analysis):
    errors = []
    for key in MITIGATION_KEYS:
        section = binary_analysis.get(key) or {}
        error = section.get("error")
        if error:
            errors.append((key, error))
    return errors


def _mitigation_highlights(mitigation_summary):
    techniques = list(mitigation_summary.get("required_techniques") or [])
    vulnerable_areas = list(mitigation_summary.get("vulnerable_areas") or [])
    return techniques, vulnerable_areas


def _pie_aslr_enabled(binary_analysis):
    pie_enabled = bool((binary_analysis.get("pie") or {}).get("enabled"))
    aslr_enabled = bool((binary_analysis.get("aslr_system") or {}).get("enabled"))
    return pie_enabled and aslr_enabled


def _canary_enabled(binary_analysis):
    return bool((binary_analysis.get("stack_canaries") or {}).get("enabled"))


def _crash_fault_fragments(binary_analysis, bug_class, access_type):
    fragments = []

    if bug_class == "stack-buffer-overflow" and access_type == "write":
        fragments.append(
            "a write during a stack-buffer-overflow is approximated -- not confirmed via "
            "precise stack-frame-layout analysis -- as likely to land near saved registers "
            "or the return address on the same frame"
        )
        if _canary_enabled(binary_analysis):
            fragments.append(
                "a stack canary is present, so a naive linear overflow reaching the return "
                "address should be caught before it is used"
            )
        else:
            fragments.append(
                "with no stack canary, an overflow reaching the return address would go "
                "undetected"
            )

    if access_type == "write" and bug_class in DIRECT_HIJACK_BUG_CLASSES:
        if _pie_aslr_enabled(binary_analysis):
            fragments.append(
                "PIE/ASLR is enabled, so an info leak would likely be needed before this "
                "primitive is directly exploitable"
            )
        else:
            fragments.append(
                "with no PIE/fixed code addresses, direct control-flow hijack is plausible "
                "without needing an info leak first"
            )

    return fragments


def _score_crash_record(binary_analysis, crash_record):
    bug_class = crash_record.get("bug_class") or "unknown"
    access_type = crash_record.get("access_type")
    class_delta, class_desc, well_characterized = _bug_class_profile(bug_class)
    access_delta = ACCESS_TYPE_DELTA.get(access_type, 0.0)

    stack_write_bonus = 0.0
    if bug_class == "stack-buffer-overflow" and access_type == "write":
        stack_write_bonus = -1.0

    delta = class_delta + access_delta + stack_write_bonus
    if access_type:
        fault_summary = f"{bug_class} ({access_type}) -- {class_desc}"
    else:
        fault_summary = f"{bug_class} -- {class_desc}"
    fault_fragments = _crash_fault_fragments(binary_analysis, bug_class, access_type)

    confidence = BASE_CONFIDENCE_WITH_CRASH
    would_increase = []
    would_decrease = []

    if access_type is not None:
        confidence += 0.1
    else:
        confidence -= 0.05
        would_decrease.append("Read/write direction is unknown for this fault")
        would_increase.append("Knowing whether the fault was a read or a write")

    if well_characterized:
        confidence += 0.1
    else:
        confidence -= 0.15
        would_decrease.append(f"'{bug_class}' has an ambiguous or logic-only severity profile")
        would_increase.append(
            f"A more specific/well-characterized bug classification than '{bug_class}'"
        )

    crash_stack = crash_record.get("crash_stack") or []
    has_symbolized_frame = any(frame.get("func") for frame in crash_stack)
    if has_symbolized_frame:
        confidence += 0.05
    else:
        would_decrease.append("The crash backtrace has no symbolized (function-level) frames")
        would_increase.append("Symbolized frames (function/file/line) in the crash backtrace")

    if bug_class in ("heap-use-after-free", "double-free"):
        if crash_record.get("alloc_stack") or crash_record.get("free_stack"):
            confidence += 0.1
        else:
            would_decrease.append("No allocation/free call stack to confirm the heap timeline")
            would_increase.append(
                "The allocation/free call stacks for this heap timeline (not present here)"
            )

    would_increase.append(
        "Disassembly or stack-frame-layout data around the fault to confirm proximity to "
        "saved registers/the return address (AutoFTE does not compute this yet)"
    )

    return delta, fault_summary, fault_fragments, confidence, would_increase, would_decrease


def assess_crash_difficulty(binary_analysis, crash_record=None):
    """Fuse `binary_analysis`'s mitigation posture with an optional normalized
    sanitizer `crash_record` (see `sanitizers.py`) into one prioritization
    signal: `{difficulty, confidence, rationale, would_increase_confidence,
    would_decrease_confidence, basis, score}`.

    `crash_record` may be `None` -- a crash with no sanitizer data (a bare
    gdb backtrace or exit-signal grouping) still gets a full, honestly
    lower-confidence assessment from mitigation posture alone, in the exact
    same return shape, so callers never have to branch on which case they
    got. This is a heuristic prioritization aid, like `exploitable` -- never
    a verdict.
    """
    mitigation_summary = binary_analysis.get("exploit_mitigation_summary") or {}
    protection_count = float(mitigation_summary.get("protection_count", 0) or 0)
    techniques, vulnerable_areas = _mitigation_highlights(mitigation_summary)
    tool_errors = _mitigation_tool_errors(binary_analysis)

    score = protection_count
    would_increase = []
    would_decrease = []

    if crash_record is None:
        basis = "mitigation_only"
        confidence = BASE_CONFIDENCE_NO_CRASH
        posture_bits = vulnerable_areas or [
            f"protection level {mitigation_summary.get('protection_level', 'unknown')}"
        ]
        rationale = (
            "No sanitizer crash record is available for this crash, so this is a "
            "mitigation-only prioritization aid, not a fault-aware one: "
            + "; ".join(posture_bits)
            + ". This heuristic, like `exploitable`, should never be read as a definitive "
            "verdict."
        )
        would_decrease.append(
            "No sanitizer crash record was available -- assessed from mitigation posture alone"
        )
        would_increase.append(
            "A normalized sanitizer crash record (bug class, read/write, access size) instead "
            "of mitigation posture alone"
        )
    else:
        basis = "mitigation_and_crash"
        (
            crash_delta,
            fault_summary,
            fault_fragments,
            confidence,
            crash_would_increase,
            crash_would_decrease,
        ) = _score_crash_record(binary_analysis, crash_record)
        score += crash_delta
        would_increase.extend(crash_would_increase)
        would_decrease.extend(crash_would_decrease)

        mitigation_bits = vulnerable_areas or techniques
        mitigation_clause = (
            "; ".join(mitigation_bits)
            if mitigation_bits
            else "mitigation posture could not be determined"
        )
        extra = ""
        if fault_fragments:
            capitalized = [fragment[0].upper() + fragment[1:] for fragment in fault_fragments]
            extra = " " + ". ".join(capitalized) + "."
        rationale = (
            f"{fault_summary}.{extra} Mitigation posture: {mitigation_clause}. This is a "
            "heuristic prioritization aid, not a verdict -- read the difficulty label and "
            "confidence the way you would (skeptically) read `exploitable`'s output."
        )

    for key, error in tool_errors:
        confidence -= 0.05
        would_decrease.append(f"{key} check failed ({error}) -- its true status is unknown")
        would_increase.append(f"A successful {key} check")

    if not would_decrease:
        would_decrease.append(
            "Nothing specific is currently undermining this assessment beyond its inherent "
            "heuristic nature -- it is still not a verdict"
        )

    confidence = round(_clamp(confidence, CONFIDENCE_FLOOR, CONFIDENCE_CEILING), 2)

    return {
        "difficulty": _difficulty_label(score),
        "confidence": confidence,
        "rationale": rationale,
        "would_increase_confidence": would_increase,
        "would_decrease_confidence": would_decrease,
        "basis": basis,
        "score": round(score, 2),
    }
