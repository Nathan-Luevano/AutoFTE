import re
from datetime import datetime

from . import crash_display, dedup

_EVIDENCE_CITATION_RE = re.compile(r"\s*\[E\d+(?:,\s*E\d+)*\]")
_MULTI_PERIOD_RE = re.compile(r"\.\s*\.+")

_CONTROL_FLOW_PRIMITIVES = (
    "instruction-pointer-control",
    "return-address-overwrite",
    "indirect-branch-through-register",
)

DEFAULT_TOP_N = 3

_BUG_CLASS_PLAIN = {
    "stack-buffer-overflow": "a write past the end of a stack buffer",
    "heap-buffer-overflow": "a write past the end of a heap allocation",
    "heap-use-after-free": "a use of heap memory after it was freed",
    "double-free": "the same heap pointer freed twice",
    "bad-free": "a free of a pointer the allocator never handed out",
    "array-index-out-of-bounds": "an array access outside its bounds",
    "use-of-uninitialized-value": "a read of memory that was never initialised",
    "memory-leak": "memory that is allocated and never freed",
    "data-race": "two threads touching the same memory without synchronisation",
    "null-pointer-dereference": "a dereference of a NULL pointer",
    "division-by-zero": "an integer division by zero",
    "signed-integer-overflow": "a signed integer arithmetic overflow",
    "unsigned-integer-overflow": "an unsigned integer arithmetic overflow",
    "SEGV": "an invalid memory access with no further detail from the sanitizer",
}

_PRIMITIVE_PLAIN = {
    "instruction-pointer-control": (
        "the instruction pointer already holds an attacker-influenced value -- "
        "control flow has been diverted"
    ),
    "return-address-overwrite": (
        "the fault is on a `ret` whose saved return address is corrupted -- a "
        "control-flow transfer to attacker bytes is the very next step"
    ),
    "indirect-branch-through-register": (
        "the fault is an indirect call/jump through a register that is not a valid "
        "code pointer"
    ),
    "memory-write": (
        "the faulting instruction writes through a pointer that currently lands in "
        "unmapped memory -- a candidate write primitive"
    ),
    "memory-read": (
        "the faulting instruction reads through an invalid pointer -- a wild/NULL "
        "read, crash-only unless the pointer is influenced"
    ),
}


def _top_func(crash_record):
    frames = [f for f in (crash_record or {}).get("crash_stack") or [] if f.get("func")]
    for frame in dedup.significant_frames(frames) or frames:
        return frame["func"]
    return None


def _what_it_is(crash_record, signature):
    if not crash_record:
        return f"Grouped by crash signature `{signature}` (no sanitizer record for this bucket)."
    bug_class = crash_record.get("bug_class") or "unknown"
    plain = _BUG_CLASS_PLAIN.get(bug_class, f"a `{bug_class}` fault")
    func = _top_func(crash_record)
    where = f" in `{func}`" if func else ""
    size = crash_record.get("access_size")
    access = crash_record.get("access_type")
    detail = ""
    if access and size is not None:
        detail = f" ({access}, {size} bytes)"
    elif access:
        detail = f" ({access})"
    return f"AddressSanitizer identifies this as **{bug_class}**{detail} -- {plain}{where}."


def _crash_state_prose(crash_state):
    if not crash_state:
        return None
    parts = []
    signal = crash_state.get("signal")
    insn = crash_state.get("faulting_instruction")
    where = crash_state.get("pc_symbol") or crash_state.get("pc")
    if signal and insn:
        parts.append(f"Under the debugger the process took {signal} on `{insn}`"
                     + (f" at `{where}`" if where else "") + ".")
    elif signal:
        parts.append(f"Under the debugger the process took {signal}.")
    for primitive in crash_state.get("primitives") or []:
        parts.append(_PRIMITIVE_PLAIN.get(primitive, primitive).capitalize() + ".")
    if not crash_state.get("primitives"):
        parts.append("No specific exploitation primitive was visible in the register state.")
    return " ".join(parts)


def _mitigation_prose(binary_data):
    summary = binary_data.get("exploit_mitigation_summary") or {}
    if not summary and not binary_data:
        return "Binary mitigations were not analysed for this run."

    def enabled(key):
        return bool((binary_data.get(key) or {}).get("enabled"))

    bits = []
    bits.append(
        "a stack canary is present, so a naive linear overflow is caught before the return"
        if enabled("stack_canaries")
        else "no stack canary, so a linear overwrite reaches the return address undetected"
    )
    bits.append(
        "PIE is on, so an information leak is needed before code addresses are known"
        if enabled("pie")
        else "no PIE, so code addresses are fixed and no leak is needed to locate a gadget"
    )
    bits.append(
        "NX is enabled, so a payload would have to be ROP/JOP rather than injected shellcode"
        if enabled("nx_bit")
        else "NX is disabled, so injected shellcode could execute directly"
    )
    relro = (binary_data.get("relro") or {}).get("status")
    if relro:
        bits.append(f"RELRO is `{relro}`")
    level = summary.get("protection_level", "Unknown")
    return f"Protection level **{level}**: " + "; ".join(bits) + "."


def _reproduce_prose(data, target_binary, source_file):
    crashes = data.get("crashes") or []
    sample = crashes[0].get("file") if crashes else None
    lines = []
    if sample:
        lines.append(f"Sample input: `{sample}`.")
    minimized = data.get("minimized")
    if minimized:
        lines.append(
            f"Minimized to {minimized['minimized_size']} bytes "
            f"(from {minimized['original_size']}, {minimized['reduction_percent']}% smaller, "
            f"{minimized['tool']})"
            + (f": `{minimized['output_path']}`." if minimized.get("output_path") else ".")
        )
    reproducible = sum(1 for c in crashes if c.get("reproducibility") == "reproducible")
    if crashes and any("reproducibility" in c for c in crashes):
        lines.append(f"Reproduced {reproducible}/{len(crashes)} times on re-run.")
    lines.append(
        f"Re-run: `autofte triage --target-binary {target_binary} "
        f"--crashes-dir <dir>` (source: `{source_file}`)."
    )
    return " ".join(lines)


def _our_read(assessment, crash_state):
    difficulty = assessment["difficulty"]
    confidence = assessment["confidence"]
    primitives = (crash_state or {}).get("primitives") or []
    if any(p in _CONTROL_FLOW_PRIMITIVES for p in primitives):
        verdict = (
            "The crashed process shows a control-flow primitive directly, so this sits at the "
            "top of the queue -- though a primitive is still not a working exploit."
        )
    elif difficulty == "Easy":
        verdict = "The fault type and the thin mitigation posture put this high in the queue."
    elif difficulty == "Hard":
        verdict = (
            "The fault looks crash-only, or well contained by the target's mitigations -- low "
            "priority unless something below changes that read."
        )
    else:
        verdict = "A real memory-safety bug of middling exploitation difficulty."
    caveat = (
        f"AutoFTE rates it **{difficulty}** at confidence {confidence:.2f} "
        f"(basis: {assessment['basis'].replace('_', ' ')}). This is a prioritisation aid, "
        "not a verdict."
    )
    raises = assessment.get("would_increase_confidence") or []
    tail = f" What would sharpen it: {raises[0]}." if raises else ""
    return f"{verdict} {caveat}{tail}"


def _tidy(text):
    text = _EVIDENCE_CITATION_RE.sub("", text or "")
    text = _MULTI_PERIOD_RE.sub(".", text)
    return text.strip()


def _clean_items(items):
    out = []
    for item in items or []:
        if isinstance(item, str) and item.strip(": \t"):
            out.append(_tidy(item).rstrip("."))
    return out


def _sentence(text):
    text = _tidy(text)
    if text and text[-1] not in ".!?":
        text += "."
    return text


def _llm_prose(llm_data):
    if not llm_data or llm_data.get("status") == "skipped":
        return None
    parts = []
    summary = _sentence(llm_data.get("summary"))
    if summary:
        parts.append(summary)
    root_cause = _tidy(llm_data.get("root_cause"))
    if root_cause and root_cause not in summary:
        parts.append(_sentence(f"Root cause: {root_cause}"))
    fixes = _clean_items(llm_data.get("fix_ideas"))
    if fixes:
        parts.append("Fix ideas: " + "; ".join(fixes[:2]) + ".")
    confirm = _clean_items(llm_data.get("what_would_confirm"))
    if confirm:
        parts.append("Would confirm: " + "; ".join(confirm[:2]) + ".")
    return " ".join(parts) or None


def build_brief(target_binary, source_file, triage, binary_data, llm_data, top_n=DEFAULT_TOP_N):
    groups = triage.get("groups", {})
    ranked = crash_display.ranked_groups(groups, binary_data)
    total = triage.get("total_crashes", 0)
    unique = triage.get("unique_crash_frames", len(ranked))
    shown = ranked[:top_n]

    lines = [
        f"# Exploitability brief -- `{target_binary}`",
        "",
        f"_Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} by AutoFTE, entirely offline._",
        "",
    ]

    if not ranked:
        lines.append("No crashing groups were found for this run.")
        return "\n".join(lines) + "\n"

    crash_word = "crash input" if total == 1 else "crash inputs"
    cause_word = "root cause" if unique == 1 else "root causes"
    if len(shown) == 1:
        which = "The single highest-ranked root cause is"
    else:
        which = (
            f"The {len(shown)} ranked highest by the fused "
            "crash-state + fault + mitigation signal are"
        )
    lines.append(
        f"AutoFTE triaged **{total}** {crash_word} into **{unique}** distinct {cause_word}. "
        f"{which} below. Every rating is a prioritisation aid, not a verdict -- read it the "
        "way you would skeptically read the `exploitable` plugin's output."
    )
    lines.append("")

    for index, item in enumerate(shown, start=1):
        assessment = item["assessment"]
        crash_record = item["crash_record"]
        label = crash_display.bug_class_label(crash_record) or item["signature"]
        lines.append(
            f"## {index}. {label} -- {assessment['difficulty']} "
            f"(confidence {assessment['confidence']:.2f}, {item['count']} crash(es))"
        )
        lines.append("")
        lines.append(f"**What it is.** {_what_it_is(crash_record, item['signature'])}")

        state_prose = _crash_state_prose(item["crash_state"])
        if state_prose:
            lines.append(f"**What the crashed process shows.** {state_prose}")

        lines.append(f"**What is in the way.** {_mitigation_prose(binary_data)}")
        lines.append(f"**Our read.** {_our_read(assessment, item['crash_state'])}")
        lines.append(
            f"**Reproduce it.** {_reproduce_prose(item['data'], target_binary, source_file)}"
        )

        if index == 1:
            llm_prose = _llm_prose(llm_data)
            if llm_prose:
                lines.append(f"**Local model notes (top finding).** {llm_prose}")
        lines.append("")

    if unique > len(shown):
        lines.append(
            f"---\n\nThe remaining {unique - len(shown)} root cause(s) are in "
            "`crash_triage.json` and the HTML dashboard."
        )
    return "\n".join(lines) + "\n"
