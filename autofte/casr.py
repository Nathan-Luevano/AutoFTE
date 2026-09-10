import json
import platform
from datetime import datetime, timezone
from pathlib import Path

from . import crash_display, dedup, disasm, source_context

SEVERITY_EXPLOITABLE = "EXPLOITABLE"
SEVERITY_PROBABLE = "PROBABLY_EXPLOITABLE"
SEVERITY_NOT = "NOT_EXPLOITABLE"
SEVERITY_UNDEFINED = "UNDEFINED"

_SEVERITY_RANK = {
    SEVERITY_UNDEFINED: 0,
    SEVERITY_NOT: 1,
    SEVERITY_PROBABLE: 2,
    SEVERITY_EXPLOITABLE: 3,
}

_PRIMITIVE_SEVERITY = {
    "instruction-pointer-control": (SEVERITY_EXPLOITABLE, "SegFaultOnPc"),
    "return-address-overwrite": (SEVERITY_EXPLOITABLE, "ReturnAv"),
    "indirect-branch-through-register": (SEVERITY_EXPLOITABLE, "BranchAv"),
    "memory-write": (SEVERITY_PROBABLE, "DestAv"),
    "memory-read": (SEVERITY_NOT, "SourceAv"),
}

_BUG_CLASS_SEVERITY = {
    "heap-buffer-overflow": (SEVERITY_PROBABLE, "HeapBufferOverflow"),
    "stack-buffer-overflow": (SEVERITY_PROBABLE, "StackBufferOverflow"),
    "global-buffer-overflow": (SEVERITY_PROBABLE, "GlobalBufferOverflow"),
    "heap-use-after-free": (SEVERITY_PROBABLE, "HeapUseAfterFree"),
    "double-free": (SEVERITY_PROBABLE, "DoubleFree"),
    "bad-free": (SEVERITY_PROBABLE, "BadFree"),
    "array-index-out-of-bounds": (SEVERITY_PROBABLE, "OutOfBounds"),
    "data-race": (SEVERITY_PROBABLE, "DataRace"),
    "null-pointer-dereference": (SEVERITY_NOT, "SEGVOnNullAddress"),
    "division-by-zero": (SEVERITY_NOT, "FPE"),
    "memory-leak": (SEVERITY_NOT, "MemoryLeak"),
    "use-of-uninitialized-value": (SEVERITY_NOT, "UninitializedValue"),
    "signed-integer-overflow": (SEVERITY_NOT, "SignedIntegerOverflow"),
    "unsigned-integer-overflow": (SEVERITY_NOT, "UnsignedIntegerOverflow"),
    "SEGV": (SEVERITY_NOT, "AccessViolation"),
}

_SIGNAL_SEVERITY = {
    "SIGABRT": (SEVERITY_NOT, "AbortSignal"),
    "SIGFPE": (SEVERITY_NOT, "FPE"),
    "SIGILL": (SEVERITY_PROBABLE, "IllegalInstruction"),
    "SIGBUS": (SEVERITY_NOT, "BusError"),
    "SIGSEGV": (SEVERITY_NOT, "AccessViolation"),
}


def _safe_name(text):
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in text)[:80] or "report"


def _frame_line(frame):
    parts = []
    if frame.get("frame") is not None:
        parts.append(f"#{frame['frame']}")
    addr = frame.get("addr")
    if addr:
        addr = str(addr)
        if not addr.startswith("0x"):
            addr = f"0x{addr}"
        parts.append(addr)
    func = frame.get("func")
    if func:
        parts.append(f"in {func}")
    if frame.get("file") and frame.get("line"):
        parts.append(f"at {frame['file']}:{frame['line']}")
    return " ".join(parts)


def _stacktrace(crash_record, fallback_label):
    frames = (crash_record or {}).get("crash_stack") or []
    lines = [line for line in (_frame_line(frame) for frame in frames) if line]
    if lines:
        return lines
    return [fallback_label] if fallback_label else []


def _fault_frame(crash_record):
    frames = [
        frame
        for frame in (crash_record or {}).get("crash_stack") or []
        if frame.get("func")
    ]
    significant = dedup.significant_frames(frames) or frames
    return significant[0] if significant else None


def _crash_line(crash_record):
    frame = _fault_frame(crash_record)
    if frame and frame.get("file") and frame.get("line"):
        return f"{frame['file']}:{frame['line']}"
    return ""


def _explanation(assessment, crash_state):
    bits = []
    if assessment:
        bits.append(
            f"AutoFTE difficulty {assessment.get('difficulty', 'Unknown')}, "
            f"confidence {assessment.get('confidence', 0):.2f}."
        )
        if assessment.get("rationale"):
            bits.append(str(assessment["rationale"]))
    if crash_state and crash_state.get("rationale"):
        bits.append(str(crash_state["rationale"]))
    bits.append(
        "CASR severity here is a best-effort interop mapping of AutoFTE's evidence, "
        "not an independent verdict."
    )
    return " ".join(bits)


def _severity_block(crash_record, crash_state, assessment, signature):
    sev_type = None
    short = None
    for primitive in (crash_state or {}).get("primitives") or []:
        cand = _PRIMITIVE_SEVERITY.get(primitive)
        if cand and (sev_type is None or _SEVERITY_RANK[cand[0]] > _SEVERITY_RANK[sev_type]):
            sev_type, short = cand

    if sev_type is None:
        cand = _BUG_CLASS_SEVERITY.get((crash_record or {}).get("bug_class"))
        if cand:
            sev_type, short = cand

    if sev_type is None:
        token = signature.split()[0] if signature else ""
        for key in ((crash_state or {}).get("signal"), token):
            cand = _SIGNAL_SEVERITY.get(key)
            if cand:
                sev_type, short = cand
                break

    if sev_type is None:
        sev_type, short = SEVERITY_UNDEFINED, "Undetermined"

    return {
        "Type": sev_type,
        "ShortDescription": short,
        "Description": crash_display.bug_class_label(crash_record) or short,
        "Explanation": _explanation(assessment, crash_state),
    }


def _representative_entry(group_data):
    entries = group_data.get("crashes") or []
    for entry in entries:
        if entry.get("sanitizer"):
            return entry
    return entries[0] if entries else None


def _lines(text):
    if not text:
        return []
    return text.splitlines()


def build_report(ranked_entry, target_binary=None, source_file=None, generated_at=None):
    group_data = ranked_entry["data"]
    signature = ranked_entry["signature"]
    crash_record = ranked_entry["crash_record"]
    crash_state = ranked_entry["crash_state"]
    assessment = ranked_entry["assessment"]

    entry = _representative_entry(group_data)
    crash_path = (entry or {}).get("path")
    executable = target_binary or (entry or {}).get("target") or ""

    cmdline = executable
    if crash_path:
        cmdline = f"{executable} {crash_path}".strip()

    report = {
        "Date": (generated_at or datetime.now(timezone.utc)).isoformat(),
        "Uname": platform.platform(),
        "OS": platform.system(),
        "OSRelease": platform.release(),
        "Architecture": platform.machine(),
        "ExecutablePath": executable,
        "ProcCmdline": cmdline,
        "CrashLine": _crash_line(crash_record),
        "Stacktrace": _stacktrace(crash_record, signature),
        "CrashSeverity": _severity_block(crash_record, crash_state, assessment, signature),
        "Source": [],
        "GroupId": group_data.get("group_id"),
        "GroupSize": group_data.get("count", 0),
    }
    if crash_path:
        report["Stdin"] = crash_path

    registers = (crash_state or {}).get("registers") or {}
    if registers:
        report["Registers"] = dict(registers)

    if crash_state and crash_state.get("faulting_instruction"):
        report["FaultingInstruction"] = crash_state["faulting_instruction"]

    minimized = group_data.get("minimized") or {}
    if minimized.get("output_path"):
        report["MinimizedInput"] = minimized["output_path"]

    if crash_record:
        raw = crash_record.get("sanitizer_raw")
        sanitizer = crash_record.get("sanitizer") or ""
        if raw:
            key = "UbsanReport" if "Undefined" in sanitizer else "AsanReport"
            report[key] = _lines(raw)

    if target_binary and crash_record and disasm.objdump_available():
        disassembly = disasm.disassemble_fault_context(target_binary, crash_record)
        if disassembly:
            report["Disassembly"] = _lines(disassembly)

    if source_file and crash_record:
        context = source_context.extract_context(source_file, crash_record)
        if context:
            report["Source"] = _lines(context)

    return report


def build_reports(triage, binary_data, target_binary=None, source_file=None, generated_at=None):
    ranked = crash_display.ranked_groups(triage.get("groups") or {}, binary_data or {})
    generated_at = generated_at or datetime.now(timezone.utc)
    reports = []
    for ranked_entry in ranked:
        report = build_report(
            ranked_entry,
            target_binary=target_binary,
            source_file=source_file,
            generated_at=generated_at,
        )
        reports.append((ranked_entry["data"].get("group_id") or ranked_entry["signature"], report))
    return reports


def write_reports(triage, binary_data, output_dir, target_binary=None, source_file=None):
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    written = []
    used = set()
    for group_id, report in build_reports(
        triage, binary_data, target_binary=target_binary, source_file=source_file
    ):
        stem = _safe_name(group_id)
        name = stem
        suffix = 2
        while name in used:
            name = f"{stem}-{suffix}"
            suffix += 1
        used.add(name)
        path = out / f"{name}.casrep"
        path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        written.append(str(path))
    return written
