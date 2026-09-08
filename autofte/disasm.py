import re
import shutil
import subprocess

from . import dedup

DEFAULT_WINDOW = 10
MAX_FUNCTION_LINES = 60

_FUNC_HEADER_RE = re.compile(r"^[0-9a-fA-F]+ <(.+)>:$")
_INSN_LINE_RE = re.compile(r"^\s*([0-9a-fA-F]+):\s+(.+?)\s*$")


def objdump_available():
    return shutil.which("objdump") is not None


def _run_objdump(binary):
    try:
        result = subprocess.run(
            ["objdump", "-d", "-C", "--no-show-raw-insn", str(binary)],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout


def _fault_frame(crash_record):
    frames = [
        frame
        for frame in (crash_record or {}).get("crash_stack") or []
        if frame.get("func")
    ]
    significant = dedup.significant_frames(frames)
    candidates = significant or frames
    return candidates[0] if candidates else None


def fault_function_name(crash_record):
    frame = _fault_frame(crash_record)
    return frame.get("func") if frame else None


def _fault_address(crash_record):
    frame = _fault_frame(crash_record)
    if not frame:
        return None
    addr = frame.get("addr")
    if addr:
        return addr.lower().lstrip("0x") or "0"
    return None


def _is_fault_addr(addr, fault_addr):
    return bool(fault_addr) and addr.lower().lstrip("0") == fault_addr.lstrip("0")


def _function_block(dump_text, func_name):
    lines = dump_text.splitlines()
    block = []
    capturing = False
    for line in lines:
        header = _FUNC_HEADER_RE.match(line)
        if header:
            if capturing:
                break
            capturing = header.group(1) == func_name
            continue
        if capturing:
            if not line.strip():
                break
            block.append(line)
    return block


def _window_around(block, fault_addr, window):
    insn_lines = [line for line in block if _INSN_LINE_RE.match(line)]
    if not insn_lines:
        return []

    center = 0
    if fault_addr is not None:
        for index, line in enumerate(insn_lines):
            match = _INSN_LINE_RE.match(line)
            if match and _is_fault_addr(match.group(1), fault_addr):
                center = index
                break

    start = max(0, center - window)
    end = min(len(insn_lines), center + window + 1)
    selected = insn_lines[start:end]
    return selected[:MAX_FUNCTION_LINES]


def _format(func_name, selected, fault_addr):
    out = [f"Disassembly of {func_name} (objdump), around the faulting instruction:"]
    for line in selected:
        match = _INSN_LINE_RE.match(line)
        addr, insn = match.group(1), match.group(2)
        marker = "  ->" if _is_fault_addr(addr, fault_addr) else "    "
        out.append(f"{marker} {addr}: {insn}")
    return "\n".join(out)


def disassemble_fault_context(binary, crash_record, window=DEFAULT_WINDOW):
    func_name = fault_function_name(crash_record)
    if not func_name or not objdump_available():
        return None

    dump_text = _run_objdump(binary)
    if not dump_text:
        return None

    block = _function_block(dump_text, func_name)
    if not block:
        return None

    fault_addr = _fault_address(crash_record)
    selected = _window_around(block, fault_addr, window)
    if not selected:
        return None

    return _format(func_name, selected, fault_addr)
