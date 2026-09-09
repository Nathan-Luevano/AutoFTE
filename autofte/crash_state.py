import re
import shutil
import subprocess

DEFAULT_TIMEOUT_SECONDS = 20
CANONICAL_USERSPACE_MAX = 0x00007FFFFFFFFFFF
MIN_MAPPED_ADDR = 0x1000

_SIGNAL_RE = re.compile(r"Program received signal (SIG[A-Z]+)")
_LABELLED_RE = re.compile(r"^(PC|SP|FP)=(0x[0-9a-fA-F]+)$", re.MULTILINE)
_FAULT_INSN_RE = re.compile(r"^=>\s+0x[0-9a-fA-F]+\s+(?:<([^>]*)>)?:?\s*(.+?)\s*$", re.MULTILINE)
_REG_RE = re.compile(r"^([a-z][a-z0-9]+)\s+(0x[0-9a-fA-F]+)\b", re.MULTILINE)
_RET_FRAME_RE = re.compile(r"^#1\s+(0x[0-9a-fA-F]+)\s+in", re.MULTILINE)
_INDIRECT_BRANCH_RE = re.compile(r"^(call|callq|jmp|jmpq)\s+\*")
_WRITE_TARGET_RE = re.compile(r",\s*[^,]*\([^)]*\)\s*$")
_READ_SOURCE_RE = re.compile(r"\b[^,]*\([^)]*\)\s*,")


def gdb_available(debugger="gdb"):
    return shutil.which(debugger) is not None


def _run_gdb(binary, crash_file, debugger, timeout):
    cmd = [
        debugger,
        "--batch",
        "--quiet",
        "--nx",
        "-ex",
        "set pagination off",
        "-ex",
        "set debuginfod enabled off",
        "-ex",
        f"run {crash_file}",
        "-ex",
        'printf "PC=%#lx\\nSP=%#lx\\nFP=%#lx\\n", $pc, $sp, $rbp',
        "-ex",
        "x/i $pc",
        "-ex",
        "info registers",
        "-ex",
        "bt 3",
        "-ex",
        "quit",
        "--args",
        binary,
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None
    return f"{result.stdout}\n{result.stderr}"


def _parse_int(value):
    try:
        return int(value, 16)
    except (TypeError, ValueError):
        return None


def looks_controlled(address):
    n = _parse_int(address) if isinstance(address, str) else address
    if n is None or n == 0:
        return False
    lo = n & 0xFF
    if lo and all(((n >> (8 * i)) & 0xFF) == lo for i in range(6)):
        return True
    body = [(n >> (8 * i)) & 0xFF for i in range(6)]
    if all(0x20 <= b <= 0x7E for b in body):
        return True
    if n > CANONICAL_USERSPACE_MAX or (0 < n < MIN_MAPPED_ADDR):
        return True
    return False


def parse_gdb_output(text):
    if not text:
        return None
    signal = None
    match = _SIGNAL_RE.search(text)
    if match:
        signal = match.group(1)

    labelled = {k: v for k, v in _LABELLED_RE.findall(text)}
    if "PC" not in labelled:
        return None

    insn_symbol = None
    faulting_instruction = None
    insn_match = _FAULT_INSN_RE.search(text)
    if insn_match:
        insn_symbol = insn_match.group(1) or None
        faulting_instruction = insn_match.group(2).strip()

    registers = {name: value for name, value in _REG_RE.findall(text)}
    ret_match = _RET_FRAME_RE.search(text)

    return {
        "signal": signal,
        "pc": labelled["PC"],
        "sp": labelled.get("SP"),
        "frame_pointer": labelled.get("FP"),
        "pc_symbol": insn_symbol,
        "faulting_instruction": faulting_instruction,
        "return_address": ret_match.group(1) if ret_match else None,
        "registers": registers,
    }


def classify(state):
    if not state:
        return {"primitives": [], "rationale": "No crash state was captured."}

    primitives = []
    notes = []
    pc = state.get("pc")
    insn = (state.get("faulting_instruction") or "").strip()
    return_address = state.get("return_address")
    frame_pointer = state.get("frame_pointer")

    if looks_controlled(pc):
        primitives.append("instruction-pointer-control")
        notes.append(
            f"the instruction pointer is {pc}, which is not a plausible code address -- "
            "control flow has already been diverted to an attacker-influenced value"
        )
    elif insn in ("ret", "retq") and (
        looks_controlled(return_address) or looks_controlled(frame_pointer)
    ):
        primitives.append("return-address-overwrite")
        notes.append(
            "the fault is on a `ret` with a corrupted saved return address / frame pointer -- "
            "a control-flow transfer to an attacker-influenced value is imminent"
        )
    elif _INDIRECT_BRANCH_RE.match(insn):
        primitives.append("indirect-branch-through-register")
        notes.append(
            f"the faulting instruction `{insn}` is an indirect branch through a "
            "register/pointer -- if that operand is attacker-influenced this is a "
            "control-flow hijack primitive"
        )
    elif insn.startswith(("mov", "add", "sub", "and", "or", "xor", "inc", "dec")) and (
        _WRITE_TARGET_RE.search(insn)
    ):
        primitives.append("memory-write")
        notes.append(
            f"the faulting instruction `{insn}` writes through a pointer that currently points "
            "at unmapped memory -- a candidate write primitive if the pointer is influenced"
        )
    elif _READ_SOURCE_RE.search(insn):
        if pc and _parse_int(pc):
            primitives.append("memory-read")
            notes.append(
                f"the faulting instruction `{insn}` reads through an invalid pointer -- "
                "a NULL/wild read (crash-only, or an info-leak primitive if the "
                "pointer is influenced)"
            )

    if not primitives:
        rationale = (
            f"Crashed with {state.get('signal') or 'a fault'} at {pc}"
            + (f" ({state['pc_symbol']})" if state.get("pc_symbol") else "")
            + ". No specific exploitation primitive is evident from the register state alone."
        )
    else:
        rationale = "Crash-state analysis: " + "; ".join(notes) + "."

    return {"primitives": primitives, "rationale": rationale}


def capture(binary, crash_file, debugger="gdb", timeout=DEFAULT_TIMEOUT_SECONDS):
    if not gdb_available(debugger):
        return None
    state = parse_gdb_output(_run_gdb(binary, crash_file, debugger, timeout))
    if state is None:
        return None
    state.update(classify(state))
    return state
