"""Parse AddressSanitizer / UndefinedBehaviorSanitizer reports into a
normalized crash record.

A sanitizer-instrumented target that crashes on a fuzzer input prints a
structured report to stderr instead of (or in addition to) just raising a
signal. That report is far richer than a gdb backtrace -- it names the bug
class, whether the fault was a read or write, the access size, the faulting
address, and (for heap bugs) the allocation and free call stacks. This
module turns that text into a single normalized dict so the rest of the
pipeline (triage, dedup, severity, the LLM prompt) can consume one shape
regardless of which sanitizer produced it.

Matches the rest of the codebase's convention of returning plain dicts from
structured-data functions (see `triage_crashes` in `triage.py` and
`analyze_binary` in `binary_analysis.py`) rather than introducing a
dataclass. The normalized record has this shape:

    {
        "sanitizer": "AddressSanitizer" | "UndefinedBehaviorSanitizer",
        "bug_class": str,               # e.g. "heap-buffer-overflow",
                                         # "stack-buffer-overflow",
                                         # "heap-use-after-free",
                                         # "double-free", "SEGV",
                                         # "signed-integer-overflow", ...
        "access_type": "read" | "write" | None,
        "access_size": int | None,
        "fault_addr": str | None,       # "0x..." or None
        "crash_stack": [frame, ...],    # where the fault happened
        "alloc_stack": [frame, ...],    # where the object was allocated,
                                         # [] if not applicable/available
        "free_stack": [frame, ...],     # where the object was freed,
                                         # [] if not applicable/available
        "sanitizer_raw": str,           # the original text, verbatim
    }

Each frame is itself a dict: {"frame": int, "addr": str, "func": str|None,
"file": str|None, "line": int|None}. Frames whose location can't be
resolved to a source file:line (bare module+offset frames deep in libc)
still appear with `file`/`line` set to None rather than being dropped, so
the frame count/ordering is never silently lossy.
"""

import re

ASAN_ERROR_MARKER_RE = re.compile(r"==\d+==ERROR: AddressSanitizer:")
ASAN_ERROR_LINE_RE = re.compile(r"==\d+==ERROR: AddressSanitizer: (.+)$", re.MULTILINE)
ASAN_ACCESS_RE = re.compile(r"\b(READ|WRITE) of size (\d+) at")
ASAN_SEGV_ACCESS_RE = re.compile(r"caused by a (READ|WRITE) memory access")
ASAN_ADDRESS_RE = re.compile(r"(?:on (?:unknown )?address|double-free on)\s+(0x[0-9a-fA-F]+)")
ASAN_FRAME_RE = re.compile(r"^\s*#(\d+)\s+(0x[0-9a-fA-F]+)\s+(.*)$")
FRAME_LOCATION_RE = re.compile(r"^(.+?):(\d+)(?::\d+)?$")

UBSAN_LINE_RE = re.compile(
    r"^(.+?):(\d+):(\d+):\s+runtime error:\s+(.+)$", re.MULTILINE
)

MSAN_MARKER_RE = re.compile(r"==\d+==WARNING: MemorySanitizer: (.+)$", re.MULTILINE)
LSAN_ERROR_MARKER_RE = re.compile(r"(?:==\d+==)?ERROR: LeakSanitizer: detected memory leaks")
LSAN_ASAN_SUMMARY_RE = re.compile(r"SUMMARY: AddressSanitizer:.*leaked")
LSAN_LEAK_SIZE_RE = re.compile(r"(Direct|Indirect) leak of (\d+) byte\(s\) in (\d+) object\(s\)")


def detect_sanitizer_output(text):
    if not text:
        return None
    if LSAN_ERROR_MARKER_RE.search(text) or LSAN_ASAN_SUMMARY_RE.search(text):
        return "lsan"
    if ASAN_ERROR_MARKER_RE.search(text):
        return "asan"
    if MSAN_MARKER_RE.search(text):
        return "msan"
    if UBSAN_LINE_RE.search(text):
        return "ubsan"
    return None


def _asan_bug_class(error_text):
    stripped = error_text.strip()
    if stripped.startswith("attempting double-free"):
        return "double-free"
    if stripped.startswith("attempting free"):
        return "bad-free"
    if stripped.startswith("SEGV"):
        return "SEGV"
    tokens = stripped.split()
    bug_class = tokens[0] if tokens else "unknown"
    return bug_class.rstrip(": \t")


def _parse_frame_location(location):
    if not location or location.startswith("("):
        return None, None
    match = FRAME_LOCATION_RE.match(location)
    if not match:
        return None, None
    return match.group(1), int(match.group(2))


def _parse_asan_frame(line):
    match = ASAN_FRAME_RE.match(line)
    if not match:
        return None

    frame_num, addr, rest = match.groups()
    rest = rest.strip()
    func = None
    location = rest
    if rest.startswith("in "):
        remainder = rest[3:]
        parts = remainder.rsplit(" ", 1)
        if len(parts) == 2:
            func, location = parts
        else:
            func, location = remainder, None

    file_name, line_number = _parse_frame_location(location)
    return {
        "frame": int(frame_num),
        "addr": addr,
        "func": func,
        "file": file_name,
        "line": line_number,
    }


def _collect_asan_stacks(text):
    crash_stack, alloc_stack, free_stack = [], [], []
    section = None
    in_block = False

    for raw_line in text.splitlines():
        frame = _parse_asan_frame(raw_line)
        if frame is not None:
            if section == "crash":
                crash_stack.append(frame)
            elif section == "alloc":
                alloc_stack.append(frame)
            elif section == "free":
                free_stack.append(frame)
            in_block = True
            continue

        if in_block:
            in_block = False
            section = None

        stripped = raw_line.strip()
        if ASAN_ERROR_MARKER_RE.search(stripped):
            section = "crash"
        elif stripped.startswith(("READ of size", "WRITE of size")):
            section = "crash"
        elif "attempting double-free" in stripped or "attempting free" in stripped:
            section = "crash"
        elif "SEGV on unknown address" in stripped:
            section = "crash"
        elif "freed by thread" in stripped:
            section = "free"
        elif "allocated by thread" in stripped:
            section = "alloc"

    return crash_stack, alloc_stack, free_stack


def parse_asan(text):
    error_match = ASAN_ERROR_LINE_RE.search(text)
    if not error_match:
        return None

    error_text = error_match.group(1)
    bug_class = _asan_bug_class(error_text)

    access_type = None
    access_size = None
    access_match = ASAN_ACCESS_RE.search(text)
    if access_match:
        access_type = access_match.group(1).lower()
        access_size = int(access_match.group(2))
    else:
        segv_match = ASAN_SEGV_ACCESS_RE.search(text)
        if segv_match:
            access_type = segv_match.group(1).lower()

    fault_addr = None
    address_match = ASAN_ADDRESS_RE.search(error_text) or ASAN_ADDRESS_RE.search(text)
    if address_match:
        fault_addr = address_match.group(1)

    crash_stack, alloc_stack, free_stack = _collect_asan_stacks(text)

    return {
        "sanitizer": "AddressSanitizer",
        "bug_class": bug_class,
        "access_type": access_type,
        "access_size": access_size,
        "fault_addr": fault_addr,
        "crash_stack": crash_stack,
        "alloc_stack": alloc_stack,
        "free_stack": free_stack,
        "sanitizer_raw": text,
    }


def _ubsan_bug_class(message):
    lowered = message.lower()
    if "signed integer overflow" in lowered:
        return "signed-integer-overflow"
    if "unsigned integer overflow" in lowered:
        return "unsigned-integer-overflow"
    if "null pointer" in lowered:
        return "null-pointer-dereference"
    if "out of bounds" in lowered:
        return "array-index-out-of-bounds"
    if "division by zero" in lowered or "divide by zero" in lowered:
        return "division-by-zero"
    if "misaligned address" in lowered:
        return "misaligned-pointer"
    if "shift exponent" in lowered or "shift amount" in lowered:
        return "shift-out-of-bounds"
    return "undefined-behavior"


def parse_ubsan(text):
    match = UBSAN_LINE_RE.search(text)
    if not match:
        return None

    file_name, line_number, _col, message = match.groups()

    crash_stack = []
    tail = text[match.end():]
    for raw_line in tail.splitlines():
        frame = _parse_asan_frame(raw_line)
        if frame is not None:
            crash_stack.append(frame)
        elif crash_stack:
            break

    if not crash_stack:
        crash_stack = [
            {
                "frame": 0,
                "addr": None,
                "func": None,
                "file": file_name,
                "line": int(line_number),
            }
        ]

    return {
        "sanitizer": "UndefinedBehaviorSanitizer",
        "bug_class": _ubsan_bug_class(message),
        "access_type": None,
        "access_size": None,
        "fault_addr": None,
        "crash_stack": crash_stack,
        "alloc_stack": [],
        "free_stack": [],
        "sanitizer_raw": text,
    }


def parse_lsan(text):
    if not (LSAN_ERROR_MARKER_RE.search(text) or LSAN_ASAN_SUMMARY_RE.search(text)):
        return None

    total_bytes = 0
    total_objects = 0
    for _kind, size, count in LSAN_LEAK_SIZE_RE.findall(text):
        total_bytes += int(size)
        total_objects += int(count)

    alloc_stack = []
    collecting = False
    for raw_line in text.splitlines():
        frame = _parse_asan_frame(raw_line)
        if frame is not None:
            if collecting:
                alloc_stack.append(frame)
            continue
        if LSAN_LEAK_SIZE_RE.search(raw_line):
            collecting = True
        elif raw_line.strip():
            collecting = False

    return {
        "sanitizer": "LeakSanitizer",
        "bug_class": "memory-leak",
        "access_type": None,
        "access_size": total_bytes or None,
        "fault_addr": None,
        "leaked_objects": total_objects or None,
        "crash_stack": alloc_stack[:1],
        "alloc_stack": alloc_stack,
        "free_stack": [],
        "sanitizer_raw": text,
    }


def parse_msan(text):
    marker = MSAN_MARKER_RE.search(text)
    if not marker:
        return None

    bug_class = marker.group(1).strip().split()[0].rstrip(":")

    crash_stack = []
    for raw_line in text[marker.end():].splitlines():
        frame = _parse_asan_frame(raw_line)
        if frame is not None:
            crash_stack.append(frame)
        elif crash_stack:
            break

    return {
        "sanitizer": "MemorySanitizer",
        "bug_class": bug_class or "use-of-uninitialized-value",
        "access_type": "read",
        "access_size": None,
        "fault_addr": None,
        "crash_stack": crash_stack,
        "alloc_stack": [],
        "free_stack": [],
        "sanitizer_raw": text,
    }


def parse_sanitizer_output(text):
    kind = detect_sanitizer_output(text)
    if kind == "msan":
        return parse_msan(text)
    if kind == "lsan":
        return parse_lsan(text)
    if kind == "asan":
        return parse_asan(text)
    if kind == "ubsan":
        return parse_ubsan(text)
    return None
