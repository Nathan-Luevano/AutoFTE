import os

DEFAULT_WINDOW = 6
WHOLE_FILE_LINE_LIMIT = 200

_STACK_KEYS = ("crash_stack", "alloc_stack", "free_stack")


def _fault_lines(crash_record, source_path):
    base = os.path.basename(source_path)
    lines = set()
    for key in _STACK_KEYS:
        for frame in (crash_record or {}).get(key) or []:
            frame_file = frame.get("file")
            line = frame.get("line")
            if frame_file and line and os.path.basename(frame_file) == base:
                lines.add(int(line))
    return sorted(lines)


def _windows(fault_lines, window, total):
    ranges = []
    for line in fault_lines:
        lo = max(1, line - window)
        hi = min(total, line + window)
        if ranges and lo <= ranges[-1][1] + 1:
            ranges[-1] = (ranges[-1][0], max(ranges[-1][1], hi))
        else:
            ranges.append((lo, hi))
    return ranges


def extract_context(source_path, crash_record, window=DEFAULT_WINDOW):
    try:
        text = open(source_path, encoding="utf-8", errors="replace").read()
    except OSError:
        return None

    source_lines = text.splitlines()
    total = len(source_lines)
    fault_lines = _fault_lines(crash_record, source_path)

    if not fault_lines or total <= WHOLE_FILE_LINE_LIMIT:
        return text

    out = [f"{os.path.basename(source_path)} (excerpts around the faulting lines):"]
    prev_hi = 0
    for lo, hi in _windows(fault_lines, window, total):
        if lo > prev_hi + 1:
            out.append("        ...")
        for number in range(lo, hi + 1):
            marker = ">>" if number in fault_lines else "  "
            out.append(f"{marker} {number:>5}  {source_lines[number - 1]}")
        prev_hi = hi
    if prev_hi < total:
        out.append("        ...")
    return "\n".join(out)
