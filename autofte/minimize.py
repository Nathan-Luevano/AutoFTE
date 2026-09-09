import os
import shutil
import subprocess
import tempfile

from . import dedup, triage

AFL_TMIN_TIMEOUT_MS = 5000
AFL_TMIN_WALL_TIMEOUT_SECONDS = 600
MAX_DDMIN_EXECUTIONS = 4000


def afl_tmin_available():
    return shutil.which("afl-tmin") is not None


def _top_func(frames):
    for frame in dedup.significant_frames(frames or []):
        if frame.get("func"):
            return frame["func"]
    return None


def crash_signature(binary, path, debugger="gdb"):
    record = triage.try_sanitizer_triage(binary, path)
    if record:
        return ("sanitizer", record.get("bug_class"), _top_func(record.get("crash_stack")))

    label = triage.run_direct(binary, path)
    if label == "TIMEOUT" or label.startswith("EXIT_"):
        return None

    if triage.gdb_is_available(debugger):
        stdout, _stderr = triage.run_with_gdb(binary, path, debugger)
        frames = triage.parse_gdb_frames(stdout)
        top = _top_func(frames)
        if top:
            return ("gdb", label, top)
    return ("signal", label)


def ddmin(data, test):
    n = 2
    while len(data) >= 2:
        chunk = max(len(data) // n, 1)
        start = 0
        shrunk = False
        while start < len(data):
            complement = data[:start] + data[start + chunk:]
            if complement and test(complement):
                data = complement
                n = max(n - 1, 2)
                shrunk = True
                break
            start += chunk
        if not shrunk:
            if n >= len(data):
                break
            n = min(n * 2, len(data))
    return data


def _run_afl_tmin(binary, in_path, out_path, timeout):
    env = dict(os.environ)
    env["AFL_SKIP_BIN_CHECK"] = "1"
    env["AFL_NO_AFFINITY"] = "1"
    cmd = [
        "afl-tmin",
        "-i",
        str(in_path),
        "-o",
        str(out_path),
        "-m",
        "none",
        "-t",
        str(AFL_TMIN_TIMEOUT_MS),
        "--",
        str(binary),
        "@@",
    ]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, env=env, timeout=timeout
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0 and os.path.exists(out_path) and os.path.getsize(out_path) > 0


def minimize_file(binary, crash_path, output_path=None, debugger="gdb", use_afl_tmin=True):
    original = open(crash_path, "rb").read()
    reference = crash_signature(binary, crash_path, debugger)
    if reference is None:
        return None

    minimized = None
    tool = None

    if use_afl_tmin and afl_tmin_available():
        handle = tempfile.NamedTemporaryFile(prefix="autofte-tmin-", delete=False)
        handle.close()
        if _run_afl_tmin(binary, crash_path, handle.name, AFL_TMIN_WALL_TIMEOUT_SECONDS):
            candidate = open(handle.name, "rb").read()
            if candidate and crash_signature(binary, handle.name, debugger) == reference:
                minimized = candidate
                tool = "afl-tmin"
        os.unlink(handle.name)

    if minimized is None:
        executions = [0]
        probe = tempfile.NamedTemporaryFile(prefix="autofte-ddmin-", delete=False)
        probe.close()

        def test(candidate):
            if executions[0] >= MAX_DDMIN_EXECUTIONS:
                return False
            executions[0] += 1
            with open(probe.name, "wb") as fh:
                fh.write(candidate)
            return crash_signature(binary, probe.name, debugger) == reference

        minimized = ddmin(original, test)
        os.unlink(probe.name)
        tool = "ddmin"

    if not minimized or len(minimized) >= len(original):
        minimized = original
        tool = tool or "none"

    if output_path:
        with open(output_path, "wb") as fh:
            fh.write(minimized)

    original_size = len(original)
    minimized_size = len(minimized)
    reduction = 0.0
    if original_size:
        reduction = round((1 - minimized_size / original_size) * 100, 1)
    return {
        "tool": tool,
        "original_size": original_size,
        "minimized_size": minimized_size,
        "reduction_percent": reduction,
        "output_path": str(output_path) if output_path else None,
        "signature": list(reference),
    }
