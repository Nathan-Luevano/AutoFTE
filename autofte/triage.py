"""Group crash files by debugger frame (or exit signal, without gdb)."""

import os
import re
import shutil
import signal
import subprocess
from collections import defaultdict
from pathlib import Path

from .paths import pick_crash_dir  # noqa: F401  (re-exported for callers/tests)

GDB_TIMEOUT_SECONDS = 10
DIRECT_RUN_TIMEOUT_SECONDS = 10
FRAME_PATTERN = re.compile(
    r"#(\d+)\s+0x([0-9a-f]+) in ([^\s]+)(?:.*?at ([^:]+):(\d+))?"
)


def gdb_is_available(debugger):
    return shutil.which(debugger) is not None


def run_with_gdb(binary, crash_file, debugger):
    cmd = [
        debugger,
        "--batch",
        "--quiet",
        "--return-child-result",
        "--ex",
        "set pagination off",
        "--ex",
        f"run {crash_file}",
        "--ex",
        "bt 10",
        "--ex",
        "quit",
        "--args",
        binary,
    ]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=GDB_TIMEOUT_SECONDS
        )
    except subprocess.TimeoutExpired:
        return "TIMEOUT", "debugger timed out"

    return result.stdout, result.stderr


def extract_gdb_frame(stdout, stderr):
    if stdout == "TIMEOUT":
        return "TIMEOUT"

    match = FRAME_PATTERN.search(stdout)
    if match:
        frame_num, addr, func, file_name, line_number = match.groups()
        if file_name and line_number:
            return f"#{frame_num} 0x{addr} in {func} at {file_name}:{line_number}"
        return f"#{frame_num} 0x{addr} in {func}"

    combined = f"{stdout}\n{stderr}"
    if "SIGSEGV" in combined or "Segmentation fault" in combined:
        return "SIGSEGV"
    if "SIGABRT" in combined:
        return "SIGABRT"
    if "SIGILL" in combined:
        return "SIGILL"
    return "UNKNOWN_CRASH"


def run_direct(binary, crash_file):
    """Fall back to just running the target when gdb is not available.

    Groups by termination signal / exit code since there is no frame to
    read a backtrace from.
    """
    try:
        result = subprocess.run(
            [binary, crash_file],
            capture_output=True,
            text=True,
            timeout=DIRECT_RUN_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return "TIMEOUT"

    if result.returncode < 0:
        try:
            sig_name = signal.Signals(-result.returncode).name
        except ValueError:
            sig_name = f"SIGNAL_{-result.returncode}"
        return sig_name

    stderr = (result.stderr or "").lower()
    stdout = (result.stdout or "").lower()
    if "segmentation fault" in stderr or "segmentation fault" in stdout:
        return "SIGSEGV"
    if "aborted" in stderr or "sigabrt" in stderr:
        return "SIGABRT"
    return f"EXIT_{result.returncode}"


def triage_crashes(crashes_dir, target_binary, debugger="gdb", progress_callback=None):
    crash_dir = Path(crashes_dir)
    binary = Path(target_binary)

    if not crash_dir.exists():
        raise FileNotFoundError(f"crashes directory not found: {crash_dir}")

    if not binary.exists() or not os.access(binary, os.X_OK):
        raise FileNotFoundError(f"target binary not executable: {binary}")

    crash_files = sorted(
        path
        for path in crash_dir.iterdir()
        if path.is_file() and path.name != "README.txt"
    )

    if not crash_files:
        return {
            "total_crashes": 0,
            "unique_crash_frames": 0,
            "triage_mode": "empty",
            "groups": {},
        }

    use_gdb = gdb_is_available(debugger)
    triage_mode = "gdb" if use_gdb else "direct"

    groups = defaultdict(list)
    total = len(crash_files)
    for index, crash_path in enumerate(crash_files, start=1):
        if progress_callback:
            progress_callback(index, total, crash_path.name)

        if use_gdb:
            stdout, stderr = run_with_gdb(str(binary), str(crash_path), debugger)
            signature = extract_gdb_frame(stdout, stderr)
        else:
            signature = run_direct(str(binary), str(crash_path))

        groups[signature].append(
            {
                "file": crash_path.name,
                "path": str(crash_path),
                "size": crash_path.stat().st_size,
            }
        )

    ordered_groups = dict(
        sorted(groups.items(), key=lambda item: len(item[1]), reverse=True)
    )

    return {
        "total_crashes": len(crash_files),
        "unique_crash_frames": len(ordered_groups),
        "triage_mode": triage_mode,
        "groups": {
            frame: {
                "count": len(items),
                "crashes": sorted(items, key=lambda item: item["size"]),
            }
            for frame, items in ordered_groups.items()
        },
    }
