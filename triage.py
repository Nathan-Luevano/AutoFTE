import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import sys
from collections import defaultdict
from pathlib import Path


DEFAULT_CRASH_DIRS = [
    "out/default/crashes",
    "out/crashes",
    "crashes",
]


def pick_crash_dir():
    for candidate in DEFAULT_CRASH_DIRS:
        if Path(candidate).exists():
            return candidate
    return DEFAULT_CRASH_DIRS[0]


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
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    except subprocess.TimeoutExpired:
        return "TIMEOUT", "debugger timed out"

    return result.stdout, result.stderr


def extract_gdb_frame(stdout, stderr):
    if "TIMEOUT" in stdout:
        return "TIMEOUT"

    pattern = r"#(\d+)\s+0x([0-9a-f]+) in ([^\s]+)(?:.*?at ([^:]+):(\d+))?"
    matches = re.findall(pattern, stdout)
    if matches:
        frame_num, addr, func, file_name, line_number = matches[0]
        if file_name and line_number:
            return f"#{frame_num} 0x{addr} in {func} at {file_name}:{line_number}"
        return f"#{frame_num} 0x{addr} in {func}"

    combined = "\n".join([stdout, stderr])
    if "SIGSEGV" in combined or "Segmentation fault" in combined:
        return "SIGSEGV"
    if "SIGABRT" in combined:
        return "SIGABRT"
    if "SIGILL" in combined:
        return "SIGILL"
    return "UNKNOWN_CRASH"


def run_direct(binary, crash_file):
    try:
        result = subprocess.run(
            [binary, crash_file],
            capture_output=True,
            text=True,
            timeout=10,
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
    if result.returncode >= 128:
        return f"EXIT_{result.returncode}"
    return f"EXIT_{result.returncode}"


def triage_crashes(crashes_dir, target_binary, debugger):
    crash_dir = Path(crashes_dir)
    binary = Path(target_binary)

    if not crash_dir.exists():
        print(f"Error: crashes directory not found: {crash_dir}")
        return None

    if not binary.exists() or not os.access(binary, os.X_OK):
        print(f"Error: target binary not executable: {binary}")
        return None

    crash_files = sorted(
        path
        for path in crash_dir.iterdir()
        if path.is_file() and path.name != "README.txt"
    )

    if not crash_files:
        print(f"No crash files found in {crash_dir}")
        return {
            "total_crashes": 0,
            "unique_crash_frames": 0,
            "triage_mode": "empty",
            "groups": {},
        }

    use_gdb = gdb_is_available(debugger)
    triage_mode = "gdb" if use_gdb else "direct"
    if not use_gdb:
        print("gdb was not found, using exit signal grouping instead")

    groups = defaultdict(list)
    total = len(crash_files)

    for index, crash_path in enumerate(crash_files, start=1):
        print(f"Processing {index}/{total}: {crash_path.name}", end="\r", flush=True)

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

    print("")

    ordered_groups = dict(
        sorted(groups.items(), key=lambda item: len(item[1]), reverse=True)
    )

    return {
        "total_crashes": total,
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


def main():
    parser = argparse.ArgumentParser(description="Group crash files by frame or signal")
    parser.add_argument(
        "--crashes-dir",
        default=os.environ.get("CRASHES_DIR", pick_crash_dir()),
        help="Directory containing crash files",
    )
    parser.add_argument(
        "--target-binary",
        default=os.environ.get("TARGET_BINARY", "./target"),
        help="Path to target binary",
    )
    parser.add_argument(
        "--output",
        default=os.environ.get("OUTPUT_JSON", "crash_triage.json"),
        help="JSON output path",
    )
    parser.add_argument(
        "--debugger",
        default=os.environ.get("DEBUGGER", "gdb"),
        help="Debugger to use when available",
    )
    args = parser.parse_args()

    result = triage_crashes(args.crashes_dir, args.target_binary, args.debugger)
    if result is None:
        return 1

    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)

    print(f"Saved triage results to {args.output}")
    print(f"Crash files: {result['total_crashes']}")
    print(f"Groups: {result['unique_crash_frames']}")
    print(f"Mode: {result['triage_mode']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
