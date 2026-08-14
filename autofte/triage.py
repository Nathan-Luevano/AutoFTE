"""Group crash files by debugger frame (or exit signal, without gdb).

Crash grouping tries three signals per crash file, in order of how much
they actually tell you about the bug: a sanitizer report (ASan/UBSan) if
the target was built with one and produced one for this input, then a gdb
backtrace, then the plain exit signal. Sanitizer output is preferred
whenever it's present -- it carries a bug class, read/write, access size,
and allocation/free stacks that a gdb backtrace or bare signal can't give
you, so there's strictly more to lose by ignoring it than by paying for
one extra direct run per crash file to check.

Every crash-file execution is classified into an outcome taxonomy before
it's allowed anywhere near a "root cause" group: `CRASHED` (a fault
signal -- SIGSEGV/SIGABRT/SIGILL/SIGBUS/SIGFPE -- or a parsed sanitizer
report), `NO_CRASH` (a clean process exit, any exit code), or `TIMEOUT`.
Only `CRASHED` outcomes become groups; `NO_CRASH`/`TIMEOUT` are tallied
and reported separately instead of silently inflating the bug count.
There is no layer at which a genuine debugger/kernel "hung, still
running" signal can be told apart from "ran past the timeout" here --
both surface as a `subprocess.TimeoutExpired`, so `HANG` is treated as a
`TIMEOUT` variant rather than invented as a distinct, undetectable state.

Every crash file confirmed `CRASHED` on its first run is then re-run
several more times (see `DEFAULT_REPRODUCTION_RUNS`) under a normalized,
symbolization-friendly sanitizer environment to verify it reproduces --
ClusterFuzz's `REPRODUCIBILITY_FACTOR = 0.5` rule -- and to catch the
common case (AFL++'s own fuzz-time `ASAN_OPTIONS` ships `symbolize=0` and
`malloc_context_size=0`, so the crash a fuzzer recorded and the crash a
triage tool re-runs are not quite the same experiment) where a "crash"
doesn't reproduce at all. `NO_CRASH`/`TIMEOUT` outcomes are never re-run:
there is nothing to verify and doing it anyway would make triage
`reproduction_runs` times slower for zero benefit on a large corpus.
"""

import os
import platform
import re
import shutil
import signal
import subprocess
import tempfile
from pathlib import Path

from . import dedup, sanitizers

GDB_TIMEOUT_SECONDS = 10
DIRECT_RUN_TIMEOUT_SECONDS = 10
DEFAULT_REPRODUCTION_RUNS = 5
REPRODUCIBILITY_FACTOR = 0.5

FRAME_PATTERN = re.compile(
    r"#(\d+)\s+0x([0-9a-f]+) in ([^\s]+)(?:.*?at ([^:]+):(\d+))?"
)
GDB_EXITED_RE = re.compile(r"\[Inferior \d+ \(process \d+\) exited (normally|with code \d+)\]")

REPRODUCTION_ASAN_OPTIONS = (
    "abort_on_error=1:symbolize=1:detect_leaks=0:allocator_may_return_null=0:"
    "handle_abort=1:handle_segv=1:print_full_thread_history=0:malloc_context_size=30"
)
REPRODUCTION_UBSAN_OPTIONS = "print_stacktrace=1:halt_on_error=1"
REPRODUCTION_LC_ALL = "C"
REPRODUCTION_TZ = "UTC"
_SANITIZER_OPTIONS_ENV_RE = re.compile(r".*SAN_OPTIONS$")

_SETARCH_CACHE = None


def _normalized_run_env():
    env = {
        key: value
        for key, value in os.environ.items()
        if not _SANITIZER_OPTIONS_ENV_RE.match(key)
    }
    env["ASAN_OPTIONS"] = REPRODUCTION_ASAN_OPTIONS
    env["UBSAN_OPTIONS"] = REPRODUCTION_UBSAN_OPTIONS
    env["LC_ALL"] = REPRODUCTION_LC_ALL
    env["TZ"] = REPRODUCTION_TZ
    return env


def _setarch_prefix():
    global _SETARCH_CACHE
    if _SETARCH_CACHE is None:
        setarch = shutil.which("setarch")
        if setarch:
            _SETARCH_CACHE = ([setarch, platform.machine(), "-R"], None)
        else:
            _SETARCH_CACHE = (
                [],
                "setarch not found on PATH; ASLR was not explicitly disabled for triage runs",
            )
    return _SETARCH_CACHE


def _run_subprocess(cmd, timeout):
    prefix, _note = _setarch_prefix()
    env = _normalized_run_env()
    with tempfile.TemporaryDirectory(prefix="autofte-triage-") as run_tmp:
        env["TMPDIR"] = run_tmp
        return subprocess.run(
            [*prefix, *cmd], capture_output=True, text=True, timeout=timeout, env=env
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
        result = _run_subprocess(cmd, GDB_TIMEOUT_SECONDS)
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


def _gdb_exit_label(stdout):
    match = GDB_EXITED_RE.search(stdout)
    if match and match.group(1) == "normally":
        return "EXIT_0"
    return "EXIT_NONZERO"


def parse_gdb_frames(stdout):
    """Parse every `#N 0xADDR in FUNC [at FILE:LINE]` line out of a gdb
    `bt` transcript, not just the first one.

    `extract_gdb_frame` above only ever needed frame #0 to produce its
    single-line signature; major/minor stack hashing needs the whole
    backtrace so it has more than one frame to normalize and hash. Returns
    `[]` for a timed-out run or a transcript with no recognizable frame
    lines -- callers treat that the same as "nothing to hash".
    """
    if stdout in (None, "TIMEOUT"):
        return []

    frames = []
    for match in FRAME_PATTERN.finditer(stdout):
        frame_num, addr, func, file_name, line_number = match.groups()
        frames.append(
            {
                "frame": int(frame_num),
                "addr": f"0x{addr}",
                "func": func,
                "file": file_name,
                "line": int(line_number) if line_number else None,
            }
        )
    return frames


def _format_frame_label(frame):
    label = f"#{frame['frame']} {frame['addr']} in {frame['func']}"
    if frame.get("file") and frame.get("line"):
        return f"{label} at {frame['file']}:{frame['line']}"
    return label


def _run_target(binary, crash_file):
    try:
        return _run_subprocess([binary, crash_file], DIRECT_RUN_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        return None


def run_direct(binary, crash_file):
    """Fall back to just running the target when gdb is not available.

    Groups by termination signal / exit code since there is no frame to
    read a backtrace from.
    """
    result = _run_target(binary, crash_file)
    if result is None:
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


def _direct_outcome(label):
    if label == "TIMEOUT":
        return "TIMEOUT"
    if label.startswith("EXIT_"):
        return "NO_CRASH"
    return "CRASHED"


def try_sanitizer_triage(binary, crash_file):
    """Run the target directly and look for an ASan/UBSan report.

    Returns the normalized sanitizer crash record (see `sanitizers.py`) if
    the run's combined stdout/stderr contains one, else None -- including
    on a timeout, since there's nothing to parse in that case.
    """
    result = _run_target(binary, crash_file)
    if result is None:
        return None

    combined = f"{result.stdout or ''}\n{result.stderr or ''}"
    return sanitizers.parse_sanitizer_output(combined)


def sanitizer_signature(record):
    parts = [record["bug_class"]]

    if record["access_type"]:
        size = f" {record['access_size']}" if record["access_size"] is not None else ""
        parts.append(f"({record['access_type']}{size})")

    crash_stack = record["crash_stack"]
    significant = dedup.significant_frames(crash_stack)
    top_frame = significant[0] if significant else (crash_stack[0] if crash_stack else None)
    if top_frame:
        location = top_frame.get("func") or top_frame.get("addr")
        if location and top_frame.get("file") and top_frame.get("line"):
            location = f"{location} at {top_frame['file']}:{top_frame['line']}"
        if location:
            parts.append(f"in {location}")

    return " ".join(parts)


def _classify_crash(binary, crash_path, debugger, use_gdb, sanitizer_record):
    """Return `(internal_key, label, richness, outcome)` for one crash
    file's execution.

    `internal_key` is what crashes are actually grouped on: `("hash",
    major_hash)` when there were frames to normalize and hash, or
    `("raw", label)` when there weren't (a bare signal name, a gdb
    transcript with no parseable frame, or a sanitizer record whose whole
    stack was noise) -- those have nothing ASLR-shiftable about them, so
    the label itself is already a stable, correct grouping key exactly
    like the old exact-match behavior. `label` is the human-readable
    string that ends up as the group's key in the returned result.
    `richness` (how many significant frames informed the label) is only
    used to pick the most complete label when several crashes share a
    major hash. `outcome` is one of `CRASHED`/`NO_CRASH`/`TIMEOUT` -- only
    `CRASHED` entries are eligible to become a group or a reproduction
    candidate; this same function is reused, unchanged, for both the
    initial classification run and every reproduction rerun, so a
    rerun's outcome/`internal_key` is directly comparable to the first
    run's.
    """
    if sanitizer_record is not None:
        crash_stack = sanitizer_record["crash_stack"]
        major_hash, _minor_hash = dedup.stack_hashes(
            crash_stack, extra_context=[sanitizer_record["bug_class"]]
        )
        label = sanitizer_signature(sanitizer_record)
        if major_hash is not None:
            key = ("hash", major_hash)
            richness = len(dedup.significant_frames(crash_stack))
        else:
            key = ("raw", label)
            richness = 0
        return key, label, richness, "CRASHED"

    if use_gdb:
        stdout, stderr = run_with_gdb(str(binary), str(crash_path), debugger)
        if stdout == "TIMEOUT":
            return ("raw", "TIMEOUT"), "TIMEOUT", 0, "TIMEOUT"
        if isinstance(stdout, str) and GDB_EXITED_RE.search(stdout):
            label = _gdb_exit_label(stdout)
            return ("raw", label), label, 0, "NO_CRASH"
        frames = parse_gdb_frames(stdout)
        significant = dedup.significant_frames(frames)
        if significant:
            major_hash, _minor_hash = dedup.stack_hashes(frames)
            return (
                ("hash", major_hash),
                _format_frame_label(significant[0]),
                len(significant),
                "CRASHED",
            )
        label = extract_gdb_frame(stdout, stderr)
        return ("raw", label), label, 0, "CRASHED"

    label = run_direct(str(binary), str(crash_path))
    return ("raw", label), label, 0, _direct_outcome(label)


def _verify_reproducibility(binary, crash_path, debugger, use_gdb, first_key, reproduction_runs):
    """Re-run a crash file confirmed `CRASHED` on its first run and
    classify it per research/05's reproducibility table.

    `first_key` is the `internal_key` `_classify_crash` already produced
    for the crash's first run -- counted as run 1 of `reproduction_runs`
    total, so only `reproduction_runs - 1` further executions actually
    happen here. A rerun only "reproduces" if it both crashed and landed
    in the exact same bucket as the first run (`internal_key` equality,
    i.e. the same major hash or the same raw signal/label) -- merely
    crashing again with a different bucket is `unstable-bucket`, not a
    reproduction.
    """
    additional_runs = max(reproduction_runs - 1, 0)
    crashed_keys = [first_key]

    for _ in range(additional_runs):
        sanitizer_record = try_sanitizer_triage(str(binary), str(crash_path))
        key, _label, _richness, outcome = _classify_crash(
            binary, crash_path, debugger, use_gdb, sanitizer_record
        )
        if outcome == "CRASHED":
            crashed_keys.append(key)

    crashed_count = len(crashed_keys)
    reproduction_rate = crashed_count / reproduction_runs

    if crashed_count == 0:
        return "non-reproducible", 0.0

    if len(set(crashed_keys)) > 1:
        return "unstable-bucket", reproduction_rate

    if reproduction_rate >= REPRODUCIBILITY_FACTOR:
        return "reproducible", reproduction_rate

    return "flaky", reproduction_rate


def _empty_reproduction_summary():
    return {
        "crashed_on_first_run": 0,
        "reproducible": 0,
        "flaky": 0,
        "unstable_bucket": 0,
        "non_reproducible": 0,
    }


def triage_crashes(
    crashes_dir,
    target_binary,
    debugger="gdb",
    progress_callback=None,
    reproduction_runs=DEFAULT_REPRODUCTION_RUNS,
):
    crash_dir = Path(crashes_dir)
    binary = Path(target_binary)
    reproduction_runs = max(int(reproduction_runs), 1)

    if not crash_dir.exists():
        raise FileNotFoundError(f"crashes directory not found: {crash_dir}")

    if not binary.exists() or not os.access(binary, os.X_OK):
        raise FileNotFoundError(f"target binary not executable: {binary}")

    crash_files = sorted(
        path
        for path in crash_dir.iterdir()
        if path.is_file() and path.name != "README.txt"
    )

    _prefix, setarch_note = _setarch_prefix()
    environment = {
        "asan_options": REPRODUCTION_ASAN_OPTIONS,
        "ubsan_options": REPRODUCTION_UBSAN_OPTIONS,
        "lc_all": REPRODUCTION_LC_ALL,
        "tz": REPRODUCTION_TZ,
        "aslr_disabled": setarch_note is None,
        "aslr_note": setarch_note,
        "reproduction_runs": reproduction_runs,
    }

    if not crash_files:
        return {
            "total_crashes": 0,
            "unique_crash_frames": 0,
            "triage_mode": "empty",
            "groups": {},
            "no_crash_count": 0,
            "timeout_count": 0,
            "reproduction_summary": _empty_reproduction_summary(),
            "environment": environment,
        }

    use_gdb = gdb_is_available(debugger)
    base_mode = "gdb" if use_gdb else "direct"

    groups = {}
    sanitizer_hits = 0
    no_crash_count = 0
    timeout_count = 0
    reproduction_summary = _empty_reproduction_summary()

    total = len(crash_files)
    for index, crash_path in enumerate(crash_files, start=1):
        if progress_callback:
            progress_callback(index, total, crash_path.name)

        sanitizer_record = try_sanitizer_triage(str(binary), str(crash_path))
        internal_key, label, richness, outcome = _classify_crash(
            binary, crash_path, debugger, use_gdb, sanitizer_record
        )

        if outcome == "NO_CRASH":
            no_crash_count += 1
            continue
        if outcome == "TIMEOUT":
            timeout_count += 1
            continue

        if sanitizer_record is not None:
            sanitizer_hits += 1

        reproduction_summary["crashed_on_first_run"] += 1
        classification, reproduction_rate = _verify_reproducibility(
            binary, crash_path, debugger, use_gdb, internal_key, reproduction_runs
        )
        reproduction_summary[classification.replace("-", "_")] += 1
        flaky_flag = classification == "reproducible" and reproduction_rate < 1.0

        entry = {
            "file": crash_path.name,
            "path": str(crash_path),
            "size": crash_path.stat().st_size,
            "reproducibility": classification,
            "reproduction_rate": reproduction_rate,
            "flaky": flaky_flag,
            "unstable_bucket": classification == "unstable-bucket",
        }
        if sanitizer_record is not None:
            entry["sanitizer"] = sanitizer_record

        bucket = groups.setdefault(
            internal_key, {"label": label, "richness": richness, "entries": []}
        )
        if richness > bucket["richness"]:
            bucket["label"] = label
            bucket["richness"] = richness
        bucket["entries"].append(entry)

    ordered_buckets = sorted(
        groups.values(), key=lambda bucket: len(bucket["entries"]), reverse=True
    )

    triage_mode = "sanitizer" if sanitizer_hits > 0 else base_mode

    final_groups = {}
    used_labels = set()
    for bucket in ordered_buckets:
        label = bucket["label"]
        unique_label = label
        suffix = 2
        while unique_label in used_labels:
            unique_label = f"{label} [{suffix}]"
            suffix += 1
        used_labels.add(unique_label)
        final_groups[unique_label] = {
            "count": len(bucket["entries"]),
            "crashes": sorted(bucket["entries"], key=lambda item: item["size"]),
        }

    total_crashes = sum(len(bucket["entries"]) for bucket in groups.values())

    return {
        "total_crashes": total_crashes,
        "unique_crash_frames": len(final_groups),
        "triage_mode": triage_mode,
        "groups": final_groups,
        "no_crash_count": no_crash_count,
        "timeout_count": timeout_count,
        "reproduction_summary": reproduction_summary,
        "environment": environment,
    }
