import pathlib
import signal
import subprocess

import pytest

from autofte import triage
from autofte.triage import (
    extract_gdb_frame,
    gdb_is_available,
    run_direct,
    run_with_gdb,
    sanitizer_signature,
    triage_crashes,
    try_sanitizer_triage,
)

from .conftest import ASAN_AVAILABLE, compile_vuln_asan_binary

# --------------------------------------------------------------------------
# extract_gdb_frame
# --------------------------------------------------------------------------

def test_extract_gdb_frame_timeout_sentinel():
    assert extract_gdb_frame("TIMEOUT", "debugger timed out") == "TIMEOUT"


def test_extract_gdb_frame_parses_frame_with_file_and_line():
    stdout = (
        "Program received signal SIGSEGV\n"
        "#0  0x0000000000401136 in vuln (input=0x7fffffffe4d0 \"AAAA\") "
        "at vuln.c:8\n"
    )
    result = extract_gdb_frame(stdout, "")
    assert result == "#0 0x0000000000401136 in vuln at vuln.c:8"


def test_extract_gdb_frame_parses_frame_without_file_info():
    stdout = "#2  0x00007ffff7a5e083 in __libc_start_main ()\n"
    result = extract_gdb_frame(stdout, "")
    assert result == "#2 0x00007ffff7a5e083 in __libc_start_main"


def test_extract_gdb_frame_falls_back_to_signal_names():
    stderr = "Program terminated with signal SIGSEGV"
    assert extract_gdb_frame("no frame data here", stderr) == "SIGSEGV"
    assert extract_gdb_frame("Segmentation fault", "") == "SIGSEGV"
    assert extract_gdb_frame("something SIGABRT happened", "") == "SIGABRT"
    assert extract_gdb_frame("SIGILL raised", "") == "SIGILL"


def test_extract_gdb_frame_unknown_when_nothing_matches():
    assert extract_gdb_frame("nothing useful", "nor here") == "UNKNOWN_CRASH"


# --------------------------------------------------------------------------
# gdb_is_available / run_with_gdb / run_direct (mocked subprocess)
# --------------------------------------------------------------------------

def test_gdb_is_available_true_and_false(monkeypatch):
    monkeypatch.setattr(triage.shutil, "which", lambda name: "/usr/bin/gdb")
    assert gdb_is_available("gdb") is True

    monkeypatch.setattr(triage.shutil, "which", lambda name: None)
    assert gdb_is_available("gdb") is False


def test_run_with_gdb_timeout(monkeypatch):
    def fake_run(cmd, capture_output, text, timeout, **kwargs):
        raise subprocess.TimeoutExpired(cmd, timeout)

    monkeypatch.setattr(triage.subprocess, "run", fake_run)
    stdout, stderr = run_with_gdb("bin", "crash1", "gdb")
    assert stdout == "TIMEOUT"
    assert "timed out" in stderr


def test_run_with_gdb_returns_stdout_stderr(monkeypatch):
    class FakeResult:
        stdout = "some backtrace"
        stderr = "some stderr"

    monkeypatch.setattr(triage.subprocess, "run", lambda *a, **k: FakeResult())
    stdout, stderr = run_with_gdb("bin", "crash1", "gdb")
    assert stdout == "some backtrace"
    assert stderr == "some stderr"


def test_run_direct_negative_returncode_maps_to_signal_name(monkeypatch):
    class FakeResult:
        returncode = -signal.SIGSEGV
        stdout = ""
        stderr = ""

    monkeypatch.setattr(triage.subprocess, "run", lambda *a, **k: FakeResult())
    assert run_direct("bin", "crash1") == "SIGSEGV"


def test_run_direct_unknown_negative_signal(monkeypatch):
    class FakeResult:
        returncode = -999
        stdout = ""
        stderr = ""

    monkeypatch.setattr(triage.subprocess, "run", lambda *a, **k: FakeResult())
    assert run_direct("bin", "crash1") == "SIGNAL_999"


def test_run_direct_detects_segfault_message_in_output(monkeypatch):
    class FakeResult:
        returncode = 139
        stdout = ""
        stderr = "Segmentation fault (core dumped)"

    monkeypatch.setattr(triage.subprocess, "run", lambda *a, **k: FakeResult())
    assert run_direct("bin", "crash1") == "SIGSEGV"


def test_run_direct_detects_abort(monkeypatch):
    class FakeResult:
        returncode = 134
        stdout = ""
        stderr = "aborted"

    monkeypatch.setattr(triage.subprocess, "run", lambda *a, **k: FakeResult())
    assert run_direct("bin", "crash1") == "SIGABRT"


def test_run_direct_plain_exit_code(monkeypatch):
    class FakeResult:
        returncode = 1
        stdout = ""
        stderr = ""

    monkeypatch.setattr(triage.subprocess, "run", lambda *a, **k: FakeResult())
    assert run_direct("bin", "crash1") == "EXIT_1"


def test_run_direct_timeout(monkeypatch):
    def fake_run(cmd, capture_output, text, timeout, **kwargs):
        raise subprocess.TimeoutExpired(cmd, timeout)

    monkeypatch.setattr(triage.subprocess, "run", fake_run)
    assert run_direct("bin", "crash1") == "TIMEOUT"


# --------------------------------------------------------------------------
# triage_crashes
# --------------------------------------------------------------------------

def test_triage_crashes_missing_dir_raises(tmp_path, make_executable):
    binary = make_executable()
    with pytest.raises(FileNotFoundError):
        triage_crashes(tmp_path / "nope", str(binary))


def test_triage_crashes_missing_binary_raises(crashes_dir):
    with pytest.raises(FileNotFoundError):
        triage_crashes(str(crashes_dir), "/nonexistent/binary")


def test_triage_crashes_non_executable_binary_raises(tmp_path, crashes_dir):
    binary = tmp_path / "target"
    binary.write_text("not executable")
    with pytest.raises(FileNotFoundError):
        triage_crashes(str(crashes_dir), str(binary))


def test_triage_crashes_empty_dir(crashes_dir, make_executable):
    binary = make_executable()
    result = triage_crashes(str(crashes_dir), str(binary))
    assert result["total_crashes"] == 0
    assert result["unique_crash_frames"] == 0
    assert result["triage_mode"] == "empty"
    assert result["groups"] == {}
    assert result["no_crash_count"] == 0
    assert result["timeout_count"] == 0
    assert result["reproduction_summary"] == {
        "crashed_on_first_run": 0,
        "reproducible": 0,
        "flaky": 0,
        "unstable_bucket": 0,
        "non_reproducible": 0,
    }
    assert result["environment"]["asan_options"] == triage.REPRODUCTION_ASAN_OPTIONS
    assert result["environment"]["ubsan_options"] == triage.REPRODUCTION_UBSAN_OPTIONS


def test_triage_crashes_ignores_readme(crashes_dir, make_executable, monkeypatch):
    binary = make_executable()
    (crashes_dir / "README.txt").write_text("readme")
    (crashes_dir / "id:000000").write_bytes(b"AAAA")

    monkeypatch.setattr(triage, "gdb_is_available", lambda debugger: False)
    monkeypatch.setattr(triage, "run_direct", lambda binary, crash_file: "SIGSEGV")

    result = triage_crashes(str(crashes_dir), str(binary))
    assert result["total_crashes"] == 1
    assert result["triage_mode"] == "direct"


def test_triage_crashes_attaches_crash_state_when_enabled(
    crashes_dir, make_executable, monkeypatch
):
    binary = make_executable()
    (crashes_dir / "crash1").write_bytes(b"A" * 10)

    monkeypatch.setattr(triage, "gdb_is_available", lambda debugger: False)
    monkeypatch.setattr(triage, "run_direct", lambda binary, crash_file: "SIGSEGV")
    monkeypatch.setattr(triage.crash_state, "gdb_available", lambda debugger="gdb": True)
    captured = {"primitives": ["memory-write"], "rationale": "writes through bad ptr."}
    monkeypatch.setattr(triage.crash_state, "capture", lambda *a, **k: dict(captured))

    result = triage_crashes(str(crashes_dir), str(binary), capture_state=True)
    group = next(iter(result["groups"].values()))
    assert group["crash_state"]["primitives"] == ["memory-write"]


def test_triage_crashes_skips_crash_state_by_default(crashes_dir, make_executable, monkeypatch):
    binary = make_executable()
    (crashes_dir / "crash1").write_bytes(b"A" * 10)
    monkeypatch.setattr(triage, "gdb_is_available", lambda debugger: False)
    monkeypatch.setattr(triage, "run_direct", lambda binary, crash_file: "SIGSEGV")

    def boom(*a, **k):
        raise AssertionError("crash_state.capture should not run when capture_state is False")

    monkeypatch.setattr(triage.crash_state, "capture", boom)
    result = triage_crashes(str(crashes_dir), str(binary))
    group = next(iter(result["groups"].values()))
    assert "crash_state" not in group


def test_triage_crashes_groups_by_signature_direct_mode(crashes_dir, make_executable, monkeypatch):
    binary = make_executable()
    (crashes_dir / "crash1").write_bytes(b"A" * 10)
    (crashes_dir / "crash2").write_bytes(b"B" * 20)
    (crashes_dir / "crash3").write_bytes(b"C" * 5)

    monkeypatch.setattr(triage, "gdb_is_available", lambda debugger: False)

    def fake_run_direct(binary, crash_file):
        if "crash3" in crash_file:
            return "SIGABRT"
        return "SIGSEGV"

    monkeypatch.setattr(triage, "run_direct", fake_run_direct)

    result = triage_crashes(str(crashes_dir), str(binary))
    assert result["triage_mode"] == "direct"
    assert result["total_crashes"] == 3
    assert result["unique_crash_frames"] == 2
    # SIGSEGV group has 2 entries, should sort first (descending count)
    groups = result["groups"]
    assert list(groups.keys())[0] == "SIGSEGV"
    assert groups["SIGSEGV"]["count"] == 2
    assert groups["SIGABRT"]["count"] == 1
    # crashes within a group sorted by size ascending
    sizes = [c["size"] for c in groups["SIGSEGV"]["crashes"]]
    assert sizes == sorted(sizes)
    assert groups["SIGSEGV"]["group_id"] == "raw:SIGSEGV"
    assert groups["SIGABRT"]["group_id"] == "raw:SIGABRT"


def test_triage_crashes_uses_gdb_mode_when_available(crashes_dir, make_executable, monkeypatch):
    binary = make_executable()
    (crashes_dir / "crash1").write_bytes(b"A")

    monkeypatch.setattr(triage, "gdb_is_available", lambda debugger: True)
    monkeypatch.setattr(triage, "run_with_gdb", lambda binary, crash_file, debugger: ("out", "err"))
    monkeypatch.setattr(triage, "extract_gdb_frame", lambda stdout, stderr: "#0 0xdead in vuln")

    result = triage_crashes(str(crashes_dir), str(binary))
    assert result["triage_mode"] == "gdb"
    assert list(result["groups"].keys()) == ["#0 0xdead in vuln"]


def test_triage_crashes_progress_callback_invoked(crashes_dir, make_executable, monkeypatch):
    binary = make_executable()
    (crashes_dir / "crash1").write_bytes(b"A")
    (crashes_dir / "crash2").write_bytes(b"B")

    monkeypatch.setattr(triage, "gdb_is_available", lambda debugger: False)
    monkeypatch.setattr(triage, "run_direct", lambda binary, crash_file: "SIGSEGV")

    calls = []
    triage_crashes(
        str(crashes_dir), str(binary), progress_callback=lambda i, t, n: calls.append((i, t, n))
    )
    assert len(calls) == 2
    assert calls[0][1] == 2  # total
    assert calls[-1][0] == 2  # last index equals total


# --------------------------------------------------------------------------
# triage_crashes -- outcome taxonomy (HARDENING 4.1): NO_CRASH/TIMEOUT are
# tallied but never become a root-cause group.
# --------------------------------------------------------------------------

def test_triage_crashes_no_crash_outcomes_excluded_from_groups(
    crashes_dir, make_executable, monkeypatch
):
    binary = make_executable()
    (crashes_dir / "crash1").write_bytes(b"A")
    (crashes_dir / "crash2").write_bytes(b"B")

    monkeypatch.setattr(triage, "gdb_is_available", lambda debugger: False)

    def fake_run_direct(binary, crash_file):
        return "EXIT_0" if "crash1" in crash_file else "SIGSEGV"

    monkeypatch.setattr(triage, "run_direct", fake_run_direct)

    result = triage_crashes(str(crashes_dir), str(binary))
    assert result["total_crashes"] == 1
    assert result["no_crash_count"] == 1
    assert result["timeout_count"] == 0
    assert result["unique_crash_frames"] == 1
    assert "EXIT_0" not in result["groups"]
    assert result["groups"]["SIGSEGV"]["count"] == 1


def test_triage_crashes_timeout_outcomes_excluded_from_groups(
    crashes_dir, make_executable, monkeypatch
):
    binary = make_executable()
    (crashes_dir / "crash1").write_bytes(b"A")
    (crashes_dir / "crash2").write_bytes(b"B")

    monkeypatch.setattr(triage, "gdb_is_available", lambda debugger: False)

    def fake_run_direct(binary, crash_file):
        return "TIMEOUT" if "crash1" in crash_file else "SIGSEGV"

    monkeypatch.setattr(triage, "run_direct", fake_run_direct)

    result = triage_crashes(str(crashes_dir), str(binary))
    assert result["total_crashes"] == 1
    assert result["timeout_count"] == 1
    assert result["no_crash_count"] == 0
    assert result["unique_crash_frames"] == 1


def test_triage_crashes_gdb_clean_exit_is_no_crash_not_a_group(
    crashes_dir, make_executable, monkeypatch
):
    binary = make_executable()
    (crashes_dir / "crash1").write_bytes(b"A")

    monkeypatch.setattr(triage, "gdb_is_available", lambda debugger: True)
    monkeypatch.setattr(
        triage,
        "run_with_gdb",
        lambda binary, crash_file, debugger: (
            "[Inferior 1 (process 4242) exited normally]\n",
            "",
        ),
    )

    result = triage_crashes(str(crashes_dir), str(binary))
    assert result["total_crashes"] == 0
    assert result["no_crash_count"] == 1
    assert result["groups"] == {}


# --------------------------------------------------------------------------
# triage_crashes -- reproducibility verification (HARDENING 4.2)
# --------------------------------------------------------------------------

def test_triage_crashes_deterministic_crash_is_fully_reproducible(
    crashes_dir, make_executable, monkeypatch
):
    binary = make_executable()
    (crashes_dir / "crash1").write_bytes(b"A")

    monkeypatch.setattr(triage, "gdb_is_available", lambda debugger: False)
    monkeypatch.setattr(triage, "run_direct", lambda binary, crash_file: "SIGSEGV")

    result = triage_crashes(str(crashes_dir), str(binary))
    assert result["reproduction_summary"] == {
        "crashed_on_first_run": 1,
        "reproducible": 1,
        "flaky": 0,
        "unstable_bucket": 0,
        "non_reproducible": 0,
    }
    entry = next(iter(result["groups"].values()))["crashes"][0]
    assert entry["reproducibility"] == "reproducible"
    assert entry["reproduction_rate"] == 1.0
    assert entry["flaky"] is False
    assert entry["unstable_bucket"] is False


def test_triage_crashes_reproducible_flags_flaky_when_not_every_run_crashes(
    crashes_dir, make_executable, monkeypatch
):
    binary = make_executable()
    (crashes_dir / "crash1").write_bytes(b"A")

    monkeypatch.setattr(triage, "gdb_is_available", lambda debugger: False)

    calls = {"n": 0}

    def fake_run_direct(binary, crash_file):
        calls["n"] += 1
        return "SIGSEGV" if calls["n"] <= 3 else "EXIT_0"

    monkeypatch.setattr(triage, "run_direct", fake_run_direct)

    result = triage_crashes(str(crashes_dir), str(binary), reproduction_runs=5)
    assert result["reproduction_summary"]["reproducible"] == 1
    entry = next(iter(result["groups"].values()))["crashes"][0]
    assert entry["reproducibility"] == "reproducible"
    assert entry["reproduction_rate"] == 3 / 5
    assert entry["flaky"] is True


def test_triage_crashes_flaky_when_reproduction_rate_below_50_percent(
    crashes_dir, make_executable, monkeypatch
):
    binary = make_executable()
    (crashes_dir / "crash1").write_bytes(b"A")

    monkeypatch.setattr(triage, "gdb_is_available", lambda debugger: False)

    calls = {"n": 0}

    def fake_run_direct(binary, crash_file):
        calls["n"] += 1
        return "SIGSEGV" if calls["n"] == 1 else "EXIT_0"

    monkeypatch.setattr(triage, "run_direct", fake_run_direct)

    result = triage_crashes(str(crashes_dir), str(binary), reproduction_runs=5)
    assert result["reproduction_summary"]["flaky"] == 1
    entry = next(iter(result["groups"].values()))["crashes"][0]
    assert entry["reproducibility"] == "flaky"
    assert entry["reproduction_rate"] == 1 / 5
    assert entry["flaky"] is False


def test_triage_crashes_unstable_bucket_when_hash_disagrees_across_runs(
    crashes_dir, make_executable, monkeypatch
):
    binary = make_executable()
    (crashes_dir / "crash1").write_bytes(b"A")

    stack_a = [{"frame": 0, "addr": "0x1", "func": "vuln", "file": "v.c", "line": 8}]
    stack_b = [{"frame": 0, "addr": "0x2", "func": "other_func", "file": "o.c", "line": 20}]
    calls = {"n": 0}

    def fake_try_sanitizer_triage(binary, crash_file):
        calls["n"] += 1
        stack = stack_a if calls["n"] % 2 == 1 else stack_b
        return {
            "sanitizer": "AddressSanitizer",
            "bug_class": "heap-buffer-overflow",
            "access_type": "write",
            "access_size": 8,
            "fault_addr": "0xdead",
            "crash_stack": stack,
            "alloc_stack": [],
            "free_stack": [],
            "sanitizer_raw": "==1==ERROR: heap-buffer-overflow ...",
        }

    monkeypatch.setattr(triage, "gdb_is_available", lambda debugger: False)
    monkeypatch.setattr(triage, "try_sanitizer_triage", fake_try_sanitizer_triage)

    result = triage_crashes(str(crashes_dir), str(binary), reproduction_runs=4)
    assert result["reproduction_summary"]["unstable_bucket"] == 1
    assert result["reproduction_summary"]["reproducible"] == 0
    entry = next(iter(result["groups"].values()))["crashes"][0]
    assert entry["reproducibility"] == "unstable-bucket"
    assert entry["unstable_bucket"] is True


def test_triage_crashes_reproduction_runs_is_configurable(
    crashes_dir, make_executable, monkeypatch
):
    binary = make_executable()
    (crashes_dir / "crash1").write_bytes(b"A")

    monkeypatch.setattr(triage, "gdb_is_available", lambda debugger: False)

    calls = {"n": 0}

    def fake_run_direct(binary, crash_file):
        calls["n"] += 1
        return "SIGSEGV"

    monkeypatch.setattr(triage, "run_direct", fake_run_direct)

    triage_crashes(str(crashes_dir), str(binary), reproduction_runs=2)
    assert calls["n"] == 2


def test_triage_crashes_records_environment_settings(
    crashes_dir, make_executable, monkeypatch
):
    binary = make_executable()
    (crashes_dir / "crash1").write_bytes(b"A")

    monkeypatch.setattr(triage, "gdb_is_available", lambda debugger: False)
    monkeypatch.setattr(triage, "run_direct", lambda binary, crash_file: "SIGSEGV")

    result = triage_crashes(str(crashes_dir), str(binary))
    env = result["environment"]
    assert env["asan_options"] == triage.REPRODUCTION_ASAN_OPTIONS
    assert env["ubsan_options"] == triage.REPRODUCTION_UBSAN_OPTIONS
    assert env["reproduction_runs"] == triage.DEFAULT_REPRODUCTION_RUNS
    assert "aslr_disabled" in env


# --------------------------------------------------------------------------
# try_sanitizer_triage / sanitizer_signature
# --------------------------------------------------------------------------

def test_try_sanitizer_triage_returns_none_when_no_sanitizer_output(monkeypatch):
    class FakeResult:
        stdout = "Program executed successfully\n"
        stderr = ""
        returncode = 0

    monkeypatch.setattr(triage.subprocess, "run", lambda *a, **k: FakeResult())
    assert try_sanitizer_triage("bin", "crash1") is None


def test_try_sanitizer_triage_returns_none_on_timeout(monkeypatch):
    def fake_run(cmd, capture_output, text, timeout, **kwargs):
        raise subprocess.TimeoutExpired(cmd, timeout)

    monkeypatch.setattr(triage.subprocess, "run", fake_run)
    assert try_sanitizer_triage("bin", "crash1") is None


def test_try_sanitizer_triage_parses_asan_from_stderr(monkeypatch):
    asan_stderr = (
        "==123==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xdead\n"
        "READ of size 1 at 0xdead thread T0\n"
        "    #0 0x401234 in vuln /tmp/vuln.c:8\n"
    )

    class FakeResult:
        stdout = ""
        stderr = asan_stderr
        returncode = 1

    monkeypatch.setattr(triage.subprocess, "run", lambda *a, **k: FakeResult())
    record = try_sanitizer_triage("bin", "crash1")
    assert record["bug_class"] == "heap-buffer-overflow"
    assert record["access_type"] == "read"
    assert record["crash_stack"][0]["func"] == "vuln"


def test_sanitizer_signature_includes_bug_class_access_and_location():
    record = {
        "bug_class": "heap-buffer-overflow",
        "access_type": "write",
        "access_size": 8,
        "crash_stack": [
            {"frame": 0, "addr": "0xdead", "func": "parse_header", "file": "p.c", "line": 42}
        ],
    }
    assert (
        sanitizer_signature(record)
        == "heap-buffer-overflow (write 8) in parse_header at p.c:42"
    )


def test_sanitizer_signature_handles_missing_stack_and_access_info():
    record = {"bug_class": "SEGV", "access_type": None, "access_size": None, "crash_stack": []}
    assert sanitizer_signature(record) == "SEGV"


def test_sanitizer_signature_skips_interceptor_frame_for_users_code():
    record = {
        "bug_class": "stack-buffer-overflow",
        "access_type": "write",
        "access_size": 101,
        "crash_stack": [
            {
                "frame": 0,
                "addr": "0x1111",
                "func": "__interceptor_strcpy",
                "file": "../../../../src/libsanitizer/asan/asan_interceptors.cpp",
                "line": 440,
            },
            {
                "frame": 1,
                "addr": "0x2222",
                "func": "vuln",
                "file": "vuln.c",
                "line": 8,
            },
        ],
    }
    assert (
        sanitizer_signature(record)
        == "stack-buffer-overflow (write 101) in vuln at vuln.c:8"
    )


def test_sanitizer_signature_falls_back_to_raw_top_frame_when_all_noise():
    record = {
        "bug_class": "stack-buffer-overflow",
        "access_type": "write",
        "access_size": 101,
        "crash_stack": [
            {
                "frame": 0,
                "addr": "0x1111",
                "func": "__interceptor_strcpy",
                "file": "../../../../src/libsanitizer/asan/asan_interceptors.cpp",
                "line": 440,
            },
        ],
    }
    assert (
        sanitizer_signature(record)
        == "stack-buffer-overflow (write 101) in __interceptor_strcpy "
        "at ../../../../src/libsanitizer/asan/asan_interceptors.cpp:440"
    )


# --------------------------------------------------------------------------
# triage_crashes -- sanitizer path wiring (mocked record)
# --------------------------------------------------------------------------

def test_triage_crashes_prefers_sanitizer_record_over_gdb(
    crashes_dir, make_executable, monkeypatch
):
    binary = make_executable()
    (crashes_dir / "crash1").write_bytes(b"A")

    fake_record = {
        "sanitizer": "AddressSanitizer",
        "bug_class": "heap-buffer-overflow",
        "access_type": "write",
        "access_size": 8,
        "fault_addr": "0xdead",
        "crash_stack": [
            {"frame": 0, "addr": "0xdead", "func": "parse_header", "file": "p.c", "line": 42}
        ],
        "alloc_stack": [],
        "free_stack": [],
        "sanitizer_raw": "==1==ERROR: AddressSanitizer: heap-buffer-overflow ...",
    }

    def _gdb_should_not_run(*args, **kwargs):
        raise AssertionError("gdb should not run when sanitizer output is present")

    monkeypatch.setattr(triage, "gdb_is_available", lambda debugger: True)
    monkeypatch.setattr(triage, "try_sanitizer_triage", lambda binary, crash_file: fake_record)
    monkeypatch.setattr(triage, "run_with_gdb", _gdb_should_not_run)

    result = triage_crashes(str(crashes_dir), str(binary))
    assert result["triage_mode"] == "sanitizer"
    assert result["unique_crash_frames"] == 1
    group = next(iter(result["groups"].values()))
    assert group["crashes"][0]["sanitizer"] == fake_record


def test_triage_crashes_falls_back_to_gdb_when_no_sanitizer_output(
    crashes_dir, make_executable, monkeypatch
):
    binary = make_executable()
    (crashes_dir / "crash1").write_bytes(b"A")

    monkeypatch.setattr(triage, "gdb_is_available", lambda debugger: True)
    monkeypatch.setattr(triage, "try_sanitizer_triage", lambda binary, crash_file: None)
    monkeypatch.setattr(
        triage, "run_with_gdb", lambda binary, crash_file, debugger: ("out", "err")
    )
    monkeypatch.setattr(triage, "extract_gdb_frame", lambda stdout, stderr: "#0 0xdead in vuln")

    result = triage_crashes(str(crashes_dir), str(binary))
    assert result["triage_mode"] == "gdb"
    entry = next(iter(result["groups"].values()))["crashes"][0]
    assert "sanitizer" not in entry


# --------------------------------------------------------------------------
# Real ASan-compiled binary integration test
# --------------------------------------------------------------------------

@pytest.mark.skipif(not ASAN_AVAILABLE, reason="gcc -fsanitize=address not available")
def test_triage_crashes_against_real_asan_binary(tmp_path, crashes_dir):
    repo_root = pathlib.Path(__file__).resolve().parents[1]
    src_path = repo_root / "examples" / "vuln-demo" / "vuln.c"
    assert src_path.exists()

    target = compile_vuln_asan_binary(tmp_path, src_path)
    # marker byte '1' selects vuln.c's stack-buffer-overflow path (see vuln.c's
    # module docstring for the full marker -> bug mapping).
    (crashes_dir / "crash1").write_bytes(b"1" + b"A" * 100)

    result = triage_crashes(str(crashes_dir), str(target))

    assert result["triage_mode"] == "sanitizer"
    assert result["total_crashes"] == 1
    group = next(iter(result["groups"].values()))
    record = group["crashes"][0]["sanitizer"]
    assert record["sanitizer"] == "AddressSanitizer"
    assert record["bug_class"] == "stack-buffer-overflow"
    assert record["access_type"] == "write"
    assert record["access_size"] > 64
    assert any(frame["func"] == "vuln_stack_overflow" for frame in record["crash_stack"])


# --------------------------------------------------------------------------
# parse_gdb_frames -- the multi-frame parse major/minor hashing needs
# --------------------------------------------------------------------------

def _gdb_bt_stdout(vuln_addr, main_addr, libc_addr):
    return (
        "Program received signal SIGSEGV, Segmentation fault.\n"
        f"0x{vuln_addr} in vuln (input=0x7fffffffe4d0 \"AAAA\") at vuln.c:8\n"
        "8\t  strcpy(buf, input);\n"
        f"#0  0x{vuln_addr} in vuln (input=0x7fffffffe4d0 \"AAAA\") at vuln.c:8\n"
        f"#1  0x{main_addr} in main (argc=2, argv=0x7fffffffe5c8) at vuln.c:20\n"
        f"#2  0x{libc_addr} in __libc_start_main ()\n"
    )


def test_parse_gdb_frames_returns_all_frames_not_just_first():
    stdout = _gdb_bt_stdout("0000555555554136", "00005555555541b0", "00007ffff7a29d8f")
    frames = triage.parse_gdb_frames(stdout)
    assert [f["func"] for f in frames] == ["vuln", "main", "__libc_start_main"]
    assert frames[0]["file"] == "vuln.c"
    assert frames[0]["line"] == 8
    assert frames[1]["file"] == "vuln.c"
    assert frames[1]["line"] == 20


def test_parse_gdb_frames_empty_for_timeout():
    assert triage.parse_gdb_frames("TIMEOUT") == []


def test_parse_gdb_frames_empty_when_no_frame_lines():
    assert triage.parse_gdb_frames("no frames here") == []


# --------------------------------------------------------------------------
# triage_crashes -- major/minor stack-hash dedup (ROADMAP 2.2)
# --------------------------------------------------------------------------

def test_triage_crashes_collapses_aslr_shifted_gdb_backtraces(
    crashes_dir, make_executable, monkeypatch
):
    binary = make_executable()
    (crashes_dir / "crash1").write_bytes(b"A" * 10)
    (crashes_dir / "crash2").write_bytes(b"B" * 20)

    monkeypatch.setattr(triage, "gdb_is_available", lambda debugger: True)

    outputs = {
        "crash1": _gdb_bt_stdout("0000555555554136", "00005555555541b0", "00007ffff7a29d8f"),
        "crash2": _gdb_bt_stdout("0000611234abc136", "0000611234abc1b0", "00007f0011229d8f"),
    }

    def fake_run_with_gdb(binary, crash_file, debugger):
        for name, out in outputs.items():
            if name in crash_file:
                return out, ""
        raise AssertionError(crash_file)

    monkeypatch.setattr(triage, "run_with_gdb", fake_run_with_gdb)

    result = triage_crashes(str(crashes_dir), str(binary))
    assert result["triage_mode"] == "gdb"
    assert result["total_crashes"] == 2
    # Same bug, ASLR-shifted addresses -> one group, not two.
    assert result["unique_crash_frames"] == 1
    group = next(iter(result["groups"].values()))
    assert group["count"] == 2


def test_triage_crashes_keeps_genuinely_different_gdb_stacks_separate(
    crashes_dir, make_executable, monkeypatch
):
    binary = make_executable()
    (crashes_dir / "crash1").write_bytes(b"A" * 10)
    (crashes_dir / "crash2").write_bytes(b"B" * 20)

    monkeypatch.setattr(triage, "gdb_is_available", lambda debugger: True)

    stack_a = _gdb_bt_stdout("0000555555554136", "00005555555541b0", "00007ffff7a29d8f")
    stack_b = (
        "Program received signal SIGSEGV, Segmentation fault.\n"
        "0x0000555555559999 in parse_header (data=0x0) at parse.c:42\n"
        "#0  0x0000555555559999 in parse_header (data=0x0) at parse.c:42\n"
        "#1  0x000055555555a000 in main (argc=1, argv=0x0) at parse.c:100\n"
    )

    def fake_run_with_gdb(binary, crash_file, debugger):
        if "crash1" in crash_file:
            return stack_a, ""
        return stack_b, ""

    monkeypatch.setattr(triage, "run_with_gdb", fake_run_with_gdb)

    result = triage_crashes(str(crashes_dir), str(binary))
    assert result["triage_mode"] == "gdb"
    # Genuinely different bugs -> two groups, not merged.
    assert result["unique_crash_frames"] == 2
    counts = sorted(group["count"] for group in result["groups"].values())
    assert counts == [1, 1]


def test_triage_crashes_gdb_group_label_is_readable_top_frame(
    crashes_dir, make_executable, monkeypatch
):
    binary = make_executable()
    (crashes_dir / "crash1").write_bytes(b"A")

    monkeypatch.setattr(triage, "gdb_is_available", lambda debugger: True)
    monkeypatch.setattr(
        triage,
        "run_with_gdb",
        lambda binary, crash_file, debugger: (
            _gdb_bt_stdout("0000555555554136", "00005555555541b0", "00007ffff7a29d8f"),
            "",
        ),
    )

    result = triage_crashes(str(crashes_dir), str(binary))
    label = next(iter(result["groups"].keys()))
    assert label == "#0 0x0000555555554136 in vuln at vuln.c:8"


def test_triage_crashes_sanitizer_bug_class_distinguishes_same_top_frame(
    crashes_dir, make_executable, monkeypatch
):
    binary = make_executable()
    (crashes_dir / "crash1").write_bytes(b"A")
    (crashes_dir / "crash2").write_bytes(b"B")

    shared_stack = [
        {"frame": 0, "addr": "0xdead", "func": "parse_header", "file": "p.c", "line": 42}
    ]
    records = {
        "crash1": {
            "sanitizer": "AddressSanitizer",
            "bug_class": "heap-buffer-overflow",
            "access_type": "write",
            "access_size": 8,
            "fault_addr": "0xdead",
            "crash_stack": shared_stack,
            "alloc_stack": [],
            "free_stack": [],
            "sanitizer_raw": "==1==ERROR: heap-buffer-overflow ...",
        },
        "crash2": {
            "sanitizer": "AddressSanitizer",
            "bug_class": "heap-use-after-free",
            "access_type": "read",
            "access_size": 1,
            "fault_addr": "0xdead",
            "crash_stack": shared_stack,
            "alloc_stack": [],
            "free_stack": [],
            "sanitizer_raw": "==2==ERROR: heap-use-after-free ...",
        },
    }

    monkeypatch.setattr(triage, "gdb_is_available", lambda debugger: True)

    def fake_try_sanitizer_triage(binary, crash_file):
        for name, record in records.items():
            if name in crash_file:
                return record
        raise AssertionError(crash_file)

    monkeypatch.setattr(triage, "try_sanitizer_triage", fake_try_sanitizer_triage)

    result = triage_crashes(str(crashes_dir), str(binary))
    assert result["triage_mode"] == "sanitizer"
    # Same top frame, different bug class -> must not collapse into one bug.
    assert result["unique_crash_frames"] == 2
