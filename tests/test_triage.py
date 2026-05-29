import signal
import subprocess

import pytest

from autofte import triage
from autofte.triage import (
    extract_gdb_frame,
    gdb_is_available,
    run_direct,
    run_with_gdb,
    triage_crashes,
)

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
    def fake_run(cmd, capture_output, text, timeout):
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
    def fake_run(cmd, capture_output, text, timeout):
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
    assert result == {
        "total_crashes": 0,
        "unique_crash_frames": 0,
        "triage_mode": "empty",
        "groups": {},
    }


def test_triage_crashes_ignores_readme(crashes_dir, make_executable, monkeypatch):
    binary = make_executable()
    (crashes_dir / "README.txt").write_text("readme")
    (crashes_dir / "id:000000").write_bytes(b"AAAA")

    monkeypatch.setattr(triage, "gdb_is_available", lambda debugger: False)
    monkeypatch.setattr(triage, "run_direct", lambda binary, crash_file: "SIGSEGV")

    result = triage_crashes(str(crashes_dir), str(binary))
    assert result["total_crashes"] == 1
    assert result["triage_mode"] == "direct"


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
