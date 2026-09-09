import pytest

from autofte import minimize


def test_ddmin_reduces_to_minimal_crashing_subset():
    data = b"AAAA" + b"NEEDLE" + b"BBBBBBBBBBBBBBBB"
    out = minimize.ddmin(data, lambda c: b"NEEDLE" in c)
    assert out == b"NEEDLE"


def test_ddmin_leaves_data_when_every_byte_matters():
    data = b"abcd"
    out = minimize.ddmin(data, lambda c: c == b"abcd")
    assert out == b"abcd"


def test_ddmin_handles_single_byte():
    assert minimize.ddmin(b"X", lambda c: True) == b"X"


def _fixture_target(tmp_path):
    crash = tmp_path / "crash"
    crash.write_bytes(b"HEAD" + b"Z" * 60 + b"TAIL")
    binary = tmp_path / "target"
    binary.write_text("#!/bin/sh\nexit 1\n")
    binary.chmod(0o755)
    return binary, crash


def test_minimize_file_returns_none_when_input_does_not_crash(tmp_path, monkeypatch):
    binary, crash = _fixture_target(tmp_path)
    monkeypatch.setattr(minimize, "crash_signature", lambda *a, **k: None)
    assert minimize.minimize_file(str(binary), str(crash)) is None


def test_minimize_file_uses_ddmin_and_preserves_signature(tmp_path, monkeypatch):
    binary, crash = _fixture_target(tmp_path)
    monkeypatch.setattr(minimize, "afl_tmin_available", lambda: False)

    def fake_signature(bin_path, path, debugger="gdb"):
        data = open(path, "rb").read()
        return ("signal", "SIGSEGV") if b"TAIL" in data else None

    monkeypatch.setattr(minimize, "crash_signature", fake_signature)

    out_path = tmp_path / "min"
    result = minimize.minimize_file(str(binary), str(crash), output_path=str(out_path))

    assert result["tool"] == "ddmin"
    assert result["minimized_size"] < result["original_size"]
    assert result["reduction_percent"] > 0
    assert b"TAIL" in out_path.read_bytes()
    assert result["signature"] == ["signal", "SIGSEGV"]


def test_minimize_file_prefers_afl_tmin_when_available(tmp_path, monkeypatch):
    binary, crash = _fixture_target(tmp_path)
    monkeypatch.setattr(minimize, "afl_tmin_available", lambda: True)
    monkeypatch.setattr(minimize, "crash_signature", lambda *a, **k: ("signal", "SIGSEGV"))

    def fake_tmin(bin_path, in_path, out_path, timeout):
        open(out_path, "wb").write(b"TINY")
        return True

    monkeypatch.setattr(minimize, "_run_afl_tmin", fake_tmin)

    result = minimize.minimize_file(str(binary), str(crash))
    assert result["tool"] == "afl-tmin"
    assert result["minimized_size"] == 4


def test_minimize_file_falls_back_when_afl_tmin_breaks_signature(tmp_path, monkeypatch):
    binary, crash = _fixture_target(tmp_path)
    monkeypatch.setattr(minimize, "afl_tmin_available", lambda: True)

    calls = {"n": 0}

    def fake_signature(bin_path, path, debugger="gdb"):
        calls["n"] += 1
        data = open(path, "rb").read()
        if data == b"WRONG":
            return ("signal", "SIGABRT")
        return ("signal", "SIGSEGV") if b"TAIL" in data else None

    monkeypatch.setattr(minimize, "crash_signature", fake_signature)
    monkeypatch.setattr(
        minimize, "_run_afl_tmin",
        lambda *a: (open(a[2], "wb").write(b"WRONG") or True),
    )

    result = minimize.minimize_file(str(binary), str(crash))
    assert result["tool"] == "ddmin"


@pytest.mark.parametrize("present", [True, False])
def test_afl_tmin_available_reflects_path(monkeypatch, present):
    monkeypatch.setattr(minimize.shutil, "which", lambda name: "/x/afl-tmin" if present else None)
    assert minimize.afl_tmin_available() is present
