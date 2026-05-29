import subprocess

import pytest

from autofte import binary_analysis
from autofte.binary_analysis import BinaryAnalyzer, _run_tool, analyze_binary

from .conftest import (
    GCC_AVAILABLE,
    compile_vuln_binary,
    file_output,
    ldd_output,
    nm_dynamic,
    objdump_symtab,
    readelf_dynamic,
    readelf_header,
    readelf_program_headers,
)

# --------------------------------------------------------------------------
# _run_tool
# --------------------------------------------------------------------------

def test_run_tool_missing_binary(monkeypatch):
    def fake_run(args, **kwargs):
        raise FileNotFoundError()

    monkeypatch.setattr(binary_analysis.subprocess, "run", fake_run)
    ok, stdout, error = _run_tool(["totally-not-a-real-tool", "x"])
    assert ok is False
    assert "not installed" in error


def test_run_tool_timeout(monkeypatch):
    def fake_run(args, **kwargs):
        raise subprocess.TimeoutExpired(args, kwargs.get("timeout", 15))

    monkeypatch.setattr(binary_analysis.subprocess, "run", fake_run)
    ok, stdout, error = _run_tool(["readelf", "x"])
    assert ok is False
    assert "timed out" in error


def test_run_tool_nonzero_exit(monkeypatch):
    class FakeResult:
        stdout = "partial"
        stderr = "boom"
        returncode = 1

    monkeypatch.setattr(binary_analysis.subprocess, "run", lambda *a, **k: FakeResult())
    ok, stdout, error = _run_tool(["readelf", "x"])
    assert ok is False
    assert error == "boom"


def test_run_tool_nonzero_exit_no_stderr_uses_fallback_message(monkeypatch):
    class FakeResult:
        stdout = ""
        stderr = "   "
        returncode = 2

    monkeypatch.setattr(binary_analysis.subprocess, "run", lambda *a, **k: FakeResult())
    ok, stdout, error = _run_tool(["readelf", "x"])
    assert ok is False
    assert "exited 2" in error


def test_run_tool_success(monkeypatch):
    class FakeResult:
        stdout = "output here"
        stderr = ""
        returncode = 0

    monkeypatch.setattr(binary_analysis.subprocess, "run", lambda *a, **k: FakeResult())
    ok, stdout, error = _run_tool(["readelf", "x"])
    assert ok is True
    assert stdout == "output here"
    assert error == ""


# --------------------------------------------------------------------------
# Individual protection checks, mocked subprocess.run per-tool
# --------------------------------------------------------------------------

def _install_tool_map(monkeypatch, mapping):
    """mapping: {tool_name: FakeResult-ish object or callable(args)->result}."""

    def fake_run(args, **kwargs):
        tool = args[0]
        if tool not in mapping:
            raise FileNotFoundError(tool)
        handler = mapping[tool]
        if callable(handler):
            return handler(args)
        return handler

    monkeypatch.setattr(binary_analysis.subprocess, "run", fake_run)


class R:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def test_check_nx_bit_enabled_and_disabled(monkeypatch):
    analyzer = BinaryAnalyzer("bin")

    _install_tool_map(monkeypatch, {"readelf": R(readelf_program_headers(nx_enabled=True))})
    result = analyzer._check_nx_bit()
    assert result["enabled"] is True

    _install_tool_map(monkeypatch, {"readelf": R(readelf_program_headers(nx_enabled=False))})
    result = analyzer._check_nx_bit()
    assert result["enabled"] is False


def test_check_nx_bit_tool_error(monkeypatch):
    analyzer = BinaryAnalyzer("bin")
    _install_tool_map(monkeypatch, {})
    result = analyzer._check_nx_bit()
    assert "error" in result


def test_check_stack_canaries_found(monkeypatch):
    analyzer = BinaryAnalyzer("bin")
    _install_tool_map(
        monkeypatch,
        {
            "objdump": R(objdump_symtab(has_canary=True)),
            "strings": R("stack smashing detected\nother string\n"),
        },
    )
    result = analyzer._check_stack_canaries()
    assert result["enabled"] is True
    assert "__stack_chk_fail" in result["symbols_found"]
    assert result["related_strings"]


def test_check_stack_canaries_absent(monkeypatch):
    analyzer = BinaryAnalyzer("bin")
    _install_tool_map(
        monkeypatch,
        {"objdump": R(objdump_symtab(has_canary=False)), "strings": R("nothing interesting\n")},
    )
    result = analyzer._check_stack_canaries()
    assert result["enabled"] is False
    assert result["symbols_found"] == []


def test_check_pie_enabled_and_disabled(monkeypatch):
    analyzer = BinaryAnalyzer("bin")
    _install_tool_map(monkeypatch, {"readelf": R(readelf_header(pie=True))})
    assert analyzer._check_pie()["enabled"] is True

    _install_tool_map(monkeypatch, {"readelf": R(readelf_header(pie=False))})
    assert analyzer._check_pie()["enabled"] is False


def test_check_relro_full(monkeypatch):
    analyzer = BinaryAnalyzer("bin")

    def fake_run(args, **kwargs):
        if args[1] == "-l":
            return R(readelf_program_headers(relro=True))
        if args[1] == "-d":
            return R(readelf_dynamic(bind_now=True))
        raise AssertionError(args)

    monkeypatch.setattr(binary_analysis.subprocess, "run", fake_run)
    result = analyzer._check_relro()
    assert result["status"] == "Full RELRO"
    assert result["gnu_relro"] is True
    assert result["bind_now"] is True


def test_check_relro_partial(monkeypatch):
    analyzer = BinaryAnalyzer("bin")

    def fake_run(args, **kwargs):
        if args[1] == "-l":
            return R(readelf_program_headers(relro=True))
        if args[1] == "-d":
            return R(readelf_dynamic(bind_now=False))
        raise AssertionError(args)

    monkeypatch.setattr(binary_analysis.subprocess, "run", fake_run)
    result = analyzer._check_relro()
    assert result["status"] == "Partial RELRO"


def test_check_relro_none(monkeypatch):
    analyzer = BinaryAnalyzer("bin")

    def fake_run(args, **kwargs):
        if args[1] == "-l":
            return R(readelf_program_headers(relro=False))
        if args[1] == "-d":
            return R(readelf_dynamic(bind_now=False))
        raise AssertionError(args)

    monkeypatch.setattr(binary_analysis.subprocess, "run", fake_run)
    result = analyzer._check_relro()
    assert result["status"] == "No RELRO"


def test_check_fortify_detects_functions(monkeypatch):
    analyzer = BinaryAnalyzer("bin")
    fortified = ("__printf_chk", "__strcpy_chk")
    _install_tool_map(
        monkeypatch,
        {"objdump": R(objdump_symtab(has_canary=False, fortified=fortified))},
    )
    result = analyzer._check_fortify()
    assert result["enabled"] is True
    assert result["fortified_functions"] == ["__printf_chk", "__strcpy_chk"]


def test_check_fortify_none(monkeypatch):
    analyzer = BinaryAnalyzer("bin")
    _install_tool_map(monkeypatch, {"objdump": R(objdump_symtab(has_canary=False))})
    result = analyzer._check_fortify()
    assert result["enabled"] is False


def test_analyze_symbols_finds_dangerous_functions_with_address_column(monkeypatch):
    """A locally-defined/exported symbol line carries an address column
    (3 whitespace-separated tokens: addr, type, name).
    """
    analyzer = BinaryAnalyzer("bin")
    _install_tool_map(
        monkeypatch,
        {
            "nm": R(
                nm_dynamic(imports=("strcpy", "gets", "printf"), with_address_column=True)
            )
        },
    )
    result = analyzer._analyze_symbols()
    assert set(result["dangerous_functions_found"]) == {"strcpy", "gets"}
    assert result["total_imported_functions"] == 3


def test_analyze_symbols_misses_dangerous_functions_on_real_nm_output(monkeypatch):
    """Documents a real parsing bug (not fixed here, see test-suite report):
    real `nm -D` leaves the address column blank for undefined dynamic
    symbols, so a genuine line like "                 U strcpy@GLIBC_2.2.5"
    only has 2 whitespace-separated tokens. `_analyze_symbols` requires
    `len(parts) >= 3`, so on a real binary it silently finds zero
    imported/dangerous functions even when strcpy is very much imported.
    """
    analyzer = BinaryAnalyzer("bin")
    _install_tool_map(
        monkeypatch,
        {"nm": R(nm_dynamic(imports=("strcpy", "gets", "printf"), with_address_column=False))},
    )
    result = analyzer._analyze_symbols()
    assert result["dangerous_functions_found"] == []
    assert result["total_imported_functions"] == 0


def test_get_dynamic_libraries(monkeypatch):
    analyzer = BinaryAnalyzer("bin")
    _install_tool_map(monkeypatch, {"ldd": R(ldd_output(libs=("libc.so.6", "libm.so.6")))})
    result = analyzer._get_dynamic_libraries()
    assert result["count"] == 2


def test_get_dynamic_libraries_tool_missing(monkeypatch):
    analyzer = BinaryAnalyzer("bin")
    _install_tool_map(monkeypatch, {})
    result = analyzer._get_dynamic_libraries()
    assert result["libraries"] == []
    assert result["count"] == 0
    assert "error" in result


def test_get_file_info_parses_arch_format_stripped(monkeypatch):
    analyzer = BinaryAnalyzer("bin")
    _install_tool_map(monkeypatch, {"file": R(file_output(arch="x86-64", stripped=False))})
    result = analyzer._get_file_info()
    assert result["architecture"] == "x86_64"
    assert result["format"] == "ELF"
    assert result["stripped"] is False


def test_analyze_checksec_unavailable(monkeypatch):
    analyzer = BinaryAnalyzer("bin")
    _install_tool_map(monkeypatch, {})
    result = analyzer._analyze_checksec()
    assert result["checksec_available"] is False


def test_check_system_aslr_reads_proc(monkeypatch, tmp_path):
    analyzer = BinaryAnalyzer("bin")
    fake_proc = tmp_path / "randomize_va_space"
    fake_proc.write_text("2\n")

    real_open = open

    def fake_open(path, *args, **kwargs):
        if path == "/proc/sys/kernel/randomize_va_space":
            return real_open(fake_proc, *args, **kwargs)
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(binary_analysis.os.path, "exists", lambda p: True)
    monkeypatch.setattr("builtins.open", fake_open)
    result = analyzer._check_system_aslr()
    assert result["value"] == "2"
    assert result["enabled"] is True
    assert "Full" in result["status"]


def test_check_system_aslr_missing_proc_path(monkeypatch):
    analyzer = BinaryAnalyzer("bin")
    monkeypatch.setattr(binary_analysis.os.path, "exists", lambda p: False)
    result = analyzer._check_system_aslr()
    assert "Cannot determine" in result["status"]


# --------------------------------------------------------------------------
# _summarize_mitigations scoring
# --------------------------------------------------------------------------

def test_summarize_mitigations_all_protections_high():
    analyzer = BinaryAnalyzer("bin")
    analyzer.protections = {
        "aslr_system": {"enabled": True},
        "nx_bit": {"enabled": True},
        "stack_canaries": {"enabled": True},
        "pie": {"enabled": True},
        "relro": {"status": "Full RELRO"},
    }
    summary = analyzer._summarize_mitigations()
    assert summary["protection_level"] == "High"
    assert summary["exploit_difficulty"] == "Hard"
    assert summary["protection_count"] == 5
    assert summary["vulnerable_areas"] == []


def test_summarize_mitigations_none_low():
    analyzer = BinaryAnalyzer("bin")
    analyzer.protections = {
        "aslr_system": {"enabled": False},
        "nx_bit": {"enabled": False},
        "stack_canaries": {"enabled": False},
        "pie": {"enabled": False},
        "relro": {"status": "No RELRO"},
    }
    summary = analyzer._summarize_mitigations()
    assert summary["protection_level"] == "Low"
    assert summary["exploit_difficulty"] == "Easy"
    assert summary["protection_count"] == 0
    assert len(summary["vulnerable_areas"]) == 5
    assert summary["recommended_approach"] == "Direct exploitation possible - minimal protections"


def test_summarize_mitigations_partial_relro_counts_half():
    analyzer = BinaryAnalyzer("bin")
    analyzer.protections = {
        "aslr_system": {"enabled": True},
        "nx_bit": {"enabled": True},
        "stack_canaries": {"enabled": False},
        "pie": {"enabled": False},
        "relro": {"status": "Partial RELRO"},
    }
    summary = analyzer._summarize_mitigations()
    assert summary["protection_count"] == 2.5
    assert summary["protection_level"] == "Medium"
    assert summary["exploit_difficulty"] == "Medium"


def test_summarize_mitigations_medium_boundary():
    analyzer = BinaryAnalyzer("bin")
    analyzer.protections = {
        "aslr_system": {"enabled": True},
        "nx_bit": {"enabled": True},
        "stack_canaries": {"enabled": False},
        "pie": {"enabled": False},
        "relro": {"status": "No RELRO"},
    }
    summary = analyzer._summarize_mitigations()
    assert summary["protection_count"] == 2
    assert summary["protection_level"] == "Medium"


def test_recommend_approach_orders_steps_by_priority():
    steps = BinaryAnalyzer._recommend_approach(
        [
            "PIE bypass (code base leak required)",
            "NX bypass (ROP/JOP required)",
            "ASLR bypass (info leak required)",
            "Stack canary bypass (leak or bruteforce)",
        ]
    )
    assert steps == (
        "Build ROP chain for code execution -> "
        "Find information leak to defeat ASLR -> "
        "Leak or bruteforce stack canary -> "
        "Leak code base address for PIE bypass"
    )


def test_recommend_approach_empty_techniques():
    assert (
        BinaryAnalyzer._recommend_approach([])
        == "Direct exploitation possible - minimal protections"
    )


# --------------------------------------------------------------------------
# analyze_all_protections / analyze_binary end-to-end, fully mocked
# --------------------------------------------------------------------------

def test_analyze_all_protections_returns_full_shape(monkeypatch, tmp_path):
    def fake_run(args, **kwargs):
        tool = args[0]
        if tool == "file":
            return R(file_output())
        if tool == "checksec":
            return R("", "", 1)
        if tool == "readelf":
            if args[1] == "-l":
                return R(readelf_program_headers(nx_enabled=True, relro=True))
            if args[1] == "-h":
                return R(readelf_header(pie=True))
            if args[1] == "-d":
                return R(readelf_dynamic(bind_now=True))
        if tool == "objdump":
            return R(objdump_symtab(has_canary=True))
        if tool == "strings":
            return R("")
        if tool == "nm":
            return R(nm_dynamic())
        if tool == "ldd":
            return R(ldd_output())
        raise FileNotFoundError(tool)

    monkeypatch.setattr(binary_analysis.subprocess, "run", fake_run)
    monkeypatch.setattr(binary_analysis.os.path, "exists", lambda p: False)

    result = analyze_binary(str(tmp_path / "target"))
    assert "exploit_mitigation_summary" in result
    assert result["nx_bit"]["enabled"] is True
    assert result["pie"]["enabled"] is True
    assert result["relro"]["status"] == "Full RELRO"
    assert result["stack_canaries"]["enabled"] is True
    assert result["exploit_mitigation_summary"]["protection_level"] in {"High", "Medium", "Low"}


# --------------------------------------------------------------------------
# Real compiled binary integration test
# --------------------------------------------------------------------------

@pytest.mark.skipif(not GCC_AVAILABLE, reason="gcc not available")
def test_analyze_binary_against_real_compiled_binary(tmp_path):
    src = "examples/vuln-demo/vuln.c"
    import pathlib

    repo_root = pathlib.Path(__file__).resolve().parents[1]
    src_path = repo_root / src
    assert src_path.exists()

    target = compile_vuln_binary(tmp_path, src_path)
    result = analyze_binary(str(target))

    # Compiled with -fno-stack-protector -no-pie -z execstack: weak binary.
    assert result["nx_bit"]["enabled"] is False
    assert result["pie"]["enabled"] is False
    assert result["stack_canaries"]["enabled"] is False
    summary = result["exploit_mitigation_summary"]
    assert summary["protection_level"] == "Low"
    assert "No PIE - fixed code addresses" in summary["vulnerable_areas"]
    assert "NX disabled - shellcode execution possible" in summary["vulnerable_areas"]
