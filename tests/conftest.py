"""Shared fixtures and small fake-output builders for the test suite."""

import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def make_executable(tmp_path):
    """Create a tiny fake "binary" file (a shell script) that is +x."""

    def _make(name="target", body="#!/bin/sh\nexit 0\n"):
        path = tmp_path / name
        path.write_text(body)
        path.chmod(0o755)
        return path

    return _make


@pytest.fixture
def crashes_dir(tmp_path):
    d = tmp_path / "crashes"
    d.mkdir()
    return d


class FakeCompletedProcess:
    """Minimal stand-in for subprocess.CompletedProcess."""

    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


@pytest.fixture
def fake_run(monkeypatch):
    """Patch subprocess.run in a target module with a scripted responder.

    Usage:
        fake_run(binary_analysis, {"readelf": FakeCompletedProcess(...)})

    The responder dict is keyed by the first argument (tool name); a
    callable value receives the full args list and must return a
    FakeCompletedProcess (or raise).
    """

    def _install(module, responses, default=None):
        def _fake(args, *a, **kw):
            key = args[0] if isinstance(args, (list, tuple)) else args
            handler = responses.get(key, default)
            if handler is None:
                raise FileNotFoundError(key)
            if callable(handler):
                return handler(args)
            return handler

        monkeypatch.setattr(module.subprocess, "run", _fake)
        return _fake

    return _install


def readelf_program_headers(nx_enabled=True, relro=True):
    """Fake `readelf -l` output.

    Real readelf wraps each program header across two lines: the header
    line itself (type + offset/addr columns) and a continuation line that
    carries the RWE/RW permission flags + alignment. GNU_STACK's
    permission flags live on that continuation line, not the header line.
    """
    stack_lines = (
        "  GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000\n"
        "                 0x0000000000000000 0x0000000000000000  "
        + ("RW " if nx_enabled else "RWE")
        + "    0x10\n"
    )
    relro_line = (
        "  GNU_RELRO      0x000df0 0x00003df0 0x00003df0 0x000210 0x000210 R   0x1\n"
        if relro
        else ""
    )
    return (
        "Elf file type is EXEC (Executable file)\n"
        "Program Headers:\n"
        "  Type           Offset             VirtAddr           PhysAddr\n"
        f"{relro_line}"
        f"{stack_lines}"
    )


def readelf_header(pie=False):
    file_type = "DYN (Position-Independent Executable file)" if pie else "EXEC (Executable file)"
    return f"ELF Header:\n  Type:                              {file_type}\n"


def readelf_dynamic(bind_now=True):
    if bind_now:
        return " 0x0000000000000018 (BIND_NOW)\n 0x000000006ffffffb (FLAGS)              BIND_NOW\n"
    return " 0x0000000000000015 (DEBUG)               0x0\n"


def objdump_symtab(has_canary=True, fortified=()):
    lines = ["SYMBOL TABLE:"]
    if has_canary:
        lines.append("0000000000000000 g     F *UND*  0000000000000000 __stack_chk_fail")
        lines.append("0000000000000000 g     F *UND*  0000000000000000 __stack_chk_guard")
    for func in fortified:
        lines.append(f"0000000000000000 g     F *UND*  0000000000000000 {func}")
    return "\n".join(lines) + "\n"


def nm_dynamic(imports=("strcpy", "printf", "malloc"), with_address_column=False):
    """Fake `nm -D` output.

    Real `nm -D` leaves the address column blank for undefined symbols,
    so a real line looks like "                 U strcpy@GLIBC_2.2.5"
    which `str.split()` turns into only 2 tokens (["U", "strcpy@..."]),
    not 3. Pass with_address_column=True to instead emit a 3-token line
    (address + type + name), which is the shape autofte's parser
    actually expects.
    """
    lines = []
    for name in imports:
        if with_address_column:
            lines.append(f"0000000000000000 U {name}")
        else:
            lines.append(f"                 U {name}")
    return "\n".join(lines) + "\n"


def file_output(arch="x86-64", elf=True, stripped=False):
    parts = []
    if elf:
        parts.append("ELF 64-bit LSB executable")
    if arch:
        parts.append(arch)
        parts.append(arch)
    parts.append("not stripped" if not stripped else "stripped")
    return ", ".join(parts)


def ldd_output(libs=("libc.so.6",)):
    return "".join(f"\t{lib} => /lib/x86_64-linux-gnu/{lib} (0x00007f0000000000)\n" for lib in libs)


GCC_AVAILABLE = shutil.which("gcc") is not None


def compile_vuln_binary(dst_dir, src_path):
    """Compile examples/vuln-demo/vuln.c into dst_dir/target with weak flags."""
    target = dst_dir / "target"
    subprocess.run(
        [
            "gcc",
            "-O0",
            "-g",
            "-fno-stack-protector",
            "-no-pie",
            "-z",
            "execstack",
            "-o",
            str(target),
            str(src_path),
        ],
        check=True,
        capture_output=True,
    )
    return target


def _detect_asan_available():
    if not GCC_AVAILABLE:
        return False
    with tempfile.TemporaryDirectory(prefix="autofte-asan-probe-") as probe_dir:
        probe_src = Path(probe_dir) / "probe.c"
        probe_src.write_text("int main(void) { return 0; }\n")
        result = subprocess.run(
            ["gcc", "-fsanitize=address", "-o", str(Path(probe_dir) / "probe"), str(probe_src)],
            capture_output=True,
        )
        return result.returncode == 0


ASAN_AVAILABLE = _detect_asan_available()


def compile_vuln_asan_binary(dst_dir, src_path):
    """Compile examples/vuln-demo/vuln.c with -fsanitize=address."""
    target = dst_dir / "target_asan"
    subprocess.run(
        ["gcc", "-fsanitize=address", "-g", "-O0", "-o", str(target), str(src_path)],
        check=True,
        capture_output=True,
    )
    return target
