import pytest

from autofte import disasm

OBJDUMP_FIXTURE = """\
target_asan:     file format elf64-x86-64

Disassembly of section .text:

0000000000105a00 <other_func>:
  105a00:\tpush   %rbp
  105a04:\tret

0000000000105b30 <vuln_stack_overflow>:
  105b30:\tpush   %rbp
  105b31:\tmov    %rsp,%rbp
  105b34:\tpush   %rbx
  105b39:\tsub    $0x80,%rsp
  105b40:\tmov    %rsp,%rbx
  105b62:\tcall   3b400 <__asan_stack_malloc_1>
  105b6b:\tmov    0x38(%rbx),%rax
  105b73:\tcmp    $0x0,%rax

0000000000105c00 <next_func>:
  105c00:\tret
"""


def _crash_record(func="vuln_stack_overflow", addr="0x105b40"):
    return {
        "crash_stack": [
            {"frame": 0, "addr": addr, "func": func, "file": "vuln.c", "line": 39},
            {"frame": 1, "addr": "0x1", "func": "main", "file": "vuln.c", "line": 20},
        ]
    }


def test_fault_function_name_picks_first_symbolized_frame():
    assert disasm.fault_function_name(_crash_record()) == "vuln_stack_overflow"
    assert disasm.fault_function_name({"crash_stack": [{"func": None}]}) is None
    assert disasm.fault_function_name(None) is None


def test_fault_function_name_skips_sanitizer_interceptor_frames():
    record = {
        "crash_stack": [
            {"frame": 0, "func": "__interceptor_memcpy", "file": None, "line": None},
            {"frame": 1, "func": "copy_row", "file": "img.c", "line": 88},
            {"frame": 2, "func": "main", "file": "img.c", "line": 12},
        ]
    }
    assert disasm.fault_function_name(record) == "copy_row"


def test_disassemble_fault_context_windows_around_fault(monkeypatch):
    monkeypatch.setattr(disasm, "objdump_available", lambda: True)
    monkeypatch.setattr(disasm, "_run_objdump", lambda binary: OBJDUMP_FIXTURE)

    out = disasm.disassemble_fault_context("bin", _crash_record(), window=2)

    assert "Disassembly of vuln_stack_overflow" in out
    assert "->" in out
    assert "105b40: mov    %rsp,%rbx" in out
    assert "-> 105b40" in out
    assert "other_func" not in out
    assert "next_func" not in out


def test_disassemble_fault_context_falls_back_to_function_start(monkeypatch):
    monkeypatch.setattr(disasm, "objdump_available", lambda: True)
    monkeypatch.setattr(disasm, "_run_objdump", lambda binary: OBJDUMP_FIXTURE)

    out = disasm.disassemble_fault_context("bin", _crash_record(addr=None), window=3)

    assert out.splitlines()[1].strip().startswith("105b30:")


def test_disassemble_fault_context_none_without_objdump(monkeypatch):
    monkeypatch.setattr(disasm, "objdump_available", lambda: False)
    assert disasm.disassemble_fault_context("bin", _crash_record()) is None


def test_disassemble_fault_context_none_when_objdump_fails(monkeypatch):
    monkeypatch.setattr(disasm, "objdump_available", lambda: True)
    monkeypatch.setattr(disasm, "_run_objdump", lambda binary: None)
    assert disasm.disassemble_fault_context("bin", _crash_record()) is None


def test_disassemble_fault_context_none_when_function_not_in_dump(monkeypatch):
    monkeypatch.setattr(disasm, "objdump_available", lambda: True)
    monkeypatch.setattr(disasm, "_run_objdump", lambda binary: OBJDUMP_FIXTURE)
    assert disasm.disassemble_fault_context("bin", _crash_record(func="nope")) is None


@pytest.mark.parametrize("record", [None, {}, {"crash_stack": []}])
def test_disassemble_fault_context_none_for_empty_record(record, monkeypatch):
    monkeypatch.setattr(disasm, "objdump_available", lambda: True)
    assert disasm.disassemble_fault_context("bin", record) is None
