import pytest

from autofte import crash_state

RET_OVERFLOW = """\
Program received signal SIGSEGV, Segmentation fault.
0x00000000004011bb in parse (s=0x7fffffffd3d0 'A' <repeats 24 times>) at /tmp/ft.c:3
3\tvoid parse(char *s){ char b[16]; strcpy(b, s); }
PC=0x4011bb
SP=0x7fffffffd3b8
FP=0x4141414141414141
=> 0x4011bb <parse+37>:\tret
rax            0x7fffffffd3a0      140737488343968
rbp            0x4141414141414141  0x4141414141414141
rip            0x4011bb            0x4011bb <parse+37>
#0  0x00000000004011bb in parse (s=0x7fffffffd3d0 'A' <repeats 24 times>) at /tmp/ft.c:3
#1  0x4141414141414141 in ?? ()
#2  0x4141414141414141 in ?? ()
"""

NULL_READ = """\
Program received signal SIGSEGV, Segmentation fault.
0x00000000004011f7 in main () at /tmp/nd.c:4
PC=0x4011f7
SP=0x7fffffffd400
FP=0x7fffffffd410
=> 0x4011f7 <main+129>:\tmov    (%rax),%eax
rax            0x0                 0
#0  0x00000000004011f7 in main () at /tmp/nd.c:4
"""

IP_CONTROL = """\
Program received signal SIGSEGV, Segmentation fault.
0x4141414141414141 in ?? ()
PC=0x4141414141414141
SP=0x7fffffffd3c8
FP=0x4141414141414141
=> 0x4141414141414141:\t<error: Cannot access memory at address 0x4141414141414141>
#0  0x4141414141414141 in ?? ()
"""

INDIRECT_CALL = """\
Program received signal SIGSEGV, Segmentation fault.
0x00000000004012aa in dispatch () at t.c:9
PC=0x4012aa
SP=0x7fffffffd3c8
FP=0x7fffffffd3e0
=> 0x4012aa <dispatch+20>:\tcall   *%rax
rax            0x4141414141414141  4702111234474983745
#0  0x00000000004012aa in dispatch () at t.c:9
#1  0x0000000000401300 in main () at t.c:20
"""

CLEAN_ABORT = """\
Program received signal SIGABRT, Aborted.
0x00007ffff7a42abc in __pthread_kill_implementation ()
PC=0x7ffff7a42abc
SP=0x7fffffffd200
FP=0x7fffffffd260
=> 0x7ffff7a42abc <__pthread_kill_implementation+284>:\tmov    %eax,%r8d
#0  0x00007ffff7a42abc in __pthread_kill_implementation ()
"""


@pytest.mark.parametrize(
    "value,controlled",
    [
        ("0x4141414141414141", True),
        ("0x00007fffffffd3b8", False),
        ("0x0000000000401136", False),
        ("0x4242424242424242", True),
        ("0xdeadbeefdeadbeef", True),
        ("0x0", False),
        ("0x8", True),
        ("0xffff888000000000", True),
    ],
)
def test_looks_controlled(value, controlled):
    assert crash_state.looks_controlled(value) is controlled


def test_parse_gdb_output_extracts_core_fields():
    state = crash_state.parse_gdb_output(RET_OVERFLOW)
    assert state["signal"] == "SIGSEGV"
    assert state["pc"] == "0x4011bb"
    assert state["frame_pointer"] == "0x4141414141414141"
    assert state["faulting_instruction"] == "ret"
    assert state["pc_symbol"] == "parse+37"
    assert state["return_address"] == "0x4141414141414141"
    assert state["registers"]["rax"] == "0x7fffffffd3a0"


def test_parse_gdb_output_none_without_pc():
    assert crash_state.parse_gdb_output("some noise\nno registers here") is None
    assert crash_state.parse_gdb_output("") is None


def test_classify_return_address_overwrite():
    result = crash_state.classify(crash_state.parse_gdb_output(RET_OVERFLOW))
    assert result["primitives"] == ["return-address-overwrite"]
    assert "imminent" in result["rationale"]


def test_classify_instruction_pointer_control():
    result = crash_state.classify(crash_state.parse_gdb_output(IP_CONTROL))
    assert result["primitives"] == ["instruction-pointer-control"]


def test_classify_indirect_branch():
    result = crash_state.classify(crash_state.parse_gdb_output(INDIRECT_CALL))
    assert result["primitives"] == ["indirect-branch-through-register"]


def test_classify_memory_read():
    result = crash_state.classify(crash_state.parse_gdb_output(NULL_READ))
    assert result["primitives"] == ["memory-read"]


def test_classify_no_primitive_for_plain_abort():
    result = crash_state.classify(crash_state.parse_gdb_output(CLEAN_ABORT))
    assert result["primitives"] == []
    assert "No specific exploitation primitive" in result["rationale"]


def test_classify_handles_none():
    assert crash_state.classify(None)["primitives"] == []


def test_capture_none_without_gdb(monkeypatch):
    monkeypatch.setattr(crash_state, "gdb_available", lambda debugger="gdb": False)
    assert crash_state.capture("bin", "crash") is None


def test_capture_none_on_gdb_failure(monkeypatch):
    monkeypatch.setattr(crash_state, "gdb_available", lambda debugger="gdb": True)
    monkeypatch.setattr(crash_state, "_run_gdb", lambda *a: None)
    assert crash_state.capture("bin", "crash") is None


def test_capture_merges_classification(monkeypatch):
    monkeypatch.setattr(crash_state, "gdb_available", lambda debugger="gdb": True)
    monkeypatch.setattr(crash_state, "_run_gdb", lambda *a: RET_OVERFLOW)
    state = crash_state.capture("bin", "crash")
    assert state["primitives"] == ["return-address-overwrite"]
    assert state["signal"] == "SIGSEGV"
