"""Fixtures below are real output, captured in-sandbox from
`gcc -fsanitize=address -g -O0` / `gcc -fsanitize=undefined -g -O0` builds of
small standalone C reproducers, not hand-written strings. Absolute paths were
shortened (e.g. `/tmp/asan_fixtures/hbo_read.c` -> `/x/hbo_read.c`) and the
shadow-byte dumps trimmed for readability; the ASan/UBSan report structure,
addresses, and messages are otherwise verbatim.

`FPE_ON_UNKNOWN_ADDRESS`, `MEMCPY_PARAM_OVERLAP`, `STACK_OVERFLOW`, and
`REQUESTED_ALLOCATION_SIZE_TOO_BIG` (V1-RELEASE.md W2) are likewise real
`gcc -fsanitize=address` captures, not fabricated, with the same
path-shortening treatment plus extra trimming of the `pc`/`bp`/`sp`
register dump and interceptor/overlap addresses to fit the 100-column
lint limit -- the trimmed parts are display noise the parser never reads;
every field the tests assert on (`bug_class`, frame `func`/`file`/`line`)
is untouched from the real capture. `STACK_OVERFLOW`'s frame list is
truncated to 5 lines (a real unbounded-recursion capture runs to
hundreds); truncation only drops repeated frames, it does not change the
shape being tested. `ALLOCATOR_OUT_OF_MEMORY` is reproduced verbatim from
a real Igor-corpus report (`poppler__pdftotext`) rather than compiled
locally, since reliably triggering ASan's internal out-of-memory path
requires exhausting a real allocator; it demonstrates that this specific
diagnostic prints no stack trace at all in real ASan output, so
`crash_stack == []` for it is correct parser behavior, not a gap.
"""

from autofte.sanitizers import (
    detect_sanitizer_output,
    parse_asan,
    parse_lsan,
    parse_sanitizer_output,
    parse_ubsan,
)

LSAN_MEMORY_LEAK = """\
=================================================================
==389672==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 32 byte(s) in 1 object(s) allocated from:
    #0 0x718a0eefd9c7 in malloc ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:69
    #1 0x61fb5f30a202 in dup /x/leak.c:3
    #2 0x61fb5f30a245 in main /x/leak.c:4
    #3 0x718a0ea2a1c9 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58

Direct leak of 32 byte(s) in 1 object(s) allocated from:
    #0 0x718a0eefd9c7 in malloc ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:69
    #1 0x61fb5f30a202 in dup /x/leak.c:3
    #2 0x61fb5f30a236 in main /x/leak.c:4

SUMMARY: AddressSanitizer: 64 byte(s) leaked in 2 allocation(s).
"""

HEAP_BUFFER_OVERFLOW_READ = """\
=================================================================
==289967==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x50200000001a
READ of size 1 at 0x50200000001a thread T0
    #0 0x6320d8604225 in main /x/hbo_read.c:4
    #1 0x70a71cc29d8f  (/lib/x86_64-linux-gnu/libc.so.6+0x29d8f)
    #2 0x70a71cc29e3f in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x29e3f)
    #3 0x6320d8604104 in _start (/x/hbo_read+0x1104)

0x50200000001a is located 0 bytes to the right of 10-byte region [0x502000000010,0x50200000001a)
allocated by thread T0 here:
    #0 0x70a71d0b4887 in __interceptor_malloc src/libsanitizer/asan/asan_malloc_linux.cpp:145
    #1 0x6320d86041e5 in main /x/hbo_read.c:3
    #2 0x70a71cc29d8f  (/lib/x86_64-linux-gnu/libc.so.6+0x29d8f)

SUMMARY: AddressSanitizer: heap-buffer-overflow /x/hbo_read.c:4 in main
Shadow bytes around the buggy address:
  0x0a047fff7fb0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x0a047fff8000: fa fa 00[02]fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Heap left redzone:       fa
  Freed heap region:       fd
==289967==ABORTING
"""

HEAP_BUFFER_OVERFLOW_WRITE = """\
=================================================================
==289998==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x50200000001a
WRITE of size 11 at 0x50200000001a thread T0
    #0 0x7b01c4e39c22 in __interceptor_memset src/libsanitizer/sanitizer_common/interceptors.inc:799
    #1 0x6161cfd211ff in main /x/hbo_write.c:5
    #2 0x7b01c4a29d8f  (/lib/x86_64-linux-gnu/libc.so.6+0x29d8f)
    #3 0x7b01c4a29e3f in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x29e3f)
    #4 0x6161cfd21104 in _start (/x/hbo_write+0x1104)

0x50200000001a is located 0 bytes to the right of 10-byte region [0x502000000010,0x50200000001a)
allocated by thread T0 here:
    #0 0x7b01c4eb4887 in __interceptor_malloc src/libsanitizer/asan/asan_malloc_linux.cpp:145
    #1 0x6161cfd211e5 in main /x/hbo_write.c:4
    #2 0x7b01c4a29d8f  (/lib/x86_64-linux-gnu/libc.so.6+0x29d8f)

SUMMARY: AddressSanitizer: heap-buffer-overflow interceptors.inc:799 in __interceptor_memset
==289998==ABORTING
"""

STACK_BUFFER_OVERFLOW = """\
=================================================================
==290023==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7fff685bc168
WRITE of size 21 at 0x7fff685bc168 thread T0
    #0 0x7d0ffc0544be in __interceptor_strcpy src/libsanitizer/asan/asan_interceptors.cpp:440
    #1 0x5ae78e5002aa in vuln /x/sbo.c:4
    #2 0x5ae78e50031f in main /x/sbo.c:7
    #3 0x7d0ffbc29d8f  (/lib/x86_64-linux-gnu/libc.so.6+0x29d8f)
    #4 0x7d0ffbc29e3f in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x29e3f)
    #5 0x5ae78e500144 in _start (/x/sbo+0x1144)

Address 0x7fff685bc168 is located in stack of thread T0 at offset 40 in frame
    #0 0x5ae78e500218 in vuln /x/sbo.c:2

  This frame has 1 object(s):
    [32, 40) 'buf' (line 3) <== Memory access at offset 40 overflows this variable
HINT: this may be a false positive if your program uses a custom stack unwind
      mechanism (longjmp and C++ exceptions *are* supported)
SUMMARY: AddressSanitizer: stack-buffer-overflow asan_interceptors.cpp:440 in __interceptor_strcpy
==290023==ABORTING
"""

STRCPY_PARAM_OVERLAP = """\
=================================================================
==449253==ERROR: AddressSanitizer: strcpy-param-overlap: memory ranges overlap
    #0 0x7af8122543e6 in __interceptor_strcpy src/libsanitizer/asan/asan_interceptors.cpp:438
    #1 0x5e828f3ab20f in vuln /x/overlap.c:4
    #2 0x5e828f3ab343 in main /x/overlap.c:9
    #3 0x7af811e29d8f  (/lib/x86_64-linux-gnu/libc.so.6+0x29d8f)
    #4 0x7af811e29e3f in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x29e3f)
    #5 0x5e828f3ab124 in _start (/x/overlap+0x1124)

Address 0x7ffd634d4830 is located in stack of thread T0 at offset 32 in frame
    #0 0x5e828f3ab222 in main /x/overlap.c:7

  This frame has 1 object(s):
    [32, 64) 'buf' (line 8) <== Memory access at offset 32 is inside this variable
HINT: this may be a false positive if your program uses a custom stack unwind
      mechanism (longjmp and C++ exceptions *are* supported)
SUMMARY: AddressSanitizer: strcpy-param-overlap asan_interceptors.cpp:438 in __interceptor_strcpy
==449253==ABORTING
"""

HEAP_USE_AFTER_FREE = """\
=================================================================
==290055==ERROR: AddressSanitizer: heap-use-after-free on address 0x502000000013
READ of size 1 at 0x502000000013 thread T0
    #0 0x6325642b5231 in main /x/uaf.c:5
    #1 0x7013eaa29d8f  (/lib/x86_64-linux-gnu/libc.so.6+0x29d8f)
    #2 0x7013eaa29e3f in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x29e3f)
    #3 0x6325642b5104 in _start (/x/uaf+0x1104)

0x502000000013 is located 3 bytes inside of 10-byte region [0x502000000010,0x50200000001a)
freed by thread T0 here:
    #0 0x7013eaeb4537 in __interceptor_free src/libsanitizer/asan/asan_malloc_linux.cpp:127
    #1 0x6325642b51f5 in main /x/uaf.c:4
    #2 0x7013eaa29d8f  (/lib/x86_64-linux-gnu/libc.so.6+0x29d8f)

previously allocated by thread T0 here:
    #0 0x7013eaeb4887 in __interceptor_malloc src/libsanitizer/asan/asan_malloc_linux.cpp:145
    #1 0x6325642b51e5 in main /x/uaf.c:3
    #2 0x7013eaa29d8f  (/lib/x86_64-linux-gnu/libc.so.6+0x29d8f)

SUMMARY: AddressSanitizer: heap-use-after-free /x/uaf.c:5 in main
==290055==ABORTING
"""

FPE_ON_UNKNOWN_ADDRESS = """\
AddressSanitizer:DEADLYSIGNAL
=================================================================
==19284==ERROR: AddressSanitizer: FPE on unknown address 0x583835d0817b (pc 0x583835d0817b bp T0)
    #0 0x583835d0817b in divide /x/fpe.c:2
    #1 0x583835d081aa in main /x/fpe.c:6
    #2 0x794c80229d8f  (/lib/x86_64-linux-gnu/libc.so.6+0x29d8f)
    #3 0x794c80229e3f in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x29e3f)
    #4 0x583835d080a4 in _start (/x/fpe+0x10a4)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: FPE /x/fpe.c:2 in divide
==19284==ABORTING
"""

MEMCPY_PARAM_OVERLAP = """\
=================================================================
==19284==ERROR: AddressSanitizer: memcpy-param-overlap: ranges [0x12,0x1a),[0x10,0x18) overlap
    #0 0x7a48a263a1ed in __interceptor_memcpy src/libsanitizer/sanitizer_common/interceptors.inc:827
    #1 0x5a7228c3f1f4 in do_copy /x/memcpy_overlap.c:4
    #2 0x5a7228c3f21d in main /x/memcpy_overlap.c:8
    #3 0x7a48a2229d8f  (/lib/x86_64-linux-gnu/libc.so.6+0x29d8f)
    #4 0x7a48a2229e3f in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x29e3f)
    #5 0x5a7228c3f104 in _start (/x/memcpy_overlap+0x1104)

0x502000000012 is located 2 bytes inside of 16-byte region [0x502000000010,0x502000000020)
allocated by thread T0 here:
    #0 0x7a48a26b4887 in __interceptor_malloc src/libsanitizer/asan/asan_malloc_linux.cpp:145
    #1 0x5a7228c3f20d in main /x/memcpy_overlap.c:7
    #2 0x7a48a2229d8f  (/lib/x86_64-linux-gnu/libc.so.6+0x29d8f)

SUMMARY: AddressSanitizer: memcpy-param-overlap interceptors.inc:827 in __interceptor_memcpy
==19284==ABORTING
"""

STACK_OVERFLOW = """\
AddressSanitizer:DEADLYSIGNAL
=================================================================
==19284==ERROR: AddressSanitizer: stack-overflow on address 0x7ffd2adf6f8c (pc 0x56da121081bd T0)
    #0 0x56da121081bd in recurse /x/stack_overflow.c:1
    #1 0x56da12108264 in recurse /x/stack_overflow.c:4
    #2 0x56da12108264 in recurse /x/stack_overflow.c:4
    #3 0x56da12108264 in recurse /x/stack_overflow.c:4
    #4 0x56da12108264 in recurse /x/stack_overflow.c:4
"""

REQUESTED_ALLOCATION_SIZE_TOO_BIG = """\
=================================================================
==19284==ERROR: AddressSanitizer: requested allocation size 0xffff exceeds max supported size (T0)
    #0 0x78069aeb4887 in __interceptor_malloc src/libsanitizer/asan/asan_malloc_linux.cpp:145
    #1 0x561ca48331a4 in alloc_it /x/huge_alloc.c:4
    #2 0x561ca48331bf in main /x/huge_alloc.c:8
    #3 0x78069aa29d8f  (/lib/x86_64-linux-gnu/libc.so.6+0x29d8f)

==19284==HINT: if you don't care about these errors you may set allocator_may_return_null=1
SUMMARY: AddressSanitizer: allocation-size-too-big asan_malloc_linux.cpp:145 in __interceptor_malloc
==19284==ABORTING
"""

ALLOCATOR_OUT_OF_MEMORY = """\
=================================================================
==18714==ERROR: AddressSanitizer: allocator is out of memory trying to allocate 0x854c bytes
==18714==FATAL: AddressSanitizer: internal allocator is out of memory trying to allocate 0x18 bytes
"""

UBSAN_SIGNED_INTEGER_OVERFLOW = (
    "/tmp/asan_fixtures/ubsan.c:3:5: runtime error: signed integer overflow: "
    "2147483647 + 1 cannot be represented in type 'int'\n"
)

UBSAN_WITH_STACKTRACE = (
    "/x/parse.c:12:9: runtime error: signed integer overflow: "
    "2147483647 + 1 cannot be represented in type 'int'\n"
    "    #0 0x55d in add /x/parse.c:12\n"
    "    #1 0x5a1 in run /x/parse.c:28\n"
    "    #2 0x5f3 in main /x/main.c:5\n"
    "SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior /x/parse.c:12:9\n"
)

GDB_OUTPUT = """\
Program received signal SIGSEGV, Segmentation fault.
0x0000000000401136 in vuln (input=0x7fffffffe4d0 "AAAA") at vuln.c:8
8\t  strcpy(buf, input);
#0  0x0000000000401136 in vuln (input=0x7fffffffe4d0 "AAAA") at vuln.c:8
#1  0x0000000000401199 in main (argc=2, argv=0x7fffffffe5c8) at vuln.c:20
"""


# --------------------------------------------------------------------------
# detect_sanitizer_output
# --------------------------------------------------------------------------

def test_detect_sanitizer_output_asan():
    assert detect_sanitizer_output(HEAP_BUFFER_OVERFLOW_READ) == "asan"


def test_detect_sanitizer_output_ubsan():
    assert detect_sanitizer_output(UBSAN_SIGNED_INTEGER_OVERFLOW) == "ubsan"


def test_detect_sanitizer_output_none_for_gdb_output():
    assert detect_sanitizer_output(GDB_OUTPUT) is None


def test_detect_sanitizer_output_none_for_arbitrary_text():
    assert detect_sanitizer_output("just some random program output\nexit code 1\n") is None


def test_detect_sanitizer_output_none_for_empty_text():
    assert detect_sanitizer_output("") is None
    assert detect_sanitizer_output(None) is None


# --------------------------------------------------------------------------
# parse_asan -- heap-buffer-overflow (read)
# --------------------------------------------------------------------------

def test_parse_asan_heap_buffer_overflow_read():
    record = parse_asan(HEAP_BUFFER_OVERFLOW_READ)
    assert record["sanitizer"] == "AddressSanitizer"
    assert record["bug_class"] == "heap-buffer-overflow"
    assert record["access_type"] == "read"
    assert record["access_size"] == 1
    assert record["fault_addr"] == "0x50200000001a"
    assert record["sanitizer_raw"] == HEAP_BUFFER_OVERFLOW_READ

    assert record["crash_stack"][0] == {
        "frame": 0,
        "addr": "0x6320d8604225",
        "func": "main",
        "file": "/x/hbo_read.c",
        "line": 4,
    }
    assert len(record["crash_stack"]) == 4

    assert record["alloc_stack"][0]["func"] == "__interceptor_malloc"
    assert record["alloc_stack"][1] == {
        "frame": 1,
        "addr": "0x6320d86041e5",
        "func": "main",
        "file": "/x/hbo_read.c",
        "line": 3,
    }
    assert record["free_stack"] == []


# --------------------------------------------------------------------------
# parse_asan -- heap-buffer-overflow (write)
# --------------------------------------------------------------------------

def test_parse_asan_heap_buffer_overflow_write():
    record = parse_asan(HEAP_BUFFER_OVERFLOW_WRITE)
    assert record["bug_class"] == "heap-buffer-overflow"
    assert record["access_type"] == "write"
    assert record["access_size"] == 11
    assert record["fault_addr"] == "0x50200000001a"
    assert record["crash_stack"][0]["func"] == "__interceptor_memset"
    assert record["alloc_stack"][0]["func"] == "__interceptor_malloc"
    assert record["free_stack"] == []


# --------------------------------------------------------------------------
# parse_asan -- stack-buffer-overflow
# --------------------------------------------------------------------------

def test_parse_asan_stack_buffer_overflow():
    record = parse_asan(STACK_BUFFER_OVERFLOW)
    assert record["bug_class"] == "stack-buffer-overflow"
    assert record["access_type"] == "write"
    assert record["access_size"] == 21
    assert record["fault_addr"] == "0x7fff685bc168"

    assert len(record["crash_stack"]) == 6
    funcs = [frame["func"] for frame in record["crash_stack"]]
    assert funcs[:3] == ["__interceptor_strcpy", "vuln", "main"]
    assert record["crash_stack"][1]["file"] == "/x/sbo.c"
    assert record["crash_stack"][1]["line"] == 4

    assert record["alloc_stack"] == []
    assert record["free_stack"] == []


# --------------------------------------------------------------------------
# parse_asan -- strcpy-param-overlap (bug_class trailing colon stripped)
# --------------------------------------------------------------------------

def test_parse_asan_strcpy_param_overlap_bug_class_has_no_trailing_colon():
    record = parse_asan(STRCPY_PARAM_OVERLAP)
    assert record["bug_class"] == "strcpy-param-overlap"
    assert not record["bug_class"].endswith(":")


def test_parse_asan_strcpy_param_overlap_has_crash_stack():
    """V1-RELEASE.md W2: the ERROR summary line itself starts the crash
    stack for `*-param-overlap` diagnostics -- there is no separate
    `READ/WRITE of size` trigger line for this bug class, so before the
    fix `crash_stack` was silently empty."""
    record = parse_asan(STRCPY_PARAM_OVERLAP)
    assert record["crash_stack"] != []
    funcs = [frame["func"] for frame in record["crash_stack"]]
    assert funcs[:3] == ["__interceptor_strcpy", "vuln", "main"]


# --------------------------------------------------------------------------
# parse_asan -- heap-use-after-free (with alloc + free stacks)
# --------------------------------------------------------------------------

def test_parse_asan_heap_use_after_free():
    record = parse_asan(HEAP_USE_AFTER_FREE)
    assert record["bug_class"] == "heap-use-after-free"
    assert record["access_type"] == "read"
    assert record["access_size"] == 1
    assert record["fault_addr"] == "0x502000000013"

    assert record["crash_stack"][0]["func"] == "main"
    assert record["crash_stack"][0]["line"] == 5

    assert record["free_stack"][0]["func"] == "__interceptor_free"
    assert record["free_stack"][1] == {
        "frame": 1,
        "addr": "0x6325642b51f5",
        "func": "main",
        "file": "/x/uaf.c",
        "line": 4,
    }

    assert record["alloc_stack"][0]["func"] == "__interceptor_malloc"
    assert record["alloc_stack"][1] == {
        "frame": 1,
        "addr": "0x6325642b51e5",
        "func": "main",
        "file": "/x/uaf.c",
        "line": 3,
    }


# --------------------------------------------------------------------------
# parse_asan -- ERROR-summary-line-starts-crash-stack bug classes
# (V1-RELEASE.md W2: sanitizers.py did not recognize the ERROR summary
# line itself as the start of the crash stack, so any bug class without
# a separate READ/WRITE/SEGV/attempting-free trigger line silently
# produced an empty crash_stack)
# --------------------------------------------------------------------------

def test_parse_asan_fpe_has_crash_stack():
    record = parse_asan(FPE_ON_UNKNOWN_ADDRESS)
    assert record["bug_class"] == "FPE"
    funcs = [frame["func"] for frame in record["crash_stack"]]
    assert funcs[:2] == ["divide", "main"]
    assert record["crash_stack"][0]["file"] == "/x/fpe.c"
    assert record["crash_stack"][0]["line"] == 2


def test_parse_asan_memcpy_param_overlap_has_crash_stack():
    record = parse_asan(MEMCPY_PARAM_OVERLAP)
    assert record["bug_class"] == "memcpy-param-overlap"
    funcs = [frame["func"] for frame in record["crash_stack"]]
    assert funcs[:3] == ["__interceptor_memcpy", "do_copy", "main"]
    assert record["crash_stack"][1]["file"] == "/x/memcpy_overlap.c"
    assert record["crash_stack"][1]["line"] == 4


def test_parse_asan_stack_overflow_has_crash_stack():
    record = parse_asan(STACK_OVERFLOW)
    assert record["bug_class"] == "stack-overflow"
    funcs = [frame["func"] for frame in record["crash_stack"]]
    assert funcs == ["recurse"] * 5
    assert record["crash_stack"][0]["file"] == "/x/stack_overflow.c"


def test_parse_asan_requested_allocation_size_too_big_has_crash_stack():
    record = parse_asan(REQUESTED_ALLOCATION_SIZE_TOO_BIG)
    assert record["bug_class"] == "requested"
    funcs = [frame["func"] for frame in record["crash_stack"]]
    assert funcs[:3] == ["__interceptor_malloc", "alloc_it", "main"]
    assert record["crash_stack"][1]["file"] == "/x/huge_alloc.c"
    assert record["crash_stack"][1]["line"] == 4


def test_parse_asan_allocator_out_of_memory_still_has_no_crash_stack():
    """Real ASan output for this diagnostic prints no stack trace at all
    -- confirmed against a real Igor-corpus report -- so an empty
    crash_stack here is correct parser behavior, not a gap the ERROR-line
    fix is expected to close."""
    record = parse_asan(ALLOCATOR_OUT_OF_MEMORY)
    assert record["bug_class"] == "allocator"
    assert record["crash_stack"] == []


# --------------------------------------------------------------------------
# parse_asan -- not an ASan report
# --------------------------------------------------------------------------

def test_parse_asan_returns_none_for_non_asan_text():
    assert parse_asan(GDB_OUTPUT) is None
    assert parse_asan("") is None


# --------------------------------------------------------------------------
# parse_ubsan
# --------------------------------------------------------------------------

def test_parse_ubsan_signed_integer_overflow():
    record = parse_ubsan(UBSAN_SIGNED_INTEGER_OVERFLOW)
    assert record["sanitizer"] == "UndefinedBehaviorSanitizer"
    assert record["bug_class"] == "signed-integer-overflow"
    assert record["access_type"] is None
    assert record["access_size"] is None
    assert record["fault_addr"] is None
    assert record["crash_stack"] == [
        {
            "frame": 0,
            "addr": None,
            "func": None,
            "file": "/tmp/asan_fixtures/ubsan.c",
            "line": 3,
        }
    ]
    assert record["alloc_stack"] == []
    assert record["free_stack"] == []
    assert record["sanitizer_raw"] == UBSAN_SIGNED_INTEGER_OVERFLOW


def test_parse_ubsan_collects_stacktrace_frames_when_present():
    record = parse_ubsan(UBSAN_WITH_STACKTRACE)
    funcs = [f["func"] for f in record["crash_stack"]]
    assert funcs == ["add", "run", "main"]
    assert record["crash_stack"][0]["line"] == 12


def test_parse_ubsan_returns_none_for_non_ubsan_text():
    assert parse_ubsan(GDB_OUTPUT) is None
    assert parse_ubsan("") is None


# --------------------------------------------------------------------------
# parse_sanitizer_output -- the unifying entry point
# --------------------------------------------------------------------------

def test_parse_sanitizer_output_dispatches_to_asan():
    record = parse_sanitizer_output(HEAP_USE_AFTER_FREE)
    assert record["sanitizer"] == "AddressSanitizer"
    assert record["bug_class"] == "heap-use-after-free"


def test_parse_sanitizer_output_dispatches_to_ubsan():
    record = parse_sanitizer_output(UBSAN_SIGNED_INTEGER_OVERFLOW)
    assert record["sanitizer"] == "UndefinedBehaviorSanitizer"


def test_parse_sanitizer_output_none_for_plain_gdb_output():
    assert parse_sanitizer_output(GDB_OUTPUT) is None


def test_parse_sanitizer_output_none_for_arbitrary_text():
    assert parse_sanitizer_output("program printed some ordinary output\n") is None


def test_detect_lsan_output():
    assert detect_sanitizer_output(LSAN_MEMORY_LEAK) == "lsan"


def test_parse_lsan_extracts_totals_and_alloc_stack():
    record = parse_lsan(LSAN_MEMORY_LEAK)
    assert record["sanitizer"] == "LeakSanitizer"
    assert record["bug_class"] == "memory-leak"
    assert record["access_size"] == 64
    assert record["leaked_objects"] == 2
    assert record["access_type"] is None
    funcs = [f["func"] for f in record["alloc_stack"]]
    assert "dup" in funcs and "main" in funcs
    assert record["crash_stack"] == record["alloc_stack"][:1]


def test_parse_sanitizer_output_dispatches_to_lsan():
    record = parse_sanitizer_output(LSAN_MEMORY_LEAK)
    assert record["sanitizer"] == "LeakSanitizer"


def test_parse_lsan_none_for_non_leak_text():
    assert parse_lsan(GDB_OUTPUT) is None
