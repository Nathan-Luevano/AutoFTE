from autofte.dedup import (
    collapse_recursive_cycles,
    is_noise_frame,
    normalize_frame,
    normalized_keys,
    significant_frames,
    stack_hashes,
    stack_hashes_for_record,
)


def _frame(frame=0, addr="0xdead", func="vuln", file=None, line=None):
    return {"frame": frame, "addr": addr, "func": func, "file": file, "line": line}


# --------------------------------------------------------------------------
# is_noise_frame / significant_frames
# --------------------------------------------------------------------------

def test_is_noise_frame_true_for_libc_startup():
    assert is_noise_frame(_frame(func="__libc_start_main")) is True
    assert is_noise_frame(_frame(func="_start")) is True
    assert is_noise_frame(_frame(func="__libc_csu_init")) is True


def test_is_noise_frame_true_for_sanitizer_runtime():
    assert is_noise_frame(_frame(func="__interceptor_strcpy")) is True
    assert is_noise_frame(_frame(func="__asan_report_error")) is True
    assert is_noise_frame(_frame(func="__sanitizer_print_stack_trace")) is True


def test_is_noise_frame_true_for_unresolved_bare_module_frame():
    assert is_noise_frame(_frame(func=None, file=None)) is True


def test_is_noise_frame_false_when_unresolved_but_has_source_location():
    assert is_noise_frame(_frame(func=None, file="ubsan.c", line=3)) is False


def test_is_noise_frame_false_for_application_code():
    assert is_noise_frame(_frame(func="parse_header")) is False
    assert is_noise_frame(_frame(func="handle_packet")) is False


def test_is_noise_frame_true_for_main_via_vendored_clusterfuzz_list():
    assert is_noise_frame(_frame(func="main")) is True


def test_significant_frames_drops_only_noise():
    frames = [
        _frame(0, func="__interceptor_memset"),
        _frame(1, func="vuln", file="vuln.c", line=8),
        _frame(2, func="caller", file="vuln.c", line=20),
        _frame(3, func="__libc_start_main"),
    ]
    result = significant_frames(frames)
    assert [f["func"] for f in result] == ["vuln", "caller"]


# --------------------------------------------------------------------------
# normalize_frame
# --------------------------------------------------------------------------

def test_normalize_frame_strips_directory_from_file():
    key = normalize_frame(_frame(func="vuln", file="/x/vuln.c", line=8))
    assert key == "vuln@vuln.c:8"


def test_normalize_frame_strips_symbol_offset_suffix():
    key = normalize_frame(_frame(func="vuln+0x1a", file=None, line=None))
    assert key == "vuln"


def test_normalize_frame_func_only_when_no_source_info():
    assert normalize_frame(_frame(func="vuln", file=None, line=None)) == "vuln"


def test_normalize_frame_ignores_address_entirely():
    a = normalize_frame(_frame(func="vuln", addr="0x1000", file="vuln.c", line=8))
    b = normalize_frame(_frame(func="vuln", addr="0x7fffdeadbeef", file="vuln.c", line=8))
    assert a == b == "vuln@vuln.c:8"


def test_normalize_frame_none_for_fully_unresolved_frame():
    assert normalize_frame(_frame(func=None, file=None, line=None)) is None


# --------------------------------------------------------------------------
# stack_hashes -- the actual point of ROADMAP 2.2
# --------------------------------------------------------------------------

def test_stack_hashes_none_for_empty_or_fully_noise_stack():
    assert stack_hashes([]) == (None, None)
    assert stack_hashes([_frame(func="__libc_start_main")]) == (None, None)


def test_stack_hashes_collapse_across_aslr_shifted_addresses():
    """Same bug, two ASLR-shifted runs: identical normalized frames,
    wildly different raw addresses -- major/minor hashes must match."""
    run_a = [
        _frame(0, addr="0x555555554136", func="vuln", file="/build/a/vuln.c", line=8),
        _frame(1, addr="0x5555555541b0", func="main", file="/build/a/vuln.c", line=20),
        _frame(2, addr="0x7ffff7a29d8f", func="__libc_start_main"),
    ]
    run_b = [
        _frame(0, addr="0x611234abc136", func="vuln", file="/build/b/vuln.c", line=8),
        _frame(1, addr="0x611234abc1b0", func="main", file="/build/b/vuln.c", line=20),
        _frame(2, addr="0x7f0011229d8f", func="__libc_start_main"),
    ]
    major_a, minor_a = stack_hashes(run_a)
    major_b, minor_b = stack_hashes(run_b)
    assert major_a is not None
    assert major_a == major_b
    assert minor_a == minor_b


def test_stack_hashes_differ_for_genuinely_different_stacks():
    heap_overflow = [
        _frame(0, func="parse_header", file="p.c", line=42),
        _frame(1, func="main", file="p.c", line=10),
    ]
    null_deref = [
        _frame(0, func="handle_packet", file="net.c", line=7),
        _frame(1, func="main", file="net.c", line=15),
    ]
    major_1, _ = stack_hashes(heap_overflow)
    major_2, _ = stack_hashes(null_deref)
    assert major_1 != major_2


def test_stack_hashes_major_frame_count_1_merges_distinct_bugs_sharing_a_top_frame():
    """Adversarial-review finding (see the benchmark record, the
    'Adversarial review: MAJOR_FRAME_COUNT=1' entry).

    `MAJOR_FRAME_COUNT` was dropped from 2 to 1 based on a real Igor-corpus
    sweep, but that sweep's headline metrics were computed with every
    `stack_hashes()` call given `extra_context=[bug_class]`. There is a
    real, currently-shipped call site with no such context:
    `triage.py`'s `_classify_crash` GDB path (used whenever a target isn't
    built with a sanitizer) calls `dedup.stack_hashes(frames)` with no
    `extra_context` at all.

    On that path, at `MAJOR_FRAME_COUNT=1`, two genuinely different bugs
    that happen to crash through the same glibc allocator-internal frame
    (e.g. `_int_malloc`/`tcache_get`/`sysmalloc` -- none of which are noise-
    filtered by `_NOISE_FUNC_RE` or the vendored ignore lists, and which
    commonly show up as the *crash* frame for heap corruption caught late
    by glibc's own consistency checks, well after the actual corrupting
    write) collapse into ONE major bucket, discarding the very next frame
    (the actual differing call site) that would have kept them apart at
    the previous default of `MAJOR_FRAME_COUNT=2`.

    This test intentionally FAILS at `MAJOR_FRAME_COUNT=1` (current) and
    PASSES at `MAJOR_FRAME_COUNT=2` (previous default) -- it is falsifying
    evidence for the sweep's implicit generalization from
    "flat purity on the corpus, given bug-class context everywhere" to
    "safe for every call site", not evidence the corpus number itself is
    wrong.
    """
    bug_a_corrupts_heap_in_handler_a = [
        _frame(0, func="_int_malloc"),
        _frame(1, func="handle_request_a", file="server.c", line=10),
        _frame(2, func="main", file="server.c", line=100),
    ]
    bug_b_corrupts_heap_in_handler_b = [
        _frame(0, func="_int_malloc"),
        _frame(1, func="handle_request_b", file="server.c", line=20),
        _frame(2, func="main", file="server.c", line=100),
    ]
    major_a, _ = stack_hashes(bug_a_corrupts_heap_in_handler_a)
    major_b, _ = stack_hashes(bug_b_corrupts_heap_in_handler_b)
    assert major_a is not None
    assert major_a != major_b, (
        "two different bugs (different second frame / call site) collapsed "
        "into the same major bucket -- MAJOR_FRAME_COUNT=1 discards the "
        "only frame that distinguished them when no extra_context is given "
        "(triage.py's GDB path, exactly)"
    )


def test_stack_hashes_extra_context_distinguishes_same_stack_different_bug_class():
    frames = [_frame(0, func="parse_header", file="p.c", line=42)]
    major_uaf, _ = stack_hashes(frames, extra_context=["heap-use-after-free"])
    major_hbo, _ = stack_hashes(frames, extra_context=["heap-buffer-overflow"])
    assert major_uaf != major_hbo


def test_stack_hashes_minor_is_finer_than_major():
    shared_top = [
        _frame(0, func="vuln", file="v.c", line=8),
        _frame(1, func="caller", file="v.c", line=20),
    ]
    deeper_a = shared_top + [_frame(2, func="caller_a", file="v.c", line=30)]
    deeper_b = shared_top + [_frame(2, func="caller_b", file="v.c", line=31)]

    major_a, minor_a = stack_hashes(deeper_a)
    major_b, minor_b = stack_hashes(deeper_b)
    assert major_a == major_b
    assert minor_a != minor_b


def test_stack_hashes_same_bug_different_line_same_major_bucket():
    """Same function, different crash line (loop iteration / call-site /
    -O2 attribution jitter) -- major hash must collapse these into one
    bucket, but the minor hash should still distinguish the exact line for
    a human reading the representative label."""
    call_site_a = [
        _frame(0, func="parse_header", file="p.c", line=42),
        _frame(1, func="main", file="p.c", line=10),
    ]
    call_site_b = [
        _frame(0, func="parse_header", file="p.c", line=57),
        _frame(1, func="main", file="p.c", line=10),
    ]
    major_a, minor_a = stack_hashes(call_site_a)
    major_b, minor_b = stack_hashes(call_site_b)
    assert major_a is not None
    assert major_a == major_b
    assert minor_a != minor_b


def test_normalize_frame_include_line_false_omits_line():
    key = normalize_frame(_frame(func="vuln", file="/x/vuln.c", line=8), include_line=False)
    assert key == "vuln@vuln.c"


def test_normalized_keys_matches_significant_frames_order():
    frames = [
        _frame(0, func="__interceptor_memset"),
        _frame(1, func="vuln", file="/x/vuln.c", line=8),
        _frame(2, func="caller", file="/x/vuln.c", line=20),
    ]
    assert normalized_keys(frames) == ["vuln@vuln.c:8", "caller@vuln.c:20"]


# --------------------------------------------------------------------------
# collapse_recursive_cycles -- HARDENING Part 3 fix #3
# --------------------------------------------------------------------------

def test_collapse_recursive_cycles_collapses_deep_single_frame_recursion():
    frames = [_frame(i, func="deep_recurse", file="r.c", line=12) for i in range(50)]
    result = collapse_recursive_cycles(frames)
    assert result == [_frame(0, func="deep_recurse", file="r.c", line=12)]


def test_collapse_recursive_cycles_collapses_three_frame_indirect_recursion():
    a = _frame(0, func="a", file="r.c", line=1)
    b = _frame(0, func="b", file="r.c", line=2)
    c = _frame(0, func="c", file="r.c", line=3)
    frames = [a, b, c] * 3
    result = collapse_recursive_cycles(frames)
    assert result == [a, b, c]


def test_collapse_recursive_cycles_collapses_three_frame_cycle_repeated_five_times():
    a = _frame(0, func="a", file="r.c", line=1)
    b = _frame(0, func="b", file="r.c", line=2)
    c = _frame(0, func="c", file="r.c", line=3)
    frames = [a, b, c] * 5
    result = collapse_recursive_cycles(frames)
    assert result == [a, b, c]


def test_collapse_recursive_cycles_leaves_no_repetition_untouched():
    frames = [
        _frame(0, func="parse_header", file="p.c", line=42),
        _frame(1, func="parse_body", file="p.c", line=50),
        _frame(2, func="main", file="p.c", line=10),
    ]
    assert collapse_recursive_cycles(frames) == frames


def test_collapse_recursive_cycles_leaves_short_repeat_untouched():
    a = _frame(0, func="a", file="r.c", line=1)
    b = _frame(0, func="b", file="r.c", line=2)
    c = _frame(0, func="c", file="r.c", line=3)
    frames = [a, b, c] * 2
    assert collapse_recursive_cycles(frames) == frames


def test_collapse_recursive_cycles_single_frame_repeated_only_twice_untouched():
    frames = [_frame(0, func="x", file="r.c", line=1)] * 2
    assert collapse_recursive_cycles(frames) == frames


def test_collapse_recursive_cycles_empty_list_untouched():
    assert collapse_recursive_cycles([]) == []


def test_collapse_recursive_cycles_preserves_trailing_frames_after_cycle():
    a = _frame(0, func="deep_recurse", file="r.c", line=12)
    tail = _frame(0, func="entry_point", file="r.c", line=1)
    frames = [a] * 20 + [tail]
    result = collapse_recursive_cycles(frames)
    assert result == [a, tail]


# --------------------------------------------------------------------------
# recursion collapsing wired into stack_hashes -- the actual point of the fix
# --------------------------------------------------------------------------

def test_stack_hashes_same_recursive_bug_different_stack_depths_same_major_hash():
    """Same unbounded-recursion bug, captured at two different stack
    depths (e.g. different `ulimit -s`/build) -- the fix must produce the
    same major (and minor) hash either way. Before this fix, a shallow
    capture whose cycle repeat count is small enough for the minor
    window to reach past the recursion into the caller's own frames
    genuinely produced a different minor hash than a deep capture whose
    window never left the recursion -- demonstrated directly here rather
    than merely asserted."""
    def cycle_frame():
        return _frame(0, func="recurse", file="parse.c", line=88)

    tail = [
        _frame(0, func="parse_entry", file="parse.c", line=10),
        _frame(0, func="top_level_handler", file="parse.c", line=5),
    ]
    shallow_stack = [cycle_frame() for _ in range(3)] + tail
    deep_stack = [cycle_frame() for _ in range(112)] + tail

    pre_fix_shallow_minor = normalized_keys(significant_frames(shallow_stack))[
        :5
    ]
    pre_fix_deep_minor = normalized_keys(significant_frames(deep_stack))[:5]
    assert pre_fix_shallow_minor != pre_fix_deep_minor

    major_shallow, minor_shallow = stack_hashes(shallow_stack)
    major_deep, minor_deep = stack_hashes(deep_stack)
    assert major_shallow is not None
    assert major_shallow == major_deep
    assert minor_shallow == minor_deep


def test_stack_hashes_recursive_cycle_collapsed_before_windowing():
    frames = [_frame(i, func="deep_recurse", file="r.c", line=12) for i in range(200)]
    major, minor = stack_hashes(frames)
    collapsed_major, collapsed_minor = stack_hashes(
        [_frame(0, func="deep_recurse", file="r.c", line=12)]
    )
    assert major == collapsed_major
    assert minor == collapsed_minor


# --------------------------------------------------------------------------
# stack_hashes_for_record (HARDENING Part 3 fix #4)
# --------------------------------------------------------------------------

def _crash_record(bug_class, crash_stack=None, alloc_stack=None, free_stack=None):
    return {
        "bug_class": bug_class,
        "crash_stack": crash_stack or [],
        "alloc_stack": alloc_stack or [],
        "free_stack": free_stack or [],
    }


def test_stack_hashes_for_record_uaf_with_free_stack_uses_free_stack():
    free_stack = [_frame(0, func="release_buffer", file="pool.c", line=40)]
    crash_stack = [_frame(0, func="use_buffer", file="handler.c", line=99)]
    record = _crash_record("heap-use-after-free", crash_stack=crash_stack, free_stack=free_stack)

    major, minor, stack_used = stack_hashes_for_record(record)

    assert stack_used == "free"
    expected_major, expected_minor = stack_hashes(
        free_stack, extra_context=["heap-use-after-free"]
    )
    assert (major, minor) == (expected_major, expected_minor)


def test_stack_hashes_for_record_double_free_and_bad_free_also_use_free_stack():
    free_stack = [_frame(0, func="release_buffer", file="pool.c", line=40)]
    for bug_class in ("double-free", "bad-free"):
        record = _crash_record(bug_class, free_stack=free_stack)
        _major, _minor, stack_used = stack_hashes_for_record(record)
        assert stack_used == "free"


def test_stack_hashes_for_record_uaf_with_empty_free_stack_falls_back_to_crash_stack():
    crash_stack = [_frame(0, func="use_buffer", file="handler.c", line=99)]
    record = _crash_record("heap-use-after-free", crash_stack=crash_stack, free_stack=[])

    major, minor, stack_used = stack_hashes_for_record(record)

    assert stack_used == "crash"
    expected_major, expected_minor = stack_hashes(
        crash_stack, extra_context=["heap-use-after-free"]
    )
    assert (major, minor) == (expected_major, expected_minor)


def test_stack_hashes_for_record_leak_uses_alloc_stack():
    alloc_stack = [_frame(0, func="make_widget", file="widget.c", line=12)]
    crash_stack = [_frame(0, func="lsan_report", file="lsan.c", line=1)]
    record = _crash_record("direct-leak", crash_stack=crash_stack, alloc_stack=alloc_stack)

    major, minor, stack_used = stack_hashes_for_record(record)

    assert stack_used == "alloc"
    expected_major, expected_minor = stack_hashes(alloc_stack, extra_context=["direct-leak"])
    assert (major, minor) == (expected_major, expected_minor)


def test_stack_hashes_for_record_heap_buffer_overflow_still_uses_crash_stack_unchanged():
    crash_stack = [
        _frame(0, func="vuln", file="vuln.c", line=8),
        _frame(1, func="caller", file="vuln.c", line=20),
    ]
    alloc_stack = [_frame(0, func="make_widget", file="widget.c", line=12)]
    free_stack = [_frame(0, func="release_buffer", file="pool.c", line=40)]
    record = _crash_record(
        "heap-buffer-overflow",
        crash_stack=crash_stack,
        alloc_stack=alloc_stack,
        free_stack=free_stack,
    )

    major, minor, stack_used = stack_hashes_for_record(record)

    assert stack_used == "crash"
    expected_major, expected_minor = stack_hashes(
        crash_stack, extra_context=["heap-buffer-overflow"]
    )
    assert (major, minor) == (expected_major, expected_minor)


def test_stack_hashes_for_record_uaf_same_free_site_different_use_site_same_major_hash():
    same_free_stack = [_frame(0, func="release_widget", file="pool.c", line=77)]
    use_site_a = [_frame(0, func="use_after_a", file="reader.c", line=5)]
    use_site_b = [_frame(0, func="use_after_b", file="writer.c", line=200)]

    record_a = _crash_record(
        "heap-use-after-free", crash_stack=use_site_a, free_stack=same_free_stack
    )
    record_b = _crash_record(
        "heap-use-after-free", crash_stack=use_site_b, free_stack=same_free_stack
    )

    major_a, _minor_a, used_a = stack_hashes_for_record(record_a)
    major_b, _minor_b, used_b = stack_hashes_for_record(record_b)

    assert used_a == used_b == "free"
    assert major_a == major_b

    old_major_a, _ = stack_hashes(use_site_a, extra_context=["heap-use-after-free"])
    old_major_b, _ = stack_hashes(use_site_b, extra_context=["heap-use-after-free"])
    assert old_major_a != old_major_b
