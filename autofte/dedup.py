"""Major/minor stack-hash bucketing -- the `exploitable`/ClusterFuzz dedup
model.

A crash frame list on its own over-identifies (an ASLR-shifted address
makes an otherwise-identical crash look new every run) and, if you key on
the raw formatted top-frame string, also under-identifies (unrelated bugs
that happen to share the same first line of text collapse into one
bucket). The fix used by every mature crash-triage tool (the `exploitable`
GDB plugin, ClusterFuzz, CASR) is the same two-step recipe:

1. Normalize each frame so it no longer carries anything ASLR/build/run
   dependent -- drop the raw address entirely, strip any `+0xNN` symbol
   offset, and reduce a source path to its basename so an out-of-tree
   rebuild in a different directory doesn't look like a different bug.
2. Drop "noise" frames that carry no information about *which* bug this
   is: libc's own startup/teardown internals, glibc alias trampolines, and
   the sanitizer runtime's interceptor/report machinery. These are the
   same handful of frames on every crash regardless of the actual bug, so
   including them in the hash would make unrelated bugs that both happen
   to unwind through, say, `__interceptor_memset` look identical.

What's left is hashed twice at two depths: a short **major** hash (the
coarse "this is probably the same root cause" bucket -- primary grouping
key) and a longer **minor** hash (a finer sub-bucket used only to pick the
most complete representative label within a major group). Two crash files
that hit the exact same bug through ASLR-shifted runs end up with
identical normalized frames and therefore the same major (and minor) hash,
even though their raw addresses never matched.
"""

import hashlib
import re

from autofte import vendored_ignore_lists

MAJOR_FRAME_COUNT = 1
NO_CONTEXT_MAJOR_FRAME_COUNT = 2
MINOR_FRAME_COUNT = 5
MAX_CYCLE_LENGTH = 10
REPEATED_CYCLE_COUNT = 3

_NOISE_FUNC_RE = re.compile(
    r"^("
    r"_start"
    r"|__libc_start_main"
    r"|__libc_start_call_main"
    r"|__libc_csu_init"
    r"|__libc_csu_fini"
    r"|__interceptor_.*"
    r"|__asan_.*"
    r"|__ubsan_.*"
    r"|__sanitizer_.*"
    r"|__GI_.*"
    r")$"
)
_UNRESOLVED_FUNCS = {"??", None}
_FRAME_OFFSET_SUFFIX_RE = re.compile(r"\+0x[0-9a-fA-F]+$")


def is_noise_frame(frame):
    func = frame.get("func")
    if func in _UNRESOLVED_FUNCS:
        return frame.get("file") is None
    stripped = _FRAME_OFFSET_SUFFIX_RE.sub("", func)
    if _NOISE_FUNC_RE.match(stripped) or vendored_ignore_lists.is_vendored_noise_function(
        stripped
    ):
        return True
    file_name = frame.get("file")
    if file_name and vendored_ignore_lists.is_vendored_noise_filepath(file_name):
        return True
    return False


def significant_frames(frames):
    return [frame for frame in frames if not is_noise_frame(frame)]


def _recursion_frame_key(frame):
    func = frame.get("func")
    if func and func != "??":
        return _FRAME_OFFSET_SUFFIX_RE.sub("", func)
    return frame.get("file")


def collapse_recursive_cycles(frames):
    """Collapse an unbounded/runaway-recursion run at the top of `frames`
    down to one copy of its repeating cycle, ClusterFuzz-style
    (`update_crash_state_for_stack_overflow_if_needed`).

    Expects `frames` to already be noise-filtered (i.e. the output of
    `significant_frames()`) -- it only ever reasons about real frames.
    Searches for the shortest cycle length `k` (1..`MAX_CYCLE_LENGTH`)
    whose repetition starting at frame 0 repeats at least
    `REPEATED_CYCLE_COUNT` times back to back; when found, every repetition
    past the first is dropped and any frames after the repeated run are
    kept unchanged. A stack with no such cycle is returned unmodified.
    """
    frame_count = len(frames)
    max_cycle_length = min(MAX_CYCLE_LENGTH, frame_count // REPEATED_CYCLE_COUNT)
    if max_cycle_length < 1:
        return frames

    keys = [_recursion_frame_key(frame) for frame in frames]
    for cycle_length in range(1, max_cycle_length + 1):
        cycle = keys[:cycle_length]
        repeat_count = 1
        pos = cycle_length
        while pos + cycle_length <= frame_count and keys[pos : pos + cycle_length] == cycle:
            repeat_count += 1
            pos += cycle_length
        if repeat_count >= REPEATED_CYCLE_COUNT:
            return frames[:cycle_length] + frames[pos:]
    return frames


def normalize_frame(frame, include_line=True):
    func = frame.get("func")
    if func and func != "??":
        func = _FRAME_OFFSET_SUFFIX_RE.sub("", func)
    else:
        func = None

    file_name = frame.get("file")
    line = frame.get("line") if include_line else None
    if file_name:
        file_name = file_name.rsplit("/", 1)[-1]

    if func and file_name and line:
        return f"{func}@{file_name}:{line}"
    if func and file_name:
        return f"{func}@{file_name}"
    if func:
        return func
    if file_name and line:
        return f"{file_name}:{line}"
    if file_name:
        return file_name
    return None


def normalized_keys(frames, include_line=True):
    keys = []
    for frame in significant_frames(frames):
        key = normalize_frame(frame, include_line=include_line)
        if key:
            keys.append(key)
    return keys


def _hash(keys):
    joined = "|".join(keys)
    return hashlib.sha1(joined.encode("utf-8")).hexdigest()[:16]


def stack_hashes(frames, extra_context=None):
    """Compute (major_hash, minor_hash) for a crash's frame list.

    `extra_context` is a list of extra tokens (e.g. a sanitizer bug class)
    always included ahead of the frame keys in both hashes -- it costs
    nothing from the frame-count budget but lets two crashes with the same
    stack but a different bug class (e.g. use-after-free vs.
    heap-buffer-overflow both surfacing in the same function) stay
    distinct.

    `MAJOR_FRAME_COUNT` (currently 1) is only safe when `extra_context` is
    supplied: it's tuned against the real Igor/GPTrace corpus, but every
    record there is a sanitizer report, so that measurement only ever
    covers the `extra_context`-supplied case. Callers with no context token
    at all (`triage.py`'s gdb-only path, when a target has no sanitizer
    build) get `NO_CONTEXT_MAJOR_FRAME_COUNT` (2) instead -- an adversarial
    review found a real, demonstrated case on that untested path where a
    single frame isn't enough to keep two different bugs apart (see
    `benchmarks/results.md`'s "W1 follow-up: gdb-path floor" entry and
    `tests/test_dedup.py::test_stack_hashes_major_frame_count_1_merges_distinct_bugs_sharing_a_top_frame`).

    Returns (None, None) if there is nothing left to hash after dropping
    noise frames (e.g. an empty or fully-noise stack) -- callers should
    fall back to grouping by whatever label they already have in that
    case, the same way the no-frame signal-only path always has.

    Before windowing, a repeated recursion cycle at the top of the
    (already noise-filtered) stack is collapsed to one copy via
    `collapse_recursive_cycles()` -- otherwise an unbounded-recursion
    crash's major hash would depend on stack depth (`ulimit -s`, ASLR,
    build), minting a new bucket for the same bug on every run.
    """
    frames = collapse_recursive_cycles(significant_frames(frames))
    minor_frame_keys = normalized_keys(frames)
    if not minor_frame_keys:
        return None, None
    major_frame_keys = normalized_keys(frames, include_line=False)

    context = list(extra_context) if extra_context else []
    major_frame_count = MAJOR_FRAME_COUNT if context else NO_CONTEXT_MAJOR_FRAME_COUNT
    major_keys = context + major_frame_keys[:major_frame_count]
    minor_keys = context + minor_frame_keys[:MINOR_FRAME_COUNT]
    return _hash(major_keys), _hash(minor_keys)


FREE_SITE_BUG_CLASSES = {"heap-use-after-free", "double-free", "bad-free"}


def stack_hashes_for_record(crash_record):
    """Compute (major_hash, minor_hash, stack_used) for a full sanitizer
    crash record, per the project methodology (HARDENING Part 3 fix #4).

    `stack_hashes()` above always hashes whatever frame list it's handed.
    This function is the record-aware wrapper around it that decides
    *which* stack a crash record's bug class should be hashed on, then
    delegates the actual hashing back to `stack_hashes()` unchanged:

    - `heap-use-after-free` / `double-free` / `bad-free`: hash the FREE
      stack (`stack_used="free"`), falling back to the crash stack if the
      free stack is empty (`stack_used="crash"`). Igor's finding is that
      the use/crash site for these bugs is the unstable one -- a dangling
      object can be read from wherever the program next happens to touch
      it, which varies with allocator state and input -- while the free
      site ("who released it too early") is the part of the bug's
      identity that stays put.
    - `*-leak`: hash the ALLOC stack (`stack_used="alloc"`) -- it is the
      only stack a leak report has at all.
    - everything else (`heap-buffer-overflow`, `stack-buffer-overflow`,
      `global-buffer-overflow`, `SEGV`, UBSan classes, ...): unchanged,
      hash the crash stack (`stack_used="crash"`), identical to calling
      `stack_hashes(crash_record["crash_stack"], ...)` directly.

    `stack_used` is returned so the choice is auditable in whatever
    report consumes it, per research/05's own "emit the choice into the
    report" instruction.

    Not yet wired into the live pipeline: `triage.py`'s `_classify_crash`
    still calls `stack_hashes(crash_stack, ...)` directly for every bug
    class, unchanged. Pointing that call site at this function instead is
    a follow-up task.
    """
    bug_class = crash_record.get("bug_class")
    crash_stack = crash_record.get("crash_stack") or []
    extra_context = [bug_class] if bug_class else None

    if bug_class in FREE_SITE_BUG_CLASSES:
        free_stack = crash_record.get("free_stack") or []
        if free_stack:
            major_hash, minor_hash = stack_hashes(free_stack, extra_context=extra_context)
            return major_hash, minor_hash, "free"
        major_hash, minor_hash = stack_hashes(crash_stack, extra_context=extra_context)
        return major_hash, minor_hash, "crash"

    if bug_class and bug_class.endswith("-leak"):
        alloc_stack = crash_record.get("alloc_stack") or []
        major_hash, minor_hash = stack_hashes(alloc_stack, extra_context=extra_context)
        return major_hash, minor_hash, "alloc"

    major_hash, minor_hash = stack_hashes(crash_stack, extra_context=extra_context)
    return major_hash, minor_hash, "crash"
