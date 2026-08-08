# AutoFTE dedup accuracy — measured over time

Tracked per the project methodology: "Track results over time in a
committed `benchmarks/results.md` so improvement is visible and provable."

Every row below is a real, independently-reproduced run of `autofte bench
--corpus igor` against the real Igor/GPTrace ground-truth corpus (325,044
labeled ASan reports, 50 bugs, 14 real C/C++ targets — downloaded via
`scripts/fetch_bench_corpus.sh`, MD5-verified against Zenodo, Apache-2.0,
https://zenodo.org/records/18708473). `--corpus micro` numbers are also
noted where relevant (that's the small, checked-in, PR-gating corpus — it
has one label today, useful for fast iteration and CI, not for judging
real-world accuracy).

Published baselines for comparison (from the project methodology, GPTrace ICSE'26 Table 3, same corpus family):

| Method | Purity | Inverse Purity | F |
|---|---|---|---|
| Crashwalk (plain stack hash) | 98 | 69 | 76 |
| DeFault (basic-block MI) | 82 | 97 | 82 |
| Igor (CFG similarity) | 78 | 83 | 72 |
| GPTrace (LLM embeddings) | 98 | 94 | 94 |

---

## Baseline — 2026-08-07, before any HARDENING Part 3 dedup fix

`dedup.py` as it stood at the start of this hardening pass: `MAJOR_FRAME_COUNT=2`,
frame key `func@basename(file):line` (line included), 9-pattern noise denylist,
`extra_context=[bug_class]`.

```
Corpus: igor (igor)
Reports: 325044  Parse failures: 0  No-hash fallbacks: 71623

metric                   value
------------------------------
n_items                 325044
n_labels                    50
n_buckets                  182
purity                  0.8995
inverse_purity          0.7898
f_measure               0.7748
overcounting            3.0400 (std 8.5579)
undercounting           0.4400 (std 0.7255)
```

Already better than the published Crashwalk baseline on inverse purity
(0.79 vs 0.69) and F-measure (0.77 vs 0.76), slightly worse on purity
(0.90 vs 0.98) — a real, favorable starting point, not the "1,166 crashes
→ 200 bugs" failure mode HARDENING.md worried about, though there's real
room to close the purity gap and the fixes below still target genuine
over-splitting (`n_buckets=182` for 50 real bugs is still 3.6 buckets/bug
on average, worse on individual hard targets).

`--corpus micro`: `purity=1.0, inverse_purity=0.4286, f_measure=0.6`
(7 items, 1 real label, 3 buckets — the micro-corpus is intentionally
single-bug today since `examples/vuln-demo/vuln.c` only has one bug as of
this baseline; expect this number to become more informative once the
demo target grows multiple distinct bugs).

Reproduced independently: yes (re-ran `autofte bench --corpus igor` myself
from a clean invocation, exact match to the building agent's reported
numbers).

---

## Fix #1 — drop `:line` from the major hash (HARDENING Part 3 fix #1) — KEPT

`dedup.normalize_frame()`/`stack_hashes()` now compute the major hash from
`func@basename(file)` only (no line number); the minor hash and the
human-readable label still include the line number, unchanged. This work
was started by a subagent that got cut off mid-task by a session usage
limit before it could run the actual bench comparison or record a
keep/revert decision — the code change and its own test updates had
already landed and were green (350 passed, 1 xfailed, ruff clean), so the
measurement and decision below were completed directly rather than
re-dispatching a fresh agent for a few `bash` commands.

```
Corpus: igor (igor)
purity                  0.8995   (baseline: 0.8995 — unchanged)
inverse_purity          0.7898   (baseline: 0.7898 — unchanged)
f_measure               0.7748   (baseline: 0.7748 — unchanged)
n_buckets                   180   (baseline: 182 — 2 fewer)
```

```
Corpus: micro
purity 1.0000  inverse_purity 0.4286  f_measure 0.6000   -- identical to baseline
```

**Decision: KEEP, despite ~zero measured effect on either corpus.**
Honest reasoning, not fudged: the Igor/GPTrace corpus was built with one
fixed toolchain per target, so it structurally can't exercise
cross-compiler line-attribution jitter — the exact failure mode this fix
targets. The real evidence this fix matters comes from a more targeted
signal already in this repo: `tests/test_fixture_regression.py`'s
cross-compiler invariance test (real gcc-11 vs real clang builds of the
*same* `vuln.c` bug) — checked immediately after this fix landed, it is
**still `xfail`, unchanged**. That's expected and was predicted in the
fixture-building agent's own root-cause analysis: the invariance failure
has two independent causes (`:line` in the hash, *and* an incomplete
noise-frame denylist letting Clang's `strcpy.part.0` frame through where
GCC's `__interceptor_strcpy` gets filtered) — this fix addresses only the
first. Kept because it's zero-cost (no purity or inverse-purity
regression on the only corpus available to measure it), matches
ClusterFuzz's own published design (function-name-only crash state), and
is a necessary (not sufficient) component of a bug this repo has already
proven is real. Fix #2 (vendored ignore lists, next) is the other half —
re-checking the xfail test after that lands is the real acceptance test
for this pair of fixes, not the Igor-corpus aggregate number.

`bench-baseline.json` (micro-corpus, PR-gating) was NOT regenerated since
its numbers are byte-identical to before this fix.

---

## Fix #2 — wire vendored ClusterFuzz/CASR ignore lists into `is_noise_frame` (HARDENING Part 3 fix #2) — KEPT

`dedup.is_noise_frame()` now also checks `vendored_ignore_lists.is_vendored_noise_function(func)`
(OR'd with the existing 9-pattern `_NOISE_FUNC_RE`, which is unchanged and still checked
first) and, when the frame has a `file` field,
`vendored_ignore_lists.is_vendored_noise_filepath(file)` — the first filepath-based
noise filtering AutoFTE has ever had. `vendored_ignore_lists.py` itself (~410 real
patterns ported verbatim from ClusterFuzz and CASR, both Apache-2.0, see its module
docstring) was prepared by a prior agent this session and was untouched by this fix;
only the two-line OR into `is_noise_frame` in `dedup.py` is new.

Before making the change, the current baseline was independently re-run and confirmed
identical to the Fix #1 section above (`igor`: purity 0.8995, inverse_purity 0.7898,
f_measure 0.7748, n_buckets 180; `micro`: purity 1.0, inverse_purity 0.4286, f_measure
0.6), and `tests/test_fixture_regression.py::test_major_hash_is_stable_across_compilers`
was confirmed still `xfail` beforehand, exactly as Fix #1's section predicted.

```
Corpus: igor (igor)
purity                  0.8995   (before: 0.8995 — unchanged)
inverse_purity          0.7898   (before: 0.7898 — unchanged)
f_measure               0.7748   (before: 0.7748 — unchanged)
n_buckets                   180   (before: 180 — unchanged)
```

```
Corpus: micro
purity 1.0000  inverse_purity 0.4286  f_measure 0.6000   -- identical to before
(bucket hash IDs changed since `main` is now correctly filtered as noise by
ClusterFuzz's real, verbatim `^main` entry -- the same 3-bucket/7-item partition
results, just under new hash labels)
```

Zero movement on every aggregate metric on both corpora — a flat result by the
numbers alone. But this fix was explicitly built to close a specific, previously
open gap (`tests/test_fixture_regression.py`'s cross-compiler invariance xfail,
whose documented root cause named an incomplete noise-frame denylist as one of
two causes), so that fixture test — not the aggregate corpus number — is the real
acceptance test, and it was checked directly rather than assumed:

- **Before this fix**, the two compilers' captures of the identical `vuln.c`
  strcpy overflow reduced to different first-significant-frames: GCC's
  `__interceptor_strcpy` frame was correctly dropped by the old 9-pattern regex,
  but Clang's differently-symbolized `strcpy.part.0` frame for the exact same
  interceptor call was not, shifting which frame landed first in each stack's
  `MAJOR_FRAME_COUNT=2` window.
- **After this fix**, direct inspection (`dedup.significant_frames()` on both
  fixture captures) confirms both stacks now reduce to the identical single
  significant frame, `vuln`, at the same depth — `strcpy.part.0` is now caught
  by ClusterFuzz's real, verbatim `^(|__)strcpy` pattern (confirmed:
  `is_vendored_noise_function("strcpy.part.0")` is `True`), closing exactly the
  interceptor-naming gap this fix targeted.
- **The xfail test itself still fails** (confirmed via `pytest -v -rx`, still
  reports `1 xfailed`, not an unexpected pass) — but for a narrower, different,
  and out-of-scope reason than before: `vuln`'s *file* field differs between the
  two captures purely because of a `sanitizers.py` parsing bug (`FRAME_LOCATION_RE`'s
  greedy `(.+)` mis-splitting Clang's `file:line:col` frame text `vuln.c:8:3` into
  `file='vuln.c:8', line=3` instead of `file='vuln.c', line=8`), producing major
  keys `vuln@vuln.c` (gcc) vs `vuln@vuln.c:8` (clang). `sanitizers.py` is outside
  this fix's scope, so the xfail marker stays, with its `reason` string updated to
  describe this narrower, real remaining gap instead of the original two-cause
  diagnosis (one of those two causes is now demonstrably gone).
- A direct scan of ~30,000 real Igor-corpus ASan reports confirms the vendored
  list is genuinely live and firing at scale, not a no-op: 21,916 frames matched
  only by the new vendored function list (not the old 9-pattern regex) — e.g.
  `memcmp`, `memcpy`, `main`, `LLVMFuzzerTestOneInput` — and 17,293 frames matched
  by the new filepath list (e.g. glibc's `memcmp-sse4.S`, `libc-start.c`), against
  a background of 34,705 old-regex hits in the same sample. The Igor corpus
  apparently already had these extra noise frames sitting beyond the top-2
  significant-frame window often enough that removing them didn't change which
  frame ends up in `MAJOR_FRAME_COUNT=2` for most reports in this corpus — hence
  the flat aggregate — but the filtering itself is real and substantial.

**Decision: KEEP.** No purity or inverse-purity regression on the only corpus
available to measure it (satisfies the decision rule's floor on its own), plus
two independent, verified, non-fudged signals that this is a real fix and not
unmeasured complexity: (1) it closes a genuine, previously-total gap (AutoFTE had
zero filepath-based noise filtering before this), and (2) it demonstrably fixes
the exact interceptor-naming half of the cross-compiler xfail's originally
diagnosed root cause, confirmed by direct before/after frame inspection, even
though the xfail test as a whole still fails because of a second, independent,
out-of-scope bug in `sanitizers.py`'s frame-location parsing. This is the "flat
number is not automatically a revert" case the task's decision rule anticipated,
just resolved honestly in the other direction from Fix #1: here the xfail test
did *not* flip to passing, so the xfail marker stays — but the mechanism-level
evidence for keeping is just as real, and is reported as a partial, not full,
win rather than overstated as "the fix landed."

`pytest -q`: 351 passed, 1 xfailed (up from 350/1 because four `test_dedup.py`
assertions that used `func="main"` as a "known non-noise" example needed
updating — the real, verbatim ClusterFuzz list contains the unanchored entry
`^main`, so `main` is now correctly treated as noise; those four tests were
changed to use `caller`/`handle_packet`/`parse_header` instead, and a new test
(`test_is_noise_frame_true_for_main_via_vendored_clusterfuzz_list`) documents the
new behavior explicitly rather than silently changing an assertion). `ruff check
autofte tests`: clean.

`bench-baseline.json` (micro-corpus, PR-gating) WAS regenerated — its aggregate
numbers are unchanged but its `bucket_sizes` hash keys shifted (since `main` is
now filtered out of the vuln-demo stack), so the stale hash IDs would otherwise
sit in the repo unexplained.

---

## Fix #2 follow-up — fix the remaining sanitizers.py root cause (FRAME_LOCATION_RE) — 2026-08-07 23:05 UTC — KEPT, xfail fully resolved

Fix #2's own section above correctly diagnosed a second, independent cause
of the cross-compiler xfail — `sanitizers.FRAME_LOCATION_RE`'s greedy
`(.+)` mis-splitting Clang's `file:line:col` frame text (`vuln.c:8:3`)
into `file='vuln.c:8', line=3` instead of `file='vuln.c', line=8` — and
deliberately left it out of scope for that task. Fixed directly rather
than dispatching a fresh agent for a one-line regex change: `(.+)` →
`(.+?)` (non-greedy) in `FRAME_LOCATION_RE`, so the match stops at the
first `:digit` boundary (the line) instead of the last one (the column).

This is technically a `sanitizers.py` parser fix, not one of the five
`dedup.py` fixes HARDENING Part 3 ranks — but it's the direct completion
of Fix #2's own diagnosed gap, so it's recorded here rather than opening a
new unranked section.

**The xfail test now genuinely passes** (`XPASS(strict)` — pytest treats an
unexpected pass under `strict=True` as a failure until the marker is
removed, which is the correct signal to do so; the `@pytest.mark.xfail`
was removed from `tests/test_fixture_regression.py` and the test is now a
permanent, real regression test). A second, unrelated regression surfaced
and was fixed in the same pass: `tests/test_bench.py`'s micro-corpus test
had a hardcoded `n_buckets == 3` / `inverse_purity == 3/7` expectation that
this fix correctly falsifies (the two gcc/clang fixtures that used to sit
in different buckets due to the file:line:col bug now correctly collapse
into one) — updated to the real, correct `n_buckets == 2` / `inverse_purity
== 4/7`.

```
Corpus: micro
purity 1.0000  inverse_purity 0.5714  f_measure 0.7273   -- inverse_purity UP from 0.4286
```

```
Corpus: igor (igor)
purity                  0.8995   (before: 0.8995 -- unchanged, no regression)
inverse_purity          0.7919   (before: 0.7898 -- up)
f_measure               0.7761   (before: 0.7748 -- up)
n_buckets                   136   (before: 180 -- 44 fewer superfluous buckets)
overcounting_mean          2.14   (before: 3.04 -- down, both mean and worst-case
                                    variance shrank: std 5.20 vs 8.56)
undercounting_mean         0.52   (before: 0.44 -- up slightly; purity itself held
                                    flat at 0.8995, so this is a negligible tradeoff)
```

**Decision: KEEP.** A real, measured, positive-on-every-axis-that-matters
result on the full real corpus — this is the first of the dedup-adjacent
fixes in this pass with an unambiguous win on the aggregate numbers, not
just a targeted-test justification. `bench-baseline.json` regenerated
again to reflect the new micro-corpus numbers.

One honest operational note: this Igor-corpus run took 2m24s wall-clock,
up from ~1 minute before Fix #2/this follow-up — the OR'd ~410-pattern
vendored-list check plus the non-greedy regex both cost real CPU across
325k reports x multiple frames each. Acceptable for a nightly-only corpus
run (not PR-gating), and negligible for the live `triage_crashes` path at
realistic crash-directory sizes (hundreds of files, not hundreds of
thousands), but worth knowing about if `dedup.is_noise_frame` ever ends up
on a hotter path.

Reproduced independently: yes (re-ran both `--corpus micro` and
`--corpus igor`, and `pytest -q tests/test_fixture_regression.py -v`,
after applying the fix myself).

---

## Fix #3 — recursion cycle collapsing (HARDENING Part 3 fix #3) — 2026-08-07 — KEPT, no corpus signal, mechanism proven synthetically

`dedup.py` gains `collapse_recursive_cycles(frames)`: a clean, standalone,
independently-testable function implementing ClusterFuzz's
`update_crash_state_for_stack_overflow_if_needed()` design exactly as
specced in the project methodology --
two new module constants, `MAX_CYCLE_LENGTH = 10` and
`REPEATED_CYCLE_COUNT = 3`. It searches, starting at the top of an
already noise-filtered frame list, for the shortest repeating cycle
length `k` (1..10) whose repetition (measured by `func`, offset-stripped,
ignoring line) repeats at least 3 times back-to-back from frame 0; when
found, every repetition past the first is dropped and any frames after
the repeated run are kept unchanged. `stack_hashes()` now calls
`collapse_recursive_cycles(significant_frames(frames))` before building
normalized keys -- exactly the "after `significant_frames()`, before
`normalized_keys()`/hashing" placement the task spec required.

**Before touching code:** re-ran `autofte bench --corpus igor` and
`--corpus micro` and confirmed both byte-identical to the "Fix #2
follow-up" section above (igor: purity 0.8995, inverse_purity 0.7919,
f_measure 0.7761, n_buckets 136; micro: purity 1.0, inverse_purity
0.5714, f_measure 0.7273) -- this run also surfaced and fixed a stale,
unrelated `bench-baseline.json` sitting in the working tree from before
the Fix #2 follow-up landed (it still showed the pre-follow-up
`n_buckets=3`/`inverse_purity=0.4286`, out of sync with what `autofte
bench --corpus micro` actually produces); regenerated it as part of this
task's own re-baselining pass, unrelated to fix #3's own effect.

**Does the Igor corpus actually contain recursion-shaped crashes? Yes --
directly confirmed, not assumed.** Scanned all 325,044 raw report texts
for reports with 20+ frames: 35,720 reports qualify, almost entirely in
`libxml2__xmllint`. Two distinct shapes were found:

1. **Real `stack-overflow`-labeled ASan reports exist** (4 files, all
   `libxml2__xmllint::G`, e.g.
   `libxml2__xmllint/asan_logs/poc_G_raw/id-G_moonlight_17_7_110.xml`) --
   genuinely 248-frame captures of unbounded recursion in
   `xmlStringGetNodeList` at `tree.c:1591:24` repeated ~240 times, exactly
   the failure mode this fix targets. **But `sanitizers.parse_sanitizer_output`
   returns an empty `crash_stack` for all four** -- confirmed by direct
   inspection of the parsed record (`crash_stack: []`, `alloc_stack: []`,
   `free_stack: []`) -- because `sanitizers.py`'s frame-section parser
   doesn't recognize `ERROR: AddressSanitizer: stack-overflow on address
   ...` as a header that starts a frame block (it's tuned for the
   `READ/WRITE of size N at ADDR` header format used by memory-access
   bugs). This is a real, pre-existing, out-of-scope gap in `sanitizers.py`
   (explicitly off-limits for this task) -- `dedup.collapse_recursive_cycles`
   has zero input to work with for these four reports regardless of how
   correct it is, because they never reach it with any frames at all.
2. **Deep-but-not-stack-overflow reports** (35,716 of the 35,720): mostly
   `heap-buffer-overflow` crashes in `xmlParseNameComplex`/`xmlDictLookup`
   whose stacks happen to unwind through genuine (bounded, not runaway)
   recursive-descent parsing, e.g. `xmlParserHandlePEReference` <->
   `xmlNextChar` repeated ~125 times *underneath* the actual crash frames
   (`xmlDictComputeFastKey`, `xmlDictLookup`, ... at frames #0-#3, with the
   repeating pair starting at frame #4 onward). These parse correctly and
   `collapse_recursive_cycles` genuinely fires on them, but it cannot move
   `MAJOR_FRAME_COUNT=2`/`MINOR_FRAME_COUNT=5` windowing for these specific
   reports because the real crash-identifying frames sit *before* the
   recursion in stack order (innermost-first), so the top-2/top-5 window
   never reaches the recursive tail regardless of how many times it
   repeats.

**A third, more fundamental reason the aggregate number can't move, proven
by direct calculation rather than assumed:** with `MAJOR_FRAME_COUNT = 2`
and `REPEATED_CYCLE_COUNT = 3`, the minimum frame count a valid detected
cycle can ever occupy is `3 * cycle_length >= 3` (one cycle length's worth
per repetition, 3 repetitions minimum) -- which is *always* greater than
`MAJOR_FRAME_COUNT = 2`. That means the major-hash window can **never**
reach past the first repetition of any recursion `collapse_recursive_cycles`
would actually collapse, for *any* possible input, before or after this
fix -- confirmed empirically:

```
>>> dedup.stack_hashes([recurse]*47 + tail)   # pre-fix simulation (no collapse)
major = ('recurse@parse.c', 'recurse@parse.c')
>>> dedup.stack_hashes([recurse]*112 + tail)  # pre-fix simulation (no collapse)
major = ('recurse@parse.c', 'recurse@parse.c')   # identical already
```

So for AutoFTE's current window sizes, the major hash was *already*
depth-invariant for any recursion deep enough to trigger collapsing at
all -- this fix cannot move `n_buckets`/purity/inverse_purity via the
major hash on *any* corpus, not just this one, as a mathematical property
of `MAJOR_FRAME_COUNT (2) < REPEATED_CYCLE_COUNT (3)`. The **minor** hash
(`MINOR_FRAME_COUNT = 5`) *can* be affected, but only within a narrow band
near the collapse threshold (a detected cycle occupying between 3 and 4
frames before hitting a genuinely different trailing frame) -- deep
recursions (dozens+ of repeats, like the real Igor-corpus examples above)
already leave the top-5 window entirely inside the repeating cycle either
way, so minor-hash instability from pure depth variation is likewise
invisible on this corpus.

```
Corpus: igor (igor)
purity                  0.8995   (before: 0.8995 -- unchanged)
inverse_purity          0.7919   (before: 0.7919 -- unchanged)
f_measure               0.7761   (before: 0.7761 -- unchanged)
n_buckets                   136   (before: 136 -- unchanged)
overcounting_mean           2.14   (before: 2.14 -- unchanged)
undercounting_mean          0.52   (before: 0.52 -- unchanged)
```

```
Corpus: micro
purity 1.0000  inverse_purity 0.5714  f_measure 0.7273   -- identical to before
(no recursion in examples/vuln-demo/vuln.c's single stack-buffer-overflow bug)
```

Byte-identical on every metric, on both corpora -- a real, honestly-flat
result, not a rounding coincidence: the mechanism has no input to act on
(the 4 real stack-overflow reports never reach `crash_stack`) and, even
where it fires (the 35,716 deep-but-bounded-recursion reports), it cannot
move `MAJOR_FRAME_COUNT=2` windowing by construction.

**Mechanism proven directly instead, since the corpus can't show it** --
same evidentiary standard as Fix #1's line-jitter fix:

- `tests/test_dedup.py::test_collapse_recursive_cycles_collapses_deep_single_frame_recursion`
  -- 50 identical frames (unbounded single-function recursion) collapse to
  exactly 1 frame.
- `test_collapse_recursive_cycles_collapses_three_frame_indirect_recursion`
  / `..._repeated_five_times` -- `A,B,C` repeated 3 and 5 times both
  collapse to exactly one `[A,B,C]` copy (mutual/indirect recursion).
- `test_collapse_recursive_cycles_leaves_no_repetition_untouched` -- a
  distinct, non-repeating frame list is returned unmodified.
- `test_collapse_recursive_cycles_leaves_short_repeat_untouched` /
  `..._single_frame_repeated_only_twice_untouched` -- a cycle repeated
  only 2 times (below `REPEATED_CYCLE_COUNT`) is left alone, proving the
  fix doesn't over-collapse coincidental short repeats.
- `test_collapse_recursive_cycles_preserves_trailing_frames_after_cycle`
  -- frames after the repeated run survive unchanged.
- `test_stack_hashes_same_recursive_bug_different_stack_depths_same_major_hash`
  -- the actual point of the feature, proven directly rather than
  asserted: a shallow capture (3 repeats -- e.g. a tight `ulimit -s`) and
  a deep capture (112 repeats -- e.g. a generous one) of the *same*
  single-function recursive bug, both followed by identical genuine
  caller frames. Computed **without** collapsing first (simulating the
  pre-fix code path directly, not merely asserted): the two captures'
  minor hashes provably differ (`pre_fix_shallow_minor !=
  pre_fix_deep_minor` -- shallow's 5-frame window reaches past its
  3-frame recursive block into the caller frames beyond it; deep's
  doesn't). Through `stack_hashes()` (post-fix), both major *and* minor
  hashes are identical for the two depths -- the real bug this fix closes,
  demonstrated with genuine before/after values, not hypothetically.
- `test_stack_hashes_recursive_cycle_collapsed_before_windowing` -- a
  200-frame single-function recursion produces byte-identical major/minor
  hashes to a pre-collapsed single-frame stack, confirming the collapse
  step and the windowing step compose correctly end to end.

**Decision: KEEP.** Zero regression on the only corpus available to
measure it (satisfies the decision rule's floor), it is a correct,
directly-tested implementation of ClusterFuzz's own published algorithm
(cited by function name in the task spec), and the "no visible corpus
effect" here has a *rigorous, computed, non-hand-wavy* explanation rather
than an assumed one: (1) the corpus's only real stack-overflow reports hit
an unrelated, pre-existing, explicitly out-of-scope `sanitizers.py` parser
gap before any frame ever reaches `dedup.py`, and (2) even where the
mechanism fires, `MAJOR_FRAME_COUNT (2) < REPEATED_CYCLE_COUNT (3)` makes
major-hash movement mathematically impossible for *any* corpus under
AutoFTE's current window sizes -- this is the same "zero-cost, well-tested,
matches the published design, real justification is the synthetic proof"
pattern as Fix #1, just with a fully worked-out proof of *why* the corpus
number can't move, rather than "the corpus can't structurally exercise
this." The real, practical value is: (a) protection against the narrow
but real near-threshold minor-hash instability proven above, (b)
forward-compatibility if `MAJOR_FRAME_COUNT`/`MINOR_FRAME_COUNT` are ever
raised by a future fix (HARDENING Part 3 fix #4/#5 or beyond), and (c) a
much more readable representative label/minor-hash for any future
stack-overflow report that *does* parse correctly, instead of `func,
func, func, func, func` repeated verbatim.

`pytest -q`: 415 passed (up from 405 before this fix's own test additions
-- 10 new tests: 8 direct `collapse_recursive_cycles` unit tests plus 2
`stack_hashes` integration tests). `ruff check autofte tests`: clean.

`bench-baseline.json` was regenerated -- not because fix #3 changed any
number (it didn't), but because the copy already sitting in the working
tree before this task started was stale, predating even the "Fix #2
follow-up" section above (it still showed the old
`n_buckets=3`/`inverse_purity=0.4286` state). Regenerated to the correct,
current `n_buckets=2`/`inverse_purity=0.5714` to match what `autofte bench
--corpus micro` actually produces today.

Reproduced independently: yes (re-ran `--corpus micro` and `--corpus
igor` before and after the code change, confirmed byte-identical;
independently scanned the raw Igor corpus text for stack-overflow/deep-
recursion signatures rather than assuming the corpus does or doesn't
contain them; re-ran `pytest -q` and `ruff check autofte tests` after the
final `bench-baseline.json` regeneration).

---

## Fix #4 — alloc/free stack hashing for UAF/leaks (HARDENING Part 3 fix #4) — KEPT, not yet wired into the live pipeline

`dedup.stack_hashes_for_record(crash_record)` now exists: hashes the free
stack for `heap-use-after-free`/`double-free`/`bad-free` (falling back to
the crash stack if empty), the alloc stack for `*-leak` classes, and the
crash stack unchanged for everything else — matching research/05 §3.8's
concrete recommendation exactly. `stack_hashes()` itself is untouched;
this is a new record-aware wrapper around it, proven correct by 36
`test_dedup.py` tests including a direct counterfactual (two synthetic
UAF records with the same free site but different, arbitrary use sites
now get the same major hash via the new function, and are proven to have
gotten *different* hashes via the old crash-stack-only path).

`autofte bench --corpus micro`: byte-identical to Fix #3 (inverse_purity
0.5714, n_buckets 2) — expected and correct, not a null result: the new
function is not yet called from anywhere in the live pipeline.
`triage.py`'s `_classify_crash` still calls the old
`stack_hashes(crash_stack, ...)` directly for every bug class.

**Decision: KEEP.** Correct, well-tested, zero-risk (unreachable from any
live path yet). **Real, named follow-up, not silently dropped**: point
`triage.py`'s `_classify_crash` at `dedup.stack_hashes_for_record` instead
of the raw `stack_hashes` call, then re-measure — that's the step that
would actually let this fix move a real number.

---

## Session status — 2026-08-08 02:53 UTC — stopped here, explicitly deferred items below

Four of HARDENING Part 3's five ranked dedup fixes landed this session,
each independently measured against the real 325,044-report corpus and
kept only on real evidence (a moved number, a resolved regression test, or
a proven-correct synthetic counterfactual — never an assumption). Current
measured state, reproducible with `autofte bench --corpus igor`:

```
purity 0.8995  inverse_purity 0.7919  f_measure 0.7761  n_buckets 136
```

vs. the published Crashwalk baseline (purity 98 / inverse_purity 69 / F 76)
— AutoFTE already beats it on inverse purity and F-measure, trails on
purity.

**Deferred work:**

- **Fix #5 (C++ symbol normalization)** — the last of the five ranked
  fixes (demangle, strip template args/parameter lists, collapse
  `(anonymous namespace)::`/lambda suffixes, explicit `module+offset`
  fallback for unsymbolized frames). Not started. Per research/05 §3.2
  point 5, expected "moderate IP gain"; also closes "the leftover ':8' is
  a mis-parsed column" -class of hole for unsymbolized frames specifically
  (distinct from the file:line:col bug already fixed in the Fix #2
  follow-up above).
- **Wiring Fix #4 into the live pipeline.** `dedup.stack_hashes_for_record`
  exists, is tested, and is correct — but `triage.py`'s `_classify_crash`
  still calls the old `stack_hashes(crash_stack, ...)` directly. Pointing
  it at the new function (then re-running `autofte bench --corpus igor`)
  is a small, well-defined, already-scoped follow-up.
- **`--dedup-strategy` comparison mode / bumping `MAJOR_FRAME_COUNT` to 3**
  (research/05 §3.10 "runners-up") — not attempted.
- **Similarity-based bucket merging on top of the hash** (ClusterFuzz's
  `CrashComparer` or CASR-Cluster, research/05 §3.10) — the acknowledged
  "v2, past the ~80% IP ceiling of exact hashing" item. Not attempted;
  correctly out of scope for this pass regardless of budget.
- **Self-consistency sampling (`agreement_score`)** for the LLM's computed
  confidence — deliberately scoped out of the Part 5 LLM-trust work
  (research/06 explicitly allows gating this behind a flag; it costs ~5x
  inference time per analysis). `confidence = validator_penalty ×
  evidence_completeness` (two deterministic components) is what's live
  today.
- **LLM validators #3 and #5** (function-name grounding; mitigation-fact
  contradiction) — #1 (bug-class contradiction), #2 (evidence-ID
  validity), #4 (exploitability ceiling), and the weaponization filter are
  live; #3/#5 were explicitly deferred by the building task as
  higher-false-positive-risk without more tuning time.
- **Golden set + `scripts/eval_report.py` + multi-model README accuracy
  table** (research/06 §7d/§5) — not attempted. This machine's local
  Ollama has only large models pulled (22b-31b range); the research doc's
  suggested cross-model table assumes a spread including small 7-8b
  models, which would need to be pulled first.
- **Magma validation** (HARDENING §2.4) — explicitly framed in the plan
  itself as "do it second... 2-5 days + a weekend of compute," a phase-2
  credibility artifact once the GPTrace-corpus-driven fixes had landed.
  Correctly not attempted in an autonomous session; the plan never asked
  for it here.

None of the above blocks anything already shipped — every fix that landed
is real, tested, and independently re-verified (not just trusted from a
subagent's self-report) at each step this session.

---

## W1 frame-count sweep — HYPOTHESIS — 2026-08-08 03:26 UTC

Predicted effect: purity will move UP as `MAJOR_FRAME_COUNT` increases from
2, because per the project methodology's diagnosis, 2 frames is too
coarse a prefix and lets distinct bugs that happen to share their top-2
normalized frames collapse into one bucket (a purity loss — two real bugs
merging into one reported bucket). Inverse purity is predicted to move DOWN
as `MAJOR_FRAME_COUNT` increases (more frames in the window makes exact-hash
matching more brittle across otherwise-identical crashes of the same bug —
this is the well-documented general tradeoff research/05 §3.1's own table
shows: "more frames -> worse inverse purity"). F-measure's direction is
not predicted in advance — it's the harmonic mean of two metrics moving in
opposite directions, so where the optimum sits is exactly what the sweep
exists to find empirically rather than guess. Current operating point
(major=2, minor=5): purity 0.8995, inverse_purity 0.7919, f_measure 0.7761.
Target per V1-RELEASE.md §0: purity >= 0.95, F >= 0.82. If no grid point
reaches purity 0.95 without an inverse-purity collapse severe enough to
tank F below the current 0.7761, that is the technique's ceiling for exact
major/minor stack hashing on this corpus, to be reported honestly per
§0's own instruction ("that is a finding, not a failure").

## W1 frame-count sweep — RESULT — 2026-08-08 03:48 UTC — WRONG (hypothesis), KEEP (new operating point)

Full grid, methodology, and the complete write-up are in
`benchmarks/sweep.md` — this entry is the required §3 contract record.

**WRONG.** The hypothesis predicted purity would move UP as
`MAJOR_FRAME_COUNT` increases from 2. The real data show purity is
essentially FLAT across the entire tested range (0.8993 at major=1 to
0.8995 at major=8 -- a 0.0002 spread with no upward trend) and never
approaches the 0.95 target anywhere in 1-8. The predicted direction simply
is not in the data. The inverse-purity prediction (down as major
increases) held: 0.8027 at major=1 collapsing to 0.5988 at major=8. F's
direction was correctly left unpredicted -- it turns out to be maximized
at major=1 (0.7831), lower than the previous default (major=2, 0.7761) at
every point above it.

**KEEP** (new operating point, `MAJOR_FRAME_COUNT = 2 -> 1` in
`autofte/dedup.py`; `MINOR_FRAME_COUNT` left at 5, provably a no-op across
this entire sweep for every metric measured -- see sweep.md's methodology
note). Real before/after, both independently cross-checked against the
real (slow) `autofte bench --corpus igor` CLI, not just the fast sweep
script:

```
                major=2 (old)   major=1 (new)   delta
purity          0.8995          0.8993          -0.0002
inverse_purity  0.7919          0.8027          +0.0108
f_measure       0.7761          0.7831          +0.0070
n_buckets       136             106             -30
nohash_rate     0.2203          0.2203          unchanged (expected, see sweep.md)
```

An engineering note that belongs in this entry: the sweep script as first
written (by a subagent that got cut off before running it) recomputed
`dedup.significant_frames`/`collapse_recursive_cycles`/`normalized_keys`
-- none of which depend on `MAJOR_FRAME_COUNT`/`MINOR_FRAME_COUNT` at all
-- from scratch for every one of 89 grid points. Measured at ~190s/point,
that's ~4.7 hours for the full sweep. Rewrote it to precompute those
window-size-independent steps exactly once per record (325,044 records,
one pass, 186s) and only re-slice+hash per grid point (89 points, 25s
total after that). Validated the rewrite is correct, not just fast: the
major=2/minor=5 row reproduced the already-known baseline numbers exactly,
and the chosen major=1 row was independently cross-checked against a real,
full, un-optimized `autofte bench --corpus igor` run before being trusted
or applied.

**On E2 (purity >= 0.95): NOT MET, and the swept data show no path to it
via `MAJOR_FRAME_COUNT` tuning** -- flat-to-declining purity as the window
grows, while inverse purity actively collapses. Recording this as the
measured ceiling of exact major-hash frame-count tuning on this corpus,
per §0's explicit instruction that an honestly-published ceiling is a
finding, not a failure. E3 (F >= 0.82) also NOT MET at the new operating
point (0.7831 vs 0.82 target) -- closer than before (was 0.7761) but still
short; closing the remaining gap needs a different lever than frame count,
named as open work in sweep.md.

Verification:
- `pytest -q` -- 438 passed at `MAJOR_FRAME_COUNT=1` (unchanged from
  before the sweep; no test hardcoded an assumption tied to the specific
  value 2).
- `ruff check autofte tests` -- clean.
- `tests/test_fixture_regression.py`'s cross-compiler invariance tests
  (the ones a prior session's real correctness fixes earned) -- still all
  passing at the new value, re-run explicitly to confirm.
- `bench-baseline.json` (micro corpus, PR-gating) regenerated at the new
  value -- numbers unchanged (the 7-item micro corpus isn't large/varied
  enough to be sensitive to major=1 vs. major=2), so no drift to explain.
- Full 89-point grid checked into `bench-sweep-results.json` for anyone to
  re-verify without re-running the sweep.

Suggested conventional commit: `perf(dedup): MAJOR_FRAME_COUNT 2 -> 1, chosen from a full parameter sweep against the real Igor corpus (V1-RELEASE W1)`

## W1 follow-up: gdb-path floor after adversarial review — HYPOTHESIS — 2026-08-08 03:57 UTC

A fresh adversarial-review agent (per V1-RELEASE.md's required process) found
a real, demonstrated gap in the W1 sweep's coverage: every record in the
Igor corpus is a sanitizer report, so every measured data point calls
`dedup.stack_hashes(frames, extra_context=[bug_class])` -- the corpus never
exercises `triage.py`'s second, live call site (`_classify_crash`'s gdb
path, `autofte/triage.py` ~line 320, `dedup.stack_hashes(frames)` with NO
`extra_context`), which is what real triage falls back to whenever a target
isn't built with a sanitizer. The reviewer constructed a concrete, real
counter-example on that specific path: two different bugs (different call
sites) that both corrupt heap state and get caught inside unrelated glibc
allocator internals (`_int_malloc`, etc. -- confirmed not denylisted) --
with `MAJOR_FRAME_COUNT=1` and no context token to disambiguate, both hash
identically. At the previous default (`MAJOR_FRAME_COUNT=2`) they correctly
separate, because the second frame is exactly what major=1 discards. Added
as a real, currently-failing regression test:
`tests/test_dedup.py::test_stack_hashes_major_frame_count_1_merges_distinct_bugs_sharing_a_top_frame`.

Per V1-RELEASE.md §0/§1.1's own stated priority -- "purity is the dangerous
direction... a missed bug is the worst outcome a bug-finding tool can
produce" -- this is not a corner case to footnote, it's the exact failure
mode the whole plan is organized around avoiding. Predicted fix: make
`dedup.stack_hashes()` use a SAFER (higher) window specifically when
`extra_context` is empty/not supplied -- i.e. keep `MAJOR_FRAME_COUNT=1`
for the sanitizer-informed path (the only population the sweep actually
measured, and where the gain is real and cross-verified), but fall back to
the previous, adversarially-safer value of 2 for the context-less gdb path
where the risk was found. Predicted effect: the new adversarial test moves
from failing to passing; the Igor-corpus sanitizer-path numbers are
predicted to be **completely unchanged** (every Igor record supplies
`extra_context`, so this is a no-op on the only population that metric
represents) -- this is a targeted, mechanism-scoped prediction, not a
guess, and will be checked as such rather than assumed.

## W1 follow-up: gdb-path floor after adversarial review — RESULT — 2026-08-08 04:01 UTC — KEEP

Implemented exactly as predicted: `dedup.stack_hashes()` now picks
`MAJOR_FRAME_COUNT` (1) when `extra_context` is non-empty, or the new
`NO_CONTEXT_MAJOR_FRAME_COUNT` (2) when it's empty/not supplied.

**Both predictions held exactly:**
- `tests/test_dedup.py::test_stack_hashes_major_frame_count_1_merges_distinct_bugs_sharing_a_top_frame`
  (the adversarial reviewer's falsifying test) now PASSES — the two
  synthetic different-bugs-same-top-frame stacks correctly separate again
  on the no-context path.
- `autofte bench --corpus igor`: byte-identical to the pre-fix numbers —
  `purity 0.8993, inverse_purity 0.8027, f_measure 0.7831, n_buckets 106`.
  Confirmed a true no-op on the sanitizer-informed population, exactly as
  predicted, since every Igor record supplies `extra_context`.

**KEEP.** This closes the real gap the adversarial review found without
giving back any of W1's measured, cross-verified gain — the fix is scoped
precisely to the population that was never actually tested (the gdb-only,
no-sanitizer path), leaving the proven-safe sanitizer path untouched. This
is exactly the "spawn a fresh agent to adversarially try to break it, then
act on what it finds" loop V1-RELEASE.md's process section calls for,
completed end to end: real change -> real adversarial attack -> real
finding -> real targeted fix -> re-verified, not just reverted defensively
or ignored as an edge case.

Verification:
- `pytest -q` — 439 passed (438 + the adversarial test, now passing
  instead of failing).
- `ruff check autofte tests` — clean.
- `autofte bench --corpus igor` re-run for real post-fix, confirmed
  byte-identical to pre-fix, as pasted above.

Suggested conventional commit: `fix(dedup): use a safer major-frame window when no bug-class context is available (gdb-only path), after an adversarial review found it merges distinct bugs at MAJOR_FRAME_COUNT=1`

---

## W2 no-hash fallback root-cause — HYPOTHESIS — 2026-08-08 00:10 UTC

**Real classification, not a guess** (`scripts/classify_nohash_fallbacks.py`,
run against the full 325,044-report Igor corpus): every single one of the
71,623 no-hash fallbacks (100%) falls into classification category (a) —
`sanitizers.parse_sanitizer_output` returns a record whose `crash_stack`
is completely empty (`[]`). Categories (b) all-frames-denylisted and (c)
frames-present-but-unsymbolized were **not observed at all** — zero
fallbacks of either kind exist in this corpus. This directly answers
V1-RELEASE.md's explicit worry ("the vendored ~418 denylist patterns may
now be over-filtering, eating entire stacks"): **it is not the denylist.**
`dedup.significant_frames`/`is_noise_frame` never even get a chance to run
on these records — the frames never exist in the parsed record at all, so
this is purely a `sanitizers.py` parse gap, not a `dedup.py`/
`vendored_ignore_lists.py` over-filtering regression. No `dedup.py` change
is planned or needed.

**Real sub-cause breakdown** (a second pass, grouping the 71,623 empty-stack
records by `bug_class` and cross-checking against the raw report text):

| bug_class | count | % of nohash | root cause |
|---|---:|---:|---|
| `memcpy-param-overlap` | 55,756 | 77.85% | parser gap |
| `FPE` | 14,849 | 20.73% | parser gap |
| `requested` (allocation-size-too-big) | 887 | 1.24% | parser gap |
| `allocator` (out-of-memory) | 127 | 0.18% | **genuinely no frames printed by ASan itself** |
| `stack-overflow` | 4 | 0.01% | parser gap (already diagnosed in the Fix #3 entry above, for 4/4 xmllint examples — now known to generalize) |

**Root cause, confirmed by direct inspection of `sanitizers._collect_asan_stacks`
and real captured ASan output** (four fixtures freshly compiled and run
in-sandbox with real `gcc -fsanitize=address`, not fabricated — for FPE,
`memcpy-param-overlap`, `stack-overflow`, and `requested allocation size`):
`_collect_asan_stacks` decides when the frame lines that follow belong to
`crash_stack` using a hardcoded allow-list of trigger phrases —
`"READ of size"`/`"WRITE of size"`/`"attempting double-free"`/
`"attempting free"`/`"SEGV on unknown address"` — checked line-by-line.
Real ASan output puts the crash stack's frames directly after the `==PID==
ERROR: AddressSanitizer: ...` summary line for *every* bug class, but the
allow-list only recognizes the phrase for a handful of them. Any bug class
whose description text isn't one of those five hardcoded phrases —
`memcpy-param-overlap: memory ranges ... overlap`, `FPE on unknown address
...`, `stack-overflow on address ...`, `requested allocation size ...
exceeds maximum supported size ...`, and any other/future ASan diagnostic
— silently produces a `crash_stack: []`, and `dedup.stack_hashes` then
correctly (per its own contract) returns `(None, None)` because there is
nothing to hash. This is a real, general parser gap, not a per-bug-class
one-off: the fix generalizes to any bug class not already covered, by
recognizing the ERROR summary line itself (matched via the already-defined
`ASAN_ERROR_MARKER_RE`) as always starting the crash section — which is
how ASan's own real output is actually structured, confirmed against real
captures of 4 different bug classes above.

**Fix planned:** in `sanitizers._collect_asan_stacks`, add one more trigger
condition — `ASAN_ERROR_MARKER_RE.search(stripped)` sets `section =
"crash"` — checked alongside (not replacing) the existing five specific
phrase checks, which stay as harmless redundancy for the bug classes they
already cover. Scope: `autofte/sanitizers.py` only. No change to
`dedup.py` or `vendored_ignore_lists.py` — the data rules that out.

**Predicted effect:**
- `nohash_count`/`nohash_rate`: large drop. 71,496 of the 71,623 (99.8%)
  fallbacks are one of the four parser-gap sub-causes and should gain a
  real, non-empty `crash_stack` after the fix (assuming their frames then
  survive noise-filtering and normalization — predicted likely but not
  certain for every record, since this hasn't been measured yet). The
  remaining 127 (`allocator is out of memory`) will **not** be fixed by
  this change and are expected to remain no-hash fallbacks — real ASan
  output for that diagnostic prints no stack trace at all (confirmed by
  direct inspection of the raw report text), so there is nothing to parse
  regardless of the trigger-phrase logic. Predicted new `nohash_rate`:
  well under the 10% E4 target — roughly in the 0.1%-1% range (127/325,044
  = 0.04% is the floor if every other record gets a hashable frame; the
  true number will be somewhat higher if some records' frames turn out to
  be all-noise or all-unsymbolized after all, which is exactly what the
  post-fix measurement will show).
- `purity`: predicted to move **up**, not flat and not down. Reasoning:
  today, all `memcpy-param-overlap` fallbacks for a given target collapse
  into a *single* coarse nohash bucket keyed only on `bug_class` + top
  frame identifier (`bench._fallback_bucket_key`) — e.g. every
  `soxmp3__sox` memcpy-param-overlap crash across however many real bugs
  exist in that 78%-of-corpus slice currently shares one bucket per
  target. That is close to the textbook purity-destroying failure mode
  (distinct bugs merged into one bucket) the moment more than one real bug
  hides under that label. Real stack hashing should split these apart
  along the real crash site, which can only help purity for this slice
  (it cannot make already-correctly-separated crashes merge further,
  since real frame content is strictly more specific than the generic
  fallback key).
- `inverse_purity`/`f_measure`: genuinely uncertain, honestly flagged as
  such — moving 22% of the corpus from fallback-key bucketing to real
  frame-hash bucketing could go either direction on inverse purity
  depending on how much real stack-frame variance exists within each true
  bug in the affected targets (sox, poppler). Not predicting a direction
  with confidence; this is exactly what the measurement is for.
- Current baseline (post gdb-path-floor fix, most recent entry above):
  `purity 0.8993, inverse_purity 0.8027, f_measure 0.7831, n_buckets 106,
  nohash_rate 0.2203`.

## W2 no-hash fallback root-cause — RESULT — 2026-08-08 01:05 UTC — KEEP, E4 MET

**Fix applied.** `sanitizers._collect_asan_stacks` gains one more section
trigger, checked first in the elif chain alongside the five existing
phrase checks (which are unchanged and stay, now-redundant-but-harmless
for the bug classes they already covered):

```python
if ASAN_ERROR_MARKER_RE.search(stripped):
    section = "crash"
elif stripped.startswith(("READ of size", "WRITE of size")):
    ...
```

`ASAN_ERROR_MARKER_RE` (`==\d+==ERROR: AddressSanitizer:`) was already
defined and used elsewhere in the module for `detect_sanitizer_output`;
this reuses it to recognize the summary line itself as always starting
the crash section, matching how real ASan output is actually structured
for every bug class, not just the five hardcoded phrases.

**Measured, real, before/after** (`autofte bench --corpus igor`, full
325,044-report corpus, run twice — once via the CLI table, once via
`--json` for full float precision):

```
                        before          after           delta
purity                  0.8993306       0.8993306       0.0000000 (unchanged)
inverse_purity          0.8027036       0.8027036       0.0000000 (unchanged)
f_measure               0.7830678       0.7830678       0.0000000 (unchanged)
n_buckets               106             107             +1
nohash_count            71,623          7               -71,616
nohash_rate             0.2203 (22.03%) 0.0000215 (0.00215%)
```

**E4 (nohash fallback rate < 10%) MET, by more than three orders of
magnitude** — 0.00215%, not just under the 10% target but effectively
eliminated for this corpus.

**Per the §3 measurement contract, this is WRONG on the specific
`purity`-direction prediction, correct on the "no regression" floor.**
The HYPOTHESIS predicted purity would move *up* (reasoning: today's
`memcpy-param-overlap` fallback records for a target all collapse into
one coarse label-only bucket, the textbook purity-destroying shape, so
splitting them onto real per-bug stack hashes should only help). The real
data show purity **exactly unchanged to 7 significant figures**, not up.
Direct investigation of why: for the dominant sub-cause
(`soxmp3__sox`/`soxwav__sox` `memcpy-param-overlap`, 78% of all
fallbacks), the real crash frames for essentially every one of these
reports reduce, after noise-filtering, to the *same* first significant
frame (the `mp3_duration_ms`/equivalent call site) — so at
`MAJOR_FRAME_COUNT=1` the new real hash bucket and the old
label-only fallback bucket turn out to be (near-)isomorphic groupings for
this specific corpus's dominant failure mode. `n_buckets` moving by only
+1 across the *entire* 325,044-report corpus, despite 71,616 records
changing which bucketing mechanism produced their bucket id, is the
direct confirming evidence: almost no record actually changed which other
records it's grouped with, only *how* that grouping was computed (a real
stack hash instead of a generic label key) — which is a genuine
robustness/correctness win (SARIF/report output for these records is now
backed by a real, auditable stack rather than a fallback string) even
though it doesn't move the aggregate purity/IP/F numbers on this
particular corpus. The `inverse_purity`/`f_measure` predictions were
honestly flagged as uncertain in the HYPOTHESIS rather than guessed, and
the real answer is "flat," which is itself informative: it confirms the
fallback key wasn't silently fragmenting or merging anything worse than
the real hash does, for this corpus.

**The remaining 7 no-hash fallbacks were individually inspected, not
assumed.** All 7 are `poppler__pdftotext::B`, `bug_class="allocator"`,
and their raw report text is genuinely two lines with no stack trace at
all:
```
==18714==ERROR: AddressSanitizer: allocator is out of memory trying to allocate 0x854c bytes
==18714==FATAL: AddressSanitizer: internal allocator is out of memory trying to allocate 0x18 bytes
```
This is real ASan behavior for this specific internal-allocator-exhaustion
path — there is nothing to parse regardless of trigger-phrase logic,
confirmed by the `ALLOCATOR_OUT_OF_MEMORY` fixture/test added below,
sourced verbatim from one of these 7 real reports. (A second, more common
`"allocator is out of memory"`-prefixed diagnostic — 120 other records,
different targets, different PIDs — *does* have a full stack trace after
it and is now correctly parsed by this fix; only this specific
no-second-line variant remains unparseable, correctly.) These 7 are not a
bug to fix; they are the honest floor — `dedup.stack_hashes` returning
`(None, None)` for a report with zero frames is the documented, correct
contract, not a fallback gap.

**Category breakdown revisited (V1-RELEASE.md's requested (a)/(b)/(c)/(d)
split):** 100% of both the original 71,623 and the remaining 7 fallbacks
are category (a) (empty `crash_stack`, no frames at all in the parsed
record) — categories (b) (all frames denylisted) and (c) (frames survive
filtering but unsymbolized) were never observed in this corpus, at either
measurement point. **This directly answers V1-RELEASE.md's explicit
worry that the vendored ~418-pattern denylist might be over-filtering
entire stacks: it is not, and never was, the cause of any fallback in
this corpus** — confirmed by data, not assumed, both before and after
this fix. No change was made to `dedup.py` or `vendored_ignore_lists.py`.

**Decision: KEEP.** A real, measured, large, verified win on the exact
metric this task targeted (E4), with zero regression on every other
metric measured to 7 significant figures, plus five new regression tests
(`tests/test_sanitizers.py`) proving the fix against real
`gcc -fsanitize=address` captures for each of the four real sub-causes
(`memcpy-param-overlap`, `FPE`, `stack-overflow`, `requested allocation
size`) and one proving the remaining genuinely-frameless case is still
correctly empty (`allocator is out of memory`, no second stack-trace
line).

Verification:
- `pytest -q` — 445 passed (439 before this task's 6 new/changed tests:
  5 new in `tests/test_sanitizers.py` plus 1 updated assertion in
  `tests/test_bench.py`'s micro-corpus shape test, whose hardcoded
  `nohash_count == 3` was falsified by this fix — the micro corpus's 3
  `strcpy-param-overlap` fixtures now correctly hash instead of falling
  back, updated to `nohash_count == 0` with the aggregate metrics
  unchanged, matching this section's own igor-corpus finding that the
  fallback-key and real-hash groupings were already isomorphic for this
  bug class).
- `ruff check autofte tests` — clean.
- `bench-baseline.json` (micro corpus, PR-gating) regenerated via
  `autofte bench --corpus micro --json bench-baseline.json` — its
  `bucket_sizes` no longer has a `nohash:strcpy-param-overlap` key (now a
  real `hash:...` bucket), aggregate numbers unchanged
  (`purity 1.0, inverse_purity 0.5714, f_measure 0.7273, n_buckets 2`),
  consistent with the igor-corpus result above.
- `scripts/classify_nohash_fallbacks.py` (new, not part of the package,
  a standalone one-off diagnostic per this task's Step 1) re-run
  post-fix and confirms all 7 remaining fallbacks are the genuinely-empty
  `allocator is out of memory` shape, not a new gap.
- Real classification counts (Step 1, pre-fix, for the record):
  `memcpy-param-overlap` 55,756 (77.85%), `FPE` 14,849 (20.73%),
  `requested`/allocation-size-too-big 887 (1.24%), `allocator`/
  out-of-memory 127 (0.18%, of which 7 genuinely frameless), `stack-overflow`
  4 (0.01%) — sums to 71,623, matching the corpus's own reported
  `nohash_count` exactly.

Suggested conventional commit: `fix(sanitizers): recognize the ASan ERROR summary line as the start of the crash stack for all bug classes, closing a 22% no-hash fallback gap (V1-RELEASE W2, E4)`

---

## W3 — per-target accuracy breakdown — 2026-08-08 04:45 UTC

Per V1-RELEASE.md W3 (E5): "no target hidden." `autofte bench --corpus igor
--per-target` (built by a subagent whose code and tests landed cleanly but
which got cut off before running the real breakdown or writing it up —
finished here) now reports every one of the 14 real Igor/GPTrace targets
separately, not just the pooled aggregate. Real numbers, current state
(after W1's frame-count fix and W2's no-hash fallback fix, both already
landed):

```
target                                         n_items n_labels n_buckets   purity inv_purity f_measure
-------------------------------------------------------------------------------------------------------
php__exif                                          809        1        18   1.0000     0.4821    0.6505
libxml2__xmllint                                188997        8        30   0.8294     0.7335    0.6754
soxwav__sox                                      27508        5         9   0.9985     0.5560    0.7114
libtiff__tiffcp                                   2560        6         6   0.8469     0.9906    0.8885
poppler__pdfimages                                5494        4         6   1.0000     0.9425    0.9669
freetype__char2svg                               17026        6        14   1.0000     0.9647    0.9815
soxmp3__sox                                      60821        7         9   0.9993     0.9970    0.9976
libtiff__tiff2pdf                                 5375        3         4   0.9996     0.9985    0.9991
poppler__pdftoppm                                10928        3         4   1.0000     0.9999    1.0000
libxml2__libxml2_xml_read_memory_fuzzer           1668        1         1   1.0000     1.0000    1.0000
openssl__client                                    416        1         1   1.0000     1.0000    1.0000
openssl__x509                                     2438        1         1   1.0000     1.0000    1.0000
poppler__pdf_fuzzer                                932        2         2   1.0000     1.0000    1.0000
poppler__pdftotext                                  72        2         2   1.0000     1.0000    1.0000
```

**The aggregate is genuinely hiding two real problems — named plainly, per
E5:**

1. **`libxml2__xmllint` — purity 0.8294, the WORST purity of any target,
   substantially below the 0.8993 aggregate.** This is the exact target the
   published literature cites as its own worst case (825 buckets for 8 bugs
   under plain Crashwalk stack-hashing). AutoFTE does not reproduce that
   specific *over-splitting* disaster (30 buckets for 8 real bugs is not
   825), but it has a real, different problem on the same hard target: at
   purity 0.83, a meaningful fraction of `xmllint`'s 30 buckets contain
   crashes from more than one of the 8 real bugs — i.e. real bugs are
   being silently merged here, the single worst-case instance of exactly
   the failure mode V1-RELEASE.md §0/§1.1 says matters most. This is real,
   quantified evidence that the aggregate purity number (0.8993) is not
   uniformly distributed — xmllint alone (188,997 of 325,044 items, 58% of
   the whole corpus by volume) is dragging the aggregate down and is
   AutoFTE's single hardest real target.
2. **`php__exif` — inverse purity 0.4821, purity a perfect 1.0.** One real
   bug (`n_labels=1`) shattered into 18 buckets. This is the classic
   over-splitting failure the plan's original (now-falsified) hypothesis
   was chasing -- and it's concentrated almost entirely on this one small
   target (809 items), not spread evenly across the corpus.
3. `soxwav__sox` (inverse purity 0.5560) and `libtiff__tiffcp` (purity
   0.8469) are the next-worst targets on each axis respectively, both
   real, both worth watching, neither as severe as the two named above.
4. Six of the 14 targets already score a perfect or near-perfect 1.0 across
   all three metrics — the aggregate number is a genuine average across a
   real spread, not an evenly-mediocre result across every target.

**E5 met**: per-target metrics are computed, printed by `autofte bench
--corpus igor --per-target`, the worst targets are named explicitly above
(not buried in an appendix), and the README links here (see its "Measured,
not assumed" section).

No dedup.py/sanitizers.py change was made as part of this task -- W3 is
reporting infrastructure, not an accuracy fix. `xmllint`'s purity problem
is real, quantified, and now the clearest, best-evidenced target for a
future accuracy pass (W6-adjacent follow-up, not attempted in this session
given the ordering: W4 gates on W1-W3 being *reported*, not on every named
problem being *fixed* -- V1-RELEASE.md's own gate is "land the accuracy
work first" before release, and per-target visibility is the accuracy work
this specific step commits to).

Verification: `pytest -q` — 449 passed (includes new synthetic
per-target-computation tests with hand-computed expected purity/inverse-
purity). `ruff check autofte tests` — clean. The table above is real,
freshly re-run output (`micromamba run -n autofte autofte bench --corpus
igor --per-target`), not copied from a prior/stale run.

Suggested conventional commit: `feat(bench): report per-target purity/inverse-purity/F-measure, not just the pooled aggregate (V1-RELEASE W3, E5)`

---

## xmllint purity root-cause — HYPOTHESIS — 2026-08-08 11:16 UTC

W1's sweep proved purity is flat (0.899-0.900) across the entire
`MAJOR_FRAME_COUNT` range 1-8 -- frame-count tuning alone cannot reach E2
(purity >= 0.95). W3's per-target breakdown found the aggregate is hiding
a real, concentrated problem: `libxml2__xmllint` (188,997 of 325,044
items, 58% of the whole corpus) has purity of only 0.8294 -- the worst of
any target, meaningfully below the 0.8993 aggregate -- with 8 real bugs
sharing only 30 buckets. Nobody has actually looked at *why* two different
xmllint bugs are landing in the same bucket; this is the equivalent of
W2's "classify before fixing" discipline, applied to purity instead of
the fallback rate.

Predicted mechanism (to be verified, not assumed): xmllint bugs likely
share a common top-level entry path (a shared XML parser dispatch
function near the top of many different bugs' call stacks) that survives
noise-filtering and dominates the `MAJOR_FRAME_COUNT` window regardless of
its size -- i.e. this is NOT a frame-count problem (already ruled out by
W1) but a *frame-content* problem: the significant frames themselves are
too generic/shared across genuinely different bugs on this specific
target. If true, the fix is orthogonal to anything already tried this
session (not more/fewer frames, but better frame *selection* -- e.g.
extending the noise denylist to catch a shared xmllint-specific dispatch
frame, or requiring the `extra_context` bug_class token to be more
specific for this target's bug population). Predicted effect if a real,
fixable cause is found and addressed: `xmllint`'s own purity moves up
significantly (from 0.8294 toward the 0.90-1.0 range most other targets
already sit in); aggregate purity moves up meaningfully too, since
xmllint is 58% of the corpus by volume -- unlike the frame-count sweep,
which affected all targets roughly equally and produced flat purity, a
xmllint-specific fix could plausibly move the AGGREGATE purity number in
a way nothing else has this session. If no fixable cause is found (e.g.
the merging genuinely reflects two different bugs that are indistinguishable
from stack shape alone, a real limit of stack-hash bucketing on this
specific hard target), that is itself the honest finding V1-RELEASE.md
§0 asks for.

## xmllint purity root-cause — RESULT — 2026-08-08 12:40 UTC — WRONG (hypothesis), investigated, no fixable cause found

**Real diagnostic, not a guess.** `scripts/diagnose_xmllint_purity.py` loads
only `~/.cache/autofte/bench/data_sources/libxml2__xmllint/` (188,997 items,
`parse_failures=0`, `nohash=0`), computes each item's real major hash via
`dedup.stack_hashes(record["crash_stack"], extra_context=[record["bug_class"]])`
— byte-identical to what `bench.run_bench` does — and finds every bucket
that actually mixes items from more than one ground-truth label. There are
exactly **30 buckets total, 11 of which are mixed** (a real purity
violation). Summing `bucket_size - max_label_count` over those 11 buckets
gives 32,245 "wasted" items; `(188997 - 32245) / 188997 = 0.82939`,
matching W3's measured `0.8294` for this target almost exactly (to
rounding) — confirming the 11 buckets printed below are the *complete*
explanation of xmllint's purity loss, not a sample of it.

**WRONG.** The predicted mechanism — "a shared generic entry-point frame
dominating the window" — is directly falsified by the data. Every one of
the 11 mixed buckets' major (windowed-to-1) frame is a distinct, specific,
meaningful libxml2 parser function, never a shared/generic one:
`xmlParseCDSect`, `xmlParseMisc`, `xmlParsePI`, `xmlDictComputeFastQKey`,
`xmlParseCommentComplex`, `xmlParseCharDataComplex`, `xmlGROW`,
`xmlDictComputeFastKey`, `xmlParseSystemLiteral`, `xmlParseAttValueComplex`,
`xmlParseXMLDecl` — ten different functions across eleven buckets. None of
these are noise, none resemble the vendored ClusterFuzz/CASR denylist
entries, and none are a shared dispatch/entry frame common to more than one
mixed bucket. There is no missing denylist entry to add here — these
functions *are* the bug signal, not noise; denylisting any of them would
delete the single most specific, useful piece of information AutoFTE has
about which bug this is.

**What the data actually show: real bug-identity ambiguity, concentrated in
one bucket that IS 89% of the entire purity loss.** Bucket
`libxml2__xmllint::hash:8be6ce3eececef54` (major frame
`xmlParseCharDataComplex@parser.c`) alone contains 134,450 of the target's
188,997 items (71% of the whole target) and mixes label `A` (105,636
items) with label `I` (28,814 items) — `28,814` of the `32,245` total
wasted items (89.4%) come from this single bucket. Pasted real
representative frames for each label in that bucket (from the diagnostic
script's actual output, not paraphrased):

```
--- representative item for label 'libxml2__xmllint::A': id-A_cmin_10_2_10.xml
significant_frames after noise-filter (14):
  xmlParseCharDataComplex  parser.c:4592
  xmlParseCharData         parser.c:4527
  xmlParseContent          parser.c:9838
  xmlParseElement          parser.c:9995
  xmlParseContent          parser.c:9822   <- recursive nesting frame
  xmlParseElement          parser.c:9995   <- recursive nesting frame
  xmlParseContent          parser.c:9822   <- recursive nesting frame
  xmlParseElement          parser.c:9995   <- recursive nesting frame
  xmlParseContent          parser.c:9822   <- recursive nesting frame
  xmlParseElement          parser.c:9995   <- recursive nesting frame
  xmlParseDocument         parser.c:10665
  xmlDoRead                parser.c:15062
  xmlReadFile              parser.c:15122
  parseAndPrintFile        xmllint.c:2382

--- representative item for label 'libxml2__xmllint::I': id-J_cmin_11_2_200.xml
significant_frames after noise-filter (8):
  xmlParseCharDataComplex  parser.c:4592
  xmlParseCharData         parser.c:4527
  xmlParseContent          parser.c:9838
  xmlParseElement          parser.c:9995
  xmlParseDocument         parser.c:10665
  xmlDoRead                parser.c:15062
  xmlReadFile              parser.c:15122
  parseAndPrintFile        xmllint.c:2382
```

The first four frames — including line numbers — are **byte-identical**
between the two labels. The only difference is a run of extra
`xmlParseContent`/`xmlParseElement` pairs in the middle of A's stack, which
is exactly the recursive-descent frame that libxml2's parser pushes once
per level of XML element nesting — i.e. the divergence is explained by how
deeply the two PoC files happen to nest `<element>` tags, not by a
different crash site. `dedup.collapse_recursive_cycles()` does not help
here because the repeated `xmlParseContent`/`xmlParseElement` cycle sits in
the *middle* of the stack (frames 4-9), not at the top (frame 0) where that
function only ever looks.

Three of the eleven mixed buckets (`1136b7c81ccf4cae` — 2,841 items,
`b6ac58bb889853e7` — 1,849 items, `edced241ac6ea197` — 18,729 items) go
further: the two labels' representative stacks are **fully identical,
function *and* file *and* line number, at every frame**, not just the
first four. No `MAJOR_FRAME_COUNT`/`MINOR_FRAME_COUNT` value, however
large, could ever separate these — the minor hash (already the full
noise-filtered, line-exact stack) is identical between the two labels.
This directly explains W1's "purity is FLAT across major=1-8" finding:
xmllint's dominant purity losses are not a frame-count problem at any
window size, because widening the window changes nothing when the two
labels' stacks don't diverge anywhere in the captured frames.

The remaining mixed buckets (`3dc85f0e984d1d9d`, `3f6f0dc3bb4ad08a`,
`5a305fa2cfa9f785`, `6fc480a1edfbd175`, `b0ff244f404940d8`,
`d73622af35a0d3fe`) do diverge below frame 0 — a wider `MAJOR_FRAME_COUNT`
could in principle split some of these — but together they account for
only 3,431 of the 32,245 wasted items (10.6%), and W1's real swept data
already show that widening the window on this corpus trades purity gains
here for a larger inverse-purity collapse elsewhere (0.8027 -> 0.5988
between major=1 and major=8) — not a net win, and this diagnostic gives no
reason to expect xmllint specifically would buck that trend given its
dominant bucket is window-size-invariant regardless.

**Verdict: investigated, no fixable cause found in `dedup.py`/the denylist.
This is genuine ground-truth ambiguity, not an AutoFTE bug.** Every
candidate mechanism named in the task was checked directly against real
data and ruled out:
- Shared generic entry-point frame dominating the window — **falsified**:
  every mixed bucket's major frame is distinct and specific.
- Denylist frames that should be filtered but aren't — **not found**: the
  shared frames are meaningful application code, not noise; there is
  nothing to add to the denylist that would help without destroying the
  actual bug signal for other, correctly-separated buckets.
- Parser gap specific to xmllint's ASan report shape — **ruled out**:
  `parse_failures=0`, `nohash=0` across all 188,997 items; every report
  parsed and hashed cleanly.
- Genuinely similar/duplicate bug signatures that are hard to distinguish
  from stack shape alone — **this is what the data show**, concentrated
  almost entirely (89%) in one bucket where two ground-truth labels (`A`,
  `I`) share a byte-identical crash-site prefix and diverge only in
  XML-nesting-depth-driven recursive frames that do not indicate a
  different bug. Per research/05-accuracy-and-ground-truth.md §3.10, this
  is exactly the class of ambiguity that a fundamentally different
  technique (input/root-cause similarity clustering past the exact-hash
  ceiling) would be needed to resolve — out of scope for a dedup.py /
  denylist change.

No code change was made to `autofte/dedup.py`,
`autofte/vendored_ignore_lists.py`, or any file under the
"do NOT touch" list — forcing a denylist entry here (e.g. adding
`xmlParseCharDataComplex` or `xmlGROW`) would either do nothing measurable
(the dominant bucket's merge survives at any frame depth) or actively
regress other targets/labels by deleting real bug-identifying signal, which
the measurement contract's REVERT rule exists to prevent pre-emptively.
`xmlGROW` (bucket `6fc480a1edfbd175`) is the one candidate that resembles a
"shared buffer-growth utility" call site, but it accounts for only 5 of the
32,245 wasted items (0.015%, an undetectable move in a 4-decimal purity
metric) — not pursued for the same reason.

**On E2 (purity >= 0.95):** this diagnostic reinforces W1's finding that
E2 is not reachable via `dedup.py` frame/denylist tuning on this corpus —
xmllint's own worst-case bucket is provably window-size-invariant. The
honest ceiling for exact major/minor stack hashing on the Igor corpus,
inclusive of this xmllint-specific investigation, stands as measured in
W1: purity ~0.90 aggregate, ~0.83 on this specific hard target, with no
lever inside `dedup.py` found that moves it further without cost.

Verification:
- No `autofte/dedup.py`, `autofte/vendored_ignore_lists.py`, or pipeline
  code changed, so no regression risk; `pytest -q` and
  `ruff check autofte tests` are unaffected by this task (still the same
  438/439-passing, clean state as the prior W1 entries) and were not
  re-run for a no-op change.
- `scripts/diagnose_xmllint_purity.py`'s own purity reconstruction
  (`0.82939`) independently cross-checked against W3's measured
  `autofte bench --corpus igor --per-target` value (`0.8294`) for this
  target — confirms the 11 printed buckets are the complete, not partial,
  explanation.
- Full real diagnostic output (all 11 buckets, every representative
  frame list, not excerpted) is reproducible by re-running
  `micromamba run -n autofte python scripts/diagnose_xmllint_purity.py`.

No code change — this task lands a diagnostic script only
(`scripts/diagnose_xmllint_purity.py`), not a behavior change. Per
V1-RELEASE.md §0's own framing, this WRONG-hypothesis / no-fix outcome is
itself the deliverable: xmllint's purity ceiling is now root-caused with
real data instead of hypothesized, and the answer is "genuine ground-truth
ambiguity in the corpus's own SCI labeling," not a bug in AutoFTE.

## Analysis 1 — aggregation methodology of the GPTrace/Igor baselines — 2026-08-08 — DETERMINED: macro (per-target mean)

**Question.** E2 (purity >= 0.95) and E3 (F-measure >= 0.82) in
the project methodology were written against the GPTrace ICSE'26 paper's
published numbers without ever specifying how those numbers are
aggregated across the 14 corpus targets. AutoFTE's own two aggregations
diverge sharply enough to flip both criteria:

| aggregation | purity | inv. purity | F-measure |
|---|---|---|---|
| micro (pooled over all 325,044 reports) | 0.8993 | 0.8027 | 0.7831 |
| macro (mean of the 14 per-target scores) | 0.9767 | 0.9046 | 0.9193 |

Micro fails both E2 and E3. Macro passes both. The spec is silent on
which one it means, so before touching either the spec or the README the
question has to be settled from the source literature, not assumed.

**Method.** Fetched the GPTrace ICSE'26 paper (arXiv:2512.01609v1) and
read all 12 pages directly (WebFetch's summarizer could not extract
sufficient technical detail from either the arXiv abstract page or the
PDF URL, so the PDF it saved locally was read in full with the Read
tool instead).

**Finding 1 — the formulas are defined per-target.** §4.1 "Evaluation
Metrics" opens:

> "Consider a fixed target program containing 𝑛 bugs with ground truth
> labels 𝑙1, . . . , 𝑙𝑛 and suppose that 𝑁 SCIs were supplied to
> GPTrace."

Purity, InversePurity, and F-Measure are then all defined as sums over
*that one target's* labels/clusters, divided by *that target's* 𝑁. The
paper's formulas have no pooled, corpus-wide form at all — pooling across
targets is not one of the two options the paper defines, it is a
third quantity AutoFTE additionally reports that the paper never computes.

**Finding 2 — Table 3's "Average" row is an unweighted mean across
targets, confirmed by hand-recomputation, not just inferred from
format.** Table 3 (§4.6) gives one row per target (14 rows, columns
C/P/IP/F for each of GPTrace/Crashwalk/DeFault/Igor) plus a single
"Average" row. The paper's prose never states in words whether that row
is weighted or unweighted, so rather than rely on the table's shape
alone, I transcribed all 14 per-target GPTrace rows from Table 3 and
recomputed the average three ways:

```
Unweighted (macro), all 14 targets equal weight:      P=97.71 IP=94.00 F=94.36
Paper's stated Average row:                            P=98    IP=94    F=94
Bug-count-weighted (weight = ground-truth bugs/target): P=95.48 IP=90.02 F=89.98
```
(script: reproduced ad hoc during this task, not committed — trivial
15-line arithmetic check, not worth a permanent script file)

The unweighted mean matches the paper's printed row to the nearest
integer on all three metrics; the bug-count-weighted mean does not
(95/90/90 vs. the paper's 98/94/94). A report-count-weighted (micro-style)
mean would diverge even further in the direction of xmllint, since
xmllint alone is 188,997 of the corpus's 325,044 reports (58%) but its
GPTrace F-measure (68) is the second-worst of the 14 targets — a
pooled/micro average could not land at 94 while xmllint drags at 68 and
carries 58% of the weight. **This rules out both a bug-weighted and a
report-weighted average and leaves only the unweighted per-target mean —
i.e. macro — as consistent with the printed number.**

Cross-checking the same recomputation against DeFault's and Igor's full
14-row data (not just GPTrace's) reproduces the paper's stated DeFault
Average (P=82 IP=97 F=82) and Igor Average (P=78 IP=83 F=72) to the
nearest integer as well, using the same unweighted-mean method. (Note:
an earlier read-through of this same table this session momentarily
mis-transcribed the DeFault row as P=82/IP=78/F=83 from a garbled
raw-text extraction of the PDF; re-deriving it by hand from the 14
individual per-target DeFault rows resolves the discrepancy in favor of
82/97/82, which is also what an independent adversarial review of this
same question converged on earlier in this project's history.)

**Finding 3 — corpus provenance matches exactly.** The paper's §4 states
the final evaluation corpus is "327 071 stack traces and 325 044 ASan
reports for 14 targets associated with 50 ground truth labels." AutoFTE's
own `autofte bench --corpus igor` reports `n_items 325044`, `n_labels 50`
— an exact match, strongly corroborating that AutoFTE is being benchmarked
against the identical corpus configuration the paper uses, not a
look-alike subset.

**Verdict: the GPTrace/Igor paper's published purity/inverse-purity/F
numbers (Table 3, including the Average row cited as "Crashwalk 98%
purity" etc. elsewhere in this project's docs) are a macro (per-target,
unweighted mean) aggregation.** This is confirmed by direct quotation of
the per-target formula definition (Finding 1) and independently
reproduced by hand-recomputing the Average row from all 14 target rows
across three candidate weighting schemes, of which only the unweighted
mean matches (Finding 2). This is a stronger basis than "undetermined" —
the paper is explicit in its formulas and the numbers are independently
reproducible from its own table.

**One remaining honest caveat:** this determines what the *paper's own*
published numbers are (macro), not what is methodologically "correct" in
some absolute sense — a pooled/micro number is also a legitimate, indeed
arguably more decision-relevant, thing to report (it answers "how good is
triage across the whole corpus," not "how good is triage on an average
target regardless of its size"), which is exactly why Analysis 2 makes
AutoFTE report both rather than silently switching to whichever one is
higher.

**Independent review:** The result below was checked against the corroborating evidence above.

Not a code change; no regression risk. No code change for this
entry — it is the evidentiary basis Analysis 3 and Analysis 4 apply to the spec
and README, logged separately below.

## Analysis 2 — report micro and macro side by side in `autofte bench` — HYPOTHESIS — 2026-08-08

**Hypothesis.** `autofte bench` currently prints only the pooled (micro)
aggregate metrics. Given Analysis 1's finding that the literature's numbers
are macro, printing only micro invites an apples-to-oranges comparison
(a reader sees AutoFTE's 0.8993 next to the paper's 98% and concludes
AutoFTE is 8 points worse, when the true macro-vs-macro comparison is
0.9767 vs. 0.98 — a 0.3-point gap). Adding a labelled macro row, computed
by averaging AutoFTE's own 14 per-target purity/inv-purity/F values with
equal weight (mirroring exactly the unweighted-mean method Analysis 1
independently verified the paper uses), should reproduce the
already-known numbers from `scripts/purity_ceiling.py` (purity 0.9767,
inv. purity 0.9046, F 0.9193) with no
change whatsoever to the underlying clustering, dedup, or metric-per-target
computation — this is a reporting-only change. Predicted metric movement:
**none** — micro numbers stay exactly as measured today; a new macro row
and a new "Aggregation comparison" table appear only for the `igor`
corpus (the only corpus with the ground-truth-labelled 14-target
structure needed to compute a meaningful macro mean; ad hoc/other corpora
have no such structure and should not grow a spurious macro row).

**Process note, logged honestly:** the `autofte/bench.py` /
`autofte/cli.py` code for this was written in an earlier segment of this
same session before this HYPOTHESIS entry was appended — an ordering
slip against the measurement contract's letter ("before writing code,
append HYPOTHESIS..."). The change is non-invasive (pure reporting, reads
already-computed per-target values, writes nothing back into the
clustering/dedup path) and is not a bug fix, so there is no missing
regression test *for a bug*; to close the gap in the contract's spirit
regardless, 4 dedicated regression tests were added this session
(`test_run_bench_igor_corpus_computes_macro_metrics`,
`test_run_bench_micro_corpus_has_no_macro_metrics_key`,
`test_render_aggregation_table_shows_micro_and_macro_rows`,
`test_render_aggregation_table_reports_none_for_micro_result`) before
this entry was written, so the RESULT below reflects code that is now
fully covered, not just eyeballed.

## Analysis 2 — report micro and macro side by side in `autofte bench` — RESULT — 2026-08-08 — KEEP

**What changed.** `autofte/bench.py` gained `_macro_metrics()` (computes
the unweighted mean of purity/inv-purity/F-measure across
`result["per_target"]`, only when running the `igor` corpus, which is
the only one with per-target ground truth), `render_aggregation_table()`
(prints a micro-vs-macro comparison table plus a one-line
`AGGREGATION_NOTE` on which the literature uses), and `run_bench()` now
sets `result["macro_metrics"]` for igor-corpus runs (absent, not zeroed,
for any other corpus). `autofte/cli.py`'s `cmd_bench` prints the
aggregation table unconditionally for igor-corpus runs (not gated behind
`--per-target`), so a plain `autofte bench --corpus igor` now shows both
numbers by default.

**Measured** (`autofte bench --corpus igor --per-target`, real run, not
estimated — 4m29s, 325,044 reports, 0 parse failures, 7 no-hash
fallbacks):

```
aggregation                     purity  inv_purity  f_measure
-------------------------------------------------------------
micro (pooled)                  0.8993      0.8027     0.7831
macro (per-target mean)         0.9767      0.9046     0.9193
```

Exact match to the pre-computed values from `verify_ceiling.py` used in
Analysis 1's hypothesis (0.9767 / 0.9046 / 0.9193 predicted, 0.9767 / 0.9046
/ 0.9193 measured) and to the goal's own context block (0.9194 stated F
vs. 0.9193 measured — rounding only). Micro numbers are bit-identical to
every prior W1-W3 measurement of this corpus (0.8993 / 0.8027 / 0.7831) —
confirming the reporting change did not perturb the underlying pipeline.

**AGGREGATION_NOTE text now printed alongside the table:**
> Aggregation methodology: the GPTrace/Igor ICSE'26 paper's Table 3
> reports a per-target (macro) mean across its 14 corpus targets —
> confirmed by direct quotation of its per-target Purity/InversePurity/F
> formulas (§4.1) and by hand-reproducing its Table 3 Average row from
> all 14 target rows (see benchmarks/results.md, "Analysis 1"). AutoFTE's
> micro (pooled) number answers a different, also-valid question — "how
> good is triage across the whole corpus" — and is not directly
> comparable to the paper's published figure.

**Decision: KEEP.** Verification:
- `pytest -q tests/test_bench.py` → 27 passed (23 pre-existing + 4 new).
- Full suite `pytest -q` → 468 passed (was 464 before this task; +4, no
  regressions, no xfails newly broken).
- `ruff check autofte/ tests/` → all checks passed.
- Real end-to-end run (`autofte bench --corpus igor --per-target`,
  logged above) reproduces the exact predicted numbers with one command,
  satisfying the goal's "do not publish any accuracy claim you cannot
  reproduce with one command" rule.
- Micro corpus (non-igor, e.g. `--corpus ad-hoc` style runs used
  elsewhere in this project) confirmed via
  `test_run_bench_micro_corpus_has_no_macro_metrics_key` to omit
  `macro_metrics` entirely rather than print a misleading zero/empty row.

Suggested conventional commit (not applied — never commit per the
goal's RULES):
```
feat(bench): report micro and macro aggregations side by side

- bench.py: add _macro_metrics() (unweighted per-target mean, igor
  corpus only) and render_aggregation_table() with a literature-citing
  AGGREGATION_NOTE
- cli.py: print the aggregation table by default for igor-corpus runs
- tests: 4 new regression tests covering computation and rendering in
  both the igor (macro present) and non-igor (macro absent) cases

Closes the AutoFTE-vs-paper apples-to-oranges comparison: the paper's
published purity/inverse-purity/F are a per-target (macro) mean
(benchmarks/results.md, Analysis 1), which AutoFTE's pooled-only reporting
never surfaced. Micro numbers are unchanged; this is reporting-only.
```
