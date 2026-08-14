# W1 — `MAJOR_FRAME_COUNT` × `MINOR_FRAME_COUNT` sweep

Per `planning/V1-RELEASE.md` W1. Full grid, real numbers, run against the
real 325,044-report Igor/GPTrace corpus via `scripts/sweep_frame_counts.py`
(major 1–8 × minor 3–15, `minor >= major`, 89 grid points).

**Methodology note, important for reading this table:** `metrics.py`'s
purity/inverse-purity/F-measure/n_buckets are computed from the **major
hash only** — `triage.py`'s live grouping buckets crashes by major hash;
the minor hash only picks which representative label to show *within* an
already-formed major bucket. So every metric below is **constant across
all `minor` values for a given `major`** — this sweep is genuinely a
1-D sweep over `MAJOR_FRAME_COUNT` for these headline numbers, not a 2-D
one, and the table reflects that (one row per `major`, `minor` doesn't
move anything measured here). `MINOR_FRAME_COUNT` still matters for label
quality/sub-bucket disambiguation, just not for these accuracy metrics.

## The full grid (one row per `major`; identical across every tested `minor` 3–15)

| major | purity | inverse_purity | f_measure | n_buckets | nohash_rate |
|---|---|---|---|---|---|
| **1** | 0.8993 | **0.8027** | **0.7831** | 106 | 0.2203 |
| 2 (previous default) | 0.8995 | 0.7919 | 0.7761 | 136 | 0.2203 |
| 3 | 0.8995 | 0.7895 | 0.7746 | 155 | 0.2203 |
| 4 | 0.8995 | 0.7855 | 0.7718 | 169 | 0.2203 |
| 5 | 0.8995 | 0.6959 | 0.7292 | 178 | 0.2203 |
| 6 | 0.8995 | 0.6938 | 0.7276 | 199 | 0.2203 |
| 7 | 0.8995 | 0.6009 | 0.6632 | 208 | 0.2203 |
| 8 | 0.8995 | 0.5988 | 0.6612 | 230 | 0.2203 |

(Full 89-point grid, including every `minor` value per `major`, is in
`sweep-results.json`, checked in for reproducibility — confirms the
"constant across minor" observation above holds for every single point,
not just the ones summarized here.)

## What the data actually shows (this overturns the plan's own leading hypothesis)

**V1-RELEASE.md §1.1's hypothesis was: "`MAJOR_FRAME_COUNT = 2` is far too
coarse... [raising it] is testable in an afternoon," predicting purity
would rise with more frames.** The swept data does not support this:

- **Purity is essentially flat across the entire tested range** — 0.8993
  at major=1 to 0.8995 at major=8, a 0.0002 spread. It does not trend
  upward with more frames, and it never gets remotely close to the E2
  target of 0.95 at *any* point in 1–8. This is a genuine falsification of
  the hypothesis, not a "didn't move much" — the predicted *direction*
  (up with more frames) simply isn't in the data.
- **Inverse purity moves sharply DOWN as major frame count increases** —
  0.8027 at major=1 down to 0.5988 at major=8 — exactly matching the
  general "more frames -> worse inverse purity" finding
  `planning/research/05-accuracy-and-ground-truth.md` §3.1 already cites
  from Igor's own paper. Purity buys nothing here; inverse purity pays a
  real, steep price for it.
- **F-measure is maximized at `major=1`** (0.7831), not at the current
  default of 2 (0.7761) or anywhere higher. Every value above 4 is
  markedly worse across the board (inverse purity falls off a cliff
  between major=4 and major=5, from 0.7855 to 0.6959).
- **The no-hash fallback rate (22.03%) is completely unaffected by
  `MAJOR_FRAME_COUNT`** — expected once you see the code:
  `stack_hashes()`'s "nothing to hash" check happens on the full
  noise-filtered frame list *before* windowing, so no choice of
  `MAJOR_FRAME_COUNT`/`MINOR_FRAME_COUNT` can move it. This is W2's
  problem entirely, not W1's — confirms V1-RELEASE.md's own workstream
  separation was correct.

## Decision — per the §3 measurement contract

**Chosen operating point: `MAJOR_FRAME_COUNT = 1`.** F-optimal among all 89
tested points (0.7831, the grid maximum), with a better inverse purity
(+0.0108 over the previous default) and a purity cost of only −0.0002 —
noise-level, not a real regression. `MINOR_FRAME_COUNT` is left at its
existing value of 5 since it provably does not move any metric in this
sweep (see the methodology note above) — there is no data-driven reason to
change it, and changing it anyway would be exactly the "no-op change kept
for tidiness" the plan explicitly warns against.

**On E2 (purity ≥ 0.95):** not reached anywhere in the swept range, and the
data show no trend toward it as `MAJOR_FRAME_COUNT` increases — if
anything the opposite (purity is flat-to-very-slightly-declining as major
grows past 4, while inverse purity collapses). **This is the technique's
measured ceiling for exact major-hash frame-count tuning on this corpus,
not a tuning failure** — per V1-RELEASE.md §0's own instruction ("if a
criterion proves unreachable, that is a finding... publish the measured
ceiling"). Closing the remaining ~5-point purity gap to 0.95, if it's
reachable at all with exact hashing, is not a `MAJOR_FRAME_COUNT` problem —
it needs a different lever (candidates, not attempted here: bug-class-aware
context beyond the single `extra_context` token already used; the
similarity-based bucket-merging "v2" research/05 §3.10 names as the actual
route past exact hashing's ~80% ceiling; or accepting 0.90 and revising E2
with evidence, exactly as §0 permits).

See `planning/AGENT_CHANGELOG.md` and `benchmarks/results.md` for the full
measurement-contract entry (HYPOTHESIS / WRONG / KEEP) and verification
detail (including the real, slow `autofte bench --corpus igor` CLI run
used to cross-check this sweep script's fast, precomputed numbers before
trusting any of them).
