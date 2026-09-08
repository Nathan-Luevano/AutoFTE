"""Markdown run summary built from triage / binary / LLM artifacts.

Per ROADMAP 2.5, this surfaces the richness the 2.1-2.4 pipeline now
produces: a per-group bug class (when a sanitizer record is attached to a
crash in that group) instead of just the raw frame/signature label, the
crash-aware difficulty from `severity.py` (fused mitigation posture + fault
signature, with its own confidence and rationale -- not just the plain
protection-level/exploit-difficulty read off `binary_analysis` alone), and
the LLM's grounded narrative including `what_would_confirm`. Severity is
recomputed here directly from `triage`/`binary_data` (both already fully
loaded by the caller) rather than threaded through a new artifact --
`severity.assess_crash_difficulty` is a pure, cheap function over data this
module already has in hand, once per displayed group, so no extra file or
CLI plumbing is needed to keep this report honest and self-contained.
"""

from datetime import datetime

from . import crash_display, severity

_PROTECTION_LABELS = (
    ("aslr_system", "ASLR"),
    ("nx_bit", "NX"),
    ("stack_canaries", "Stack canaries"),
    ("pie", "PIE"),
)

MAX_GROUPS_SHOWN = 5


def build_report(target_binary, source_file, triage, binary_data, llm_data, max_groups=None):
    if max_groups is None:
        max_groups = MAX_GROUPS_SHOWN
    lines = [
        "# AutoFTE run summary",
        "",
        f"- Target: `{target_binary}`",
        f"- Source: `{source_file}`",
        f"- Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"- Crash count: {triage.get('total_crashes', 0)}",
        f"- Unique crash groups: {triage.get('unique_crash_frames', 0)}",
        "",
    ]

    groups = triage.get("groups", {})
    if groups:
        lines.extend(
            [
                "## Crash groups",
                "",
                "Ranked by crash-aware exploit difficulty (most severe first), with "
                "crash count breaking ties. Groups are collapsed via major/minor "
                "stack-hash dedup (plus sanitizer bug class, when available) -- "
                "not raw signature matching -- so `unique_crash_frames` above is "
                "the true distinct-bug count, not the crash count.",
                "",
            ]
        )
        ranked = []
        for frame, data in groups.items():
            crash_record = crash_display.representative_crash_record(data)
            assessment = severity.assess_crash_difficulty(binary_data, crash_record)
            ranked.append((assessment["score"], -data.get("count", 0), frame, data, assessment))
        ranked.sort(key=lambda item: (item[0], item[1]))

        for index, (_score, _neg, frame, data, assessment) in enumerate(
            ranked[:max_groups], start=1
        ):
            sample = data.get("crashes", [{}])[0]
            count = data.get("count", 0)
            crash_record = crash_display.representative_crash_record(data)
            label = crash_display.bug_class_label(crash_record)
            heading = label or frame

            lines.append(f"### {index}. {heading} -- {count} crashes")
            if label and label != frame:
                lines.append(f"- Signature: `{frame}`")
            lines.append(f"- Sample crash file: `{sample.get('file', 'n/a')}`")

            lines.append(
                f"- Difficulty: **{assessment['difficulty']}** "
                f"(confidence {assessment['confidence']:.2f})"
            )
            lines.append(f"- Why: {assessment['rationale']}")
            lines.append(
                "- Would raise confidence: " + assessment["would_increase_confidence"][0]
            )
            lines.append(
                "- Currently limited by: " + assessment["would_decrease_confidence"][0]
            )
            lines.append("")
        lines.append("")

    mitigation_summary = binary_data.get("exploit_mitigation_summary", {})
    if mitigation_summary:
        lines.extend(
            [
                "## Binary protections",
                "",
                f"- Protection level: {mitigation_summary.get('protection_level', 'Unknown')}",
                "- Exploit difficulty estimate: "
                f"{mitigation_summary.get('exploit_difficulty', 'Unknown')}",
            ]
        )

        for key, label in _PROTECTION_LABELS:
            enabled = binary_data.get(key, {}).get("enabled")
            if enabled is not None:
                lines.append(f"- {label}: {'enabled' if enabled else 'disabled'}")

        relro_status = binary_data.get("relro", {}).get("status")
        if relro_status:
            lines.append(f"- RELRO: {relro_status}")

        if mitigation_summary.get("vulnerable_areas"):
            lines.extend(["", "Weak spots:"])
            lines.extend(f"- {item}" for item in mitigation_summary["vulnerable_areas"])

        lines.append("")

    summary = llm_data.get("summary")
    bug_type = llm_data.get("likely_bug_type")

    lines.extend(["## LLM notes", ""])
    if summary:
        lines.extend([summary, ""])
    elif not bug_type:
        # Only claim the run has no LLM data at all when neither field
        # showed up -- a bug_type with no summary still deserves the
        # section header instead of a contradictory "unavailable" note.
        lines.extend(["LLM analysis was skipped or unavailable for this run.", ""])

    if bug_type:
        lines.append(f"- Likely bug type: {bug_type}")

    root_cause = llm_data.get("root_cause")
    if root_cause:
        lines.append(f"- Root cause: {root_cause}")

    confidence = llm_data.get("confidence")
    if confidence is not None:
        lines.append(f"- Confidence: {confidence}")

    next_checks = llm_data.get("next_checks", [])
    if next_checks:
        lines.extend(["", "Next checks:"])
        lines.extend(f"- {item}" for item in next_checks)

    fix_ideas = llm_data.get("fix_ideas", [])
    if fix_ideas:
        lines.extend(["", "Fix ideas:"])
        lines.extend(f"- {item}" for item in fix_ideas)

    what_would_confirm = llm_data.get("what_would_confirm", [])
    if what_would_confirm:
        lines.extend(["", "What would confirm this:"])
        lines.extend(f"- {item}" for item in what_would_confirm)

    lines.append("")
    return "\n".join(lines)
