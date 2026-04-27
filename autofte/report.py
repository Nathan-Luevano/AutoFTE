"""Markdown run summary built from triage / binary / LLM artifacts."""

from datetime import datetime

_PROTECTION_LABELS = (
    ("aslr_system", "ASLR"),
    ("nx_bit", "NX"),
    ("stack_canaries", "Stack canaries"),
    ("pie", "PIE"),
)


def build_report(target_binary, source_file, triage, binary_data, llm_data):
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
        lines.extend(["## Crash groups", ""])
        for frame, data in list(groups.items())[:5]:
            sample = data.get("crashes", [{}])[0]
            lines.append(
                f"- `{frame}`: {data.get('count', 0)} files, sample `{sample.get('file', 'n/a')}`"
            )
        lines.append("")

    mitigation_summary = binary_data.get("exploit_mitigation_summary", {})
    if mitigation_summary:
        lines.extend(
            [
                "## Binary protections",
                "",
                f"- Protection level: {mitigation_summary.get('protection_level', 'Unknown')}",
                f"- Exploit difficulty estimate: {mitigation_summary.get('exploit_difficulty', 'Unknown')}",
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

    if summary:
        lines.extend(["## LLM notes", "", summary, ""])
    else:
        lines.extend(
            ["## LLM notes", "", "LLM analysis was skipped or unavailable for this run.", ""]
        )

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

    lines.append("")
    return "\n".join(lines)
