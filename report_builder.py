import argparse
import json
from datetime import datetime
from pathlib import Path


def load_json(path):
    file_path = Path(path)
    if not file_path.exists():
        return {}

    with file_path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


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

    protections = binary_data.get("exploit_mitigation_summary", {})
    if protections:
        lines.extend(
            [
                "## Binary protections",
                "",
                f"- Protection level: {protections.get('protection_level', 'Unknown')}",
                f"- Exploit difficulty estimate: {protections.get('exploit_difficulty', 'Unknown')}",
            ]
        )

        for key, label in [
            ("aslr_system", "ASLR"),
            ("nx_bit", "NX"),
            ("stack_canaries", "Stack canaries"),
            ("pie", "PIE"),
        ]:
            enabled = binary_data.get(key, {}).get("enabled")
            if enabled is not None:
                lines.append(f"- {label}: {'enabled' if enabled else 'disabled'}")

        relro_status = binary_data.get("relro", {}).get("status")
        if relro_status:
            lines.append(f"- RELRO: {relro_status}")

        if protections.get("vulnerable_areas"):
            lines.append("")
            lines.append("Weak spots:")
            for item in protections["vulnerable_areas"]:
                lines.append(f"- {item}")

        lines.append("")

    summary = llm_data.get("summary")
    if summary:
        lines.extend(["## LLM notes", "", summary])
        lines.append("")

    bug_type = llm_data.get("likely_bug_type")
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
        lines.append("")
        lines.append("Next checks:")
        for item in next_checks:
            lines.append(f"- {item}")

    fix_ideas = llm_data.get("fix_ideas", [])
    if fix_ideas:
        lines.append("")
        lines.append("Fix ideas:")
        for item in fix_ideas:
            lines.append(f"- {item}")

    if not summary and not bug_type:
        lines.extend(
            [
                "## LLM notes",
                "",
                "LLM analysis was skipped or unavailable for this run.",
            ]
        )

    lines.append("")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Build a short markdown report from analysis artifacts")
    parser.add_argument("--target-binary", default="./target")
    parser.add_argument("--source-file", default="vuln.c")
    parser.add_argument("--triage-json", default="crash_triage.json")
    parser.add_argument("--binary-analysis", default="binary_analysis.json")
    parser.add_argument("--llm-analysis", default="llm_analysis.json")
    parser.add_argument("--output", default="analysis_summary.md")
    args = parser.parse_args()

    triage = load_json(args.triage_json)
    binary_data = load_json(args.binary_analysis)
    llm_data = load_json(args.llm_analysis)
    report = build_report(args.target_binary, args.source_file, triage, binary_data, llm_data)

    with open(args.output, "w", encoding="utf-8") as handle:
        handle.write(report)

    print(f"Wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
