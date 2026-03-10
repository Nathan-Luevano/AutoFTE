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


def build_manifest(vulnerability_data, binary_data, target_binary):
    summary = binary_data.get("exploit_mitigation_summary", {})
    return {
        "generated_at": datetime.now().isoformat(),
        "target_binary": target_binary,
        "likely_bug_type": vulnerability_data.get("likely_bug_type", "unknown"),
        "summary": vulnerability_data.get("summary", "No local note available."),
        "root_cause": vulnerability_data.get("root_cause", "Unknown"),
        "binary_protections": {
            "protection_level": summary.get("protection_level", "Unknown"),
            "exploit_difficulty": summary.get("exploit_difficulty", "Unknown"),
            "aslr": binary_data.get("aslr_system", {}).get("enabled"),
            "nx": binary_data.get("nx_bit", {}).get("enabled"),
            "pie": binary_data.get("pie", {}).get("enabled"),
            "canaries": binary_data.get("stack_canaries", {}).get("enabled"),
            "relro": binary_data.get("relro", {}).get("status"),
        },
        "manual_steps": [
            "Review the crash summary and binary protections first.",
            "Decide whether a Mythic plugin even makes sense for this target.",
            "Translate the local notes into your own manual operator workflow.",
        ],
    }


def build_readme(manifest):
    lines = [
        "# Mythic notes",
        "",
        "This folder is only a scratch export from the local analysis pipeline.",
        "It does not create a plugin or install anything automatically.",
        "",
        f"- Target: `{manifest['target_binary']}`",
        f"- Likely bug type: `{manifest['likely_bug_type']}`",
        f"- Generated: {manifest['generated_at']}",
        "",
        "## Summary",
        "",
        manifest["summary"],
        "",
        "## Root cause",
        "",
        manifest["root_cause"],
        "",
        "## Manual steps",
        "",
    ]

    for item in manifest["manual_steps"]:
        lines.append(f"- {item}")

    lines.append("")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Export local notes for manual Mythic follow-up")
    parser.add_argument("--vulnerability-analysis", default="llm_analysis.json")
    parser.add_argument("--binary-analysis", default="binary_analysis.json")
    parser.add_argument("--target-binary", default="./target")
    parser.add_argument("--output-dir", default="mythic_output")
    args = parser.parse_args()

    vulnerability_data = load_json(args.vulnerability_analysis)
    binary_data = load_json(args.binary_analysis)
    manifest = build_manifest(vulnerability_data, binary_data, args.target_binary)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    with (output_dir / "manifest.json").open("w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2)

    (output_dir / "README.md").write_text(build_readme(manifest), encoding="utf-8")

    print(f"Wrote {output_dir / 'manifest.json'}")
    print(f"Wrote {output_dir / 'README.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
