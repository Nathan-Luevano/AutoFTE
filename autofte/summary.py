import csv
import io
from datetime import datetime

from . import crash_display

CSV_COLUMNS = (
    "rank",
    "difficulty",
    "confidence",
    "score",
    "count",
    "reproducible_count",
    "bug_class",
    "exploit_primitives",
    "signature",
    "group_id",
    "sample_crash_file",
)

SCHEMA = "autofte-summary/1"

_DIFFICULTY_EXPLOITABILITY = {"Easy": 3, "Medium": 2, "Hard": 1}


def groups_at_or_above(summary, difficulty):
    threshold = _DIFFICULTY_EXPLOITABILITY.get(difficulty.capitalize())
    if threshold is None:
        raise ValueError(f"unknown difficulty: {difficulty}")
    return [
        group
        for group in summary.get("groups", [])
        if _DIFFICULTY_EXPLOITABILITY.get(group.get("difficulty"), 0) >= threshold
    ]

_PROTECTION_KEYS = (
    ("aslr_system", "aslr"),
    ("nx_bit", "nx"),
    ("stack_canaries", "stack_canaries"),
    ("pie", "pie"),
)


def _binary_section(binary_data):
    mitigation = binary_data.get("exploit_mitigation_summary", {}) or {}
    protections = {}
    for key, name in _PROTECTION_KEYS:
        enabled = (binary_data.get(key) or {}).get("enabled")
        if enabled is not None:
            protections[name] = bool(enabled)
    relro = (binary_data.get("relro") or {}).get("status")
    if relro:
        protections["relro"] = relro
    return {
        "protection_level": mitigation.get("protection_level", "Unknown"),
        "exploit_difficulty": mitigation.get("exploit_difficulty", "Unknown"),
        "protection_count": mitigation.get("protection_count", 0),
        "protections": protections,
        "vulnerable_areas": list(mitigation.get("vulnerable_areas") or []),
        "required_techniques": list(mitigation.get("required_techniques") or []),
    }


def _group_entries(triage, binary_data):
    entries = []
    for rank, item in enumerate(
        crash_display.ranked_groups(triage.get("groups"), binary_data), start=1
    ):
        signature = item["signature"]
        data = item["data"]
        crash_record = item["crash_record"]
        assessment = item["assessment"]
        crashes = data.get("crashes", []) or []
        reproducible = sum(
            1 for c in crashes if c.get("reproducibility") == "reproducible"
        )
        entries.append(
            {
                "rank": rank,
                "signature": signature,
                "group_id": data.get("group_id"),
                "bug_class": (crash_record or {}).get("bug_class"),
                "bug_class_label": crash_display.bug_class_label(crash_record),
                "access_type": (crash_record or {}).get("access_type"),
                "access_size": (crash_record or {}).get("access_size"),
                "count": data.get("count", len(crashes)),
                "reproducible_count": reproducible,
                "sample_crash_file": (crashes[0].get("file") if crashes else None),
                "difficulty": assessment["difficulty"],
                "confidence": assessment["confidence"],
                "score": assessment["score"],
                "basis": assessment["basis"],
                "rationale": assessment["rationale"],
                "exploit_primitives": list(
                    (item.get("crash_state") or {}).get("primitives") or []
                ),
            }
        )
    return entries


def _llm_section(llm_data):
    if not llm_data or llm_data.get("status") == "skipped":
        return None
    keys = (
        "summary",
        "likely_bug_type",
        "root_cause",
        "confidence",
        "next_checks",
        "fix_ideas",
        "what_would_confirm",
        "agreement_score",
    )
    section = {key: llm_data[key] for key in keys if key in llm_data}
    return section or None


def render_table(summary):
    totals = summary.get("totals", {})
    lines = [
        f"Target: {summary.get('target_binary', 'n/a')}",
        f"Crashes: {totals.get('crashes', 0)}  "
        f"Unique groups: {totals.get('unique_groups', 0)}  "
        f"Mode: {totals.get('triage_mode') or 'n/a'}",
        "",
        f"{'#':>2}  {'DIFFICULTY':<10} {'CONF':>5} {'COUNT':>6}  BUG",
    ]
    groups = summary.get("groups", [])
    if not groups:
        lines.append("(no crash groups)")
        return "\n".join(lines)
    for group in groups:
        bug = group.get("bug_class_label") or group.get("signature") or "unknown"
        primitives = group.get("exploit_primitives") or []
        if primitives:
            bug = f"{bug}  [{', '.join(primitives)}]"
        lines.append(
            f"{group.get('rank', 0):>2}  {group.get('difficulty', '?'):<10} "
            f"{group.get('confidence', 0):>5.2f} {group.get('count', 0):>6}  {bug}"
        )
    binary = summary.get("binary", {})
    lines.extend(
        [
            "",
            f"Binary: protection level {binary.get('protection_level', 'Unknown')}, "
            f"{len(binary.get('protections', {}))} checks resolved",
        ]
    )
    return "\n".join(lines)


def render_csv(summary):
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for group in summary.get("groups", []):
        row = {key: group.get(key, "") for key in CSV_COLUMNS}
        row["exploit_primitives"] = " ".join(group.get("exploit_primitives") or [])
        writer.writerow(row)
    return buffer.getvalue()


def build_summary(target_binary, source_file, triage, binary_data, llm_data):
    groups = _group_entries(triage, binary_data)
    return {
        "schema": SCHEMA,
        "target_binary": str(target_binary),
        "source_file": str(source_file),
        "generated": datetime.now().isoformat(timespec="seconds"),
        "totals": {
            "crashes": triage.get("total_crashes", 0),
            "unique_groups": triage.get("unique_crash_frames", len(groups)),
            "triage_mode": triage.get("triage_mode"),
            "no_crash_count": triage.get("no_crash_count", 0),
            "timeout_count": triage.get("timeout_count", 0),
        },
        "top_group": groups[0] if groups else None,
        "groups": groups,
        "binary": _binary_section(binary_data),
        "llm": _llm_section(llm_data),
    }
