"""Build a SARIF 2.1.0 log from a triage run, per ROADMAP 3.1.

SARIF (Static Analysis Results Interchange Format) is what CI code-scanning
dashboards, issue trackers, and `github/codeql-action`-style upload steps
expect, so this is what lets AutoFTE plug into that ecosystem instead of
fighting it -- interoperate, don't reinvent (PLAN.md's guardrail). One
`run` is emitted per triage run, and one SARIF `result` per crash group in
`triage["groups"]` -- a group is AutoFTE's notion of "one distinct bug", so
that is the natural granularity for a SARIF finding.

Per-result mapping decisions:

- `ruleId` is the sanitizer-derived `bug_class` (e.g. "heap-buffer-overflow")
  from a representative crash's `sanitizer` record in that group, when one
  is attached -- the same "prefer sanitizer, fall back to the raw
  frame/signature" pattern `report.py`/`dashboard.py` already use. When no
  crash in the group carries a sanitizer record (gdb-only or signal-only
  triage), the group's raw label is used instead, since it is the only
  identifying string available for that group.

- `level` is derived from `severity.assess_crash_difficulty`'s `difficulty`
  and `confidence`, not from the raw mitigation `protection_count` alone,
  since the crash-aware fusion is the actually differentiated signal (see
  `severity.py`'s module docstring). The mapping is deliberately
  confidence-gated in both directions: a low-confidence assessment is never
  reported as `error` even if the heuristic scored it "Easy", because
  `severity.py`'s own contract is "prioritization aid, never a verdict" --
  promoting a low-confidence guess to SARIF's most severe level would
  mislead a CI dashboard that can't see the surrounding rationale. Concretely:
    * confidence < 0.5, or difficulty "Hard"          -> "note"
    * difficulty "Easy" and confidence >= 0.7          -> "error"
    * everything else (mainly "Medium", or "Easy" with
      middling confidence)                             -> "warning"

- `message.text` combines the bug-class/signature heading, the severity
  rationale (which already names the specific mitigation/fault-signature
  reasoning), and the run's LLM `summary` when one is present. The LLM
  write-up in this codebase is produced once per run (grounded in the top
  crash group, per `llm.py`), not per group, so it is appended to every
  result's message as extra context rather than treated as group-specific.

- `locations` prefers a symbolized file:line from the representative
  crash's sanitizer `crash_stack`, from the first *significant* frame (per
  `dedup.significant_frames`) rather than the raw top frame, so a libc/
  sanitizer interceptor frame never becomes the reported location; failing
  that, it falls back to
  parsing an " at FILE:LINE" suffix out of the group's raw label (gdb-path
  groups carry that in their label text even though the full frame list
  isn't persisted per-crash); failing that, it points at `target_binary`
  with no line info. SARIF requires at least one location per result, so a
  result is never emitted with an empty `locations` array.

`properties` on each result carries the raw `confidence`, `crash_count`,
and `basis` from the severity assessment so SARIF consumers that
understand custom properties can surface them, while consumers that don't
simply ignore an unrecognized bag (per the SARIF spec).
"""

import json
import re
from importlib.metadata import PackageNotFoundError, metadata, version

from . import crash_display, dedup, severity

SCHEMA_URI = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)
SARIF_VERSION = "2.1.0"

FALLBACK_TOOL_VERSION = "0.0.0-dev"
FALLBACK_INFORMATION_URI = "https://github.com/Nathan-Luevano/AutoFTE"

LOW_CONFIDENCE_THRESHOLD = 0.5
HIGH_CONFIDENCE_THRESHOLD = 0.7

_LABEL_LOCATION_RE = re.compile(r"\bat (\S+):(\d+)")


def _tool_version():
    try:
        return version("autofte")
    except PackageNotFoundError:
        return FALLBACK_TOOL_VERSION


def _information_uri():
    try:
        package_metadata = metadata("autofte")
    except PackageNotFoundError:
        return FALLBACK_INFORMATION_URI

    for entry in package_metadata.get_all("Project-URL") or []:
        name, _, url = entry.partition(",")
        if name.strip().lower() == "homepage":
            return url.strip()

    return FALLBACK_INFORMATION_URI


def _bug_class_heading(label, crash_record):
    """Like `crash_display.bug_class_label`, but falls back to the group's
    raw `label` instead of `None` when there's no sanitizer record -- SARIF
    rule/result headings always need *some* identifying string."""
    return crash_display.bug_class_label(crash_record) or label


def _rule_id(label, crash_record):
    if crash_record and crash_record.get("bug_class"):
        return crash_record["bug_class"]
    return label


def _map_level(difficulty, confidence):
    if confidence < LOW_CONFIDENCE_THRESHOLD or difficulty == "Hard":
        return "note"
    if difficulty == "Easy" and confidence >= HIGH_CONFIDENCE_THRESHOLD:
        return "error"
    return "warning"


def _location_from_crash_record(crash_record):
    if not crash_record:
        return None, None
    crash_stack = crash_record.get("crash_stack") or []
    significant = dedup.significant_frames(crash_stack)
    for frame in significant or crash_stack:
        if frame.get("file") and frame.get("line"):
            return frame["file"], frame["line"]
    return None, None


def _location_from_label(label):
    match = _LABEL_LOCATION_RE.search(label)
    if not match:
        return None, None
    return match.group(1), int(match.group(2))


def _build_location(label, crash_record, target_binary):
    file_path, line_number = _location_from_crash_record(crash_record)
    if file_path is None:
        file_path, line_number = _location_from_label(label)

    if file_path is not None:
        physical_location = {"artifactLocation": {"uri": file_path}}
        if line_number is not None:
            physical_location["region"] = {"startLine": line_number}
        return {"physicalLocation": physical_location}

    uri = target_binary or "unknown-binary"
    return {"physicalLocation": {"artifactLocation": {"uri": uri}}}


def _build_message(heading, assessment, llm_data):
    parts = [f"{heading}. {assessment['rationale']}"]
    summary = (llm_data or {}).get("summary")
    if summary:
        parts.append(summary)
    return " ".join(parts)


def build_sarif(triage, binary_data, llm_data=None, target_binary=None):
    """Return a SARIF 2.1.0 log (a plain dict, JSON-serializable as-is) for
    one triage run, with one `result` per group in `triage["groups"]`.
    """
    llm_data = llm_data or {}
    groups = triage.get("groups", {})

    results = []
    rules_by_id = {}

    for label, group_data in groups.items():
        crash_record = crash_display.representative_crash_record(group_data)
        heading = _bug_class_heading(label, crash_record)
        rule_id = _rule_id(label, crash_record)
        assessment = severity.assess_crash_difficulty(binary_data, crash_record)
        level = _map_level(assessment["difficulty"], assessment["confidence"])

        rules_by_id.setdefault(
            rule_id, {"id": rule_id, "shortDescription": {"text": heading}}
        )

        results.append(
            {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": _build_message(heading, assessment, llm_data)},
                "locations": [_build_location(label, crash_record, target_binary)],
                "properties": {
                    "confidence": assessment["confidence"],
                    "crash_count": group_data.get("count", 0),
                    "basis": assessment["basis"],
                },
            }
        )

    driver = {
        "name": "AutoFTE",
        "version": _tool_version(),
        "informationUri": _information_uri(),
    }
    if rules_by_id:
        driver["rules"] = list(rules_by_id.values())

    return {
        "$schema": SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {"driver": driver},
                "results": results,
            }
        ],
    }


def dump_sarif(triage, binary_data, llm_data=None, target_binary=None):
    """Convenience wrapper: `build_sarif(...)` serialized to a JSON string."""
    return json.dumps(
        build_sarif(triage, binary_data, llm_data, target_binary), indent=2
    )
