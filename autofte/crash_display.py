"""Shared helpers for picking a representative crash out of a triage group
and rendering its bug class as a short human label.

Previously duplicated verbatim across `dashboard.py`, `report.py`, and
`sarif.py` (three independently-maintained copies of the same two
functions) -- factored out here so there is exactly one place that decides
what "the" crash record for a group is and how its bug class reads.
"""


def representative_crash_record(group_data):
    """Return the first sanitizer record found among `group_data`'s
    crashes, or `None` if the group has no sanitizer-parsed crash (e.g.
    gdb-only or signal-only triage)."""
    for crash in group_data.get("crashes", []):
        record = crash.get("sanitizer")
        if record:
            return record
    return None


def bug_class_label(crash_record):
    """Render a crash record's bug class plus access type/size detail,
    e.g. "heap-buffer-overflow (write, 4 bytes)". Returns `None` if there
    is no crash record at all (callers that need a fallback string, e.g.
    the SARIF rule heading, handle that themselves)."""
    if not crash_record:
        return None
    bug_class = crash_record.get("bug_class") or "unknown"
    details = []
    access_type = crash_record.get("access_type")
    access_size = crash_record.get("access_size")
    if access_type:
        details.append(access_type)
    if access_size is not None:
        details.append(f"{access_size} bytes")
    if details:
        return f"{bug_class} ({', '.join(details)})"
    return bug_class
