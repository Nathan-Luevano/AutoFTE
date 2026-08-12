from autofte.report import build_report


def test_build_report_empty_inputs():
    text = build_report("./target", "vuln.c", {}, {}, {})
    assert "# AutoFTE run summary" in text
    assert "Target: `./target`" in text
    assert "Crash count: 0" in text
    # No groups/binary sections when empty
    assert "## Crash groups" not in text
    assert "## Binary protections" not in text
    # LLM header always prints
    assert "## LLM notes" in text
    assert "LLM analysis was skipped or unavailable for this run." in text


def test_build_report_with_populated_triage_groups():
    triage = {
        "total_crashes": 5,
        "unique_crash_frames": 2,
        "groups": {
            "SIGSEGV": {"count": 3, "crashes": [{"file": "c1", "size": 10}]},
            "SIGABRT": {"count": 2, "crashes": [{"file": "c2", "size": 20}]},
        },
    }
    text = build_report("./target", "vuln.c", triage, {}, {})
    assert "## Crash groups" in text
    assert "### 1. SIGSEGV -- 3 crashes" in text
    assert "- Sample crash file: `c1`" in text
    assert "### 2. SIGABRT -- 2 crashes" in text
    assert "- Sample crash file: `c2`" in text
    # every displayed group gets a crash-aware difficulty, not just a plain
    # protection-level readout
    assert "- Difficulty: **Easy**" in text
    assert "- Why:" in text
    assert "- Would raise confidence:" in text
    assert "- Currently limited by:" in text


def test_build_report_group_shows_bug_class_and_raw_signature():
    triage = {
        "total_crashes": 1,
        "unique_crash_frames": 1,
        "groups": {
            "heap-buffer-overflow (write 8) in parse_header at parse.c:42": {
                "count": 1,
                "crashes": [
                    {
                        "file": "c1",
                        "size": 10,
                        "sanitizer": {
                            "bug_class": "heap-buffer-overflow",
                            "access_type": "write",
                            "access_size": 8,
                            "crash_stack": [{"frame": 0, "func": "parse_header"}],
                        },
                    }
                ],
            }
        },
    }
    text = build_report("./target", "vuln.c", triage, {}, {})
    assert "### 1. heap-buffer-overflow (write, 8 bytes) -- 1 crashes" in text
    assert "- Signature: `heap-buffer-overflow (write 8) in parse_header at parse.c:42`" in text


def test_build_report_group_difficulty_reflects_mitigation_posture():
    triage = {
        "total_crashes": 1,
        "unique_crash_frames": 1,
        "groups": {
            "stack-smash": {
                "count": 1,
                "crashes": [
                    {
                        "file": "c1",
                        "size": 10,
                        "sanitizer": {
                            "bug_class": "stack-buffer-overflow",
                            "access_type": "write",
                            "crash_stack": [{"frame": 0, "func": "vuln"}],
                        },
                    }
                ],
            }
        },
    }
    weak_binary = {
        "exploit_mitigation_summary": {"protection_count": 0},
        "stack_canaries": {"enabled": False},
        "pie": {"enabled": False},
    }
    strong_binary = {
        "exploit_mitigation_summary": {"protection_count": 8},
        "stack_canaries": {"enabled": True},
        "pie": {"enabled": True},
    }
    weak_text = build_report("./target", "vuln.c", triage, weak_binary, {})
    strong_text = build_report("./target", "vuln.c", triage, strong_binary, {})
    assert "**Easy**" in weak_text
    assert "**Hard**" in strong_text


def test_build_report_limits_to_five_groups():
    groups = {f"SIG{i}": {"count": 1, "crashes": [{"file": f"c{i}", "size": 1}]} for i in range(8)}
    triage = {"total_crashes": 8, "unique_crash_frames": 8, "groups": groups}
    text = build_report("./target", "vuln.c", triage, {}, {})
    shown = sum(1 for i in range(8) if f"SIG{i}" in text)
    assert shown == 5


def test_build_report_binary_protections_section():
    binary_data = {
        "exploit_mitigation_summary": {
            "protection_level": "Low",
            "exploit_difficulty": "Easy",
            "vulnerable_areas": ["No PIE - fixed code addresses"],
        },
        "aslr_system": {"enabled": True},
        "nx_bit": {"enabled": False},
        "stack_canaries": {"enabled": False},
        "pie": {"enabled": False},
        "relro": {"status": "No RELRO"},
    }
    text = build_report("./target", "vuln.c", {}, binary_data, {})
    assert "## Binary protections" in text
    assert "Protection level: Low" in text
    assert "ASLR: enabled" in text
    assert "NX: disabled" in text
    assert "RELRO: No RELRO" in text
    assert "Weak spots:" in text
    assert "- No PIE - fixed code addresses" in text


def test_build_report_with_llm_summary():
    llm_data = {
        "summary": "This looks like a classic stack buffer overflow.",
        "likely_bug_type": "stack-buffer-overflow",
        "root_cause": "strcpy with no bounds check",
        "confidence": 0.85,
        "next_checks": ["check heap layout"],
        "fix_ideas": ["use strlcpy"],
    }
    text = build_report("./target", "vuln.c", {}, {}, llm_data)
    assert "## LLM notes" in text
    assert "This looks like a classic stack buffer overflow." in text
    assert "Likely bug type: stack-buffer-overflow" in text
    assert "Root cause: strcpy with no bounds check" in text
    assert "Confidence: 0.85" in text
    assert "Next checks:" in text
    assert "- check heap layout" in text
    assert "Fix ideas:" in text
    assert "- use strlcpy" in text
    # Fallback text should not appear when a real summary was provided
    assert "LLM analysis was skipped or unavailable for this run." not in text


def test_build_report_llm_header_present_when_only_bug_type_set():
    """The '## LLM notes' header must print whenever summary or bug_type
    is present, and the "unavailable" fallback line must NOT show up next
    to a bug_type bullet just because summary itself is empty -- that
    would read as contradictory.
    """
    llm_data = {"likely_bug_type": "heap-overflow"}
    text = build_report("./target", "vuln.c", {}, {}, llm_data)
    assert "## LLM notes" in text
    assert "- Likely bug type: heap-overflow" in text
    assert "LLM analysis was skipped or unavailable for this run." not in text


def test_build_report_llm_fallback_only_when_both_absent():
    text = build_report("./target", "vuln.c", {}, {}, {})
    assert "## LLM notes" in text
    assert "LLM analysis was skipped or unavailable for this run." in text


def test_build_report_llm_notes_absent_summary_and_bug_type():
    text = build_report("./target", "vuln.c", {}, {}, {})
    assert "## LLM notes" in text
    assert "LLM analysis was skipped or unavailable for this run." in text
    assert "Likely bug type" not in text


def test_build_report_includes_what_would_confirm():
    llm_data = {
        "summary": "Looks like a heap overflow.",
        "what_would_confirm": ["Confirm the overflowed region borders heap metadata"],
    }
    text = build_report("./target", "vuln.c", {}, {}, llm_data)
    assert "What would confirm this:" in text
    assert "- Confirm the overflowed region borders heap metadata" in text
