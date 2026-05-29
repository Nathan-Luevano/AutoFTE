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
    assert "`SIGSEGV`: 3 files, sample `c1`" in text
    assert "`SIGABRT`: 2 files, sample `c2`" in text


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
    is present, per the spec. NOTE: current source still emits the
    'unavailable' fallback line in this case because it only branches on
    `summary` being falsy, not on `bug_type` too -- see bug notes in the
    test-suite completion report. This test documents actual behavior.
    """
    llm_data = {"likely_bug_type": "heap-overflow"}
    text = build_report("./target", "vuln.c", {}, {}, llm_data)
    assert "## LLM notes" in text
    assert "- Likely bug type: heap-overflow" in text
    # Documents current (arguably buggy) behavior: fallback text still
    # shows up because `summary` is falsy, even though bug_type is set.
    assert "LLM analysis was skipped or unavailable for this run." in text


def test_build_report_llm_notes_absent_summary_and_bug_type():
    text = build_report("./target", "vuln.c", {}, {}, {})
    assert "## LLM notes" in text
    assert "LLM analysis was skipped or unavailable for this run." in text
    assert "Likely bug type" not in text
