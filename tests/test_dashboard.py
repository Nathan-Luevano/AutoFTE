from autofte.dashboard import build_html


def test_build_html_empty_inputs_does_not_crash():
    html = build_html({}, {}, {})
    assert "<!DOCTYPE html>" in html
    assert "AutoFTE dashboard" in html
    assert "No crash data found." in html


def test_build_html_escapes_unsafe_crash_group_name():
    triage = {
        "groups": {
            "<script>alert(1)</script>": {
                "count": 1,
                "crashes": [{"file": "c1", "size": 1}],
            }
        }
    }
    html = build_html(triage, {}, {})
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_build_html_escapes_unsafe_sample_filename():
    triage = {
        "groups": {
            "SIGSEGV": {
                "count": 1,
                "crashes": [{"file": '"><img src=x onerror=alert(1)>', "size": 1}],
            }
        }
    }
    html = build_html(triage, {}, {})
    assert "<img src=x onerror=alert(1)>" not in html


def test_build_html_escapes_llm_summary_and_lists():
    llm_data = {
        "summary": "<b>bold</b> summary",
        "likely_bug_type": "<i>bug</i>",
        "next_checks": ["<script>evil()</script>"],
        "fix_ideas": ["<script>evil2()</script>"],
    }
    html = build_html({}, {}, llm_data)
    assert "<b>bold</b>" not in html
    assert "<i>bug</i>" not in html
    assert "<script>evil()</script>" not in html
    assert "<script>evil2()</script>" not in html
    assert "&lt;b&gt;bold&lt;/b&gt; summary" in html


def test_build_html_includes_metrics():
    triage = {"total_crashes": 4, "unique_crash_frames": 2, "groups": {}}
    html = build_html(triage, {}, {})
    assert ">4<" in html
    assert ">2<" in html


def test_build_html_binary_summary_rendered():
    binary_data = {
        "exploit_mitigation_summary": {"protection_level": "High", "exploit_difficulty": "Hard"},
        "aslr_system": {"enabled": True},
        "nx_bit": {"enabled": True},
        "pie": {"enabled": True},
        "stack_canaries": {"enabled": True},
        "relro": {"status": "Full RELRO"},
    }
    html = build_html({}, binary_data, {})
    assert "Protection level: High" in html
    assert "ASLR: enabled" in html
    assert "RELRO: Full RELRO" in html


def test_build_html_group_rows_limited_to_eight():
    groups = {f"SIG{i}": {"count": 1, "crashes": [{"file": f"c{i}", "size": 1}]} for i in range(12)}
    html = build_html({"groups": groups}, {}, {})
    shown = sum(1 for i in range(12) if f">SIG{i}<" in html)
    assert shown == 8


def test_build_html_shows_reproducibility_in_count_cell():
    triage = {
        "groups": {
            "SIGSEGV": {
                "count": 2,
                "crashes": [
                    {"file": "c1", "size": 1, "reproducibility": "reproducible"},
                    {"file": "c2", "size": 1, "reproducibility": "non-reproducible"},
                ],
            }
        }
    }
    html = build_html(triage, {}, {})
    assert "1/2 reproducible" in html


def test_build_html_max_groups_override():
    groups = {f"SIG{i}": {"count": 1, "crashes": [{"file": f"c{i}", "size": 1}]} for i in range(12)}
    html = build_html({"groups": groups}, {}, {}, max_groups=3)
    shown = sum(1 for i in range(12) if f">SIG{i}<" in html)
    assert shown == 3


def test_build_html_group_row_shows_bug_class_and_signature():
    triage = {
        "groups": {
            "heap-buffer-overflow (write 8) in parse_header at parse.c:42": {
                "count": 3,
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
        }
    }
    html_out = build_html(triage, {}, {})
    assert "heap-buffer-overflow (write, 8 bytes)" in html_out
    assert "heap-buffer-overflow (write 8) in parse_header at parse.c:42" in html_out
    assert "confidence)" in html_out
    assert "<summary>why</summary>" in html_out


def test_build_html_group_row_difficulty_present_without_sanitizer_record():
    triage = {"groups": {"SIGSEGV": {"count": 1, "crashes": [{"file": "c1", "size": 1}]}}}
    html_out = build_html(triage, {}, {})
    assert "Easy" in html_out or "Medium" in html_out or "Hard" in html_out


def test_build_html_group_rows_ranked_by_severity():
    triage = {
        "groups": {
            "null-deref": {
                "count": 9,
                "crashes": [
                    {
                        "file": "c1",
                        "size": 1,
                        "sanitizer": {"bug_class": "null-pointer-dereference"},
                    }
                ],
            },
            "stack-smash": {
                "count": 1,
                "crashes": [
                    {
                        "file": "c2",
                        "size": 1,
                        "sanitizer": {"bug_class": "stack-buffer-overflow", "access_type": "write"},
                    }
                ],
            },
        }
    }
    html_out = build_html(triage, {}, {})
    assert html_out.index("stack-smash") < html_out.index("null-deref")


def test_build_html_renders_disassembly_context_escaped():
    llm_data = {"summary": "s", "disassembly_context": "105b30: cmp <a> & 0x1"}
    html = build_html({}, {}, llm_data)
    assert "Faulting instruction context" in html
    assert "<a>" not in html
    assert "&lt;a&gt;" in html


def test_build_html_no_disassembly_section_when_absent():
    html = build_html({}, {}, {"summary": "s"})
    assert "Faulting instruction context" not in html


def test_build_html_includes_llm_narrative_fields():
    llm_data = {
        "summary": "A heap overflow.",
        "likely_bug_type": "heap-buffer-overflow",
        "confidence": 0.7,
        "root_cause": "missing bounds check",
        "what_would_confirm": ["Check adjacent heap chunk contents"],
    }
    html_out = build_html({}, {}, llm_data)
    assert "A heap overflow." in html_out
    assert "Root cause: missing bounds check" in html_out
    assert "Confidence: 0.7" in html_out
    assert "What would confirm this" in html_out
    assert "Check adjacent heap chunk contents" in html_out
