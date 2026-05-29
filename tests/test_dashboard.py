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
