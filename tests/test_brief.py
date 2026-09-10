from autofte.brief import build_brief


def _triage(**group_extra):
    group = {
        "count": 4,
        "crashes": [
            {"file": "c1", "reproducibility": "reproducible", "sanitizer": {
                "bug_class": "stack-buffer-overflow",
                "access_type": "write",
                "access_size": 72,
                "crash_stack": [
                    {"frame": 0, "func": "__interceptor_strcpy", "file": None},
                    {"frame": 1, "func": "parse_line", "file": "p.c", "line": 9},
                ],
            }},
        ],
    }
    group.update(group_extra)
    weak = {
        "count": 1,
        "crashes": [{"file": "n1", "sanitizer": {"bug_class": "null-pointer-dereference",
                                                 "crash_stack": [{"frame": 0, "func": "cfg"}]}}],
    }
    return {
        "total_crashes": 5,
        "unique_crash_frames": 2,
        "groups": {"stack-smash": group, "null": weak},
    }


BINARY = {
    "exploit_mitigation_summary": {"protection_level": "Low"},
    "stack_canaries": {"enabled": False},
    "pie": {"enabled": False},
    "nx_bit": {"enabled": True},
    "relro": {"status": "No RELRO"},
}


def test_brief_header_and_counts():
    text = build_brief("./target", "src.c", _triage(), BINARY, {})
    assert "# Exploitability brief -- `./target`" in text
    assert "triaged **5** crash inputs into **2** distinct root causes" in text
    assert "entirely offline" in text


def test_brief_picks_significant_frame_and_bug_class():
    text = build_brief("./target", "src.c", _triage(), BINARY, {}, top_n=1)
    assert "## 1. stack-buffer-overflow (write, 72 bytes)" in text
    assert "in `parse_line`" in text
    assert "__interceptor_strcpy" not in text


def test_brief_renders_crash_state_primitive_in_prose():
    triage = _triage(crash_state={
        "signal": "SIGSEGV",
        "faulting_instruction": "ret",
        "pc_symbol": "parse_line+37",
        "primitives": ["return-address-overwrite"],
    })
    text = build_brief("./target", "src.c", triage, BINARY, {}, top_n=1)
    assert "What the crashed process shows." in text
    assert "took SIGSEGV on `ret`" in text
    assert "control-flow transfer to attacker bytes is the very next step" in text
    assert "sits at the top of the queue" in text


def test_brief_renders_minimized_and_reproducibility():
    triage = _triage(minimized={
        "tool": "ddmin", "original_size": 120, "minimized_size": 41,
        "reduction_percent": 65.8, "output_path": "minimized/h.min",
    })
    text = build_brief("./target", "src.c", triage, BINARY, {}, top_n=1)
    assert "Minimized to 41 bytes (from 120, 65.8% smaller, ddmin): `minimized/h.min`" in text
    assert "Reproduced 1/1 times" in text


def test_brief_mitigation_prose_reflects_posture():
    text = build_brief("./target", "src.c", _triage(), BINARY, {}, top_n=1)
    assert "no stack canary" in text
    assert "no PIE" in text
    assert "NX is enabled" in text


def test_brief_llm_notes_only_on_top_finding_and_tidied():
    llm = {"summary": "A stack smash [E3]", "fix_ideas": ["Bound the copy [E9]."],
           "what_would_confirm": ["No crash on long input.."]}
    text = build_brief("./target", "src.c", _triage(), BINARY, llm, top_n=2)
    assert "**Local model notes (top finding).** A stack smash. Fix ideas: Bound the copy." in text
    assert "[E3]" not in text and ".." not in text
    assert text.count("Local model notes") == 1


def test_brief_no_groups():
    text = build_brief("./target", "src.c", {"groups": {}}, BINARY, {})
    assert "No crashing groups were found" in text


def test_brief_mentions_remaining_causes():
    text = build_brief("./target", "src.c", _triage(), BINARY, {}, top_n=1)
    assert "remaining 1 root cause(s) are in `crash_triage.json`" in text
