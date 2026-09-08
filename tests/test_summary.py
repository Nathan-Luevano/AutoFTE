import pytest

from autofte.summary import SCHEMA, build_summary, groups_at_or_above, render_table


def _triage():
    return {
        "total_crashes": 6,
        "unique_crash_frames": 2,
        "triage_mode": "sanitizer",
        "groups": {
            "null-deref in main": {
                "count": 4,
                "crashes": [
                    {
                        "file": "c1",
                        "reproducibility": "reproducible",
                        "sanitizer": {"bug_class": "null-pointer-dereference"},
                    }
                ],
            },
            "stack-smash in vuln": {
                "count": 2,
                "crashes": [
                    {
                        "file": "c2",
                        "reproducibility": "reproducible",
                        "sanitizer": {
                            "bug_class": "stack-buffer-overflow",
                            "access_type": "write",
                            "access_size": 64,
                        },
                    }
                ],
            },
        },
    }


def test_build_summary_shape_and_schema():
    result = build_summary("./target", "vuln.c", _triage(), {}, {})
    assert result["schema"] == SCHEMA
    assert result["target_binary"] == "./target"
    assert result["totals"]["crashes"] == 6
    assert result["totals"]["unique_groups"] == 2
    assert len(result["groups"]) == 2


def test_groups_ranked_by_severity_not_count():
    result = build_summary("./target", "vuln.c", _triage(), {}, {})
    ranks = {g["signature"]: g["rank"] for g in result["groups"]}
    assert ranks["stack-smash in vuln"] == 1
    assert ranks["null-deref in main"] == 2
    assert result["top_group"]["signature"] == "stack-smash in vuln"
    assert result["top_group"]["bug_class"] == "stack-buffer-overflow"
    assert result["top_group"]["reproducible_count"] == 1


def test_binary_section_reads_protections():
    binary_data = {
        "exploit_mitigation_summary": {
            "protection_level": "Low",
            "exploit_difficulty": "Easy",
            "protection_count": 1,
            "vulnerable_areas": ["No PIE"],
        },
        "nx_bit": {"enabled": True},
        "pie": {"enabled": False},
        "relro": {"status": "No RELRO"},
    }
    result = build_summary("./target", "vuln.c", {}, binary_data, {})
    assert result["binary"]["protection_level"] == "Low"
    assert result["binary"]["protections"] == {
        "nx": True,
        "pie": False,
        "relro": "No RELRO",
    }
    assert result["binary"]["vulnerable_areas"] == ["No PIE"]


def test_llm_section_none_when_skipped():
    assert build_summary("./t", "v.c", {}, {}, {})["llm"] is None
    skipped = build_summary("./t", "v.c", {}, {}, {"status": "skipped"})
    assert skipped["llm"] is None


def test_llm_section_extracts_known_keys():
    llm_data = {
        "summary": "overflow",
        "likely_bug_type": "stack-buffer-overflow",
        "confidence": 0.8,
        "next_checks": ["a"],
        "ignored_key": "x",
    }
    section = build_summary("./t", "v.c", {}, {}, llm_data)["llm"]
    assert section["summary"] == "overflow"
    assert section["confidence"] == 0.8
    assert "ignored_key" not in section


def test_groups_at_or_above_filters_by_exploitability():
    summary = {
        "groups": [
            {"signature": "a", "difficulty": "Easy"},
            {"signature": "b", "difficulty": "Medium"},
            {"signature": "c", "difficulty": "Hard"},
        ]
    }
    assert [g["signature"] for g in groups_at_or_above(summary, "easy")] == ["a"]
    assert [g["signature"] for g in groups_at_or_above(summary, "medium")] == ["a", "b"]
    assert len(groups_at_or_above(summary, "hard")) == 3


def test_groups_at_or_above_rejects_unknown():
    with pytest.raises(ValueError):
        groups_at_or_above({"groups": []}, "nope")


def test_render_table_lists_ranked_groups():
    text = render_table(build_summary("./target", "vuln.c", _triage(), {}, {}))
    assert "DIFFICULTY" in text
    assert "stack-buffer-overflow (write, 64 bytes)" in text
    lines = [ln for ln in text.splitlines() if ln.strip().startswith(("1", "2"))]
    assert lines[0].split()[1] == "Easy"


def test_render_table_handles_no_groups():
    text = render_table(build_summary("./target", "vuln.c", {}, {}, {}))
    assert "(no crash groups)" in text


def test_empty_inputs():
    result = build_summary("./target", "vuln.c", {}, {}, {})
    assert result["groups"] == []
    assert result["top_group"] is None
    assert result["totals"]["crashes"] == 0
