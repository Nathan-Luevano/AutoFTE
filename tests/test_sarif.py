import json

from autofte import binary_analysis, sarif


def _mitigation_analysis(*, canary, pie, nx, aslr, relro_status):
    protections = {
        "aslr_system": {"enabled": aslr},
        "nx_bit": {"enabled": nx},
        "stack_canaries": {"enabled": canary},
        "pie": {"enabled": pie},
        "relro": {"status": relro_status},
    }
    analyzer = binary_analysis.BinaryAnalyzer("bin")
    analyzer.protections = protections
    protections["exploit_mitigation_summary"] = analyzer._summarize_mitigations()
    return protections


WEAK_ANALYSIS = _mitigation_analysis(
    canary=False, pie=False, nx=False, aslr=False, relro_status="No RELRO"
)

STRONG_ANALYSIS = _mitigation_analysis(
    canary=True, pie=True, nx=True, aslr=True, relro_status="Full RELRO"
)


def _sanitizer_record(
    bug_class="stack-buffer-overflow", access_type="write", file="vuln.c", line=42
):
    return {
        "sanitizer": "AddressSanitizer",
        "bug_class": bug_class,
        "access_type": access_type,
        "access_size": 8,
        "fault_addr": "0xdeadbeef",
        "crash_stack": [
            {"frame": 0, "addr": "0x1234", "func": "parse_header", "file": file, "line": line}
        ],
        "alloc_stack": [],
        "free_stack": [],
        "sanitizer_raw": "==1==ERROR: AddressSanitizer: stack-buffer-overflow ...",
    }


def _group(count, crashes, label="SIGSEGV", group_id=None):
    data = {"count": count, "crashes": crashes}
    if group_id is not None:
        data["group_id"] = group_id
    return label, data


def _triage_with_groups(*groups):
    return {
        "total_crashes": sum(data["count"] for _label, data in groups),
        "unique_crash_frames": len(groups),
        "groups": dict(groups),
    }


# --------------------------------------------------------------------------
# Overall shape / well-formedness
# --------------------------------------------------------------------------


def test_build_sarif_has_schema_and_version():
    triage = _triage_with_groups(_group(1, [{"file": "c1", "size": 4}]))
    data = sarif.build_sarif(triage, WEAK_ANALYSIS)
    assert data["$schema"] == sarif.SCHEMA_URI
    assert data["version"] == "2.1.0"


def test_build_sarif_driver_identifies_autofte():
    triage = _triage_with_groups(_group(1, [{"file": "c1", "size": 4}]))
    data = sarif.build_sarif(triage, WEAK_ANALYSIS)
    driver = data["runs"][0]["tool"]["driver"]
    assert driver["name"] == "AutoFTE"
    assert driver["version"]
    assert driver["informationUri"].startswith("https://")


def test_build_sarif_one_result_per_group():
    triage = _triage_with_groups(
        _group(3, [{"file": "c1", "size": 4}], label="SIGSEGV"),
        _group(2, [{"file": "c2", "size": 5}], label="SIGABRT"),
        _group(1, [{"file": "c3", "size": 6}], label="EXIT_1"),
    )
    data = sarif.build_sarif(triage, WEAK_ANALYSIS)
    assert len(data["runs"][0]["results"]) == 3


def test_build_sarif_result_carries_group_fingerprint_and_difficulty():
    triage = _triage_with_groups(
        _group(2, [{"file": "c1", "size": 4}], label="SIGSEGV", group_id="hash:abc123"),
    )
    result = sarif.build_sarif(triage, WEAK_ANALYSIS)["runs"][0]["results"][0]
    assert result["partialFingerprints"] == {"autofteGroupId/v1": "hash:abc123"}
    assert result["properties"]["difficulty"] in ("Easy", "Medium", "Hard")


def test_build_sarif_no_fingerprint_when_group_id_absent():
    triage = _triage_with_groups(_group(1, [{"file": "c1", "size": 4}]))
    result = sarif.build_sarif(triage, WEAK_ANALYSIS)["runs"][0]["results"][0]
    assert "partialFingerprints" not in result


def test_build_sarif_empty_groups_produces_empty_results():
    triage = {"total_crashes": 0, "unique_crash_frames": 0, "groups": {}}
    data = sarif.build_sarif(triage, WEAK_ANALYSIS)
    assert data["runs"][0]["results"] == []


def test_build_sarif_every_result_has_nonempty_locations():
    triage = _triage_with_groups(
        _group(1, [{"file": "c1", "size": 4, "sanitizer": _sanitizer_record()}], label="hbo"),
        _group(1, [{"file": "c2", "size": 4}], label="SIGSEGV"),
        _group(
            1,
            [{"file": "c3", "size": 4}],
            label="#0 0xaddr in parse_header at vuln.c:99",
        ),
    )
    data = sarif.build_sarif(triage, WEAK_ANALYSIS, target_binary="./target")
    for result in data["runs"][0]["results"]:
        assert result["locations"]
        assert len(result["locations"]) >= 1
        for location in result["locations"]:
            assert location["physicalLocation"]["artifactLocation"]["uri"]


def test_build_sarif_output_round_trips_through_json():
    triage = _triage_with_groups(
        _group(1, [{"file": "c1", "size": 4, "sanitizer": _sanitizer_record()}], label="hbo")
    )
    data = sarif.build_sarif(triage, WEAK_ANALYSIS, {"summary": "a run summary"}, "./target")
    text = json.dumps(data)
    reloaded = json.loads(text)
    assert reloaded == data


# --------------------------------------------------------------------------
# ruleId
# --------------------------------------------------------------------------


def test_rule_id_uses_sanitizer_bug_class_when_present():
    record = _sanitizer_record(bug_class="heap-use-after-free")
    triage = _triage_with_groups(
        _group(1, [{"file": "c1", "size": 4, "sanitizer": record}], label="raw-label")
    )
    data = sarif.build_sarif(triage, WEAK_ANALYSIS)
    assert data["runs"][0]["results"][0]["ruleId"] == "heap-use-after-free"


def test_rule_id_falls_back_to_raw_label_without_sanitizer_record():
    triage = _triage_with_groups(_group(1, [{"file": "c1", "size": 4}], label="SIGABRT"))
    data = sarif.build_sarif(triage, WEAK_ANALYSIS)
    assert data["runs"][0]["results"][0]["ruleId"] == "SIGABRT"


def test_driver_rules_include_an_entry_for_each_ruleid_used():
    triage = _triage_with_groups(
        _group(1, [{"file": "c1", "size": 4, "sanitizer": _sanitizer_record()}], label="hbo"),
        _group(1, [{"file": "c2", "size": 4}], label="SIGABRT"),
    )
    data = sarif.build_sarif(triage, WEAK_ANALYSIS)
    rule_ids = {rule["id"] for rule in data["runs"][0]["tool"]["driver"]["rules"]}
    assert rule_ids == {"stack-buffer-overflow", "SIGABRT"}


# --------------------------------------------------------------------------
# level mapping
# --------------------------------------------------------------------------


def test_level_easy_high_confidence_is_error():
    record = _sanitizer_record(bug_class="stack-buffer-overflow", access_type="write")
    triage = _triage_with_groups(
        _group(1, [{"file": "c1", "size": 4, "sanitizer": record}], label="hbo")
    )
    data = sarif.build_sarif(triage, WEAK_ANALYSIS)
    result = data["runs"][0]["results"][0]
    assert result["properties"]["confidence"] >= sarif.HIGH_CONFIDENCE_THRESHOLD
    assert result["level"] == "error"


def test_level_hard_is_note_even_with_high_confidence():
    record = _sanitizer_record(bug_class="null-pointer-dereference", access_type="read")
    triage = _triage_with_groups(
        _group(1, [{"file": "c1", "size": 4, "sanitizer": record}], label="npd")
    )
    data = sarif.build_sarif(triage, STRONG_ANALYSIS)
    result = data["runs"][0]["results"][0]
    assert result["level"] == "note"


def test_level_low_confidence_is_note_regardless_of_difficulty():
    triage = _triage_with_groups(_group(1, [{"file": "c1", "size": 4}], label="SIGSEGV"))
    data = sarif.build_sarif(triage, WEAK_ANALYSIS)
    result = data["runs"][0]["results"][0]
    assert result["properties"]["confidence"] < sarif.LOW_CONFIDENCE_THRESHOLD
    assert result["level"] == "note"


def test_map_level_medium_is_warning():
    assert sarif._map_level("Medium", 0.6) == "warning"


def test_map_level_easy_middling_confidence_is_warning():
    assert sarif._map_level("Easy", 0.6) == "warning"


def test_map_level_boundaries():
    assert sarif._map_level("Hard", 0.9) == "note"
    assert sarif._map_level("Easy", 0.1) == "note"
    assert sarif._map_level("Easy", 0.7) == "error"
    assert sarif._map_level("Medium", 0.5) == "warning"


# --------------------------------------------------------------------------
# message text
# --------------------------------------------------------------------------


def test_message_includes_llm_summary_when_present():
    triage = _triage_with_groups(_group(1, [{"file": "c1", "size": 4}], label="SIGSEGV"))
    data = sarif.build_sarif(triage, WEAK_ANALYSIS, {"summary": "distinctive run summary text"})
    assert "distinctive run summary text" in data["runs"][0]["results"][0]["message"]["text"]


def test_message_omits_llm_summary_when_absent():
    triage = _triage_with_groups(_group(1, [{"file": "c1", "size": 4}], label="SIGSEGV"))
    data = sarif.build_sarif(triage, WEAK_ANALYSIS)
    text = data["runs"][0]["results"][0]["message"]["text"]
    assert "SIGSEGV" in text
    assert text


def test_message_includes_bug_class_heading_when_sanitizer_present():
    record = _sanitizer_record(bug_class="heap-buffer-overflow", access_type="write")
    triage = _triage_with_groups(
        _group(1, [{"file": "c1", "size": 4, "sanitizer": record}], label="raw")
    )
    data = sarif.build_sarif(triage, WEAK_ANALYSIS)
    text = data["runs"][0]["results"][0]["message"]["text"]
    assert "heap-buffer-overflow" in text
    assert "write" in text


# --------------------------------------------------------------------------
# locations
# --------------------------------------------------------------------------


def test_location_uses_sanitizer_crash_stack_top_frame():
    record = _sanitizer_record(file="parse.c", line=77)
    triage = _triage_with_groups(
        _group(1, [{"file": "c1", "size": 4, "sanitizer": record}], label="raw")
    )
    data = sarif.build_sarif(triage, WEAK_ANALYSIS)
    location = data["runs"][0]["results"][0]["locations"][0]
    physical = location["physicalLocation"]
    assert physical["artifactLocation"]["uri"] == "parse.c"
    assert physical["region"]["startLine"] == 77


def test_location_skips_interceptor_frame_for_users_code():
    record = {
        "sanitizer": "AddressSanitizer",
        "bug_class": "stack-buffer-overflow",
        "access_type": "write",
        "access_size": 101,
        "fault_addr": "0xdeadbeef",
        "crash_stack": [
            {
                "frame": 0,
                "addr": "0x1111",
                "func": "__interceptor_strcpy",
                "file": "../../../../src/libsanitizer/asan/asan_interceptors.cpp",
                "line": 440,
            },
            {"frame": 1, "addr": "0x2222", "func": "vuln", "file": "vuln.c", "line": 8},
        ],
        "alloc_stack": [],
        "free_stack": [],
        "sanitizer_raw": "==1==ERROR: AddressSanitizer: stack-buffer-overflow ...",
    }
    triage = _triage_with_groups(
        _group(1, [{"file": "c1", "size": 4, "sanitizer": record}], label="raw")
    )
    data = sarif.build_sarif(triage, WEAK_ANALYSIS)
    physical = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert physical["artifactLocation"]["uri"] == "vuln.c"
    assert physical["region"]["startLine"] == 8


def test_location_falls_back_to_label_file_line_without_sanitizer_record():
    triage = _triage_with_groups(
        _group(
            1,
            [{"file": "c1", "size": 4}],
            label="#0 0xdead in parse_header at vuln.c:99",
        )
    )
    data = sarif.build_sarif(triage, WEAK_ANALYSIS)
    physical = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert physical["artifactLocation"]["uri"] == "vuln.c"
    assert physical["region"]["startLine"] == 99


def test_location_falls_back_to_target_binary_when_nothing_symbolized():
    triage = _triage_with_groups(_group(1, [{"file": "c1", "size": 4}], label="SIGSEGV"))
    data = sarif.build_sarif(triage, WEAK_ANALYSIS, target_binary="./target")
    physical = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert physical["artifactLocation"]["uri"] == "./target"
    assert "region" not in physical


def test_location_falls_back_to_unknown_binary_when_no_target_given():
    triage = _triage_with_groups(_group(1, [{"file": "c1", "size": 4}], label="SIGSEGV"))
    data = sarif.build_sarif(triage, WEAK_ANALYSIS)
    physical = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert physical["artifactLocation"]["uri"] == "unknown-binary"


# --------------------------------------------------------------------------
# properties
# --------------------------------------------------------------------------


def test_properties_bag_carries_confidence_crash_count_and_basis():
    record = _sanitizer_record()
    triage = _triage_with_groups(
        _group(9, [{"file": "c1", "size": 4, "sanitizer": record}], label="raw")
    )
    data = sarif.build_sarif(triage, WEAK_ANALYSIS)
    props = data["runs"][0]["results"][0]["properties"]
    assert props["crash_count"] == 9
    assert props["basis"] == "mitigation_and_crash"
    assert 0.0 <= props["confidence"] <= 1.0


def test_properties_basis_is_mitigation_only_without_sanitizer_record():
    triage = _triage_with_groups(_group(1, [{"file": "c1", "size": 4}], label="SIGSEGV"))
    data = sarif.build_sarif(triage, WEAK_ANALYSIS)
    assert data["runs"][0]["results"][0]["properties"]["basis"] == "mitigation_only"


# --------------------------------------------------------------------------
# dump_sarif convenience wrapper
# --------------------------------------------------------------------------


def test_dump_sarif_returns_valid_json_string():
    triage = _triage_with_groups(_group(1, [{"file": "c1", "size": 4}], label="SIGSEGV"))
    text = sarif.dump_sarif(triage, WEAK_ANALYSIS)
    parsed = json.loads(text)
    assert parsed["version"] == "2.1.0"
