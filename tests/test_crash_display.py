from autofte.crash_display import bug_class_label, ranked_groups, representative_crash_record


def test_representative_crash_record_returns_first_sanitizer():
    group = {"crashes": [{"file": "a"}, {"file": "b", "sanitizer": {"bug_class": "x"}}]}
    assert representative_crash_record(group) == {"bug_class": "x"}


def test_representative_crash_record_none_when_no_sanitizer():
    assert representative_crash_record({"crashes": [{"file": "a"}]}) is None


def test_bug_class_label_formats_details():
    record = {"bug_class": "heap-buffer-overflow", "access_type": "write", "access_size": 8}
    assert bug_class_label(record) == "heap-buffer-overflow (write, 8 bytes)"
    assert bug_class_label(None) is None


def test_ranked_groups_orders_by_severity_then_count():
    groups = {
        "leak": {"count": 20, "crashes": [{"sanitizer": {"bug_class": "memory-leak"}}]},
        "uaf": {"count": 1, "crashes": [{"sanitizer": {"bug_class": "heap-use-after-free"}}]},
    }
    ranked = ranked_groups(groups, {})
    assert [item["signature"] for item in ranked] == ["uaf", "leak"]
    assert ranked[0]["assessment"]["difficulty"]
    assert ranked[0]["count"] == 1


def test_ranked_groups_handles_none():
    assert ranked_groups(None, {}) == []
