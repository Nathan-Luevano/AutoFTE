import json

from autofte import casr


def _triage(**group_extra):
    group = {
        "count": 3,
        "group_id": "hash:abc123",
        "crashes": [
            {
                "file": "c1",
                "path": "/crashes/c1",
                "size": 20,
                "sanitizer": {
                    "sanitizer": "AddressSanitizer",
                    "bug_class": "heap-buffer-overflow",
                    "access_type": "write",
                    "access_size": 8,
                    "crash_stack": [
                        {"frame": 0, "func": "__interceptor_memcpy", "file": None},
                        {"frame": 1, "func": "parse", "file": "p.c", "line": 12},
                    ],
                    "sanitizer_raw": "==1==ERROR: AddressSanitizer: heap-buffer-overflow\n#0 mc\n",
                },
            },
        ],
    }
    group.update(group_extra)
    weak = {
        "count": 1,
        "group_id": "raw:SIGABRT",
        "crashes": [{"file": "n1", "path": "/crashes/n1", "size": 4}],
    }
    return {
        "total_crashes": 4,
        "unique_crash_frames": 2,
        "groups": {"heap-buffer-overflow in parse": group, "SIGABRT": weak},
    }


BINARY = {
    "exploit_mitigation_summary": {"protection_level": "Low"},
    "stack_canaries": {"enabled": False},
    "pie": {"enabled": False},
    "nx_bit": {"enabled": True},
}


def test_build_reports_one_per_group():
    reports = casr.build_reports(_triage(), BINARY)
    assert len(reports) == 2
    ids = {gid for gid, _ in reports}
    assert ids == {"hash:abc123", "raw:SIGABRT"}


def test_report_core_fields_and_stacktrace():
    reports = dict(casr.build_reports(_triage(), BINARY))
    report = reports["hash:abc123"]
    assert report["ExecutablePath"] == ""
    assert report["ProcCmdline"].endswith("/crashes/c1")
    assert report["Stdin"] == "/crashes/c1"
    assert report["CrashLine"] == "p.c:12"
    assert report["Stacktrace"] == ["#0 in __interceptor_memcpy", "#1 in parse at p.c:12"]
    assert report["AsanReport"][0].startswith("==1==ERROR")
    assert report["GroupSize"] == 3


def test_severity_maps_buffer_overflow_to_probably_exploitable():
    reports = dict(casr.build_reports(_triage(), BINARY))
    sev = reports["hash:abc123"]["CrashSeverity"]
    assert sev["Type"] == "PROBABLY_EXPLOITABLE"
    assert sev["ShortDescription"] == "HeapBufferOverflow"
    assert "not an independent verdict" in sev["Explanation"]


def test_severity_control_flow_primitive_wins():
    triage = _triage(crash_state={
        "signal": "SIGSEGV",
        "primitives": ["return-address-overwrite"],
        "registers": {"rip": "0x4141414141414141"},
        "rationale": "fault on ret.",
    })
    reports = dict(casr.build_reports(triage, BINARY))
    report = reports["hash:abc123"]
    assert report["CrashSeverity"]["Type"] == "EXPLOITABLE"
    assert report["CrashSeverity"]["ShortDescription"] == "ReturnAv"
    assert report["Registers"] == {"rip": "0x4141414141414141"}


def test_severity_signal_fallback_for_gdb_only_group():
    reports = dict(casr.build_reports(_triage(), BINARY))
    sev = reports["raw:SIGABRT"]["CrashSeverity"]
    assert sev["Type"] == "NOT_EXPLOITABLE"
    assert sev["ShortDescription"] == "AbortSignal"


def test_write_reports_emits_casrep_files(tmp_path):
    written = casr.write_reports(_triage(), BINARY, tmp_path)
    assert len(written) == 2
    for path in written:
        assert path.endswith(".casrep")
        json.loads((tmp_path / path.split("/")[-1]).read_text())


def test_write_reports_disambiguates_colliding_names(tmp_path):
    triage = _triage()
    triage["groups"]["SIGABRT"]["group_id"] = "hash:abc123"
    written = casr.write_reports(triage, BINARY, tmp_path)
    assert len(written) == 2
    assert len({p.split("/")[-1] for p in written}) == 2


def test_minimized_input_surfaced(tmp_path):
    triage = _triage(minimized={"output_path": "/min/g1.min", "reduction_percent": 80})
    report = dict(casr.build_reports(triage, BINARY))["hash:abc123"]
    assert report["MinimizedInput"] == "/min/g1.min"
