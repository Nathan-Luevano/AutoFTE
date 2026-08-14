import argparse
import json

import pytest

from autofte import cli

from .conftest import FakeCompletedProcess

SUBCOMMANDS_MIN_ARGS = {
    "triage": [],
    "binscan": ["some-binary"],
    "llm": [],
    "report": [],
    "dashboard": [],
    "crash-info": [],
    "doctor": [],
    "pipeline": [],
    "demo": [],
    "bench": [],
}


def test_build_parser_returns_parser_with_all_subcommands():
    parser = cli.build_parser()
    assert parser.prog == "autofte"
    subparsers_action = next(
        action for action in parser._actions if isinstance(action, argparse._SubParsersAction)
    )
    assert set(subparsers_action.choices) == set(SUBCOMMANDS_MIN_ARGS)


@pytest.mark.parametrize("command,extra_args", SUBCOMMANDS_MIN_ARGS.items())
def test_each_subcommand_parses_with_defaults(command, extra_args, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    parser = cli.build_parser()
    args = parser.parse_args([command, *extra_args])
    assert args.command == command
    assert callable(args.func)


def test_main_no_args_exits_nonzero(capsys):
    with pytest.raises(SystemExit) as exc_info:
        cli.main([])
    assert exc_info.value.code != 0


def test_main_help_exits_zero(capsys):
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["--help"])
    assert exc_info.value.code == 0


def test_main_invalid_subcommand_exits_nonzero():
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["not-a-real-command"])
    assert exc_info.value.code != 0


def test_main_binscan_missing_binary_returns_error(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    rc = cli.main(["binscan", "does-not-exist"])
    assert rc == 1
    out = capsys.readouterr().out
    assert "not found" in out


# --------------------------------------------------------------------------
# report / dashboard end-to-end (pure file I/O, no mocking needed)
# --------------------------------------------------------------------------

def _write_json(path, data):
    path.write_text(json.dumps(data), encoding="utf-8")


def test_cmd_report_end_to_end(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    triage = {
        "total_crashes": 2,
        "unique_crash_frames": 1,
        "groups": {"SIGSEGV": {"count": 2, "crashes": [{"file": "c1", "size": 10}]}},
    }
    _write_json(tmp_path / "triage.json", triage)
    _write_json(tmp_path / "binary.json", {})
    _write_json(tmp_path / "llm.json", {"summary": "looks bad"})

    rc = cli.main(
        [
            "report",
            "--target-binary",
            "./target",
            "--source-file",
            "vuln.c",
            "--triage-json",
            "triage.json",
            "--binary-analysis",
            "binary.json",
            "--llm-analysis",
            "llm.json",
            "--output",
            "out.md",
        ]
    )
    assert rc == 0
    output = (tmp_path / "out.md").read_text(encoding="utf-8")
    assert "# AutoFTE run summary" in output
    assert "looks bad" in output
    assert "Wrote out.md" in capsys.readouterr().out


def test_cmd_report_missing_json_files_defaults_to_empty(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    rc = cli.main(["report", "--output", "out.md"])
    assert rc == 0
    output = (tmp_path / "out.md").read_text(encoding="utf-8")
    assert "Crash count: 0" in output


def test_cmd_report_format_sarif_writes_json(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    triage = {
        "total_crashes": 2,
        "unique_crash_frames": 1,
        "groups": {"SIGSEGV": {"count": 2, "crashes": [{"file": "c1", "size": 10}]}},
    }
    _write_json(tmp_path / "triage.json", triage)
    _write_json(tmp_path / "binary.json", {})
    _write_json(tmp_path / "llm.json", {"summary": "looks bad"})

    rc = cli.main(
        [
            "report",
            "--triage-json",
            "triage.json",
            "--binary-analysis",
            "binary.json",
            "--llm-analysis",
            "llm.json",
            "--output",
            "out.sarif",
            "--format",
            "sarif",
        ]
    )
    assert rc == 0
    assert "Wrote out.sarif" in capsys.readouterr().out
    data = json.loads((tmp_path / "out.sarif").read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["tool"]["driver"]["name"] == "AutoFTE"
    assert len(data["runs"][0]["results"]) == 1


def test_cmd_report_default_format_is_markdown(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    rc = cli.main(["report", "--output", "out.md"])
    assert rc == 0
    output = (tmp_path / "out.md").read_text(encoding="utf-8")
    assert output.startswith("# AutoFTE run summary")


def test_cmd_dashboard_end_to_end(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    empty_triage = {"total_crashes": 0, "unique_crash_frames": 0, "groups": {}}
    _write_json(tmp_path / "triage.json", empty_triage)
    _write_json(tmp_path / "binary.json", {})
    _write_json(tmp_path / "llm.json", {})

    rc = cli.main(
        [
            "dashboard",
            "--triage-json",
            "triage.json",
            "--binary-analysis",
            "binary.json",
            "--llm-analysis",
            "llm.json",
            "--output-dir",
            "dashboard-out",
        ]
    )
    assert rc == 0
    index_file = tmp_path / "dashboard-out" / "index.html"
    assert index_file.exists()
    assert "<!DOCTYPE html>" in index_file.read_text(encoding="utf-8")
    assert "Wrote" in capsys.readouterr().out


def test_cmd_doctor_end_to_end(monkeypatch, capsys):
    monkeypatch.setattr(cli.doctor.shutil, "which", lambda tool: None)
    monkeypatch.setattr(cli.doctor.config, "list_installed_models", lambda host: [])

    rc = cli.main(["doctor"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "AutoFTE environment check" in out


def test_cmd_triage_missing_crashes_dir_returns_error(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    rc = cli.main(
        [
            "triage",
            "--crashes-dir",
            "no-such-dir",
            "--target-binary",
            "no-such-binary",
            "--quiet",
        ]
    )
    assert rc == 1
    assert "Error" in capsys.readouterr().out


def test_cmd_triage_end_to_end(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    crashes = tmp_path / "crashes"
    crashes.mkdir()
    (crashes / "crash1").write_bytes(b"AAAA")

    binary = tmp_path / "target"
    binary.write_text("#!/bin/sh\nkill -SEGV $$\n")
    binary.chmod(0o755)

    monkeypatch.setattr(cli, "triage_crashes", cli.triage_crashes)  # sanity, uses real impl
    monkeypatch.setattr("autofte.triage.gdb_is_available", lambda debugger: False)

    rc = cli.main(
        [
            "triage",
            "--crashes-dir",
            str(crashes),
            "--target-binary",
            str(binary),
            "--output",
            "triage.json",
            "--quiet",
        ]
    )
    assert rc == 0
    result = json.loads((tmp_path / "triage.json").read_text())
    assert result["total_crashes"] == 1


def test_cmd_pipeline_missing_binary_returns_error(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    rc = cli.main(["pipeline", "./nope", "vuln.c"])
    assert rc == 1
    assert "not found" in capsys.readouterr().out


def test_cmd_binscan_end_to_end(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    binary = tmp_path / "target"
    binary.write_text("fake binary bytes")

    fake_result = {
        "exploit_mitigation_summary": {
            "protection_level": "Low",
            "exploit_difficulty": "Easy",
            "required_techniques": ["NX bypass (ROP/JOP required)"],
            "vulnerable_areas": ["No PIE - fixed code addresses"],
        }
    }
    monkeypatch.setattr(cli, "analyze_binary", lambda path: fake_result)

    rc = cli.main(["binscan", str(binary), "--output", "binscan.json"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Protection Level: Low" in out
    assert "NX bypass (ROP/JOP required)" in out
    assert "No PIE - fixed code addresses" in out
    saved = json.loads((tmp_path / "binscan.json").read_text())
    assert saved == fake_result


class _FakeLLMClient:
    def __init__(self, model, host, timeout=None):
        self.model = model
        self.host = host
        self.timeout = timeout

    def check(self):
        return True, "ok"


def test_cmd_llm_end_to_end_success(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    _write_json(tmp_path / "triage.json", {"groups": {}})

    monkeypatch.setattr(cli, "OllamaClient", _FakeLLMClient)
    monkeypatch.setattr(cli.config, "resolve_host", lambda explicit: "http://x")
    monkeypatch.setattr(cli.config, "resolve_model", lambda explicit, host: "fake-model")
    monkeypatch.setattr(
        cli,
        "llm_analyze",
        lambda client, triage_data, source_code, binary_analysis, **kwargs: {
            "summary": "a summary",
            "model_used": client.model,
        },
    )

    rc = cli.main(["llm", "--triage-json", "triage.json", "--output", "llm.json"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Using model: fake-model" in out
    assert "a summary" in out
    saved = json.loads((tmp_path / "llm.json").read_text())
    assert saved["summary"] == "a summary"


def test_cmd_llm_passes_severity_assessment_when_binary_analysis_present(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.chdir(tmp_path)
    triage = {
        "groups": {
            "heap-buffer-overflow": {
                "count": 1,
                "crashes": [
                    {
                        "file": "c1",
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
    _write_json(tmp_path / "triage.json", triage)
    _write_json(
        tmp_path / "binary.json",
        {"exploit_mitigation_summary": {"protection_count": 1}},
    )

    monkeypatch.setattr(cli, "OllamaClient", _FakeLLMClient)
    monkeypatch.setattr(cli.config, "resolve_host", lambda explicit: "http://x")
    monkeypatch.setattr(cli.config, "resolve_model", lambda explicit, host: "fake-model")

    captured = {}

    def fake_llm_analyze(client, triage_data, source_code, binary_analysis, **kwargs):
        captured["severity_assessment"] = kwargs.get("severity_assessment")
        return {"summary": "a summary"}

    monkeypatch.setattr(cli, "llm_analyze", fake_llm_analyze)

    rc = cli.main(
        [
            "llm",
            "--triage-json",
            "triage.json",
            "--binary-analysis",
            "binary.json",
            "--output",
            "llm.json",
        ]
    )
    assert rc == 0
    assessment = captured["severity_assessment"]
    assert assessment is not None
    assert assessment["basis"] == "mitigation_and_crash"
    assert assessment["difficulty"] in ("Easy", "Medium", "Hard")


def test_cmd_llm_missing_triage_file_errors(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    rc = cli.main(["llm", "--triage-json", "no-such.json"])
    assert rc == 1
    assert "not found" in capsys.readouterr().out


def test_cmd_llm_model_resolution_failure(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    _write_json(tmp_path / "triage.json", {"groups": {}})

    def fake_resolve_model(explicit, host):
        raise cli.config.ModelResolutionError("no models installed")

    monkeypatch.setattr(cli.config, "resolve_model", fake_resolve_model)

    rc = cli.main(["llm", "--triage-json", "triage.json"])
    assert rc == 1
    assert "no models installed" in capsys.readouterr().out


def test_cmd_llm_client_check_failure(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    _write_json(tmp_path / "triage.json", {"groups": {}})

    class UnreachableClient:
        def __init__(self, model, host, timeout=None):
            pass

        def check(self):
            return False, "Ollama is not reachable"

    monkeypatch.setattr(cli, "OllamaClient", UnreachableClient)
    monkeypatch.setattr(cli.config, "resolve_model", lambda explicit, host: "fake-model")

    rc = cli.main(["llm", "--triage-json", "triage.json"])
    assert rc == 1
    assert "not reachable" in capsys.readouterr().out


def test_cmd_crash_info_with_explicit_file(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    crash_file = tmp_path / "crash1.txt"
    crash_file.write_text("hello\nworld\n")

    rc = cli.main(["crash-info", str(crash_file)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Crash file:" in out
    assert "Size:" in out


def test_cmd_crash_info_missing_file_errors(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    rc = cli.main(["crash-info", str(tmp_path / "nope")])
    assert rc == 1
    assert "Error" in capsys.readouterr().out


def test_cmd_pipeline_success_with_skip_llm(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    crashes = tmp_path / "crashes"
    crashes.mkdir()
    (crashes / "crash1").write_bytes(b"AAAA")

    binary = tmp_path / "target"
    binary.write_text("#!/bin/sh\nkill -SEGV $$\n")
    binary.chmod(0o755)

    source = tmp_path / "vuln.c"
    source.write_text("int main(){return 0;}")

    monkeypatch.setattr("autofte.triage.gdb_is_available", lambda debugger: False)
    monkeypatch.setattr(cli, "analyze_binary", lambda path: {"exploit_mitigation_summary": {}})

    rc = cli.main(
        [
            "pipeline",
            str(binary),
            str(source),
            "--crashes-dir",
            str(crashes),
            "--skip-llm",
            "--quiet",
            "--triage-json",
            "triage.json",
            "--binary-analysis",
            "binary.json",
            "--llm-analysis",
            "llm.json",
            "--summary-md",
            "summary.md",
            "--dashboard-dir",
            "dashboard",
        ]
    )
    assert rc == 0
    assert (tmp_path / "triage.json").exists()
    assert (tmp_path / "binary.json").exists()
    assert (tmp_path / "summary.md").exists()
    assert (tmp_path / "dashboard" / "index.html").exists()
    llm_result = json.loads((tmp_path / "llm.json").read_text())
    assert llm_result["status"] == "skipped"
    out = capsys.readouterr().out
    assert "Done." not in out


def test_cmd_pipeline_sarif_flag_writes_sarif_alongside_markdown(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    crashes = tmp_path / "crashes"
    crashes.mkdir()
    (crashes / "crash1").write_bytes(b"AAAA")

    binary = tmp_path / "target"
    binary.write_text("#!/bin/sh\nkill -SEGV $$\n")
    binary.chmod(0o755)

    source = tmp_path / "vuln.c"
    source.write_text("int main(){return 0;}")

    monkeypatch.setattr("autofte.triage.gdb_is_available", lambda debugger: False)
    monkeypatch.setattr(cli, "analyze_binary", lambda path: {"exploit_mitigation_summary": {}})

    rc = cli.main(
        [
            "pipeline",
            str(binary),
            str(source),
            "--crashes-dir",
            str(crashes),
            "--skip-llm",
            "--triage-json",
            "triage.json",
            "--binary-analysis",
            "binary.json",
            "--llm-analysis",
            "llm.json",
            "--summary-md",
            "summary.md",
            "--dashboard-dir",
            "dashboard",
            "--sarif",
            "findings.sarif",
        ]
    )
    assert rc == 0
    assert (tmp_path / "summary.md").exists()
    sarif_data = json.loads((tmp_path / "findings.sarif").read_text())
    assert sarif_data["version"] == "2.1.0"
    out = capsys.readouterr().out
    assert "SARIF: findings.sarif" in out


def test_cmd_pipeline_without_sarif_flag_writes_no_sarif_file(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    crashes = tmp_path / "crashes"
    crashes.mkdir()
    (crashes / "crash1").write_bytes(b"AAAA")

    binary = tmp_path / "target"
    binary.write_text("#!/bin/sh\nkill -SEGV $$\n")
    binary.chmod(0o755)

    source = tmp_path / "vuln.c"
    source.write_text("int main(){return 0;}")

    monkeypatch.setattr("autofte.triage.gdb_is_available", lambda debugger: False)
    monkeypatch.setattr(cli, "analyze_binary", lambda path: {"exploit_mitigation_summary": {}})

    rc = cli.main(
        [
            "pipeline",
            str(binary),
            str(source),
            "--crashes-dir",
            str(crashes),
            "--skip-llm",
            "--quiet",
            "--triage-json",
            "triage.json",
            "--binary-analysis",
            "binary.json",
            "--llm-analysis",
            "llm.json",
            "--summary-md",
            "summary.md",
            "--dashboard-dir",
            "dashboard",
        ]
    )
    assert rc == 0
    assert not (tmp_path / "findings.sarif").exists()
    assert "SARIF" not in capsys.readouterr().out


# --------------------------------------------------------------------------
# demo
# --------------------------------------------------------------------------

def test_plural_singular_and_plural_forms():
    assert cli._plural(1, "crash", "crashes") == "1 crash"
    assert cli._plural(0, "crash", "crashes") == "0 crashes"
    assert cli._plural(2, "crash", "crashes") == "2 crashes"
    assert cli._plural(1, "root cause", "root causes") == "1 root cause"
    assert cli._plural(3, "root cause", "root causes") == "3 root causes"


def _fake_no_ollama(monkeypatch):
    def fake_resolve_model(explicit, host):
        raise cli.config.ModelResolutionError("no models installed")

    monkeypatch.setattr(cli.config, "resolve_model", fake_resolve_model)


def test_cmd_demo_end_to_end_no_ollama(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    demo_dir = tmp_path / "demo"
    demo_dir.mkdir()
    (demo_dir / "vuln.c").write_text("int main(){return 0;}")
    crashes = demo_dir / "crashes"
    crashes.mkdir()
    (crashes / "crash1").write_bytes(b"AAAA")

    target = demo_dir / "target"
    target.write_text("#!/bin/sh\nkill -SEGV $$\n")
    target.chmod(0o755)

    monkeypatch.setattr("autofte.triage.gdb_is_available", lambda debugger: False)
    monkeypatch.setattr(
        cli,
        "analyze_binary",
        lambda path: {
            "stack_canaries": {"enabled": False},
            "pie": {"enabled": False},
            "exploit_mitigation_summary": {
                "protection_level": "Low",
                "exploit_difficulty": "Easy",
            },
        },
    )
    _fake_no_ollama(monkeypatch)

    rc = cli.main(["demo", "--demo-dir", str(demo_dir)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "AutoFTE demo" in out
    assert "→ 1 crash · 1 root cause · #1 SIGSEGV (1 crash) — Easy · 1/1 reproducible" in out
    # quiet by default: no per-step pipeline noise, no CWD pollution, no
    # absolute installed-package path leaked into the output.
    assert "AutoFTE local pipeline" not in out
    assert "BINARY PROTECTION SUMMARY" not in out
    assert str(demo_dir) not in out
    assert "Artifacts written to autofte-demo-output/" in out
    assert not (tmp_path / "crash_triage.json").exists()
    output_dir = tmp_path / "autofte-demo-output"
    assert (output_dir / "crash_triage.json").exists()
    assert (output_dir / "dashboard" / "index.html").exists()
    llm_result = json.loads((output_dir / "llm_analysis.json").read_text())
    assert llm_result["status"] == "skipped"


def test_cmd_demo_pluralizes_crashes_with_singular_root_cause(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    demo_dir = tmp_path / "demo"
    demo_dir.mkdir()
    (demo_dir / "vuln.c").write_text("int main(){return 0;}")
    crashes = demo_dir / "crashes"
    crashes.mkdir()
    (crashes / "crash1").write_bytes(b"AAAA")
    (crashes / "crash2").write_bytes(b"BBBB")

    target = demo_dir / "target"
    target.write_text("#!/bin/sh\nkill -SEGV $$\n")
    target.chmod(0o755)

    monkeypatch.setattr("autofte.triage.gdb_is_available", lambda debugger: False)
    monkeypatch.setattr(
        cli,
        "analyze_binary",
        lambda path: {
            "stack_canaries": {"enabled": False},
            "pie": {"enabled": False},
            "exploit_mitigation_summary": {
                "protection_level": "Low",
                "exploit_difficulty": "Easy",
            },
        },
    )
    _fake_no_ollama(monkeypatch)

    rc = cli.main(["demo", "--demo-dir", str(demo_dir)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "→ 2 crashes · 1 root cause · #1 SIGSEGV (2 crashes) — Easy · 2/2 reproducible" in out


def _demo_fixture(tmp_path, num_crashes=1):
    demo_dir = tmp_path / "demo"
    demo_dir.mkdir()
    (demo_dir / "vuln.c").write_text("int main(){return 0;}")
    crashes = demo_dir / "crashes"
    crashes.mkdir()
    for i in range(num_crashes):
        (crashes / f"crash{i}").write_bytes(b"AAAA")

    target = demo_dir / "target"
    target.write_text("#!/bin/sh\nkill -SEGV $$\n")
    target.chmod(0o755)
    return demo_dir


def test_cmd_demo_verbose_shows_full_pipeline_output(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    demo_dir = _demo_fixture(tmp_path)

    monkeypatch.setattr("autofte.triage.gdb_is_available", lambda debugger: False)
    monkeypatch.setattr(cli, "analyze_binary", lambda path: {"exploit_mitigation_summary": {}})
    _fake_no_ollama(monkeypatch)

    rc = cli.main(["demo", "--demo-dir", str(demo_dir), "--verbose"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "AutoFTE local pipeline" in out
    assert "BINARY PROTECTION SUMMARY" in out


def test_cmd_demo_custom_output_dir(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    demo_dir = _demo_fixture(tmp_path)
    out_dir = tmp_path / "somewhere-else"

    monkeypatch.setattr("autofte.triage.gdb_is_available", lambda debugger: False)
    monkeypatch.setattr(cli, "analyze_binary", lambda path: {"exploit_mitigation_summary": {}})
    _fake_no_ollama(monkeypatch)

    rc = cli.main(
        ["demo", "--demo-dir", str(demo_dir), "--output-dir", str(out_dir)]
    )
    assert rc == 0
    assert (out_dir / "crash_triage.json").exists()
    assert (out_dir / "dashboard" / "index.html").exists()
    assert not (tmp_path / "autofte-demo-output").exists()
    out = capsys.readouterr().out
    assert "Artifacts written to somewhere-else/" in out


def test_friendly_path_relative_to_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    nested = tmp_path / "a" / "b"
    nested.mkdir(parents=True)
    assert cli._friendly_path(nested) == "a/b"


def test_friendly_path_outside_cwd_shows_last_two_components(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    nested = cli.Path(
        "/opt/some-venv/site-packages/autofte/demo_assets/vuln-demo/target_asan"
    )
    assert cli._friendly_path(nested) == "vuln-demo/target_asan"


def test_friendly_label_shortens_embedded_absolute_paths():
    label = (
        "heap-buffer-overflow (write 65) in vuln_heap_overflow "
        "at /home/user/repos/AutoFTE/examples/vuln-demo/vuln.c:56"
    )
    assert cli._friendly_label(label) == (
        "heap-buffer-overflow (write 65) in vuln_heap_overflow at vuln.c:56"
    )


def test_friendly_label_leaves_text_without_paths_unchanged():
    assert cli._friendly_label("SIGSEGV") == "SIGSEGV"


def test_pick_headline_group_ranks_by_severity_not_just_count():
    binary_data = {"exploit_mitigation_summary": {"protection_count": 0}}
    groups = {
        "null-pointer-dereference in noisy_path": {
            "count": 900,
            "crashes": [
                {
                    "sanitizer": {
                        "bug_class": "null-pointer-dereference",
                        "access_type": None,
                        "access_size": None,
                        "crash_stack": [{"frame": 0, "func": "noisy_path"}],
                    }
                }
            ],
        },
        "heap-buffer-overflow (write 8) in parse_header": {
            "count": 3,
            "crashes": [
                {
                    "sanitizer": {
                        "bug_class": "heap-buffer-overflow",
                        "access_type": "write",
                        "access_size": 8,
                        "crash_stack": [{"frame": 0, "func": "parse_header"}],
                    }
                }
            ],
        },
    }
    label, group, assessment = cli._pick_headline_group(binary_data, groups)
    assert label == "heap-buffer-overflow (write 8) in parse_header"
    assert group["count"] == 3
    assert assessment["difficulty"] == "Easy"


def test_cmd_demo_builds_target_when_missing(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    demo_dir = tmp_path / "demo"
    demo_dir.mkdir()
    (demo_dir / "vuln.c").write_text("int main(){return 0;}")
    crashes = demo_dir / "crashes"
    crashes.mkdir()
    (crashes / "crash1").write_bytes(b"AAAA")

    real_run = cli.subprocess.run

    def fake_run(args, *a, **kw):
        if args[0] != "make":
            return real_run(args, *a, **kw)
        target = demo_dir / "target"
        target.write_text("#!/bin/sh\nkill -SEGV $$\n")
        target.chmod(0o755)
        return FakeCompletedProcess(returncode=0)

    monkeypatch.setattr(cli.subprocess, "run", fake_run)
    monkeypatch.setattr("autofte.triage.gdb_is_available", lambda debugger: False)
    monkeypatch.setattr(cli, "analyze_binary", lambda path: {"exploit_mitigation_summary": {}})
    _fake_no_ollama(monkeypatch)

    rc = cli.main(["demo", "--demo-dir", str(demo_dir)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Building bundled demo target" in out


def test_cmd_demo_build_failure_returns_error(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    demo_dir = tmp_path / "demo"
    demo_dir.mkdir()

    monkeypatch.setattr(
        cli.subprocess, "run", lambda args, *a, **kw: FakeCompletedProcess(returncode=1)
    )

    rc = cli.main(["demo", "--demo-dir", str(demo_dir)])
    assert rc == 1
    assert "failed to build" in capsys.readouterr().out.lower()


def test_cmd_demo_missing_demo_dir_returns_error(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    missing = tmp_path / "nope"

    rc = cli.main(["demo", "--demo-dir", str(missing)])
    assert rc == 1
    assert "not found" in capsys.readouterr().out


def test_cmd_demo_missing_crashes_dir_returns_error(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    demo_dir = tmp_path / "demo"
    demo_dir.mkdir()
    target = demo_dir / "target"
    target.write_text("#!/bin/sh\nexit 0\n")
    target.chmod(0o755)

    rc = cli.main(["demo", "--demo-dir", str(demo_dir)])
    assert rc == 1
    assert "crashes" in capsys.readouterr().out.lower()


def test_cmd_demo_default_dir_points_at_bundled_examples():
    assert cli.DEMO_DIR.parts[-2:] == ("examples", "vuln-demo")
