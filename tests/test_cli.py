import argparse
import json

import pytest

from autofte import cli

SUBCOMMANDS_MIN_ARGS = {
    "triage": [],
    "binscan": ["some-binary"],
    "llm": [],
    "report": [],
    "dashboard": [],
    "crash-info": [],
    "doctor": [],
    "pipeline": [],
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
    binary.write_text("#!/bin/sh\nexit 139\n")
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
    def __init__(self, model, host):
        self.model = model
        self.host = host

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
        lambda client, triage_data, source_code, binary_analysis: {
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
        def __init__(self, model, host):
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
    binary.write_text("#!/bin/sh\nexit 139\n")
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
    assert "Done." in out
