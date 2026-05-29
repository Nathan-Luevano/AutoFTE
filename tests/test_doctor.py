from autofte import doctor


def test_check_environment_reports_tool_availability(monkeypatch):
    def fake_which(tool):
        available = {"readelf", "objdump", "nm", "ldd", "file", "strings", "gdb"}
        return f"/usr/bin/{tool}" if tool in available else None

    monkeypatch.setattr(doctor.shutil, "which", fake_which)
    monkeypatch.setattr(doctor.config, "list_installed_models", lambda host: ["model-a"])

    report = doctor.check_environment(host="http://x")
    assert report["required_tools"]["readelf"] is True
    assert report["optional_tools"]["gdb"] is True
    assert report["optional_tools"]["checksec"] is False
    assert report["ollama_reachable"] is True
    assert report["ollama_models"] == ["model-a"]
    assert report["ollama_error"] is None


def test_check_environment_missing_required_tools(monkeypatch):
    monkeypatch.setattr(doctor.shutil, "which", lambda tool: None)
    monkeypatch.setattr(doctor.config, "list_installed_models", lambda host: ["model-a"])

    report = doctor.check_environment(host="http://x")
    assert all(found is False for found in report["required_tools"].values())


def test_check_environment_ollama_unreachable(monkeypatch):
    monkeypatch.setattr(doctor.shutil, "which", lambda tool: None)

    def fake_list(host):
        raise ConnectionError("refused")

    monkeypatch.setattr(doctor.config, "list_installed_models", fake_list)
    report = doctor.check_environment(host="http://x")
    assert report["ollama_reachable"] is False
    assert "refused" in report["ollama_error"]
    assert report["ollama_models"] == []


def test_check_environment_uses_resolve_host(monkeypatch):
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    monkeypatch.setattr(doctor.shutil, "which", lambda tool: None)
    monkeypatch.setattr(doctor.config, "list_installed_models", lambda host: [])

    report = doctor.check_environment(host=None)
    assert report["host"] == "http://localhost:11434"


def test_format_report_contains_all_sections():
    report = {
        "host": "http://localhost:11434",
        "required_tools": {"readelf": True, "objdump": False},
        "optional_tools": {"gdb": True, "checksec": False},
        "ollama_reachable": True,
        "ollama_models": ["llama3"],
        "ollama_error": None,
    }
    text = doctor.format_report(report)
    assert "[ok] readelf" in text
    assert "[MISSING] objdump" in text
    assert "[ok] gdb" in text
    assert "[missing] checksec" in text
    assert "reachable, 1 model(s) installed" in text
    assert "llama3" in text


def test_format_report_ollama_unreachable_section():
    report = {
        "host": "http://localhost:11434",
        "required_tools": {},
        "optional_tools": {},
        "ollama_reachable": False,
        "ollama_models": [],
        "ollama_error": "connection refused",
    }
    text = doctor.format_report(report)
    assert "not reachable (connection refused)" in text
    assert "LLM notes will be skipped" in text
