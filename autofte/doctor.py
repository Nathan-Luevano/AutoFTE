"""Environment sanity check: what does this machine actually have?

Nothing here is required for every subcommand (e.g. gdb and afl-fuzz are
both optional, with fallbacks), but people trying AutoFTE for the first
time want one command that tells them what's missing instead of
discovering it one cryptic failure at a time.
"""

import shutil

from . import config

REQUIRED_TOOLS = ("readelf", "objdump", "nm", "ldd", "file", "strings")
OPTIONAL_TOOLS = ("gdb", "checksec", "afl-fuzz", "afl-cmin")


def check_environment(host=None):
    host = config.resolve_host(host)

    required = {tool: shutil.which(tool) is not None for tool in REQUIRED_TOOLS}
    optional = {tool: shutil.which(tool) is not None for tool in OPTIONAL_TOOLS}

    ollama_reachable = False
    ollama_models = []
    ollama_error = None
    try:
        ollama_models = config.list_installed_models(host)
        ollama_reachable = True
    except Exception as exc:  # noqa: BLE001 - this is a diagnostic, report anything
        ollama_error = str(exc)

    return {
        "host": host,
        "required_tools": required,
        "optional_tools": optional,
        "ollama_reachable": ollama_reachable,
        "ollama_models": ollama_models,
        "ollama_error": ollama_error,
    }


def format_report(report):
    lines = ["AutoFTE environment check", ""]

    lines.append("Required tools (binary analysis will fail without these):")
    for tool, found in report["required_tools"].items():
        lines.append(f"  [{'ok' if found else 'MISSING'}] {tool}")

    lines.append("")
    lines.append("Optional tools (features fall back gracefully without these):")
    for tool, found in report["optional_tools"].items():
        lines.append(f"  [{'ok' if found else 'missing'}] {tool}")

    lines.append("")
    lines.append(f"Ollama at {report['host']}:")
    if report["ollama_reachable"]:
        lines.append(f"  reachable, {len(report['ollama_models'])} model(s) installed")
        for name in report["ollama_models"]:
            lines.append(f"    - {name}")
    else:
        lines.append(f"  not reachable ({report['ollama_error']})")
        lines.append("  LLM notes will be skipped; everything else still works.")

    return "\n".join(lines)
