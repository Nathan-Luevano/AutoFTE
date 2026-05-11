"""AutoFTE command-line interface.

Each analysis step is its own subcommand so it can be run standalone,
plus a `pipeline` subcommand that chains all of them the way the old
pipeline.sh did.
"""

import argparse
import subprocess
import sys
from pathlib import Path

from . import config, dashboard, doctor, report
from .binary_analysis import analyze_binary
from .io_utils import load_json, write_json
from .llm import LLMResponseError, OllamaClient, analyze as llm_analyze
from .paths import pick_crash_dir
from .triage import triage_crashes


def _print_progress(index, total, name):
    print(f"Processing {index}/{total}: {name}", end="\r", flush=True)
    if index == total:
        print()


def cmd_triage(args):
    try:
        result = triage_crashes(
            args.crashes_dir,
            args.target_binary,
            debugger=args.debugger,
            progress_callback=None if args.quiet else _print_progress,
        )
    except FileNotFoundError as exc:
        print(f"Error: {exc}")
        return 1

    if result["triage_mode"] == "direct":
        print("gdb was not found, using exit signal grouping instead")
    if result["total_crashes"] == 0:
        print(f"No crash files found in {args.crashes_dir}")

    write_json(args.output, result)
    print(f"Saved triage results to {args.output}")
    print(f"Crash files: {result['total_crashes']}")
    print(f"Groups: {result['unique_crash_frames']}")
    print(f"Mode: {result['triage_mode']}")
    return 0


def cmd_binscan(args):
    if not Path(args.binary).exists():
        print(f"Error: binary '{args.binary}' not found")
        return 1

    print(f"Analyzing binary protections: {args.binary}")
    results = analyze_binary(args.binary)
    write_json(args.output, results)
    print(f"Analysis complete. Results saved to: {args.output}")

    summary = results.get("exploit_mitigation_summary", {})
    print("\nBINARY PROTECTION SUMMARY")
    print("=" * 50)
    print(f"Protection Level: {summary.get('protection_level', 'Unknown')}")
    print(f"Exploit Difficulty: {summary.get('exploit_difficulty', 'Unknown')}")

    if summary.get("required_techniques"):
        print("\nRequired Bypass Techniques:")
        for technique in summary["required_techniques"]:
            print(f"  - {technique}")

    if summary.get("vulnerable_areas"):
        print("\nVulnerable Areas:")
        for area in summary["vulnerable_areas"]:
            print(f"  - {area}")

    return 0


def cmd_llm(args):
    if not Path(args.triage_json).exists():
        print(f"Error: triage file not found: {args.triage_json}")
        return 1

    triage_data = load_json(args.triage_json)
    source_code = None
    if args.source_file and Path(args.source_file).exists():
        source_code = Path(args.source_file).read_text(encoding="utf-8")
    binary_analysis = None
    if Path(args.binary_analysis).exists():
        binary_analysis = load_json(args.binary_analysis)

    host = config.resolve_host(args.host)
    try:
        model = config.resolve_model(args.model, host)
    except config.ModelResolutionError as exc:
        print(f"Error: {exc}")
        return 1

    client = OllamaClient(model=model, host=host)
    ok, message = client.check()
    if not ok:
        print(message)
        return 1

    print(f"Using model: {model}")
    try:
        result = llm_analyze(client, triage_data, source_code, binary_analysis)
    except LLMResponseError as exc:
        print(f"Error: {exc}")
        return 1

    write_json(args.output, result)
    print(f"Wrote {args.output}")
    print(result.get("summary", "No summary returned"))
    return 0


def cmd_report(args):
    triage = load_json(args.triage_json)
    binary_data = load_json(args.binary_analysis)
    llm_data = load_json(args.llm_analysis)
    text = report.build_report(
        args.target_binary, args.source_file, triage, binary_data, llm_data
    )
    Path(args.output).write_text(text, encoding="utf-8")
    print(f"Wrote {args.output}")
    return 0


def cmd_dashboard(args):
    triage = load_json(args.triage_json)
    binary_data = load_json(args.binary_analysis)
    llm_data = load_json(args.llm_analysis)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / "index.html"
    html_text = dashboard.build_html(triage, binary_data, llm_data)
    output_file.write_text(html_text, encoding="utf-8")
    print(f"Wrote {output_file}")
    return 0


def cmd_crash_info(args):
    crash_file = Path(args.crash_file) if args.crash_file else _latest_crash_file()
    if crash_file is None or not crash_file.is_file():
        print("Error: crash file not found")
        return 1

    size = crash_file.stat().st_size
    file_type = subprocess.run(
        ["file", "-b", str(crash_file)], capture_output=True, text=True
    ).stdout.strip()

    print(f"Crash file: {crash_file}")
    print(f"Size: {size} bytes")
    print(f"Type: {file_type}")
    print()

    if "text" in file_type.lower():
        print("Preview:")
        with crash_file.open("r", encoding="utf-8", errors="replace") as handle:
            for _, line in zip(range(12), handle):
                print(line.rstrip("\n"))
    else:
        print("Hex preview:")
        result = subprocess.run(
            ["hexdump", "-C", str(crash_file)], capture_output=True, text=True
        )
        for line in result.stdout.splitlines()[:12]:
            print(line)

    return 0


def _latest_crash_file():
    crash_dir = Path(pick_crash_dir())
    if not crash_dir.is_dir():
        return None
    candidates = sorted(
        p for p in crash_dir.iterdir() if p.is_file() and p.name != "README.txt"
    )
    return candidates[-1] if candidates else None


def cmd_doctor(args):
    report_data = doctor.check_environment(args.host)
    print(doctor.format_report(report_data))
    return 0


def cmd_pipeline(args):
    crashes_dir = args.crashes_dir or pick_crash_dir()
    if not Path(args.target_binary).exists():
        print(f"Error: target binary not found or not executable: {args.target_binary}")
        print("Build it first, e.g.: make -C examples/vuln-demo")
        return 1
    if not Path(crashes_dir).is_dir():
        print(f"Error: no crash directory found ({crashes_dir})")
        return 1

    print("AutoFTE local pipeline")
    print(f"Target: {args.target_binary}")
    print(f"Source: {args.source_file}")
    print(f"Crashes: {crashes_dir}\n")

    triage_ns = argparse.Namespace(
        crashes_dir=crashes_dir,
        target_binary=args.target_binary,
        debugger=args.debugger,
        output=args.triage_json,
        quiet=args.quiet,
    )
    if cmd_triage(triage_ns) != 0:
        return 1

    binscan_ns = argparse.Namespace(binary=args.target_binary, output=args.binary_analysis)
    if cmd_binscan(binscan_ns) != 0:
        write_json(
            args.binary_analysis,
            {"status": "skipped", "summary": "Binary analysis did not complete cleanly."},
        )

    if not args.skip_llm:
        llm_ns = argparse.Namespace(
            triage_json=args.triage_json,
            source_file=args.source_file if Path(args.source_file).exists() else None,
            binary_analysis=args.binary_analysis,
            output=args.llm_analysis,
            model=args.model,
            host=args.host,
        )
        if cmd_llm(llm_ns) != 0:
            write_json(
                args.llm_analysis,
                {
                    "status": "skipped",
                    "summary": (
                        "Ollama was not available, so this run only includes "
                        "local analysis."
                    ),
                },
            )
    else:
        write_json(
            args.llm_analysis,
            {"status": "skipped", "summary": "LLM step skipped (--skip-llm)."},
        )

    report_ns = argparse.Namespace(
        target_binary=args.target_binary,
        source_file=args.source_file,
        triage_json=args.triage_json,
        binary_analysis=args.binary_analysis,
        llm_analysis=args.llm_analysis,
        output=args.summary_md,
    )
    cmd_report(report_ns)

    dashboard_ns = argparse.Namespace(
        triage_json=args.triage_json,
        binary_analysis=args.binary_analysis,
        llm_analysis=args.llm_analysis,
        output_dir=args.dashboard_dir,
    )
    cmd_dashboard(dashboard_ns)

    print("\nDone.")
    print(f"  Triage: {args.triage_json}")
    print(f"  Binary analysis: {args.binary_analysis}")
    print(f"  LLM notes: {args.llm_analysis}")
    print(f"  Summary: {args.summary_md}")
    print(f"  Dashboard: {args.dashboard_dir}/index.html")
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="autofte", description="Local crash triage and binary analysis pipeline"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_triage = subparsers.add_parser("triage", help="Group crash files by debugger frame or signal")
    p_triage.add_argument("--crashes-dir", default=pick_crash_dir())
    p_triage.add_argument("--target-binary", default="./target")
    p_triage.add_argument("--output", default="crash_triage.json")
    p_triage.add_argument("--debugger", default="gdb")
    p_triage.add_argument("--quiet", action="store_true", help="Suppress per-file progress output")
    p_triage.set_defaults(func=cmd_triage)

    p_binscan = subparsers.add_parser(
        "binscan", help="Check a binary's exploit mitigations (NX, PIE, RELRO, ...)"
    )
    p_binscan.add_argument("binary")
    p_binscan.add_argument("-o", "--output", default="binary_analysis.json")
    p_binscan.set_defaults(func=cmd_binscan)

    p_llm = subparsers.add_parser("llm", help="Ask a local Ollama model for a short write-up")
    p_llm.add_argument("--triage-json", default="crash_triage.json")
    p_llm.add_argument("--source-file")
    p_llm.add_argument("--binary-analysis", default="binary_analysis.json")
    p_llm.add_argument("--output", default="llm_analysis.json")
    p_llm.add_argument("--model", help="Ollama model name (default: auto-detect)")
    p_llm.add_argument("--host", help="Ollama host (default: $OLLAMA_HOST or http://localhost:11434)")
    p_llm.set_defaults(func=cmd_llm)

    p_report = subparsers.add_parser(
        "report", help="Build a markdown summary from analysis artifacts"
    )
    p_report.add_argument("--target-binary", default="./target")
    p_report.add_argument("--source-file", default="vuln.c")
    p_report.add_argument("--triage-json", default="crash_triage.json")
    p_report.add_argument("--binary-analysis", default="binary_analysis.json")
    p_report.add_argument("--llm-analysis", default="llm_analysis.json")
    p_report.add_argument("--output", default="analysis_summary.md")
    p_report.set_defaults(func=cmd_report)

    p_dashboard = subparsers.add_parser("dashboard", help="Build a static HTML dashboard")
    p_dashboard.add_argument("--triage-json", default="crash_triage.json")
    p_dashboard.add_argument("--binary-analysis", default="binary_analysis.json")
    p_dashboard.add_argument("--llm-analysis", default="llm_analysis.json")
    p_dashboard.add_argument("--output-dir", default="dashboard")
    p_dashboard.set_defaults(func=cmd_dashboard)

    p_crash_info = subparsers.add_parser(
        "crash-info", help="Print quick details about one crash file"
    )
    p_crash_info.add_argument(
        "crash_file", nargs="?", help="Defaults to the newest file in the crash dir"
    )
    p_crash_info.set_defaults(func=cmd_crash_info)

    p_doctor = subparsers.add_parser(
        "doctor", help="Check which required/optional tools are installed"
    )
    p_doctor.add_argument("--host", help="Ollama host to check")
    p_doctor.set_defaults(func=cmd_doctor)

    p_pipeline = subparsers.add_parser(
        "pipeline", help="Run the full triage -> binscan -> llm -> report -> dashboard flow"
    )
    p_pipeline.add_argument("target_binary", nargs="?", default="./target")
    p_pipeline.add_argument("source_file", nargs="?", default="vuln.c")
    p_pipeline.add_argument("--crashes-dir")
    p_pipeline.add_argument("--debugger", default="gdb")
    p_pipeline.add_argument("--model", help="Ollama model name (default: auto-detect)")
    p_pipeline.add_argument("--host", help="Ollama host")
    p_pipeline.add_argument(
        "--skip-llm", action="store_true", help="Skip the LLM write-up step entirely"
    )
    p_pipeline.add_argument("--quiet", action="store_true")
    p_pipeline.add_argument("--triage-json", default="crash_triage.json")
    p_pipeline.add_argument("--binary-analysis", default="binary_analysis.json")
    p_pipeline.add_argument("--llm-analysis", default="llm_analysis.json")
    p_pipeline.add_argument("--summary-md", default="analysis_summary.md")
    p_pipeline.add_argument("--dashboard-dir", default="dashboard")
    p_pipeline.set_defaults(func=cmd_pipeline)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
