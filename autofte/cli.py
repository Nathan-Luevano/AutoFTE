"""AutoFTE command-line interface.

Each analysis step is its own subcommand so it can be run standalone,
plus a `pipeline` subcommand that chains all of them the way the old
pipeline.sh did.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from . import (
    __version__,
    bench,
    config,
    crash_display,
    dashboard,
    disasm,
    doctor,
    report,
    sarif,
    severity,
    summary,
)
from .binary_analysis import analyze_binary
from .io_utils import load_json, write_json
from .llm import LLMResponseError, OllamaClient
from .llm import analyze as llm_analyze
from .paths import pick_crash_dir
from .triage import DEFAULT_REPRODUCTION_RUNS, triage_crashes

DEMO_DIR = Path(__file__).resolve().parent.parent / "examples" / "vuln-demo"
PACKAGED_DEMO_DIR = Path(__file__).resolve().parent / "demo_assets" / "vuln-demo"
DEMO_ASSET_NAMES = ("Makefile", "vuln.c", "README.md")
DEMO_ASSET_SUBDIRS = ("in", "crashes")
DEMO_REPRODUCTION_RUNS = 2


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
            reproduction_runs=getattr(args, "reproduction_runs", DEFAULT_REPRODUCTION_RUNS),
        )
    except FileNotFoundError as exc:
        print(f"Error: {exc}")
        return 1

    quiet = args.quiet
    if result["triage_mode"] == "direct" and not quiet:
        print("gdb was not found, using exit signal grouping instead")
    if result["triage_mode"] == "empty" and not quiet:
        print(f"No crash files found in {args.crashes_dir}")

    write_json(args.output, result)
    if not quiet:
        print(f"Saved triage results to {args.output}")

        repro = result.get("reproduction_summary", {})
        crashed_on_first_run = repro.get("crashed_on_first_run", 0)
        if crashed_on_first_run:
            reproducible = repro.get("reproducible", 0)
            rate = reproducible / crashed_on_first_run * 100
            print(
                f"Reproducible: {reproducible}/{crashed_on_first_run} ({rate:.1f}%) -- "
                f"flaky: {repro.get('flaky', 0)}, "
                f"unstable-bucket: {repro.get('unstable_bucket', 0)}, "
                f"non-reproducible: {repro.get('non_reproducible', 0)}"
            )
        if result.get("no_crash_count") or result.get("timeout_count"):
            print(
                f"Non-crash noise excluded: {result.get('no_crash_count', 0)} no-crash, "
                f"{result.get('timeout_count', 0)} timeout"
            )

        print(f"Crash files: {result['total_crashes']}")
        print(f"Groups: {result['unique_crash_frames']}")
        print(f"Mode: {result['triage_mode']}")
    return 0


def cmd_binscan(args):
    if not Path(args.binary).exists():
        print(f"Error: binary '{args.binary}' not found")
        return 1

    quiet = getattr(args, "quiet", False)
    if not quiet:
        print(f"Analyzing binary protections: {args.binary}")
    results = analyze_binary(args.binary)
    write_json(args.output, results)
    if quiet:
        return 0

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


def _top_group_crash_record(triage_data):
    groups = triage_data.get("groups", {})
    first_group = next(iter(groups.values()), None)
    if not first_group:
        return None
    return crash_display.representative_crash_record(first_group)


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

    timeout = config.resolve_timeout(getattr(args, "llm_timeout", None))
    client = OllamaClient(model=model, host=host, timeout=timeout)
    ok, message = client.check()
    if not ok:
        print(message)
        return 1

    crash_record = _top_group_crash_record(triage_data)

    severity_assessment = None
    if binary_analysis is not None:
        severity_assessment = severity.assess_crash_difficulty(binary_analysis, crash_record)

    disassembly = None
    target_binary = getattr(args, "target_binary", None)
    if target_binary and Path(target_binary).exists():
        disassembly = disasm.disassemble_fault_context(target_binary, crash_record)

    quiet = getattr(args, "quiet", False)
    if not quiet:
        print(f"Using model: {model}")
        if disassembly:
            print("Grounding with disassembly around the faulting instruction")
    try:
        result = llm_analyze(
            client,
            triage_data,
            source_code,
            binary_analysis,
            severity_assessment=severity_assessment,
            disassembly=disassembly,
        )
    except LLMResponseError as exc:
        print(f"Error: {exc}")
        return 1

    if disassembly:
        result["disassembly_context"] = disassembly

    write_json(args.output, result)
    if not quiet:
        print(f"Wrote {args.output}")
        print(result.get("summary", "No summary returned"))
    return 0


def cmd_report(args):
    triage = load_json(args.triage_json)
    binary_data = load_json(args.binary_analysis)
    llm_data = load_json(args.llm_analysis)

    if args.format == "sarif":
        write_json(
            args.output,
            sarif.build_sarif(triage, binary_data, llm_data, args.target_binary),
        )
    elif args.format == "json":
        write_json(
            args.output,
            summary.build_summary(
                args.target_binary, args.source_file, triage, binary_data, llm_data
            ),
        )
    else:
        text = report.build_report(
            args.target_binary,
            args.source_file,
            triage,
            binary_data,
            llm_data,
            max_groups=getattr(args, "top", None),
        )
        Path(args.output).write_text(text, encoding="utf-8")

    if not getattr(args, "quiet", False):
        print(f"Wrote {args.output}")
    return 0


def cmd_dashboard(args):
    triage = load_json(args.triage_json)
    binary_data = load_json(args.binary_analysis)
    llm_data = load_json(args.llm_analysis)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / "index.html"
    html_text = dashboard.build_html(
        triage, binary_data, llm_data, max_groups=getattr(args, "top", None)
    )
    output_file.write_text(html_text, encoding="utf-8")
    if not getattr(args, "quiet", False):
        print(f"Wrote {output_file}")
    return 0


def cmd_summary(args):
    for path in (args.triage_json, args.binary_analysis, args.llm_analysis):
        if not Path(path).exists():
            print(f"Error: file not found: {path}")
            return 1

    data = summary.build_summary(
        args.target_binary,
        args.source_file,
        load_json(args.triage_json),
        load_json(args.binary_analysis),
        load_json(args.llm_analysis),
    )
    if args.format == "json":
        write_json(args.output, data)
        if not getattr(args, "quiet", False):
            print(f"Wrote {args.output}")
        return 0
    if args.format == "csv":
        Path(args.output).write_text(summary.render_csv(data), encoding="utf-8")
        if not getattr(args, "quiet", False):
            print(f"Wrote {args.output}")
        return 0

    print(summary.render_table(data))
    if args.fail_on_difficulty:
        hits = summary.groups_at_or_above(data, args.fail_on_difficulty)
        if hits:
            return 2
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
    if getattr(args, "json", False):
        print(json.dumps(report_data, indent=2))
        return 0
    print(doctor.format_report(report_data))
    return 0


def cmd_bench(args):
    try:
        corpus_path, corpus_kind = bench.resolve_corpus(args.corpus)
    except bench.CorpusNotFoundError as exc:
        print(f"Error: {exc}")
        return 1

    result = bench.run_bench(corpus_path, corpus_kind)
    result["corpus_path"] = args.corpus
    print(bench.render_table(result))

    if result.get("macro_metrics") is not None:
        print()
        print(bench.render_aggregation_table(result))

    if args.per_target:
        print()
        print(bench.render_per_target_table(result))

    if args.json:
        bench.write_results(args.json, result)
        print(f"\nSaved results to {args.json}")

    if getattr(args, "csv", None):
        csv_text = bench.render_per_target_csv(result)
        if csv_text:
            Path(args.csv).write_text(csv_text, encoding="utf-8")
            print(f"\nSaved per-target CSV to {args.csv}")
        else:
            print("\nNo per-target metrics to write as CSV (igor corpus only)")

    baseline = None
    if args.baseline:
        try:
            baseline = bench.load_results(args.baseline)
        except OSError as exc:
            print(f"Error: could not read baseline {args.baseline}: {exc}")
            return 1
        diff_lines = bench.diff_against_baseline(result, baseline)
        if diff_lines:
            print(f"\nDiff vs baseline ({args.baseline}):")
            for line in diff_lines:
                print(line)

    reasons = bench.check_regression(result, baseline, args.fail_purity_drop, args.fail_under_f)
    if reasons:
        print("\nRegression gate failed:")
        for reason in reasons:
            print(f"  - {reason}")
        return 1

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

    if not args.quiet:
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
        reproduction_runs=getattr(args, "reproduction_runs", DEFAULT_REPRODUCTION_RUNS),
    )
    if cmd_triage(triage_ns) != 0:
        return 1

    binscan_ns = argparse.Namespace(
        binary=args.target_binary, output=args.binary_analysis, quiet=args.quiet
    )
    if cmd_binscan(binscan_ns) != 0:
        write_json(
            args.binary_analysis,
            {"status": "skipped", "summary": "Binary analysis did not complete cleanly."},
        )

    if not args.skip_llm:
        llm_ns = argparse.Namespace(
            triage_json=args.triage_json,
            target_binary=args.target_binary,
            source_file=args.source_file if Path(args.source_file).exists() else None,
            binary_analysis=args.binary_analysis,
            output=args.llm_analysis,
            model=args.model,
            host=args.host,
            llm_timeout=getattr(args, "llm_timeout", None),
            quiet=args.quiet,
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
        format="markdown",
        quiet=args.quiet,
    )
    cmd_report(report_ns)

    dashboard_ns = argparse.Namespace(
        triage_json=args.triage_json,
        binary_analysis=args.binary_analysis,
        llm_analysis=args.llm_analysis,
        output_dir=args.dashboard_dir,
        quiet=args.quiet,
    )
    cmd_dashboard(dashboard_ns)

    if args.sarif:
        sarif_ns = argparse.Namespace(
            target_binary=args.target_binary,
            source_file=args.source_file,
            triage_json=args.triage_json,
            binary_analysis=args.binary_analysis,
            llm_analysis=args.llm_analysis,
            output=args.sarif,
            format="sarif",
            quiet=args.quiet,
        )
        cmd_report(sarif_ns)

    fail_on = getattr(args, "fail_on_difficulty", None)
    gate_hits = []
    if fail_on:
        gate_summary = summary.build_summary(
            args.target_binary,
            args.source_file,
            load_json(args.triage_json),
            load_json(args.binary_analysis),
            load_json(args.llm_analysis),
        )
        gate_hits = summary.groups_at_or_above(gate_summary, fail_on)

    if getattr(args, "summary_json", None):
        summary_ns = argparse.Namespace(
            target_binary=args.target_binary,
            source_file=args.source_file,
            triage_json=args.triage_json,
            binary_analysis=args.binary_analysis,
            llm_analysis=args.llm_analysis,
            output=args.summary_json,
            format="json",
            quiet=args.quiet,
        )
        cmd_report(summary_ns)

    if fail_on and gate_hits:
        if not args.quiet:
            print(
                f"\nSeverity gate failed: {len(gate_hits)} crash group(s) at or above "
                f"'{fail_on}' exploit difficulty:"
            )
            for group in gate_hits:
                print(f"  - {group.get('bug_class_label') or group['signature']} "
                      f"({group['difficulty']}, confidence {group['confidence']})")
        return 2

    if args.quiet:
        return 0

    print("\nDone.")
    print(f"  Triage: {args.triage_json}")
    print(f"  Binary analysis: {args.binary_analysis}")
    print(f"  LLM notes: {args.llm_analysis}")
    print(f"  Summary: {args.summary_md}")
    print(f"  Dashboard: {args.dashboard_dir}/index.html")
    if args.sarif:
        print(f"  SARIF: {args.sarif}")
    if getattr(args, "summary_json", None):
        print(f"  JSON summary: {args.summary_json}")
    return 0


def _resolve_demo_source():
    if (DEMO_DIR / "vuln.c").exists():
        return DEMO_DIR
    return PACKAGED_DEMO_DIR


def _materialize_demo_dir(source_dir):
    if os.access(source_dir, os.W_OK):
        return source_dir

    work_dir = Path(tempfile.gettempdir()) / "autofte-demo"
    work_dir.mkdir(parents=True, exist_ok=True)
    for name in DEMO_ASSET_NAMES:
        src = source_dir / name
        if src.exists() and not (work_dir / name).exists():
            shutil.copy2(src, work_dir / name)
    for sub in DEMO_ASSET_SUBDIRS:
        src_sub = source_dir / sub
        dst_sub = work_dir / sub
        if src_sub.is_dir() and not dst_sub.exists():
            shutil.copytree(src_sub, dst_sub)
    return work_dir


def _friendly_path(path):
    """Render `path` for display without leaking a full absolute installed-package
    path -- relative to the CWD when possible, else just its last two components
    (e.g. `vuln-demo/target_asan`), which is enough for a reader to recognize what
    it is without the noise of everything above it.
    """
    path = Path(path)
    try:
        return str(path.relative_to(Path.cwd()))
    except ValueError:
        pass
    parts = path.parts[-2:]
    return "/".join(parts) if len(parts) == 2 else path.name


_ABS_PATH_TOKEN_RE = re.compile(r"/[^\s:]+")


def _friendly_label(text):
    """Shorten any absolute filesystem path embedded in a crash-group label
    (e.g. from a source file's compiled-in debug path) down to just its
    filename, so the demo verdict line never leaks an installed-package or
    build-machine path -- same spirit as `_friendly_path`, applied to text
    rather than a single `Path`.
    """
    return _ABS_PATH_TOKEN_RE.sub(lambda m: Path(m.group(0)).name, text)


def _ensure_demo_targets(demo_dir, capture_build_output):
    """Build (or reuse) the demo's ASan-instrumented target, falling back to the
    plain target only if the ASan build genuinely can't be produced on this
    machine. Returns `(target_path, mode, fallback_note)` where `mode` is
    `"sanitizer"` or `"plain"`, or `(None, None, None)` if neither could be built.
    """
    asan_target = demo_dir / "target_asan"
    if not asan_target.exists():
        print(f"Building bundled demo target: make -C {_friendly_path(demo_dir)} target_asan")
        result = subprocess.run(
            ["make", "-C", str(demo_dir), "target_asan"],
            capture_output=capture_build_output,
        )
        if result.returncode != 0 or not asan_target.exists():
            asan_target = None

    if asan_target is not None:
        return asan_target, "sanitizer", None

    plain_target = demo_dir / "target"
    if not plain_target.exists():
        print(f"Building bundled demo target: make -C {_friendly_path(demo_dir)}")
        result = subprocess.run(
            ["make", "-C", str(demo_dir)],
            capture_output=capture_build_output,
        )
        if result.returncode != 0 or not plain_target.exists():
            return None, None, None

    note = (
        "Note: couldn't build the AddressSanitizer target (target_asan); falling back "
        "to the plain target, so crash grouping will be coarser (no bug class/access "
        "info)."
    )
    return plain_target, "plain", note


def _plural(n, singular, plural=None):
    return f"{n} {singular}" if n == 1 else f"{n} {plural or singular + 's'}"


def _pick_headline_group(binary_data, groups):
    """Pick the group to feature as "#1" in the demo verdict line, ranked by
    `severity.assess_crash_difficulty()` (most severe/exploitable first, i.e. the
    lowest score) rather than by raw crash count -- crash count only breaks ties.
    This is `cmd_demo`'s own presentation choice; it does not change `groups`'
    underlying count-based ordering in `triage.py`, `report.py`, or `dashboard.py`.
    """
    if not groups:
        return None, None, None

    ranked = []
    for label, group in groups.items():
        crash_record = None
        for crash in group.get("crashes", []):
            record = crash.get("sanitizer")
            if record:
                crash_record = record
                break
        assessment = severity.assess_crash_difficulty(binary_data, crash_record)
        ranked.append((assessment["score"], -group.get("count", 0), label, group, assessment))

    ranked.sort(key=lambda item: (item[0], item[1]))
    _score, _neg_count, label, group, assessment = ranked[0]
    return label, group, assessment


def cmd_demo(args):
    if args.demo_dir:
        demo_dir = Path(args.demo_dir)
    else:
        demo_dir = _materialize_demo_dir(_resolve_demo_source())
    if not demo_dir.is_dir():
        print(f"Error: bundled demo directory not found: {demo_dir}")
        return 1

    verbose = args.verbose
    target_binary, _target_mode, fallback_note = _ensure_demo_targets(
        demo_dir, capture_build_output=not verbose
    )
    if target_binary is None:
        print(f"Error: failed to build the demo target in {demo_dir}")
        return 1
    if fallback_note:
        print(fallback_note)

    crashes_dir = demo_dir / "crashes"
    if not crashes_dir.is_dir():
        print(f"Error: bundled demo crashes not found: {crashes_dir}")
        return 1

    source_file = demo_dir / "vuln.c"

    output_dir = Path(args.output_dir) if args.output_dir else Path.cwd() / "autofte-demo-output"
    output_dir.mkdir(parents=True, exist_ok=True)

    triage_json = args.triage_json or str(output_dir / "crash_triage.json")
    binary_analysis = args.binary_analysis or str(output_dir / "binary_analysis.json")
    llm_analysis = args.llm_analysis or str(output_dir / "llm_analysis.json")
    summary_md = args.summary_md or str(output_dir / "analysis_summary.md")
    dashboard_dir = args.dashboard_dir or str(output_dir / "dashboard")

    print(
        "AutoFTE demo: building and triaging the bundled vuln-demo target "
        f"({_friendly_path(target_binary)})\n"
    )

    pipeline_ns = argparse.Namespace(
        target_binary=str(target_binary),
        source_file=str(source_file),
        crashes_dir=str(crashes_dir),
        debugger="gdb",
        model=args.model,
        host=args.host,
        llm_timeout=getattr(args, "llm_timeout", None),
        skip_llm=False,
        quiet=not verbose,
        triage_json=triage_json,
        binary_analysis=binary_analysis,
        llm_analysis=llm_analysis,
        summary_md=summary_md,
        dashboard_dir=dashboard_dir,
        sarif=None,
        reproduction_runs=DEMO_REPRODUCTION_RUNS,
    )
    if cmd_pipeline(pipeline_ns) != 0:
        return 1

    triage_data = load_json(triage_json)
    binary_data = load_json(binary_analysis)

    total_crashes = triage_data.get("total_crashes", 0)
    groups = triage_data.get("groups", {})
    unique_groups = triage_data.get("unique_crash_frames", len(groups))

    label, group, assessment = _pick_headline_group(binary_data, groups)
    headline = _friendly_label(label) if label else "no crashing groups found"
    top_count = group.get("count", 0) if group else 0
    difficulty = assessment["difficulty"] if assessment else "Unknown"

    entries = group.get("crashes", []) if group else []
    repro_suffix = ""
    if entries:
        reproducible = sum(1 for c in entries if c.get("reproducibility") == "reproducible")
        repro_suffix = f" · {reproducible}/{len(entries)} reproducible"

    print(
        f"\n→ {_plural(total_crashes, 'crash', 'crashes')} · "
        f"{_plural(unique_groups, 'root cause', 'root causes')} · "
        f"#1 {headline} ({_plural(top_count, 'crash', 'crashes')}) — {difficulty}"
        f"{repro_suffix}"
    )
    print(f"\nArtifacts written to {_friendly_path(output_dir)}/")
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="autofte", description="Local crash triage and binary analysis pipeline"
    )
    parser.add_argument(
        "--version", action="version", version=f"autofte {__version__}"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_triage = subparsers.add_parser("triage", help="Group crash files by debugger frame or signal")
    p_triage.add_argument("--crashes-dir", default=pick_crash_dir())
    p_triage.add_argument("--target-binary", default="./target")
    p_triage.add_argument("--output", default="crash_triage.json")
    p_triage.add_argument("--debugger", default="gdb")
    p_triage.add_argument("--quiet", action="store_true", help="Suppress per-file progress output")
    p_triage.add_argument(
        "--reproduction-runs",
        type=int,
        default=DEFAULT_REPRODUCTION_RUNS,
        help=(
            "Times to re-run each crashing input to gauge reproducibility "
            f"(default {DEFAULT_REPRODUCTION_RUNS}); 1 disables verification for speed"
        ),
    )
    p_triage.set_defaults(func=cmd_triage)

    p_binscan = subparsers.add_parser(
        "binscan", help="Check a binary's exploit mitigations (NX, PIE, RELRO, ...)"
    )
    p_binscan.add_argument("binary")
    p_binscan.add_argument("-o", "--output", default="binary_analysis.json")
    p_binscan.set_defaults(func=cmd_binscan)

    p_llm = subparsers.add_parser("llm", help="Ask a local Ollama model for a short write-up")
    p_llm.add_argument("--triage-json", default="crash_triage.json")
    p_llm.add_argument(
        "--target-binary",
        default="./target",
        help="Target binary, disassembled around the fault to ground the write-up",
    )
    p_llm.add_argument("--source-file")
    p_llm.add_argument("--binary-analysis", default="binary_analysis.json")
    p_llm.add_argument("--output", default="llm_analysis.json")
    p_llm.add_argument("--model", help="Ollama model name (default: auto-detect)")
    p_llm.add_argument("--host", help="Ollama host (default: $OLLAMA_HOST or http://localhost:11434)")
    p_llm.add_argument(
        "--llm-timeout",
        type=float,
        help=(
            "Seconds to wait for the model to answer (default: $AUTOFTE_LLM_TIMEOUT, "
            "or no timeout -- slow/cold-loading local models are expected)"
        ),
    )
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
    p_report.add_argument(
        "--top", type=int, help="Max crash groups to include in the markdown summary"
    )
    p_report.add_argument(
        "--format",
        choices=("markdown", "sarif", "json"),
        default="markdown",
        help=(
            "Output format: a markdown summary (default), a SARIF 2.1.0 log, "
            "or a consolidated JSON summary"
        ),
    )
    p_report.set_defaults(func=cmd_report)

    p_dashboard = subparsers.add_parser("dashboard", help="Build a static HTML dashboard")
    p_dashboard.add_argument("--triage-json", default="crash_triage.json")
    p_dashboard.add_argument("--binary-analysis", default="binary_analysis.json")
    p_dashboard.add_argument("--llm-analysis", default="llm_analysis.json")
    p_dashboard.add_argument("--output-dir", default="dashboard")
    p_dashboard.add_argument(
        "--top", type=int, help="Max crash groups to show in the dashboard table"
    )
    p_dashboard.set_defaults(func=cmd_dashboard)

    p_summary = subparsers.add_parser(
        "summary", help="Print a severity-ranked table from analysis artifacts"
    )
    p_summary.add_argument("--target-binary", default="./target")
    p_summary.add_argument("--source-file", default="vuln.c")
    p_summary.add_argument("--triage-json", default="crash_triage.json")
    p_summary.add_argument("--binary-analysis", default="binary_analysis.json")
    p_summary.add_argument("--llm-analysis", default="llm_analysis.json")
    p_summary.add_argument(
        "--format",
        choices=("table", "json", "csv"),
        default="table",
        help="Output format: terminal table (default), JSON, or CSV",
    )
    p_summary.add_argument(
        "--output", default="summary.json", help="Output path for --format json/csv"
    )
    p_summary.add_argument(
        "--fail-on-difficulty",
        choices=("easy", "medium", "hard"),
        help="Exit non-zero if any crash group is at or above this exploit difficulty",
    )
    p_summary.set_defaults(func=cmd_summary)

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
    p_doctor.add_argument(
        "--json", action="store_true", help="Print the environment report as JSON"
    )
    p_doctor.set_defaults(func=cmd_doctor)

    p_bench = subparsers.add_parser(
        "bench",
        help="Score dedup bucketing against a labeled ground-truth crash corpus",
    )
    p_bench.add_argument(
        "--corpus",
        default="micro",
        help="'micro' (checked-in, default), 'igor' (fetched cache), or a path",
    )
    p_bench.add_argument(
        "--per-target",
        action="store_true",
        help="Also print a per-target metrics table (igor corpus only; V1-RELEASE.md W3)",
    )
    p_bench.add_argument("--baseline", help="Path to a bench-results.json to diff against")
    p_bench.add_argument("--json", help="Write full results to this path")
    p_bench.add_argument("--csv", help="Write the per-target metrics table to this path as CSV")
    p_bench.add_argument(
        "--fail-under-f", type=float, help="Exit non-zero if f_measure is below this value"
    )
    p_bench.add_argument(
        "--fail-purity-drop",
        type=float,
        default=2.0,
        help="With --baseline, fail if purity drops more than this many points (default 2.0)",
    )
    p_bench.set_defaults(func=cmd_bench)

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
        "--llm-timeout",
        type=float,
        help=(
            "Seconds to wait for the model to answer (default: $AUTOFTE_LLM_TIMEOUT, "
            "or no timeout -- slow/cold-loading local models are expected)"
        ),
    )
    p_pipeline.add_argument(
        "--skip-llm", action="store_true", help="Skip the LLM write-up step entirely"
    )
    p_pipeline.add_argument("--quiet", action="store_true")
    p_pipeline.add_argument(
        "--reproduction-runs",
        type=int,
        default=DEFAULT_REPRODUCTION_RUNS,
        help=(
            "Times to re-run each crashing input to gauge reproducibility "
            f"(default {DEFAULT_REPRODUCTION_RUNS}); 1 disables verification for speed"
        ),
    )
    p_pipeline.add_argument("--triage-json", default="crash_triage.json")
    p_pipeline.add_argument("--binary-analysis", default="binary_analysis.json")
    p_pipeline.add_argument("--llm-analysis", default="llm_analysis.json")
    p_pipeline.add_argument("--summary-md", default="analysis_summary.md")
    p_pipeline.add_argument("--dashboard-dir", default="dashboard")
    p_pipeline.add_argument(
        "--sarif",
        help="Also write a SARIF 2.1.0 log to this path (off by default)",
    )
    p_pipeline.add_argument(
        "--summary-json",
        help="Also write a consolidated JSON summary to this path (off by default)",
    )
    p_pipeline.add_argument(
        "--fail-on-difficulty",
        choices=("easy", "medium", "hard"),
        help="Exit non-zero if any crash group is at or above this exploit difficulty",
    )
    p_pipeline.set_defaults(func=cmd_pipeline)

    p_demo = subparsers.add_parser(
        "demo",
        help="Build and triage the bundled vuln-demo target in one command, zero setup",
    )
    p_demo.add_argument(
        "--demo-dir", help="Path to the bundled demo directory (default: examples/vuln-demo)"
    )
    p_demo.add_argument("--model", help="Ollama model name (default: auto-detect)")
    p_demo.add_argument("--host", help="Ollama host (default: $OLLAMA_HOST or http://localhost:11434)")
    p_demo.add_argument(
        "--llm-timeout",
        type=float,
        help=(
            "Seconds to wait for the model to answer (default: $AUTOFTE_LLM_TIMEOUT, "
            "or no timeout -- slow/cold-loading local models are expected)"
        ),
    )
    p_demo.add_argument(
        "--verbose",
        action="store_true",
        help="Show full pipeline output instead of the short summary",
    )
    p_demo.add_argument(
        "--output-dir",
        help="Directory to write generated artifacts into (default: ./autofte-demo-output)",
    )
    p_demo.add_argument(
        "--triage-json", help="Default: <output-dir>/crash_triage.json"
    )
    p_demo.add_argument(
        "--binary-analysis", help="Default: <output-dir>/binary_analysis.json"
    )
    p_demo.add_argument("--llm-analysis", help="Default: <output-dir>/llm_analysis.json")
    p_demo.add_argument("--summary-md", help="Default: <output-dir>/analysis_summary.md")
    p_demo.add_argument("--dashboard-dir", help="Default: <output-dir>/dashboard")
    p_demo.set_defaults(func=cmd_demo)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
