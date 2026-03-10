import argparse
import html
import json
from pathlib import Path


def load_json(path):
    file_path = Path(path)
    if not file_path.exists():
        return {}

    with file_path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def render_list(items):
    if not items:
        return "<p>None.</p>"
    rows = "".join(f"<li>{html.escape(str(item))}</li>" for item in items)
    return f"<ul>{rows}</ul>"


def build_html(triage, binary_data, llm_data):
    groups = triage.get("groups", {})
    group_rows = []
    for frame, data in list(groups.items())[:8]:
        sample = data.get("crashes", [{}])[0]
        group_rows.append(
            "<tr>"
            f"<td>{html.escape(frame)}</td>"
            f"<td>{data.get('count', 0)}</td>"
            f"<td>{html.escape(sample.get('file', 'n/a'))}</td>"
            f"<td>{sample.get('size', 'n/a')}</td>"
            "</tr>"
        )

    summary = binary_data.get("exploit_mitigation_summary", {})
    summary_html = render_list(
        [
            f"Protection level: {summary.get('protection_level', 'Unknown')}",
            f"Exploit difficulty: {summary.get('exploit_difficulty', 'Unknown')}",
            f"ASLR: {'enabled' if binary_data.get('aslr_system', {}).get('enabled') else 'disabled'}",
            f"NX: {'enabled' if binary_data.get('nx_bit', {}).get('enabled') else 'disabled'}",
            f"PIE: {'enabled' if binary_data.get('pie', {}).get('enabled') else 'disabled'}",
            f"Canaries: {'enabled' if binary_data.get('stack_canaries', {}).get('enabled') else 'disabled'}",
            f"RELRO: {binary_data.get('relro', {}).get('status', 'Unknown')}",
        ]
        if binary_data
        else []
    )

    notes_html = render_list(llm_data.get("next_checks", []))
    fixes_html = render_list(llm_data.get("fix_ideas", []))
    llm_summary = html.escape(llm_data.get("summary", "No LLM note for this run."))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AutoFTE dashboard</title>
  <style>
    :root {{
      --bg: #f4f1ea;
      --paper: #fffdf8;
      --ink: #1b1f23;
      --muted: #5f6368;
      --line: #d8d2c6;
      --accent: #7b4b2a;
      --accent-soft: #efe4d7;
    }}
    * {{
      box-sizing: border-box;
    }}
    body {{
      margin: 0;
      font-family: Georgia, "Times New Roman", serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top left, #efe1d2 0, transparent 30%),
        linear-gradient(180deg, #f8f4ed 0, var(--bg) 100%);
    }}
    .wrap {{
      max-width: 980px;
      margin: 0 auto;
      padding: 32px 18px 56px;
    }}
    .hero {{
      background: var(--paper);
      border: 1px solid var(--line);
      border-radius: 18px;
      padding: 28px;
      box-shadow: 0 20px 60px rgba(55, 38, 24, 0.08);
    }}
    h1, h2 {{
      margin: 0 0 12px;
      font-weight: 600;
    }}
    p {{
      margin: 0 0 12px;
      line-height: 1.55;
    }}
    .muted {{
      color: var(--muted);
    }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px;
      margin-top: 18px;
    }}
    .card {{
      background: var(--paper);
      border: 1px solid var(--line);
      border-radius: 16px;
      padding: 20px;
    }}
    .metric {{
      font-size: 2rem;
      color: var(--accent);
      margin-bottom: 4px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin-top: 12px;
      font-size: 0.95rem;
    }}
    th, td {{
      border-bottom: 1px solid var(--line);
      padding: 10px 8px;
      text-align: left;
      vertical-align: top;
    }}
    th {{
      background: var(--accent-soft);
      font-weight: 600;
    }}
    ul {{
      margin: 10px 0 0;
      padding-left: 18px;
    }}
    .section {{
      margin-top: 20px;
    }}
    @media (max-width: 640px) {{
      .wrap {{
        padding: 18px 14px 40px;
      }}
      .hero, .card {{
        padding: 18px;
      }}
      .metric {{
        font-size: 1.6rem;
      }}
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <section class="hero">
      <h1>AutoFTE dashboard</h1>
      <p class="muted">A quick local summary of the most recent run.</p>
      <div class="grid">
        <div class="card">
          <div class="metric">{triage.get('total_crashes', 0)}</div>
          <p>Crash files</p>
        </div>
        <div class="card">
          <div class="metric">{triage.get('unique_crash_frames', 0)}</div>
          <p>Crash groups</p>
        </div>
        <div class="card">
          <div class="metric">{html.escape(str(summary.get('protection_level', 'Unknown')))}</div>
          <p>Protection level</p>
        </div>
        <div class="card">
          <div class="metric">{html.escape(str(llm_data.get('likely_bug_type', 'n/a')))}</div>
          <p>Likely bug type</p>
        </div>
      </div>
    </section>

    <section class="section card">
      <h2>Crash groups</h2>
      <p class="muted">Top buckets from the triage output.</p>
      <table>
        <thead>
          <tr>
            <th>Signature</th>
            <th>Count</th>
            <th>Sample</th>
            <th>Size</th>
          </tr>
        </thead>
        <tbody>
          {''.join(group_rows) if group_rows else '<tr><td colspan="4">No crash data found.</td></tr>'}
        </tbody>
      </table>
    </section>

    <section class="grid section">
      <div class="card">
        <h2>Binary notes</h2>
        {summary_html}
      </div>
      <div class="card">
        <h2>LLM summary</h2>
        <p>{llm_summary}</p>
      </div>
    </section>

    <section class="grid section">
      <div class="card">
        <h2>Next checks</h2>
        {notes_html}
      </div>
      <div class="card">
        <h2>Fix ideas</h2>
        {fixes_html}
      </div>
    </section>
  </div>
</body>
</html>
"""


def main():
    parser = argparse.ArgumentParser(description="Build a static HTML dashboard")
    parser.add_argument("--triage-json", default="crash_triage.json")
    parser.add_argument("--binary-analysis", default="binary_analysis.json")
    parser.add_argument("--llm-analysis", default="llm_analysis.json")
    parser.add_argument("--output-dir", default="dashboard")
    args = parser.parse_args()

    triage = load_json(args.triage_json)
    binary_data = load_json(args.binary_analysis)
    llm_data = load_json(args.llm_analysis)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / "index.html"
    output_file.write_text(build_html(triage, binary_data, llm_data), encoding="utf-8")

    print(f"Wrote {output_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
