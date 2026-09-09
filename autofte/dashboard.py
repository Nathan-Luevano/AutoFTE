"""Static HTML dashboard built from triage / binary / LLM artifacts.

Per ROADMAP 2.5 / PLAN.md's JTBD #1 ("1,166 crashes -> 3 real bugs, ranked
and explained"), the crash-groups table is the scannable ranked list: each
row now shows the group's bug class (when a sanitizer record is attached to
one of its crashes) alongside the raw signature, its crash count, and the
crash-aware difficulty from `severity.py` with its confidence -- the
rationale is tucked into a native `<details>` disclosure (no JS needed) so
the table stays scannable while the reasoning is one click away. Severity is
recomputed here directly from `triage`/`binary_data`, the same way
`report.py` does it, rather than threaded through a new artifact.
"""

import html

from . import crash_display

MAX_GROUPS_SHOWN = 8


def _render_list(items):
    if not items:
        return "<p>None.</p>"
    rows = "".join(f"<li>{html.escape(str(item))}</li>" for item in items)
    return f"<ul>{rows}</ul>"


def _group_row(rank, frame, data, assessment):
    sample = data.get("crashes", [{}])[0]
    crash_record = crash_display.representative_crash_record(data)
    label = crash_display.bug_class_label(crash_record)

    if label and label != frame:
        signature_html = (
            f"<strong>{html.escape(label)}</strong>"
            f"<br><span class=\"muted\">{html.escape(frame)}</span>"
        )
    else:
        signature_html = f"<strong>{html.escape(frame)}</strong>"

    primitives = (data.get("crash_state") or {}).get("primitives") or []
    if primitives:
        joined = html.escape(", ".join(primitives))
        signature_html += f'<br><span class="primitive">{joined}</span>'

    crashes = data.get("crashes", [])
    count_html = str(data.get("count", 0))
    if crashes and any("reproducibility" in c for c in crashes):
        reproducible = sum(1 for c in crashes if c.get("reproducibility") == "reproducible")
        count_html += (
            f"<br><span class=\"muted\">{reproducible}/{len(crashes)} reproducible</span>"
        )

    confidence_pct = round(assessment["confidence"] * 100)
    difficulty_html = (
        f"{html.escape(assessment['difficulty'])} "
        f"<span class=\"muted\">({confidence_pct}% confidence)</span>"
        "<details><summary>why</summary>"
        f"<p>{html.escape(assessment['rationale'])}</p>"
        "</details>"
    )

    return (
        "<tr>"
        f"<td>{rank}</td>"
        f"<td>{signature_html}</td>"
        f"<td>{count_html}</td>"
        f"<td>{difficulty_html}</td>"
        f"<td>{html.escape(str(sample.get('file', 'n/a')))}</td>"
        "</tr>"
    )


def build_html(triage, binary_data, llm_data, max_groups=None):
    if max_groups is None:
        max_groups = MAX_GROUPS_SHOWN
    groups = triage.get("groups", {})
    ranked = crash_display.ranked_groups(groups, binary_data)[:max_groups]
    group_rows = [
        _group_row(rank, item["signature"], item["data"], item["assessment"])
        for rank, item in enumerate(ranked, start=1)
    ]

    def _flag(key):
        return "enabled" if binary_data.get(key, {}).get("enabled") else "disabled"

    summary = binary_data.get("exploit_mitigation_summary", {})
    summary_html = _render_list(
        [
            f"Protection level: {summary.get('protection_level', 'Unknown')}",
            f"Exploit difficulty: {summary.get('exploit_difficulty', 'Unknown')}",
            f"ASLR: {_flag('aslr_system')}",
            f"NX: {_flag('nx_bit')}",
            f"PIE: {_flag('pie')}",
            f"Canaries: {_flag('stack_canaries')}",
            f"RELRO: {binary_data.get('relro', {}).get('status', 'Unknown')}",
        ]
        if binary_data
        else []
    )

    notes_html = _render_list(llm_data.get("next_checks", []))
    fixes_html = _render_list(llm_data.get("fix_ideas", []))
    confirm_html = _render_list(llm_data.get("what_would_confirm", []))
    llm_summary = html.escape(llm_data.get("summary", "No LLM note for this run."))

    narrative_bits = []
    if llm_data.get("likely_bug_type"):
        narrative_bits.append(f"Likely bug type: {llm_data['likely_bug_type']}")
    if llm_data.get("confidence") is not None:
        narrative_bits.append(f"Confidence: {llm_data['confidence']}")
    if llm_data.get("root_cause"):
        narrative_bits.append(f"Root cause: {llm_data['root_cause']}")
    narrative_html = _render_list(narrative_bits)

    disassembly = llm_data.get("disassembly_context")
    disassembly_html = ""
    if disassembly:
        disassembly_html = (
            '<section class="section card">'
            "<h2>Faulting instruction context</h2>"
            f"<pre>{html.escape(disassembly)}</pre>"
            "</section>"
        )

    group_rows_html = "".join(group_rows) if group_rows else (
        '<tr><td colspan="5">No crash data found.</td></tr>'
    )

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
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: Georgia, "Times New Roman", serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top left, #efe1d2 0, transparent 30%),
        linear-gradient(180deg, #f8f4ed 0, var(--bg) 100%);
    }}
    .wrap {{ max-width: 980px; margin: 0 auto; padding: 32px 18px 56px; }}
    .hero {{
      background: var(--paper);
      border: 1px solid var(--line);
      border-radius: 18px;
      padding: 28px;
      box-shadow: 0 20px 60px rgba(55, 38, 24, 0.08);
    }}
    h1, h2 {{ margin: 0 0 12px; font-weight: 600; }}
    p {{ margin: 0 0 12px; line-height: 1.55; }}
    .muted {{ color: var(--muted); font-size: 0.9em; }}
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
    .metric {{ font-size: 2rem; color: var(--accent); margin-bottom: 4px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 0.95rem; }}
    th, td {{
      border-bottom: 1px solid var(--line);
      padding: 10px 8px;
      text-align: left;
      vertical-align: top;
    }}
    th {{ background: var(--accent-soft); font-weight: 600; }}
    ul {{ margin: 10px 0 0; padding-left: 18px; }}
    .primitive {{
      display: inline-block;
      margin-top: 4px;
      padding: 1px 7px;
      border-radius: 6px;
      background: #7b2a2a;
      color: #fff;
      font-size: 0.78rem;
    }}
    pre {{
      background: #f3ede2;
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 14px;
      overflow-x: auto;
      font-size: 0.85rem;
      line-height: 1.45;
    }}
    .section {{ margin-top: 20px; }}
    details {{ margin-top: 4px; }}
    details summary {{
      cursor: pointer;
      color: var(--accent);
      font-size: 0.85em;
    }}
    details p {{ margin: 6px 0 0; font-size: 0.9em; color: var(--muted); }}
    @media (max-width: 640px) {{
      .wrap {{ padding: 18px 14px 40px; }}
      .hero, .card {{ padding: 18px; }}
      .metric {{ font-size: 1.6rem; }}
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
      <p class="muted">
        Ranked by crash-aware exploit difficulty (most severe first), with crash
        count breaking ties. Groups are collapsed via major/minor stack-hash dedup.
        Bug class and difficulty come from the crash-aware severity assessment for a
        representative crash in each group; click "why" for the reasoning behind it.
      </p>
      <table>
        <thead>
          <tr><th>#</th><th>Bug class / signature</th><th>Count</th>
              <th>Difficulty</th><th>Sample</th></tr>
        </thead>
        <tbody>
          {group_rows_html}
        </tbody>
      </table>
    </section>

    <section class="grid section">
      <div class="card">
        <h2>Binary notes</h2>
        {summary_html}
      </div>
      <div class="card">
        <h2>LLM narrative</h2>
        <p>{llm_summary}</p>
        {narrative_html}
        <h2 class="section">What would confirm this</h2>
        {confirm_html}
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

    {disassembly_html}
  </div>
</body>
</html>
"""
