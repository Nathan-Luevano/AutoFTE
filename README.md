# AutoFTE

![AutoFTE logo](AutoFTE.jpg)

AutoFTE is a small local workflow I built while messing around with AFL++, crash triage, and basic binary analysis. It is not meant to be a polished platform. The goal is just to take a toy target from "I have crash files" to "I have a readable summary of what probably broke."

## What it does

- Runs quick crash triage and groups similar inputs together
- Checks the target for common protections like NX, PIE, RELRO, and canaries
- Optionally asks a local Ollama model for a short write-up and patch ideas
- Generates a simple markdown summary and a static HTML dashboard

## Repo layout

- `vuln.c`: intentionally vulnerable demo target
- `fuzzer.sh`: thin AFL++ wrapper for local runs
- `triage.py`: groups crash files by debugger frame or crash signal
- `binary_analyzer.py`: collects quick protection info
- `llm_analyzer.py`: optional Ollama-based notes
- `report_builder.py`: builds a short markdown summary
- `sec_dash.py`: writes a lightweight static dashboard
- `pipeline.sh`: runs the normal local workflow

## Quick start

1. Create the micromamba env:

```bash
micromamba create -f environment.yml
micromamba activate autofte
```

2. Build the sample target:

```bash
make
```

3. Make sure you have at least one crash file in `out/default/crashes/`.

4. Run the pipeline:

```bash
./pipeline.sh ./target vuln.c
```

Outputs land in the repo root:

- `crash_triage.json`
- `binary_analysis.json`
- `llm_analysis.json` if Ollama is reachable
- `analysis_summary.md`
- `dashboard/index.html`

## Notes

- AFL++, `gdb`, and the usual binutils tools still need to exist on the machine.
- If `gdb` is missing, crash grouping falls back to signal-based buckets.
- Ollama is optional. If it is not running, the rest of the pipeline still finishes.
- `mythic_integrator.py` is just an old side experiment and is not part of the normal flow anymore.
