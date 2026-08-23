# AutoFTE

AutoFTE is a local-first command-line tool for triaging fuzzer crashes. It groups crashes by likely root cause, inspects binary exploit mitigations, and generates Markdown, HTML, JSON, and SARIF reports.

## Install

AutoFTE supports Python 3.9 or newer on Linux. The recommended installation method is [pipx](https://pipx.pypa.io/):

```bash
pipx install autofte
autofte doctor
```

You can also install it with pip:

```bash
python3 -m pip install autofte
```

## Try the demo

```bash
autofte demo
```

The bundled demo builds a small intentionally vulnerable target, triages its sample crashes, and writes the results to `autofte-demo-output/`.

## Basic usage

```bash
autofte pipeline \
  --target-binary ./target \
  --source-file ./target.c \
  --crashes-dir ./crashes
```

AutoFTE uses sanitizer reports when available, falls back to GDB backtraces, and uses exit-signal grouping as a last resort. Run `autofte --help` to see all commands and options.

## Requirements and optional tools

- `readelf`, `objdump`, `nm`, `ldd`, `file`, and `strings` are required for binary analysis.
- GDB, `checksec`, and AFL++ are optional.
- Ollama is optional and is used only for local LLM-generated notes. Core triage and reporting work without it.

Crash data, binaries, and source code stay on your machine. AutoFTE makes no network calls except to an explicitly configured Ollama host.

## Links

- [Full documentation and examples](https://github.com/Nathan-Luevano/AutoFTE#readme)
- [Issue tracker](https://github.com/Nathan-Luevano/AutoFTE/issues)
- [Releases](https://github.com/Nathan-Luevano/AutoFTE/releases)
- [Security policy](https://github.com/Nathan-Luevano/AutoFTE/security/policy)

AutoFTE is licensed under the MIT License.
