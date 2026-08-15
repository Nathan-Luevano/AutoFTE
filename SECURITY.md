# Security Policy

AutoFTE is a local-first crash-triage tool: it runs entirely on your machine, makes no network calls except to a local (or explicitly configured) Ollama host, and never sends crash data, source, or binaries anywhere else. That said, it does parse untrusted input (crash files, sanitizer reports, target binaries) and shells out to system tools, so it has a real attack surface.

## Reporting a vulnerability

Please **do not open a public issue** for security reports. Instead, use GitHub's private vulnerability reporting:

1. Go to the [Security tab](https://github.com/Nathan-Luevano/AutoFTE/security) of this repository.
2. Click **"Report a vulnerability"** to open a private advisory.

Include, where possible:

- A description of the issue and its potential impact
- Steps to reproduce (a minimal crash file / binary / command line is ideal)
- The AutoFTE version or commit you tested against

You should get an initial response within a few days. There's no bug bounty — this is a small open-source project — but you'll be credited in the advisory unless you'd prefer otherwise.

## Supported versions

AutoFTE is pre-1.0 (alpha). Only the latest commit on `main` (or the latest tagged release, once one exists) is supported — please make sure you can reproduce the issue there before reporting.

## Scope

In scope:

- AutoFTE's own code (parsing, dedup logic, report/SARIF/dashboard generation, the CLI)
- The bundled `examples/vuln-demo` build/packaging (not the intentional bugs inside `vuln.c` itself — those are the point)
- The `Dockerfile` and `action.yml`

Out of scope:

- Vulnerabilities in third-party tools AutoFTE shells out to (`gdb`, `readelf`, AFL++, etc.) — please report those upstream
- Vulnerabilities in a local Ollama install itself — please report those to the [Ollama project](https://github.com/ollama/ollama)
