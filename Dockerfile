# --- builder: build a wheel, keep build tooling out of the final image ---
FROM python:3.14-slim AS builder

WORKDIR /src

COPY pyproject.toml README.md LICENSE ./
COPY autofte/ ./autofte/

RUN pip install --no-cache-dir build \
    && python -m build --wheel --outdir /wheels

# --- runtime: only what autofte needs to run and to build the demo target ---
FROM python:3.14-slim

# gdb/binutils/file back the binary-analysis and triage pipeline; build-essential
# provides the gcc/make `autofte demo` needs to compile the bundled vuln-demo target.
RUN apt-get update && apt-get install -y --no-install-recommends \
        gdb \
        binutils \
        file \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 1000 autofte
WORKDIR /home/autofte

COPY --from=builder /wheels/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -rf /tmp/*.whl

USER autofte

ENTRYPOINT ["autofte"]
CMD ["--help"]
