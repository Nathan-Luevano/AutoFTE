FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        gdb \
        binutils \
        file \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY autofte/ ./autofte/
COPY examples/ ./examples/

RUN pip install --no-cache-dir .

ENTRYPOINT ["autofte"]
CMD ["--help"]
