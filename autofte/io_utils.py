"""Small JSON read/write helpers shared by the CLI subcommands."""

import json
from pathlib import Path


def load_json(path):
    file_path = Path(path)
    if not file_path.exists():
        return {}
    with file_path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path, data):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
