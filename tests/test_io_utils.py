import json

from autofte.io_utils import load_json, write_json


def test_load_json_missing_file_returns_empty_dict(tmp_path):
    assert load_json(tmp_path / "does-not-exist.json") == {}


def test_write_json_then_load_json_round_trips(tmp_path):
    path = tmp_path / "data.json"
    data = {"crashes": 3, "groups": ["a", "b"]}

    write_json(path, data)

    assert load_json(path) == data


def test_write_json_accepts_str_path(tmp_path):
    path = str(tmp_path / "data.json")

    write_json(path, {"ok": True})

    assert load_json(path) == {"ok": True}


def test_write_json_is_indented_and_human_readable(tmp_path):
    path = tmp_path / "data.json"

    write_json(path, {"a": 1})

    assert path.read_text(encoding="utf-8") == json.dumps({"a": 1}, indent=2)
