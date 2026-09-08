from autofte import source_context


def _write(tmp_path, name, n_lines):
    p = tmp_path / name
    p.write_text("\n".join(f"line {i}" for i in range(1, n_lines + 1)) + "\n")
    return p


def _record(*lines, file="vuln.c"):
    return {"crash_stack": [{"func": "f", "file": file, "line": ln} for ln in lines]}


def test_returns_whole_file_when_short(tmp_path):
    p = _write(tmp_path, "vuln.c", 20)
    out = source_context.extract_context(str(p), _record(10))
    assert out.count("\n") >= 19
    assert ">>" not in out


def test_windows_around_fault_lines_for_large_file(tmp_path):
    p = _write(tmp_path, "vuln.c", 500)
    out = source_context.extract_context(str(p), _record(250), window=3)
    assert ">>   250  line 250" in out
    assert "line 247" in out and "line 253" in out
    assert "line 100" not in out
    assert "..." in out


def test_merges_adjacent_windows(tmp_path):
    p = _write(tmp_path, "vuln.c", 500)
    out = source_context.extract_context(str(p), _record(250, 254), window=3)
    body = [ln for ln in out.splitlines() if "..." not in ln][1:]
    assert len(body) == len(range(247, 258))
    assert out.count("...") == 2


def test_ignores_frames_from_other_files(tmp_path):
    p = _write(tmp_path, "vuln.c", 500)
    out = source_context.extract_context(str(p), _record(250, file="other.c"), window=3)
    assert out == p.read_text()


def test_missing_file_returns_none(tmp_path):
    assert source_context.extract_context(str(tmp_path / "nope.c"), _record(1)) is None
