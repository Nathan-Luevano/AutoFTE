from autofte.paths import DEFAULT_CRASH_DIRS, pick_crash_dir


def test_pick_crash_dir_returns_first_existing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "out" / "crashes").mkdir(parents=True)
    (tmp_path / "crashes").mkdir()

    # "out/default/crashes" doesn't exist, "out/crashes" does -> should win
    result = pick_crash_dir(("out/default/crashes", "out/crashes", "crashes"))
    assert result == "out/crashes"


def test_pick_crash_dir_falls_back_to_first_candidate(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = pick_crash_dir(("nope/one", "nope/two"))
    assert result == "nope/one"


def test_pick_crash_dir_default_candidates_used(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = pick_crash_dir()
    assert result == DEFAULT_CRASH_DIRS[0]


def test_pick_crash_dir_prefers_earliest_match(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    assert pick_crash_dir(("a", "b")) == "a"
