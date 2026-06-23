from vulnguard.engine import scan_paths


def test_scan_multiple_files(tmp_path):
    a = tmp_path / "a.py"
    b = tmp_path / "b.py"
    a.write_text("x = eval(data)\n", encoding="utf-8")
    b.write_text("import os\nos.system(cmd)\n", encoding="utf-8")

    result = scan_paths([str(a), str(b)])
    ids = {f.rule_id for f in result.findings}
    assert "PY001" in ids  # from a.py
    assert "PY003" in ids  # from b.py
    assert result.scanned_files == 2


def test_overlapping_paths_deduplicated(tmp_path):
    a = tmp_path / "a.py"
    a.write_text("x = eval(data)\n", encoding="utf-8")

    # Same file passed twice and via its directory.
    result = scan_paths([str(a), str(a), str(tmp_path)])
    py001 = [f for f in result.findings if f.rule_id == "PY001"]
    assert len(py001) == 1  # collapsed, not tripled


def test_missing_path_records_error_without_crashing(tmp_path):
    good = tmp_path / "ok.py"
    good.write_text("x = 1\n", encoding="utf-8")
    result = scan_paths([str(good), str(tmp_path / "nope.py")])
    assert any("not found" in e.lower() for e in result.errors)
