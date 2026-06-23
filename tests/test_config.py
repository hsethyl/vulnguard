from vulnguard.config import Config, load_config
from vulnguard.engine import scan_path
from vulnguard.models import Finding, Severity


def _finding(rule_id="PY001", path="src/app.py"):
    return Finding(rule_id=rule_id, severity=Severity.HIGH, message="m", file_path=path)


def test_ignore_rule_filters_finding():
    cfg = Config(ignore_rules=frozenset({"PY001"}))
    assert cfg.is_ignored(_finding(rule_id="PY001")) is True
    assert cfg.is_ignored(_finding(rule_id="PY002")) is False


def test_ignore_path_glob():
    cfg = Config(ignore_paths=("*.min.js",))
    assert cfg.is_ignored(_finding(path="static/app.min.js")) is True
    assert cfg.is_ignored(_finding(path="static/app.js")) is False


def test_ignore_directory_prefix():
    cfg = Config(ignore_paths=("legacy/",))
    assert cfg.is_ignored(_finding(path="legacy/old.py")) is True
    assert cfg.is_ignored(_finding(path="src/new.py")) is False


def test_load_config_parses_toml(tmp_path):
    (tmp_path / ".vulnguard.toml").write_text(
        '[ignore]\nrules = ["PY007"]\npaths = ["vendor/"]\n[scan]\nfail_on = "high"\n',
        encoding="utf-8",
    )
    cfg = load_config(str(tmp_path))
    assert "PY007" in cfg.ignore_rules
    assert cfg.ignore_paths == ("vendor/",)
    assert cfg.fail_on == "HIGH"


def test_no_config_returns_empty(tmp_path):
    cfg = load_config(str(tmp_path))
    assert cfg.ignore_rules == frozenset()
    assert cfg.fail_on is None


def test_engine_applies_ignore_rules(tmp_path):
    (tmp_path / "app.py").write_text("x = eval(data)\n", encoding="utf-8")
    # Without config: PY001 present.
    assert any(f.rule_id == "PY001" for f in scan_path(str(tmp_path)).findings)
    # With config ignoring PY001: gone.
    (tmp_path / ".vulnguard.toml").write_text('[ignore]\nrules = ["PY001"]\n', encoding="utf-8")
    assert not any(f.rule_id == "PY001" for f in scan_path(str(tmp_path)).findings)
