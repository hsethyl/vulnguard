from vulnguard.scanner.dependency_scanner import (
    _compare,
    _is_vulnerable,
    scan_package_json,
    scan_requirements_txt,
)


def test_version_compare():
    assert _compare("1.2.3", "1.2.4") == -1
    assert _compare("2.0.0", "1.9.9") == 1
    assert _compare("1.0", "1.0.0") == 0


def test_is_vulnerable_specifier():
    assert _is_vulnerable("5.3", "<5.4") is True
    assert _is_vulnerable("5.4", "<5.4") is False


def test_requirements_detects_vulnerable_pyyaml(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("PyYAML==5.3.1\nrequests==2.31.0\n", encoding="utf-8")
    ids = {f.rule_id for f in scan_requirements_txt(str(req))}
    assert "CVE-2020-14343" in ids  # vulnerable pyyaml
    assert "CVE-2023-32681" not in ids  # requests 2.31.0 is safe


def test_requirements_safe_version_not_flagged(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("PyYAML==6.0.1\n", encoding="utf-8")
    assert scan_requirements_txt(str(req)) == []


def test_package_json_detects_vulnerable_lodash(tmp_path):
    pkg = tmp_path / "package.json"
    pkg.write_text('{"dependencies": {"lodash": "4.17.20"}}', encoding="utf-8")
    ids = {f.rule_id for f in scan_package_json(str(pkg))}
    assert "CVE-2021-23337" in ids
