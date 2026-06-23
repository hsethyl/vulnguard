from vulnguard.engine import scan_path
from vulnguard.fixers.dependency_fixes import apply_requirements_fixes
from vulnguard.fixers.engine import apply_fixes, build_fixes
from vulnguard.fixers.line_fixes import fix_hardcoded_secret, fix_yaml_load


def test_fix_yaml_load_line():
    result = fix_yaml_load("data = yaml.load(stream)")
    assert result is not None
    assert "yaml.safe_load(" in result.new_line


def test_fix_yaml_load_with_loader_skipped():
    assert fix_yaml_load("yaml.load(s, Loader=yaml.Loader)") is None


def test_fix_hardcoded_secret_line():
    result = fix_hardcoded_secret('api_key = "G7kq9Lm2Zxabc"')
    assert result is not None
    assert 'os.environ["API_KEY"]' in result.new_line
    assert result.env_var == ("API_KEY", "G7kq9Lm2Zxabc")
    assert result.needs_os_import is True


def test_dependency_fix_bumps_version():
    text = "PyYAML==5.3.1\nrequests==2.31.0\n"
    from vulnguard.scanner.dependency_scanner import scan_requirements_txt
    # build findings by scanning a temp-like text is awkward; emulate directly:
    import tempfile, os
    fd, path = tempfile.mkstemp(suffix="requirements.txt")
    os.close(fd)
    with open(path, "w", encoding="utf-8") as h:
        h.write(text)
    findings = scan_requirements_txt(path)
    new_text, changed = apply_requirements_fixes(text, findings)
    os.remove(path)
    assert changed == 1
    assert "PyYAML==5.4" in new_text


def test_end_to_end_dry_run_then_apply(tmp_path):
    target = tmp_path / "app.py"
    target.write_text(
        'import yaml\n'
        'password = "S3cr3t!Pa55phrase"\n'
        'cfg = yaml.load(open("c.yml"))\n',
        encoding="utf-8",
    )
    result = scan_path(str(tmp_path))
    findings = list(result.findings)

    # Dry run computes changes but writes nothing.
    computed = build_fixes(findings)
    assert str(target) in computed

    original = target.read_text(encoding="utf-8")
    report_dry = apply_fixes(findings, str(tmp_path), apply=False)
    assert report_dry.total_changes >= 2
    assert target.read_text(encoding="utf-8") == original  # untouched

    # Apply writes the fixes and a backup.
    report = apply_fixes(findings, str(tmp_path), apply=True)
    assert report.applied is True
    new_text = target.read_text(encoding="utf-8")
    assert "yaml.safe_load(" in new_text
    assert 'os.environ["PASSWORD"]' in new_text
    assert "import os" in new_text
    assert (tmp_path / "app.py.vulnguard.bak").exists()
    assert (tmp_path / ".env.example").exists()
