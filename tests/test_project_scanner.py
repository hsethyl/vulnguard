import shutil
import subprocess

import pytest

from vulnguard.scanner.project_scanner import scan_project


def _ids(root) -> set[str]:
    return {f.rule_id for f in scan_project(str(root))}


def test_env_without_gitignore_flagged(tmp_path):
    (tmp_path / ".env").write_text("SECRET=abc123\n", encoding="utf-8")
    assert "PRJ001" in _ids(tmp_path)


def test_env_ignored_not_flagged(tmp_path):
    (tmp_path / ".env").write_text("SECRET=abc123\n", encoding="utf-8")
    (tmp_path / ".gitignore").write_text(".env\n", encoding="utf-8")
    assert "PRJ001" not in _ids(tmp_path)


def test_env_wildcard_ignored_not_flagged(tmp_path):
    (tmp_path / ".env").write_text("SECRET=abc123\n", encoding="utf-8")
    (tmp_path / ".gitignore").write_text("*.env\n.env*\n", encoding="utf-8")
    assert "PRJ001" not in _ids(tmp_path)


def test_env_example_template_not_flagged(tmp_path):
    (tmp_path / ".env.example").write_text("SECRET=CHANGE_ME\n", encoding="utf-8")
    assert _ids(tmp_path) == set()


@pytest.mark.skipif(shutil.which("git") is None, reason="git not available")
def test_tracked_env_flagged_as_committed(tmp_path):
    subprocess.run(["git", "init"], cwd=tmp_path, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    (tmp_path / ".env").write_text("SECRET=abc123\n", encoding="utf-8")
    subprocess.run(["git", "add", ".env"], cwd=tmp_path, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    assert "PRJ002" in _ids(tmp_path)
