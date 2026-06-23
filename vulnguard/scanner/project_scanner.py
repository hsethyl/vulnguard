"""Project-level checks that look at the repository as a whole.

The flagship check: a `.env` file (which usually holds real secrets) that is
not covered by `.gitignore` — meaning it can be committed and leaked. This is
an everyday analogy: leaving your house key under the doormat *and* posting the
address publicly.
"""

from __future__ import annotations

import fnmatch
import os
import subprocess
from typing import Optional

from ..models import Finding, Severity

# .env-style files that typically hold real secrets.
_ENV_NAMES = {".env", ".env.local", ".env.development", ".env.production", ".env.prod"}
# Templates that are meant to be committed (no real secrets).
_ENV_TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist")

_IGNORED_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv"}


def _is_secret_env_file(name: str) -> bool:
    if name in _ENV_NAMES:
        return True
    if name.startswith(".env") and not name.endswith(_ENV_TEMPLATE_SUFFIXES):
        return True
    return False


def _collect_gitignore_patterns(root: str) -> list[str]:
    patterns: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _IGNORED_DIRS]
        if ".gitignore" in filenames:
            try:
                with open(os.path.join(dirpath, ".gitignore"), "r", encoding="utf-8", errors="ignore") as handle:
                    for raw in handle:
                        line = raw.strip()
                        if line and not line.startswith("#") and not line.startswith("!"):
                            patterns.append(line.rstrip("/"))
            except OSError:
                continue
    return patterns


def _is_ignored(rel_path: str, basename: str, patterns: list[str]) -> bool:
    rel_norm = rel_path.replace(os.sep, "/")
    for pattern in patterns:
        pat = pattern.lstrip("/")
        if fnmatch.fnmatch(basename, pat):
            return True
        if fnmatch.fnmatch(rel_norm, pat):
            return True
        if fnmatch.fnmatch(rel_norm, f"*/{pat}"):
            return True
        if fnmatch.fnmatch(rel_norm, f"{pat.rstrip('*')}*"):
            return True
    return False


def _git_tracked(file_path: str, root: str) -> Optional[bool]:
    """Return True/False if git is available, else None (unknown)."""
    try:
        result = subprocess.run(
            ["git", "ls-files", "--error-unmatch", file_path],
            cwd=root,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.returncode == 0


def scan_project(root: str) -> list[Finding]:
    """Inspect a directory tree for env-file exposure. No-op for single files."""
    if not os.path.isdir(root):
        return []

    findings: list[Finding] = []
    patterns = _collect_gitignore_patterns(root)

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _IGNORED_DIRS]
        for name in filenames:
            if not _is_secret_env_file(name):
                continue
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)

            tracked = _git_tracked(full, root)
            if tracked is True:
                findings.append(
                    Finding(
                        rule_id="PRJ002",
                        severity=Severity.CRITICAL,
                        message=f"Secret file '{rel}' is tracked by git (committed).",
                        file_path=full,
                        category="project",
                        cwe="CWE-538",
                        remediation="git rm --cached the file, add it to .gitignore, and rotate the secrets.",
                    )
                )
                continue

            if not _is_ignored(rel, name, patterns):
                findings.append(
                    Finding(
                        rule_id="PRJ001",
                        severity=Severity.HIGH,
                        message=f"Secret file '{rel}' is not covered by .gitignore.",
                        file_path=full,
                        category="project",
                        cwe="CWE-538",
                        remediation=f"Add '{name}' to .gitignore so it can't be committed.",
                    )
                )
    return findings
