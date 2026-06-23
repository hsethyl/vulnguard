"""Optional project configuration via `.vulnguard.toml`.

Example:

    [ignore]
    rules = ["PY007", "DAST003"]      # rule ids to suppress
    paths = ["legacy/", "*.min.js"]   # files/dirs to skip (glob)

    [scan]
    fail_on = "HIGH"                  # default --fail-on threshold

Configuration is optional; with no file present, nothing is filtered.
"""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from typing import Optional

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - older interpreters
    tomllib = None  # type: ignore

from .models import Finding

CONFIG_NAME = ".vulnguard.toml"


@dataclass(frozen=True)
class Config:
    ignore_rules: frozenset[str] = field(default_factory=frozenset)
    ignore_paths: tuple[str, ...] = ()
    fail_on: Optional[str] = None
    source: Optional[str] = None  # path of the loaded config, for diagnostics

    def is_ignored(self, finding: Finding) -> bool:
        if finding.rule_id in self.ignore_rules:
            return True
        return _path_matches(finding.file_path, self.ignore_paths)

    def filter(self, findings: tuple[Finding, ...]) -> tuple[Finding, ...]:
        return tuple(f for f in findings if not self.is_ignored(f))


def _path_matches(path: str, patterns: tuple[str, ...]) -> bool:
    if not patterns:
        return False
    norm = path.replace(os.sep, "/")
    base = norm.rsplit("/", 1)[-1]
    for raw in patterns:
        pat = raw.replace(os.sep, "/")
        if pat.endswith("/"):  # directory prefix
            stem = pat.rstrip("/")
            if norm == stem or norm.startswith(stem + "/") or ("/" + stem + "/") in ("/" + norm):
                return True
            continue
        if fnmatch.fnmatch(norm, pat) or fnmatch.fnmatch(base, pat):
            return True
        if fnmatch.fnmatch(norm, "*/" + pat):
            return True
    return False


def _candidate_dirs(start_path: str) -> list[str]:
    base = start_path if os.path.isdir(start_path) else os.path.dirname(start_path)
    dirs = []
    if base:
        dirs.append(base)
    cwd = os.getcwd()
    if cwd not in dirs:
        dirs.append(cwd)
    return dirs


def load_config(start_path: str) -> Config:
    """Find and parse .vulnguard.toml near start_path (then cwd). Best-effort."""
    if tomllib is None:
        return Config()

    for directory in _candidate_dirs(start_path):
        candidate = os.path.join(directory, CONFIG_NAME)
        if not os.path.isfile(candidate):
            continue
        try:
            with open(candidate, "rb") as handle:
                data = tomllib.load(handle)
        except (OSError, ValueError):
            return Config()

        ignore = data.get("ignore") or {}
        scan = data.get("scan") or {}
        rules = ignore.get("rules") or []
        paths = ignore.get("paths") or []
        fail_on = scan.get("fail_on")
        return Config(
            ignore_rules=frozenset(str(r) for r in rules),
            ignore_paths=tuple(str(p) for p in paths),
            fail_on=str(fail_on).upper() if fail_on else None,
            source=candidate,
        )
    return Config()
