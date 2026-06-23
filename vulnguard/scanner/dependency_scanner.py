"""Scan dependency manifests for known-vulnerable versions.

Supports requirements.txt (PyPI) and package.json (npm), matching against the
offline KNOWN_VULNERABILITIES database. Version comparison is a small,
self-contained implementation so we need no third-party packages.
"""

from __future__ import annotations

import json
import os
import re
from typing import Optional

from ..data.vuln_db import KNOWN_VULNERABILITIES
from ..models import Finding, Severity

_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def _parse_version(version: str) -> tuple[int, ...]:
    """Turn '1.2.3' into (1, 2, 3). Non-numeric pre-release suffixes are dropped."""
    parts: list[int] = []
    for chunk in version.strip().split("."):
        match = re.match(r"\d+", chunk)
        parts.append(int(match.group()) if match else 0)
    return tuple(parts)


def _compare(a: str, b: str) -> int:
    """Return -1/0/1 for version a vs b."""
    va, vb = _parse_version(a), _parse_version(b)
    length = max(len(va), len(vb))
    va += (0,) * (length - len(va))
    vb += (0,) * (length - len(vb))
    return (va > vb) - (va < vb)


def _is_vulnerable(version: str, specifier: str) -> bool:
    """Evaluate a simple specifier like '<5.4' against a concrete version."""
    match = re.match(r"\s*(<=|>=|<|>|==)\s*(.+)", specifier)
    if not match:
        return False
    op, bound = match.group(1), match.group(2).strip()
    cmp = _compare(version, bound)
    return {
        "<": cmp < 0,
        "<=": cmp <= 0,
        ">": cmp > 0,
        ">=": cmp >= 0,
        "==": cmp == 0,
    }[op]


def _clean_version(raw: str) -> Optional[str]:
    """Extract a concrete version from a manifest value.

    Returns None when the version is a range/wildcard we can't pin precisely
    (e.g. '^1.0.0', '*', '>=2,<3'), because we can't be sure it's vulnerable.
    """
    raw = raw.strip()
    # npm caret/tilde: ^1.2.3 -> 1.2.3 (lower bound is what's installed-ish)
    raw = raw.lstrip("^~")
    raw = raw.lstrip("=")
    match = re.match(r"\d+(?:\.\d+)*", raw)
    if match and match.group() == raw:
        return raw
    if match:
        return match.group()
    return None


def _advise(
    ecosystem: str,
    package: str,
    version: str,
    file_path: str,
    line: int,
) -> list[Finding]:
    findings: list[Finding] = []
    advisories = KNOWN_VULNERABILITIES.get(ecosystem, {}).get(package.lower(), [])
    for adv in advisories:
        if _is_vulnerable(version, adv["vulnerable"]):
            findings.append(
                Finding(
                    rule_id=adv["id"],
                    severity=_SEVERITY_MAP.get(adv["severity"], Severity.MEDIUM),
                    message=f"{package} {version} is vulnerable: {adv['summary']}",
                    file_path=file_path,
                    line=line,
                    snippet=f"{package}=={version}",
                    category="dependency",
                    cwe=None,
                    fixable=True,
                    remediation=f"Upgrade {package} to >= {adv['fixed']}.",
                )
            )
    return findings


def scan_requirements_txt(file_path: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        with open(file_path, "r", encoding="utf-8") as handle:
            lines = handle.readlines()
    except OSError:
        return findings

    for line_no, raw in enumerate(lines, start=1):
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        match = re.match(r"([A-Za-z0-9._-]+)\s*==\s*([0-9][\w.]*)", line)
        if not match:
            continue
        package, version = match.group(1), match.group(2)
        findings.extend(_advise("pypi", package, version, file_path, line_no))
    return findings


def scan_package_json(file_path: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        with open(file_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return findings

    for section in ("dependencies", "devDependencies"):
        for package, raw_version in (data.get(section) or {}).items():
            version = _clean_version(str(raw_version))
            if version is None:
                continue
            findings.extend(_advise("npm", package, version, file_path, 0))
    return findings


def scan_dependency_file(file_path: str) -> list[Finding]:
    name = os.path.basename(file_path).lower()
    if name == "requirements.txt":
        return scan_requirements_txt(file_path)
    if name == "package.json":
        return scan_package_json(file_path)
    return []


def extract_dependencies(file_path: str) -> list[dict]:
    """Return concrete dependencies as dicts: ecosystem, name, version, line.

    Shared by the offline scanner and the OSV.dev client so both see the same
    set of packages. Only pinned versions are returned.
    """
    name = os.path.basename(file_path).lower()
    deps: list[dict] = []

    if name == "requirements.txt":
        try:
            with open(file_path, "r", encoding="utf-8") as handle:
                lines = handle.readlines()
        except OSError:
            return deps
        for line_no, raw in enumerate(lines, start=1):
            line = raw.split("#", 1)[0].strip()
            match = re.match(r"([A-Za-z0-9._-]+)\s*==\s*([0-9][\w.]*)", line)
            if match:
                deps.append(
                    {"ecosystem": "PyPI", "name": match.group(1),
                     "version": match.group(2), "line": line_no}
                )

    elif name == "package.json":
        try:
            with open(file_path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError):
            return deps
        for section in ("dependencies", "devDependencies"):
            for pkg, raw_version in (data.get(section) or {}).items():
                version = _clean_version(str(raw_version))
                if version is not None:
                    deps.append(
                        {"ecosystem": "npm", "name": pkg, "version": version, "line": 0}
                    )

    return deps
