"""Fix vulnerable dependencies by pinning a safe version in requirements.txt."""

from __future__ import annotations

import re
from typing import Optional

from ..models import Finding


def _fixed_version(finding: Finding) -> Optional[str]:
    """Extract the safe target version from the remediation text."""
    match = re.search(r">=\s*(\d+(?:\.\d+)*(?:[A-Za-z]\w*)?)", finding.remediation)
    return match.group(1) if match else None


def _package_name(finding: Finding) -> Optional[str]:
    """The snippet is 'package==version'."""
    match = re.match(r"([A-Za-z0-9._-]+)==", finding.snippet)
    return match.group(1) if match else None


def apply_requirements_fixes(text: str, findings: list[Finding]) -> tuple[str, int]:
    """Bump each vulnerable, fixable dependency to its safe version.

    Returns the new text and the number of lines changed.
    """
    targets: dict[str, str] = {}
    for finding in findings:
        if finding.category != "dependency" or not finding.fixable:
            continue
        package = _package_name(finding)
        fixed = _fixed_version(finding)
        if package and fixed:
            targets[package.lower()] = fixed

    if not targets:
        return text, 0

    changed = 0
    out_lines: list[str] = []
    for raw in text.splitlines():
        match = re.match(r"(\s*)([A-Za-z0-9._-]+)(\s*==\s*)([0-9][\w.]*)(.*)", raw)
        if match and match.group(2).lower() in targets:
            new_version = targets[match.group(2).lower()]
            if new_version != match.group(4):
                out_lines.append(
                    f"{match.group(1)}{match.group(2)}=={new_version}{match.group(5)}"
                )
                changed += 1
                continue
        out_lines.append(raw)

    trailing = "\n" if text.endswith("\n") else ""
    return "\n".join(out_lines) + trailing, changed
