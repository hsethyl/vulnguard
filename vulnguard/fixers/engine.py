"""Orchestrate fixes across files: apply line fixes, deps, backups, diffs.

Default behavior is a dry run: it computes the changes and a unified diff but
writes nothing. Writing happens only when apply=True, and always after taking
a .vulnguard.bak backup of each modified file.
"""

from __future__ import annotations

import difflib
import os
from collections import defaultdict
from dataclasses import dataclass, field

from ..models import Finding
from .dependency_fixes import apply_requirements_fixes
from .line_fixes import LINE_FIXERS


@dataclass(frozen=True)
class FileFix:
    file_path: str
    original: str
    fixed: str
    change_count: int
    diff: str


@dataclass(frozen=True)
class FixReport:
    file_fixes: tuple[FileFix, ...] = field(default_factory=tuple)
    env_example_path: str = ""
    env_vars: tuple[tuple[str, str], ...] = field(default_factory=tuple)
    applied: bool = False
    errors: tuple[str, ...] = field(default_factory=tuple)

    @property
    def total_changes(self) -> int:
        return sum(f.change_count for f in self.file_fixes)


def _ensure_os_import(text: str) -> tuple[str, bool]:
    """Add 'import os' to a Python file if it references os.environ but lacks it."""
    if "os.environ" not in text:
        return text, False
    import re

    if re.search(r"^\s*import os\b", text, re.MULTILINE):
        return text, False
    if re.search(r"^\s*import\s+os\s*,", text, re.MULTILINE):
        return text, False
    lines = text.splitlines()
    insert_at = 0
    # Skip shebang and module docstring / leading comments.
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if idx == 0 and stripped.startswith("#!"):
            insert_at = 1
            continue
        if stripped.startswith(("import ", "from ")):
            insert_at = idx
            break
        if stripped and not stripped.startswith("#"):
            insert_at = idx
            break
    lines.insert(insert_at, "import os")
    trailing = "\n" if text.endswith("\n") else ""
    return "\n".join(lines) + trailing, True


def _fix_source_file(text: str, findings: list[Finding]) -> tuple[str, int, list[tuple[str, str]]]:
    """Apply line-level fixes. Returns (new_text, changes, env_vars)."""
    lines = text.splitlines()
    env_vars: list[tuple[str, str]] = []
    changes = 0
    needs_os = False

    # Map line number -> applicable fixable findings.
    by_line: dict[int, list[Finding]] = defaultdict(list)
    for finding in findings:
        if finding.fixable and finding.rule_id in LINE_FIXERS and finding.line:
            by_line[finding.line].append(finding)

    for line_no, line_findings in by_line.items():
        idx = line_no - 1
        if not (0 <= idx < len(lines)):
            continue
        for finding in line_findings:
            fixer = LINE_FIXERS[finding.rule_id]
            result = fixer(lines[idx])
            if result is None:
                continue
            lines[idx] = result.new_line
            changes += 1
            if result.env_var:
                env_vars.append(result.env_var)
            if result.needs_os_import:
                needs_os = True

    trailing = "\n" if text.endswith("\n") else ""
    new_text = "\n".join(lines) + trailing

    if needs_os:
        new_text, added = _ensure_os_import(new_text)
        if added:
            changes += 1

    return new_text, changes, env_vars


def _diff(path: str, original: str, fixed: str) -> str:
    return "".join(
        difflib.unified_diff(
            original.splitlines(keepends=True),
            fixed.splitlines(keepends=True),
            fromfile=f"a/{path}",
            tofile=f"b/{path}",
        )
    )


def build_fixes(findings: list[Finding]) -> dict[str, tuple[str, str, int, list[tuple[str, str]]]]:
    """Compute fixes per file without touching disk.

    Returns: file_path -> (original, fixed, change_count, env_vars).
    """
    by_file: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        by_file[finding.file_path].append(finding)

    result: dict[str, tuple[str, str, int, list[tuple[str, str]]]] = {}
    for file_path, file_findings in by_file.items():
        if not any(f.fixable for f in file_findings):
            continue
        try:
            with open(file_path, "r", encoding="utf-8") as handle:
                original = handle.read()
        except (OSError, UnicodeDecodeError):
            continue

        name = os.path.basename(file_path).lower()
        if name == "requirements.txt":
            fixed, changes = apply_requirements_fixes(original, file_findings)
            env_vars: list[tuple[str, str]] = []
        else:
            fixed, changes, env_vars = _fix_source_file(original, file_findings)

        if changes > 0 and fixed != original:
            result[file_path] = (original, fixed, changes, env_vars)
    return result


def apply_fixes(findings: list[Finding], root: str, apply: bool) -> FixReport:
    """Compute (and optionally write) fixes for all fixable findings."""
    computed = build_fixes(findings)
    file_fixes: list[FileFix] = []
    all_env_vars: list[tuple[str, str]] = []
    errors: list[str] = []

    for file_path, (original, fixed, changes, env_vars) in sorted(computed.items()):
        file_fixes.append(
            FileFix(
                file_path=file_path,
                original=original,
                fixed=fixed,
                change_count=changes,
                diff=_diff(file_path, original, fixed),
            )
        )
        all_env_vars.extend(env_vars)

    # Deduplicate env vars, last value wins.
    env_map: dict[str, str] = {}
    for name, value in all_env_vars:
        env_map[name] = value

    env_example_path = ""
    if apply:
        for fix in file_fixes:
            try:
                backup = fix.file_path + ".vulnguard.bak"
                if not os.path.exists(backup):
                    with open(backup, "w", encoding="utf-8") as handle:
                        handle.write(fix.original)
                with open(fix.file_path, "w", encoding="utf-8") as handle:
                    handle.write(fix.fixed)
            except OSError as exc:
                errors.append(f"{fix.file_path}: write failed: {exc}")

        if env_map:
            base = root if os.path.isdir(root) else os.path.dirname(root) or "."
            env_example_path = os.path.join(base, ".env.example")
            try:
                existing = ""
                if os.path.exists(env_example_path):
                    with open(env_example_path, "r", encoding="utf-8") as handle:
                        existing = handle.read()
                # Write placeholders, never the real secret: .env.example is
                # meant to be committed. The original value remains in the
                # .vulnguard.bak backup and should be rotated regardless.
                additions = [
                    f"{name}=CHANGE_ME"
                    for name in env_map
                    if f"{name}=" not in existing
                ]
                if additions:
                    prefix = existing if existing.endswith("\n") or not existing else existing + "\n"
                    with open(env_example_path, "w", encoding="utf-8") as handle:
                        handle.write(prefix + "\n".join(additions) + "\n")
            except OSError as exc:
                errors.append(f"{env_example_path}: write failed: {exc}")

    return FixReport(
        file_fixes=tuple(file_fixes),
        env_example_path=env_example_path,
        env_vars=tuple(env_map.items()),
        applied=apply,
        errors=tuple(errors),
    )
