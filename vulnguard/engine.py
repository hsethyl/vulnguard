"""Scan orchestration: walk a path and dispatch each file to the right scanners."""

from __future__ import annotations

import os
from typing import Callable

from .config import load_config
from .models import Finding, ScanResult
from .scanner.dependency_scanner import extract_dependencies, scan_dependency_file
from .scanner.go_scanner import scan_go_file
from .scanner.java_scanner import scan_java_file
from .scanner.osv_client import OSVError, query_osv
from .scanner.js_scanner import scan_js_file
from .scanner.project_scanner import scan_project
from .scanner.python_scanner import scan_python_file
from .scanner.secret_scanner import scan_secrets_in_file

# Directories we never descend into.
_IGNORED_DIRS = {
    ".git", "__pycache__", "node_modules", ".venv", "venv", "env",
    ".mypy_cache", ".pytest_cache", "dist", "build", ".idea", ".vscode",
}

_PYTHON_EXT = {".py", ".pyw"}
_JS_EXT = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
_GO_EXT = {".go"}
_JAVA_EXT = {".java"}
_DEP_FILES = {"requirements.txt", "package.json"}
# Files we run secret detection on (text-ish files).
_SECRET_EXT = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".json", ".yml", ".yaml", ".env",
    ".ini", ".cfg", ".toml", ".txt", ".sh", ".rb", ".go", ".java", ".php",
    ".properties", ".xml", ".conf",
}

# Skip files larger than this many bytes to stay fast.
_MAX_FILE_BYTES = 2_000_000


def _scanners_for(file_path: str) -> list[Callable[[str], list[Finding]]]:
    name = os.path.basename(file_path).lower()
    _, ext = os.path.splitext(name)
    scanners: list[Callable[[str], list[Finding]]] = []

    if ext in _PYTHON_EXT:
        scanners.append(scan_python_file)
    if ext in _JS_EXT:
        scanners.append(scan_js_file)
    if ext in _GO_EXT:
        scanners.append(scan_go_file)
    if ext in _JAVA_EXT:
        scanners.append(scan_java_file)
    if name in _DEP_FILES:
        scanners.append(scan_dependency_file)
    if ext in _SECRET_EXT or name in _DEP_FILES:
        scanners.append(scan_secrets_in_file)
    return scanners


def _iter_files(root: str) -> list[str]:
    if os.path.isfile(root):
        return [root]
    collected: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _IGNORED_DIRS]
        for filename in filenames:
            collected.append(os.path.join(dirpath, filename))
    return collected


def scan_path(root: str, osv: bool = False) -> ScanResult:
    """Scan a file or directory tree. Never raises on per-file errors.

    When osv=True, dependencies are additionally checked against OSV.dev
    (requires network); failures are recorded as errors, not exceptions.
    """
    if not os.path.exists(root):
        return ScanResult(errors=(f"Path not found: {root}",))

    findings: list[Finding] = []
    errors: list[str] = []
    scanned = 0
    dep_files: list[str] = []

    # Project-level checks (e.g. .env exposure) run once over the tree.
    try:
        findings.extend(scan_project(root))
    except Exception as exc:  # defensive: never abort a scan on a project check
        errors.append(f"project scan failed: {exc}")

    for file_path in _iter_files(root):
        scanners = _scanners_for(file_path)
        if not scanners:
            continue
        try:
            if os.path.getsize(file_path) > _MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        scanned += 1
        if os.path.basename(file_path).lower() in _DEP_FILES:
            dep_files.append(file_path)
        for scanner in scanners:
            try:
                findings.extend(scanner(file_path))
            except Exception as exc:  # defensive: one bad file must not abort the scan
                errors.append(f"{file_path}: {scanner.__name__} failed: {exc}")

    if osv:
        findings, osv_errors = _augment_with_osv(findings, dep_files)
        errors.extend(osv_errors)

    # Apply .vulnguard.toml ignore rules/paths, if a config is present.
    config = load_config(root)
    kept = list(config.filter(tuple(findings)))

    return ScanResult(findings=tuple(kept), scanned_files=scanned, errors=tuple(errors))


def scan_paths(paths: list[str], osv: bool = False) -> ScanResult:
    """Scan multiple files/directories and merge the results.

    Duplicate findings (same rule, file, and line) are collapsed so that
    overlapping paths don't double-count. Used by the CLI and pre-commit, which
    pass many staged files at once.
    """
    merged: list[Finding] = []
    errors: list[str] = []
    scanned = 0
    seen: set[tuple] = set()

    for path in paths:
        result = scan_path(path, osv=osv)
        scanned += result.scanned_files
        errors.extend(result.errors)
        for finding in result.findings:
            key = (finding.rule_id, finding.file_path, finding.line, finding.column)
            if key not in seen:
                seen.add(key)
                merged.append(finding)

    return ScanResult(findings=tuple(merged), scanned_files=scanned, errors=tuple(errors))


def _augment_with_osv(
    findings: list[Finding], dep_files: list[str]
) -> tuple[list[Finding], list[str]]:
    """Query OSV.dev for each dependency, skipping ids already reported offline."""
    errors: list[str] = []
    seen_ids = {f.rule_id for f in findings if f.category == "dependency"}
    for file_path in dep_files:
        for dep in extract_dependencies(file_path):
            try:
                for finding in query_osv(
                    dep["name"], dep["version"], dep["ecosystem"], file_path, dep["line"]
                ):
                    if finding.rule_id not in seen_ids:
                        seen_ids.add(finding.rule_id)
                        findings.append(finding)
            except OSVError as exc:
                errors.append(str(exc))
    return findings, errors
