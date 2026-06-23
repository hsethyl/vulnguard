"""Lightweight static analysis for Go source via regex.

Conservative single-line rules targeting well-known dangerous sinks, mirroring
the JS scanner's approach (no full Go parser is shipped).
"""

from __future__ import annotations

import re

from ..models import Finding, Severity

_LINE_COMMENT = re.compile(r"//.*$")

# (rule_id, severity, regex, message, cwe, remediation, fixable)
_RULES: list[tuple[str, Severity, "re.Pattern[str]", str, str, str, bool]] = [
    (
        "GO001",
        Severity.HIGH,
        re.compile(r'exec\.Command\(\s*"(?:sh|bash|zsh|cmd|powershell)"'),
        "exec.Command invoking a shell is prone to command injection.",
        "CWE-78",
        "Call the program directly with separate args; avoid passing a shell.",
        False,
    ),
    (
        "GO002",
        Severity.HIGH,
        re.compile(r"\.(?:Query|QueryRow|QueryContext|Exec|ExecContext)\([^)]*(?:fmt\.Sprintf|\+)"),
        "SQL query built with string formatting (SQL injection).",
        "CWE-89",
        "Use parameterized queries with placeholders ($1, ?) and args.",
        False,
    ),
    (
        "GO003",
        Severity.MEDIUM,
        re.compile(r"\b(?:md5|sha1)\.New\(\)"),
        "Weak hash (md5/sha1) unsuitable for security use.",
        "CWE-327",
        "Use sha256.New() (or bcrypt/argon2 for passwords).",
        False,
    ),
    (
        "GO004",
        Severity.HIGH,
        re.compile(r"InsecureSkipVerify\s*:\s*true"),
        "TLS certificate verification disabled (InsecureSkipVerify: true).",
        "CWE-295",
        "Set InsecureSkipVerify to false and trust a proper CA.",
        True,
    ),
]


def scan_go_source(source: str, file_path: str) -> list[Finding]:
    findings: list[Finding] = []
    for line_no, raw_line in enumerate(source.splitlines(), start=1):
        line = _LINE_COMMENT.sub("", raw_line)
        if not line.strip():
            continue
        for rule_id, severity, pattern, message, cwe, remediation, fixable in _RULES:
            match = pattern.search(line)
            if match:
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        severity=severity,
                        message=message,
                        file_path=file_path,
                        line=line_no,
                        column=match.start() + 1,
                        snippet=line.strip()[:120],
                        category="sast",
                        cwe=cwe,
                        fixable=fixable,
                        remediation=remediation,
                    )
                )
    return findings


def scan_go_file(file_path: str) -> list[Finding]:
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
            source = handle.read()
    except OSError as exc:
        return [
            Finding(
                rule_id="GO000",
                severity=Severity.LOW,
                message=f"Could not read file: {exc}",
                file_path=file_path,
                category="sast",
            )
        ]
    return scan_go_source(source, file_path)
