"""Lightweight static analysis for Java source via regex.

Conservative single-line rules for common dangerous sinks.
"""

from __future__ import annotations

import re

from ..models import Finding, Severity

_LINE_COMMENT = re.compile(r"//.*$")

# (rule_id, severity, regex, message, cwe, remediation)
_RULES: list[tuple[str, Severity, "re.Pattern[str]", str, str, str]] = [
    (
        "JAVA001",
        Severity.HIGH,
        re.compile(r"Runtime\.getRuntime\(\)\.exec\("),
        "Runtime.exec() is prone to command injection.",
        "CWE-78",
        "Use ProcessBuilder with a fixed argument list and validate inputs.",
    ),
    (
        "JAVA002",
        Severity.HIGH,
        re.compile(r"\.(?:executeQuery|executeUpdate|execute)\([^)]*\+"),
        "SQL built via string concatenation (SQL injection).",
        "CWE-89",
        "Use PreparedStatement with parameter placeholders.",
    ),
    (
        "JAVA003",
        Severity.MEDIUM,
        re.compile(r'MessageDigest\.getInstance\(\s*"(?:MD5|SHA-1|SHA1)"'),
        "Weak hash algorithm (MD5/SHA-1).",
        "CWE-327",
        'Use "SHA-256" (or bcrypt/PBKDF2 for passwords).',
    ),
    (
        "JAVA004",
        Severity.HIGH,
        re.compile(r"new\s+ObjectInputStream\(|\.readObject\(\)"),
        "Java deserialization of untrusted data enables remote code execution.",
        "CWE-502",
        "Avoid native serialization; use a safe format (JSON) with allow-lists.",
    ),
]


def scan_java_source(source: str, file_path: str) -> list[Finding]:
    findings: list[Finding] = []
    for line_no, raw_line in enumerate(source.splitlines(), start=1):
        line = _LINE_COMMENT.sub("", raw_line)
        if not line.strip():
            continue
        for rule_id, severity, pattern, message, cwe, remediation in _RULES:
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
                        fixable=False,
                        remediation=remediation,
                    )
                )
    return findings


def scan_java_file(file_path: str) -> list[Finding]:
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
            source = handle.read()
    except OSError as exc:
        return [
            Finding(
                rule_id="JAVA000",
                severity=Severity.LOW,
                message=f"Could not read file: {exc}",
                file_path=file_path,
                category="sast",
            )
        ]
    return scan_java_source(source, file_path)
