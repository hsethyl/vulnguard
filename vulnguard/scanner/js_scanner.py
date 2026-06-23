"""Lightweight static analysis for JavaScript / TypeScript via regex.

We don't ship a full JS parser, so this uses conservative regex rules tuned
to keep false positives low. Each rule targets a well-known dangerous sink.
"""

from __future__ import annotations

import re

from ..models import Finding, Severity

# (rule_id, severity, regex, message, cwe, remediation)
_RULES: list[tuple[str, Severity, "re.Pattern[str]", str, str, str]] = [
    (
        "JS001",
        Severity.HIGH,
        re.compile(r"\.innerHTML\s*[+]?=\s*"),
        "Assignment to innerHTML can introduce XSS.",
        "CWE-79",
        "Use textContent, or sanitize HTML (e.g. DOMPurify) before assigning.",
    ),
    (
        "JS002",
        Severity.HIGH,
        re.compile(r"document\.write\s*\("),
        "document.write() can introduce XSS.",
        "CWE-79",
        "Build DOM nodes explicitly or sanitize input.",
    ),
    (
        "JS003",
        Severity.CRITICAL,
        re.compile(r"(?<![.\w])eval\s*\("),
        "Use of eval() allows arbitrary code execution.",
        "CWE-95",
        "Avoid eval(). Use JSON.parse() for data.",
    ),
    (
        "JS004",
        Severity.HIGH,
        re.compile(r"new\s+Function\s*\("),
        "new Function() executes code from a string, like eval().",
        "CWE-95",
        "Avoid dynamic code construction.",
    ),
    (
        "JS005",
        Severity.HIGH,
        re.compile(r"child_process\.(?:exec|execSync)\s*\("),
        "child_process.exec runs a shell and is prone to command injection.",
        "CWE-78",
        "Use execFile/spawn with an argument array instead of exec.",
    ),
    (
        "JS006",
        Severity.MEDIUM,
        re.compile(r"\bdangerouslySetInnerHTML\b"),
        "React dangerouslySetInnerHTML can introduce XSS.",
        "CWE-79",
        "Sanitize the HTML (e.g. DOMPurify) before rendering.",
    ),
    (
        "JS007",
        Severity.MEDIUM,
        re.compile(r"\bset(?:Timeout|Interval)\s*\(\s*['\"]"),
        "setTimeout/setInterval with a string argument behaves like eval().",
        "CWE-95",
        "Pass a function reference instead of a string.",
    ),
]

# Strip line and block comments crudely so commented-out code isn't flagged.
_LINE_COMMENT = re.compile(r"//.*$")


def scan_js_source(source: str, file_path: str) -> list[Finding]:
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


def scan_js_file(file_path: str) -> list[Finding]:
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
            source = handle.read()
    except OSError as exc:
        return [
            Finding(
                rule_id="JS000",
                severity=Severity.LOW,
                message=f"Could not read file: {exc}",
                file_path=file_path,
                category="sast",
            )
        ]
    return scan_js_source(source, file_path)
