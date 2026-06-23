"""Detect hardcoded secrets in any text file.

Two complementary strategies:
1. Named patterns for well-known secret formats (AWS keys, private keys, etc.).
2. Generic "assignment to a high-entropy string" detection for unknown keys.

High entropy = looks random = likely a real secret rather than a placeholder.
This is an everyday analogy: a real key looks like keyboard-mashing
("aZ9$kQ2..."), while a placeholder looks like a word ("changeme").
"""

from __future__ import annotations

import math
import re
from typing import Optional

from ..models import Finding, Severity

# (rule_id, severity, compiled regex, message)
_NAMED_PATTERNS: list[tuple[str, Severity, "re.Pattern[str]", str]] = [
    (
        "SEC001",
        Severity.CRITICAL,
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
        "Hardcoded private key.",
    ),
    (
        "SEC002",
        Severity.CRITICAL,
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "Hardcoded AWS access key ID.",
    ),
    (
        "SEC003",
        Severity.HIGH,
        re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
        "Hardcoded API key (sk-... format, e.g. OpenAI/Stripe).",
    ),
    (
        "SEC004",
        Severity.HIGH,
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
        "Hardcoded GitHub token.",
    ),
    (
        "SEC005",
        Severity.HIGH,
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        "Hardcoded Slack token.",
    ),
    (
        "SEC007",
        Severity.HIGH,
        re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        "Hardcoded Google API key.",
    ),
    (
        "SEC008",
        Severity.MEDIUM,
        re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
        "Hardcoded JSON Web Token (JWT).",
    ),
]

# Assignment of a secret-looking variable to a string literal.
# Matches: password = "...", api_key: "...", SECRET_TOKEN='...'
_ASSIGNMENT = re.compile(
    r"""(?ix)
    \b(?P<name>\w*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|
        private[_-]?key|auth|credential)\w*)
    \s*[:=]\s*
    (?P<quote>['"])(?P<value>[^'"\n]{6,})(?P=quote)
    """
)

# Obvious non-secrets we should not flag.
_PLACEHOLDERS = {
    "changeme", "password", "secret", "your_api_key", "xxxxxx", "example",
    "placeholder", "todo", "none", "null", "test", "dummy", "redacted",
    "<your-key>", "...", "********",
}


def _shannon_entropy(value: str) -> float:
    """Bits of entropy per character. Random strings score ~4+; words score lower."""
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def _looks_like_secret(value: str) -> bool:
    cleaned = value.strip()
    if cleaned.lower() in _PLACEHOLDERS:
        return False
    if len(cleaned) < 8:
        return False
    # Environment-variable references and format placeholders are not secrets.
    if cleaned.startswith(("${", "os.environ", "%(", "{")):
        return False
    return _shannon_entropy(cleaned) >= 3.5


def scan_secrets_in_text(text: str, file_path: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = text.splitlines()

    for line_no, line in enumerate(lines, start=1):
        for rule_id, severity, pattern, message in _NAMED_PATTERNS:
            if pattern.search(line):
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        severity=severity,
                        message=message,
                        file_path=file_path,
                        line=line_no,
                        snippet=line.strip()[:120],
                        category="secret",
                        cwe="CWE-798",
                        fixable=False,
                        remediation="Remove the secret, rotate it, and load it from an environment variable.",
                    )
                )

        match = _ASSIGNMENT.search(line)
        if match and _looks_like_secret(match.group("value")):
            findings.append(
                Finding(
                    rule_id="SEC006",
                    severity=Severity.HIGH,
                    message=f"Hardcoded secret assigned to '{match.group('name')}'.",
                    file_path=file_path,
                    line=line_no,
                    column=match.start() + 1,
                    snippet=line.strip()[:120],
                    category="secret",
                    cwe="CWE-798",
                    fixable=True,
                    remediation="Move the value to an environment variable and read it via os.environ.",
                )
            )
    return findings


def scan_secrets_in_file(file_path: str) -> list[Finding]:
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
            text = handle.read()
    except OSError as exc:
        return [
            Finding(
                rule_id="SEC000",
                severity=Severity.LOW,
                message=f"Could not read file: {exc}",
                file_path=file_path,
                category="secret",
            )
        ]
    return scan_secrets_in_text(text, file_path)
