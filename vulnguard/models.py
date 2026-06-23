"""Core data models for vulnguard.

All models are immutable (frozen dataclasses) per the immutability principle:
a Finding, once produced by a scanner, is never mutated. Transformations
create new objects.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import IntEnum
from typing import Optional


class Severity(IntEnum):
    """Severity ordered so that higher value == more severe.

    IntEnum lets us sort findings by severity directly.
    """

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name


@dataclass(frozen=True)
class Finding:
    """A single detected vulnerability.

    Attributes:
        rule_id: Stable identifier of the rule that produced this (e.g. "PY001").
        severity: How dangerous this is.
        message: Human-readable description of the problem.
        file_path: Path to the file the finding is in.
        line: 1-based line number (0 if not line-specific, e.g. a dependency).
        column: 1-based column (0 if unknown).
        cwe: Associated CWE identifier (e.g. "CWE-78") or None.
        snippet: The offending source line, trimmed.
        category: Coarse grouping ("sast", "secret", "dependency").
        fixable: Whether an automatic fixer exists for this rule.
        remediation: Short guidance on how to fix it.
    """

    rule_id: str
    severity: Severity
    message: str
    file_path: str
    line: int = 0
    column: int = 0
    cwe: Optional[str] = None
    snippet: str = ""
    category: str = "sast"
    fixable: bool = False
    remediation: str = ""

    def sort_key(self) -> tuple:
        """Order: most severe first, then by file/line for stable output."""
        return (-int(self.severity), self.file_path, self.line, self.rule_id)


@dataclass(frozen=True)
class ScanResult:
    """The full result of a scan: an immutable collection of findings."""

    findings: tuple[Finding, ...] = field(default_factory=tuple)
    scanned_files: int = 0
    errors: tuple[str, ...] = field(default_factory=tuple)

    def with_findings(self, new_findings: list[Finding]) -> "ScanResult":
        return replace(self, findings=tuple(new_findings))

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.sort_key())

    def counts_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {s.label: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity.label] += 1
        return counts

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0
