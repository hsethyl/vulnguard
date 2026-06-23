"""Human-readable console report with optional ANSI color."""

from __future__ import annotations

import os
import sys

from ..models import ScanResult, Severity

_COLORS = {
    Severity.CRITICAL: "\033[1;37;41m",  # white on red
    Severity.HIGH: "\033[1;31m",         # bright red
    Severity.MEDIUM: "\033[1;33m",       # yellow
    Severity.LOW: "\033[1;36m",          # cyan
}
_RESET = "\033[0m"
_DIM = "\033[2m"
_BOLD = "\033[1m"


def _use_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def _c(text: str, code: str, color: bool) -> str:
    return f"{code}{text}{_RESET}" if color else text


def render_console(result: ScanResult, root: str) -> str:
    color = _use_color()
    lines: list[str] = []
    lines.append(_c(f"vulnguard scan - {root}", _BOLD, color))
    lines.append(_c(f"  scanned {result.scanned_files} file(s)", _DIM, color))
    lines.append("")

    if not result.has_findings:
        lines.append(_c("  No vulnerabilities found.", "\033[1;32m", color))
    else:
        for finding in result.sorted_findings():
            badge = _c(f" {finding.severity.label:^8} ", _COLORS[finding.severity], color)
            location = finding.file_path
            if finding.line:
                location += f":{finding.line}"
            cwe = f" [{finding.cwe}]" if finding.cwe else ""
            fix = _c(" (auto-fixable)", "\033[1;32m", color) if finding.fixable else ""
            lines.append(f"{badge} {_c(finding.rule_id, _BOLD, color)}{cwe} {location}{fix}")
            lines.append(f"         {finding.message}")
            if finding.snippet:
                lines.append(_c(f"         > {finding.snippet}", _DIM, color))
            if finding.remediation:
                lines.append(_c(f"         fix: {finding.remediation}", "\033[2;32m" if color else "", color)
                             if color else f"         fix: {finding.remediation}")
            lines.append("")

    counts = result.counts_by_severity()
    summary = "  ".join(
        f"{s.label}: {counts[s.label]}" for s in sorted(Severity, reverse=True)
    )
    lines.append(_c("Summary: " + summary, _BOLD, color))

    if result.errors:
        lines.append("")
        lines.append(_c(f"{len(result.errors)} file error(s):", _DIM, color))
        for err in result.errors:
            lines.append(_c(f"  ! {err}", _DIM, color))

    return "\n".join(lines)
