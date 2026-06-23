"""Machine-readable JSON and SARIF 2.1.0 reporters."""

from __future__ import annotations

import json

from .. import __version__
from ..models import ScanResult


def render_json(result: ScanResult) -> str:
    payload = {
        "tool": "vulnguard",
        "version": __version__,
        "scanned_files": result.scanned_files,
        "summary": result.counts_by_severity(),
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.label,
                "message": f.message,
                "file": f.file_path,
                "line": f.line,
                "column": f.column,
                "cwe": f.cwe,
                "category": f.category,
                "fixable": f.fixable,
                "remediation": f.remediation,
                "snippet": f.snippet,
            }
            for f in result.sorted_findings()
        ],
        "errors": list(result.errors),
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


_SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}


def render_sarif(result: ScanResult) -> str:
    """SARIF 2.1.0 — consumable by GitHub code scanning and editors."""
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "vulnguard",
                        "version": __version__,
                        "informationUri": "https://example.local/vulnguard",
                        "rules": [],
                    }
                },
                "results": [
                    {
                        "ruleId": f.rule_id,
                        "level": _SARIF_LEVEL.get(f.severity.label, "warning"),
                        "message": {"text": f.message},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": f.file_path},
                                    "region": {
                                        "startLine": max(f.line, 1),
                                        "startColumn": max(f.column, 1),
                                    },
                                }
                            }
                        ],
                    }
                    for f in result.sorted_findings()
                ],
            }
        ],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)
