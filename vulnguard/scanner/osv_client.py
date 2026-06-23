"""Optional online dependency check against the OSV.dev database.

OSV (https://osv.dev) is a free, open vulnerability database covering most
ecosystems. We use only the public query API over HTTPS with the standard
library, so there are no third-party dependencies.

Network use is opt-in (the --osv CLI flag). The parsing logic is separated
from the HTTP call so it can be unit-tested without a network.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Optional

from ..models import Finding, Severity

_OSV_URL = "https://api.osv.dev/v1/query"
_TIMEOUT = 15

_SEVERITY_WORDS = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


class OSVError(RuntimeError):
    """Raised when the OSV service cannot be reached or returns bad data."""


def _fetch(name: str, version: str, ecosystem: str) -> dict:
    body = json.dumps(
        {"version": version, "package": {"name": name, "ecosystem": ecosystem}}
    ).encode("utf-8")
    request = urllib.request.Request(
        _OSV_URL, data=body, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=_TIMEOUT) as response:
            return json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        raise OSVError(f"OSV query failed for {name}=={version}: {exc}") from exc


def _severity_for(vuln: dict) -> Severity:
    word = (vuln.get("database_specific") or {}).get("severity")
    if isinstance(word, str) and word.upper() in _SEVERITY_WORDS:
        return _SEVERITY_WORDS[word.upper()]
    # Fall back to CVSS score if present.
    for sev in vuln.get("severity") or []:
        score = str(sev.get("score", ""))
        digits = "".join(ch for ch in score if ch.isdigit() or ch == ".")
        try:
            value = float(digits.split("/")[0]) if digits else 0.0
        except ValueError:
            value = 0.0
        if value >= 9.0:
            return Severity.CRITICAL
        if value >= 7.0:
            return Severity.HIGH
        if value >= 4.0:
            return Severity.MEDIUM
    return Severity.MEDIUM


def _fixed_version(vuln: dict, name: str) -> Optional[str]:
    for affected in vuln.get("affected") or []:
        pkg = (affected.get("package") or {}).get("name", "")
        if pkg.lower() != name.lower():
            continue
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                if "fixed" in event:
                    return event["fixed"]
    return None


def parse_osv_response(
    data: dict, name: str, version: str, file_path: str, line: int
) -> list[Finding]:
    """Pure parser: turn an OSV /v1/query response into Findings."""
    findings: list[Finding] = []
    for vuln in data.get("vulns") or []:
        vuln_id = vuln.get("id", "OSV-UNKNOWN")
        summary = vuln.get("summary") or vuln.get("details") or "Known vulnerability."
        summary = summary.strip().splitlines()[0][:200]
        fixed = _fixed_version(vuln, name)
        remediation = (
            f"Upgrade {name} to >= {fixed}." if fixed
            else f"Upgrade {name}; see https://osv.dev/vulnerability/{vuln_id}"
        )
        findings.append(
            Finding(
                rule_id=vuln_id,
                severity=_severity_for(vuln),
                message=f"{name} {version} is vulnerable: {summary}",
                file_path=file_path,
                line=line,
                snippet=f"{name}=={version}",
                category="dependency",
                cwe=None,
                fixable=fixed is not None,
                remediation=remediation,
            )
        )
    return findings


def query_osv(
    name: str, version: str, ecosystem: str, file_path: str, line: int
) -> list[Finding]:
    """Query OSV for one package. Raises OSVError on network failure."""
    data = _fetch(name, version, ecosystem)
    return parse_osv_response(data, name, version, file_path, line)
