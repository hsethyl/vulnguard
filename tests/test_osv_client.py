from vulnguard.models import Severity
from vulnguard.scanner.osv_client import parse_osv_response


def _sample(severity_word="HIGH", fixed="2.3.2"):
    return {
        "vulns": [
            {
                "id": "GHSA-aaaa-bbbb-cccc",
                "summary": "Session cookie disclosure.",
                "database_specific": {"severity": severity_word},
                "affected": [
                    {
                        "package": {"name": "flask", "ecosystem": "PyPI"},
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [{"introduced": "0"}, {"fixed": fixed}],
                            }
                        ],
                    }
                ],
            }
        ]
    }


def test_parses_finding_with_fixed_version():
    findings = parse_osv_response(_sample(), "flask", "2.0.0", "requirements.txt", 3)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "GHSA-aaaa-bbbb-cccc"
    assert f.severity == Severity.HIGH
    assert f.fixable is True
    assert ">= 2.3.2" in f.remediation
    assert f.category == "dependency"


def test_severity_from_cvss_score():
    data = {
        "vulns": [
            {
                "id": "X",
                "summary": "bad",
                "severity": [{"type": "CVSS_V3", "score": "9.8"}],
                "affected": [],
            }
        ]
    }
    findings = parse_osv_response(data, "pkg", "1.0", "f", 0)
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].fixable is False  # no fixed version available


def test_empty_response_no_findings():
    assert parse_osv_response({"vulns": []}, "pkg", "1.0", "f", 0) == []
