"""Pure analysis of an HTTP response into security Findings.

Kept free of any network code so it can be unit-tested with synthetic headers.
"""

from __future__ import annotations

from urllib.parse import urlparse

from ..models import Finding, Severity


def _finding(rule_id, severity, message, url, cwe, remediation) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        message=message,
        file_path=url,
        line=0,
        category="dast",
        cwe=cwe,
        fixable=False,
        remediation=remediation,
    )


def _cookie_flags(cookie: str) -> set[str]:
    return {part.strip().lower() for part in cookie.split(";")}


def _cookie_name(cookie: str) -> str:
    return cookie.split("=", 1)[0].strip()


def analyze_response(
    url: str,
    status: int,
    headers: dict[str, str],
    cookies: list[str],
) -> list[Finding]:
    """Analyze a response. `headers` keys must be lower-cased."""
    findings: list[Finding] = []
    is_https = urlparse(url).scheme == "https"
    h = {k.lower(): v for k, v in headers.items()}

    if not is_https:
        findings.append(_finding(
            "DAST008", Severity.HIGH,
            "Site served over plain HTTP (no transport encryption).",
            url, "CWE-319",
            "Serve the site over HTTPS and redirect HTTP to HTTPS.",
        ))

    if is_https and "strict-transport-security" not in h:
        findings.append(_finding(
            "DAST001", Severity.MEDIUM,
            "Missing Strict-Transport-Security (HSTS) header.",
            url, "CWE-319",
            "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
        ))

    if "content-security-policy" not in h:
        findings.append(_finding(
            "DAST002", Severity.MEDIUM,
            "Missing Content-Security-Policy header.",
            url, "CWE-1021",
            "Add a Content-Security-Policy restricting script/style sources.",
        ))

    if h.get("x-content-type-options", "").lower() != "nosniff":
        findings.append(_finding(
            "DAST003", Severity.LOW,
            "Missing 'X-Content-Type-Options: nosniff'.",
            url, "CWE-16",
            "Add 'X-Content-Type-Options: nosniff'.",
        ))

    csp = h.get("content-security-policy", "").lower()
    if "x-frame-options" not in h and "frame-ancestors" not in csp:
        findings.append(_finding(
            "DAST004", Severity.MEDIUM,
            "Missing clickjacking protection (X-Frame-Options / frame-ancestors).",
            url, "CWE-1021",
            "Add 'X-Frame-Options: DENY' or a CSP frame-ancestors directive.",
        ))

    for header in ("server", "x-powered-by", "x-aspnet-version"):
        value = h.get(header, "")
        if any(ch.isdigit() for ch in value):
            findings.append(_finding(
                "DAST005", Severity.LOW,
                f"Software/version disclosed via '{header}: {value}'.",
                url, "CWE-200",
                f"Remove or obfuscate the '{header}' response header.",
            ))

    for cookie in cookies:
        flags = _cookie_flags(cookie)
        cname = _cookie_name(cookie)
        if is_https and "secure" not in flags:
            findings.append(_finding(
                "DAST006", Severity.MEDIUM,
                f"Cookie '{cname}' is missing the Secure flag.",
                url, "CWE-614",
                "Set the Secure attribute so cookies are only sent over HTTPS.",
            ))
        if "httponly" not in flags:
            findings.append(_finding(
                "DAST007", Severity.MEDIUM,
                f"Cookie '{cname}' is missing the HttpOnly flag.",
                url, "CWE-1004",
                "Set the HttpOnly attribute to block JavaScript access.",
            ))

    return findings
