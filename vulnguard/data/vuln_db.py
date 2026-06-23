"""A small, offline database of known-vulnerable package versions.

This is intentionally a curated sample, not a complete feed. It demonstrates
the matching logic and works with no network access. For production use, the
dependency scanner can additionally query the OSV.dev API (see
dependency_scanner.query_osv), which covers the full ecosystem.

Format: ecosystem -> package (lowercased) -> list of advisories.
Each advisory specifies the vulnerable version range and a safe version.
"""

from __future__ import annotations

# Each advisory: id, vulnerable specifier, fixed version, severity, summary.
KNOWN_VULNERABILITIES: dict[str, dict[str, list[dict]]] = {
    "pypi": {
        "pyyaml": [
            {
                "id": "CVE-2020-14343",
                "vulnerable": "<5.4",
                "fixed": "5.4",
                "severity": "CRITICAL",
                "summary": "Arbitrary code execution via full_load / FullLoader.",
            }
        ],
        "requests": [
            {
                "id": "CVE-2023-32681",
                "vulnerable": "<2.31.0",
                "fixed": "2.31.0",
                "severity": "MEDIUM",
                "summary": "Proxy-Authorization header leak on redirect.",
            }
        ],
        "flask": [
            {
                "id": "CVE-2023-30861",
                "vulnerable": "<2.3.2",
                "fixed": "2.3.2",
                "severity": "HIGH",
                "summary": "Possible session cookie disclosure via caching proxies.",
            }
        ],
        "jinja2": [
            {
                "id": "CVE-2024-22195",
                "vulnerable": "<3.1.3",
                "fixed": "3.1.3",
                "severity": "MEDIUM",
                "summary": "XSS via the xmlattr filter.",
            }
        ],
        "django": [
            {
                "id": "CVE-2023-43665",
                "vulnerable": "<4.2.7",
                "fixed": "4.2.7",
                "severity": "HIGH",
                "summary": "Denial of service in django.utils.text.Truncator.",
            }
        ],
        "cryptography": [
            {
                "id": "CVE-2023-50782",
                "vulnerable": "<42.0.0",
                "fixed": "42.0.0",
                "severity": "HIGH",
                "summary": "Bleichenbacher timing oracle in RSA decryption.",
            }
        ],
    },
    "npm": {
        "lodash": [
            {
                "id": "CVE-2021-23337",
                "vulnerable": "<4.17.21",
                "fixed": "4.17.21",
                "severity": "HIGH",
                "summary": "Command injection via template.",
            }
        ],
        "axios": [
            {
                "id": "CVE-2023-45857",
                "vulnerable": "<1.6.0",
                "fixed": "1.6.0",
                "severity": "MEDIUM",
                "summary": "SSRF / credential leak via following redirects.",
            }
        ],
        "minimist": [
            {
                "id": "CVE-2021-44906",
                "vulnerable": "<1.2.6",
                "fixed": "1.2.6",
                "severity": "CRITICAL",
                "summary": "Prototype pollution.",
            }
        ],
    },
}
