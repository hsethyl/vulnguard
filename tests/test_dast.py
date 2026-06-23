import pytest

from vulnguard.dast.analyzer import analyze_response
from vulnguard.dast.client import DastError, authorize, is_local


def _ids(url, headers, cookies=None):
    return {f.rule_id for f in analyze_response(url, 200, headers, cookies or [])}


# --- analyzer ---

def test_http_site_flags_no_tls():
    ids = _ids("http://example.com", {})
    assert "DAST008" in ids
    assert "DAST001" not in ids  # HSTS only relevant on https


def test_https_missing_security_headers():
    ids = _ids("https://example.com", {})
    assert "DAST001" in ids  # HSTS
    assert "DAST002" in ids  # CSP
    assert "DAST003" in ids  # nosniff
    assert "DAST004" in ids  # clickjacking


def test_well_secured_response_minimal_findings():
    headers = {
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
    }
    ids = _ids("https://example.com", headers)
    assert ids == set()


def test_version_disclosure_flagged():
    ids = _ids("https://example.com", {"server": "nginx/1.18.0"})
    assert "DAST005" in ids


def test_cookie_missing_flags():
    cookies = ["session=abc; Path=/"]
    ids = _ids("https://example.com", {}, cookies)
    assert "DAST006" in ids  # Secure
    assert "DAST007" in ids  # HttpOnly


def test_cookie_with_flags_ok():
    cookies = ["session=abc; Secure; HttpOnly"]
    ids = _ids("https://example.com", {}, cookies)
    assert "DAST006" not in ids
    assert "DAST007" not in ids


# --- authorization gate ---

def test_localhost_is_local():
    assert is_local("http://localhost:8000/") is True
    assert is_local("http://127.0.0.1/") is True
    assert is_local("https://example.com/") is False


def test_authorize_allows_localhost_without_flag():
    authorize("http://localhost:8000/", authorized=False)  # no raise


def test_authorize_blocks_remote_without_flag():
    with pytest.raises(DastError):
        authorize("https://example.com/", authorized=False)


def test_authorize_allows_remote_with_flag():
    authorize("https://example.com/", authorized=True)  # no raise


def test_authorize_rejects_bad_scheme():
    with pytest.raises(DastError):
        authorize("ftp://example.com/", authorized=True)
