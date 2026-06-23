"""Fetch a URL and run the passive analyzer. Network + authorization live here."""

from __future__ import annotations

import urllib.error
import urllib.request
from urllib.parse import urlparse

from ..models import Finding, ScanResult
from .analyzer import analyze_response

_TIMEOUT = 15
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
_USER_AGENT = "vulnguard-dast/0.1 (passive security check)"


class DastError(RuntimeError):
    """Raised for unreachable targets or authorization failures."""


def is_local(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return host in _LOCAL_HOSTS


def authorize(url: str, authorized: bool) -> None:
    """Refuse to scan non-local hosts without explicit authorization."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise DastError(f"Unsupported URL scheme: {parsed.scheme!r} (use http/https).")
    if not parsed.hostname:
        raise DastError("URL has no host.")
    if not is_local(url) and not authorized:
        raise DastError(
            f"Refusing to scan non-local host '{parsed.hostname}'. "
            "Only scan systems you own or are authorized to test; "
            "re-run with --i-am-authorized to confirm you have permission."
        )


def _fetch(url: str) -> tuple[int, dict[str, str], list[str]]:
    request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=_TIMEOUT) as response:
            headers = {k.lower(): v for k, v in response.headers.items()}
            cookies = response.headers.get_all("Set-Cookie") or []
            return response.status, headers, list(cookies)
    except urllib.error.HTTPError as exc:
        # An HTTP error still has headers worth analyzing.
        headers = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
        cookies = exc.headers.get_all("Set-Cookie") if exc.headers else []
        return exc.code, headers, list(cookies or [])
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise DastError(f"Could not reach {url}: {exc}") from exc


def scan_url(url: str, authorized: bool = False) -> ScanResult:
    """Passively scan one URL. Raises DastError on auth/network problems."""
    authorize(url, authorized)
    status, headers, cookies = _fetch(url)
    findings = analyze_response(url, status, headers, cookies)
    return ScanResult(findings=tuple(findings), scanned_files=1)
