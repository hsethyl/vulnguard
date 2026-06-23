"""DAST v2: passive, non-intrusive web checks.

This module performs only a single, normal GET request and inspects the
response (security headers, cookie flags, TLS). It sends NO attack payloads.
Even so, scanning a host you do not own can be unlawful, so the CLI requires
explicit authorization for non-local targets.
"""
