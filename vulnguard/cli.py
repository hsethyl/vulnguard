"""vulnguard command-line interface.

Commands:
  vulnguard scan <path> [--format console|json|sarif] [--output FILE] [--fail-on LEVEL]
  vulnguard fix  <path> [--apply]
"""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .dast.client import DastError, scan_url
from .engine import scan_path, scan_paths
from .fixers.engine import apply_fixes
from .models import ScanResult, Severity
from .report.console import render_console
from .report.json_report import render_json, render_sarif

_FAIL_LEVELS = {s.label: s for s in Severity}


def _write_output(text: str, output: str | None) -> None:
    if output:
        with open(output, "w", encoding="utf-8") as handle:
            handle.write(text)
        print(f"Wrote report to {output}")
    else:
        print(text)


def _render(result: ScanResult, fmt: str, root: str) -> str:
    if fmt == "json":
        return render_json(result)
    if fmt == "sarif":
        return render_sarif(result)
    return render_console(result, root)


def _exit_code(result: ScanResult, fail_on: str | None) -> int:
    if not fail_on:
        return 0
    threshold = _FAIL_LEVELS[fail_on]
    worst = max((f.severity for f in result.findings), default=None)
    if worst is not None and worst >= threshold:
        return 2
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    label = args.paths[0] if len(args.paths) == 1 else f"{len(args.paths)} targets"
    result = scan_paths(args.paths, osv=args.osv)
    _write_output(_render(result, args.format, label), args.output)
    return _exit_code(result, args.fail_on)


def cmd_fix(args: argparse.Namespace) -> int:
    result = scan_path(args.path)
    report = apply_fixes(list(result.findings), args.path, apply=args.apply)

    if not report.file_fixes:
        print("No auto-fixable findings.")
        return 0

    for fix in report.file_fixes:
        print(f"\n=== {fix.file_path}  ({fix.change_count} change(s)) ===")
        print(fix.diff if fix.diff.strip() else "(no textual diff)")

    if report.env_vars:
        print("\nSecrets to move into environment variables (.env.example):")
        for name, _value in report.env_vars:
            print(f"  {name}")

    if args.apply:
        print(f"\nApplied {report.total_changes} change(s). Backups saved as *.vulnguard.bak")
        if report.env_example_path:
            print(f"Wrote {report.env_example_path} — fill real values and keep it out of git.")
        print("WARNING: review the changes and rotate any secret that was committed.")
    else:
        print(f"\nDry run: {report.total_changes} change(s) would be applied. "
              "Re-run with --apply to write them.")

    for err in report.errors:
        print(f"! {err}", file=sys.stderr)
    return 0


def cmd_dast(args: argparse.Namespace) -> int:
    try:
        result = scan_url(args.url, authorized=args.i_am_authorized)
    except DastError as exc:
        print(f"DAST error: {exc}", file=sys.stderr)
        return 1
    _write_output(_render(result, args.format, args.url), args.output)
    return _exit_code(result, args.fail_on)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnguard",
        description="Scan code for vulnerabilities and apply safe fixes.",
    )
    parser.add_argument("--version", action="version", version=f"vulnguard {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan files or directories for vulnerabilities.")
    scan.add_argument("paths", nargs="+", help="One or more files/directories to scan.")
    scan.add_argument(
        "--format", choices=["console", "json", "sarif"], default="console",
        help="Output format (default: console).",
    )
    scan.add_argument("--output", "-o", help="Write the report to a file instead of stdout.")
    scan.add_argument(
        "--fail-on", choices=list(_FAIL_LEVELS), default=None,
        help="Exit with code 2 if a finding at or above this severity exists.",
    )
    scan.add_argument(
        "--osv", action="store_true",
        help="Also check dependencies against OSV.dev (requires network).",
    )
    scan.set_defaults(func=cmd_scan)

    fix = sub.add_parser("fix", help="Show or apply automatic fixes.")
    fix.add_argument("path", help="File or directory to fix.")
    fix.add_argument(
        "--apply", action="store_true",
        help="Write the fixes to disk (default: dry run showing a diff).",
    )
    fix.set_defaults(func=cmd_fix)

    dast = sub.add_parser(
        "dast",
        help="Passively check a running website's security headers/cookies/TLS.",
    )
    dast.add_argument("url", help="URL to check (http:// or https://).")
    dast.add_argument(
        "--i-am-authorized", action="store_true",
        help="Confirm you own or are authorized to test the target (required for non-local hosts).",
    )
    dast.add_argument(
        "--format", choices=["console", "json", "sarif"], default="console",
        help="Output format (default: console).",
    )
    dast.add_argument("--output", "-o", help="Write the report to a file instead of stdout.")
    dast.add_argument(
        "--fail-on", choices=list(_FAIL_LEVELS), default=None,
        help="Exit with code 2 if a finding at or above this severity exists.",
    )
    dast.set_defaults(func=cmd_dast)

    return parser


def _force_utf8_stdout() -> None:
    """Windows consoles often default to cp949/cp1252, which can't encode some
    report characters. Reconfigure to UTF-8 when possible."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8")
            except (ValueError, OSError):
                pass


def main(argv: list[str] | None = None) -> int:
    _force_utf8_stdout()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
