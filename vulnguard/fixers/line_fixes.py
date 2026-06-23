"""Pure, line-level fixers. Each returns a transformed line plus side-effects.

Keeping these pure (string in, string out) makes them trivial to unit-test and
keeps the risky I/O (writing files, backups) isolated in the fix engine.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

# Reuse the same secret-assignment shape used for detection.
_ASSIGNMENT = re.compile(
    r"""(?ix)
    ^(?P<prefix>\s*(?P<name>\w*(?:password|passwd|pwd|secret|token|api[_-]?key|
        access[_-]?key|private[_-]?key|auth|credential)\w*)\s*[:=]\s*)
    (?P<quote>['"])(?P<value>[^'"\n]{6,})(?P=quote)
    (?P<suffix>.*)$
    """
)


@dataclass(frozen=True)
class LineFix:
    """Result of fixing one line.

    new_line: replacement text (without trailing newline).
    env_var: (NAME, value) to record in .env.example, if a secret was extracted.
    needs_os_import: True when the fix references os.environ.
    """

    new_line: str
    env_var: Optional[tuple[str, str]] = None
    needs_os_import: bool = False


def _env_name(var_name: str) -> str:
    """Convert a python identifier to an ENV-style name: apiKey -> API_KEY."""
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", var_name)
    return re.sub(r"[^A-Za-z0-9]+", "_", spaced).upper().strip("_")


def fix_yaml_load(line: str) -> Optional[LineFix]:
    """yaml.load(x) -> yaml.safe_load(x), only when no explicit Loader is given."""
    if "yaml.load(" not in line:
        return None
    if "Loader" in line:
        return None  # has a Loader arg; safe_load signature differs -> manual
    return LineFix(new_line=line.replace("yaml.load(", "yaml.safe_load("))


def fix_hardcoded_secret(line: str) -> Optional[LineFix]:
    """password = "abc123" -> password = os.environ["PASSWORD"]."""
    match = _ASSIGNMENT.match(line)
    if not match:
        return None
    env = _env_name(match.group("name"))
    value = match.group("value")
    new_line = f'{match.group("prefix")}os.environ["{env}"]{match.group("suffix")}'
    return LineFix(new_line=new_line, env_var=(env, value), needs_os_import=True)


_VERIFY_FALSE = re.compile(r"verify\s*=\s*False")
_DEBUG_TRUE = re.compile(r"debug\s*=\s*True")
_AUTOESCAPE_FALSE = re.compile(r"autoescape\s*=\s*False")


def fix_verify_false(line: str) -> Optional[LineFix]:
    """verify=False -> verify=True (restore TLS verification)."""
    if not _VERIFY_FALSE.search(line):
        return None
    return LineFix(new_line=_VERIFY_FALSE.sub("verify=True", line))


def fix_debug_true(line: str) -> Optional[LineFix]:
    """debug=True -> debug=False (disable the debug server)."""
    if not _DEBUG_TRUE.search(line):
        return None
    return LineFix(new_line=_DEBUG_TRUE.sub("debug=False", line))


def fix_autoescape_false(line: str) -> Optional[LineFix]:
    """autoescape=False -> autoescape=True (restore template escaping)."""
    if not _AUTOESCAPE_FALSE.search(line):
        return None
    return LineFix(new_line=_AUTOESCAPE_FALSE.sub("autoescape=True", line))


# rule_id -> line fixer
LINE_FIXERS = {
    "PY006": fix_yaml_load,
    "PY009": fix_verify_false,
    "PY010": fix_debug_true,
    "PY013": fix_autoescape_false,
    "SEC006": fix_hardcoded_secret,
}
