"""Static analysis for Python source using the `ast` module.

AST-based detection is far more robust than regex: it understands calls,
attributes, and keyword arguments, so it has far fewer false positives than
text matching. Each rule is a small, focused check on an AST node.
"""

from __future__ import annotations

import ast
from typing import Optional

from ..models import Finding, Severity


def _snippet(source_lines: list[str], line: int) -> str:
    if 1 <= line <= len(source_lines):
        return source_lines[line - 1].strip()
    return ""


def _call_name(node: ast.Call) -> str:
    """Return a dotted name for a call target, e.g. 'subprocess.call' or 'eval'."""
    func = node.func
    parts: list[str] = []
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value
    if isinstance(func, ast.Name):
        parts.append(func.id)
    return ".".join(reversed(parts))


def _keyword_is(node: ast.Call, name: str, value: bool) -> bool:
    for kw in node.keywords:
        if kw.arg == name and isinstance(kw.value, ast.Constant) and kw.value.value is value:
            return True
    return False


def _has_keyword_true(node: ast.Call, name: str) -> bool:
    return _keyword_is(node, name, True)


def _is_nonempty_str(value: ast.expr) -> bool:
    return isinstance(value, ast.Constant) and isinstance(value.value, str) and value.value.strip() != ""


def _list_has_wildcard(value: ast.expr) -> bool:
    if not isinstance(value, (ast.List, ast.Tuple)):
        return False
    return any(
        isinstance(elt, ast.Constant) and elt.value == "*" for elt in value.elts
    )


def _is_dynamic_sql(arg: ast.expr) -> bool:
    """Detect a SQL string built via f-string, % formatting, +, or .format()."""
    if isinstance(arg, ast.JoinedStr):  # f-string with interpolation
        return any(isinstance(v, ast.FormattedValue) for v in arg.values)
    if isinstance(arg, ast.BinOp) and isinstance(arg.op, (ast.Add, ast.Mod)):
        return True
    if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute) and arg.func.attr == "format":
        return True
    return False


# Calls that are dangerous purely by being called.
_DANGEROUS_CALLS: dict[str, dict] = {
    "eval": {
        "rule_id": "PY001",
        "severity": Severity.CRITICAL,
        "cwe": "CWE-95",
        "message": "Use of eval() allows arbitrary code execution.",
        "remediation": "Avoid eval(). Use ast.literal_eval() for data, or an explicit parser.",
    },
    "exec": {
        "rule_id": "PY002",
        "severity": Severity.CRITICAL,
        "cwe": "CWE-95",
        "message": "Use of exec() allows arbitrary code execution.",
        "remediation": "Avoid exec(). Refactor to call explicit functions.",
    },
    "os.system": {
        "rule_id": "PY003",
        "severity": Severity.HIGH,
        "cwe": "CWE-78",
        "message": "os.system() invokes a shell and is prone to command injection.",
        "remediation": "Use subprocess.run([...], shell=False) with a list of arguments.",
    },
    "pickle.loads": {
        "rule_id": "PY005",
        "severity": Severity.HIGH,
        "cwe": "CWE-502",
        "message": "pickle.loads() on untrusted data enables arbitrary code execution.",
        "remediation": "Use json or another safe format for untrusted data.",
    },
    "pickle.load": {
        "rule_id": "PY005",
        "severity": Severity.HIGH,
        "cwe": "CWE-502",
        "message": "pickle.load() on untrusted data enables arbitrary code execution.",
        "remediation": "Use json or another safe format for untrusted data.",
    },
}

# Weak hash constructors.
_WEAK_HASHES = {"hashlib.md5", "hashlib.sha1", "md5", "sha1"}

# Names that look like a DB cursor execute call.
_EXECUTE_METHODS = {"execute", "executemany"}


class _Visitor(ast.NodeVisitor):
    def __init__(self, file_path: str, source_lines: list[str]) -> None:
        self.file_path = file_path
        self.source_lines = source_lines
        self.findings: list[Finding] = []

    def _add(
        self,
        node: ast.AST,
        rule_id: str,
        severity: Severity,
        message: str,
        cwe: str,
        remediation: str,
        fixable: bool = False,
    ) -> None:
        line = getattr(node, "lineno", 0)
        col = getattr(node, "col_offset", 0) + 1
        self.findings.append(
            Finding(
                rule_id=rule_id,
                severity=severity,
                message=message,
                file_path=self.file_path,
                line=line,
                column=col,
                cwe=cwe,
                snippet=_snippet(self.source_lines, line),
                category="sast",
                fixable=fixable,
                remediation=remediation,
            )
        )

    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node)

        if name in _DANGEROUS_CALLS:
            spec = _DANGEROUS_CALLS[name]
            self._add(
                node,
                spec["rule_id"],
                spec["severity"],
                spec["message"],
                spec["cwe"],
                spec["remediation"],
            )

        # subprocess.* with shell=True
        if name.startswith("subprocess.") and _has_keyword_true(node, "shell"):
            self._add(
                node,
                "PY004",
                Severity.HIGH,
                f"{name}(shell=True) is vulnerable to command injection.",
                "CWE-78",
                "Pass args as a list and use shell=False. (manual: shell=False alone can break a string command)",
                fixable=False,
            )

        # yaml.load without a safe loader -> arbitrary object construction
        if name in ("yaml.load", "load") and self._yaml_unsafe(node):
            self._add(
                node,
                "PY006",
                Severity.HIGH,
                "yaml.load() without SafeLoader can construct arbitrary objects.",
                "CWE-20",
                "Use yaml.safe_load() instead.",
                fixable=True,
            )

        # weak hash
        if name in _WEAK_HASHES:
            self._add(
                node,
                "PY007",
                Severity.MEDIUM,
                f"{name}() is a weak hash unsuitable for security use.",
                "CWE-327",
                "Use hashlib.sha256() (or bcrypt/argon2 for passwords).",
            )

        # TLS certificate verification disabled
        if _keyword_is(node, "verify", False):
            self._add(
                node,
                "PY009",
                Severity.HIGH,
                "TLS certificate verification disabled (verify=False).",
                "CWE-295",
                "Remove verify=False (default True), or pass a trusted CA bundle.",
                fixable=True,
            )

        # Flask/WSGI debug server enabled (RCE via the debugger, info leak)
        if name.endswith("run") and _keyword_is(node, "debug", True):
            self._add(
                node,
                "PY010",
                Severity.HIGH,
                "Web server started with debug=True (remote code execution risk).",
                "CWE-489",
                "Set debug=False in production.",
                fixable=True,
            )

        # Archive extraction without path checks -> path traversal (zip slip)
        if isinstance(node.func, ast.Attribute) and node.func.attr == "extractall":
            self._add(
                node,
                "PY011",
                Severity.MEDIUM,
                "Archive extractall() can write outside the target dir (path traversal).",
                "CWE-22",
                "Validate each member's path before extracting, or use a vetted extractor.",
            )

        # Insecure temp file creation (race condition)
        if name in ("tempfile.mktemp", "mktemp"):
            self._add(
                node,
                "PY012",
                Severity.MEDIUM,
                "tempfile.mktemp() is insecure (race condition).",
                "CWE-377",
                "Use tempfile.mkstemp() or NamedTemporaryFile().",
            )

        # Jinja2 autoescaping disabled -> XSS / SSTI
        if _keyword_is(node, "autoescape", False):
            self._add(
                node,
                "PY013",
                Severity.HIGH,
                "Template autoescape disabled (autoescape=False) - XSS/SSTI risk.",
                "CWE-79",
                "Enable autoescaping: autoescape=True or select_autoescape().",
                fixable=True,
            )

        # SQL injection via dynamic string passed to execute()
        if isinstance(node.func, ast.Attribute) and node.func.attr in _EXECUTE_METHODS:
            if node.args and _is_dynamic_sql(node.args[0]):
                self._add(
                    node,
                    "PY008",
                    Severity.HIGH,
                    "Possible SQL injection: query built with string formatting.",
                    "CWE-89",
                    "Use parameterized queries: cursor.execute(sql, params).",
                )

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            name = target.id
            value = node.value

            if name == "SECRET_KEY" and _is_nonempty_str(value):
                self._add(
                    node,
                    "DJ001",
                    Severity.CRITICAL,
                    "Django SECRET_KEY is hardcoded.",
                    "CWE-798",
                    "Load SECRET_KEY from an environment variable.",
                )
            elif name == "ALLOWED_HOSTS" and _list_has_wildcard(value):
                self._add(
                    node,
                    "DJ002",
                    Severity.HIGH,
                    "ALLOWED_HOSTS = ['*'] accepts any Host header.",
                    "CWE-20",
                    "List explicit, trusted hostnames instead of '*'.",
                )
            elif name == "DEBUG" and isinstance(value, ast.Constant) and value.value is True:
                self._add(
                    node,
                    "DJ003",
                    Severity.HIGH,
                    "DEBUG = True leaks tracebacks/settings in production.",
                    "CWE-489",
                    "Set DEBUG = False in production (drive it from an env var).",
                )
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str) and node.value == "0.0.0.0":
            self._add(
                node,
                "PY014",
                Severity.MEDIUM,
                "Binding to 0.0.0.0 exposes the service on all network interfaces.",
                "CWE-668",
                "Bind to 127.0.0.1 unless external access is explicitly required.",
            )
        self.generic_visit(node)

    def _yaml_unsafe(self, node: ast.Call) -> bool:
        """yaml.load is unsafe unless a safe Loader is passed."""
        name = _call_name(node)
        if name == "load" and not (
            isinstance(node.func, ast.Attribute)
        ):
            return False
        # if a Loader keyword names a safe loader, it's fine
        for kw in node.keywords:
            if kw.arg == "Loader":
                loader = ast.dump(kw.value)
                if "Safe" in loader:
                    return False
                return True
        # positional Loader as 2nd arg
        if len(node.args) >= 2:
            loader = ast.dump(node.args[1])
            return "Safe" not in loader
        # no loader at all -> unsafe on old PyYAML
        return _call_name(node) == "yaml.load"


def scan_python_source(source: str, file_path: str) -> list[Finding]:
    """Scan a string of Python source. Returns findings (possibly empty).

    Raises nothing for syntactically invalid code; instead returns a single
    informational finding so the caller can surface a parse error.
    """
    source_lines = source.splitlines()
    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError as exc:
        return [
            Finding(
                rule_id="PY000",
                severity=Severity.LOW,
                message=f"Could not parse file (syntax error): {exc.msg}",
                file_path=file_path,
                line=exc.lineno or 0,
                category="sast",
            )
        ]
    visitor = _Visitor(file_path, source_lines)
    visitor.visit(tree)
    return visitor.findings


def scan_python_file(file_path: str) -> list[Finding]:
    try:
        with open(file_path, "r", encoding="utf-8") as handle:
            source = handle.read()
    except (OSError, UnicodeDecodeError) as exc:
        return [
            Finding(
                rule_id="PY000",
                severity=Severity.LOW,
                message=f"Could not read file: {exc}",
                file_path=file_path,
                category="sast",
            )
        ]
    return scan_python_source(source, file_path)
