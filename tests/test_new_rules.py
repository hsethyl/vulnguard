from vulnguard.fixers.line_fixes import fix_debug_true, fix_verify_false
from vulnguard.scanner.js_scanner import scan_js_source
from vulnguard.scanner.python_scanner import scan_python_source
from vulnguard.scanner.secret_scanner import scan_secrets_in_text


def _py(source: str) -> set[str]:
    return {f.rule_id for f in scan_python_source(source, "f.py")}


def _js(source: str) -> set[str]:
    return {f.rule_id for f in scan_js_source(source, "f.js")}


def _sec(text: str) -> set[str]:
    return {f.rule_id for f in scan_secrets_in_text(text, "f.py")}


# --- Python new rules ---

def test_detects_verify_false():
    assert "PY009" in _py("import requests\nrequests.get(url, verify=False)")


def test_verify_true_is_safe():
    assert "PY009" not in _py("import requests\nrequests.get(url, verify=True)")


def test_detects_flask_debug_true():
    assert "PY010" in _py("app.run(host='0.0.0.0', debug=True)")


def test_run_without_debug_is_safe():
    assert "PY010" not in _py("app.run(host='0.0.0.0')")


def test_detects_extractall():
    assert "PY011" in _py("import tarfile\ntarfile.open(p).extractall(dest)")


def test_detects_mktemp():
    assert "PY012" in _py("import tempfile\nf = tempfile.mktemp()")


# --- JS new rule ---

def test_detects_settimeout_string():
    assert "JS007" in _js("setTimeout('doStuff()', 100);")


def test_settimeout_function_is_safe():
    assert "JS007" not in _js("setTimeout(doStuff, 100);")


# --- Secret new patterns ---

def test_detects_google_api_key():
    key = "AIza" + "B" * 35
    assert "SEC007" in _sec(f'k = "{key}"')


def test_detects_jwt():
    jwt = "eyJhbGciOiJIUzI1Niable.eyJzdWIiOiIxMjM0NXabc.SflKxwRJSMeKKF2QTabc"
    assert "SEC008" in _sec(f'token = "{jwt}"')


# --- New auto-fixers ---

def test_fix_verify_false_line():
    result = fix_verify_false("requests.get(u, verify=False)")
    assert result is not None and "verify=True" in result.new_line


def test_fix_debug_true_line():
    result = fix_debug_true("app.run(debug=True)")
    assert result is not None and "debug=False" in result.new_line
