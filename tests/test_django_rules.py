from vulnguard.fixers.line_fixes import fix_autoescape_false
from vulnguard.scanner.python_scanner import scan_python_source


def _py(source: str) -> set[str]:
    return {f.rule_id for f in scan_python_source(source, "settings.py")}


def test_detects_hardcoded_secret_key():
    assert "DJ001" in _py('SECRET_KEY = "django-insecure-abc123xyz"')


def test_secret_key_from_env_is_safe():
    assert "DJ001" not in _py('SECRET_KEY = os.environ["SECRET_KEY"]')


def test_detects_allowed_hosts_wildcard():
    assert "DJ002" in _py("ALLOWED_HOSTS = ['*']")


def test_allowed_hosts_explicit_is_safe():
    assert "DJ002" not in _py("ALLOWED_HOSTS = ['example.com', 'www.example.com']")


def test_detects_debug_true_assignment():
    assert "DJ003" in _py("DEBUG = True")


def test_debug_false_is_safe():
    assert "DJ003" not in _py("DEBUG = False")


def test_detects_autoescape_false():
    src = "from jinja2 import Environment\nenv = Environment(autoescape=False)"
    assert "PY013" in _py(src)


def test_detects_bind_all_interfaces():
    assert "PY014" in _py('app.run(host="0.0.0.0")')


def test_fix_autoescape_false_line():
    result = fix_autoescape_false("Environment(autoescape=False)")
    assert result is not None and "autoescape=True" in result.new_line
