from vulnguard.scanner.python_scanner import scan_python_source


def _rule_ids(source: str) -> set[str]:
    return {f.rule_id for f in scan_python_source(source, "test.py")}


def test_detects_eval():
    assert "PY001" in _rule_ids("x = eval(user_input)")


def test_detects_exec():
    assert "PY002" in _rule_ids("exec(code)")


def test_detects_os_system():
    assert "PY003" in _rule_ids("import os\nos.system('ls ' + path)")


def test_detects_subprocess_shell_true():
    src = "import subprocess\nsubprocess.run(cmd, shell=True)"
    assert "PY004" in _rule_ids(src)


def test_subprocess_shell_false_is_safe():
    src = "import subprocess\nsubprocess.run(['ls', path], shell=False)"
    assert "PY004" not in _rule_ids(src)


def test_detects_pickle_loads():
    assert "PY005" in _rule_ids("import pickle\npickle.loads(data)")


def test_detects_yaml_load_unsafe():
    assert "PY006" in _rule_ids("import yaml\nyaml.load(stream)")


def test_yaml_safe_load_is_safe():
    assert "PY006" not in _rule_ids("import yaml\nyaml.safe_load(stream)")


def test_yaml_load_with_safe_loader_is_safe():
    src = "import yaml\nyaml.load(stream, Loader=yaml.SafeLoader)"
    assert "PY006" not in _rule_ids(src)


def test_detects_weak_hash():
    assert "PY007" in _rule_ids("import hashlib\nh = hashlib.md5(b'x')")


def test_detects_sql_injection_fstring():
    src = "cursor.execute(f'SELECT * FROM t WHERE id = {uid}')"
    assert "PY008" in _rule_ids(src)


def test_detects_sql_injection_concat():
    src = "cursor.execute('SELECT * FROM t WHERE id = ' + uid)"
    assert "PY008" in _rule_ids(src)


def test_parameterized_query_is_safe():
    src = "cursor.execute('SELECT * FROM t WHERE id = ?', (uid,))"
    assert "PY008" not in _rule_ids(src)


def test_clean_code_has_no_findings():
    src = "def add(a, b):\n    return a + b\n"
    assert _rule_ids(src) == set()


def test_syntax_error_reported_not_raised():
    findings = scan_python_source("def (:\n", "bad.py")
    assert any(f.rule_id == "PY000" for f in findings)
