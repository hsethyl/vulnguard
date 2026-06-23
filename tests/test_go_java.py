from vulnguard.fixers.line_fixes import fix_insecure_skip_verify
from vulnguard.scanner.go_scanner import scan_go_source
from vulnguard.scanner.java_scanner import scan_java_source


def _go(src: str) -> set[str]:
    return {f.rule_id for f in scan_go_source(src, "f.go")}


def _java(src: str) -> set[str]:
    return {f.rule_id for f in scan_java_source(src, "F.java")}


# --- Go ---

def test_go_command_injection():
    assert "GO001" in _go('exec.Command("sh", "-c", userInput)')


def test_go_safe_command_not_flagged():
    assert "GO001" not in _go('exec.Command("ls", "-la")')


def test_go_sql_injection():
    assert "GO002" in _go('db.Query(fmt.Sprintf("SELECT * FROM t WHERE id=%s", id))')


def test_go_parameterized_query_safe():
    assert "GO002" not in _go('db.Query("SELECT * FROM t WHERE id=$1", id)')


def test_go_weak_hash():
    assert "GO003" in _go("h := md5.New()")


def test_go_insecure_skip_verify():
    assert "GO004" in _go("tls.Config{InsecureSkipVerify: true}")


def test_go_clean_no_findings():
    assert _go("package main\nfunc main() {}") == set()


def test_fix_insecure_skip_verify_line():
    result = fix_insecure_skip_verify("tls.Config{InsecureSkipVerify: true}")
    assert result is not None and "InsecureSkipVerify: false" in result.new_line


# --- Java ---

def test_java_command_injection():
    assert "JAVA001" in _java('Runtime.getRuntime().exec(cmd);')


def test_java_sql_injection():
    assert "JAVA002" in _java('stmt.executeQuery("SELECT * FROM t WHERE id=" + id);')


def test_java_weak_hash():
    assert "JAVA003" in _java('MessageDigest.getInstance("MD5");')


def test_java_insecure_deserialization():
    assert "JAVA004" in _java("ObjectInputStream in = new ObjectInputStream(s);")


def test_java_clean_no_findings():
    assert _java("class A { int x = 1; }") == set()
