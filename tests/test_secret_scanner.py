from vulnguard.scanner.secret_scanner import scan_secrets_in_text


def _rule_ids(text: str) -> set[str]:
    return {f.rule_id for f in scan_secrets_in_text(text, "f.py")}


def test_detects_aws_key():
    assert "SEC002" in _rule_ids('key = "AKIAIOSFODNN7EXAMPLE"')


def test_detects_private_key_header():
    assert "SEC001" in _rule_ids("-----BEGIN RSA PRIVATE KEY-----")


def test_detects_sk_api_key():
    assert "SEC003" in _rule_ids('k = "sk-abcdefghijklmnopqrstuvwxyz0123"')


def test_detects_github_token():
    assert "SEC004" in _rule_ids('t = "ghp_0123456789abcdefghijklmnopqrstuvwx"')


def test_detects_hardcoded_password_high_entropy():
    assert "SEC006" in _rule_ids('password = "G7$kq9Lm2Zx!pw"')


def test_placeholder_password_not_flagged():
    assert "SEC006" not in _rule_ids('password = "changeme"')


def test_env_reference_not_flagged():
    assert "SEC006" not in _rule_ids('password = os.environ["DB_PASSWORD"]')


def test_short_value_not_flagged():
    assert "SEC006" not in _rule_ids('pwd = "abc"')
