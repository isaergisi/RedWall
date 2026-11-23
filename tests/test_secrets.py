from redwall.engines.secrets import redact, shannon_entropy
from redwall.scanner import ScanOptions, scan

# Built at runtime so no real-looking secret is ever committed to the repo.
AWS = "AKIA" + "Q3EGRTZ7XJ5LN2WP"
GITHUB = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
PEM = "-----BEGIN " + "RSA PRIVATE KEY-----"


def _scan(tmp_path, name, text):
    (tmp_path / name).write_text(text)
    return scan(tmp_path, options=ScanOptions(engines=["secrets"])).findings


def test_specific_token_patterns(tmp_path):
    findings = _scan(tmp_path, "config.env", f"AWS_KEY={AWS}\nTOKEN={GITHUB}\n{PEM}\n")
    assert [(f.rule_id, f.line) for f in findings] == [
        ("RW-SECRET-AWS", 1), ("RW-SECRET-GITHUB", 2), ("RW-SECRET-PRIVATE-KEY", 3)]


def test_secrets_are_redacted_everywhere(tmp_path):
    findings = _scan(tmp_path, "settings.py", f'aws = "{AWS}"\n')
    [f] = findings
    assert AWS not in f.snippet and AWS not in f.message
    assert f.snippet.startswith('aws = "AKIA')


def test_generic_password_needs_entropy_and_no_placeholder(tmp_path):
    findings = _scan(tmp_path, "app.py", "\n".join([
        'password = "Xk9#mQ2$vL7!pR4z"',  # redwall: ignore[RW-SECRET-GENERIC] (test data)
        'password = "changeme123"',
        'api_key = "your-api-key-here"',
        'password = "aaaaaaaaaaaa"',
        'token = os.environ["TOKEN"]',
    ]))
    assert [(f.rule_id, f.line) for f in findings] == [("RW-SECRET-GENERIC", 1)]


def test_lockfiles_are_skipped(tmp_path):
    assert _scan(tmp_path, "package-lock.json", f'"x": "{AWS}"') == []


def test_helpers():
    assert shannon_entropy("aaaa") == 0
    assert shannon_entropy("abcd") == 2
    assert redact("supersecretvalue") == "supe********"
