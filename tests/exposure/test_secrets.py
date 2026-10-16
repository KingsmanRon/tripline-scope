"""A1 detector: provider formats, structural rules, key-name rule, false positives, fixtures and redaction.

Every secret-shaped value is generated at runtime; none is committed.
"""

import base64
import random
import string

import pytest

from tripline_scope.exposure.secrets import (
    Lines,
    detect,
    entropy,
    is_test_fixture_path,
    key_family,
    location_likelihood,
    redacted_context,
)

R = random.Random(99)


def rnd(alphabet, n):
    return "".join(R.choice(alphabet) for _ in range(n))


AN = string.ascii_letters + string.digits


def live(text, name):
    return [c for c in detect(text, name) if not c.suppressed]


@pytest.mark.parametrize("make,name,rule", [
    (lambda: f"aws_secret_access_key = {rnd(AN + '/+', 40)}\n", "credentials", "A1.aws-secret-key"),
    (lambda: f"key_id={'AKIA' + rnd('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', 16)}\n", "x.txt", "A1.aws-access-key-id"),
    (lambda: f"DefaultEndpointsProtocol=https;AccountName=lab;AccountKey={rnd(AN + '+/', 86)}==;\n", "a.config",
     "A1.azure-storage-key"),
    (lambda: f"https://st.blob.core.windows.net/c?sv=2024-05-04&ss=b&sig={rnd(AN, 44)}%3D\n", "x.txt",
     "A1.azure-sas-signature"),
    (lambda: f"token: ghp_{rnd(AN, 36)}\n", "ci.yml", "A1.github-token"),
    (lambda: f"SLACK=xoxb-{rnd(string.digits, 12)}-{rnd(AN, 24)}\n", "a.ini", "A1.slack-token"),
    (lambda: f"hook = https://hooks.slack.com/services/T{rnd(string.ascii_uppercase, 8)}/B{rnd(string.ascii_uppercase, 8)}/{rnd(AN, 24)}\n",
     "a.ini", "A1.slack-webhook"),
    (lambda: f"STRIPE={'sk_' + 'live_' + rnd(AN, 24)}\n", "a.env", "A1.stripe-key"),
    (lambda: f'k="AIza{rnd(AN + "_-", 35)}"\n', "b.js", "A1.google-api-key"),
    (lambda: f"SG.{rnd(AN, 22)}.{rnd(AN, 43)}\n", "mail.cfg", "A1.sendgrid-key"),
    (lambda: '<machineKey validationKey="' + rnd("0123456789ABCDEF", 64) + '" />', "web.config", "A1.aspnet-machine-key"),
    (lambda: 'Authorization: Basic ' + base64.b64encode(f"svc:{rnd(AN, 14)}".encode()).decode() + "\n", "h.conf",
     "A1.basic-auth-header"),
    (lambda: f"sqlcmd -S DB1 -U sa -P {rnd(AN, 12)} -Q x\n", "job.bat", "A1.cli-password"),
    (lambda: f'$p = ConvertTo-SecureString "{rnd(AN, 12)}" -AsPlainText -Force\n', "s.ps1", "A1.powershell-plaintext"),
    (lambda: f"DATABASE_URL=postgres://app:{rnd(AN, 14)}@db.hosp.example:5432/pathdb\n", ".env", "A1.url-credentials"),
    (lambda: f'conn = "Server=LAB;Database=LabDB;User Id=app;Password={rnd(AN, 12)};"\n', "Repo.cs",
     "A1.db-connection-password"),
    (lambda: f"<?php define('DB_PASSWORD', '{rnd(AN, 12)}');\n", "wp-config.php", "A1.generic-password"),
    (lambda: f'SECRET_KEY = "{rnd(AN + "!@#", 40)}"\n', "settings.py", "A1.generic-secret"),
    (lambda: f'fastcgi_param DB_PASSWORD {rnd(AN, 12)};\n', "site.conf", "A1.generic-password"),
    (lambda: f'{{"api_key": "{rnd(AN, 32)}"}}\n', "cfg.json", "A1.generic-secret"),
])
def test_true_positives(make, name, rule):
    text = make()
    rules = {c.rule_id for c in live(text, name)}
    assert rule in rules, (rule, rules)


def test_private_keys():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    k = Ed25519PrivateKey.generate()
    pem = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                          serialization.NoEncryption()).decode()
    c = live(pem, "id_ed25519")
    assert [x.family for x in c] == ["private-key"]
    enc = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                          serialization.BestAvailableEncryption(b"synthetic-pass")).decode()
    assert [x.family for x in live(enc, "id_enc")] == ["private-key-encrypted"]
    doc = "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"
    assert not live(doc, "README.md")


@pytest.mark.parametrize("text,name", [
    ("password = ${DB_PASSWORD}\n", "app.ini"),
    ("DB_PASSWORD=changeme\n", ".env"),
    ("api_key: your_api_key_here\n", "cfg.yml"),
    ("password: %DB_PASS%\n", "cfg.yml"),
    ('{"password": "{{ vault_db_password }}"}', "cfg.json"),
    ("password=@Microsoft.KeyVault(SecretUri=https://kv.vault.azure.net/secrets/db)\n", "app.settings"),
    ('const p = {password: e.value, token: t, passwordField: "#pwd"};\n', "login.js"),
    ("var o={secret:o.secret,tokenUrl:\"/oauth/token\",authMode:\"pkce\"};", "bundle.min.js"),
    ('integrity="sha384-' + "a" * 10 + 'Bc9xYz0" password_min_length=12\n', "index.html"),
    ("PasswordMinLength = 12\nPasswordExpiryDays = 90\npassword_policy = strict\n", "policy.ini"),
    ("token = true\nsecret = false\n", "flags.ini"),
    ("password: Enter your password to continue to the portal\n", "messages.yml"),
    ("password_file = /etc/app/db.pass\n", "app.ini"),
    ("aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n", "README.md"),
    ("accession_no=8001015009081\nref=1234567890123\n", "data.ini"),
    ("compass = north\nbypass = true\n", "misc.ini"),
    ("SECRET_KEY = os.environ.get('SECRET_KEY')\n", "settings.py"),
    ("if password == 'x': pass\n", "check.py"),
])
def test_false_positives_suppressed(text, name):
    assert not live(text, name), [(c.rule_id, c.suppressed) for c in detect(text, name)]


def test_stripe_test_mode_key_suppressed():
    text = f'k="sk_{"test"}_{rnd(AN, 24)}"\n'
    cs = detect(text, "a.js")
    assert cs and all(c.suppressed == "test-mode provider key" for c in cs)


def test_low_entropy_token_suppressed_but_weak_password_kept():
    assert not live('api_token = "aaaaaaaaaaaaaaaa"\n', "a.ini")
    weak = live("db_password = Summer2026\n", "a.ini")
    assert weak and weak[0].family == "password"


def test_overlap_prefers_specific_rule():
    tok = "ghp_" + rnd(AN, 36)
    cs = live(f"url = https://bot:{tok}@git.example/x.git\n", "config")
    assert [c.rule_id for c in cs] == ["A1.github-token"]


def test_connection_string_target_parsed():
    pw = rnd(AN, 12)
    cs = live(f'<add connectionString="Data Source=LABSQL01\\PROD,1433;Initial Catalog=LabDB;User ID=lab_app;Password={pw}" />',
              "web.config")
    c = cs[0]
    assert c.rule_id == "A1.db-connection-password"
    assert c.target == {"server": "LABSQL01\\PROD,1433", "database": "LabDB", "user": "lab_app"}


def test_redacted_context_never_contains_values():
    pw, key, other = rnd(AN, 14), "AIza" + rnd(AN, 35), rnd("0123456789abcdef", 40)
    text = (f'{{a:"Server=LAB;Database=X;User ID=u;Password={pw};",k:"{key}","x-api-key":"{other}",'
            f'note:"untracked {rnd(AN, 30)}"}}')
    cs = detect(text, "bundle.js")
    lines = Lines(text)
    for c in cs:
        ctx = redacted_context(text, lines, c, cs)
        for v in (pw, key, other):
            assert v not in ctx
        assert "«redacted:" in ctx or ctx == "«context withheld»"


def test_minified_bundle_context_is_bounded():
    key = "AIza" + rnd(AN, 35)
    text = "var a=1;" * 20000 + f'k:"{key}"' + ";var b=2" * 20000
    cs = live(text, "app.min.js")
    ctx = redacted_context(text, Lines(text), cs[0], cs)
    assert len(ctx) <= 240 and key not in ctx


def test_test_fixture_paths():
    assert is_test_fixture_path("app/tests/fixtures/web.config")
    assert is_test_fixture_path("config/.env.example")
    assert is_test_fixture_path("src/settings.test.js")
    assert is_test_fixture_path("archive.zip!examples/app.ini")
    assert not is_test_fixture_path("wwwroot/web.config")
    assert not is_test_fixture_path("deploy/latest/settings.py")


def test_key_family_and_entropy_and_likelihood():
    assert key_family("DbPassword") == "password"
    assert key_family("x-api-key") == "secret"
    assert key_family("passwordField") is None and key_family("tokenUrl") is None
    assert key_family("APP_KEY") == "signing-key"
    assert entropy("aaaa") == 0 and entropy(rnd(AN, 64)) > 5
    assert location_likelihood("web_root", "wwwroot/js/app.min.js")[0] == "high"
    assert location_likelihood("web_root", "wwwroot/web.config")[0] == "medium"
    assert location_likelihood("web_root", "wwwroot/App_Data/x.json")[0] == "medium"
    assert location_likelihood("config", "nginx/nginx.conf")[0] == "low"


def test_trailing_comment_is_not_prose():
    pw = rnd(AN, 12)
    cs = live(f"DB_PASSWORD={pw}   # production database, rotate yearly\n", ".env")
    assert [c.rule_id for c in cs] == ["A1.generic-password"]
