"""A1: plaintext secret detection in snapshot files (configs, scripts, repositories, bundled JavaScript).

Detection combines provider-specific formats (fixed prefixes, lengths, alphabets), structural rules (PEM private
keys, credentials in URLs and connection strings, ASP.NET machine keys, HTTP Basic headers, command-line password
flags) and a key-name rule (``password = ...``, ``"apiKey": "..."``) gated by placeholder, variable-reference,
entropy and file-type checks. Obvious test fixtures, documentation examples and test-mode provider keys are
suppressed and counted.

A secret value is held only transiently: each candidate becomes a keyed, case-local fingerprint
(``Keys.secret``) and a redacted context in which every detected value and any other high-entropy token is
replaced. The value itself never reaches a finding, a log, the audit log or a report. Nothing here
authenticates with, validates or transmits a found credential.
"""

from __future__ import annotations

import base64
import binascii
import bisect
import json
import math
import re
from collections import Counter
from dataclasses import dataclass, field

from tripline_scope.core.redact import scrub_text

from .filetypes import CODE_EXT, PUBLIC_WEB_EXT, SERVER_SIDE_EXT, SERVER_SIDE_NAMES, basename, ext_of

DETECTOR = "exposure.secrets/0.1.0"

# ------------------------------------------------------------------------------------------ helpers


def entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


_PLACEHOLDER_RE = re.compile(
    r"(?i)^(\$\{[^}]*\}|\$\(?[A-Za-z_][A-Za-z0-9_]*\)?|%[A-Za-z_][A-Za-z0-9_]*%|\{\{.*\}\}|<[^<>]*>|\[[^\]]*\]|"
    r"#\{[^}]*\}|@[A-Za-z_]+@|__[A-Z0-9_]+__|\(\s*\)|x+|\*+|\.+|-+|_+|0+|#+|•+)$")
_PLACEHOLDER_WORDS = {
    "password", "passwd", "pass", "pwd", "secret", "changeme", "change_me", "change-me", "xxx", "xxxx", "none", "null",
    "nil", "true", "false", "undefined", "test", "testing", "example", "sample", "dummy", "placeholder", "default",
    "todo", "tbd", "n/a", "na", "empty", "blank", "value", "string", "str", "redacted", "hidden", "masked",
    "mypassword", "yourpassword", "your_password", "your-password", "secretkey", "mysecret", "token", "apikey",
    "api_key", "key", "required", "optional", "notset", "not_set", "unset", "foo", "bar", "foobar", "abc", "abc123",
    "password123", "letmein", "qwerty", "hunter2", "secret123", "test123", "bool", "boolean", "number", "int", "any",
    "object", "function", "self", "this", "env", "environment", "config", "settings",
}
_PLACEHOLDER_SUBSTR = ("changeme", "change_me", "change-me", "your_", "your-", "yourpass", "example", "placeholder",
                       "dummy", "replace_", "replace-", "replaceme", "redacted", "xxxxx", "*****", "insert_",
                       "enter_", "<", ">", "notreal", "not-a-real", "not_a_real", "fake", "sample", "lorem")
_REFERENCE_SUBSTR = ("process.env", "os.environ", "getenv", "env(", "env[", "config(", "configuration[",
                     "system.getenv", "@microsoft.keyvault", "keyvault", "vault:", "vault://", "secret://",
                     "arn:aws:secretsmanager", "arn:aws:ssm", "secrets.", "ssm:", "{{", "}}", "${", "%(", "$(",
                     "environment.", "settings.", "context.", "request.", "params.", "props.", "this.", "self.",
                     "args.", "input(", "prompt(", "read-host")
_FILEPATH_RE = re.compile(r"(?i)^(/|[a-z]:\\|\\\\|\./|\.\./|~/)|\.(pem|key|txt|json|ya?ml|cfg|conf|p12|pfx|crt|jks)$")
_TEST_DIRS = {"test", "tests", "__tests__", "spec", "specs", "fixture", "fixtures", "testdata", "test-data",
              "test_data", "mocks", "mock", "__mocks__", "examples", "example", "samples", "sample", "stubs", "testing"}
_TEST_FILE = re.compile(r"(?i)(\.(example|sample|template|tmpl|dist|default)$|^\.env\.(example|sample|template|dist)$|"
                        r"^(test|spec)[._-]|[._-](test|spec)\.[a-z0-9]+$|\.(test|spec)\.[a-z0-9]+$)")
_NON_SECRET_TOKENS = {
    "url", "uri", "endpoint", "path", "file", "filename", "dir", "directory", "name", "type", "mode", "length", "len",
    "policy", "format", "expiry", "expires", "expiration", "expire", "timeout", "ttl", "header", "field", "label",
    "hint", "required", "enabled", "enable", "disabled", "min", "max", "minimum", "maximum", "regex", "pattern",
    "count", "version", "prompt", "reset", "strength", "algorithm", "algo", "id", "provider", "manager", "rotation",
    "age", "change", "confirm", "confirmation", "input", "placeholder", "text", "message", "msg", "error", "errors",
    "validator", "validation", "size", "limit", "lifetime", "location", "ref", "reference", "env", "var", "variable",
    "param", "parameter", "attempts", "retries", "complexity", "history", "display", "show", "visible", "encoder",
    "encoding", "rounds", "iterations", "method", "scheme", "callback", "redirect", "template", "flag", "mask",
    "icon", "class", "style", "color", "title", "tooltip", "aria", "store", "storage", "hash", "hashed", "digest",
    "used", "last", "changed", "updated", "created", "date", "time", "forgot", "forgotten", "recovery", "recover",
    "verify", "verification", "check", "checker", "generator", "generate", "toggle", "button", "btn", "form", "link",
    "page", "route", "view", "modal", "dialog", "screen", "state", "status", "strategy", "source", "schema", "table",
    "column", "col", "index", "query", "event", "events", "handler", "listener", "rule", "rules", "help",
    "description", "desc", "doc", "docs", "lookup", "map", "list", "kind", "keyword", "pass_through", "passthrough",
    "bypass", "passenger", "compass", "is", "has", "should", "can", "get", "set", "on", "use", "need", "needs",
    "new", "old", "current", "repeat", "again", "strong", "weak", "valid", "invalid",
    "chars", "characters", "types", "regexp", "tokens", "tokenizer", "tokenize", "csrf", "xsrf", "refresh_url",
}
_KW = re.compile(r"(?i)(pass(?:word|wd|phrase)?|pwd|secret|token|api[_\-.]?key|apikey|access[_\-.]?key|"
                 r"private[_\-.]?key|signing[_\-.]?key|encryption[_\-.]?key|app[_\-.]?key|auth[_\-.]?key|"
                 r"master[_\-.]?key|credentials?|salt)")
_IDENT_CH = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-")
_SPLIT = re.compile(r"[^A-Za-z0-9]+|(?<=[a-z0-9])(?=[A-Z])")
_CONN_CTX = re.compile(r"(?i)(\bserver|data source|\bhost|\baddress|initial catalog|\bdatabase|\bdbname|jdbc:|"
                       r"provider\s*=|\bdsn)\s*[=:]")
_SERVER = re.compile(r"(?i)(?:^|[;\s\"'])(?:server|data source|host|address|addr|network address)\s*=\s*([^;\"'<>\s]+)")
_DBNAME = re.compile(r"(?i)(?:^|[;\s\"'])(?:database|initial catalog|dbname)\s*=\s*([^;\"'<>\s]+)")
_USER = re.compile(r"(?i)(?:^|[;\s\"'])(?:user id|uid|user|username|login)\s*=\s*([^;\"'<>\s]+)")
_HIGH_ENTROPY_TOKEN = re.compile(r"[A-Za-z0-9+/=_\-]{20,}")
_DIRECTIVE = re.compile(r"(?i)\b(SetEnv|fastcgi_param|uwsgi_param|env)\s+$")
_DB_SCHEMES = {"postgres", "postgresql", "mysql", "mariadb", "mssql", "sqlserver", "mongodb", "mongodb+srv", "redis",
               "rediss", "oracle", "jdbc", "odbc", "db2", "cockroachdb", "clickhouse", "amqp", "amqps"}

FAMILY_TITLES = {
    "private-key": "Unencrypted private key in plaintext",
    "private-key-encrypted": "Encrypted private key stored with application files",
    "cloud-key": "Cloud provider secret key in plaintext",
    "cloud-key-id": "Cloud access key identifier in plaintext",
    "db-credential": "Plaintext database credential",
    "password": "Plaintext password",
    "secret": "Plaintext API secret or token",
    "api-token": "Plaintext provider API token",
    "signing-key": "Plaintext signing or encryption key",
    "session-token": "Hard-coded bearer/session token",
    "password-hash": "Password hash stored with application files",
}
FAMILY_IMPACT = {
    "private-key": "high", "private-key-encrypted": "medium", "cloud-key": "high", "cloud-key-id": "low",
    "db-credential": "medium", "password": "medium", "secret": "medium", "api-token": "medium",
    "signing-key": "high", "session-token": "medium", "password-hash": "low",
}
_GENERIC_RULE = {"password": "A1.generic-password", "secret": "A1.generic-secret",
                 "signing-key": "A1.generic-signing-key"}
FAMILY_FIX = {"signing-key": "rotate-signing-key", "private-key": "rotate-signing-key",
              "private-key-encrypted": "rotate-signing-key"}


def key_tokens(key: str) -> list[str]:
    return [t.lower() for t in _SPLIT.split(key) if t]


def key_family(key: str) -> str | None:
    toks = key_tokens(key)
    if not toks:
        return None
    joined = "".join(toks)
    if any(t in _NON_SECRET_TOKENS for t in toks):
        return None
    if "connectionstring" in joined or "connstr" in joined:
        return None
    if any(t in ("password", "passwd", "pwd", "pass", "passphrase", "passw") for t in toks) or any(
            x in joined for x in ("password", "passwd", "passphrase")):
        return "password"
    if ("secret" in joined or "token" in toks or joined.endswith("token") or "apikey" in joined
            or "accesskey" in joined or "privatekey" in joined or "credential" in joined or "authkey" in joined
            or "masterkey" in joined or toks[-1] == "salt"):
        return "secret"
    if "signingkey" in joined or "encryptionkey" in joined or "appkey" in joined:
        return "signing-key"
    return None


def is_placeholder(value: str) -> bool:
    v = value.strip()
    lv = v.lower()
    if not v or _PLACEHOLDER_RE.match(v) or lv in _PLACEHOLDER_WORDS:
        return True
    if len(set(lv)) <= 2 and len(lv) >= 3:
        return True
    return any(s in lv for s in _PLACEHOLDER_SUBSTR)


def is_reference(value: str) -> bool:
    lv = value.lower()
    return any(s in lv for s in _REFERENCE_SUBSTR)


def is_test_fixture_path(rel: str) -> bool:
    parts = [p for p in re.split(r"[/!]", rel) if p]
    if any(p.lower() in _TEST_DIRS for p in parts[:-1]):
        return True
    return bool(parts) and bool(_TEST_FILE.search(parts[-1]))


def _b64_basic_ok(v: str) -> bool:
    try:
        raw = base64.b64decode(v + "=" * (-len(v) % 4), validate=True)
    except (binascii.Error, ValueError):
        return False
    try:
        s = raw.decode("utf-8")
    except UnicodeDecodeError:
        return False
    user, sep, pw = s.partition(":")
    return bool(sep) and bool(user) and len(pw) >= 3 and not is_placeholder(pw)


def _jwt_ok(v: str) -> bool:
    head = v.split(".", 1)[0]
    try:
        doc = json.loads(base64.urlsafe_b64decode(head + "=" * (-len(head) % 4)))
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return False
    return isinstance(doc, dict) and ("alg" in doc or "typ" in doc)


# ------------------------------------------------------------------------------------------ candidates
@dataclass
class Candidate:
    rule_id: str
    family: str
    start: int
    end: int
    value: str
    confidence: float
    key: str | None = None
    priority: int = 0
    suppressed: str | None = None
    target: dict = field(default_factory=dict)
    title: str | None = None


@dataclass
class _Rule:
    rule_id: str
    family: str
    rx: re.Pattern
    group: int
    confidence: float
    priority: int = 50
    validator: object = None
    context: re.Pattern | None = None   # must occur on the same line
    title: str | None = None


_RULES = [
    _Rule("A1.aws-secret-key", "cloud-key",
          re.compile(r"(?i)aws_?secret_?access_?key[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"),
          1, 0.95, 90, title="AWS secret access key in plaintext"),
    _Rule("A1.aws-access-key-id", "cloud-key-id", re.compile(r"(?<![A-Z0-9])((?:AKIA|ASIA)[A-Z2-7]{16})(?![A-Z0-9])"),
          1, 0.9, 80, title="AWS access key identifier in plaintext"),
    _Rule("A1.azure-storage-key", "cloud-key", re.compile(r"(?i)AccountKey=([A-Za-z0-9+/]{86}==)"), 1, 0.95, 90,
          title="Azure storage account key in plaintext"),
    _Rule("A1.azure-sas-signature", "cloud-key", re.compile(r"[?&;]sig=([A-Za-z0-9%+/=]{40,120})"), 1, 0.8, 85,
          context=re.compile(r"[?&;]sv=\d{4}-\d{2}-\d{2}"), title="Azure shared access signature in plaintext"),
    _Rule("A1.github-token", "api-token",
          re.compile(r"(?<![A-Za-z0-9_])(gh[pousr]_[A-Za-z0-9]{36,251}|github_pat_[A-Za-z0-9_]{50,251})(?![A-Za-z0-9_])"),
          1, 0.95, 90, title="GitHub access token in plaintext"),
    _Rule("A1.slack-token", "api-token", re.compile(r"(?<![A-Za-z0-9])(xox[abposr]-[A-Za-z0-9-]{10,200})"), 1, 0.9, 90,
          title="Slack token in plaintext"),
    _Rule("A1.slack-webhook", "api-token",
          re.compile(r"https://hooks\.slack\.com/services/(T[A-Z0-9]{6,}/B[A-Z0-9]{6,}/[A-Za-z0-9]{20,})"), 1, 0.9, 90,
          title="Slack incoming-webhook URL in plaintext"),
    _Rule("A1.stripe-key", "api-token",
          re.compile(r"(?<![A-Za-z0-9_])((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,99})(?![A-Za-z0-9])"), 1, 0.95, 90,
          title="Stripe secret key in plaintext"),
    _Rule("A1.google-api-key", "api-token",
          re.compile(r"(?<![A-Za-z0-9_\-])(AIza[0-9A-Za-z_\-]{35})(?![A-Za-z0-9_\-])"), 1, 0.9, 90,
          title="Google API key in plaintext"),
    _Rule("A1.sendgrid-key", "api-token",
          re.compile(r"(?<![A-Za-z0-9])(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})(?![A-Za-z0-9_\-])"), 1, 0.95, 90,
          title="SendGrid API key in plaintext"),
    _Rule("A1.jwt", "session-token",
          re.compile(r"(?<![A-Za-z0-9_\-])(eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{16,})"), 1, 0.8,
          70, validator=_jwt_ok, title="Hard-coded JSON Web Token"),
    _Rule("A1.aspnet-machine-key", "signing-key",
          re.compile(r"(?i)\b(?:validationKey|decryptionKey)\s*=\s*\"([0-9A-Fa-f]{32,256})\""), 1, 0.95, 90,
          title="ASP.NET machine key (validation/decryption) in plaintext"),
    _Rule("A1.basic-auth-header", "password", re.compile(r"(?i)\bbasic\s+([A-Za-z0-9+/]{8,}={0,2})(?![A-Za-z0-9+/=])"),
          1, 0.85, 75, validator=_b64_basic_ok, context=re.compile(r"(?i)authori[sz]ation"),
          title="HTTP Basic credentials in plaintext"),
    _Rule("A1.bearer-token", "session-token", re.compile(r"(?i)\bbearer\s+([A-Za-z0-9._\-~+/]{24,}=*)"), 1, 0.75, 60,
          validator=lambda v: entropy(v) >= 3.5, context=re.compile(r"(?i)authori[sz]ation"),
          title="Hard-coded bearer token"),
    _Rule("A1.htpasswd-hash", "password-hash",
          re.compile(r"(?m)^[A-Za-z0-9._@\-]{1,64}:(\$apr1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}|"
                     r"\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}|\{SHA\}[A-Za-z0-9+/]{27}=)[ \t]*\r?$"), 1, 0.9, 80,
          title="Password hash stored with web-server files"),
    _Rule("A1.cli-password", "password",
          re.compile(r"(?i)\b(?:sqlcmd|bcp|osql|mysql|mysqldump|psql|mongo|mongosh|mongodump|pg_dump)\b[^\n]{0,300}?"
                     r"(?:\s-P\s*|\s--password[= ])(['\"]?)([^\s'\"]{3,128})\1"), 2, 0.85, 85,
          title="Password passed on a command line in a script"),
    _Rule("A1.powershell-plaintext", "password",
          re.compile(r"(?i)ConvertTo-SecureString\s+(?:-String\s+)?([\"'])([^\"'\r\n]{3,200})\1\s+-AsPlainText"), 2,
          0.9, 85, title="Plaintext password converted to a SecureString in a script"),
    _Rule("A1.net-use-password", "password",
          re.compile(r"(?i)\bnet\s+use\s+\\\\[^\s]+\s+([\"']?)([^\s\"'/]{3,128})\1\s+/user:"), 2, 0.85, 85,
          title="Plaintext password in a 'net use' command"),
]
_PEM = re.compile(r"-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?)-----")
_URL = re.compile(r"(?i)\b([a-z][a-z0-9+.\-]{1,24})://([^\s:/@'\"<>(){}\[\]]{1,128}):([^\s/@'\"<>(){}\[\]]{1,256})@"
                  r"([A-Za-z0-9.\-_]{1,253})(?::(\d{1,5}))?(/[^\s'\"<>?#;]*)?")
_PHP_DEFINE = re.compile(r"(?i)\bdefine\(\s*['\"]([A-Za-z0-9_]{2,80})['\"]\s*,\s*(['\"])([^'\"\r\n]{1,300})\2\s*\)")


class Lines:
    def __init__(self, text: str):
        self.text = text
        self.starts = [0] + [m.end() for m in re.finditer("\n", text)]

    def pos(self, offset: int) -> tuple[int, int, int, int]:
        """(line number, column, line start, line end) for an offset."""
        i = bisect.bisect_right(self.starts, offset) - 1
        ls = self.starts[i]
        le = self.starts[i + 1] - 1 if i + 1 < len(self.starts) else len(self.text)
        return i + 1, offset - ls + 1, ls, le


_XML_VALUE = re.compile(r"(?i)\s+value\s*=\s*")


def _value_after_key(text: str, i: int, j: int, n: int, line_start: int) -> tuple[int, int, bool] | None:
    """Parse ``<separator> value`` after a key spanning ``[i, j)``. Returns (start, end, quoted) of the value."""
    k = j
    if k < n and text[k] in "\"'":
        k += 1
    while k < n and text[k] in " \t":
        k += 1
    if text.startswith("=>", k) or text.startswith(":=", k):
        k += 2
    elif k < n and text[k] == "=" and not text.startswith("==", k):
        k += 1
    elif k < n and text[k] == ":" and not text.startswith("::", k):
        k += 1
    else:
        m = _XML_VALUE.match(text, j + (1 if j < n and text[j] in "\"'" else 0))
        if m:  # <add key="DbPassword" value="..."/>
            k = m.end()
        elif not (k > j and _DIRECTIVE.search(text, max(line_start, i - 40), i)):
            return None  # otherwise "SetEnv KEY value" / "fastcgi_param KEY value;"
    while k < n and text[k] in " \t":
        k += 1
    if k >= n:
        return None
    if text[k] in "\"'`":
        q = text[k]
        e = text.find(q, k + 1, min(n, k + 502))
        if e == -1 or "\n" in text[k + 1:e]:
            return None
        return k + 1, e, True
    for opener, closer in (("${", "}"), ("$(", ")"), ("{{", "}}"), ("%(", ")")):
        if text.startswith(opener, k):  # unquoted variable reference: keep it whole so it is recognised as one
            e = text.find(closer, k + len(opener), min(n, k + 300))
            return (k, e + len(closer), False) if e != -1 else None
    e = k
    while e < n and e - k < 500 and text[e] not in " \t\r\n;,&<>\"'`(){}[]|":
        e += 1
    if e == k:
        return None
    return k, e, False


def detect(text: str, rel: str) -> list[Candidate]:
    """All secret candidates in ``text`` (suppressed ones carry a reason). Values are returned to the caller only
    so that it can fingerprint and redact them; callers must not store them."""
    ext = ext_of(rel)
    code = ext in CODE_EXT
    n = len(text)
    lines = Lines(text)
    out: list[Candidate] = []

    # --- private keys
    for m in _PEM.finditer(text):
        label = m.group(1)
        end_m = re.compile(r"-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----").search(text, m.end(), min(n, m.end() + 20000))
        body_end = end_m.start() if end_m else min(n, m.end() + 4000)
        body = text[m.end():body_end]
        b64 = re.sub(r"[^A-Za-z0-9+/=]", "", re.sub(r"(?m)^[A-Za-z\-]+:.*$", "", body))
        encrypted = "ENCRYPTED" in label or "ENCRYPTED" in body[:300]
        fam = "private-key-encrypted" if encrypted else "private-key"
        c = Candidate("A1.private-key", fam, m.end(), body_end, b64, 0.97, priority=100,
                      title=FAMILY_TITLES[fam])
        if len(b64) < 40:
            c.suppressed = "placeholder"
        out.append(c)

    # --- provider and structural rules
    for r in _RULES:
        for m in r.rx.finditer(text):
            v = m.group(r.group)
            s, e = m.start(r.group), m.end(r.group)
            ln, col, ls, le = lines.pos(s)
            if r.context is not None and not r.context.search(text, ls, le + 1):
                continue
            if r.validator is not None and not r.validator(v):
                continue
            c = Candidate(r.rule_id, r.family, s, e, v, r.confidence, priority=r.priority, title=r.title)
            if "EXAMPLE" in v or re.search(r"(?i)x{6,}", v):
                c.suppressed = "documentation example value"
            elif r.rule_id == "A1.stripe-key" and "_test_" in v:
                c.suppressed = "test-mode provider key"
            elif r.family == "password" and (is_placeholder(v) or is_reference(v)):
                c.suppressed = "placeholder or variable reference"
            if r.rule_id == "A1.cli-password":
                seg = text[m.start():m.end()]
                sm = re.search(r"\s-S\s*['\"]?([^\s'\"]+)", seg)
                um = re.search(r"\s-U\s*['\"]?([^\s'\"]+)", seg)
                c.target = {"server": sm.group(1) if sm else None, "database": None, "user": um.group(1) if um else None}
                c.family = "db-credential" if sm or um else "password"
            out.append(c)

    # --- credentials in URLs
    for m in _URL.finditer(text):
        scheme, user, pw, host = m.group(1).lower(), m.group(2), m.group(3), m.group(4)
        path = (m.group(6) or "").strip("/")
        fam = "db-credential" if scheme.split(":")[0] in _DB_SCHEMES or scheme.startswith("jdbc") else "password"
        c = Candidate("A1.url-credentials", fam, m.start(3), m.end(3), pw, 0.85, priority=70,
                      title="Credentials embedded in a URL")
        c.target = {"server": host, "database": path.split("/")[0] if path and fam == "db-credential" else None,
                    "user": user}
        if is_placeholder(pw) or is_reference(pw) or len(pw) < 3:
            c.suppressed = "placeholder or variable reference"
        out.append(c)

    # --- PHP define('DB_PASSWORD', '...')
    for m in _PHP_DEFINE.finditer(text):
        fam = key_family(m.group(1))
        if not fam:
            continue
        v = m.group(3)
        c = Candidate(_GENERIC_RULE[fam], fam, m.start(3), m.end(3), v, 0.75, key=m.group(1), priority=40)
        _gate_value(c, v, quoted=True, code=False)
        out.append(c)

    # --- key-name rule
    seen_keys: set[tuple[int, int]] = set()
    for m in _KW.finditer(text):
        i = m.start()
        while i > 0 and text[i - 1] in _IDENT_CH:
            i -= 1
        j = m.end()
        while j < n and text[j] in _IDENT_CH:
            j += 1
        if (i, j) in seen_keys:
            continue
        seen_keys.add((i, j))
        key = text[i:j].strip(".-")
        fam = key_family(key)
        if not fam:
            continue
        _, _, ls, _ = lines.pos(i)
        parsed = _value_after_key(text, i, j, n, ls)
        if not parsed:
            continue
        vs, ve, quoted = parsed
        v = text[vs:ve]
        c = Candidate(_GENERIC_RULE[fam], fam, vs, ve, v, 0.75 if fam == "password" else 0.7, key=key, priority=40)
        _, _, ls, le = lines.pos(vs)
        seg = text[max(ls, vs - 400): min(le, ve + 400)]
        in_conn = fam == "password" and bool(_CONN_CTX.search(seg))
        _gate_value(c, v, quoted=quoted or in_conn, code=code)
        if c.suppressed is None and fam == "password":
            if in_conn:
                c.rule_id, c.family, c.confidence = "A1.db-connection-password", "db-credential", 0.9
                c.title = "Plaintext database password in a connection string"
                sm, dm, um = _SERVER.search(seg), _DBNAME.search(seg), _USER.search(seg)
                c.target = {"server": sm.group(1) if sm else None, "database": dm.group(1) if dm else None,
                            "user": um.group(1) if um else None}
        out.append(c)

    return _resolve_overlaps(out)


def _gate_value(c: Candidate, v: str, *, quoted: bool, code: bool) -> None:
    sv = v.strip()
    if code and not quoted:
        c.suppressed = "unquoted identifier in code (variable, not a literal)"
    elif is_reference(sv):
        c.suppressed = "placeholder or variable reference"
    elif is_placeholder(sv):
        c.suppressed = "placeholder or variable reference"
    elif _FILEPATH_RE.search(sv):
        c.suppressed = "value is a file path or reference"
    elif sv.count(" ") >= 3:
        c.suppressed = "value is prose, not a secret"
    elif c.family == "password":
        if len(sv) < 4 or (sv.isdigit() and len(sv) < 6):
            c.suppressed = "too short to be a credential"
        elif entropy(sv) < 2.0:
            c.confidence = 0.6
    else:
        if len(sv) < 12 or entropy(sv) < 3.0:
            c.suppressed = "low entropy or too short for a token"
        elif re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", sv):
            c.confidence = 0.5
        elif re.fullmatch(r"\d+(\.\d+)*", sv):
            c.suppressed = "numeric value"


def _resolve_overlaps(cands: list[Candidate]) -> list[Candidate]:
    """Keep the highest-priority candidate where value spans overlap (specific rules beat the key-name rule)."""
    cands.sort(key=lambda c: (-c.priority, c.start, c.end))
    kept: list[Candidate] = []
    for c in cands:
        if any(c.start < k.end and k.start < c.end for k in kept):
            continue
        kept.append(c)
    kept.sort(key=lambda c: (c.start, c.end, c.rule_id))
    return kept


# ------------------------------------------------------------------------------------------ redaction
def _tokenish(t: str) -> bool:
    """Safety net for undetected secrets in a context line: random-looking tokens, not ordinary identifiers."""
    has_digit = any(ch.isdigit() for ch in t)
    has_alpha = any(ch.isalpha() for ch in t)
    return (has_digit and has_alpha and entropy(t) >= 3.3) or (len(t) >= 32 and entropy(t) >= 3.8)


def redacted_context(text: str, lines: Lines, focus: Candidate, spans: list[Candidate], *, width: int = 70) -> str:
    """The line around ``focus`` with every candidate value and any other high-entropy token replaced."""
    _, _, ls, le = lines.pos(focus.start)
    ws = max(ls, focus.start - width)
    we = min(le, focus.end + width // 2) if focus.family not in ("private-key", "private-key-encrypted") else min(
        le, focus.start)
    if focus.family in ("private-key", "private-key-encrypted"):
        ws = max(ls, focus.start - 64)
    parts, pos = [], ws
    for c in sorted((c for c in spans if c.start < max(we, focus.end) and c.end > ws), key=lambda c: c.start):
        s = max(c.start, ws)
        if s > pos:
            parts.append(text[pos:s])
        if c.start >= ws or c is focus:
            parts.append(f"«redacted:{c.family}»")
        pos = max(pos, c.end)
    if pos < we:
        parts.append(text[pos:we])
    ctx = "".join(parts)
    ctx = _HIGH_ENTROPY_TOKEN.sub(lambda m: "«redacted:token»" if _tokenish(m.group(0)) else m.group(0), ctx)
    ctx = scrub_text(re.sub(r"\s+", " ", ctx)).strip()
    if ws > ls:
        ctx = "..." + ctx
    if we < le:
        ctx = ctx + "..."
    for c in spans:
        if len(c.value) >= 4 and c.value in ctx:
            return "«context withheld»"
    return ctx[:240]


# ------------------------------------------------------------------------------------------ location exposure
def location_likelihood(root_kind: str, rel: str) -> tuple[str, str]:
    name = basename(rel).lower()
    ext = ext_of(rel)
    low = rel.lower()
    if root_kind == "web_root":
        hidden = any(seg in low for seg in ("app_data/", "/bin/", "web-inf/", "/private/"))
        if not hidden and (name == ".env" or ext in PUBLIC_WEB_EXT) and name not in SERVER_SIDE_NAMES:
            return "high", "static file under a web root: normally served to any client that requests the path"
        if name in SERVER_SIDE_NAMES or ext in SERVER_SIDE_EXT or hidden:
            return "medium", ("server-side file under a web root: not normally served, but exposed by misconfiguration, "
                              "source disclosure, backups or anyone with server access")
        return "medium", "file under a web root"
    if root_kind == "repository":
        return "medium", "repository content is copied to every clone and kept in history"
    if root_kind == "share":
        return "medium", "file share readable by internal users and service accounts"
    return "low", "configuration or script store limited to administrators"
