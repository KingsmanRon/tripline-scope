"""How accounts and free text appear in reports, attachments and scope-candidates.

Accounts are always given a stable, case-keyed reference (``ACCT-...``). The readable label is shown only for
names that cannot be patient identifiers: ``DOMAIN\\user`` and plain logins, and UPNs in the hospital's own
``directory_domains`` (shown as ``user (domain account)``). Every other e-mail-shaped name (for example a
patient-portal login) is pseudonymised. Text that still looks identifier-like after scrubbing is replaced.
"""

from __future__ import annotations

from tripline_scope.core.redact import find_identifier_like, scrub_text


class Display:
    def __init__(self, store, directory_domains: list[str]):
        self._fp = store.fingerprinter("paths-account")
        self._dirdom = {d.lower() for d in directory_domains}

    def ref(self, account: str | None) -> str | None:
        if not account:
            return None
        return "ACCT-" + self._fp(account.strip().lower())[:10]

    def label(self, account: str | None) -> str | None:
        if not account:
            return None
        a = account.strip()
        if "@" in a:
            local, _, domain = a.partition("@")
            if domain.lower() in self._dirdom:
                text = f"{local} ({domain.lower()} account)"
            else:
                return "pseudonymised e-mail-shaped account"
        else:
            text = a
        text = scrub_text(text)[:80]
        if find_identifier_like(text) or "[redacted]" in text:
            return "pseudonymised account"
        return text

    def account(self, account: str | None) -> dict | None:
        if not account:
            return None
        return {"account_ref": self.ref(account), "label": self.label(account)}

    def accounts(self, accounts) -> list[dict]:
        out = {}
        for a in accounts or []:
            d = self.account(a)
            if d:
                out[d["account_ref"]] = d
        return [out[k] for k in sorted(out)]


def safe_text(value, limit: int = 200) -> str | None:
    if value is None:
        return None
    t = scrub_text(str(value))[:limit]
    return "[redacted]" if find_identifier_like(t) else t
