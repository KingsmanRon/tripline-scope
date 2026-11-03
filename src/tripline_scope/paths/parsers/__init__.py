"""Parser registry: family -> (module, version). Parsers are written from the public format documentation."""

from __future__ import annotations

from . import entra, finapp, generic, indicators, mssql, postgres, web, windows

REGISTRY = {
    "mssql_audit": mssql,
    "pg_log": postgres,
    "pgaudit": postgres,
    "iis": web,
    "apache": web,
    "nginx": web,
    "win_security": windows,
    "entra_signin": entra,
    "vpn": generic,
    "firewall": generic,
    "proxy": generic,
    "generic": generic,
    "indicators": indicators,
    "fin_app_audit": finapp,
    "bank_settlement": finapp,
}


def parser_name(family: str) -> str:
    return f"{family}/{REGISTRY[family].VERSION}"
