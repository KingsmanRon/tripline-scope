"""Module B analysis configuration: the ``paths:`` section of ``case.yaml`` merged over documented defaults.

Every value is an explicit, operator-visible assumption; the merged configuration is hashed into every
analysis, report and scope-candidates output (``config_sha256``).
"""

from __future__ import annotations

import copy
import fnmatch
import ipaddress
import re

from tripline_scope.core.canonical import canonical_bytes, sha256_hex
from tripline_scope.core.errors import ConfigError

DEFAULTS: dict = {
    # operator-declared sensitive tables (e.g. from the data map): "database.schema.table", wildcards allowed
    "sensitive_tables": [],
    # UPN domains of the hospital's own directory: accounts in these domains are named in containment advice;
    # every other e-mail-shaped account is shown only as a pseudonymous reference
    "directory_domains": [],
    "internal_networks": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "100.64.0.0/10",
                          "169.254.0.0/16", "fc00::/7", "fe80::/10", "::1/128"],
    "shared_ips": [],            # declared NAT/proxy/egress addresses shared by many users
    "correlation": {
        "signin_to_vpn_s": 300,          # identity sign-in -> VPN session, same account
        "vpn_lease_tolerance_s": 60,     # VPN-assigned address used just outside the session bounds
        "web_to_vpn_s": 3600,            # web request and VPN session from the same public address
        "web_to_db_s": 5,                # web request -> database session from the web server, no request id
        "host_logon_to_db_s": 900,       # Windows logon from an address -> database session from that address
        "data_to_egress_s": 3600,        # export/staging or read -> outbound flow from the same host
        "shared_ip_min_accounts": 2,     # distinct accounts behind one address that make it "shared"
        "unknown_clock_uncertainty_s": 120,   # assumed when a source documents no clock uncertainty
        "session_gap_s": 1800,           # database session id reused after this much silence
        "max_alternatives": 3,
    },
    "hospital_hours": None,      # {timezone: Africa/Johannesburg, weekdays: "07:00-18:00", saturday: ..., sunday: ...}
    "service_accounts": [],      # account patterns of applications/services (exempt from off-hours)
    "known_jobs": [],            # [{account, operations: [..], reason}] e.g. nightly imports
    "baseline": {"start": None, "end": None, "min_days": 3},
    "bulk_read": {"factor": 5.0, "min_rows": 1000},
    "web_admin_patterns": ["*/admin*", "*/manage*", "*/upload*", "*/wp-admin*", "*/phpmyadmin*", "*/console*",
                           "*/elmah*", "*/setup*"],
    "web_script_extensions": ["aspx", "ashx", "asmx", "asp", "php", "jsp", "jspx", "cgi", "pl", "cfm"],
    "staging_extensions": ["bak", "csv", "zip", "7z", "rar", "dmp", "sql", "bcp", "dat", "tar", "gz", "tgz",
                           "xlsx", "xls", "json", "mdf", "ldf", "parquet"],
    "egress_min_bytes": 1_000_000,
    "silence_gap_s": 21600,      # a source silent this long inside its coverage is reported as a possible gap
    "timeline_max_rows": 50_000,
    "max_paths_detailed": 50,
    "measures_taken": [],        # operator-supplied text for the regulator summary
}
_LIST_KEYS = {"sensitive_tables", "directory_domains", "internal_networks", "shared_ips", "service_accounts",
              "known_jobs", "web_admin_patterns", "web_script_extensions", "staging_extensions", "measures_taken"}


def _merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def validate(cfg: dict) -> dict:
    unknown = set(cfg) - set(DEFAULTS)
    if unknown:
        raise ConfigError(f"case.yaml paths: unknown keys {sorted(unknown)}")
    for k in _LIST_KEYS:
        if not isinstance(cfg.get(k), list):
            raise ConfigError(f"case.yaml paths.{k} must be a list")
    for n in cfg["internal_networks"]:
        try:
            ipaddress.ip_network(str(n), strict=False)
        except ValueError as exc:
            raise ConfigError("case.yaml paths.internal_networks has an invalid network") from exc
    for k, v in cfg["correlation"].items():
        if k not in DEFAULTS["correlation"]:
            raise ConfigError(f"case.yaml paths.correlation: unknown key {k}")
        if not isinstance(v, int | float) or v < 0:
            raise ConfigError(f"case.yaml paths.correlation.{k} must be a non-negative number")
    hh = cfg.get("hospital_hours")
    if hh is not None:
        if not isinstance(hh, dict) or not hh.get("timezone"):
            raise ConfigError("case.yaml paths.hospital_hours needs a timezone")
        for day in ("weekdays", "saturday", "sunday"):
            if hh.get(day) and not re.fullmatch(r"\d{2}:\d{2}-\d{2}:\d{2}", str(hh[day])):
                raise ConfigError(f"case.yaml paths.hospital_hours.{day} must look like 07:00-18:00")
    for j in cfg["known_jobs"]:
        if not isinstance(j, dict) or not j.get("account") or not j.get("reason"):
            raise ConfigError("case.yaml paths.known_jobs entries need account and reason")
    return cfg


def load_config(case) -> dict:
    return validate(_merge(DEFAULTS, case.config.get("paths") or {}))


def config_sha256(cfg: dict) -> str:
    return sha256_hex(canonical_bytes(cfg))


# ---------------------------------------------------------------------------------------------- matchers
def norm_table(name: str | None) -> str:
    return (name or "").replace("[", "").replace("]", "").replace('"', "").strip().lower()


class TableMatcher:
    def __init__(self, patterns: list[str]):
        self.patterns = [norm_table(p) for p in patterns]
        self.exact = [p for p in self.patterns if not any(c in p for c in "*?[")]

    def matches(self, table: str | None) -> bool:
        t = norm_table(table)
        if not t:
            return False
        return any(fnmatch.fnmatchcase(t, p) for p in self.patterns)

    def __bool__(self) -> bool:
        return bool(self.patterns)


class NetMatcher:
    def __init__(self, nets: list[str]):
        self.nets = [ipaddress.ip_network(str(n), strict=False) for n in nets]

    def contains(self, ip: str | None) -> bool | None:
        if not ip:
            return None
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return None
        return any(a in n for n in self.nets if n.version == a.version)


def account_matches(account: str | None, patterns: list[str]) -> bool:
    a = (account or "").lower()
    return bool(a) and any(fnmatch.fnmatchcase(a, str(p).lower()) for p in patterns)
