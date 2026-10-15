"""Installation configuration for ingest: restore targets, live connections and processing limits.

These live in the installation ``config.yaml`` (never in ``case.yaml``)::

    restore_targets:
      mssql:
        host: 10.0.0.5            # the hospital's licensed restore / test SQL Server
        port: 1433
        login: tscope_restore     # dbcreator-only login (see docs/INGEST.md)
        password_env: TSCOPE_MSSQL_RESTORE_PASSWORD   # name of an env var; else prompted. Never stored.
        backup_transfer: shared_path    # shared_path | docker_cp (docker_cp: demos/tests only)
        server_backup_dir: /mnt/restore-in   # where the server sees the backup files
        host_backup_dir: /srv/evidence       # shared_path: where this host sees the same files
        container: mssql-test                # docker_cp only
        data_dir: /var/opt/mssql/data        # where restored data/log files go (default: server default)
        encryption: false                    # TDS encryption (needs pyOpenSSL, not in this bundle)
        trust_server_certificate: true
        database_prefix: tscope_             # restored database = <prefix><case>_<source>
      postgres:
        host: 127.0.0.1
        port: 5432
        login: tscope_restore     # CREATEDB, not superuser
        password_env: TSCOPE_PG_RESTORE_PASSWORD
        bin_dir: /usr/lib/postgresql/16/bin
    live_connections:
      labsql:
        engine: mssql             # mssql | postgres
        host: 10.0.0.9
        port: 1433
        login: tscope_reader
        password_env: TSCOPE_LIVE_LABSQL_PASSWORD
    ingest:
      sample_rows: 10000
      batch_rows: 50000
      ...

Restored database names are derived from the case id and source id only, never from data.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, fields
from pathlib import PurePosixPath

from tripline_scope.core.errors import ConfigError
from tripline_scope.core.home import get_secret

_ENV_RE = re.compile(r"^[A-Z_][A-Z0-9_]{0,63}$")
_HOST_RE = re.compile(r"^[A-Za-z0-9.\-:\[\]_]{1,253}$")
_PREFIX_RE = re.compile(r"^[a-z][a-z0-9_]{0,30}$")
_PATH_RE = re.compile(r"^[A-Za-z0-9_\-./: \\]{1,400}$")
_FORBIDDEN_KEYS = {"password", "pwd", "secret", "connection_string", "dsn"}


@dataclass(frozen=True)
class IngestLimits:
    sample_rows: int = 10_000
    batch_rows: int = 50_000
    part_rows: int = 500_000
    max_rows_per_table: int = 50_000_000
    max_bytes_per_file: int = 64 * 1024**3
    max_field_bytes: int = 1024 * 1024
    xlsx_max_uncompressed_bytes: int = 2 * 1024**3
    xlsx_max_ratio: int = 200
    json_array_max_bytes: int = 512 * 1024**2
    query_timeout_s: int = 300
    restore_timeout_s: int = 6 * 3600
    key_set_cap: int = 2_000_000
    live_max_rows_per_table: int = 5_000_000
    live_statement_timeout_s: int = 60
    live_lock_timeout_s: int = 5


def limits(home) -> IngestLimits:
    raw = (home.config.get("ingest") or {}) if home is not None else {}
    if not isinstance(raw, dict):
        raise ConfigError("installation config 'ingest' must be a mapping")
    known = {f.name for f in fields(IngestLimits)}
    unknown = set(raw) - known
    if unknown:
        raise ConfigError(f"unknown ingest setting(s): {sorted(unknown)}")
    vals = {}
    for k, v in raw.items():
        if not isinstance(v, int) or isinstance(v, bool) or v < 1:
            raise ConfigError(f"ingest.{k} must be a positive integer")
        vals[k] = v
    return IngestLimits(**vals)


# ------------------------------------------------------------------------------------------ targets
@dataclass(frozen=True)
class Target:
    engine: str                       # mssql | postgres
    host: str
    port: int
    login: str
    password_env: str | None
    # SQL Server
    backup_transfer: str = "shared_path"
    server_backup_dir: str | None = None
    host_backup_dir: str | None = None
    container: str | None = None
    data_dir: str | None = None
    log_dir: str | None = None
    encryption: bool = False
    trust_server_certificate: bool = False
    # PostgreSQL
    bin_dir: str | None = None
    maintenance_db: str = "postgres"
    tls: bool = False
    tls_cafile: str | None = None
    # both
    database_prefix: str = "tscope_"
    login_timeout_s: int = 15
    name: str = "restore"

    @property
    def instance_ref(self) -> str:
        """Opaque, stable reference to the instance for certificates and status (no host or port shown)."""
        h = hashlib.sha256(f"tripline-instance:{self.engine}:{self.host.lower()}:{self.port}".encode()).hexdigest()
        return f"{self.engine}:{h[:16]}"

    def password(self) -> str:
        label = f"Password for the {self.engine} {self.name} login"
        if not self.password_env:
            from tripline_scope.core.home import get_secret as _gs

            return _gs(label, "TSCOPE_NO_PASSWORD_ENV_CONFIGURED")
        return get_secret(label, self.password_env)


_COMMON = {"host", "port", "login", "password_env", "database_prefix", "login_timeout_s"}
_MSSQL_KEYS = _COMMON | {"backup_transfer", "server_backup_dir", "host_backup_dir", "container", "data_dir",
                         "log_dir", "encryption", "trust_server_certificate"}
_PG_KEYS = _COMMON | {"bin_dir", "maintenance_db", "tls", "tls_cafile"}
_LIVE_KEYS = {"engine", "host", "port", "login", "password_env", "login_timeout_s", "encryption",
              "trust_server_certificate", "tls", "tls_cafile", "maintenance_db"}


def _check_common(raw: dict, where: str) -> None:
    bad = _FORBIDDEN_KEYS & set(raw)
    if bad:
        raise ConfigError(f"{where}: passwords and connection strings are never stored in config; "
                          "use password_env (the name of an environment variable) or the prompt")
    host = raw.get("host")
    if not isinstance(host, str) or not _HOST_RE.match(host):
        raise ConfigError(f"{where}.host must be a host name or address")
    port = raw.get("port")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ConfigError(f"{where}.port must be an integer 1-65535")
    if not isinstance(raw.get("login"), str) or not raw["login"].strip() or len(raw["login"]) > 128:
        raise ConfigError(f"{where}.login is required")
    env = raw.get("password_env")
    if env is not None and (not isinstance(env, str) or not _ENV_RE.match(env)):
        raise ConfigError(f"{where}.password_env must be an environment variable name (A-Z, 0-9, _)")
    prefix = raw.get("database_prefix", "tscope_")
    if not isinstance(prefix, str) or not _PREFIX_RE.match(prefix):
        raise ConfigError(f"{where}.database_prefix must match {_PREFIX_RE.pattern}")
    for b in ("encryption", "trust_server_certificate", "tls"):
        if b in raw and not isinstance(raw[b], bool):
            raise ConfigError(f"{where}.{b} must be true or false")


def _check_path(raw: dict, key: str, where: str, *, required: bool = False) -> None:
    v = raw.get(key)
    if v is None:
        if required:
            raise ConfigError(f"{where}.{key} is required")
        return
    if not isinstance(v, str) or not _PATH_RE.match(v) or ".." in v.split("/"):
        raise ConfigError(f"{where}.{key} must be a plain absolute path")
    if not (v.startswith("/") or re.match(r"^[A-Za-z]:\\", v)):
        raise ConfigError(f"{where}.{key} must be absolute")


def mssql_target(home) -> Target:
    raw = ((home.config.get("restore_targets") or {}).get("mssql"))
    where = "restore_targets.mssql"
    if not raw:
        raise ConfigError("no SQL Server restore target configured (installation config restore_targets.mssql; "
                          "see docs/INGEST.md)")
    if not isinstance(raw, dict):
        raise ConfigError(f"{where} must be a mapping")
    _check_common(raw, where)
    unknown = set(raw) - _MSSQL_KEYS
    if unknown:
        raise ConfigError(f"{where}: unknown key(s) {sorted(unknown)}")
    transfer = raw.get("backup_transfer", "shared_path")
    if transfer not in ("shared_path", "docker_cp"):
        raise ConfigError(f"{where}.backup_transfer must be shared_path or docker_cp")
    _check_path(raw, "server_backup_dir", where, required=True)
    _check_path(raw, "host_backup_dir", where, required=transfer == "shared_path")
    _check_path(raw, "data_dir", where)
    _check_path(raw, "log_dir", where)
    if transfer == "docker_cp":
        c = raw.get("container")
        if not isinstance(c, str) or not re.match(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,127}$", c):
            raise ConfigError(f"{where}.container is required for docker_cp and must be a container name")
    return Target(engine="mssql", host=raw["host"], port=raw["port"], login=raw["login"],
                  password_env=raw.get("password_env"), backup_transfer=transfer,
                  server_backup_dir=raw["server_backup_dir"], host_backup_dir=raw.get("host_backup_dir"),
                  container=raw.get("container"), data_dir=raw.get("data_dir"), log_dir=raw.get("log_dir"),
                  encryption=bool(raw.get("encryption", False)),
                  trust_server_certificate=bool(raw.get("trust_server_certificate", False)),
                  database_prefix=raw.get("database_prefix", "tscope_"),
                  login_timeout_s=int(raw.get("login_timeout_s", 15)))


def pg_target(home) -> Target:
    raw = ((home.config.get("restore_targets") or {}).get("postgres"))
    where = "restore_targets.postgres"
    if not raw:
        raise ConfigError("no PostgreSQL restore target configured (installation config restore_targets.postgres; "
                          "see docs/INGEST.md)")
    if not isinstance(raw, dict):
        raise ConfigError(f"{where} must be a mapping")
    _check_common(raw, where)
    unknown = set(raw) - _PG_KEYS
    if unknown:
        raise ConfigError(f"{where}: unknown key(s) {sorted(unknown)}")
    _check_path(raw, "bin_dir", where)
    _check_path(raw, "tls_cafile", where)
    mdb = raw.get("maintenance_db", "postgres")
    if not isinstance(mdb, str) or not re.match(r"^[A-Za-z0-9_]{1,63}$", mdb):
        raise ConfigError(f"{where}.maintenance_db must be a database name")
    return Target(engine="postgres", host=raw["host"], port=raw["port"], login=raw["login"],
                  password_env=raw.get("password_env"), bin_dir=raw.get("bin_dir"), maintenance_db=mdb,
                  tls=bool(raw.get("tls", False)), tls_cafile=raw.get("tls_cafile"),
                  database_prefix=raw.get("database_prefix", "tscope_"),
                  login_timeout_s=int(raw.get("login_timeout_s", 15)))


def target_for(home, engine: str) -> Target:
    return mssql_target(home) if engine == "mssql" else pg_target(home)


def live_connection(home, name: str) -> Target:
    conns = home.config.get("live_connections") or {}
    if not isinstance(conns, dict) or name not in conns:
        raise ConfigError("unknown live connection (installation config live_connections)")
    raw = conns[name]
    where = f"live_connections.{name}"
    if not isinstance(raw, dict):
        raise ConfigError(f"{where} must be a mapping")
    _check_common(raw, where)
    unknown = set(raw) - _LIVE_KEYS
    if unknown:
        raise ConfigError(f"{where}: unknown key(s) {sorted(unknown)}")
    engine = raw.get("engine")
    if engine not in ("mssql", "postgres"):
        raise ConfigError(f"{where}.engine must be mssql or postgres")
    _check_path(raw, "tls_cafile", where)
    return Target(engine=engine, host=raw["host"], port=raw["port"], login=raw["login"],
                  password_env=raw.get("password_env"), encryption=bool(raw.get("encryption", False)),
                  trust_server_certificate=bool(raw.get("trust_server_certificate", False)),
                  tls=bool(raw.get("tls", False)), tls_cafile=raw.get("tls_cafile"),
                  maintenance_db=raw.get("maintenance_db", "postgres"),
                  login_timeout_s=int(raw.get("login_timeout_s", 15)), name=f"live connection {name}")


# ------------------------------------------------------------------------------------------ naming
def restored_db_name(prefix: str, case_id: str, source_id: str) -> str:
    """``tscope_case_test_001_src_001``: derived from case and source ids only (never from data)."""
    name = f"{prefix}{case_id}_{source_id}".lower().replace("-", "_")
    name = re.sub(r"[^a-z0-9_]", "_", name)
    if len(name) > 63:
        digest = hashlib.sha256(name.encode()).hexdigest()[:8]
        name = name[:54] + "_" + digest
    if not re.match(r"^[a-z][a-z0-9_]{0,62}$", name):
        raise ConfigError("cannot derive a safe database name from the case and source ids")
    return name


def server_path(target: Target, file_name: str) -> str:
    base = target.server_backup_dir.rstrip("/\\")
    sep = "\\" if re.match(r"^[A-Za-z]:\\", base) else "/"
    return f"{base}{sep}{file_name}"


def shared_server_path(target: Target, host_path: str) -> str:
    """Map a host path under ``host_backup_dir`` to the path the server sees under ``server_backup_dir``."""
    hb = PurePosixPath(target.host_backup_dir)
    hp = PurePosixPath(host_path)
    try:
        rel = hp.relative_to(hb)
    except ValueError:
        raise ConfigError("backup file is not under restore_targets.mssql.host_backup_dir; the server cannot read "
                          "it in place (move the evidence copy there, or use another transfer mode)") from None
    base = target.server_backup_dir.rstrip("/\\")
    sep = "\\" if re.match(r"^[A-Za-z]:\\", base) else "/"
    return base + sep + sep.join(rel.parts)
