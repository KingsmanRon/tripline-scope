"""Module B common event schema (PLAN section 7) and shared constants.

One row per source record in ``work/paths/events/<SRC>.parquet`` (encrypted through ``CaseStore``). The
PLAN columns come first; the extra columns after ``consequence_class`` are additive and documented in
``docs/ACCESS_PATHS.md``. SQL text, URL query strings, passwords, tokens and command lines are never stored:
statements are reduced to an operation, object names and a keyed fingerprint.
"""

from __future__ import annotations

import pyarrow as pa

METHOD_VERSION = "paths/0.1.0"
MANIFEST_SCHEMA = "tripline.logs-manifest/v1"
CANDIDATES_SCHEMA = "tripline.scope-candidates/v1"
ANALYSIS_SCHEMA = "tripline.paths-analysis/v1"

FAMILIES = (
    "mssql_audit", "pg_log", "pgaudit", "iis", "apache", "nginx", "win_security", "entra_signin",
    "vpn", "firewall", "proxy", "indicators", "generic",
)
DB_FAMILIES = ("mssql_audit", "pg_log", "pgaudit")
WEB_FAMILIES = ("iis", "apache", "nginx")
FLOW_FAMILIES = ("firewall", "proxy")

# Observation types (what the record shows) and the event-level consequence they support.
OBS_CONSEQUENCE = {
    "select": "access_observed",
    "modify": "access_observed",
    "execute": "access_observed",
    "bulk_import": "access_observed",
    "dump_export": "export_or_staging_observed",
    "select_into": "export_or_staging_observed",
    "file_staged": "export_or_staging_observed",
    "auditing_disabled": "undetermined",
    "log_cleared": "undetermined",
}
DATA_OBSERVATIONS = {"select", "modify", "execute", "bulk_import", "dump_export", "select_into", "file_staged"}
# Context events (sign-ins, logons, web requests, flows, privilege changes...) carry no claim about data.
NOT_APPLICABLE = "not_applicable"

EVENT_SCHEMA = pa.schema([
    ("event_id", pa.string()),
    ("source_id", pa.string()),
    ("source_family", pa.string()),
    ("ordinal", pa.int64()),
    ("ts_original_text", pa.string()),
    ("tz_original", pa.string()),
    ("ts_utc", pa.timestamp("us", tz="UTC")),
    ("clock_offset_s", pa.float64()),
    ("ts_uncertainty_s", pa.float64()),
    ("time_precision", pa.string()),
    ("host", pa.string()),
    ("account", pa.string()),
    ("application", pa.string()),
    ("session_id", pa.string()),
    ("request_id", pa.string()),
    ("logon_id", pa.string()),
    ("remote_ip", pa.string()),
    ("operation", pa.string()),
    ("observation_type", pa.string()),
    ("database", pa.string()),
    ("object_name", pa.string()),
    ("rows", pa.int64()),
    ("bytes", pa.int64()),
    ("outcome", pa.string()),
    ("mfa", pa.string()),
    ("url_path", pa.string()),
    ("http_status", pa.int32()),
    ("parser", pa.string()),
    ("raw_sha256", pa.string()),
    ("consequence_class", pa.string()),
    # ---- additive columns
    ("record_locator", pa.string()),      # "<file>:<line>" or "<file>#<record>" for forensic hand-off
    ("tz_basis", pa.string()),            # record | manifest | format | unknown
    ("ts_utc_min", pa.timestamp("us", tz="UTC")),   # earliest supported UTC instant (precision, skew, zone)
    ("ts_utc_max", pa.timestamp("us", tz="UTC")),   # latest supported UTC instant
    ("objects", pa.list_(pa.string())),   # every object named by the record ("db.schema.table")
    ("event_code", pa.string()),          # Windows event id, SQL audit action id, Entra error code...
    ("dest_ip", pa.string()),
    ("dest_port", pa.int32()),
    ("assigned_ip", pa.string()),         # VPN-assigned address
    ("domain", pa.string()),              # destination domain (proxy) or web host
    ("method", pa.string()),
    ("bytes_received", pa.int64()),       # bytes received by the logging system (e.g. uploads to a web server)
    ("target_account", pa.string()),      # account acted upon (group member added, account created...)
    ("location", pa.string()),            # sign-in country/region as exported
    ("statement_fp", pa.string()),        # keyed fingerprint of the normalised statement (no literals)
    ("file_hash", pa.string()),
    ("flags", pa.list_(pa.string())),
])

FIELD_NAMES = [f.name for f in EVENT_SCHEMA]
STRING_FIELDS = {f.name for f in EVENT_SCHEMA if pa.types.is_string(f.type)}
INT_FIELDS = {f.name for f in EVENT_SCHEMA if pa.types.is_integer(f.type)} - {"ordinal"}
