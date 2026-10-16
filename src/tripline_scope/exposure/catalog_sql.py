"""Read-only catalogue queries for Module A (SQL Server and PostgreSQL).

The hospital's DBA runs these on a **restored copy** or with a **metadata-only, read-only login**, saving each
result set as ``<query>.csv`` (with a header row) in one directory per database, or lets
``tscope exposure collect-catalog`` write a single JSON export. They read catalogue views only: no table data,
no password hashes, no user-mapping options, no linked-server provider strings.

Every query is a single ``SELECT``. ``scope`` says whether it runs once per server or in each database.
"""

from __future__ import annotations

CATALOG_SCHEMA = "tripline.exposure-catalog/v1"

MSSQL: dict[str, tuple[str, str]] = {
    "server_info": ("server", """
SELECT CAST(SERVERPROPERTY('ProductVersion') AS nvarchar(128)) AS product_version,
       CAST(SERVERPROPERTY('Edition') AS nvarchar(128)) AS edition,
       CAST(SERVERPROPERTY('IsIntegratedSecurityOnly') AS int) AS integrated_security_only,
       CAST(SERVERPROPERTY('ServerName') AS nvarchar(256)) AS server_name"""),
    "server_principals": ("server", """
SELECT p.name, p.type, p.type_desc, CAST(p.is_disabled AS int) AS is_disabled,
       CONVERT(varchar(33), p.create_date, 126) AS create_date, CONVERT(varchar(33), p.modify_date, 126) AS modify_date,
       p.default_database_name, CONVERT(varchar(200), p.sid, 1) AS sid
FROM sys.server_principals p
WHERE p.type IN ('S', 'U', 'G', 'R', 'C', 'K', 'E', 'X')"""),
    "sql_logins": ("server", """
SELECT l.name, CAST(l.is_policy_checked AS int) AS is_policy_checked,
       CAST(l.is_expiration_checked AS int) AS is_expiration_checked, CAST(l.is_disabled AS int) AS is_disabled
FROM sys.sql_logins l"""),
    "server_role_members": ("server", """
SELECT r.name AS role_name, m.name AS member_name
FROM sys.server_role_members rm
JOIN sys.server_principals r ON r.principal_id = rm.role_principal_id
JOIN sys.server_principals m ON m.principal_id = rm.member_principal_id"""),
    "server_permissions": ("server", """
SELECT pr.name AS grantee, pe.class_desc, pe.permission_name, pe.state_desc
FROM sys.server_permissions pe
JOIN sys.server_principals pr ON pr.principal_id = pe.grantee_principal_id"""),
    "databases": ("server", """
SELECT d.name, SUSER_SNAME(d.owner_sid) AS owner_login, CAST(d.is_trustworthy_on AS int) AS is_trustworthy_on,
       CAST(d.is_db_chaining_on AS int) AS is_db_chaining_on, CAST(d.is_encrypted AS int) AS is_encrypted,
       d.state_desc, d.containment_desc
FROM sys.databases d"""),
    "configurations": ("server", """
SELECT c.name, CAST(c.value_in_use AS int) AS value_in_use
FROM sys.configurations c
WHERE c.name IN ('xp_cmdshell', 'clr enabled', 'clr strict security', 'Ole Automation Procedures',
                 'Ad Hoc Distributed Queries', 'remote access', 'cross db ownership chaining',
                 'external scripts enabled', 'Database Mail XPs', 'remote admin connections',
                 'contained database authentication', 'c2 audit mode', 'common criteria compliance enabled',
                 'default trace enabled', 'scan for startup procs')"""),
    "linked_servers": ("server", """
SELECT s.name, s.product, s.provider, s.data_source, CAST(s.is_rpc_out_enabled AS int) AS is_rpc_out_enabled,
       CAST(s.is_data_access_enabled AS int) AS is_data_access_enabled
FROM sys.servers s
WHERE s.is_linked = 1"""),
    "linked_logins": ("server", """
SELECT s.name AS linked_server, CAST(l.uses_self_credential AS int) AS uses_self_credential, l.remote_name,
       p.name AS local_principal
FROM sys.linked_logins l
JOIN sys.servers s ON s.server_id = l.server_id
LEFT JOIN sys.server_principals p ON p.principal_id = l.local_principal_id
WHERE s.is_linked = 1"""),
    "server_audits": ("server", """
SELECT a.name, a.type_desc, a.on_failure_desc, CAST(a.is_state_enabled AS int) AS is_state_enabled
FROM sys.server_audits a"""),
    "server_audit_specifications": ("server", """
SELECT s.name AS specification, a.name AS audit_name, CAST(s.is_state_enabled AS int) AS is_state_enabled,
       d.audit_action_name
FROM sys.server_audit_specifications s
LEFT JOIN sys.server_audits a ON a.audit_guid = s.audit_guid
LEFT JOIN sys.server_audit_specification_details d ON d.server_specification_id = s.server_specification_id"""),
    "credentials": ("server", """
SELECT c.name, c.credential_identity FROM sys.credentials c"""),
    "services": ("server", """
SELECT s.servicename, s.service_account, s.status_desc FROM sys.dm_server_services s"""),
    "database_principals": ("database", """
SELECT DB_NAME() AS database_name, p.name, p.type, p.type_desc, p.authentication_type_desc,
       CONVERT(varchar(200), p.sid, 1) AS sid, SUSER_SNAME(p.sid) AS login_name, CAST(p.is_fixed_role AS int) AS is_fixed_role
FROM sys.database_principals p
WHERE p.type IN ('S', 'U', 'G', 'R', 'A', 'E', 'X', 'C', 'K')"""),
    "database_role_members": ("database", """
SELECT DB_NAME() AS database_name, r.name AS role_name, m.name AS member_name
FROM sys.database_role_members rm
JOIN sys.database_principals r ON r.principal_id = rm.role_principal_id
JOIN sys.database_principals m ON m.principal_id = rm.member_principal_id"""),
    "database_permissions": ("database", """
SELECT DB_NAME() AS database_name, pr.name AS grantee, pe.class_desc, pe.permission_name, pe.state_desc,
       CASE pe.class WHEN 1 THEN OBJECT_SCHEMA_NAME(pe.major_id) WHEN 3 THEN SCHEMA_NAME(pe.major_id) END AS schema_name,
       CASE pe.class WHEN 1 THEN OBJECT_NAME(pe.major_id) END AS object_name
FROM sys.database_permissions pe
JOIN sys.database_principals pr ON pr.principal_id = pe.grantee_principal_id"""),
    "database_audit_specifications": ("database", """
SELECT DB_NAME() AS database_name, s.name AS specification, CAST(s.is_state_enabled AS int) AS is_state_enabled,
       d.audit_action_name
FROM sys.database_audit_specifications s
LEFT JOIN sys.database_audit_specification_details d ON d.database_specification_id = s.database_specification_id"""),
    "tables": ("database", """
SELECT DB_NAME() AS database_name, s.name AS schema_name, t.name AS table_name, SUM(p.rows) AS row_estimate
FROM sys.tables t
JOIN sys.schemas s ON s.schema_id = t.schema_id
JOIN sys.partitions p ON p.object_id = t.object_id AND p.index_id IN (0, 1)
GROUP BY s.name, t.name"""),
    "columns": ("database", """
SELECT DB_NAME() AS database_name, s.name AS schema_name, t.name AS table_name, c.name AS column_name
FROM sys.columns c
JOIN sys.tables t ON t.object_id = c.object_id
JOIN sys.schemas s ON s.schema_id = t.schema_id"""),
}

_PG_NOSYS = "n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg\\_toast%'"
_PG_GRANTEE = "CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END AS grantee"

POSTGRES: dict[str, tuple[str, str]] = {
    "server_info": ("database", """
SELECT current_setting('server_version') AS server_version, current_database() AS database_name"""),
    "roles": ("server", """
SELECT r.rolname, r.rolsuper, r.rolinherit, r.rolcreaterole, r.rolcreatedb, r.rolcanlogin, r.rolreplication,
       r.rolbypassrls, r.rolconnlimit,
       to_char(r.rolvaliduntil AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS rolvaliduntil
FROM pg_roles r"""),
    "auth_members": ("server", """
SELECT r.rolname AS role_name, m.rolname AS member_name,
       to_jsonb(am) ->> 'admin_option' AS admin_option, to_jsonb(am) ->> 'inherit_option' AS inherit_option
FROM pg_auth_members am
JOIN pg_roles r ON r.oid = am.roleid
JOIN pg_roles m ON m.oid = am.member"""),
    "databases": ("server", """
SELECT d.datname AS name, pg_get_userbyid(d.datdba) AS owner, d.datallowconn
FROM pg_database d"""),
    "database_privileges": ("server", f"""
SELECT d.datname AS database_name, {_PG_GRANTEE}, a.privilege_type, a.is_grantable
FROM pg_database d, LATERAL aclexplode(COALESCE(d.datacl, acldefault('d', d.datdba))) a"""),
    "schema_privileges": ("database", f"""
SELECT n.nspname AS schema_name, pg_get_userbyid(n.nspowner) AS owner, {_PG_GRANTEE}, a.privilege_type
FROM pg_namespace n, LATERAL aclexplode(COALESCE(n.nspacl, acldefault('n', n.nspowner))) a
WHERE {_PG_NOSYS}"""),
    "table_privileges": ("database", f"""
SELECT n.nspname AS schema_name, c.relname AS table_name, c.relkind::text AS relkind,
       pg_get_userbyid(c.relowner) AS owner, {_PG_GRANTEE}, a.privilege_type, a.is_grantable
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace,
LATERAL aclexplode(COALESCE(c.relacl, acldefault('r', c.relowner))) a
WHERE c.relkind IN ('r', 'v', 'm', 'p', 'f') AND {_PG_NOSYS}"""),
    "tables": ("database", f"""
SELECT n.nspname AS schema_name, c.relname AS table_name, pg_get_userbyid(c.relowner) AS owner,
       c.reltuples::bigint AS row_estimate, c.relrowsecurity
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r', 'p') AND {_PG_NOSYS}"""),
    "columns": ("database", f"""
SELECT n.nspname AS schema_name, c.relname AS table_name, a.attname AS column_name
FROM pg_attribute a
JOIN pg_class c ON c.oid = a.attrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE a.attnum > 0 AND NOT a.attisdropped AND c.relkind IN ('r', 'p', 'v', 'm', 'f') AND {_PG_NOSYS}"""),
    "settings": ("server", """
SELECT s.name, s.setting, s.source
FROM pg_settings s
WHERE s.name IN ('log_connections', 'log_disconnections', 'log_statement', 'logging_collector',
                 'log_min_duration_statement', 'shared_preload_libraries', 'session_preload_libraries',
                 'pgaudit.log', 'pgaudit.log_catalog', 'ssl', 'password_encryption', 'log_line_prefix')"""),
    "extensions": ("database", """
SELECT e.extname, e.extversion FROM pg_extension e"""),
    "languages": ("database", """
SELECT l.lanname, l.lanpltrusted, l.lanispl FROM pg_language l"""),
    "foreign_servers": ("database", """
SELECT s.srvname, w.fdwname, pg_get_userbyid(s.srvowner) AS owner,
       (SELECT string_agg(o, ',') FROM unnest(s.srvoptions) o
         WHERE o LIKE 'host=%' OR o LIKE 'dbname=%' OR o LIKE 'port=%') AS target
FROM pg_foreign_server s
JOIN pg_foreign_data_wrapper w ON w.oid = s.srvfdw"""),
    "user_mappings": ("database", """
SELECT m.srvname, m.usename FROM pg_user_mappings m"""),
    "hba_rules": ("server", """
SELECT h.line_number, h.type, array_to_string(h.database, ',') AS database,
       array_to_string(h.user_name, ',') AS user_name, h.address, h.auth_method
FROM pg_hba_file_rules h"""),
}

QUERIES = {"mssql": MSSQL, "postgres": POSTGRES}

PERMISSIONS_NOTE = {
    "mssql": "Metadata-only login: GRANT VIEW ANY DEFINITION, VIEW SERVER STATE (SQL Server 2022: VIEW ANY SECURITY "
             "DEFINITION and VIEW SERVER SECURITY STATE suffice) TO the login; map it to a user in each scanned database "
             "with no role memberships. It must hold no write, DDL or admin rights; the collector refuses otherwise.",
    "postgres": "Metadata-only login: CREATE ROLE ... LOGIN; GRANT pg_read_all_settings TO it; GRANT CONNECT on the "
                "scanned database. pg_hba_file_rules needs superuser unless granted explicitly; without it the "
                "client-authentication check is reported as unavailable. The login must own nothing and hold no "
                "INSERT/UPDATE/DELETE/TRUNCATE or CREATE privileges; the collector refuses otherwise.",
}


def script(engine: str) -> str:
    """The catalogue queries as one annotated SQL script for the DBA."""
    qs = QUERIES[engine]
    head = [f"-- Tripline Scope Module A catalogue export ({engine}); {CATALOG_SCHEMA}",
            "-- Read-only catalogue SELECTs. Save each result set as <query>.csv with a header row in one directory",
            "-- per database (or run 'tscope exposure collect-catalog').",
            f"-- {PERMISSIONS_NOTE[engine]}", ""]
    body = []
    for name, (scope, sql) in qs.items():
        body.append(f"-- query: {name}   (scope: {scope}{'; run in each scanned database' if scope == 'database' else ''})")
        body.append(sql.strip() + ";")
        body.append("")
    return "\n".join(head + body)
