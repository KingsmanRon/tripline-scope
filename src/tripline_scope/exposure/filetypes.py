"""File-type recognition by magic bytes and metadata (never by pretending to read opaque formats)."""

from __future__ import annotations

import posixpath

CODE_EXT = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".py", ".php", ".cs", ".java", ".go", ".rb", ".vb",
            ".kt", ".scala", ".swift", ".c", ".cpp", ".h", ".rs", ".pl", ".lua", ".dart", ".aspx", ".ascx",
            ".cshtml", ".vue", ".svelte"}
SCRIPT_EXT = {".ps1", ".psm1", ".sh", ".bash", ".bat", ".cmd", ".sql"}
DELIMITED_EXT = {".csv", ".tsv", ".psv", ".tab"}
JSON_EXT = {".json"}
JSONL_EXT = {".jsonl", ".ndjson"}
XLSX_EXT = {".xlsx", ".xlsm"}
OFFICE_EXT = {".docx", ".pptx", ".odt", ".ods", ".odp", ".doc", ".xls", ".ppt", ".pdf", ".rtf"}
BACKUP_EXT = {".bak", ".trn", ".dmp", ".dump", ".backup", ".mdf", ".ndf", ".ldf", ".sql", ".gz", ".zip", ".7z",
              ".tar", ".tgz", ".rar", ".xz", ".bz2"}
# Web-servable static content when found under a web root (likely downloadable if the path is published).
PUBLIC_WEB_EXT = {".js", ".mjs", ".map", ".json", ".env", ".txt", ".html", ".htm", ".xml", ".yml", ".yaml", ".ini",
                  ".bak", ".old", ".orig", ".sql", ".csv", ".tsv", ".xlsx", ".log", ".zip", ".gz", ".conf", ".cfg",
                  ".properties", ".pem", ".key"}
# Server-side files the web server normally executes or blocks rather than serving raw.
SERVER_SIDE_NAMES = {"web.config", ".htaccess", ".htpasswd"}
SERVER_SIDE_EXT = {".php", ".aspx", ".asp", ".ascx", ".cshtml", ".cs", ".vb", ".config", ".py", ".rb", ".jsp"}


def ext_of(name: str) -> str:
    base = posixpath.basename(name.split("!")[-1]).lower()
    if base.startswith(".") and base.count(".") == 1:
        return base  # dotfiles such as .env
    return posixpath.splitext(base)[1]


def basename(name: str) -> str:
    return posixpath.basename(name.split("!")[-1])


def sniff(name: str, head: bytes) -> str:
    """Classify by magic bytes first, then extension."""
    ext = ext_of(name)
    if head.startswith(b"TAPE"):
        return "mssql_backup"
    if head.startswith(b"PGDMP"):
        return "pg_custom_dump"
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        if ext in XLSX_EXT:
            return "xlsx"
        if ext in OFFICE_EXT:
            return "office"
        return "zip"
    if head.startswith(b"\x1f\x8b"):
        return "gzip"
    if head.startswith(b"BZh") and len(head) > 3 and head[3:4].isdigit():
        return "bzip2"
    if head.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if head.startswith(b"Rar!"):
        return "rar"
    if len(head) > 262 and head[257:262] == b"ustar":
        return "tar"
    if ext in (".mdf", ".ndf", ".ldf") and len(head) >= 96 and head[0] == 1 and head[1] in (15, 1):
        return "mssql_data_file"
    if b"EXPORT:V" in head[:64]:
        return "oracle_export"
    if head.startswith(b"%PDF") or ext in OFFICE_EXT:
        return "office"
    if head.startswith((b"\xff\xfe", b"\xfe\xff")):
        return "text"
    if b"\x00" in head[:8192]:
        return "binary"
    return "text"


def decode_text(data: bytes) -> str:
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return data.decode("utf-16")
        except UnicodeDecodeError:
            return data.decode("latin-1")
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


SQL_DUMP_MARKERS = ("-- PostgreSQL database dump", "-- MySQL dump", "-- MariaDB dump", "/****** Object:",
                    "-- Dumped from database version", "SET ANSI_NULLS", "INSERT INTO", "COPY ")


def text_kind(name: str, text_head: str) -> str:
    ext = ext_of(name)
    if ext in DELIMITED_EXT:
        return "delimited"
    if ext in JSON_EXT:
        return "json"
    if ext in JSONL_EXT:
        return "jsonl"
    if ext == ".sql" and any(m in text_head for m in SQL_DUMP_MARKERS[:6]):
        return "sql_dump"
    if ext == ".sql" and ("INSERT INTO" in text_head.upper() or "\nCOPY " in text_head):
        return "sql_dump"
    return "text"
