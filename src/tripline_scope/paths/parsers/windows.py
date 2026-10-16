"""Windows Security events: native ``.evtx`` (read with the MIT-licensed ``evtx`` package), XML exported with
``wevtutil qe Security /f:xml`` or ``Get-WinEvent ... | ForEach-Object { $_.ToXml() }``, and CSV produced by the
export script in ``docs/ACCESS_PATHS.md`` (``TimeCreated`` in round-trip ISO format, ``EventID``, ``Computer``,
``RecordId`` and one column per ``EventData`` name).

EVTX chunk/record checksums are validated by default (damaged chunks are counted as parse failures); set
``options.validate_checksums: false`` to recover records from damaged chunks, which is then noted.

Mapped events: 4624/4625 logon success/failure, 4634/4647 logoff, 4648 explicit credentials, 4672 special
privileges, 4688 process start (executable name only -- command lines are never read), 4663 object access
(file paths reduced to extension + keyed fingerprint), 5140/5145 share access, 4720/4722/4724/4725/4726/4738
account changes, 4728/4732/4756 group member added, 4729/4733/4757 removed, 4719 audit policy change,
1100 event logging stopped, 1102 security log cleared, 4768/4769/4771/4776 domain authentication.
XML with a DTD or entity declarations is refused.
"""

from __future__ import annotations

import csv
import io
import json
import re
from xml.etree.ElementTree import XMLPullParser  # noqa: S405 - DTD/entities refused before parsing

from ..timenorm import parse_iso
from .base import ParseContext, blank, clean_ip, text_stream, to_int

VERSION = "1.0"
_WRITE_MASK = 0x2 | 0x4 | 0x40000 | 0x10000000 | 0x40000000   # WriteData/AddFile, AppendData, WRITE_DAC..., GENERIC_ALL/WRITE
_WRITE_ACCESS_CODES = ("%%4417", "%%4418", "%%4424")          # WriteData, AppendData, WriteAttributes


def _acct(domain, user) -> str | None:
    u = blank(user)
    if not u:
        return None
    d = blank(domain)
    return f"{d}\\{u}" if d and "\\" not in u and "@" not in u else u


def _logon_id(v) -> str | None:
    v = blank(v)
    if not v:
        return None
    v = v.lower()
    try:
        return hex(int(v, 16)) if v.startswith("0x") else hex(int(v))
    except ValueError:
        return v


def _basename(path) -> str | None:
    p = blank(path)
    if not p:
        return None
    return re.split(r"[\\/]", p)[-1][:80]


def map_event(ctx: ParseContext, ev: dict) -> dict:
    """Map a normalised event ({EventID, TimeCreated, Computer, RecordId, data{}}) to record fields."""
    eid = to_int(ev.get("EventID"))
    d = ev.get("data") or {}
    rec: dict = {"host": blank(ev.get("Computer")) or ctx.host, "event_code": str(eid) if eid is not None else None,
                 "outcome": "success", "flags": []}
    subj = _acct(d.get("SubjectDomainName"), d.get("SubjectUserName"))
    targ = _acct(d.get("TargetDomainName"), d.get("TargetUserName"))
    if eid in (4624, 4625):
        rec.update(account=targ, logon_id=_logon_id(d.get("TargetLogonId")), remote_ip=clean_ip(d.get("IpAddress")),
                   client_host=blank(d.get("WorkstationName")), application=blank(d.get("AuthenticationPackageName")),
                   operation=f"logon_type_{blank(d.get('LogonType')) or 'unknown'}",
                   observation_type="login_success" if eid == 4624 else "login_failure")
        if eid == 4625:
            rec["outcome"] = "failure"
    elif eid in (4634, 4647):
        rec.update(account=targ, logon_id=_logon_id(d.get("TargetLogonId")), operation="logoff", observation_type="logoff")
    elif eid == 4648:
        rec.update(account=subj, target_account=targ, logon_id=_logon_id(d.get("SubjectLogonId")),
                   remote_ip=clean_ip(d.get("IpAddress")), object_name=blank(d.get("TargetServerName")),
                   operation="explicit_credentials", observation_type="explicit_credentials")
    elif eid == 4672:
        rec.update(account=subj, logon_id=_logon_id(d.get("SubjectLogonId")), operation="special_privileges",
                   observation_type="special_privileges")
    elif eid == 4688:
        rec.update(account=subj, logon_id=_logon_id(d.get("SubjectLogonId")),
                   application=_basename(d.get("NewProcessName")), operation="process_start",
                   observation_type="process_start")
    elif eid == 4663:
        mask = d.get("AccessMask")
        access = str(d.get("AccessList") or "")
        writing = False
        try:
            writing = bool(int(str(mask), 16 if str(mask).lower().startswith("0x") else 10) & _WRITE_MASK) if mask else False
        except ValueError:
            writing = False
        writing = writing or any(c in access for c in _WRITE_ACCESS_CODES)
        ref = ctx.file_ref(d.get("ObjectName")) if str(d.get("ObjectType") or "File").lower() == "file" else None
        rec.update(account=subj, logon_id=_logon_id(d.get("SubjectLogonId")), application=_basename(d.get("ProcessName")),
                   object_name=ref, operation="file_write" if writing else "object_access",
                   observation_type="file_write" if writing else "object_access")
    elif eid in (5140, 5145):
        rec.update(account=subj, logon_id=_logon_id(d.get("SubjectLogonId")), remote_ip=clean_ip(d.get("IpAddress")),
                   object_name=blank(d.get("ShareName")), operation="share_access", observation_type="share_access")
    elif eid in (4720, 4722, 4724, 4725, 4726, 4738):
        rec.update(account=subj, target_account=targ, logon_id=_logon_id(d.get("SubjectLogonId")),
                   operation={4720: "account_created", 4722: "account_enabled", 4724: "password_reset",
                              4725: "account_disabled", 4726: "account_deleted", 4738: "account_changed"}[eid],
                   observation_type="account_change")
    elif eid in (4728, 4732, 4756, 4729, 4733, 4757):
        added = eid in (4728, 4732, 4756)
        member = blank(d.get("MemberName"))
        if member and member.upper().startswith("CN="):
            member = "dn:" + ctx.file_fp(member.lower())[:12]      # distinguished names can carry personal names
        rec.update(account=subj, target_account=member or blank(d.get("MemberSid")),
                   object_name=_acct(d.get("TargetDomainName"), d.get("TargetUserName")),
                   logon_id=_logon_id(d.get("SubjectLogonId")),
                   operation="group_member_added" if added else "group_member_removed",
                   observation_type="privilege_change" if added else "privilege_revoke")
    elif eid == 4719:
        changes = str(d.get("AuditPolicyChanges") or "")
        removed = "%%8448" in changes or "%%8450" in changes
        rec.update(account=subj, logon_id=_logon_id(d.get("SubjectLogonId")), operation="audit_policy_changed",
                   observation_type="auditing_disabled" if removed else "auditing_enabled")
    elif eid == 1102:
        rec.update(account=subj, logon_id=_logon_id(d.get("SubjectLogonId")), operation="security_log_cleared",
                   observation_type="log_cleared")
    elif eid == 1100:
        rec.update(operation="event_logging_stopped", observation_type="auditing_disabled")
    elif eid in (4768, 4769, 4771, 4776):
        status = str(d.get("Status") or d.get("FailureCode") or "0x0").lower()
        ok = status in ("0x0", "0", "")
        rec.update(account=_acct(d.get("TargetDomainName"), d.get("TargetUserName")) or blank(d.get("TargetUserName")),
                   remote_ip=clean_ip(d.get("IpAddress")), client_host=blank(d.get("Workstation")),
                   operation={4768: "kerberos_tgt", 4769: "kerberos_service_ticket", 4771: "kerberos_preauth_failed",
                              4776: "ntlm_validation"}[eid],
                   observation_type="domain_authentication", outcome="success" if ok and eid != 4771 else "failure")
    else:
        rec.update(account=subj, logon_id=_logon_id(d.get("SubjectLogonId")), operation=f"event_{eid}",
                   observation_type="other")
    return {k: v for k, v in rec.items() if v is not None or k in ("account",)}


# ---------------------------------------------------------------------------------------------- EVTX
def _evtx_events(ctx: ParseContext, stream, relname: str):
    from evtx import PyEvtxParser

    data = stream.read()
    validate = ctx.options.get("validate_checksums", True)
    if not validate:
        ctx.notes.add("evtx_checksums_not_validated")
    parser = PyEvtxParser(io.BytesIO(data), number_of_threads=1, validate_checksums=bool(validate))
    n, errors_in_row = 0, 0
    it = parser.records_json()
    while True:
        try:
            item = next(it)
        except StopIteration:
            break
        except RuntimeError:
            item = RuntimeError("unreadable")
        n += 1
        if isinstance(item, Exception):
            ctx.fail(f"{relname}#record{n}", "EVTX record or chunk could not be read (checksum or structure)")
            errors_in_row += 1
            if errors_in_row > 10_000:
                ctx.fail(relname, "too many consecutive EVTX errors; rest of file not read")
                break
            continue
        errors_in_row = 0
        try:
            doc = json.loads(item["data"])
        except (TypeError, ValueError, KeyError):
            ctx.fail(f"{relname}#record{n}", "EVTX record JSON could not be read")
            continue
        ev = doc.get("Event", {}) if isinstance(doc, dict) else {}
        sysd = ev.get("System", {}) or {}
        eid = sysd.get("EventID")
        if isinstance(eid, dict):
            eid = eid.get("#text")
        tc = (sysd.get("TimeCreated") or {}).get("#attributes", {}).get("SystemTime") or item.get("timestamp")
        data = {}
        ed = ev.get("EventData")
        if isinstance(ed, dict):
            for k, v in ed.items():
                if k == "#attributes":
                    continue
                data[k] = v if not isinstance(v, dict) else v.get("#text")
        ud = ev.get("UserData")
        if isinstance(ud, dict):
            for inner in ud.values():
                if isinstance(inner, dict):
                    for k, v in inner.items():
                        if k != "#attributes":
                            data[k] = v if not isinstance(v, dict) else v.get("#text")
        rid = item.get("event_record_id") or sysd.get("EventRecordID")
        yield {"EventID": eid, "TimeCreated": tc, "Computer": sysd.get("Computer"), "RecordId": rid,
               "data": data, "_raw": item["data"], "_loc": f"{relname}#{rid}"}


# ---------------------------------------------------------------------------------------------- XML
def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _xml_events(ctx: ParseContext, stream, relname: str):
    text = text_stream(stream).read()
    head = text[:4096].upper()
    if "<!DOCTYPE" in head or "<!ENTITY" in text.upper():
        ctx.fail(relname, "XML with DTD or entity declarations refused")
        return
    text = re.sub(r"^\s*<\?xml[^>]*\?>", "", text)
    parser = XMLPullParser(events=("end",))
    parser.feed("<tscope-root>")
    pos, step, n = 0, 1 << 20, 0
    while True:
        chunk = text[pos:pos + step] if pos < len(text) else None
        if chunk is None:
            parser.feed("</tscope-root>")
        else:
            parser.feed(chunk)
            pos += step
        for _evt, el in parser.read_events():
            if _local(el.tag) != "Event":
                continue
            n += 1
            sysel = next((c for c in el if _local(c.tag) == "System"), None)
            info = {"EventID": None, "TimeCreated": None, "Computer": None, "RecordId": None, "data": {}}
            if sysel is not None:
                for c in sysel:
                    t = _local(c.tag)
                    if t == "EventID":
                        info["EventID"] = (c.text or "").strip()
                    elif t == "TimeCreated":
                        info["TimeCreated"] = c.get("SystemTime")
                    elif t == "Computer":
                        info["Computer"] = (c.text or "").strip()
                    elif t == "EventRecordID":
                        info["RecordId"] = (c.text or "").strip()
            for c in el:
                t = _local(c.tag)
                if t == "EventData":
                    for dnode in c:
                        if dnode.get("Name"):
                            info["data"][dnode.get("Name")] = (dnode.text or "").strip()
                elif t == "UserData":
                    for inner in c:
                        for dnode in inner:
                            info["data"][_local(dnode.tag)] = (dnode.text or "").strip()
            from xml.etree.ElementTree import tostring  # noqa: S405 - serialising a parsed element

            info["_raw"] = tostring(el, encoding="unicode")
            info["_loc"] = f"{relname}#{info['RecordId'] or n}"
            el.clear()
            yield info
        if chunk is None:
            break


# ---------------------------------------------------------------------------------------------- CSV
_CSV_ALIASES = {"timecreated": "TimeCreated", "time": "TimeCreated", "eventid": "EventID", "id": "EventID",
                "computer": "Computer", "machinename": "Computer", "recordid": "RecordId", "eventrecordid": "RecordId"}


def _csv_events(ctx: ParseContext, stream, relname: str):
    reader = csv.reader(text_stream(stream))
    header = None
    for row in reader:
        if not row:
            continue
        if header is None:
            header = [h.strip().lstrip("﻿") for h in row]
            continue
        d = dict(zip(header, row, strict=False))
        info = {"EventID": None, "TimeCreated": None, "Computer": None, "RecordId": None, "data": {}}
        for k, v in d.items():
            key = _CSV_ALIASES.get(k.lower())
            if key:
                info[key] = v
            elif k.lower() not in ("message", "commandline", "providername", "leveldisplayname"):
                info["data"][k] = v
        info["_raw"] = "\x1f".join(row)
        info["_loc"] = f"{relname}:{reader.line_num}"
        yield info


def parse(ctx: ParseContext, stream, relname: str):
    src = {"evtx": _evtx_events, "xml": _xml_events, "csv": _csv_events}[ctx.fmt]
    for info in src(ctx, stream, relname):
        ts, prec, abbr = parse_iso(str(info.get("TimeCreated") or ""))
        if ts is None:
            ctx.fail(info["_loc"], "unparseable TimeCreated/SystemTime")
            continue
        if to_int(info.get("EventID")) is None:
            ctx.fail(info["_loc"], "missing EventID")
            continue
        rec = map_event(ctx, info)
        rec.update(_raw=info["_raw"], _loc=info["_loc"], _ts=(ts, prec, abbr))
        yield rec
