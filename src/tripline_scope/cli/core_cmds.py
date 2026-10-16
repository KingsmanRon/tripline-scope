"""Shared commands: installation, users, sign-in, cases, sources, audit, release, verification and closure."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from tripline_scope.cli import emit
from tripline_scope.cli.common import (
    add_approver_args,
    add_case_arg,
    approver_sign_in,
    case_of,
    home_of,
    read_password,
)
from tripline_scope.core import custody, hostcheck
from tripline_scope.core.auth import (
    UserStore,
    create_session,
    current_identity,
    end_session,
    identity_provider,
    save_cli_token,
)
from tripline_scope.core.case import Case
from tripline_scope.core.closure import close_case
from tripline_scope.core.context import command
from tripline_scope.core.errors import ConfigError
from tripline_scope.core.home import Home, get_secret
from tripline_scope.core.keys import generate_keypair, key_id, load_public_key
from tripline_scope.core.reports import KINDS, ReportStore


# ------------------------------------------------------------------------------------------------ install
def cmd_init(args):
    root = Path(args.home) if args.home else _default_home()
    kek_pw = None if args.no_kek_passphrase else get_secret("New hospital KEK passphrase", "TSCOPE_KEK_PASSPHRASE", confirm=True)
    sign_pw = get_secret("New hospital signing key passphrase", "TSCOPE_HOSPITAL_KEY_PASSPHRASE", confirm=True)
    home = Home.init(root, hospital_name=args.hospital_name, kek_path=args.kek, kek_passphrase=kek_pw,
                     hospital_key_passphrase=sign_pw, keystore_dir=args.keystore)
    pw = read_password(args, "TSCOPE_PASSWORD", f"Password for new admin {args.admin}")
    UserStore(home).add(args.admin, pw, system_roles=["admin"])
    from tripline_scope.core.audit import AuditLog

    AuditLog(home.audit_path).append(command="init", actor=args.admin, role="admin", case_id=None,
                                     params={"hospital_key_id": key_id(load_public_key(home.hospital_public_key_path))})
    emit(args, {"home": str(home.root), "hospital_signing_key_id": key_id(load_public_key(home.hospital_public_key_path)),
                "admin": args.admin})


def _default_home():
    from tripline_scope.core.home import default_home

    return default_home()


def cmd_doctor(args):
    home = home_of(args)
    w = hostcheck.warnings(home)
    import duckdb

    from tripline_scope import __version__

    emit(args, {"version": __version__, "duckdb": duckdb.__version__, "warnings": w},
         "\n".join([f"tscope {__version__} (duckdb {duckdb.__version__})"] + [f"WARNING: {x}" for x in w] or ["no warnings"]))


# ------------------------------------------------------------------------------------------------ users
def cmd_user_add(args):
    home = home_of(args)
    with command("user add", home=home, role="admin", params={"user": args.user, "admin": args.admin}):
        pw = read_password(args, "TSCOPE_NEW_USER_PASSWORD", f"Password for {args.user}")
        UserStore(home).add(args.user, pw, system_roles=["admin"] if args.admin else [], display=args.display or "")
    emit(args, {"created": args.user})


def cmd_user_list(args):
    home = home_of(args)
    users = UserStore(home).list()
    emit(args, {"users": users}, "\n".join(f"{u['username']:20} roles={','.join(u['system_roles']) or '-'} "
                                           f"totp={'yes' if u['totp'] else 'no'} {'DISABLED' if u['disabled'] else ''}"
                                           for u in users))


def cmd_user_passwd(args):
    home = home_of(args)
    with command("user passwd", home=home, role="admin", params={"user": args.user}):
        UserStore(home).set_password(args.user, read_password(args, "TSCOPE_NEW_USER_PASSWORD", f"New password for {args.user}"))
    emit(args, {"updated": args.user})


def cmd_user_disable(args):
    home = home_of(args)
    with command("user disable" if args.disable else "user enable", home=home, role="admin", params={"user": args.user}):
        UserStore(home).set_disabled(args.user, args.disable)
    emit(args, {"user": args.user, "disabled": args.disable})


def cmd_user_totp(args):
    home = home_of(args)
    with command("user totp-enroll", home=home, role="admin", params={"user": args.user}):
        uri = UserStore(home).enroll_totp(args.user)
    # Shown once to enrol the authenticator app; this is an account secret, not patient data.
    print(uri)


def cmd_login(args):
    home = home_of(args)
    pw = read_password(args, "TSCOPE_PASSWORD", f"Password for {args.user}")
    from tripline_scope.core.audit import AuditLog

    log = AuditLog(home.audit_path)
    try:
        ident = identity_provider(home).authenticate(args.user, pw, args.totp)
    except Exception as exc:
        log.append(command="login", actor=args.user, role=None, case_id=None, outcome="denied", error_class=type(exc).__name__)
        raise
    token = create_session(home, ident)
    if args.print_token:
        print(token)
    else:
        save_cli_token(token)
    log.append(command="login", actor=ident.username, role=None, case_id=None, params={"auth": ident.auth_method})
    if not args.print_token:
        emit(args, {"signed_in": ident.username, "auth": ident.auth_method})


def cmd_logout(args):
    end_session(home_of(args))
    emit(args, {"signed_out": True})


def cmd_whoami(args):
    ident = current_identity(home_of(args))
    emit(args, {"user": ident.username, "system_roles": sorted(ident.system_roles), "auth": ident.auth_method})


# ------------------------------------------------------------------------------------------------ keys
def cmd_keys_generate(args):
    out = Path(args.out)
    pw = get_secret(f"Passphrase for new {args.role} key", f"TSCOPE_{args.role.upper()}_KEY_PASSPHRASE", confirm=True)
    kid = generate_keypair(out / f"{args.role}_signing.pem", out / f"{args.role}_signing.pub", pw)
    emit(args, {"role": args.role, "key_id": kid, "private_key": str(out / f"{args.role}_signing.pem"),
                "public_key": str(out / f"{args.role}_signing.pub")})


def cmd_keys_provider(args):
    home = home_of(args)
    with command("keys set-provider", home=home, role="admin", params={"name": args.name}):
        pub = load_public_key(args.public_key)
        home.config["signing"]["provider_public_key"] = str(Path(args.public_key).resolve())
        home.config["signing"]["provider_private_key"] = str(Path(args.private_key).resolve()) if args.private_key else None
        home.config["signing"]["provider_name"] = args.name
        home.save_config()
    emit(args, {"provider": args.name, "key_id": key_id(pub)})


def cmd_keys_show(args):
    home = home_of(args)
    out = {"hospital_key_id": key_id(load_public_key(home.hospital_public_key_path)),
           "hospital_public_key": str(home.hospital_public_key_path)}
    if home.config["signing"].get("provider_public_key"):
        out["provider_key_id"] = key_id(load_public_key(home.config["signing"]["provider_public_key"]))
        out["provider_name"] = home.config["signing"].get("provider_name")
    emit(args, out)


# ------------------------------------------------------------------------------------------------ cases
def cmd_case_init(args):
    home = home_of(args)
    ident = current_identity(home)
    if "admin" not in ident.system_roles and ident.username not in (args.approver or []):
        raise ConfigError("cases are opened by an admin or by one of the case's approvers")
    case = Case.init(args.dir, home, case_id=args.case_id, mode=args.mode, incident_start=args.incident_start,
                     incident_end=args.incident_end, operators=args.operator or [], reviewers=args.reviewer or [],
                     approvers=args.approver or [], retain_reports_until=args.retain_until, title=args.title or "")
    with command("case init", home=home, case=case, params={"mode": args.mode, "team": case.team()}) as ctx:
        ctx.output("case.yaml", case.config_sha256())
    emit(args, {"case_id": case.case_id, "dir": str(case.root), "mode": case.mode})


def cmd_case_show(args):
    case = case_of(args)
    out = {k: case.config.get(k) for k in ("case_id", "mode", "incident_window", "team", "legal_hold", "retention",
                                            "declared_gaps")}
    out["status"] = case.state.get("status")
    out["sources"] = [{k: s.get(k) for k in ("source_id", "kind", "label", "evidence_role", "mode", "received_at")}
                      for s in case.sources()]
    emit(args, out)


def cmd_case_assign(args):
    home, case = home_of(args), case_of(args)
    ident = current_identity(home)
    role = "admin" if "admin" in ident.system_roles else "approver"
    with command("case assign", home=home, case=case, role=role, params={"user": args.user, "role": args.role,
                                                                           "remove": args.remove}):
        if not identity_provider(home).exists(args.user):
            raise ConfigError("unknown user")
        if args.remove:
            case.unassign(args.user, args.role)
        else:
            case.assign(args.user, args.role)
    emit(args, {"team": case.team()})


def cmd_case_gap(args):
    home, case = home_of(args), case_of(args)
    with command("case gap", home=home, case=case, role="operator", params={"affects": args.affects}) as ctx:
        gid = case.add_gap(args.description, args.affects or [])
        ctx.output("case.yaml", case.config_sha256())
    emit(args, {"gap_id": gid})


def cmd_case_hold(args):
    home, case = home_of(args), case_of(args)
    active = args.state == "on"
    with command("case hold", home=home, case=case, role="approver", params={"active": active}) as ctx:
        case.set_legal_hold(active, args.reason, ctx.actor)
    emit(args, {"legal_hold": case.legal_hold})


def cmd_case_close(args):
    home, case = home_of(args), case_of(args)
    approver = approver_sign_in(args, home, case)
    with command("case close", home=home, case=case, role="approver", identity=approver,
                 params={"external_backups": len(args.external_backup or [])}) as ctx:
        store = ctx.store
        custody.full_check(case, store) if not args.skip_source_check else None
        cert = close_case(case, home, store, approver=approver, hospital=home.hospital_signer(),
                          external_backups=args.external_backup or [], retain_reports_until=args.retain_until)
        from tripline_scope.core.canonical import sha256_file

        ctx.output("destruction_certificate", sha256_file(cert))
    emit(args, {"closed": case.case_id, "certificate": str(cert)})


# ------------------------------------------------------------------------------------------------ sources
def cmd_source_add(args):
    home, case = home_of(args), case_of(args)
    params = {"kind": args.kind, "evidence_role": args.evidence_role, "mode": "encrypted_copy" if args.copy else "reference"}
    with command("source add", home=home, case=case, role="operator", params=params) as ctx:
        rec = custody.add_source(
            case, ctx.store, kind=args.kind, paths=[Path(p) for p in (args.path or [])], label=args.label,
            evidence_role=args.evidence_role, legal_basis=args.legal_basis, supplied_by=args.supplied_by,
            received_at=args.received_at, registered_by=ctx.actor, mode=params["mode"],
        )
        for f in rec["files"]:
            ctx.input(f"{rec['source_id']}/{f['name']}", f.get("sha256") or f.get("tree_sha256"))
        ctx.output("manifest", rec["manifest_sha256"])
        if not rec["read_only_media"]:
            ctx.note("source path is writable by this process; integrity relies on hashing and the write guard")
    emit(args, {"source_id": rec["source_id"], "files": [{"name": f["name"], "sha256": f.get("sha256") or f.get("tree_sha256"),
                                                          "size": f.get("size")} for f in rec["files"]],
                "read_only_media": rec["read_only_media"]})


def cmd_source_list(args):
    case = case_of(args)
    rows = [{k: s.get(k) for k in ("source_id", "kind", "label", "evidence_role", "mode", "supplied_by", "received_at",
                                   "legal_basis")} for s in case.sources()]
    emit(args, {"sources": rows}, "\n".join(f"{r['source_id']}  {r['kind']:12} {r['evidence_role']:14} {r['label']}"
                                            for r in rows) or "no sources")


def cmd_source_verify(args):
    home, case = home_of(args), case_of(args)
    with command("source verify", home=home, case=case, role=None, params={"full": args.full},
                 allow_closed=case.is_closed) as ctx:
        if args.full:
            hashes = custody.full_check(case, None)
            for k, v in hashes.items():
                ctx.input(k, v)
            result = {"verified": len(hashes), "mode": "full sha256"}
        else:
            problems = custody.quick_check(case)
            if problems:
                raise custody.SourceModified("; ".join(problems))
            result = {"verified": sum(len(s.get("files", [])) for s in case.sources()), "mode": "size+mtime"}
    emit(args, result)


# ------------------------------------------------------------------------------------------------ audit
def cmd_audit_verify(args):
    log_path = Path(args.log) if args.log else (case_of(args).audit.path if args.case else home_of(args).audit_path)
    from tscope_verify.audit import verify_audit_log

    res = verify_audit_log(log_path)
    emit(args, res.as_dict(), res.render())
    return 0 if res.ok else 1


def cmd_audit_export(args):
    case = case_of(args)
    n = case.audit.export_jsonl(args.out)
    emit(args, {"exported": n, "out": args.out})


# ------------------------------------------------------------------------------------------------ release / verify
def cmd_release(args):
    home, case = home_of(args), case_of(args)
    approver = approver_sign_in(args, home, case)
    with command("release", home=home, case=case, role="approver", identity=approver,
                 params={"kind": args.kind, "draft": args.draft}) as ctx:
        rs = ReportStore(case)
        draft = rs.get_draft(args.kind, args.draft)
        ctx.input("draft_report", draft.report_sha256)
        vdir = rs.release(args.kind, args.draft, approver=approver, hospital=home.hospital_signer())
        from tripline_scope.core.canonical import sha256_file

        ctx.output("release.json", sha256_file(vdir / "release.json"))
        ctx.output("report.json", sha256_file(vdir / "report.json"))
        res = rs.verify(args.kind, home)
        if not res.ok:
            raise ConfigError("released chain failed verification:\n" + res.render())
    emit(args, {"released": str(vdir), "kind": args.kind, "version": int(vdir.name[1:])})


def cmd_reports(args):
    case = case_of(args)
    rs = ReportStore(case)
    out = {}
    for kind in sorted(KINDS):
        vs = rs.versions(kind)
        ds = rs.drafts(kind)
        if vs or ds:
            out[kind] = {"released": [n for n, _ in vs], "drafts": [d.draft_id for d in ds]}
    emit(args, out, "\n".join(f"{k:10} released={v['released']} drafts={v['drafts']}" for k, v in out.items()) or "no reports")


def cmd_verify(args):
    """Verify a case with the installation's pinned keys, or pass through to the stand-alone verifier."""
    if args.rest:
        from tscope_verify.cli import main as vmain

        return vmain(args.rest)
    home, case = home_of(args), case_of(args)
    rs = ReportStore(case)
    from tscope_verify.audit import verify_audit_log
    from tscope_verify.certificate import verify_certificate

    results = []
    for kind in sorted(KINDS):
        if rs.versions(kind):
            results.append(rs.verify(kind, home))
    results.append(verify_audit_log(case.audit.path))
    cert = case.dir("reports") / "closure" / "certificate.json"
    if cert.exists():
        results.append(verify_certificate(cert, hospital_keys=home.trusted_hospital_keys()))
    ok = all(r.ok for r in results)
    emit(args, {"ok": ok, "results": [r.as_dict() for r in results]}, "\n".join(r.render() for r in results))
    return 0 if ok else 1


# ------------------------------------------------------------------------------------------------ registration
def register(sub):
    p = sub.add_parser("init", help="initialise an installation home (KEK, hospital signing key, first admin)")
    p.add_argument("--hospital-name", required=True)
    p.add_argument("--kek", help="path for the hospital KEK file (default <home>/kek/kek.json; use removable media)")
    p.add_argument("--keystore", help="keystore directory for wrapped case keys (default <home>/keystore)")
    p.add_argument("--no-kek-passphrase", action="store_true", help="store the KEK unwrapped (protect the file instead)")
    p.add_argument("--admin", required=True)
    p.add_argument("--password-stdin", action="store_true")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("doctor", help="check host settings (swap, KEK permissions, spill settings)")
    p.set_defaults(func=cmd_doctor)

    u = sub.add_parser("user", help="manage local accounts (admin)").add_subparsers(dest="user_cmd", required=True)
    p = u.add_parser("add")
    p.add_argument("user")
    p.add_argument("--admin", action="store_true")
    p.add_argument("--display")
    p.add_argument("--password-stdin", action="store_true")
    p.set_defaults(func=cmd_user_add)
    p = u.add_parser("list")
    p.set_defaults(func=cmd_user_list)
    p = u.add_parser("passwd")
    p.add_argument("user")
    p.add_argument("--password-stdin", action="store_true")
    p.set_defaults(func=cmd_user_passwd)
    for name, dis in (("disable", True), ("enable", False)):
        p = u.add_parser(name)
        p.add_argument("user")
        p.set_defaults(func=cmd_user_disable, disable=dis)
    p = u.add_parser("totp-enroll")
    p.add_argument("user")
    p.set_defaults(func=cmd_user_totp)

    p = sub.add_parser("login", help="sign in (local account; TOTP if enrolled)")
    p.add_argument("--user", required=True)
    p.add_argument("--totp")
    p.add_argument("--password-stdin", action="store_true")
    p.add_argument("--print-token", action="store_true", help="print the session token instead of storing it")
    p.set_defaults(func=cmd_login)
    sub.add_parser("logout").set_defaults(func=cmd_logout)
    sub.add_parser("whoami").set_defaults(func=cmd_whoami)

    k = sub.add_parser("keys", help="signing keys").add_subparsers(dest="keys_cmd", required=True)
    p = k.add_parser("generate", help="generate an Ed25519 key pair (e.g. for the provider or release signing)")
    p.add_argument("--role", choices=["provider", "release"], required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_keys_generate)
    p = k.add_parser("set-provider", help="configure the provider co-signing key (admin)")
    p.add_argument("--name", required=True)
    p.add_argument("--public-key", required=True)
    p.add_argument("--private-key")
    p.set_defaults(func=cmd_keys_provider)
    k.add_parser("show").set_defaults(func=cmd_keys_show)

    c = sub.add_parser("case", help="case lifecycle").add_subparsers(dest="case_cmd", required=True)
    p = c.add_parser("init", help="open a new case directory")
    p.add_argument("dir")
    p.add_argument("--case-id", required=True)
    p.add_argument("--mode", choices=["incident", "readiness"], default="incident")
    p.add_argument("--incident-start")
    p.add_argument("--incident-end")
    p.add_argument("--operator", action="append")
    p.add_argument("--reviewer", action="append")
    p.add_argument("--approver", action="append")
    p.add_argument("--retain-until", help="date until which signed reports are retained")
    p.add_argument("--title")
    p.set_defaults(func=cmd_case_init)
    p = c.add_parser("show")
    add_case_arg(p)
    p.set_defaults(func=cmd_case_show)
    p = c.add_parser("assign")
    add_case_arg(p)
    p.add_argument("--user", required=True)
    p.add_argument("--role", choices=["operator", "reviewer", "approver"], required=True)
    p.add_argument("--remove", action="store_true")
    p.set_defaults(func=cmd_case_assign)
    p = c.add_parser("gap", help="declare an evidence gap (e.g. missing logs)")
    add_case_arg(p)
    p.add_argument("--description", required=True)
    p.add_argument("--affects", action="append")
    p.set_defaults(func=cmd_case_gap)
    p = c.add_parser("hold", help="set or lift a legal hold (approver)")
    add_case_arg(p)
    p.add_argument("state", choices=["on", "off"])
    p.add_argument("--reason")
    p.set_defaults(func=cmd_case_hold)
    p = c.add_parser("close", help="close the case: destroy keys and working data, sign a destruction certificate")
    add_case_arg(p)
    add_approver_args(p)
    p.add_argument("--external-backup", action="append", help="declare a residual backup that may hold case data")
    p.add_argument("--retain-until")
    p.add_argument("--skip-source-check", action="store_true", help="originals already returned to the hospital")
    p.set_defaults(func=cmd_case_close)

    s = sub.add_parser("source", help="register and verify sources (chain of custody)").add_subparsers(
        dest="source_cmd", required=True)
    p = s.add_parser("add")
    add_case_arg(p)
    p.add_argument("--kind", required=True, choices=sorted(custody.SOURCE_KINDS))
    p.add_argument("--path", action="append")
    p.add_argument("--label", required=True)
    p.add_argument("--evidence-role", required=True, choices=sorted(custody.EVIDENCE_ROLES))
    p.add_argument("--legal-basis", required=True)
    p.add_argument("--supplied-by", required=True)
    p.add_argument("--received-at", required=True)
    p.add_argument("--copy", action="store_true", help="store an encrypted copy instead of a read-only reference")
    p.set_defaults(func=cmd_source_add)
    p = s.add_parser("list")
    add_case_arg(p)
    p.set_defaults(func=cmd_source_list)
    p = s.add_parser("verify")
    add_case_arg(p)
    p.add_argument("--full", action="store_true", help="re-hash every source (SHA-256)")
    p.set_defaults(func=cmd_source_verify)

    a = sub.add_parser("audit", help="audit log").add_subparsers(dest="audit_cmd", required=True)
    p = a.add_parser("verify")
    add_case_arg(p)
    p.add_argument("--log", help="verify this audit log file instead")
    p.set_defaults(func=cmd_audit_verify)
    p = a.add_parser("export", help="export as JSON Lines for the SIEM")
    add_case_arg(p)
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_audit_export)

    p = sub.add_parser("release", help="approver signs a draft report into a new immutable version")
    add_case_arg(p)
    p.add_argument("--kind", required=True, choices=sorted(KINDS))
    p.add_argument("--draft")
    add_approver_args(p)
    p.set_defaults(func=cmd_release)

    p = sub.add_parser("reports", help="list released versions and drafts")
    add_case_arg(p)
    p.set_defaults(func=cmd_reports)

    p = sub.add_parser("verify", help="verify a case offline, or pass arguments to tscope-verify")
    add_case_arg(p)
    p.add_argument("rest", nargs=argparse.REMAINDER, help="e.g. 'report DIR --hospital-key K' (stand-alone verifier)")
    p.set_defaults(func=cmd_verify)


__all__ = ["register", "sys"]
