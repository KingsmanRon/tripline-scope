"""Command execution context: authentication, case-role authorisation, source integrity and audit logging.

Every ``tscope`` command that touches a case runs inside :func:`command`::

    with command("scope match", case=case, home=home, role="operator", params={...}) as ctx:
        store = ctx.store
        ...
        ctx.output("people", store.file_sha256("work/scope/people.parquet"))

On exit one audit entry is appended (outcome ``ok``, ``denied`` or ``error`` with the exception class only).
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field

from .auth import Identity, current_identity
from .case import Case
from .custody import protect_case_sources, quick_check
from .errors import PermissionDenied, SourceModified, TriplineError
from .home import Home


@dataclass
class Ctx:
    home: Home
    case: Case | None
    identity: Identity | None
    role: str | None
    params: dict = field(default_factory=dict)
    inputs: dict = field(default_factory=dict)
    outputs: dict = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    _store: object = None

    @property
    def actor(self) -> str | None:
        return self.identity.username if self.identity else None

    @property
    def store(self):
        if self._store is None:
            from .store import open_store

            if self.case is None:
                raise TriplineError("no case")
            self._store = open_store(self.case, self.home)
        return self._store

    def input(self, label: str, sha256: str) -> None:
        self.inputs[label] = sha256

    def output(self, label: str, sha256: str) -> None:
        self.outputs[label] = sha256

    def note(self, text: str) -> None:
        self.notes.append(text)


def require_case_role(case: Case, ident: Identity, role: str) -> None:
    if role == "admin":
        if "admin" not in ident.system_roles:
            raise PermissionDenied("requires the admin system role")
        return
    if role not in case.roles_of(ident.username):
        raise PermissionDenied(f"user is not assigned the {role} role on this case")
    if role == "operator" and ident.username in case.audit.actors_with_role("approver", case.case_id):
        raise PermissionDenied("separation of duties: approver of this case cannot act as operator")
    if role == "approver" and ident.username in case.audit.actors_with_role("operator", case.case_id):
        raise PermissionDenied("separation of duties: operator of this case cannot act as approver")


@contextmanager
def command(
    name: str,
    *,
    home: Home,
    case: Case | None = None,
    role: str | None = None,
    params: dict | None = None,
    identity: Identity | None = None,
    allow_closed: bool = False,
    anonymous: bool = False,
):
    ident = identity if identity is not None else current_identity(home, required=not anonymous)
    ctx = Ctx(home=home, case=case, identity=ident, role=role, params=dict(params or {}))
    log = case.audit if case is not None else None
    if log is None:
        from .audit import AuditLog

        log = AuditLog(home.audit_path)
    case_id = case.case_id if case is not None else None
    try:
        if case is not None:
            if not allow_closed:
                case.require_open()
            if role and ident is not None:
                require_case_role(case, ident, role)
            protect_case_sources(case)
            problems = quick_check(case)
            if problems and not allow_closed:
                raise SourceModified("source changed since registration: " + "; ".join(problems))
            ctx.input("case.yaml", case.config_sha256())
        elif role == "admin" and ident is not None and "admin" not in ident.system_roles:
            raise PermissionDenied("requires the admin system role")
        yield ctx
        if case is not None and not allow_closed:
            problems = quick_check(case)
            if problems:
                raise SourceModified("source changed during command: " + "; ".join(problems))
    except PermissionDenied as exc:
        log.append(command=name, actor=ctx.actor, role=role, case_id=case_id, outcome="denied",
                   params=ctx.params, error_class=type(exc).__name__)
        raise
    except BaseException as exc:
        log.append(command=name, actor=ctx.actor, role=role, case_id=case_id, outcome="error",
                   params=ctx.params, inputs=ctx.inputs, outputs=ctx.outputs, error_class=type(exc).__name__)
        raise
    else:
        log.append(command=name, actor=ctx.actor, role=role, case_id=case_id, outcome="ok", params=ctx.params,
                   inputs=ctx.inputs, outputs=ctx.outputs, note="; ".join(ctx.notes) if ctx.notes else None)
