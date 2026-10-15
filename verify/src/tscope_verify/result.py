from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""


@dataclass
class Result:
    subject: str
    checks: list[Check] = field(default_factory=list)
    info: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return bool(self.checks) and all(c.ok for c in self.checks)

    def add(self, name: str, ok: bool, detail: str = "") -> bool:
        self.checks.append(Check(name, bool(ok), detail))
        return bool(ok)

    def extend(self, other: Result, prefix: str = "") -> None:
        for c in other.checks:
            self.checks.append(Check(prefix + c.name, c.ok, c.detail))

    def as_dict(self) -> dict:
        return {
            "subject": self.subject,
            "ok": self.ok,
            "checks": [{"name": c.name, "ok": c.ok, "detail": c.detail} for c in self.checks],
            "info": self.info,
        }

    def render(self) -> str:
        lines = [f"{'PASS' if self.ok else 'FAIL'}  {self.subject}"]
        for c in self.checks:
            lines.append(f"  [{'ok' if c.ok else 'FAIL'}] {c.name}{(': ' + c.detail) if c.detail else ''}")
        return "\n".join(lines)
