"""Approved local asset mapping shared by exposure findings, access paths and containment advice.

``assets.yaml``::

    assets:
      - asset_id: AST-LABDB          # opaque, hospital-chosen
        kind: database               # database | host | application | share | identity | network
        names: [LABSQL01, labdb, 10.20.0.15, LabDB]   # any name/IP/DB the asset appears under
        owner: "Lab systems team"
        criticality: high

Cross-module joins use ``asset_id`` (and opaque finding ids), never secret values.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from .errors import ConfigError


@dataclass(frozen=True)
class Asset:
    asset_id: str
    kind: str
    names: tuple[str, ...]
    owner: str | None = None
    criticality: str | None = None


class AssetMap:
    def __init__(self, assets: list[Asset]):
        self.assets = {a.asset_id: a for a in assets}
        self._index: dict[str, str] = {}
        for a in assets:
            for n in a.names:
                key = n.strip().lower()
                if key in self._index and self._index[key] != a.asset_id:
                    raise ConfigError(f"asset name {n!r} maps to two assets")
                self._index[key] = a.asset_id

    @classmethod
    def load(cls, path: Path | str | None) -> AssetMap:
        if not path:
            return cls([])
        doc = yaml.safe_load(Path(path).read_text()) or {}
        return cls.from_list(doc.get("assets", []))

    @classmethod
    def from_list(cls, items: list[dict]) -> AssetMap:
        return cls([
            Asset(i["asset_id"], i.get("kind", "unknown"), tuple(str(n) for n in i.get("names", [])),
                  i.get("owner"), i.get("criticality"))
            for i in items
        ])

    def resolve(self, name: str | None) -> str | None:
        if not name:
            return None
        return self._index.get(str(name).strip().lower())

    def to_list(self) -> list[dict]:
        return [{"asset_id": a.asset_id, "kind": a.kind, "names": list(a.names), "owner": a.owner,
                 "criticality": a.criticality} for a in self.assets.values()]
