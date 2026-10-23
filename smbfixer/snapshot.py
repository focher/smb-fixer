"""A snapshot is the raw command output from both ends, saved so analysis can be re-run offline."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from smbfixer.runner import Result

SCHEMA = 1


@dataclass
class Snapshot:
    created_at: float = field(default_factory=time.time)
    meta: dict = field(default_factory=dict)
    client: dict[str, Result] = field(default_factory=dict)
    host: dict[str, Result] = field(default_factory=dict)

    def add(self, side: str, result: Result) -> None:
        getattr(self, side)[result.name] = result

    def out(self, side: str, name: str) -> str:
        """stdout of a collected command, or '' if it was not collected or failed to start."""
        result = getattr(self, side).get(name)
        return result.stdout if result else ""

    def ok(self, side: str, name: str) -> bool:
        result = getattr(self, side).get(name)
        return bool(result and result.ok)

    def to_dict(self) -> dict:
        return {
            "schema": SCHEMA,
            "created_at": self.created_at,
            "meta": self.meta,
            "client": {k: v.to_dict() for k, v in self.client.items()},
            "host": {k: v.to_dict() for k, v in self.host.items()},
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Snapshot":
        if data.get("schema") != SCHEMA:
            raise ValueError(f"unsupported snapshot schema {data.get('schema')}")
        return cls(
            created_at=data["created_at"],
            meta=data.get("meta", {}),
            client={k: Result.from_dict(v) for k, v in data.get("client", {}).items()},
            host={k: Result.from_dict(v) for k, v in data.get("host", {}).items()},
        )

    def save(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=1))
        return path

    @classmethod
    def load(cls, path: Path) -> "Snapshot":
        return cls.from_dict(json.loads(Path(path).read_text()))
