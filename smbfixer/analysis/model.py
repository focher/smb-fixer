from __future__ import annotations

from dataclasses import asdict, dataclass, field

SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2, "ok": 3}

# Recommendation targets. Settings with the same target are merged into one snippet in the report.
CLIENT_NSMB = "client:/etc/nsmb.conf"
CLIENT_SHELL = "client:shell"
HOST_SMB_EXTRA = "host:/boot/config/smb-extra.conf"
HOST_UI = "host:Unraid web UI"
HOST_SHELL = "host:shell"
NETWORK = "network"


@dataclass
class Recommendation:
    target: str
    action: str  # "key = value", a command, or a UI step
    why: str = ""
    section: str = ""  # config section, e.g. "default", "global", or a share name
    tradeoff: str = ""  # set when the change trades safety/compatibility for speed
    remove_key: str = ""  # set when the fix is deleting an existing line rather than setting a value

    @property
    def side(self) -> str:
        return self.target.split(":", 1)[0]


@dataclass
class Finding:
    id: str
    severity: str
    category: str  # network | client | host | storage | logs | correlation | performance
    title: str
    detail: str = ""
    evidence: list[str] = field(default_factory=list)
    recommendations: list[Recommendation] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)
