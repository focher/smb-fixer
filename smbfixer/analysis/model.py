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

# Where each target is carried out, in the order the report lists them.
MACHINES = {
    CLIENT_NSMB: "Mac",
    CLIENT_SHELL: "Mac",
    HOST_SMB_EXTRA: "Unraid server",
    HOST_SHELL: "Unraid server",
    HOST_UI: "Unraid web UI",
    NETWORK: "Network",
}
MACHINE_HEADINGS = {
    "Mac": "On this Mac (Terminal)",
    "Unraid server": "On the Unraid server",
    "Unraid web UI": "In the Unraid web UI (any browser, http://<server>)",
    "Network": "On the network (cables, switch, router)",
}
WHERE = {
    CLIENT_NSMB: "Mac: /etc/nsmb.conf",
    CLIENT_SHELL: "Mac: Terminal",
    HOST_SMB_EXTRA: "Unraid: Settings > SMB > SMB Extras",
    HOST_SHELL: "Unraid: terminal / SSH",
    HOST_UI: "Unraid web UI",
    NETWORK: "Network",
}


@dataclass
class Recommendation:
    target: str
    action: str  # "key = value", a command, or a UI step
    why: str = ""
    section: str = ""  # config section, e.g. "default", "global", or a share name
    tradeoff: str = ""  # set when the change trades safety/compatibility for speed
    remove_key: str = ""  # set when the fix is deleting an existing line rather than setting a value
    drop_lines: list[str] = field(default_factory=list)  # exact lines to delete (e.g. malformed nsmb.conf)
    command: list[str] = field(default_factory=list)  # argv `smbfixer apply` may run on that machine
    check: bool = False  # a command that only inspects; not a change

    @property
    def side(self) -> str:
        return self.target.split(":", 1)[0]

    @property
    def machine(self) -> str:
        return MACHINES.get(self.target, self.side)

    @property
    def where(self) -> str:
        return WHERE.get(self.target, self.target)

    @property
    def automatic(self) -> bool:
        """`smbfixer apply` can make this change itself."""
        if self.check:
            return False
        return self.target in {CLIENT_NSMB, HOST_SMB_EXTRA} or bool(self.command)


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
