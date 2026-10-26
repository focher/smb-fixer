"""Parsers for macOS command output."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import unquote


@dataclass
class Mount:
    server: str
    share: str
    mount_point: str
    user: str = ""
    options: list[str] = field(default_factory=list)


_MOUNT_RE = re.compile(
    r"^//(?:(?P<user>[^@/]+)@)?(?P<server>[^/]+)/(?P<share>\S+) on (?P<mp>.+?) \((?P<opts>[^)]*)\)\s*$"
)


def normalize_server(server: str) -> str:
    server = unquote(server)
    # Bonjour-resolved mounts look like "Tower._smb._tcp.local".
    return re.sub(r"\._smb\._tcp\.local\.?$", ".local", server, flags=re.I)


def smbfs_mounts(text: str) -> list[Mount]:
    mounts = []
    for line in text.splitlines():
        m = _MOUNT_RE.match(line.strip())
        if not m or "smbfs" not in m["opts"]:
            continue
        mounts.append(
            Mount(
                server=normalize_server(m["server"]),
                share=unquote(m["share"]),
                mount_point=m["mp"],
                user=unquote(m["user"] or ""),
                options=[o.strip() for o in m["opts"].split(",")],
            )
        )
    return mounts


def statshares(text: str) -> dict[str, dict[str, list[str]]]:
    """Parse `smbutil statshares -a` into {share: {ATTRIBUTE: [values...]}}."""
    shares: dict[str, dict[str, list[str]]] = {}
    current = None
    for line in text.splitlines():
        if not line.strip() or set(line.strip()) <= {"=", "-"}:
            continue
        if line.startswith("SHARE") and "ATTRIBUTE" in line:
            continue
        if not line[0].isspace():
            current = shares.setdefault(line.strip(), {})
            continue
        if current is None:
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            current.setdefault(parts[0], []).append(parts[1].strip())
        elif len(parts) == 1:
            current.setdefault(parts[0], []).append("")
    return shares


def first(attrs: dict[str, list[str]], key: str, default: str = "") -> str:
    values = attrs.get(key) or []
    return values[0] if values else default


def is_true(attrs: dict[str, list[str]], key: str) -> bool:
    return first(attrs, key).upper() == "TRUE"


def ini(text: str) -> dict[str, dict[str, str]]:
    """Loose INI parser (nsmb.conf, smb.conf). Keys are lower-cased; comments start with # or ;."""
    sections: dict[str, dict[str, str]] = {}
    current = sections.setdefault("", {})
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in "#;":
            continue
        if line.startswith("[") and line.endswith("]"):
            current = sections.setdefault(line[1:-1].strip(), {})
            continue
        if "=" in line:
            key, _, value = line.partition("=")
            current[key.strip().lower()] = value.strip()
    if not sections[""]:
        del sections[""]
    return sections


def route_interface(text: str) -> str:
    m = re.search(r"^\s*interface:\s*(\S+)", text, re.M)
    return m.group(1) if m else ""


def route_gateway(text: str) -> str:
    m = re.search(r"^\s*gateway:\s*(\S+)", text, re.M)
    return m.group(1) if m else ""


def ifconfig(text: str) -> dict[str, dict]:
    ifaces: dict[str, dict] = {}
    current = None
    for line in text.splitlines():
        m = re.match(r"^(\S+?):\s+flags=\S+\s+mtu\s+(\d+)", line)
        if m:
            current = ifaces.setdefault(m.group(1), {"mtu": int(m.group(2)), "inet": [], "media": "", "status": ""})
            continue
        if current is None:
            continue
        line = line.strip()
        if line.startswith("inet "):
            current["inet"].append(line.split()[1])
        elif line.startswith("media:"):
            current["media"] = line.partition(":")[2].strip()
        elif line.startswith("status:"):
            current["status"] = line.partition(":")[2].strip()
    return ifaces


def media_speed_mbps(media: str) -> int | None:
    """'autoselect (10GbaseT <full-duplex>)' -> 10000; '1000baseT' -> 1000."""
    m = re.search(r"(\d+(?:\.\d+)?)(G|)base", media, re.I)
    if not m:
        return None
    value = float(m.group(1))
    return int(value * 1000) if m.group(2).upper() == "G" else int(value)


def hwports(text: str) -> dict[str, str]:
    """networksetup -listallhardwareports -> {device: port name}."""
    ports: dict[str, str] = {}
    name = None
    for line in text.splitlines():
        if line.startswith("Hardware Port:"):
            name = line.partition(":")[2].strip()
        elif line.startswith("Device:") and name:
            ports[line.partition(":")[2].strip()] = name
            name = None
    return ports


def ping(text: str) -> dict:
    out: dict = {}
    m = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received.*?([\d.]+)% packet loss", text)
    if m:
        out.update(sent=int(m.group(1)), received=int(m.group(2)), loss=float(m.group(3)))
    m = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms", text)
    if m:
        out.update(min=float(m.group(1)), avg=float(m.group(2)), max=float(m.group(3)), stddev=float(m.group(4)))
    return out


def sysctl(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if sep:
            out[key.strip()] = value.strip()
    return out


@dataclass
class LogEvent:
    when: datetime | None
    side: str
    source: str
    message: str
    kind: str = ""


# Unified log compact style: "2026-10-23 10:00:00.123 E  kernel[0:1a2b] (smbfs) <message>"
_MAC_LOG_RE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+\S+\s+(\S+?)\[[^\]]*\]\s*(.*)$")


def unified_log(text: str) -> list[LogEvent]:
    events = []
    for line in text.splitlines():
        m = _MAC_LOG_RE.match(line)
        if not m:
            continue
        try:
            when = datetime.strptime(m.group(1)[:26], "%Y-%m-%d %H:%M:%S.%f")
        except ValueError:
            when = None
        events.append(LogEvent(when, "client", m.group(2), m.group(3).strip()))
    return events


def _speed_mbps(text: str) -> int | None:
    m = re.search(r"([\d.]+)\s*(G|M)b", text)
    if not m:
        return None
    return int(float(m.group(1)) * (1000 if m.group(2) == "G" else 1))


def multichannel(text: str) -> list[dict]:
    """Parse `smbutil multichannel -a` into one dict per mounted session."""
    sessions: list[dict] = []
    cur: dict | None = None
    nic: dict | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("Session:"):
            cur = {"mount": line.partition(":")[2].strip(), "channels": [], "server_nics": [], "client_nics": []}
            sessions.append(cur)
            nic = None
            continue
        if cur is None or not line:
            continue
        if line.startswith("Info:"):
            m = re.search(r"Setup Time:\s*([\d-]+ [\d:]+)", line)
            cur["setup_time"] = m.group(1) if m else ""
            m = re.search(r"Multichannel ON:\s*(\w+)", line)
            cur["multichannel_on"] = bool(m and m.group(1).lower() == "yes")
            m = re.search(r"Reconnect Count:\s*(\d+)", line)
            cur["reconnect_count"] = int(m.group(1)) if m else 0
        elif re.match(r"^[A-Z]?\s*\d+\s+\S+\s+\(", line):
            m = re.match(r"^[A-Z]?\s*(\d+)\s+(\S+)\s+\(([^)]*)\).*?\[([^\]]*)\]\s+(\S+)\s+(\d+)\s+(.*)$", line)
            if m:
                cur["channels"].append({"id": m.group(1), "client_if": m.group(2), "client_type": m.group(3),
                                        "state": m.group(4).strip(), "server_ip": m.group(5),
                                        "speed_mbps": _speed_mbps(m.group(7))})
        elif line.startswith(("Server NIC:", "Client NIC:")):
            nic = {"ips": []}
            cur["server_nics" if line.startswith("Server") else "client_nics"].append(nic)
        elif line.startswith("name:") and nic is not None:
            m = re.search(r"name:\s*([^,]+)", line)
            nic["name"] = m.group(1).strip() if m else ""
            m = re.search(r"type:\s*([^,]+)", line)
            nic["type"] = m.group(1).strip() if m else ""
            m = re.search(r"state\s+(\w+)", line)
            nic["state"] = m.group(1) if m else ""
            nic["speed_mbps"] = _speed_mbps(line)
        elif line.startswith("ip_addr:") and nic is not None:
            nic["ips"].append(line.partition(":")[2].strip())
    return sessions


_INI_LINE = re.compile(r"^\s*(?:$|[#;].*|\[[^\]]+\]\s*|[A-Za-z0-9_.:]+\s*=\s*[^\s\"|]*\s*)$")


def nsmb_problems(text: str) -> list[str]:
    """Lines in nsmb.conf that macOS will not understand (e.g. pasted shell commands)."""
    bad = []
    for line in text.splitlines():
        if not _INI_LINE.match(line):
            bad.append(line.strip())
    return bad
