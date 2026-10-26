"""Parsers for Samba and Linux/Unraid host output."""

from __future__ import annotations

import json
import re
from datetime import datetime

from smbfixer.parse.macos import LogEvent, ini


def testparm(text: str) -> dict[str, dict[str, str]]:
    return ini(text)


def smb_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    v = value.strip().lower()
    if v in {"yes", "true", "1", "on", "auto"}:
        return True
    if v in {"no", "false", "0", "off", "disabled"}:
        return False
    return None


def vfs_objects(section: dict[str, str]) -> list[str]:
    return section.get("vfs objects", "").replace(",", " ").split()


def unraid_cfg(text: str) -> dict[str, str]:
    """key="value" files under /boot/config."""
    out = {}
    for line in text.splitlines():
        m = re.match(r'^\s*([A-Za-z0-9_.]+)\s*=\s*"?(.*?)"?\s*$', line)
        if m and not line.lstrip().startswith("#"):
            out[m.group(1)] = m.group(2)
    return out


def sectioned(text: str, marker: str = "### ") -> dict[str, str]:
    """Split collector output that uses '### name' headers."""
    out: dict[str, str] = {}
    name = None
    buf: list[str] = []
    for line in text.splitlines():
        if line.startswith(marker):
            if name is not None:
                out[name] = "\n".join(buf)
            name, buf = line[len(marker):].strip(), []
        elif name is not None:
            buf.append(line)
    if name is not None:
        out[name] = "\n".join(buf)
    return out


def share_cfgs(text: str) -> dict[str, dict[str, str]]:
    return {name.removesuffix(".cfg"): unraid_cfg(body) for name, body in sectioned(text).items()}


def disks_ini(text: str) -> dict[str, dict[str, str]]:
    disks: dict[str, dict[str, str]] = {}
    current = None
    for line in text.splitlines():
        m = re.match(r'^\["?([^"\]]+)"?\]\s*$', line.strip())
        if m:
            current = disks.setdefault(m.group(1), {})
        elif current is not None:
            kv = unraid_cfg(line)
            current.update(kv)
    return disks


def net(text: str) -> dict[str, dict]:
    out = {}
    for line in text.splitlines():
        parts = line.strip().split("|")
        if len(parts) == 7:  # snapshots taken before the lower-device column existed
            parts.append("-")
        if len(parts) != 8:
            continue
        name, mtu, speed, duplex, state, master, phys, lower = parts

        def num(v):
            try:
                n = int(v)
                return n if n >= 0 else None
            except ValueError:
                return None

        out[name] = {
            "mtu": num(mtu),
            "speed": num(speed),
            "duplex": duplex or None,
            "state": state,
            "master": None if master == "-" else master,
            "physical": phys == "yes",
            "lower": None if lower == "-" else lower,
        }
    return out


_STACKED = re.compile(r"^(?:shim-(?P<shim>.+)|(?P<base>.+?)\.(?:macvlan|ipvlan)\d*)$")


def is_shim_name(name: str) -> bool:
    return bool(_STACKED.match(name))


def parent_device(ifaces: dict[str, dict], name: str) -> str | None:
    """The device a macvlan/ipvlan/vlan sub-interface sits on (br0.macvlan0 -> br0, shim-br0 -> br0)."""
    info = ifaces.get(name, {})
    if info.get("lower"):
        return info["lower"]
    m = _STACKED.match(name)
    if m:
        parent = m.group("shim") or m.group("base")
        return parent if parent in ifaces else None
    return None


def physical_members(ifaces: dict[str, dict], name: str, _seen: frozenset = frozenset()) -> list[str]:
    """Resolve a bridge/bond/macvlan (br0.macvlan0 -> br0 -> bond0 -> eth0) down to physical NICs."""
    if name not in ifaces or name in _seen:
        return []
    _seen = _seen | {name}
    if ifaces[name]["physical"]:
        return [name]
    members = []
    for child, info in ifaces.items():
        if info["master"] == name:
            members += physical_members(ifaces, child, _seen)
    if not members and (parent := parent_device(ifaces, name)):
        members = physical_members(ifaces, parent, _seen)
    return members


def ip_link_stats(text: str) -> dict[str, dict]:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return {}
    out = {}
    for link in data if isinstance(data, list) else []:
        stats = link.get("stats64") or link.get("stats") or {}
        out[link.get("ifname", "?")] = {
            "rx": stats.get("rx", {}),
            "tx": stats.get("tx", {}),
            "mtu": link.get("mtu"),
            "parent": link.get("link"),
            "kind": (link.get("linkinfo") or {}).get("info_kind"),
            "tx_queues": link.get("num_tx_queues"),
        }
    return out


def routes(text: str) -> list[dict]:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []
    return [r for r in data if isinstance(r, dict)] if isinstance(data, list) else []


def addrs(text: str) -> dict[str, list[str]]:
    """ip -j addr -> {address: [interfaces holding it]}."""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return {}
    out: dict[str, list[str]] = {}
    for link in data if isinstance(data, list) else []:
        for a in link.get("addr_info", []):
            if a.get("local"):
                out.setdefault(a["local"], []).append(link.get("ifname", "?"))
    return out


def route_to_client(text: str) -> dict:
    lines = text.splitlines()
    if not lines:
        return {}
    out = {"client_ip": lines[0].strip()}
    try:
        routes = json.loads("\n".join(lines[1:]))
        if routes:
            out["dev"] = routes[0].get("dev")
            out["src"] = routes[0].get("prefsrc") or routes[0].get("from")
            out["gateway"] = routes[0].get("gateway")
    except (json.JSONDecodeError, ValueError):
        pass
    return out


def ethtool(text: str) -> dict[str, dict]:
    out = {}
    for name, body in sectioned(text).items():
        info: dict = {"counters": {}}
        for line in body.splitlines():
            line = line.strip()
            if line.startswith("Speed:"):
                m = re.search(r"(\d+)Mb/s", line)
                info["speed"] = int(m.group(1)) if m else None
            elif line.startswith("Duplex:"):
                info["duplex"] = line.partition(":")[2].strip().lower()
            elif line.startswith("Link detected:"):
                info["link"] = line.partition(":")[2].strip() == "yes"
            elif ":" in line:
                key, _, value = line.partition(":")
                if value.strip().isdigit():
                    info["counters"][key.strip()] = int(value)
        out[name] = info
    return out


def load(text: str) -> dict:
    out: dict = {}
    lines = text.splitlines()
    if lines and lines[0].strip().isdigit():
        out["cpus"] = int(lines[0])
    for line in lines[1:]:
        parts = line.split()
        if len(parts) >= 3 and re.match(r"^[\d.]+$", parts[0]) and "/" in line:
            out["load"] = [float(p) for p in parts[:3]]
        elif parts and parts[0] == "Mem:" and len(parts) >= 7:
            out["mem_total_mb"] = int(parts[1])
            out["mem_available_mb"] = int(parts[6])
        elif parts and parts[0] == "Swap:" and len(parts) >= 3:
            out["swap_used_mb"] = int(parts[2])
    return out


def vmstat(text: str) -> dict:
    """Average the sample lines of `vmstat 1 N`, skipping the since-boot first sample."""
    header = None
    rows = []
    for line in text.splitlines():
        parts = line.split()
        if "wa" in parts and "id" in parts:
            header = parts
        elif header and len(parts) == len(header) and all(p.isdigit() for p in parts):
            rows.append([int(p) for p in parts])
    if not header or not rows:
        return {}
    rows = rows[1:] or rows
    return {col: sum(r[i] for r in rows) / len(rows) for i, col in enumerate(header)}


def df(text: str) -> dict[str, dict]:
    out = {}
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 6 and parts[4].endswith("%"):
            out[parts[5]] = {"fs": parts[0], "size_kb": int(parts[1]), "used_pct": int(parts[4][:-1])}
    return out


def user_shares(text: str) -> dict[str, dict]:
    out = {}
    for line in text.splitlines():
        parts = line.strip().split("|")
        if len(parts) == 3:
            out[parts[1]] = {"exclusive": parts[0] == "symlink", "target": parts[2]}
    return out


def smbstatus_json(text: str) -> dict:
    try:
        data = json.loads(text)
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, ValueError):
        return {}


def sessions(status: dict) -> list[dict]:
    return list((status.get("sessions") or {}).values())


def tcons(status: dict) -> list[dict]:
    return list((status.get("tcons") or {}).values())


# Samba log header: "[2026/10/23 10:00:00.123456,  0] ../../source3/smbd/server.c:1234(func)"
_SAMBA_HDR = re.compile(r"^\[(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})(?:\.\d+)?,\s*(\d+)[^\]]*\]\s*(.*)$")


def samba_log(text: str) -> list[LogEvent]:
    events: list[LogEvent] = []
    pending = None
    for line in text.splitlines():
        m = _SAMBA_HDR.match(line)
        if m:
            if pending:
                events.append(pending)
            when = datetime.strptime(m.group(1), "%Y/%m/%d %H:%M:%S")
            where = m.group(3).rsplit("/", 1)[-1]
            pending = LogEvent(when, "host", f"smbd {where}".strip(), "")
        elif pending is not None and line.strip():
            pending.message = (pending.message + " " + line.strip()).strip()
    if pending:
        events.append(pending)
    return events


_SYSLOG_RE = re.compile(r"^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+([^:\[]+)(?:\[\d+\])?:\s*(.*)$")


def syslog(text: str, year: int) -> list[LogEvent]:
    events = []
    for line in text.splitlines():
        m = _SYSLOG_RE.match(line)
        if not m:
            continue
        try:
            when = datetime.strptime(f"{year} {m.group(1)}", "%Y %b %d %H:%M:%S")
        except ValueError:
            when = None
        events.append(LogEvent(when, "host", m.group(2).strip(), m.group(3).strip()))
    return events
