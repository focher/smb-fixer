"""Facts: everything the rules need, parsed once from a snapshot."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from smbfixer.analysis import logs
from smbfixer.parse import macos as pm
from smbfixer.parse import samba as ps
from smbfixer.snapshot import Snapshot


@dataclass
class Facts:
    snap: Snapshot
    have_client: bool = False
    have_host: bool = False

    # client
    macos_version: str = ""
    mounts: list[pm.Mount] = field(default_factory=list)
    mount: pm.Mount | None = None
    share_attrs: dict[str, list[str]] = field(default_factory=dict)
    nsmb: dict[str, str] = field(default_factory=dict)
    nsmb_present: bool = False
    nsmb_problems: dict[str, list[str]] = field(default_factory=dict)  # file -> unparseable lines
    multichannel: dict = field(default_factory=dict)  # session for the mount under test
    all_channel_ids: set[str] = field(default_factory=set)
    client_iface: str = ""
    client_iface_info: dict = field(default_factory=dict)
    client_iface_port: str = ""
    client_ifaces: dict[str, dict] = field(default_factory=dict)
    client_ports: dict[str, str] = field(default_factory=dict)
    client_gateway: str = ""
    ping: dict = field(default_factory=dict)
    ping_jumbo: dict = field(default_factory=dict)
    ping_1500: dict = field(default_factory=dict)
    ds_store_disabled: bool = False
    client_events: list = field(default_factory=list)
    client_epoch: int | None = None
    client_tz: timedelta | None = None
    episodes: list = field(default_factory=list)  # real trouble; idle closes are kept apart
    idle_closes: list = field(default_factory=list)
    loops: list = field(default_factory=list)

    # host
    unraid_version: str = ""
    samba_version: tuple[int, ...] = ()
    smbconf: dict[str, dict[str, str]] = field(default_factory=dict)
    share_name: str = ""
    share_conf: dict[str, str] = field(default_factory=dict)
    smb_extra: dict[str, dict[str, str]] = field(default_factory=dict)
    ident: dict[str, str] = field(default_factory=dict)
    share_cfg: dict[str, str] = field(default_factory=dict)
    disk_cfg: dict[str, str] = field(default_factory=dict)
    disks: dict[str, dict[str, str]] = field(default_factory=dict)
    user_shares: dict[str, dict] = field(default_factory=dict)
    host_ifaces: dict[str, dict] = field(default_factory=dict)
    host_route: dict = field(default_factory=dict)
    host_phys: list[str] = field(default_factory=list)
    host_routes: list[dict] = field(default_factory=list)
    host_addrs: dict[str, list[str]] = field(default_factory=dict)
    link_stats: dict[str, dict] = field(default_factory=dict)
    ethtool: dict[str, dict] = field(default_factory=dict)
    load: dict = field(default_factory=dict)
    vmstat: dict = field(default_factory=dict)
    df: dict[str, dict] = field(default_factory=dict)
    smbstatus: dict = field(default_factory=dict)
    client_sessions: list[dict] = field(default_factory=list)
    host_events: list = field(default_factory=list)
    host_epoch: int | None = None
    host_tz: timedelta | None = None
    iperf3_on_host: bool = False
    array: dict[str, str] = field(default_factory=dict)
    host_boot: datetime | None = None  # on the client's wall clock

    # derived
    clock_skew: float | None = None  # host - client, seconds
    correlations: list = field(default_factory=list)
    bench: dict = field(default_factory=dict)
    stalls: list = field(default_factory=list)

    @property
    def smb_global(self) -> dict[str, str]:
        return self.smbconf.get("global", {})

    def smb_param(self, key: str, default: str | None = None) -> str | None:
        """Effective value for the share under test: share section wins over [global]."""
        key = key.lower()
        if key in self.share_conf:
            return self.share_conf[key]
        return self.smb_global.get(key, default)

    def attr(self, key: str) -> str:
        return pm.first(self.share_attrs, key)


def _tz(text: str) -> tuple[int | None, timedelta | None]:
    m = re.match(r"^\s*(\d+)\s+([+-])(\d{2})(\d{2})", text)
    if not m:
        return None, None
    sign = 1 if m.group(2) == "+" else -1
    return int(m.group(1)), sign * timedelta(hours=int(m.group(3)), minutes=int(m.group(4)))


def _samba_version(text: str) -> tuple[int, ...]:
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", text)
    return tuple(int(x) for x in m.groups()) if m else ()


def _find_share(smbconf: dict, share: str) -> tuple[str, dict]:
    for name, section in smbconf.items():
        if name.lower() == share.lower():
            return name, section
    return share, {}


def align(events, shift: timedelta):
    """Shift naive host timestamps onto the client's local wall clock."""
    for e in events:
        if e.when:
            e.when = e.when - shift
    return events


def build_facts(snap: Snapshot) -> Facts:
    f = Facts(snap=snap)
    f.have_client = bool(snap.client)
    f.have_host = bool(snap.host) and snap.ok("host", "date")
    f.bench = snap.meta.get("bench", {})
    f.stalls = snap.meta.get("stalls", [])

    # ---------------- client ----------------
    if f.have_client:
        m = re.search(r"ProductVersion:\s*(\S+)", snap.out("client", "sw_vers"))
        f.macos_version = m.group(1) if m else ""
        f.mounts = pm.smbfs_mounts(snap.out("client", "mount"))
        mp = snap.meta.get("mount_point", "")
        f.mount = next((m for m in f.mounts if m.mount_point == mp), None)
        shares = pm.statshares(snap.out("client", "statshares"))
        if f.mount:
            f.share_attrs = shares.get(f.mount.share) or next(
                (v for k, v in shares.items() if k.lower() == f.mount.share.lower()), {})
        elif len(shares) == 1:
            f.share_attrs = next(iter(shares.values()))

        parsed = {}
        for name, path in (("nsmb_user", "~/Library/Preferences/nsmb.conf"), ("nsmb_system", "/etc/nsmb.conf")):
            text = snap.out("client", name)
            bad = pm.nsmb_problems(text)
            if bad:
                f.nsmb_problems[path] = bad
            good = "\n".join(line for line in text.splitlines() if line.strip() not in bad)
            parsed[name] = pm.ini(good).get("default", {})
        # /etc/nsmb.conf takes precedence over the per-user file
        f.nsmb = {**parsed["nsmb_user"], **parsed["nsmb_system"]}
        f.nsmb_present = snap.ok("client", "nsmb_system") or snap.ok("client", "nsmb_user")

        mc = pm.multichannel(snap.out("client", "multichannel"))
        f.all_channel_ids = {ch["id"] for s in mc for ch in s["channels"]}
        f.multichannel = next((s for s in mc if s["mount"] == mp), {})

        f.client_ifaces = pm.ifconfig(snap.out("client", "ifconfig"))
        f.client_ports = pm.hwports(snap.out("client", "hwports"))
        f.client_iface = pm.route_interface(snap.out("client", "route"))
        f.client_iface_info = f.client_ifaces.get(f.client_iface, {})
        f.client_iface_port = f.client_ports.get(f.client_iface, "")
        gw = pm.route_gateway(snap.out("client", "route"))
        f.client_gateway = "" if not gw or gw.startswith("link#") else gw
        f.ping = pm.ping(snap.out("client", "ping"))
        f.ping_jumbo = pm.ping(snap.out("client", "ping_jumbo"))
        f.ping_1500 = pm.ping(snap.out("client", "ping_1500"))
        f.ds_store_disabled = snap.out("client", "ds_store").strip() in {"1", "true", "YES"}
        f.client_epoch, f.client_tz = _tz(snap.out("client", "date"))
        f.client_events = logs.classify_client(pm.unified_log(snap.out("client", "smb_log")))
        all_eps = logs.episodes(f.client_events)
        f.episodes = [e for e in all_eps if not e.idle]
        f.idle_closes = [e for e in all_eps if e.idle]
        f.loops = logs.reconnect_loops(f.client_events)

    # ---------------- host ----------------
    if f.have_host:
        m = re.search(r'^version="?([^"\s]+)', snap.out("host", "os"), re.M)
        f.unraid_version = m.group(1) if m else ""
        f.samba_version = _samba_version(snap.out("host", "samba_version"))
        f.smbconf = ps.testparm(snap.out("host", "testparm"))
        f.share_name, f.share_conf = _find_share(f.smbconf, snap.meta.get("share", ""))
        f.smb_extra = pm.ini(snap.out("host", "smb_extra"))
        f.ident = ps.unraid_cfg(snap.out("host", "ident"))
        f.share_cfg = ps.share_cfgs(snap.out("host", "share_cfgs")).get(f.share_name, {})
        f.disk_cfg = ps.unraid_cfg(snap.out("host", "disk_cfg"))
        f.disks = ps.disks_ini(snap.out("host", "disks_ini"))
        f.user_shares = ps.user_shares(snap.out("host", "user_shares"))
        f.host_ifaces = ps.net(snap.out("host", "net"))
        f.link_stats = ps.ip_link_stats(snap.out("host", "ip_link"))
        for name, st in f.link_stats.items():
            info = f.host_ifaces.get(name)
            if info is not None:
                info["kind"] = st.get("kind")
                info["tx_queues"] = st.get("tx_queues")
                if not info.get("lower") and st.get("parent") and not info.get("master"):
                    info["lower"] = st["parent"]
        f.host_route = ps.route_to_client(snap.out("host", "route_to_client"))
        f.host_phys = ps.physical_members(f.host_ifaces, f.host_route.get("dev") or "")
        f.host_routes = ps.routes(snap.out("host", "routes"))
        f.host_addrs = ps.addrs(snap.out("host", "addrs"))
        f.ethtool = ps.ethtool(snap.out("host", "ethtool"))
        f.load = ps.load(snap.out("host", "load"))
        f.vmstat = ps.vmstat(snap.out("host", "vmstat"))
        f.df = ps.df(snap.out("host", "df"))
        f.smbstatus = ps.smbstatus_json(snap.out("host", "smbstatus_json"))
        client_ip = f.host_route.get("client_ip", "")
        f.client_sessions = [s for s in ps.sessions(f.smbstatus)
                             if client_ip and client_ip in str(s.get("remote_machine", "")) + str(s.get("hostname", ""))]
        f.iperf3_on_host = snap.ok("host", "iperf3")
        f.host_epoch, f.host_tz = _tz(snap.out("host", "date"))

        f.array = ps.unraid_cfg(snap.out("host", "array"))
        if f.client_epoch is not None and f.host_epoch is not None:
            f.clock_skew = float(f.host_epoch - f.client_epoch)
        up = snap.out("host", "uptime").split()
        if up and f.host_epoch is not None and f.client_tz is not None:
            try:
                boot_utc = datetime.fromtimestamp(f.host_epoch - float(up[0]) - (f.clock_skew or 0.0), timezone.utc)
                boot_utc = boot_utc.replace(tzinfo=None)
                f.host_boot = boot_utc + f.client_tz
            except (ValueError, OverflowError):
                pass
        year = datetime.fromtimestamp(snap.created_at).year
        host_events = logs.classify_samba(ps.samba_log(snap.out("host", "samba_log")))
        host_events += logs.classify_syslog(ps.syslog(snap.out("host", "syslog"), year))
        # Unraid sends smbd messages to both log.smbd and syslog; keep one copy of each.
        seen, unique = set(), []
        for e in host_events:
            key = (e.when.replace(microsecond=0) if e.when else None, e.kind, e.message.split(":", 1)[-1][:80])
            if e.kind and key in seen:
                continue
            seen.add(key)
            unique.append(e)
        host_events = unique
        # host wall clock -> client wall clock: undo the time-zone difference and the clock skew
        tz_diff = (f.host_tz - f.client_tz) if f.host_tz is not None and f.client_tz is not None else timedelta()
        f.host_events = align(host_events, tz_diff + timedelta(seconds=f.clock_skew or 0.0))

    if f.client_events and f.host_events:
        f.correlations = logs.correlate(f.client_events, f.host_events)
    return f
