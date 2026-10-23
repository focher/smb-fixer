"""macOS client collectors. All commands are read-only."""

from __future__ import annotations

import functools
from pathlib import Path

from smbfixer.config import Config
from smbfixer.parse import macos as parse
from smbfixer.runner import run_local

# Unified-log predicate covering the smbfs kernel extension and the user-space SMB helpers.
LOG_PREDICATE = (
    '(process == "kernel" AND (senderImagePath CONTAINS[c] "smbfs" OR eventMessage CONTAINS[c] "smb"))'
    ' OR process == "NetAuthSysAgent" OR process == "smbd" OR subsystem == "com.apple.smb"'
)


def sh(name: str, script: str, timeout: float = 60.0):
    return functools.partial(run_local, name, ["/bin/sh", "-c", script], timeout)


def cmd(name: str, argv: list[str], timeout: float = 60.0):
    return functools.partial(run_local, name, argv, timeout)


def jobs(cfg: Config, meta: dict) -> list:
    target = meta.get("host_ip") or cfg.host.address
    out = [
        cmd("sw_vers", ["sw_vers"]),
        cmd("statshares", ["smbutil", "statshares", "-a"]),
        cmd("multichannel", ["smbutil", "multichannel", "-a"]),
        cmd("mount", ["mount", "-t", "smbfs"]),
        sh("nsmb_system", "cat /etc/nsmb.conf"),
        sh("nsmb_user", 'cat "$HOME/Library/Preferences/nsmb.conf"'),
        cmd("ifconfig", ["ifconfig", "-a"]),
        cmd("hwports", ["networksetup", "-listallhardwareports"]),
        cmd("ds_store", ["defaults", "read", "com.apple.desktopservices", "DSDontWriteNetworkStores"]),
        cmd("date", ["date", "+%s %z"]),
        sh("tcp_445", "netstat -an -p tcp | grep -E '\\.445 '"),
        cmd("sysctl_net", ["sysctl", "net.inet.tcp.delayed_ack", "net.inet.tcp.sendspace",
                           "net.inet.tcp.recvspace", "kern.ipc.maxsockbuf"]),
        cmd("smb_log", ["log", "show", "--last", f"{cfg.collect.log_minutes}m", "--style", "compact",
                        "--predicate", LOG_PREDICATE], timeout=180),
    ]
    if target:
        out += [
            cmd("route", ["route", "-n", "get", target]),
            cmd("ping", ["ping", "-c", str(cfg.collect.ping_count), "-q", target],
                timeout=cfg.collect.ping_count * 2 + 10),
            # 8972 = 9000 MTU - 20 (IP) - 8 (ICMP); -D sets Don't Fragment.
            cmd("ping_jumbo", ["ping", "-c", "3", "-D", "-s", "8972", "-t", "5", target], timeout=15),
            cmd("ping_1500", ["ping", "-c", "3", "-D", "-s", "1472", "-t", "5", target], timeout=15),
        ]
    return out


def guess_mount(snap) -> str:
    mounts = parse.smbfs_mounts(snap.out("client", "mount"))
    host = snap.meta.get("host_address", "").lower()
    ip = snap.meta.get("host_ip", "")
    for m in mounts:
        if m.server.lower() in {host, ip} or m.server.lower().split(".")[0] == host.split(".")[0]:
            return m.mount_point
    return mounts[0].mount_point if mounts else ""


def share_for_mount(snap, mount_point: str) -> str:
    for m in parse.smbfs_mounts(snap.out("client", "mount")):
        if m.mount_point == mount_point:
            return m.share
    return Path(mount_point).name
