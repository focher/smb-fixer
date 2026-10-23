"""Collectors: gather raw, read-only diagnostics from the client and the host."""

from __future__ import annotations

import socket
import sys
from concurrent.futures import ThreadPoolExecutor

from smbfixer.collect import host as host_collect
from smbfixer.collect import macos
from smbfixer.config import Config
from smbfixer.runner import SSH
from smbfixer.snapshot import Snapshot


def resolve(address: str) -> str:
    try:
        return socket.gethostbyname(address)
    except OSError:
        return ""


def collect(cfg: Config, *, client: bool = True, host: bool = True, progress=None) -> Snapshot:
    snap = Snapshot()
    snap.meta.update(
        host_address=cfg.host.address,
        host_ip=resolve(cfg.host.address) if cfg.host.address else "",
        mount_point=cfg.client.mount_point,
        share=cfg.client.share,
        platform=sys.platform,
    )
    jobs = []
    if client:
        jobs += [("client", job) for job in macos.jobs(cfg, snap.meta)]
    if host:
        ssh = SSH(cfg.host)
        jobs += [("host", job) for job in host_collect.jobs(cfg, ssh)]

    # Independent read-only commands; run concurrently so a full collect takes seconds, not minutes.
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [(side, pool.submit(job)) for side, job in jobs]
        for side, fut in futures:
            result = fut.result()
            snap.add(side, result)
            if progress:
                progress(side, result)

    if client and not snap.meta["mount_point"]:
        snap.meta["mount_point"] = macos.guess_mount(snap)
    if not snap.meta["share"] and snap.meta["mount_point"]:
        snap.meta["share"] = macos.share_for_mount(snap, snap.meta["mount_point"])
    return snap
