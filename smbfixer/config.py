"""Configuration loading (TOML file + CLI overrides)."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_PATHS = (
    Path("smbfixer.toml"),
    Path.home() / ".config" / "smbfixer" / "config.toml",
)


@dataclass
class HostConfig:
    address: str = ""
    ssh_user: str = "root"
    ssh_port: int = 22
    ssh_key: str = ""
    # Extra ssh options, e.g. ["-o", "ProxyJump=bastion"]
    ssh_options: list[str] = field(default_factory=list)
    platform: str = "auto"  # auto | unraid | samba


@dataclass
class ClientConfig:
    # Local mount point of the share under test, e.g. /Volumes/media
    mount_point: str = ""
    # Share name on the host; derived from the mount if empty
    share: str = ""


@dataclass
class CollectConfig:
    log_minutes: int = 60
    host_log_lines: int = 3000
    ping_count: int = 10


@dataclass
class MonitorConfig:
    probe_interval: float = 2.0
    stall_threshold_ms: float = 1500.0
    probe_timeout: float = 20.0


@dataclass
class BenchConfig:
    size_mb: int = 512
    small_files: int = 200


@dataclass
class Config:
    host: HostConfig = field(default_factory=HostConfig)
    client: ClientConfig = field(default_factory=ClientConfig)
    collect: CollectConfig = field(default_factory=CollectConfig)
    monitor: MonitorConfig = field(default_factory=MonitorConfig)
    bench: BenchConfig = field(default_factory=BenchConfig)
    source: Path | None = None


def _apply(section: object, values: dict) -> None:
    for key, value in values.items():
        if not hasattr(section, key):
            raise ValueError(f"unknown config key: {key}")
        setattr(section, key, value)


def load(path: str | os.PathLike | None = None) -> Config:
    cfg = Config()
    candidates = [Path(path)] if path else [p for p in DEFAULT_PATHS if p.exists()]
    for candidate in candidates[:1]:
        with open(candidate, "rb") as fh:
            data = tomllib.load(fh)
        for name in ("host", "client", "collect", "monitor", "bench"):
            if name in data:
                _apply(getattr(cfg, name), data[name])
        cfg.source = candidate
    return cfg


EXAMPLE = """\
# smbfixer configuration. Copy to ./smbfixer.toml or ~/.config/smbfixer/config.toml

[host]
address = "tower.local"      # Unraid hostname or IP
ssh_user = "root"
ssh_port = 22
# ssh_key = "~/.ssh/id_ed25519"
platform = "auto"            # auto | unraid | samba

[client]
mount_point = "/Volumes/media"   # share mounted in Finder
# share = "media"                # defaults to the mounted share name

[collect]
log_minutes = 60
host_log_lines = 3000
ping_count = 10

[monitor]
probe_interval = 2.0
stall_threshold_ms = 1500
probe_timeout = 20

[bench]
size_mb = 512
small_files = 200
"""
