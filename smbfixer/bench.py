"""Throughput and metadata benchmarks against the mounted share.

Writes only to a temporary file/folder under the mount (and, with --host-disk, under the share's
path on the host) and always removes them afterwards.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

from smbfixer.runner import SSH

F_NOCACHE = 48  # macOS: bypass the unified buffer cache for this descriptor
CHUNK = 4 * 1024 * 1024


def _nocache(fd: int) -> None:
    if sys.platform == "darwin":
        try:
            fcntl.fcntl(fd, F_NOCACHE, 1)
        except OSError:
            pass


def sequential(mount: str, size_mb: int) -> dict:
    path = Path(mount) / f".smbfixer-bench-{os.getpid()}.tmp"
    block = os.urandom(CHUNK)
    total = size_mb * 1024 * 1024
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        _nocache(fd)
        start = time.monotonic()
        written = 0
        while written < total:
            written += os.write(fd, block[: min(CHUNK, total - written)])
        os.fsync(fd)
        os.close(fd)
        write_s = time.monotonic() - start

        fd = os.open(path, os.O_RDONLY)
        _nocache(fd)
        start = time.monotonic()
        while os.read(fd, CHUNK):
            pass
        os.close(fd)
        read_s = time.monotonic() - start
    finally:
        path.unlink(missing_ok=True)
    mb = total / 1e6
    return {"size_mb": size_mb, "write_mbps": round(mb / write_s, 1), "read_mbps": round(mb / read_s, 1)}


def small_files(mount: str, count: int) -> dict:
    root = Path(mount) / f".smbfixer-small-{os.getpid()}"
    payload = os.urandom(4096)
    try:
        root.mkdir()
        start = time.monotonic()
        for i in range(count):
            (root / f"f{i:05d}").write_bytes(payload)
        create_s = time.monotonic() - start
        start = time.monotonic()
        for i in range(count):
            os.stat(root / f"f{i:05d}")
        stat_s = time.monotonic() - start
        start = time.monotonic()
        os.listdir(root)
        list_ms = (time.monotonic() - start) * 1000
        start = time.monotonic()
        for i in range(count):
            (root / f"f{i:05d}").unlink()
        delete_s = time.monotonic() - start
    finally:
        shutil.rmtree(root, ignore_errors=True)
    total = create_s + stat_s + delete_s
    return {
        "small_files": count,
        "small_create_ms": round(create_s / count * 1000, 2),
        "small_stat_ms": round(stat_s / count * 1000, 2),
        "small_delete_ms": round(delete_s / count * 1000, 2),
        "small_list_ms": round(list_ms, 1),
        "small_file_ops_per_s": round(3 * count / total, 1),
    }


def iperf(ssh: SSH, address: str, seconds: int = 5) -> dict:
    if shutil.which("iperf3") is None:
        return {"iperf_error": "iperf3 not installed on the client (brew install iperf3)"}
    if not ssh.run("iperf3", "command -v iperf3").ok:
        return {"iperf_error": "iperf3 not installed on the host (Unraid: install via a plugin/NerdTools)"}
    out = {}
    for label, extra in (("tx", []), ("rx", ["-R"])):
        ssh.run("iperf3-server", "iperf3 -s -1 -D -p 5201")
        time.sleep(1)
        proc = subprocess.run(["iperf3", "-c", address, "-p", "5201", "-t", str(seconds), "-J", *extra],
                              capture_output=True, text=True, timeout=seconds + 30)
        try:
            data = json.loads(proc.stdout)
            bps = data["end"]["sum_received"]["bits_per_second"]
            out[f"iperf_{label}_mbps"] = round(bps / 1e6, 1)
        except (json.JSONDecodeError, KeyError):
            out[f"iperf_{label}_error"] = (proc.stderr or proc.stdout)[-200:]
    speeds = [v for k, v in out.items() if k.endswith("_mbps")]
    if speeds:
        out["iperf_mbps"] = max(speeds)
    return out


def host_disk(ssh: SSH, share_path: str, size_mb: int) -> dict:
    """Write+read a file directly on the host to separate storage speed from SMB/network speed."""
    target = f"{share_path.rstrip('/')}/.smbfixer-dd-$$"
    script = (
        f"t={target}; "
        f"dd if=/dev/zero of=$t bs=1M count={size_mb} oflag=direct conv=fsync 2>&1 | tail -1; "
        f"dd if=$t of=/dev/null bs=1M iflag=direct 2>&1 | tail -1; rm -f $t"
    )
    r = ssh.run("host-dd", script, timeout=600)
    rates = re.findall(r"([\d.,]+) ([MG])B/s", r.stdout)
    out: dict = {}
    for label, (value, unit) in zip(("host_write_mbps", "host_read_mbps"), rates):
        v = float(value.replace(",", "."))
        out[label] = round(v * (1000 if unit == "G" else 1), 1)
    if not out:
        out["host_disk_error"] = (r.stderr or r.stdout)[-200:]
    return out
