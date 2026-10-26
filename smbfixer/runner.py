"""Run commands locally or on the host over SSH."""

from __future__ import annotations

import os
import shlex
import subprocess
import time
from dataclasses import asdict, dataclass

from smbfixer.config import HostConfig


@dataclass
class Result:
    name: str
    command: str
    returncode: int
    stdout: str
    stderr: str
    duration: float

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Result":
        return cls(**data)


def run_local(name: str, argv: list[str], timeout: float = 60.0, input: str | None = None) -> Result:
    start = time.monotonic()
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, errors="replace", input=input)
        rc, out, err = proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError as exc:
        rc, out, err = 127, "", str(exc)
    except subprocess.TimeoutExpired as exc:
        rc = 124
        out = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        err = f"timed out after {timeout}s"
    return Result(name, shlex.join(argv), rc, out, err, time.monotonic() - start)


class SSH:
    def __init__(self, host: HostConfig):
        if not host.address:
            raise ValueError("host.address is not configured")
        self.host = host

    def base_argv(self) -> list[str]:
        argv = [
            "ssh",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=10",
            "-o", "ServerAliveInterval=15",
            # Multiplex the many short collector commands over one connection.
            "-o", "ControlMaster=auto",
            "-o", "ControlPath=~/.ssh/smbfixer-%C",
            "-o", "ControlPersist=120",
            "-p", str(self.host.ssh_port),
        ]
        if self.host.ssh_key:
            argv += ["-i", os.path.expanduser(self.host.ssh_key)]
        argv += list(self.host.ssh_options)
        argv.append(f"{self.host.ssh_user}@{self.host.address}")
        return argv

    def run(self, name: str, script: str, timeout: float = 60.0, input: str | None = None) -> Result:
        # The remote login shell on Unraid is bash; wrap so pipelines behave predictably.
        argv = self.base_argv() + ["bash", "-c", shlex.quote(script)]
        result = run_local(name, argv, timeout=timeout, input=input)
        result.command = script
        return result

    def popen(self, script: str) -> subprocess.Popen:
        argv = self.base_argv() + ["bash", "-c", shlex.quote(script)]
        return subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
