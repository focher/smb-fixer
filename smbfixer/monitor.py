"""Live monitoring: probe the mount for stalls while tailing logs on both ends.

Everything is timestamped on arrival at the client, so the two sides line up without needing
synchronised clocks.
"""

from __future__ import annotations

import queue
import re
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from smbfixer.analysis import logs
from smbfixer.collect.macos import LOG_PREDICATE
from smbfixer.config import Config
from smbfixer.parse.macos import LogEvent
from smbfixer.runner import SSH

HOST_TAIL = "tail -n0 -F /var/log/samba/log.smbd /var/log/syslog 2>/dev/null"
HOST_POLL = "cat /proc/loadavg; vmstat 1 2 | tail -1; smbstatus -L 2>/dev/null | grep -c '^[0-9]'"
SYSLOG_LINE = re.compile(r"^[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\S+\s+([^:\[]+)(?:\[\d+\])?:\s*(.*)$")
SAMBA_HDR = re.compile(r"^\[\d{4}/\d{2}/\d{2} [\d:.]+,\s*\d+")
QUIET = {"noise", "timemachine", "access"}  # recorded by `check`, too chatty to stream


@dataclass
class Stall:
    at: datetime
    op: str
    ms: float
    timed_out: bool = False

    def to_dict(self) -> dict:
        return {"at": self.at.strftime("%Y-%m-%d %H:%M:%S"), "op": self.op, "ms": self.ms, "timed_out": self.timed_out}


@dataclass
class Session:
    stalls: list[Stall] = field(default_factory=list)
    client_events: list[LogEvent] = field(default_factory=list)
    host_events: list[LogEvent] = field(default_factory=list)
    probes: int = 0
    probe_ms: list[float] = field(default_factory=list)


class Monitor:
    def __init__(self, cfg: Config, mount_point: str, *, use_host: bool = True, samba_debug: int | None = None,
                 out=sys.stdout, color: bool | None = None):
        self.cfg = cfg
        self.mount = mount_point
        self.ssh = SSH(cfg.host) if use_host and cfg.host.address else None
        self.samba_debug = samba_debug
        self.out = out
        self.color = out.isatty() if color is None else color
        self.events: queue.Queue = queue.Queue()
        self.stop = threading.Event()
        self.session = Session()
        self.procs: list[subprocess.Popen] = []
        self._restore_level: str | None = None
        self._retry_seen: dict[str, datetime] = {}

    # ------------------------------------------------------------------ output
    def emit(self, side: str, kind: str, text: str, code: str = "0") -> None:
        stamp = datetime.now().strftime("%H:%M:%S")
        line = f"{stamp} {side:<6} {kind:<10} {text}"
        if self.color:
            line = f"\033[{code}m{line}\033[0m"
        print(line, file=self.out, flush=True)

    # ------------------------------------------------------------------ probes
    def _probe_once(self, op: str, argv: list[str]) -> None:
        timeout = self.cfg.monitor.probe_timeout
        start = time.monotonic()
        proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            proc.wait(timeout=timeout)
            timed_out = False
        except subprocess.TimeoutExpired:
            # A process stuck in the kernel on a hung SMB mount may not die; don't block on it.
            proc.kill()
            timed_out = True
        ms = (time.monotonic() - start) * 1000
        self.session.probes += 1
        self.session.probe_ms.append(ms)
        if timed_out or ms >= self.cfg.monitor.stall_threshold_ms:
            stall = Stall(datetime.now(), op, ms, timed_out)
            self.session.stalls.append(stall)
            label = "TIMEOUT" if timed_out else "STALL"
            self.emit("probe", label, f"{op} took {ms / 1000:.1f}s", "31;1")

    def probe_loop(self) -> None:
        # stat the root, then list it: the second exercises directory enumeration like Finder does.
        while not self.stop.is_set():
            self._probe_once("stat", ["/usr/bin/stat", "-f", "%m", self.mount])
            self._probe_once("readdir", ["/bin/ls", "-f", self.mount])
            self.stop.wait(self.cfg.monitor.probe_interval)

    # ------------------------------------------------------------------ log tails
    def _reader(self, proc: subprocess.Popen, handler) -> None:
        for line in proc.stdout:  # type: ignore[union-attr]
            if self.stop.is_set():
                break
            handler(line.rstrip("\n"))

    def client_line(self, line: str) -> None:
        m = re.match(r"^\S+ \S+\s+\S+\s+(\S+?)\[[^\]]*\]\s*(.*)$", line)
        if not m:
            return
        ev = logs.classify(LogEvent(datetime.now(), "client", m.group(1), m.group(2)), logs.CLIENT_PATTERNS)
        if not ev.kind or ev.kind in QUIET:
            return
        self.session.client_events.append(ev)
        if ev.kind == "reconnect_retry":
            # A stuck session logs this every ~2s; mention it once a minute per session.
            sid = logs.session_id(ev)
            last = self._retry_seen.get(sid)
            self._retry_seen[sid] = last or ev.when
            if last and (ev.when - last).total_seconds() < 60:
                return
            self._retry_seen[sid] = ev.when
            self.emit("client", "retrying", f"session {sid or '?'} is still trying to reconnect", "2")
            return
        self.emit("client", ev.kind, f"{ev.source}: {ev.message[:160]}", "33" if ev.kind in logs.TROUBLE else "0")

    def host_line(self, line: str) -> None:
        if not line.strip() or line.startswith("==>") or SAMBA_HDR.match(line):
            return
        m = SYSLOG_LINE.match(line)
        source, msg = (m.group(1).strip(), m.group(2)) if m else ("smbd", line.strip())
        ev = LogEvent(datetime.now(), "host", source, msg)
        logs.classify(ev, logs.SYSLOG_PATTERNS)
        if not ev.kind:
            logs.classify(ev, logs.SAMBA_PATTERNS)
        if ev.kind:
            self.session.host_events.append(ev)
            self.emit("host", ev.kind, f"{source}: {msg[:160]}", "35" if ev.kind in logs.CAUSES else "0")

    def host_poll_loop(self) -> None:
        while not self.stop.wait(10):
            r = self.ssh.run("poll", HOST_POLL, timeout=20)
            if not r.ok and r.returncode == 255:
                self.emit("host", "ssh", "lost SSH connection to host", "31")
                continue
            lines = r.stdout.splitlines()
            if len(lines) >= 3:
                load = lines[0].split()[0]
                vm = lines[1].split()
                wa = vm[15] if len(vm) > 15 else "?"
                self.emit("host", "stats", f"load {load}  iowait {wa}%  locked files {lines[2].strip()}", "2")

    # ------------------------------------------------------------------ lifecycle
    def _start(self, argv, handler) -> None:
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
        self.procs.append(proc)
        threading.Thread(target=self._reader, args=(proc, handler), daemon=True).start()

    def run(self, duration: float | None = None) -> Session:
        self.emit("info", "start", f"probing {self.mount} every {self.cfg.monitor.probe_interval}s; Ctrl-C to stop")
        self._start(["log", "stream", "--style", "compact", "--predicate", LOG_PREDICATE], self.client_line)
        if self.ssh:
            if self.samba_debug is not None:
                cur = self.ssh.run("lvl", "testparm -sv 2>/dev/null | awk -F' = ' '/^\\s*log level/{print $2; exit}'")
                self._restore_level = (cur.stdout.strip() or "0").split()[0]
                self.ssh.run("dbg", f"smbcontrol smbd debug {int(self.samba_debug)}")
                self.emit("host", "config", f"samba debug level {self.samba_debug} (will restore {self._restore_level})")
            proc = self.ssh.popen(HOST_TAIL)
            self.procs.append(proc)
            threading.Thread(target=self._reader, args=(proc, self.host_line), daemon=True).start()
            threading.Thread(target=self.host_poll_loop, daemon=True).start()
        threading.Thread(target=self.probe_loop, daemon=True).start()
        try:
            if duration:
                self.stop.wait(duration)
            else:
                while not self.stop.wait(1):
                    pass
        except KeyboardInterrupt:
            pass
        finally:
            self.shutdown()
        return self.session

    def shutdown(self) -> None:
        self.stop.set()
        for p in self.procs:
            p.terminate()
        if self.ssh and self._restore_level is not None:
            self.ssh.run("dbg", f"smbcontrol smbd debug {self._restore_level}")
            self.emit("host", "config", f"samba debug level restored to {self._restore_level}")


def summarize(session: Session, window: float = 90.0) -> list[str]:
    lines = []
    ms = sorted(session.probe_ms)
    if ms:
        p50 = ms[len(ms) // 2]
        p99 = ms[min(len(ms) - 1, int(len(ms) * 0.99))]
        lines.append(f"{session.probes} probes: median {p50:.0f} ms, p99 {p99:.0f} ms, max {ms[-1]:.0f} ms")
    lines.append(f"{len(session.stalls)} stall(s), {len(session.client_events)} client log events, "
                 f"{len(session.host_events)} host log events")
    for s in session.stalls:
        near = [e for e in session.host_events + session.client_events
                if s.at - timedelta(seconds=window) <= e.when <= s.at + timedelta(seconds=5)]
        lines.append(f"  stall {s.at:%H:%M:%S} {s.op} {s.ms / 1000:.1f}s"
                     + (" (timed out)" if s.timed_out else ""))
        for e in near[-5:]:
            lines.append(f"    {e.when:%H:%M:%S} {e.side} {e.kind}: {e.source}: {e.message[:120]}")
        if not near:
            lines.append("    no log events nearby: suspect network loss or a host-side wait that is not logged "
                         "(try --samba-debug 2)")
    return lines
