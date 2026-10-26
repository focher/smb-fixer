"""Classify log lines from both ends and correlate client-side trouble with host-side causes."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta

from smbfixer.parse.macos import LogEvent

# Order matters: the first match wins. Messages below come from the macOS smbfs kext.
CLIENT_PATTERNS = [
    # Routine chatter that would otherwise match the generic error pattern.
    ("noise", re.compile(r"Time Machine entitlement check failed|No compression algorithm enabled|"
                         r"addSelection:|Unexpectedly opened a dir for|process_svrmsg_items", re.I)),
    ("timemachine", re.compile(r"TM Read - attributes|Attempt setting durable handle timeout", re.I)),
    ("durable", re.compile(r"Durable Handle V2 or Persistent Handles not supported|failed to set Durable Handle", re.I)),
    ("dead", re.compile(r"is dead, give up", re.I)),
    ("io_failed", re.compile(r"(?:READ|WRITE) failed with an error|read_write_async failed", re.I)),
    ("disconnect", re.compile(r"Server closed their side of the connection|connection (?:reset|lost)|broken pipe|"
                              r"ECONNRESET", re.I)),
    ("timeout", re.compile(r"ts > iod_lastrecv|timed? ?out|not responding", re.I)),
    # One line every couple of seconds while a session keeps retrying; used for loop detection.
    ("reconnect_retry", re.compile(r"smb_iod_start_reconnect", re.I)),
    ("reconnect", re.compile(r"Starting reconnect|negotiate succeeded|Reconnect succeeded|reconnect", re.I)),
    ("access", re.compile(r"ntcreatex failed 13|failed Query Info 13", re.I)),
    ("error", re.compile(r"\berror\b|\bfail", re.I)),
]

SESSION_ID = re.compile(r"\b(?:id|iod) (\d+)\b")

SAMBA_PATTERNS = [
    ("disconnect", re.compile(r"NT_STATUS_CONNECTION_(?:RESET|DISCONNECTED)|Connection reset by peer|"
                              r"read_fd_with_timeout|client \S+ (?:disconnected|went away)", re.I)),
    ("timeout", re.compile(r"NT_STATUS_IO_TIMEOUT|timed out|Timeout waiting", re.I)),
    ("oplock", re.compile(r"oplock|lease[ _]break", re.I)),
    ("resource", re.compile(r"Too many open files|NT_STATUS_NO_MEMORY|out of memory|EMFILE|ENFILE", re.I)),
    ("auth", re.compile(r"NT_STATUS_LOGON_FAILURE|NT_STATUS_ACCESS_DENIED|authentication for user", re.I)),
    ("crash", re.compile(r"PANIC|INTERNAL ERROR|smb_panic", re.I)),
]

SYSLOG_PATTERNS = [
    ("spinup", re.compile(r"read SMART /dev/|spinning up|spin(?:ning)?[ -]up", re.I)),
    ("spindown", re.compile(r"spinning down|spin(?:ning)?[ -]down", re.I)),
    # "Link is Up" alone is normal at boot; only downs and resets indicate trouble.
    ("nic", re.compile(r"Link is Down|link down|tx timeout|Reset adapter|NETDEV WATCHDOG|"
                       r"transmit queue \d+ timed out|link becomes not ready", re.I)),
    ("io_error", re.compile(r"I/O error|blk_update_request|critical medium error|"
                            r"ata\d+(?:\.\d+)?: (?:exception|failed command|hard resetting|COMRESET)", re.I)),
    ("oom", re.compile(r"Out of memory|oom-kill|invoked oom-killer", re.I)),
    ("crash", re.compile(r"(?:smbd|shfs).*(?:segfault|general protection|panic)|kernel BUG", re.I)),
    ("shfs", re.compile(r"shfs.*(?:error|fail)", re.I)),
]

# Client-side kinds that indicate the user saw a hang or a dropped connection.
TROUBLE = {"reconnect", "timeout", "disconnect", "dead", "io_failed"}
# Host-side kinds that commonly cause client hangs.
CAUSES = {"spinup", "nic", "io_error", "oom", "crash", "disconnect", "timeout", "resource", "oplock", "shfs"}


def classify(event: LogEvent, patterns) -> LogEvent:
    text = f"{event.source} {event.message}"
    for kind, rx in patterns:
        if rx.search(text):
            event.kind = kind
            break
    return event


def classify_client(events):
    return [classify(e, CLIENT_PATTERNS) for e in events]


def classify_samba(events):
    return [classify(e, SAMBA_PATTERNS) for e in events]


def classify_syslog(events):
    out = []
    for e in events:
        classify(e, SYSLOG_PATTERNS)
        if e.kind == "" and e.source.startswith("smbd"):
            classify(e, SAMBA_PATTERNS)
        out.append(e)
    return out


def session_id(event: LogEvent) -> str:
    m = SESSION_ID.search(event.message)
    return m.group(1) if m else ""


@dataclass
class Episode:
    """A burst of client-side trouble: what the user experiences as one hang."""
    start: datetime
    end: datetime
    events: list[LogEvent]

    @property
    def seconds(self) -> float:
        return (self.end - self.start).total_seconds()

    @property
    def kinds(self) -> dict[str, int]:
        return counts(self.events)

    @property
    def idle(self) -> bool:
        """A lone server-side close with no stall or failed I/O: the server dropping an idle session."""
        return self.kinds == {"disconnect": 1}

    @property
    def sessions(self) -> list[str]:
        return sorted({s for s in (session_id(e) for e in self.events) if s})

    def describe(self) -> str:
        k = self.kinds
        parts = [f"{k[n]} {label}" for n, label in (
            ("timeout", "stalls"), ("disconnect", "server disconnects"), ("reconnect", "reconnects"),
            ("io_failed", "failed reads/writes"), ("dead", "session gave up")) if n in k]
        span = f"{self.start:%H:%M:%S}" + (f"–{self.end:%H:%M:%S} ({self.seconds:.0f}s)" if self.seconds >= 1 else "")
        return f"{span}: {', '.join(parts)}"


def episodes(events, gap: timedelta = timedelta(seconds=120)) -> list[Episode]:
    trouble = sorted((e for e in events if e.kind in TROUBLE and e.when), key=lambda e: e.when)
    out: list[Episode] = []
    for e in trouble:
        if out and e.when - out[-1].end <= gap:
            out[-1].events.append(e)
            out[-1].end = e.when
        else:
            out.append(Episode(e.when, e.when, [e]))
    return out


@dataclass
class Loop:
    session: str
    first: datetime
    last: datetime
    attempts: int


def reconnect_loops(events, min_span: timedelta = timedelta(minutes=5)) -> list[Loop]:
    """Sessions that keep logging smb_iod_start_reconnect: the kernel retrying a share that never comes back."""
    by_id: dict[str, list[datetime]] = {}
    for e in events:
        if e.kind == "reconnect_retry" and e.when:
            by_id.setdefault(session_id(e) or "?", []).append(e.when)
    loops = []
    for sid, times in by_id.items():
        if times[-1] - times[0] >= min_span:
            loops.append(Loop(sid, times[0], times[-1], len(times)))
    return loops


@dataclass
class Correlation:
    client_event: LogEvent
    host_events: list[LogEvent]
    episode: Episode | None = None


def correlate(client_events, host_events, window: timedelta = timedelta(seconds=90)):
    """Pair each client trouble episode with host events around it.

    Both lists must already be on one clock (see facts.align). The window looks mostly backwards
    because the host-side cause (e.g. a disk spinning up) starts before the client gives up.
    """
    causes = [e for e in host_events if e.kind in CAUSES and e.when]
    out = []
    for ep in episodes(client_events):
        if ep.idle:
            continue
        near = [he for he in causes if ep.start - window <= he.when <= ep.end + timedelta(seconds=15)]
        if near:
            out.append(Correlation(ep.events[0], near, ep))
    return out


def counts(events) -> dict[str, int]:
    out: dict[str, int] = {}
    for e in events:
        if e.kind and e.kind != "noise":
            out[e.kind] = out.get(e.kind, 0) + 1
    return out


def samples(events, kind: str, n: int = 3) -> list[str]:
    picked = [e for e in events if e.kind == kind][-n:]
    return [f"{e.when:%Y-%m-%d %H:%M:%S} {e.source}: {e.message[:200]}" if e.when else e.message[:200]
            for e in picked]
