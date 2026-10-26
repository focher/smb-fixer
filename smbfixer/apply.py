"""Make the recommended changes that smbfixer can safely make itself.

- Mac: rewrite /etc/nsmb.conf (via sudo, after a backup) and run plain `defaults write` style commands.
- Unraid server: rewrite /boot/config/smb-extra.conf over SSH (after a backup), validate the whole
  Samba config with testparm, roll back if it fails, then reload smbd.

Unraid web UI steps and physical network fixes are never automated: Unraid applies UI settings
through its own services, and cables and switches are not ours to touch.
"""

from __future__ import annotations

import difflib
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Callable

from smbfixer import report
from smbfixer.analysis.facts import Facts
from smbfixer.analysis.model import CLIENT_SHELL, HOST_SHELL, Recommendation
from smbfixer.runner import SSH

NSMB = "/etc/nsmb.conf"
EXTRA = "/boot/config/smb-extra.conf"


class ApplyError(RuntimeError):
    pass


@dataclass
class Change:
    machine: str
    title: str
    preview: str
    run: Callable[[], str]
    recs: list[Recommendation] = field(default_factory=list)


def diff(old: str, new: str, path: str) -> str:
    lines = difflib.unified_diff(old.splitlines(), new.splitlines(), f"{path} (now)", f"{path} (new)", lineterm="")
    return "\n".join(lines)


def choose(recs: list[Recommendation], *, include_tradeoffs: bool, interactive: bool,
           ask: Callable[[str], bool]) -> list[Recommendation]:
    """Automatic recommendations to act on. Tradeoffs need an explicit yes (or --include-tradeoffs)."""
    chosen = []
    for r in recs:
        if not r.automatic:
            continue
        if not r.tradeoff or include_tradeoffs:
            chosen.append(r)
        elif interactive and ask(f"[{r.machine}] {r.action}\n    tradeoff: {r.tradeoff}\n    Include this change? [y/N] "):
            chosen.append(r)
    return chosen


def write_nsmb(new: str) -> str:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    backup = f"{NSMB}.smbfixer-{stamp}"
    script = (f"set -e; if [ -e {NSMB} ]; then cp {NSMB} {backup}; fi; "
              f"cat > {NSMB}.smbfixer-new; chmod 644 {NSMB}.smbfixer-new; mv {NSMB}.smbfixer-new {NSMB}")
    print("  (sudo may ask for your Mac password)", file=sys.stderr)
    proc = subprocess.run(["sudo", "/bin/sh", "-c", script], input=new, text=True)
    if proc.returncode != 0:
        raise ApplyError(f"writing {NSMB} failed (exit {proc.returncode})")
    with open(NSMB) as fh:
        if fh.read() != new:
            raise ApplyError(f"{NSMB} does not contain the expected content after writing")
    return f"wrote {NSMB} (backup {backup}); unmount and remount the share for it to take effect"


EXTRA_SCRIPT = r"""
f={path}; b="$f.smbfixer-{stamp}"
if [ -e "$f" ]; then cp "$f" "$b"; fi
cat > "$f.smbfixer-new" && mv "$f.smbfixer-new" "$f"
out=$(testparm -s 2>&1 >/dev/null); rc=$?
if [ $rc -ne 0 ] || echo "$out" | grep -qiE 'unknown parameter|error loading|error in parameter'; then
  if [ -e "$b" ]; then cp "$b" "$f"; else rm -f "$f"; fi
  echo "ROLLED_BACK"; echo "$out" | tail -5; exit 3
fi
smbcontrol smbd reload-config || {{ echo "RELOAD_FAILED"; exit 4; }}
echo "OK $b"
"""


def write_extra(ssh: SSH, new: str) -> str:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    r = ssh.run("apply-smb-extra", EXTRA_SCRIPT.format(path=EXTRA, stamp=stamp), timeout=60, input=new)
    if "ROLLED_BACK" in r.stdout:
        raise ApplyError("testparm rejected the new smb-extra.conf; the previous file was restored:\n"
                         + r.stdout.split("ROLLED_BACK", 1)[1].strip())
    if not r.ok or "OK " not in r.stdout:
        raise ApplyError(f"updating {EXTRA} failed: {(r.stderr or r.stdout).strip()[-300:]}")
    check = ssh.run("verify-smb-extra", f"cat {EXTRA}")
    if check.stdout != new:
        raise ApplyError(f"{EXTRA} on the server does not match what was written")
    backup = r.stdout.split("OK ", 1)[1].strip()
    return (f"wrote {EXTRA} (backup {backup}), validated with testparm and reloaded Samba; "
            "settings such as socket options apply to new connections, so reconnect the share")


def run_command(rec: Recommendation, ssh: SSH | None) -> str:
    if rec.target == HOST_SHELL:
        if ssh is None:
            raise ApplyError("no SSH access to the server")
        r = ssh.run("apply-cmd", shlex.join(rec.command))
    else:
        proc = subprocess.run(rec.command, capture_output=True, text=True)
        if proc.returncode != 0:
            raise ApplyError(f"{shlex.join(rec.command)} failed: {proc.stderr.strip()}")
        return f"ran {shlex.join(rec.command)}"
    if not r.ok:
        raise ApplyError(f"{shlex.join(rec.command)} failed on the server: {r.stderr.strip()}")
    return f"ran {shlex.join(rec.command)} on the server"


def plan(facts: Facts, recs: list[Recommendation], ssh: SSH | None) -> list[Change]:
    files = report.proposed_files(facts, recs)
    changes = []
    if report.NSMB_FILE in files:
        old, new = files[report.NSMB_FILE]
        changes.append(Change("Mac", f"Rewrite {NSMB}", diff(old, new, NSMB), lambda new=new: write_nsmb(new),
                              [r for r in recs if r.target == report.CLIENT_NSMB]))
    if report.EXTRA_FILE in files:
        old, new = files[report.EXTRA_FILE]
        if ssh is None:
            raise ApplyError("server changes need SSH access (host.address in smbfixer.toml)")
        changes.append(Change("Unraid server", f"Rewrite {EXTRA} and reload Samba", diff(old, new, EXTRA),
                              lambda new=new: write_extra(ssh, new),
                              [r for r in recs if r.target == report.HOST_SMB_EXTRA]))
    for r in recs:
        if r.command and r.target in {CLIENT_SHELL, HOST_SHELL}:
            changes.append(Change(r.machine, r.action, f"$ {shlex.join(r.command)}",
                                  lambda r=r: run_command(r, ssh), [r]))
    return changes
