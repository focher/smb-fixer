import os
import stat
import subprocess

import pytest

from smbfixer import apply as ap
from smbfixer import configedit, report
from smbfixer.analysis import analyze
from smbfixer.analysis.model import CLIENT_NSMB, CLIENT_SHELL, HOST_SMB_EXTRA, HOST_UI, Recommendation
from smbfixer.runner import Result
from tests.test_host_paths import EXTRA, unraid_snapshot
from tests.test_real_patterns import BROKEN_NSMB


def rec(target, action, section="global", **kw):
    return Recommendation(target, action, section=section, **kw)


def test_edit_keeps_comments_and_order():
    text = "[global]\n# keep me\nfoo = 1\nStrict Sync = yes\n\n[tm]\nbar = 2\n"
    new = configedit.edit(text, [
        rec(HOST_SMB_EXTRA, "strict sync = no"),
        rec(HOST_SMB_EXTRA, "", remove_key="foo"),
        rec(HOST_SMB_EXTRA, "posix locking = no", section="tm"),
        rec(HOST_SMB_EXTRA, "x = y", section="new"),
    ])
    assert new == "[global]\n# keep me\nstrict sync = no\n\n[tm]\nbar = 2\nposix locking = no\n\n[new]\nx = y\n"


def test_edit_drops_malformed_lines_and_empty_sections():
    new = configedit.edit(BROKEN_NSMB, [
        rec(CLIENT_NSMB, "", section="default", drop_lines=BROKEN_NSMB.splitlines()),
        rec(CLIENT_NSMB, "signing_required=no", section="default"),
    ], sep="=")
    assert new == "[default]\nsigning_required=no\n"
    assert configedit.edit("[global]\na = 1\n", [rec(HOST_SMB_EXTRA, "", remove_key="a")]) == ""


def test_automatic_flags_and_machines():
    assert rec(CLIENT_NSMB, "a=b").automatic and rec(CLIENT_NSMB, "a=b").machine == "Mac"
    assert rec(HOST_SMB_EXTRA, "a = b").machine == "Unraid server"
    assert not rec(HOST_UI, "Settings > X").automatic
    assert not rec(CLIENT_SHELL, "look", check=True, command=["true"]).automatic
    assert rec(CLIENT_SHELL, "do", command=["true"]).automatic


def test_choose_requires_consent_for_tradeoffs():
    safe = rec(HOST_SMB_EXTRA, "a = b")
    risky = rec(HOST_SMB_EXTRA, "strict sync = no", tradeoff="data loss on power failure")
    manual = rec(HOST_UI, "click")
    assert ap.choose([safe, risky, manual], include_tradeoffs=False, interactive=False, ask=lambda p: True) == [safe]
    assert ap.choose([safe, risky], include_tradeoffs=False, interactive=True, ask=lambda p: True) == [safe, risky]
    assert ap.choose([safe, risky], include_tradeoffs=True, interactive=False, ask=lambda p: False) == [safe, risky]


def test_plan_matches_report_file():
    facts, findings = analyze(unraid_snapshot())
    recs = [r for r in report.all_recs(findings) if r.automatic and not r.tradeoff]
    changes = ap.plan(facts, recs, ssh=object())
    server = next(c for c in changes if c.machine == "Unraid server")
    assert "-ea support = no" in server.preview and "-oplocks = no" in server.preview
    assert "+socket options" not in server.preview  # pinned buffers removed, not replaced


def test_plan_leaves_plain_samba_config_alone(capsys):
    facts, findings = analyze(unraid_snapshot())
    facts.unraid_version = ""
    recs = [r for r in report.all_recs(findings) if r.automatic and not r.tradeoff]
    changes = ap.plan(facts, recs, ssh=None)
    assert not any(c.machine == "Unraid server" for c in changes)
    assert "not Unraid" in capsys.readouterr().err


class LocalSSH:
    """Runs 'remote' scripts locally against fake testparm/smbcontrol binaries."""

    def __init__(self, bindir):
        self.env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}"}

    def run(self, name, script, timeout=60, input=None):
        p = subprocess.run(["bash", "-c", script], input=input, capture_output=True, text=True, env=self.env)
        return Result(name, script, p.returncode, p.stdout, p.stderr, 0.0)


def fake_bin(tmp_path, testparm_rc=0, testparm_out=""):
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    for name, body in {"testparm": f'echo "{testparm_out}" >&2; exit {testparm_rc}',
                       "smbcontrol": f'echo reloaded >> "{tmp_path}/reloads"'}.items():
        f = bindir / name
        f.write_text(f"#!/bin/sh\n{body}\n")
        f.chmod(f.stat().st_mode | stat.S_IEXEC)
    return bindir


def test_write_extra_backs_up_validates_and_reloads(tmp_path, monkeypatch):
    target = tmp_path / "smb-extra.conf"
    target.write_text(EXTRA)
    monkeypatch.setattr(ap, "EXTRA", str(target))
    msg = ap.write_extra(LocalSSH(fake_bin(tmp_path)), "[global]\nfoo = bar\n")
    assert target.read_text() == "[global]\nfoo = bar\n"
    backups = list(tmp_path.glob("smb-extra.conf.smbfixer-*"))
    assert len(backups) == 1 and backups[0].read_text() == EXTRA
    assert (tmp_path / "reloads").read_text() == "reloaded\n"
    assert "validated with testparm" in msg


@pytest.mark.parametrize("rc,out", [(1, "Error loading services."), (0, "Ignoring unknown parameter \"bogus\"")])
def test_write_extra_rolls_back_when_testparm_objects(tmp_path, monkeypatch, rc, out):
    target = tmp_path / "smb-extra.conf"
    target.write_text(EXTRA)
    monkeypatch.setattr(ap, "EXTRA", str(target))
    with pytest.raises(ap.ApplyError, match="previous file was restored"):
        ap.write_extra(LocalSSH(fake_bin(tmp_path, rc, out)), "[global]\nbogus = 1\n")
    assert target.read_text() == EXTRA
    assert not (tmp_path / "reloads").exists()
