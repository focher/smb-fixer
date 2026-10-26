"""Copy failures seen on a live macOS 15.7 / Unraid 7.3 pair: a write to the array blocks the connection
(async I/O off, sendfile on), the Mac reconnects, and the open file cannot be reclaimed."""

from smbfixer import report
from smbfixer.analysis import analyze
from tests.fixtures import result
from tests.test_host_paths import unraid_snapshot

CLIENT_LOG = """\
Timestamp               Ty Process[PID:TID]
2026-10-23 10:05:37.001 E  kernel[0:1] (smbfs) smb_iod_sendrq: id 0: TRAN_SEND returned non-fatal error 35 sr_command = 0x9
2026-10-23 10:05:37.002 E  kernel[0:1] (smbfs) smb_iod_reconnect: id 0 Starting reconnect with 10.0.0.10
2026-10-23 10:05:37.003 E  kernel[0:1] (smbfs) smb2_smb_read_write_async: smb_iod_rq_enqueue failed 35
2026-10-23 10:05:37.004 E  kernel[0:1] (smbfs) smb_iod_reconnect: id 0 The negotiate succeeded to 10.0.0.10
2026-10-23 10:05:37.005 E  kernel[0:1] (smbfs) smb2fs_reconnect_dur_handle: Warning: Could not reopen durable handle for Episode.m4v
2026-10-23 10:05:37.006 E  kernel[0:1] (smbfs) smb2fs_reconnect: smb2fs_reconnect_dur_handle failed <2> for sharedFID on <Episode.m4v>
2026-10-23 10:05:37.007 E  kernel[0:1] (smbfs) smb_iod_reconnect: id 0: Reconnect completed successfully.
2026-10-23 10:05:37.008 E  kernel[0:1] (smbfs) smb2_smb_write: smb2_smb_read_write_async failed with an error 35
"""
SYSLOG = """\
Oct 23 10:05:37 Tower smbd[157101]: [2026/10/23 10:05:37.616028,  0] ../../source3/smbd/smb2_read.c:265(smb2_sendfile_send_data)
Oct 23 10:05:37 Tower smbd[157101]:   smb2_sendfile_send_data: sendfile failed for file Movie.mkv (Broken pipe) for client PID=157101. Terminating
Oct 23 10:05:37 Tower smbd[218609]: [2026/10/23 10:05:37.753780,  0] ../../source3/smbd/durable.c:951(vfs_default_durable_reconnect)
Oct 23 10:05:37 Tower smbd[218609]:   vfs_default_durable_reconnect: default_durable_reconnect_fn [TV/Episode.m4v] failed: NT_STATUS_OBJECT_NAME_NOT_FOUND
"""
SAMBA_LOG = """\
[2026/10/23 10:05:37.616028,  0] ../../source3/smbd/smb2_read.c:265(smb2_sendfile_send_data)
  smb2_sendfile_send_data: sendfile failed for file Movie.mkv (Broken pipe) for client PID=157101. Terminating
[2026/10/23 10:05:37.753780,  0] ../../source3/smbd/durable.c:951(vfs_default_durable_reconnect)
  vfs_default_durable_reconnect: default_durable_reconnect_fn [TV/Episode.m4v] failed: NT_STATUS_OBJECT_NAME_NOT_FOUND
"""


def snapshot():
    snap = unraid_snapshot()
    snap.client["smb_log"].stdout = CLIENT_LOG
    snap.host["syslog"] = result("syslog", SYSLOG)
    snap.host["samba_log"] = result("samba_log", SAMBA_LOG)
    snap.host["smb_extra"] = result("smb_extra", "[global]\nsocket options = TCP_NODELAY\n\n[tm]\nposix locking = no\n")
    snap.host["testparm"].stdout = snap.host["testparm"].stdout.replace(
        "[global]\n", "[global]\n\taio read size = 0\n\taio write size = 0\n\tuse sendfile = Yes\n"
                      "\tdurable handles = Yes\n\tkernel share modes = No\n\tposix locking = Yes\n", 1)
    return snap


def by_id(findings):
    return {f.id: f for f in findings}


def test_copy_failure_chain():
    facts, findings = analyze(snapshot())
    f = by_id(findings)

    sync = f["host.synchronous_io"]
    assert sync.severity == "critical" and "error 35" in sync.detail
    assert {r.action for r in sync.recommendations} == {"aio read size = 1", "aio write size = 1", "use sendfile = no"}

    lost = f["host.durable_unavailable"]
    assert lost.severity == "critical" and "posix locking = Yes" in lost.detail
    assert "file: Episode.m4v" in lost.evidence
    actions = [(r.section, r.action, r.remove_key) for r in lost.recommendations]
    assert ("global", "posix locking = no", "") in actions
    assert ("tm", "delete the 'posix locking' line", "posix locking") in actions

    ep = f["logs.episodes"]
    assert ep.severity == "critical" and "open files lost" in ep.evidence[0]

    # each server event counted once even though it is in log.smbd and syslog
    assert sum(1 for e in facts.host_events if e.kind == "durable_lost") == 1

    new = report.snippets(facts, findings)[report.EXTRA_FILE]
    for line in ("aio read size = 1", "aio write size = 1", "use sendfile = no", "posix locking = no"):
        assert line in new.splitlines(), line
    assert "[tm]" not in new  # the per-share copy is folded into [global]
