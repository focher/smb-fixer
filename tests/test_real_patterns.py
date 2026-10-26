"""Regression tests built from message patterns seen on a real macOS 15 client talking to Unraid."""

from datetime import datetime, timedelta

from smbfixer.analysis import analyze
from smbfixer import report
from tests.fixtures import result, troubled_snapshot

BROKEN_NSMB = 'echo "[default]" | sudo tee -a /etc/nsmb.conf\necho "signing_required=no" | sudo tee -a /etc/nsmb.conf\n'

MULTICHANNEL = """\
Session: /Volumes/media
Info: Setup Time: 2026-10-23 10:50:15, Multichannel ON: yes, Reconnect Count: 0
\tTotal RX Bytes: 44043762444 (Packets: 1004313)
       id         client IF             server IF   state                     server ip                 port   speed
========================================================================================================================
M   17699  en7    (Ethernet)    4          4294967295          [session active       ]   192.168.1.10                 445    1.0 Gb
Server NIC:
\tname: NA, idx: 4294967295, type:    NA, speed 1.0 Gb, state connected
\t\tip_addr: 192.168.1.10
Client NIC:
\tname: en7, idx: 4, type: wired, speed 10.0 Gb, state connected
\t\tip_addr: 192.168.1.60
"""


def _log():
    lines = ["Timestamp               Ty Process[PID:TID]"]
    # an orphaned session retrying every 2 s for 20 minutes
    for i in range(600):
        m, sec = divmod(i * 2, 60)
        lines.append(f"2026-10-23 08:{17 + m:02d}:{sec:02d}.390 E  kernel[0:51aa49f] (smbfs) "
                     "smb_iod_start_reconnect: id 10912 start reconnect.")
    # hourly Time Machine run, durable handles refused, then the server closes the session
    for hour in (8, 9):
        lines += [
            f"2026-10-23 {hour:02d}:46:30.001 E  kernel[0:1] (smbfs) smbfs_vnop_ioctl: TM Read - attributes 0xc reconnTO 0 QoS 0x0",
            f"2026-10-23 {hour:02d}:46:30.002 E  kernel[0:1] (smbfs) smbfs_vnop_ioctl: Time Machine entitlement check failed",
            f"2026-10-23 {hour:02d}:46:30.003 E  kernel[0:1] (smbfs) smb2fs_smb_check_dur_handle_v2: "
            "Durable Handle V2 or Persistent Handles not supported.",
            f"2026-10-23 {hour:02d}:46:30.004 E  kernel[0:1] (smbfs) smbfs_vnop_ioctl: Server failed to set Durable Handle V2",
            f"2026-10-23 {hour:02d}:52:10.000 E  kernel[0:1] (smbfs) nbssn_recvhdr: id 1769{hour} flags 0x62 "
            "Server closed their side of the connection.",
        ]
    # the real lockup: server stops answering, closes after every renegotiate, session dies, reads fail
    lines.append("2026-10-23 10:48:40.000 E  kernel[0:2] (smbfs) smb_iod_sendall: id 17281 ts > iod_lastrecv && ts > sr_timesent.")
    lines.append("2026-10-23 10:48:40.001 E  kernel[0:2] (smbfs) smb_iod_reconnect: id 17281 Starting reconnect with 192.168.1.10")
    start = datetime(2026, 10, 23, 10, 48, 40)
    for s in range(0, 60, 4):
        t = (start + timedelta(seconds=s)).strftime("%Y-%m-%d %H:%M:%S")
        lines.append(f"{t}.100 E  kernel[0:2] (smbfs) "
                     "nbssn_recvhdr: id 17281 flags 0x36 Server closed their side of the connection.")
        lines.append(f"{t}.200 E  kernel[0:2] (smbfs) "
                     "smb_iod_reconnect: id 17281 The negotiate succeeded to 192.168.1.10")
    lines += [
        "2026-10-23 10:49:40.100 E  kernel[0:2] (smbfs) smbfs_do_strategy: Movie.mkv: READ failed with an error of 57",
        "2026-10-23 10:49:40.200 E  kernel[0:2] (smbfs) smb_iod_request: iod 17281 is dead, give up on request 0x104",
    ]
    lines += [f"2026-10-23 10:5{i % 10}:0{i % 10}.000 E  kernel[0:3] (smbfs) smb2fs_smb_cmpd_query: "
              "smb2fs_smb_ntcreatex failed 13" for i in range(25)]
    return "\n".join(lines) + "\n"


def snapshot():
    snap = troubled_snapshot()
    snap.add("client", result("nsmb_system", BROKEN_NSMB))
    snap.add("client", result("multichannel", MULTICHANNEL))
    snap.add("client", result("smb_log", _log()))
    snap.host = {}  # client-only, like running without SSH access
    return snap


def by_id(findings):
    return {f.id: f for f in findings}


def test_real_patterns():
    facts, findings = analyze(snapshot())
    f = by_id(findings)
    assert not [i for i in f if i.startswith("internal.")], [x.detail for x in findings if x.id.startswith("internal")]

    assert "client.nsmb_malformed" in f
    assert facts.nsmb == {}  # pasted commands must not be read as settings

    loop = f["client.reconnect_loop.10912"]
    assert "leftover" in loop.detail and "600 reconnect attempts" in loop.detail

    assert "client.time_machine_durable" in f
    tm_actions = [r.action for r in f["client.time_machine_durable"].recommendations]
    assert "durable handles = yes" in tm_actions and "posix locking = no" in tm_actions

    ep = f["logs.episodes"]
    assert ep.severity == "critical" and "failed I/O" in ep.title
    assert any("server disconnects" in e and "session gave up" in e for e in ep.evidence)
    assert "set up at 2026-10-23 10:50:15" in ep.evidence[-1]

    # the hourly closes after Time Machine are idle sessions, not trouble
    idle = f["logs.idle_closes"]
    assert idle.severity == "info" and "2 idle" in idle.title and "Time Machine" in idle.detail
    assert "logs.periodic" not in f
    assert len(facts.episodes) == 1  # only the 10:48 lockup

    assert "client.access_denied" in f
    assert "performance.mc_server_speed" in f

    # reconnect_retry spam and noise lines must not inflate the trouble counts
    assert facts.episodes and all(e.kind != "reconnect_retry" for ep in facts.episodes for e in ep.events)


def test_signing_rule_uses_real_attribute_name():
    snap = snapshot()
    stats = snap.client["statshares"]
    stats.stdout = stats.stdout.replace("                              SIGNING_ON                    TRUE\n",
                                        "                              SMB_CURR_SIGN_ALGORITHM       AES_128_GMAC\n")
    _, findings = analyze(snap)
    sig = by_id(findings)["client.signing"]
    assert any("AES_128_GMAC" in e for e in sig.evidence)
    assert "signing_required=no" in report.snippets(*analyze(snap))[report.NSMB_FILE]
