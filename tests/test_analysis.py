import json

from smbfixer import report
from smbfixer.analysis import analyze
from smbfixer.snapshot import Snapshot
from tests.fixtures import troubled_snapshot


def ids(findings):
    return {f.id for f in findings}


def test_troubled_snapshot_findings():
    facts, findings = analyze(troubled_snapshot())
    found = ids(findings)
    assert not [f for f in findings if f.id.startswith("internal.")], [f.detail for f in findings]
    expected = {
        "network.jumbo_broken",          # client 9000, host 1500, DF ping fails
        "network.nic_errors.eth0",       # rx errors + CRC counter
        "client.signing",
        "client.reconnects",
        "client.multichannel_wifi",      # Wi-Fi up next to 10GbE, MC supported
        "client.ds_store",
        "logs.episodes",
        "logs.host_samba",
        "host.fruit_missing",
        "host.socket_options",
        "host.strict_sync",
        "storage.fuse",
        "correlation.lockups",
    }
    assert expected <= found, expected - found
    assert "storage.spindown" not in found  # media is pool-only
    assert "network.wifi" not in found  # route goes over wired en7
    assert "client.encryption" not in found
    fuse = next(f for f in findings if f.id == "storage.fuse")
    assert fuse.severity == "warning"  # pool-only share can become exclusive


def test_array_share_flags_spindown():
    snap = troubled_snapshot()
    snap.meta["share"] = "backups"
    snap.host["testparm"].stdout += "\n[backups]\n\tpath = /mnt/user/backups\n"
    _, findings = analyze(snap)
    found = ids(findings)
    assert "storage.spindown" in found
    assert next(f for f in findings if f.id == "storage.fuse").severity == "info"


def test_correlation_links_reconnect_to_spinup():
    facts, findings = analyze(troubled_snapshot())
    corr = next(f for f in findings if f.id == "correlation.lockups")
    assert "spinup" in corr.title
    assert facts.clock_skew == 1.0


def test_severity_ordering():
    _, findings = analyze(troubled_snapshot())
    order = [f.severity for f in findings]
    assert order == sorted(order, key=["critical", "warning", "info", "ok"].index)


def test_snippets_merge_into_sections():
    facts, findings = analyze(troubled_snapshot())
    snip = report.snippets(facts, findings)
    client = snip[report.NSMB_FILE]
    assert client.startswith("[default]")
    assert "signing_required=no" in client and "mc_prefer_wired=yes" in client
    host = snip[report.EXTRA_FILE]
    assert "[global]" in host and "fruit:metadata = stream" in host
    assert "socket options = TCP_NODELAY" in host


def test_renderers_run():
    facts, findings = analyze(troubled_snapshot())
    out = report.text(facts, findings, color=False)
    assert "What to do, by machine" in out and "On this Mac" in out and "On the Unraid server" in out
    assert "[auto] Replace /etc/nsmb.conf with:" in out and "[you]" in out
    assert report.markdown(facts, findings).startswith("# SMB Fixer report")
    data = json.loads(report.as_json(facts, findings))
    assert data["findings"] and data["files"]


def test_snapshot_round_trip(tmp_path):
    snap = troubled_snapshot()
    path = snap.save(tmp_path / "s.json")
    again = Snapshot.load(path)
    assert ids(analyze(again)[1]) == ids(analyze(snap)[1])


def test_client_only_snapshot_does_not_crash():
    snap = troubled_snapshot()
    snap.host = {}
    _, findings = analyze(snap)
    assert not [f for f in findings if f.id.startswith("internal.")]
    assert not [f for f in findings if f.category == "host"]


def test_healthy_connection_is_quiet():
    snap = troubled_snapshot()
    c, h = snap.client, snap.host
    c["statshares"].stdout = c["statshares"].stdout.replace("SIGNING_ON                    TRUE",
                                                            "SIGNING_ON                    FALSE") \
        .replace("SESSION_RECONNECT_COUNT       2", "SESSION_RECONNECT_COUNT       0")
    c["ifconfig"].stdout = c["ifconfig"].stdout.replace("mtu 9000", "mtu 1500").replace(
        "\tstatus: active\nen7", "\tstatus: inactive\nen7")
    c["smb_log"].stdout = ""
    c["ds_store"].stdout = "1\n"
    h["smbstatus_json"].stdout = "{}"
    h["testparm"].stdout = (h["testparm"].stdout.replace("SO_RCVBUF=65536 SO_SNDBUF=65536", "")
                            .replace("strict sync = Yes", "strict sync = No")
                            .replace("\twrite list = tim\n", "\twrite list = tim\n\tvfs objects = catia fruit streams_xattr\n"
                                     "\treaddir_attr:aapl_max_access = no\n"))
    h["user_shares"].stdout = "symlink|media|/mnt/cache/media\n"
    h["ip_link"].stdout = h["ip_link"].stdout.replace('"errors":120', '"errors":0')
    h["ethtool"].stdout = h["ethtool"].stdout.replace("     rx_crc_errors: 118\n", "")
    h["samba_log"].stdout = ""
    h["syslog"].stdout = ""
    h["disk_cfg"].stdout = 'spindownDelay="0"\n'
    _, findings = analyze(snap)
    assert [f.id for f in findings if f.severity in {"critical", "warning"}] == []
