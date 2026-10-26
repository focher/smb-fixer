"""Host-side regressions from a real Unraid 7.3 box: macvlan shim routing, legacy smb-extra tweaks,
the multichannel interfaces hint, and periodic trouble detection."""

from smbfixer import report
from smbfixer.analysis import analyze
from smbfixer.analysis.rules import interfaces_with_speed
from smbfixer.parse import samba as ps
from tests.fixtures import result, troubled_snapshot

NET = """\
bond0|1500|20000|full|up|br0|no|eth0
br0|1500|20000|unknown|up|-|no|bond0
br0.macvlan0|1500|20000|unknown|up|-|no|br0
shim-br0|1500|20000|unknown|up|-|no|br0
eth0|1500|10000|full|up|bond0|yes|-
eth1|1500|10000|full|up|bond0|yes|-
eth2|1500|1000|full|up|-|yes|-
"""
IP_LINK = ('[{"ifname":"br0.macvlan0","link":"br0","mtu":1500,"num_tx_queues":1,'
           '"linkinfo":{"info_kind":"macvlan"},"stats64":{"rx":{"packets":5},"tx":{"packets":5}}},'
           '{"ifname":"br0","mtu":1500,"num_tx_queues":1,"linkinfo":{"info_kind":"bridge"},'
           '"stats64":{"rx":{"packets":5},"tx":{"packets":5}}}]')
ROUTES = ('[{"dst":"10.0.0.0/24","dev":"br0.macvlan0","prefsrc":"10.0.0.11"},'
          '{"dst":"10.0.0.0/24","dev":"br0","prefsrc":"10.0.0.10","metric":1}]')
ADDRS = ('[{"ifname":"br0","addr_info":[{"local":"10.0.0.10"}]},'
         '{"ifname":"shim-br0","addr_info":[{"local":"10.0.0.10"}]},'
         '{"ifname":"br0.macvlan0","addr_info":[{"local":"10.0.0.11"}]}]')
EXTRA = """\
[global]
ea support = no
oplocks = no
level2 oplocks = no
socket options = TCP_NODELAY IPTOS_LOWDELAY SO_RCVBUF=131072 SO_SNDBUF=131072
vfs objects = catia fruit streams_xattr
fruit:metadata = netatalk
fruit:wipe_abe = yes
fruit:copyfile = yes
"""


def unraid_snapshot():
    snap = troubled_snapshot()
    snap.meta["host_ip"] = "10.0.0.10"
    h = snap.host
    h["net"] = result("net", NET)
    h["ip_link"] = result("ip_link", IP_LINK)
    h["routes"] = result("routes", ROUTES)
    h["addrs"] = result("addrs", ADDRS)
    h["route_to_client"] = result("route_to_client",
                                  '10.0.0.20\n[{"dst":"10.0.0.20","from":"10.0.0.10","dev":"br0.macvlan0"}]\n')
    h["smb_extra"] = result("smb_extra", EXTRA)
    h["testparm"].stdout = (h["testparm"].stdout
                            .replace("\toplocks = Yes", "\toplocks = No\n\tlevel2 oplocks = No\n\tea support = No"
                                     "\n\tinterfaces = 10.0.0.10/24 10.0.0.11/24 127.0.0.1 ::1")
                            .replace("\twrite list = tim\n", "\twrite list = tim\n\tfruit:metadata = stream\n"))
    return snap


def by_id(findings):
    return {f.id: f for f in findings}


def test_macvlan_resolves_to_bond_members():
    ifaces = ps.net(NET)
    assert ps.parent_device(ifaces, "br0.macvlan0") == "br0"
    assert ps.physical_members(ifaces, "br0.macvlan0") == ["eth0", "eth1"]
    # 7-column output from older snapshots still resolves by name
    old = ps.net("\n".join("|".join(line.split("|")[:7]) for line in NET.splitlines()))
    assert ps.physical_members(old, "br0.macvlan0") == ["eth0", "eth1"]


def test_shim_route_flagged_with_evidence():
    facts, findings = analyze(unraid_snapshot())
    assert facts.host_phys == ["eth0", "eth1"]
    f = by_id(findings)["network.host_shim_route"]
    assert "br0.macvlan0" in f.title and "br0" in f.title
    assert any("metric 1" in e for e in f.evidence)
    assert any("10.0.0.10 is assigned to br0, shim-br0" in e for e in f.evidence)


def test_plain_bridge_route_not_flagged():
    snap = unraid_snapshot()
    snap.host["route_to_client"] = result("route_to_client", '10.0.0.20\n[{"dst":"10.0.0.20","dev":"br0"}]\n')
    facts, findings = analyze(snap)
    assert "network.host_shim_route" not in by_id(findings)
    assert facts.host_phys == ["eth0", "eth1"]


def test_legacy_tweaks_are_removed_from_snippet():
    facts, findings = analyze(unraid_snapshot())
    f = by_id(findings)
    legacy = f["host.legacy_tweaks"]
    assert any("ea support = no" in e for e in legacy.evidence)
    assert any("fruit:wipe_abe" in e for e in legacy.evidence)
    assert any("netatalk" in e for e in legacy.evidence)
    oplocks = f["host.oplocks"]
    assert {r.remove_key for r in oplocks.recommendations} == {"oplocks", "level2 oplocks"}
    assert "no SMB2 leases" in oplocks.detail
    snippet = report.snippets(facts, findings)["/boot/config/smb-extra.conf (host)"]
    for gone in ("ea support", "oplocks", "SO_RCVBUF", "netatalk", "wipe_abe"):
        assert gone not in snippet, gone
    assert "fruit:copyfile = yes" in snippet  # good lines survive
    assert "vfs objects = catia fruit streams_xattr" in snippet


def test_interfaces_hint_keeps_unraid_list():
    line = interfaces_with_speed("10.0.0.10/24 10.0.0.11/24 127.0.0.1 ::1", "10.0.0.10", 10_000_000_000)
    assert line == '"10.0.0.10/24;speed=10000000000" 10.0.0.11/24 127.0.0.1 ::1'
    assert interfaces_with_speed('"10.0.0.10/24;capability=RSS,speed=1"', "10.0.0.10", 2) == \
        '"10.0.0.10/24;capability=RSS,speed=2"'
    assert interfaces_with_speed("br0 lo", "10.0.0.10", 1) is None


def test_periodic_needs_real_episodes():
    snap = unraid_snapshot()
    log = ["Timestamp               Ty Process[PID:TID]"]
    for hour in (8, 9, 10):
        log += [f"2026-10-23 {hour:02d}:52:10.000 E  kernel[0:1] (smbfs) smb_iod_sendall: id 5 ts > iod_lastrecv",
                f"2026-10-23 {hour:02d}:52:14.000 E  kernel[0:1] (smbfs) nbssn_recvhdr: id 5 flags 0x36 "
                "Server closed their side of the connection."]
    snap.client["smb_log"].stdout = "\n".join(log) + "\n"
    f = by_id(analyze(snap)[1])
    assert ":52 past the hour" in f["logs.periodic"].title
    assert "logs.idle_closes" not in f


def test_stopped_array_and_restart_explain_the_outage():
    snap = unraid_snapshot()
    h = snap.host
    h["array"] = result("array", 'mdState="STOPPED"\nfsState="Stopped"\n')
    # host clock 1792768601 with 600 s uptime -> booted 10:06:41 local (-0500), 1 s skew
    h["uptime"] = result("uptime", "600.00 4000.00\n")
    h["syslog"].stdout += "Oct 23 10:07:30 Tower kernel: i40e 0000:01:00.1 eth1: NIC Link is Up, 10 Gbps Full Duplex\n"
    snap.client["smb_log"].stdout = (
        "Timestamp               Ty Process[PID:TID]\n"
        "2026-10-23 10:05:47.000 E  kernel[0:1] (smbfs) smb_iod_sendall: id 7 ts > iod_lastrecv\n"
        "2026-10-23 10:06:47.000 E  kernel[0:1] (smbfs) smb_iod_request: iod 7 is dead, give up on request 0x1\n")
    facts, findings = analyze(snap)
    f = by_id(findings)
    assert f["host.array_stopped"].severity == "critical"
    assert facts.host_boot.strftime("%H:%M") == "10:06"
    assert "restarted at 2026-10-23 10:06" in f["host.recent_boot"].title
    ep = f["logs.episodes"]
    assert ep.severity == "warning" and "explained by the server restart" in ep.title
    assert "logs.host_critical" not in f  # "Link is Up" at boot is not a fault
    assert "storage.spindown" not in f
