from datetime import datetime

from smbfixer.parse import macos as pm
from smbfixer.parse import samba as ps
from tests.fixtures import CLIENT, HOST


def test_mounts_normalise_bonjour_names():
    [m] = pm.smbfs_mounts(CLIENT["mount"])
    assert (m.server, m.share, m.mount_point, m.user) == ("Tower.local", "media", "/Volumes/media", "tim")


def test_statshares_multi_value_attributes():
    shares = pm.statshares(CLIENT["statshares"])
    attrs = shares["media"]
    assert pm.first(attrs, "SMB_VERSION") == "SMB_3.1.1"
    assert len(attrs["SMB_NEGOTIATE"]) == 2
    assert pm.is_true(attrs, "SIGNING_ON")
    assert pm.first(attrs, "SESSION_RECONNECT_TIME") == "2026-10-23 10:15:41"


def test_ifconfig_and_media_speed():
    ifaces = pm.ifconfig(CLIENT["ifconfig"])
    assert ifaces["en7"]["mtu"] == 9000
    assert ifaces["en0"]["inet"] == ["192.168.1.50"]
    assert pm.media_speed_mbps(ifaces["en7"]["media"]) == 10000
    assert pm.media_speed_mbps("autoselect (1000baseT <full-duplex>)") == 1000
    assert pm.media_speed_mbps("autoselect") is None


def test_hwports_route_ping():
    assert pm.hwports(CLIENT["hwports"]) == {"en0": "Wi-Fi", "en7": "Thunderbolt Ethernet Slot 1"}
    assert pm.route_interface(CLIENT["route"]) == "en7"
    assert pm.route_gateway(CLIENT["route"]) == ""
    p = pm.ping(CLIENT["ping"])
    assert p["loss"] == 0.0 and p["avg"] == 0.33
    assert pm.ping(CLIENT["ping_jumbo"])["received"] == 0


def test_unified_log():
    events = pm.unified_log(CLIENT["smb_log"])
    assert len(events) == 2
    assert events[0].when == datetime(2026, 10, 23, 10, 15, 12, 4000)
    assert events[0].source == "kernel"


def test_testparm_sections():
    conf = ps.testparm(HOST["testparm"])
    assert conf["global"]["server signing"] == "default"
    assert conf["media"]["path"] == "/mnt/user/media"
    assert ps.vfs_objects(conf["media"]) == []


def test_unraid_cfgs():
    cfgs = ps.share_cfgs(HOST["share_cfgs"])
    assert cfgs["media"]["shareUseCache"] == "only"
    assert cfgs["backups"]["shareUseCache"] == "yes"
    assert ps.disks_ini(HOST["disks_ini"])["disk1"]["spundown"] == "1"


def test_net_resolves_bridge_to_physical():
    ifaces = ps.net(HOST["net"])
    assert ifaces["eth0"]["physical"] and ifaces["eth0"]["speed"] == 10000
    assert ifaces["br0"]["speed"] is None
    assert ps.physical_members(ifaces, "br0") == ["eth0"]


def test_ethtool_load_vmstat_df():
    e = ps.ethtool(HOST["ethtool"])["eth0"]
    assert e["speed"] == 10000 and e["duplex"] == "full" and e["counters"]["rx_crc_errors"] == 118
    load = ps.load(HOST["load"])
    assert load["cpus"] == 8 and load["load"][0] == 0.9 and load["mem_available_mb"] == 25000
    assert ps.vmstat(HOST["vmstat"])["wa"] == 1
    assert ps.df(HOST["df"])["/var/log"]["used_pct"] == 16


def test_samba_and_syslog():
    [ev] = ps.samba_log(HOST["samba_log"])
    assert "NT_STATUS_CONNECTION_RESET" in ev.message
    assert ev.when == datetime(2026, 10, 23, 10, 15, 40)
    sys_events = ps.syslog(HOST["syslog"], 2026)
    assert sys_events[0].source == "emhttpd" and "read SMART" in sys_events[0].message


def test_parsers_tolerate_garbage():
    assert pm.statshares("garbage\n") == {"garbage": {}}
    assert ps.smbstatus_json("not json") == {}
    assert ps.ip_link_stats("") == {}
    assert ps.vmstat("") == {}
    assert pm.ping("") == {}
