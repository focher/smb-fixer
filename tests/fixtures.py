"""Sample command output modelled on a real macOS client and an Unraid 7 host."""

from smbfixer.runner import Result
from smbfixer.snapshot import Snapshot

CLIENT = {
    "sw_vers": "ProductName:\t\tmacOS\nProductVersion:\t\t15.6\nBuildVersion:\t\t24G84\n",
    "mount": "//tim@Tower._smb._tcp.local/media on /Volumes/media (smbfs, nodev, nosuid, mounted by tim)\n",
    "statshares": """\
==================================================================================================
SHARE                         ATTRIBUTE TYPE                VALUE
==================================================================================================
media
                              SERVER_NAME                   Tower._smb._tcp.local
                              USER_ID                       501
                              SMB_NEGOTIATE                 SMBV_NEG_SMB2_ENABLED
                              SMB_NEGOTIATE                 SMBV_NEG_SMB3_ENABLED
                              SMB_VERSION                   SMB_3.1.1
                              SMB_SHARE_TYPE                DISK
                              SIGNING_SUPPORTED             TRUE
                              SIGNING_ON                    TRUE
                              SMB_CURR_ENCRYPT_ALGORITHM    OFF
                              MULTI_CHANNEL_SUPPORTED       TRUE
                              SESSION_RECONNECT_TIME        2026-10-23 10:15:41
                              SESSION_RECONNECT_COUNT       2

--------------------------------------------------------------------------------------------------
""",
    "nsmb_system": "",
    "ifconfig": """\
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether aa:bb:cc:dd:ee:00
\tinet 192.168.1.50 netmask 0xffffff00 broadcast 192.168.1.255
\tmedia: autoselect
\tstatus: active
en7: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 9000
\tether aa:bb:cc:dd:ee:07
\tinet 192.168.1.60 netmask 0xffffff00 broadcast 192.168.1.255
\tmedia: autoselect (10GbaseT <full-duplex>)
\tstatus: active
""",
    "hwports": """\

Hardware Port: Wi-Fi
Device: en0
Ethernet Address: aa:bb:cc:dd:ee:00

Hardware Port: Thunderbolt Ethernet Slot 1
Device: en7
Ethernet Address: aa:bb:cc:dd:ee:07
""",
    "route": """\
   route to: 192.168.1.10
destination: 192.168.1.0
       mask: 255.255.255.0
  interface: en7
      flags: <UP,DONE,CLONING>
""",
    "ping": """\
PING 192.168.1.10 (192.168.1.10): 56 data bytes

--- 192.168.1.10 ping statistics ---
10 packets transmitted, 10 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 0.210/0.330/0.610/0.110 ms
""",
    "ping_jumbo": """\
PING 192.168.1.10 (192.168.1.10): 8972 data bytes

--- 192.168.1.10 ping statistics ---
3 packets transmitted, 0 packets received, 100.0% packet loss
""",
    "ping_1500": "3 packets transmitted, 3 packets received, 0.0% packet loss\n",
    "ds_store": "",
    "date": "1792768600 -0500\n",
    "smb_log": """\
Timestamp               Ty Process[PID:TID]
2026-10-23 10:15:12.004 E  kernel[0:2f1a] (smbfs) smb_iod_sendrecv: request timed out, server not responding
2026-10-23 10:15:41.551 Df kernel[0:2f1a] (smbfs) smb_iod_reconnect: Reconnect succeeded
""",
}

HOST = {
    "os": 'version="7.3.0"\nLinux 6.12.24-Unraid x86_64\n',
    "samba_version": "Version 4.21.4\n",
    "testparm": """\
[global]
\tserver min protocol = SMB2_02
\tserver max protocol = SMB3
\tserver signing = default
\tserver multi channel support = Yes
\tsocket options = TCP_NODELAY SO_RCVBUF=65536 SO_SNDBUF=65536
\tstrict sync = Yes
\toplocks = Yes
\tsmb2 leases = Yes
\tkernel oplocks = No
\tlog level = 0

[media]
\tpath = /mnt/user/media
\tvalid users = tim
\twrite list = tim
""",
    "smbstatus_json": '{"sessions": {"1": {"remote_machine": "192.168.1.60", "username": "tim", '
                      '"session_dialect": "SMB3_11", "signing": {"cipher": "AES-128-GMAC", "degree": "partial"}, '
                      '"encryption": {"cipher": "", "degree": "none"}}}}',
    "smb_extra": "",
    "ident": 'NAME="Tower"\nenable_fruit="no"\n',
    "share_cfgs": '### media.cfg\nshareUseCache="only"\nshareCachePool="cache"\n### backups.cfg\nshareUseCache="yes"\n',
    "disk_cfg": 'spindownDelay="1"\n',
    "disks_ini": '["disk1"]\nname="disk1"\nspundown="1"\n',
    "user_shares": "dir|media|\ndir|backups|\n",
    "net": "lo|65536|-1||unknown|-|no\neth0|1500|10000|full|up|bond0|yes\nbond0|1500|10000|full|up|br0|no\n"
           "br0|1500|-1||up|-|no\n",
    "ip_link": '[{"ifname":"eth0","mtu":1500,"stats64":{"rx":{"bytes":1,"packets":1000000,"errors":120,"dropped":0},'
               '"tx":{"bytes":1,"packets":900000,"errors":0,"dropped":0}}},'
               '{"ifname":"br0","mtu":1500,"stats64":{"rx":{"packets":1},"tx":{"packets":1}}}]',
    "route_to_client": '192.168.1.60\n[{"dst":"192.168.1.60","dev":"br0","prefsrc":"192.168.1.10"}]\n',
    "ethtool": "### eth0\nSettings for eth0:\n\tSpeed: 10000Mb/s\n\tDuplex: Full\n\tLink detected: yes\n"
               "     rx_crc_errors: 118\n",
    "load": "8\n0.90 0.70 0.60 2/600 12345\n               total        used        free      shared  buff/cache   available\n"
            "Mem:           31900        6000        1000         500       24900       25000\nSwap:              0           0           0\n",
    "vmstat": "procs -----------memory---------- ---swap-- -----io---- -system-- ------cpu-----\n"
              " r  b   swpd   free   buff  cache   si   so    bi    bo   in   cs us sy id wa st\n"
              " 1  0      0 100000 100 2000000    0    0     5    10  100  200  5  2 92  1  0\n"
              " 1  0      0 100000 100 2000000    0    0     5    10  100  200  5  2 92  1  0\n",
    "df": "Filesystem 1024-blocks Used Available Capacity Mounted on\ntmpfs 131072 20000 111072 16% /var/log\n",
    "date": "1792768601 -0500\n",
    "iperf3": "",
    "samba_log": """\
[2026/10/23 10:15:40.123456,  0] ../../source3/smbd/smb2_server.c:4100(smbd_smb2_request_error_ex)
  smbd_smb2_request_error_ex: idx[1] status[NT_STATUS_CONNECTION_RESET] || at ../../source3/smbd/smb2_read.c:421
""",
    "syslog": """\
Oct 23 10:14:58 Tower emhttpd: read SMART /dev/sdc
Oct 23 10:14:59 Tower kernel: ata3.00: configured for UDMA/133
Oct 23 09:00:00 Tower emhttpd: spinning down /dev/sdc
""",
}


def result(name, out, rc=0):
    return Result(name, name, rc, out, "", 0.01)


def troubled_snapshot() -> Snapshot:
    snap = Snapshot(created_at=1792768600.0, meta={
        "host_address": "tower.local", "host_ip": "192.168.1.10",
        "mount_point": "/Volumes/media", "share": "media",
    })
    for k, v in CLIENT.items():
        snap.add("client", result(k, v, 0 if v or k in {"ds_store"} else 1))
    snap.client["ds_store"].returncode = 1
    snap.client["nsmb_system"].returncode = 1
    for k, v in HOST.items():
        snap.add("host", result(k, v, 0 if v else 1))
    return snap
