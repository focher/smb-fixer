"""Samba / Unraid host collectors, run over SSH. All commands are read-only."""

from __future__ import annotations

import functools

from smbfixer.config import Config
from smbfixer.runner import SSH

NET_SCRIPT = r"""
for d in /sys/class/net/*; do
  n=${d##*/}
  m=$(readlink "$d/master" 2>/dev/null); m=${m##*/}
  phys=no; [ -e "$d/device" ] && phys=yes
  echo "$n|$(cat $d/mtu 2>/dev/null)|$(cat $d/speed 2>/dev/null)|$(cat $d/duplex 2>/dev/null)|$(cat $d/operstate 2>/dev/null)|${m:--}|$phys"
done
"""

ETHTOOL_SCRIPT = r"""
for d in /sys/class/net/*; do
  [ -e "$d/device" ] || continue
  n=${d##*/}; echo "### $n"; ethtool "$n" 2>/dev/null; ethtool -S "$n" 2>/dev/null | grep -iE 'err|drop|miss|fifo|crc|timeout' | grep -vE ': 0$'
done
"""

USER_SHARES_SCRIPT = r"""
for d in /mnt/user/*; do
  [ -e "$d" ] || continue
  if [ -L "$d" ]; then echo "symlink|${d##*/}|$(readlink "$d")"; else echo "dir|${d##*/}|"; fi
done
"""

SHARE_CFG_SCRIPT = r"""
for f in /boot/config/shares/*.cfg; do [ -e "$f" ] || continue; echo "### ${f##*/}"; cat "$f"; echo; done
"""


def jobs(cfg: Config, ssh: SSH) -> list:
    n = cfg.collect.host_log_lines

    def r(name: str, script: str, timeout: float = 60.0):
        return functools.partial(ssh.run, name, script, timeout)

    return [
        r("os", "cat /etc/unraid-version 2>/dev/null; uname -srm"),
        r("samba_version", "smbd -V"),
        r("testparm", "testparm -sv 2>/dev/null"),
        r("smbstatus_json", "smbstatus --json 2>/dev/null"),
        r("smbstatus", "smbstatus 2>/dev/null"),
        r("smb_extra", "cat /boot/config/smb-extra.conf 2>/dev/null"),
        r("ident", "cat /boot/config/ident.cfg 2>/dev/null"),
        r("share_cfgs", SHARE_CFG_SCRIPT),
        r("disk_cfg", "cat /boot/config/disk.cfg 2>/dev/null"),
        r("disks_ini", "cat /var/local/emhttp/disks.ini 2>/dev/null"),
        r("user_shares", USER_SHARES_SCRIPT),
        r("net", NET_SCRIPT),
        r("ip_link", "ip -j -s link"),
        r("route_to_client", 'c=${SSH_CONNECTION%% *}; echo "$c"; ip -j route get "$c"'),
        r("ethtool", ETHTOOL_SCRIPT),
        r("load", "nproc; cat /proc/loadavg; free -m"),
        r("vmstat", "vmstat 1 5", timeout=30),
        r("df", "df -Pk"),
        r("date", "date '+%s %z'"),
        r("sysctl_net", "sysctl net.core.rmem_max net.core.wmem_max net.ipv4.tcp_rmem net.ipv4.tcp_wmem"),
        r("iperf3", "command -v iperf3"),
        r("samba_log", f"tail -n {n} /var/log/samba/log.smbd 2>/dev/null"),
        r("syslog", f"grep -E 'smbd|nmbd|samba|shfs|emhttpd|kernel' /var/log/syslog | tail -n {n}"),
    ]
