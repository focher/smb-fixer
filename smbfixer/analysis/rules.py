"""Diagnostic rules. Each rule takes Facts and yields Findings.

Rules only recommend changes; nothing here modifies either machine. Recommendations that trade
safety or compatibility for speed say so in `tradeoff`.
"""

from __future__ import annotations

import re
import shlex
from datetime import timedelta

from smbfixer.analysis import logs
from smbfixer.analysis.facts import Facts
from smbfixer.analysis.model import (
    CLIENT_NSMB,
    CLIENT_SHELL,
    HOST_SHELL,
    HOST_SMB_EXTRA,
    HOST_UI,
    NETWORK,
    Finding,
    Recommendation,
)
from smbfixer.parse import macos as pm
from smbfixer.parse import samba as ps

RULES = []


def rule(fn):
    RULES.append(fn)
    return fn


def nsmb(key, value, why, tradeoff=""):
    return Recommendation(CLIENT_NSMB, f"{key}={value}", why, section="default", tradeoff=tradeoff)


def extra(key, value, why, section="global", tradeoff=""):
    return Recommendation(HOST_SMB_EXTRA, f"{key} = {value}", why, section=section, tradeoff=tradeoff)


def drop(key, why, section="global", tradeoff=""):
    return Recommendation(HOST_SMB_EXTRA, f"delete the '{key}' line", why, section=section, tradeoff=tradeoff,
                          remove_key=key)


def in_extra(f: Facts, key: str, section: str = "global") -> str | None:
    """Value of `key` in smb-extra.conf, if the user (not Unraid) set it there."""
    sec = next((v for k, v in f.smb_extra.items() if k.lower() == section.lower()), {})
    return sec.get(key.lower())


def restore(f: Facts, key: str, good: str, why: str, tradeoff: str = "") -> Recommendation:
    """Fix a bad value: delete it from smb-extra.conf if it was set there, otherwise set the good value."""
    if in_extra(f, key) is not None:
        return drop(key, why + f" Samba's default is {good}.", tradeoff=tradeoff)
    section = f.share_name if key.lower() in f.share_conf else "global"
    return extra(key, good, why, section=section, tradeoff=tradeoff)


# --------------------------------------------------------------------------- network


@rule
def wifi_path(f: Facts):
    if f.client_iface_port and "wi-fi" in f.client_iface_port.lower():
        yield Finding(
            "network.wifi", "warning", "network",
            f"SMB traffic to the host leaves over Wi-Fi ({f.client_iface})",
            "Wi-Fi adds latency spikes and retransmits that show up as Finder beachballs and slow copies. "
            "If a wired interface is available, macOS may still prefer Wi-Fi for this route.",
            [f"route to host uses {f.client_iface} ({f.client_iface_port})"],
            [Recommendation(NETWORK, "Use a wired connection, and put it above Wi-Fi in "
                                     "System Settings > Network > ... > Set Service Order",
                            "A wired link removes most latency jitter.")],
        )


@rule
def link_speed(f: Facts):
    client_speed = pm.media_speed_mbps(f.client_iface_info.get("media", "")) if f.client_iface_info else None
    host_speeds = {n: (f.ethtool.get(n, {}).get("speed") or f.host_ifaces.get(n, {}).get("speed"))
                   for n in f.host_phys}
    evidence = []
    if client_speed:
        evidence.append(f"client {f.client_iface}: {f.client_iface_info.get('media')}")
    for n, s in host_speeds.items():
        evidence.append(f"host {n}: {s} Mb/s" if s else f"host {n}: speed unknown")
    slow = []
    if client_speed and client_speed < 1000 and "wi-fi" not in f.client_iface_port.lower():
        slow.append(f"client link is {client_speed} Mb/s")
    slow += [f"host {n} is {s} Mb/s" for n, s in host_speeds.items() if s and s < 1000]
    if slow:
        yield Finding(
            "network.link_speed", "warning", "network", "A link in the path negotiated below 1 Gb/s",
            "; ".join(slow) + ". This usually means a bad cable, a port forced to 100 Mb/s, or an old switch.",
            evidence,
            [Recommendation(NETWORK, "Replace the cable / check switch port settings for the slow link",
                            "Auto-negotiation dropping to 100 Mb/s is almost always physical.")],
        )
    for n in f.host_phys:
        duplex = f.ethtool.get(n, {}).get("duplex") or f.host_ifaces.get(n, {}).get("duplex")
        if duplex and duplex.startswith("half"):
            yield Finding(
                "network.half_duplex", "critical", "network", f"Host NIC {n} is running half duplex",
                "Half duplex causes collisions and severe throughput collapse under SMB load.",
                [f"{n}: duplex {duplex}"],
                [Recommendation(NETWORK, f"Fix auto-negotiation on {n} (cable/switch); never force one side only",
                                "A duplex mismatch is a classic cause of stalls.")],
            )


@rule
def mtu(f: Facts):
    cm = f.client_iface_info.get("mtu")
    hm = f.host_ifaces.get(f.host_route.get("dev") or "", {}).get("mtu")
    if not cm or not hm:
        return
    evidence = [f"client {f.client_iface} mtu {cm}", f"host {f.host_route.get('dev')} mtu {hm}"]
    jumbo_wanted = max(cm, hm) > 1500
    if jumbo_wanted and f.ping_jumbo and f.ping_jumbo.get("received", 0) == 0:
        yield Finding(
            "network.jumbo_broken", "critical", "network", "Jumbo frames are configured but do not pass end to end",
            "A 9000-byte don't-fragment ping failed. Large SMB reads/writes get dropped silently, which looks like "
            "a hang that resolves only after TCP retransmits or a reconnect.",
            evidence + ["ping -D -s 8972: no replies"],
            [Recommendation(NETWORK, "Either enable jumbo frames on every hop (client, switch, host) or set MTU 1500 "
                                     "on both client and host", "MTU must match across the whole L2 path.")],
        )
    elif cm != hm:
        yield Finding(
            "network.mtu_mismatch", "warning", "network", "Client and host MTU differ",
            "Mismatched MTU forces fragmentation or black-holes large frames depending on which side is bigger.",
            evidence,
            [Recommendation(NETWORK, f"Set the same MTU on both ends (both 1500, or both 9000 if the switch supports it)",
                            "Consistent MTU avoids silent drops of large SMB frames.")],
        )


@rule
def host_shim_route(f: Facts):
    """The host's route to the client leaves via a macvlan/ipvlan sub-interface (Docker host access)."""
    dev = f.host_route.get("dev") or ""
    info = f.host_ifaces.get(dev, {})
    kind = info.get("kind") or ""
    # Bridges, bonds and 802.1Q VLANs also have lower devices; only macvlan/ipvlan shims are suspect.
    if kind and kind not in {"macvlan", "ipvlan"}:
        return
    if not kind and not ps.is_shim_name(dev):
        return
    parent = ps.parent_device(f.host_ifaces, dev)
    host_ip = f.snap.meta.get("host_ip", "")
    ev = [f"route to {f.host_route.get('client_ip')}: dev {dev}"
          + (f" (src {f.host_route['src']})" if f.host_route.get("src") else "")
          + (f", {kind}" if kind else "") + (f" on {parent}" if parent else "")]
    for r in [r for r in f.host_routes if r.get("dev") in {dev, parent}]:
        ev.append(f"route {r.get('dst')} dev {r.get('dev')} metric {r.get('metric', 0)}")
    if info.get("tx_queues"):
        ev.append(f"{dev}: {info['tx_queues']} transmit queue(s)")
    holders = f.host_addrs.get(host_ip, [])
    if len(holders) > 1:
        ev.append(f"{host_ip} is assigned to {', '.join(holders)}")
    yield Finding(
        "network.host_shim_route", "warning", "network",
        f"Host answers this Mac through {dev}, a sub-interface of {parent or 'the bridge'}",
        f"Replies to the Mac do not leave through {parent or 'the main bridge'} directly but through a "
        f"{kind or 'macvlan'} device that Unraid creates for Docker's 'Host access to custom networks'. "
        "Its route wins because it has a lower metric than the bridge's own route. This adds a virtual hop "
        "to every SMB reply, and macvlan on Unraid has a history of kernel call traces and network drops "
        "(Unraid recommends ipvlan for custom networks). Worth ruling out if lockups continue.",
        ev,
        [Recommendation(HOST_UI, "Settings > Docker (Enable Docker: No to edit) > Docker custom network type: ipvlan",
                        "Avoids macvlan on the host's own network path.",
                        tradeoff="With ipvlan, containers on the custom network share the host's MAC address; "
                                 "routers doing MAC-based DHCP reservations see one MAC."),
         Recommendation(HOST_UI, "...or set 'Host access to custom networks: Disabled' if you do not need it",
                        "Removes the shim interface and its competing route.",
                        tradeoff="The server and containers with their own IPs can no longer reach each other "
                                 "directly."),
         Recommendation(HOST_SHELL, f"ip route get {f.host_route.get('client_ip')} from {host_ip}",
                        f"After the change this should show dev {parent or 'br0'}.", check=True)],
    )


@rule
def ping_quality(f: Facts):
    p = f.ping
    if not p:
        return
    ev = [f"{p.get('sent')} sent, {p.get('received')} received, {p.get('loss')}% loss",
          f"rtt min/avg/max/stddev {p.get('min')}/{p.get('avg')}/{p.get('max')}/{p.get('stddev')} ms"]
    loss = p.get("loss", 0)
    if loss > 0:
        yield Finding(
            "network.packet_loss", "critical" if loss >= 2 else "warning", "network",
            f"{loss}% packet loss between client and host",
            "Any loss on a LAN is abnormal. SMB over TCP stalls for retransmit timeouts on every lost segment.",
            ev,
            [Recommendation(NETWORK, "Check cables, switch port error counters, and Wi-Fi signal", "Loss should be 0% on a LAN.")],
        )
    avg = p.get("avg") or 0
    if avg > 5 and not f.client_gateway:
        yield Finding(
            "network.latency", "warning", "network", f"High LAN latency ({avg:.1f} ms average)",
            "Same-subnet round trips should be well under 1 ms wired. SMB metadata operations (Finder browsing) "
            "are latency-bound, so this directly slows directory listings.",
            ev,
        )
    if p.get("max") and avg and p["max"] > max(10 * avg, 20):
        yield Finding(
            "network.jitter", "info", "network", "Latency spikes observed",
            f"Max RTT {p['max']} ms vs {avg} ms average suggests intermittent congestion or power saving.",
            ev,
        )


@rule
def host_nic_errors(f: Facts):
    ifaces = set(f.host_phys) | {f.host_route.get("dev") or ""}
    for name in sorted(i for i in ifaces if i):
        st = f.link_stats.get(name)
        if not st:
            continue
        rx, tx = st["rx"], st["tx"]
        bad = {k: v for k, v in {
            "rx errors": rx.get("errors", 0), "rx dropped": rx.get("dropped", 0),
            "rx missed": rx.get("missed", 0), "tx errors": tx.get("errors", 0),
            "tx dropped": tx.get("dropped", 0), "tx carrier": tx.get("carrier_errors", 0),
        }.items() if v}
        counters = {k: v for k, v in f.ethtool.get(name, {}).get("counters", {}).items() if v}
        if not bad and not counters:
            continue
        packets = (rx.get("packets", 0) + tx.get("packets", 0)) or 1
        ratio = sum(bad.values()) / packets
        sev = "warning" if ratio > 1e-5 or any("err" in k or "crc" in k.lower() for k in counters) else "info"
        yield Finding(
            f"network.nic_errors.{name}", sev, "network", f"Error/drop counters are non-zero on host {name}",
            "Counters are cumulative since boot. Rising rx errors/CRC counts point at cabling; rx drops/missed point "
            "at the host not keeping up (ring buffer, CPU, or IRQ affinity).",
            [f"{k}: {v}" for k, v in {**bad, **counters}.items()][:12],
            [Recommendation(NETWORK, f"Re-check after a load test: if {name} counters grow, replace the cable/port",
                            "Distinguishes historical noise from an active problem.")],
        )


@rule
def routed_path(f: Facts):
    if f.client_gateway:
        yield Finding(
            "network.routed", "info", "network", "Client reaches the host through a router",
            "Traffic crosses a gateway, so firewall/IDS inspection and router CPU can cap SMB throughput "
            "and add latency. Same-subnet is preferable for file sharing.",
            [f"gateway {f.client_gateway}"],
        )


# --------------------------------------------------------------------------- client


@rule
def no_mount(f: Facts):
    if f.have_client and not f.mount:
        yield Finding(
            "client.no_mount", "info", "client", "No mounted share from this host was found",
            "Mount the share in Finder (Go > Connect to Server) so per-connection details "
            "(dialect, signing, encryption, multichannel) can be checked.",
            [f"smbfs mounts: {', '.join(m.mount_point for m in f.mounts) or 'none'}"],
        )


@rule
def dialect(f: Facts):
    ver = f.attr("SMB_VERSION")
    if ver and not ver.upper().startswith("SMB_3"):
        yield Finding(
            "client.dialect", "warning", "client", f"Connection negotiated {ver}",
            "SMB 3.x is needed for multichannel, better leasing and performance. The host or client is limiting it.",
            [f"SMB_VERSION {ver}", f"server min protocol: {f.smb_global.get('server min protocol', '?')}",
             f"server max protocol: {f.smb_global.get('server max protocol', '?')}"],
            [nsmb("protocol_vers_map", "6", "Allow SMB2 and SMB3 only (bitmask 2|4)."),
             extra("server max protocol", "SMB3", "Make sure the host offers SMB 3.")],
        )
    pvm = f.nsmb.get("protocol_vers_map")
    if pvm and pvm.isdigit() and int(pvm) & 1:
        yield Finding(
            "client.smb1_enabled", "warning", "client", "nsmb.conf allows SMB1",
            "SMB1 is slow and insecure; Samba on Unraid does not need it for macOS.",
            [f"protocol_vers_map={pvm}"],
            [nsmb("protocol_vers_map", "6", "SMB2 + SMB3 only.")],
        )


@rule
def signing(f: Facts):
    client_on = pm.is_true(f.share_attrs, "SIGNING_ON")
    algo = f.attr("SMB_CURR_SIGN_ALGORITHM") or f.attr("SMB_CURR_SIGNING_ALGORITHM")
    if algo and algo.upper() not in {"OFF", "NONE"}:
        client_on = True
    host_degree = next((str((s.get("signing") or {}).get("degree", "")) for s in f.client_sessions), "")
    if host_degree and host_degree.lower() not in {"none", ""}:
        client_on = True
    if not client_on:
        return
    server_signing = (f.smb_global.get("server signing") or "").lower()
    host_requires = server_signing in {"mandatory", "required"}
    recs = []
    if f.nsmb.get("signing_required", "").lower() == "no":
        detail_extra = (" The client already asks for no signing, so the host is insisting on it."
                        if not host_requires else "")
    else:
        detail_extra = ""
        recs.append(nsmb("signing_required", "no",
                         "Lets the Mac skip signing when the server does not demand it.",
                         tradeoff="Signing protects against tampering on untrusted networks; only disable on a trusted LAN."))
    if host_requires:
        recs.append(extra("server signing", "auto", "The host currently requires signing for every session.",
                          tradeoff="Same as above: keep signing if the network is not trusted."))
    yield Finding(
        "client.signing", "warning", "client", "SMB packet signing is active on this connection",
        "Signing hashes every packet and is one of the most common reasons macOS SMB is slow, "
        "especially on 2.5/10 GbE where it can cut throughput substantially." + detail_extra,
        [e for e in [f.attr("SIGNING_ON") and f"SIGNING_ON {f.attr('SIGNING_ON')}",
                     algo and f"signing algorithm {algo}",
                     host_degree and f"host session signing degree: {host_degree}",
                     f.have_host and f"host server signing = {server_signing or 'default'}",
                     f"client signing_required = {f.nsmb.get('signing_required', 'default')}"] if e],
        recs,
    )


@rule
def encryption(f: Facts):
    algo = f.attr("SMB_CURR_ENCRYPT_ALGORITHM")
    host_degree = next((str((s.get("encryption") or {}).get("degree", "")) for s in f.client_sessions), "")
    active = (algo and algo.upper() not in {"OFF", "NONE"}) or (host_degree and host_degree.lower() not in {"none", ""})
    if not active:
        return
    setting = (f.smb_param("server smb encrypt") or f.smb_param("smb encrypt") or "").lower()
    recs = []
    if setting == "required":
        recs.append(extra("server smb encrypt", "if_required", "Encryption is forced for every session.",
                          tradeoff="Keep 'required' if traffic crosses an untrusted network."))
    yield Finding(
        "client.encryption", "info", "client", "SMB encryption is active",
        "Encryption costs CPU on both ends (AES on Unraid's CPU is usually the limit). Fine for security, "
        "but expect lower peak throughput on fast links.",
        [e for e in [algo and f"client cipher {algo}", host_degree and f"host encryption degree {host_degree}",
                     f"server smb encrypt = {setting or 'default'}"] if e],
        recs,
    )


@rule
def reconnects(f: Facts):
    count = f.attr("SESSION_RECONNECT_COUNT")
    if count.isdigit() and int(count) > 0:
        yield Finding(
            "client.reconnects", "warning", "client", f"The session has reconnected {count} time(s) since mount",
            "Each reconnect follows a period where the server stopped answering: this is what a Finder lockup "
            "looks like from the client. See correlation findings for likely host-side causes.",
            [f"SESSION_RECONNECT_COUNT {count}", f"SESSION_RECONNECT_TIME {f.attr('SESSION_RECONNECT_TIME')}"],
        )


@rule
def multichannel_wifi(f: Facts):
    if not pm.is_true(f.share_attrs, "MULTI_CHANNEL_SUPPORTED"):
        return
    if "wi-fi" in f.client_iface_port.lower():
        return
    wifi_active = [d for d, port in f.client_ports.items()
                   if "wi-fi" in port.lower() and f.client_ifaces.get(d, {}).get("status") == "active"
                   and f.client_ifaces.get(d, {}).get("inet")]
    if wifi_active and f.nsmb.get("mc_prefer_wired", "").lower() != "yes":
        yield Finding(
            "client.multichannel_wifi", "warning", "client",
            "Multichannel is available and Wi-Fi is up alongside the wired link",
            "macOS can add the Wi-Fi interface as an extra SMB channel, dragging throughput down to Wi-Fi speeds "
            "and adding stalls when Wi-Fi roams.",
            [f"wired route via {f.client_iface}", f"active Wi-Fi: {', '.join(wifi_active)}"],
            [nsmb("mc_prefer_wired", "yes", "Use wired channels only when one is available.")],
        )
    if f.nsmb.get("mc_on", "").lower() == "no":
        yield Finding(
            "client.multichannel_off", "info", "client", "Multichannel is disabled on the client",
            "With a multi-port or RSS-capable NIC on the host, multichannel can raise throughput.",
            ["mc_on=no in nsmb.conf"],
            [nsmb("mc_on", "yes", "Re-enable multichannel if you have more than one usable path.")],
        )


@rule
def ds_store(f: Facts):
    if f.have_client and not f.ds_store_disabled:
        yield Finding(
            "client.ds_store", "info", "client", "Finder writes .DS_Store files on network shares",
            "Every folder you open triggers extra writes and metadata round trips; on array disks this can also "
            "spin up a sleeping disk just to browse.",
            ["DSDontWriteNetworkStores not set"],
            [Recommendation(CLIENT_SHELL, "defaults write com.apple.desktopservices DSDontWriteNetworkStores -bool true",
                            "Stop Finder writing view metadata to shares (log out/in to apply).",
                            command=["defaults", "write", "com.apple.desktopservices",
                                     "DSDontWriteNetworkStores", "-bool", "true"],
                            tradeoff="Finder view settings for network folders will no longer be remembered.")],
        )


@rule
def nsmb_malformed(f: Facts):
    for path, bad in f.nsmb_problems.items():
        yield Finding(
            "client.nsmb_malformed", "warning", "client", f"{path} contains lines macOS cannot parse",
            "These lines look like pasted shell commands rather than settings, so whatever they were meant to set "
            "is not in effect. Replace the file with plain key=value lines under [default].",
            [f"{path}: {line}" for line in bad[:6]],
            [Recommendation(CLIENT_NSMB, "delete the lines that are not settings",
                            "Leaves only [default] and key=value lines.", section="default", drop_lines=bad)],
        )


@rule
def lockup_episodes(f: Facts):
    eps = f.episodes
    if not eps:
        return
    boot = f.host_boot
    restart = [e for e in eps if boot and boot - timedelta(minutes=15) <= e.start <= boot + timedelta(minutes=2)]
    severe = [e for e in eps if {"dead", "io_failed", "durable_lost"} & e.kinds.keys() and e not in restart]
    worst = max(eps, key=lambda e: (len(e.events), e.seconds))
    ev = [e.describe() + ("  (server was restarting)" if e in restart else "")
          for e in sorted(eps, key=lambda e: e.start)[-8:]]
    setup = f.multichannel.get("setup_time")
    if setup:
        ev.append(f"current session for {f.multichannel.get('mount')} was set up at {setup}")
    yield Finding(
        "logs.episodes", "critical" if severe else "warning", "logs",
        f"{len(eps)} connection trouble episode(s) in the client log"
        + (f"; {len(severe)} ended with failed I/O" if severe else "")
        + (f" ({len(restart)} explained by the server restart)" if restart else ""),
        "Each episode is a burst of stalls, server disconnects and reconnects: what the user sees as a hang. "
        + ("Failed reads/writes mean applications got errors, not just delays. " if severe else "")
        + (f"The worst lasted {worst.seconds:.0f}s with {len(worst.events)} events." if worst.seconds >= 1
           else f"The worst had {len(worst.events)} events."),
        ev,
    )


@rule
def array_state(f: Facts):
    state = f.array.get("mdState", "")
    if state and state != "STARTED":
        yield Finding(
            "host.array_stopped", "critical", "host", f"The Unraid array is {state.lower()}: no shares are exported",
            "Samba only exports user shares while the array is started, so the Mac cannot mount anything. "
            "This is the normal state right after a reboot when auto-start is off.",
            [f"mdState = {state}", f"fsState = {f.array.get('fsState', '?')}",
             f"Samba sections: {', '.join(n for n in f.smbconf if n != 'global') or 'none besides [global]'}"],
            [Recommendation(HOST_UI, "Main > Array Operation > Start", "Start the array to export shares."),
             Recommendation(HOST_UI, "Settings > Disk Settings > Enable auto start: Yes",
                            "Start the array automatically after a reboot.",
                            tradeoff="With an encrypted array the passphrase still has to be entered.")],
        )
    pos = f.array.get("mdResyncPos", "0")
    if pos.isdigit() and int(pos) > 0:
        yield Finding(
            "storage.resync", "warning", "storage",
            f"A parity {f.array.get('mdResyncAction', 'check/sync').lower()} is running",
            "While parity runs every array disk is busy; SMB reads and writes to the array are much slower and "
            "Finder may stall.",
            [f"mdResyncPos = {pos}", f"mdResync = {f.array.get('mdResync', '?')}"],
            [Recommendation(HOST_UI, "Settings > Scheduler: run parity checks outside working hours",
                            "Avoid overlapping parity with heavy SMB use.")],
        )


@rule
def recent_boot(f: Facts):
    if not f.host_boot:
        return
    up_min = float(f.snap.out("host", "uptime").split()[0]) / 60
    if up_min > 24 * 60:
        return
    yield Finding(
        "host.recent_boot", "info", "host", f"The server restarted at {f.host_boot:%Y-%m-%d %H:%M} ({up_min:.0f} min ago)",
        "Client trouble just before this time is from the shutdown, and host counters and logs only cover "
        "the time since boot.",
        [f"host uptime {up_min:.0f} min"],
    )


@rule
def idle_closes(f: Facts):
    if not f.idle_closes:
        return
    tm = sorted(e.when for e in f.client_events if e.kind == "timemachine" and e.when)
    after_tm = [ep for ep in f.idle_closes if any(0 <= (ep.start - t).total_seconds() <= 1800 for t in tm)]
    yield Finding(
        "logs.idle_closes", "info", "logs",
        f"The server closed {len(f.idle_closes)} idle session(s)",
        "Each was a single server-side close with no stall, failed I/O or reconnect storm around it: Samba "
        "dropping a session nothing was using. macOS reconnects on next use, so this is normally harmless."
        + (f" {len(after_tm)} came within 30 minutes of a Time Machine backup, which leaves its session idle "
           "when it finishes." if after_tm else ""),
        [f"{ep.start:%Y-%m-%d %H:%M:%S} session {', '.join(ep.sessions) or '?'}" for ep in f.idle_closes[-6:]],
    )


@rule
def reconnect_loop(f: Facts):
    for loop in f.loops:
        orphan = loop.session not in f.all_channel_ids
        minutes = (loop.last - loop.first).total_seconds() / 60
        yield Finding(
            f"client.reconnect_loop.{loop.session}", "warning", "client",
            f"SMB session {loop.session} has been retrying for {minutes:.0f} minutes",
            f"The kernel logged {loop.attempts} reconnect attempts between {loop.first:%H:%M} and {loop.last:%H:%M}. "
            + ("No currently mounted share uses this session, so it is a leftover from an earlier mount "
               "(often a Time Machine or Finder mount that went away while in use). "
               if orphan else "It belongs to a current mount that never recovered. ")
            + "It burns a little CPU and spams the log, and the server may see repeated connection attempts.",
            [f"session {loop.session}: {loop.attempts} retries", f"current channel ids: "
             f"{', '.join(sorted(f.all_channel_ids)) or 'none'}"],
            [Recommendation(CLIENT_SHELL, "mount -t smbfs; smbutil statshares -a",
                            "Find the stale volume; then `diskutil unmount force /Volumes/<name>`.", check=True),
             Recommendation(CLIENT_SHELL, "If nothing stale is listed, restart the Mac",
                            "Orphaned kernel sessions are only cleared by a reboot.")],
        )


@rule
def time_machine(f: Facts):
    tm = [e for e in f.client_events if e.kind == "timemachine"]
    durable = [e for e in f.client_events if e.kind == "durable"]
    if not durable:
        return
    tm_share = next((name for name, sec in f.smbconf.items()
                     if (sec.get("fruit:time machine") or "").lower() == "yes"), "")
    params = {k: v for k, v in DURABLE_PREREQS.items()}
    if f.smbconf:
        sec = f.smbconf.get(tm_share, {}) if tm_share else {}
        eff = lambda k: (sec.get(k) or f.smb_global.get(k) or "").lower()  # noqa: E731
        params = {k: v for k, v in params.items() if eff(k) != v}
    recs = [Recommendation(HOST_UI, "Shares > <time machine share> > SMB Security Settings > Export: Yes (Time Machine)",
                           "Unraid then adds the fruit Time Machine options for that share.")] if not tm_share else []
    if params:
        recs += durable_fixes(f, params, "Durable handles need these; set server-wide so every share gets them.")
    last = max(e.when for e in durable if e.when) if any(e.when for e in durable) else None
    if f.smbconf and tm_share and not params and (f.host_boot is None or (last and last < f.host_boot)):
        # The config is right now; the refusals in the log are from before it was applied.
        yield Finding(
            "client.time_machine_durable", "info", "client",
            "Time Machine share now allows durable handles",
            f"[{tm_share}] meets every prerequisite. The {len(durable)} refusal(s) in the log predate the "
            + (f"server restart at {f.host_boot:%H:%M}" if f.host_boot else "change")
            + "; the next backup should no longer log 'Durable Handle V2 ... not supported'.",
            [f"last refusal {last:%Y-%m-%d %H:%M}" if last else "refusals logged earlier",
             *[f"[{tm_share}] {k} ok" for k in ("durable handles", "kernel oplocks", "kernel share modes",
                                                 "posix locking")]],
        )
        return
    yield Finding(
        "client.time_machine_durable", "warning", "client",
        "Time Machine backs up over SMB without durable handles",
        "macOS asks for durable (v2) handles so a backup survives a brief network drop; the server refused. "
        "Any disconnect during a backup then fails it, and repeated failures can force Time Machine to "
        "start a new backup or report the sparsebundle as damaged.",
        [f"{len(durable)} durable-handle refusals, {len(tm)} Time Machine I/O lines"]
        + logs.samples(f.client_events, "durable", 2)
        + ([f"Time Machine share on host: [{tm_share}]"] if tm_share else []),
        recs,
    )


@rule
def access_denied(f: Facts):
    n = sum(1 for e in f.client_events if e.kind == "access")
    if n >= 20:
        yield Finding(
            "client.access_denied", "info", "client", f"{n} permission-denied (EACCES) replies from the server",
            "Finder and Spotlight probe many paths and some denials are normal. If applications fail to open or "
            "save files, compare share ownership with the SMB user (Unraid: Tools > New Permissions, carefully).",
            logs.samples(f.client_events, "access", 2),
        )


@rule
def periodic(f: Facts):
    """Disconnects that recur at the same minute past the hour point at a scheduled job."""
    marks = []
    for ep in f.episodes:
        if "disconnect" in ep.kinds:
            marks.append(ep.start)
    if len(marks) < 2:
        return
    def dist(t, m):
        d = abs(t.minute - m)
        return min(d, 60 - d)

    def score(m):
        hits = [t for t in marks if dist(t, m) <= 1]
        return len({(t.date(), t.hour) for t in hits}), -sum(dist(t, m) for t in hits), hits

    minute = max(range(60), key=lambda m: score(m)[:2])
    hours, _, hits = score(minute)
    if hours < 2:
        return
    tm_starts = sorted({e.when.replace(second=0, microsecond=0) for e in f.client_events
                        if e.kind == "timemachine" and e.when})
    after_tm = [t for t in hits if any(0 <= (t - s).total_seconds() <= 900 for s in tm_starts)]
    yield Finding(
        "logs.periodic", "warning", "logs", f"Server disconnects repeat around :{minute:02d} past the hour",
        "Problems that land at the same minute each hour usually come from a scheduled job on the host or client. "
        + ("They follow Time Machine backups by a few minutes, so the backup (or the host's work after it) is the "
           "prime suspect. " if after_tm else "")
        + "On Unraid check the mover schedule, parity/scrub schedules, User Scripts and container cron jobs.",
        [f"disconnect at {t:%Y-%m-%d %H:%M:%S}" for t in hits[-6:]],
    )


@rule
def mc_server_speed(f: Facts):
    mc = f.multichannel
    if not mc or not mc.get("multichannel_on"):
        return
    client = max((n.get("speed_mbps") or 0 for n in mc["client_nics"] if n.get("state") == "connected"), default=0)
    server = max((n.get("speed_mbps") or 0 for n in mc["server_nics"] if n.get("state") == "connected"), default=0)
    host_actual = max((f.ethtool.get(n, {}).get("speed") or f.host_ifaces.get(n, {}).get("speed") or 0
                       for n in f.host_phys), default=0)
    if not client or not server or server >= client:
        return
    if not f.have_host:
        detail = ("Samba reports 1 Gb/s when it cannot read the speed of its interface (common on Unraid's br0 "
                  "bridge), or the host link really is that speed. Run with host access to tell which.")
        recs = []
    elif host_actual and host_actual <= server:
        detail = (f"The host NIC really is {host_actual} Mb/s, so the {client} Mb/s client link cannot be used fully; "
                  "that link is the throughput ceiling.")
        recs = []
    else:
        detail = ("Samba reports this when it cannot read the speed of its interface (common on Unraid's br0 "
                  "bridge). macOS uses the advertised speed to decide how to spread multichannel traffic."
                  + (f" The host's physical NIC is {host_actual} Mb/s." if host_actual else ""))
        line = interfaces_with_speed(f.smb_global.get("interfaces", ""), f.snap.meta.get("host_ip", ""),
                                     (host_actual or client) * 1_000_000)
        recs = [extra("interfaces", line,
                      "Advertise the real link speed to SMB3 clients; every other entry is kept as Unraid set it.",
                      tradeoff="This pins a copy of Unraid's generated interface list. If the server's addresses "
                               "change, update or delete this line.")] if line else []
        if not line:
            detail += " Could not find the host address in Samba's 'interfaces' list, so no change is proposed."
    yield Finding(
        "performance.mc_server_speed", "info", "performance",
        f"Server advertises {server} Mb/s to a {client} Mb/s client", detail,
        [f"client NIC {client} Mb/s", f"server NIC (advertised) {server} Mb/s"]
        + ([f"host physical NIC {host_actual} Mb/s"] if host_actual else []),
        recs,
    )


def interfaces_with_speed(current: str, host_ip: str, speed_bps: int) -> str | None:
    """Return Samba's existing interfaces list with a speed option added to the host_ip entry."""
    try:
        entries = shlex.split(current)
    except ValueError:
        return None
    if not host_ip or not entries:
        return None
    out, found = [], False
    for entry in entries:
        addr, _, opts = entry.partition(";")
        if addr.split("/")[0] == host_ip:
            found = True
            options = [o for o in opts.split(",") if o and not o.startswith("speed=")]
            entry = f"{addr};" + ",".join(options + [f"speed={speed_bps}"])
        out.append(f'"{entry}"' if ";" in entry else entry)
    return " ".join(out) if found else None


# --------------------------------------------------------------------------- host


@rule
def fruit(f: Facts):
    if not f.have_host or not f.smbconf:
        return
    vfs = ps.vfs_objects(f.share_conf) if "vfs objects" in f.share_conf else ps.vfs_objects(f.smb_global)
    where = f"[{f.share_name}]" if "vfs objects" in f.share_conf else "[global]"
    if "fruit" not in vfs:
        yield Finding(
            "host.fruit_missing", "warning", "host", "vfs_fruit (Apple SMB extensions) is not enabled",
            "Without fruit, macOS falls back to slower generic SMB: no AAPL create context, extra round trips for "
            "resource forks and Finder info, and slow directory enumeration.",
            [f"{where} vfs objects = {' '.join(vfs) or '(none)'}",
             f"Unraid enable_fruit = {f.ident.get('enable_fruit', '?')}"],
            [Recommendation(HOST_UI, "Settings > SMB > SMB Settings > Enhanced macOS interoperability: Yes",
                            "Unraid then adds catia, fruit and streams_xattr to every share."),
             extra("fruit:metadata", "stream", "Store Finder metadata in a stream instead of AppleDouble files."),
             extra("fruit:posix_rename", "yes", "Lets macOS rename open files the way it expects."),
             extra("fruit:nfs_aces", "no", "Stops macOS chmod from rewriting Unix permissions."),
             extra("fruit:wipe_intentionally_left_blank_rfork", "yes", "Drops empty resource forks."),
             extra("fruit:delete_empty_adfiles", "yes", "Cleans up empty ._ AppleDouble files.")],
        )
        return
    if "streams_xattr" in vfs and vfs.index("fruit") > vfs.index("streams_xattr"):
        yield Finding(
            "host.fruit_order", "warning", "host", "vfs_fruit is listed after streams_xattr",
            "fruit must come before streams_xattr or Apple metadata handling breaks.",
            [f"{where} vfs objects = {' '.join(vfs)}"],
            [extra("vfs objects", "catia fruit streams_xattr", "Correct module order.",
                   section=f.share_name if where != "[global]" else "global")],
        )
    if (f.smb_param("readdir_attr:aapl_max_access") or "yes").lower() not in {"no", "false"}:
        yield Finding(
            "host.aapl_max_access", "info", "performance", "Finder directory listings compute max access per file",
            "With fruit, Samba calculates each entry's effective permissions during enumeration. Turning this off "
            "makes large folders open noticeably faster.",
            ["readdir_attr:aapl_max_access is default (yes)"],
            [extra("readdir_attr:aapl_max_access", "no", "Skip per-file access calculation in listings.",
                   tradeoff="Finder may show a lock badge less accurately on files you cannot write.")],
        )


@rule
def protocol_floor(f: Facts):
    floor = (f.smb_global.get("server min protocol") or "").upper()
    if floor in {"NT1", "LANMAN1", "LANMAN2", "CORE", "COREPLUS"}:
        yield Finding(
            "host.smb1", "warning", "host", f"Host still accepts {floor} (SMB1)",
            "Not needed for macOS and a security risk.",
            [f"server min protocol = {floor}"],
            [extra("server min protocol", "SMB2_10", "Refuse SMB1.")],
        )


@rule
def socket_options(f: Facts):
    so = f.smb_global.get("socket options", "")
    if any(k in so.upper() for k in ("SO_RCVBUF", "SO_SNDBUF")):
        yield Finding(
            "host.socket_options", "warning", "host", "Samba socket buffers are pinned by 'socket options'",
            "Fixed SO_RCVBUF/SO_SNDBUF disables Linux TCP autotuning and usually lowers throughput on fast links. "
            "Samba's own testparm warns about this setting.",
            [f"socket options = {so}"]
            + (["set in smb-extra.conf"] if in_extra(f, "socket options") is not None else []),
            [restore(f, "socket options", "TCP_NODELAY", "Let the kernel size TCP buffers.")],
        )


@rule
def oplocks_leases(f: Facts):
    checks = [("oplocks", "no", "yes"), ("level2 oplocks", "no", "yes"),
              ("smb2 leases", "no", "yes"), ("kernel oplocks", "yes", "no")]
    issues = [(k, good) for k, bad, good in checks if (f.smb_param(k) or good).lower() == bad]
    if issues:
        names = {k for k, _ in issues}
        yield Finding(
            "host.oplocks", "warning", "host", "Client-side caching is restricted on the host",
            "Disabling oplocks forces the Mac to go to the server for every read and stat, which makes browsing "
            "and app saves slow."
            + (" With 'oplocks = no' Samba also grants no SMB2 leases, even though 'smb2 leases' is on."
               if "oplocks" in names and "smb2 leases" not in names else ""),
            [f"{k} = {f.smb_param(k)}" + (" (set in smb-extra.conf)" if in_extra(f, k) is not None else "")
             for k, _ in issues],
            [restore(f, k, good, "Allow the client to cache safely.") for k, good in issues],
        )


DURABLE_PREREQS = {"durable handles": "yes", "kernel oplocks": "no", "kernel share modes": "no", "posix locking": "no"}
POSIX_TRADEOFF = ("SMB byte-range locks are no longer mirrored to programs running on the server itself "
                  "(Docker containers, scripts) or to NFS clients, and vice versa.")


def durable_fixes(f: Facts, unmet: dict[str, str], why: str) -> list[Recommendation]:
    """Server-wide settings for the unmet durable-handle prerequisites, plus cleanup of per-share copies."""
    recs = [extra(key, DURABLE_PREREQS[key], why, tradeoff=POSIX_TRADEOFF if key == "posix locking" else "")
            for key in DURABLE_PREREQS if key in unmet]
    # Per-share sections in smb-extra.conf are parsed before Unraid defines the shares
    # ("No path in service ... making it unavailable"); once [global] covers it they are redundant.
    for section, values in f.smb_extra.items():
        if section.lower() != "global":
            for key in DURABLE_PREREQS:
                if key in values:
                    recs.append(drop(key, "Covered by the [global] setting.", section=section))
    return recs


@rule
def durable_unavailable(f: Facts):
    lost_client = [e for e in f.client_events if e.kind == "durable_lost"]
    lost_host = [e for e in f.host_events if e.kind == "durable_lost"]
    if not lost_client and not lost_host:
        return
    unmet = {k: f.smb_param(k) for k, v in DURABLE_PREREQS.items() if (f.smb_param(k) or "").lower() != v}
    files = sorted({m.group(1) for e in lost_client
                    if (m := re.search(r"(?:handle for|on <)\s*<?([^<>]+?)>?\s*$", e.message))})
    yield Finding(
        "host.durable_unavailable", "critical" if unmet else "warning", "host",
        f"Open files are lost when the connection drops ({len(lost_client) or len(lost_host)} time(s))",
        "After a reconnect the Mac asks the server to hand back the files it had open (a durable handle). "
        "The server refused, so the copy or save in progress fails with an error instead of carrying on. "
        + (f"Samba only grants durable handles when {', '.join(f'{k} = {v}' for k, v in DURABLE_PREREQS.items())}; "
           f"[{f.share_name or 'global'}] has {', '.join(f'{k} = {v}' for k, v in unmet.items())}."
           if unmet else "The durable-handle settings look right, so the handle may have expired first."),
        [f"file: {name}" for name in files[:4]] + logs.samples(f.client_events, "durable_lost", 2)
        + logs.samples(f.host_events, "durable_lost", 2),
        durable_fixes(f, unmet, "Lets Samba grant durable handles so open files survive a reconnect.") if unmet else [],
    )


@rule
def synchronous_io(f: Facts):
    if not f.smb_global:
        return
    aio_off = [k for k in ("aio read size", "aio write size") if (f.smb_global.get(k) or "1").strip() == "0"]
    sendfile = (f.smb_global.get("use sendfile") or "no").lower() == "yes"
    if not aio_off:
        return
    stalls = [e for e in f.client_events if e.kind == "timeout" and "TRAN_SEND" in e.message]
    sendfile_fail = [e for e in f.host_events if e.kind == "sendfile"]
    seen = bool(stalls or sendfile_fail)
    recs = [extra(k, "1", "Do disk I/O in background threads so one slow read or write does not block the "
                          "whole connection.",
                  tradeoff="Overrides Unraid's shipped default (its smb.conf turns async I/O off); delete these "
                           "lines from SMB Extras to go back.")
            for k in aio_off]
    if sendfile:
        recs.append(extra("use sendfile", "no", "sendfile runs inside the connection's main process and blocks "
                                               "it for the whole read.",
                          tradeoff="Slightly more CPU per read; overrides Unraid's shipped default."))
    yield Finding(
        "host.synchronous_io", "critical" if seen else "warning", "host",
        "Samba handles each connection's disk I/O one request at a time",
        "Unraid ships with async I/O off" + (" and sendfile on" if sendfile else "") + ". A Mac uses one SMB "
        "connection for everything it does with a share, so a slow write to the parity array (or a read from a "
        "disk that is spinning up) freezes every other transfer on that connection. When the freeze lasts a few "
        "seconds the Mac cannot send (error 35), drops the connection and reconnects, and copies in progress fail."
        + (f" This happened {len(stalls) or len(sendfile_fail)} time(s) in the collected logs." if seen else ""),
        [f"{k} = 0" for k in aio_off] + (["use sendfile = Yes"] if sendfile else [])
        + logs.samples(f.client_events, "timeout", 2) + logs.samples(f.host_events, "sendfile", 1),
        recs,
    )


# vfs_fruit options documented in the Samba manual page.
KNOWN_FRUIT = {
    "aapl", "nfs_aces", "copyfile", "model", "posix_rename", "veto_appledouble", "zero_file_id",
    "time machine", "time machine max size", "metadata", "resource", "locking", "encoding",
    "wipe_intentionally_left_blank_rfork", "delete_empty_adfiles", "convert_adouble",
}


@rule
def legacy_tweaks(f: Facts):
    """Settings in smb-extra.conf that come from old tuning guides and hurt current macOS/Samba."""
    if not f.smb_extra:
        return
    ev, recs = [], []
    if (in_extra(f, "ea support") or "").lower() == "no":
        ev.append("ea support = no")
        recs.append(drop("ea support", "The fruit + streams_xattr setup that Unraid uses for Macs keeps Finder "
                                       "info and resource forks in extended attributes; Samba's default is yes."))
    meta = in_extra(f, "fruit:metadata")
    share_meta = f.share_conf.get("fruit:metadata")
    if meta and share_meta and meta.lower() != share_meta.lower():
        ev.append(f"global fruit:metadata = {meta}, but [{f.share_name}] uses {share_meta}")
        recs.append(drop("fruit:metadata", "Unraid sets this per share; a different global value only makes "
                                           "shares disagree about where Mac metadata is stored."))
    for key in in_extra_keys(f):
        if key.startswith("fruit:") and key[len("fruit:"):] not in KNOWN_FRUIT:
            ev.append(f"{key} = {in_extra(f, key)} (not a documented vfs_fruit option)")
            recs.append(drop(key, "Samba ignores unknown fruit options silently; this one does nothing."))
    if ev:
        yield Finding(
            "host.legacy_tweaks", "warning", "host", "smb-extra.conf contains outdated or conflicting tweaks",
            "These lines are common in old Samba-for-Mac tuning posts. On current Samba they either undo "
            "defaults that macOS relies on or have no effect.",
            ev, recs,
        )


def in_extra_keys(f: Facts) -> list[str]:
    return list(next((v for k, v in f.smb_extra.items() if k.lower() == "global"), {}))


@rule
def strict_sync(f: Facts):
    if (f.smb_param("strict sync") or "").lower() == "yes" and f.have_host:
        yield Finding(
            "host.strict_sync", "info", "performance", "Samba honours every client flush ('strict sync = yes')",
            "macOS apps and Finder flush often. With strict sync each flush waits for the disk, which is slow on "
            "the parity-protected array.",
            ["strict sync = yes"],
            [extra("strict sync", "no", "Let Samba acknowledge flushes without forcing a disk sync.",
                   section=f.share_name if "strict sync" in f.share_conf else "global",
                   tradeoff="On power loss, recently written data may be lost. Only with a UPS.")],
        )


@rule
def multichannel_host(f: Facts):
    if not f.samba_version:
        return
    speeds = [f.ethtool.get(n, {}).get("speed") or f.host_ifaces.get(n, {}).get("speed") or 0 for n in f.host_phys]
    mc = (f.smb_global.get("server multi channel support") or "").lower()
    if f.samba_version >= (4, 15) and mc == "no" and (len(f.host_phys) > 1 or max(speeds, default=0) >= 10000):
        yield Finding(
            "host.multichannel", "info", "performance", "Host has multichannel off but could benefit",
            "With several NICs, or a 10 GbE NIC that supports RSS, macOS can open several channels and spread load.",
            [f"server multi channel support = {mc}", f"host NICs on path: {', '.join(f.host_phys)}"],
            [extra("server multi channel support", "yes", "Allow SMB3 multichannel.",
                   tradeoff="Multichannel on Samba is newer code; watch for disconnects after enabling.")],
        )


@rule
def fuse_user_share(f: Facts):
    if not f.share_name or not f.share_conf:
        return
    path = f.share_conf.get("path", "")
    if not path.startswith("/mnt/user/"):
        return
    info = f.user_shares.get(f.share_name, {})
    if info.get("exclusive"):
        return
    use_cache = f.share_cfg.get("shareUseCache", "")
    pool_only = use_cache == "only"
    yield Finding(
        "storage.fuse", "warning" if pool_only else "info", "storage",
        f"Share '{f.share_name}' is served through Unraid's FUSE layer (shfs)",
        "/mnt/user goes through shfs, which adds CPU work and latency to every file operation. "
        + ("This share lives only on a pool, so it can be an exclusive share that bypasses FUSE entirely."
           if pool_only else
           "Shares that live on a single pool can be made exclusive to bypass FUSE."),
        [f"path = {path}", f"shareUseCache = {use_cache or '?'}", "not an exclusive share"],
        [Recommendation(HOST_UI, "Settings > Global Share Settings > Permit exclusive shares: Yes",
                        "Required before any share can bypass FUSE."),
         Recommendation(HOST_UI, f"Shares > {f.share_name}: Primary storage = a pool, Secondary storage = None",
                        "An exclusive share is a direct path to the pool filesystem.",
                        tradeoff="Data no longer moves to the array via mover; size the pool accordingly.")],
    )


@rule
def spindown(f: Facts):
    use_cache = f.share_cfg.get("shareUseCache", "")
    delay = f.disk_cfg.get("spindownDelay", "")
    if not f.share_cfg or use_cache == "only" or delay in {"", "0"}:
        return
    if f.array.get("mdState", "STARTED") != "STARTED":
        return
    spinups = [e for e in f.host_events if e.kind == "spinup"]
    yield Finding(
        "storage.spindown", "info", "storage", "Share data can sit on array disks that spin down",
        "Opening a folder whose files are on a sleeping disk blocks until it spins up (often 5-15 s, longer with "
        "several disks). macOS shows this as a Finder beachball or a frozen save dialog.",
        [f"shareUseCache = {use_cache or 'no'}", f"spindownDelay = {delay}",
         f"spin-up events in collected syslog: {len(spinups)}"],
        [Recommendation(HOST_UI, f"Shares > {f.share_name}: keep frequently browsed data on a pool",
                        "Pools (SSD) do not spin down."),
         Recommendation(HOST_UI, "Settings > Disk Settings > Default spin down delay: increase it",
                        "Fewer spin-ups during working hours.", tradeoff="More power use and disk wear.")],
    )


@rule
def host_resources(f: Facts):
    cpus = f.load.get("cpus") or 1
    load1 = (f.load.get("load") or [0])[0]
    if load1 / cpus > 1.5:
        yield Finding(
            "host.load", "warning", "host", f"Host CPU is overloaded (load {load1} on {cpus} CPUs)",
            "SMB latency rises with run-queue length; check for parity checks, VMs, or containers competing.",
            [f"loadavg {f.load.get('load')}"],
        )
    wa = f.vmstat.get("wa")
    if wa is not None and wa >= 20:
        yield Finding(
            "host.iowait", "warning", "storage", f"Host is waiting on disk I/O ({wa:.0f}% iowait)",
            "Storage, not the network, is the bottleneck while this persists (parity check, mover, or a slow disk).",
            [f"vmstat iowait avg {wa:.1f}%"],
        )
    total, avail = f.load.get("mem_total_mb"), f.load.get("mem_available_mb")
    if total and avail is not None and avail / total < 0.1:
        yield Finding(
            "host.memory", "warning", "host", "Host memory is nearly exhausted",
            "Low memory shrinks the page cache Samba relies on and risks the OOM killer.",
            [f"available {avail} MB of {total} MB"],
        )
    log_fs = f.df.get("/var/log")
    if log_fs and log_fs["used_pct"] >= 80:
        yield Finding(
            "host.log_full", "warning", "host", f"/var/log is {log_fs['used_pct']}% full",
            "On Unraid /var/log is a small RAM disk; once full, logging stops and some services misbehave.",
            [f"/var/log {log_fs['used_pct']}% used"],
            [Recommendation(HOST_SHELL, "du -sh /var/log/* | sort -h | tail", "Find what is filling the log.",
                                           check=True)],
        )


@rule
def host_logs(f: Facts):
    c = logs.counts(f.host_events)
    serious = {k: v for k, v in c.items() if k in {"nic", "io_error", "oom", "crash"}}
    if serious:
        ev = [f"{k}: {v}" for k, v in sorted(serious.items())]
        for kind in serious:
            ev += logs.samples(f.host_events, kind, 2)
        yield Finding(
            "logs.host_critical", "critical", "logs", "Host log shows hardware or crash events",
            "NIC resets, disk I/O errors, OOM kills or smbd crashes will drop or freeze SMB sessions.",
            ev,
        )
    samba = {k: v for k, v in c.items() if k in {"disconnect", "timeout", "resource", "oplock"}}
    if samba:
        ev = [f"{k}: {v}" for k, v in sorted(samba.items())]
        for kind in samba:
            ev += logs.samples(f.host_events, kind, 2)
        yield Finding(
            "logs.host_samba", "warning" if samba.keys() - {"oplock"} else "info", "logs",
            "Samba log shows disconnects, timeouts or resource errors",
            "Default Unraid log level is low, so even a few of these are meaningful. Use `smbfixer monitor "
            "--samba-debug 2` to capture more while reproducing.",
            ev,
        )


@rule
def clock(f: Facts):
    if f.clock_skew is not None and abs(f.clock_skew) > 5:
        yield Finding(
            "host.clock_skew", "warning", "host", f"Client and host clocks differ by {f.clock_skew:+.0f} s",
            "Skew breaks Kerberos and makes log correlation unreliable (corrected for in this report).",
            [f"host - client = {f.clock_skew:+.0f} s"],
            [Recommendation(HOST_UI, "Settings > Date and Time: enable NTP", "Keep clocks in sync."),],
        )


# --------------------------------------------------------------------------- correlation & measurements


@rule
def correlation(f: Facts):
    if not f.correlations:
        return
    by_kind: dict[str, int] = {}
    for c in f.correlations:
        for he in c.host_events:
            by_kind[he.kind] = by_kind.get(he.kind, 0) + 1
    # Prefer root causes over symptoms: a Samba disconnect is usually the *result* of a spin-up or NIC reset.
    rank = ["crash", "oom", "io_error", "nic", "spinup", "shfs", "resource", "oplock", "timeout", "disconnect"]
    top = min(by_kind, key=lambda k: rank.index(k) if k in rank else len(rank))
    explain = {
        "spinup": "Client hangs line up with array disks spinning up.",
        "nic": "Client hangs line up with host NIC link drops/resets.",
        "io_error": "Client hangs line up with disk I/O errors on the host.",
        "oom": "Client hangs line up with the host running out of memory.",
        "crash": "Client hangs line up with a crash on the host.",
        "oplock": "Client hangs line up with oplock/lease breaks (another client or process holding the file).",
    }.get(top, "Client hangs line up with host-side Samba errors.")
    ev = []
    for c in f.correlations[:5]:
        ev.append(f"client {c.episode.describe()}" if c.episode else
                  f"client {c.client_event.when:%H:%M:%S} {c.client_event.kind}: {c.client_event.message[:120]}")
        for he in c.host_events[:2]:
            ev.append(f"  host {he.when:%H:%M:%S} {he.kind}: {he.source}: {he.message[:120]}")
    yield Finding(
        "correlation.lockups", "critical", "correlation",
        f"{len(f.correlations)} client trouble episode(s) coincide with host events (most often: {top})",
        explain + " Host times are shifted onto the client clock.",
        ev,
    )


@rule
def stalls(f: Facts):
    if not f.stalls:
        return
    worst = max(s.get("ms", 0) for s in f.stalls)
    yield Finding(
        "performance.stalls", "critical" if worst >= 10000 else "warning", "performance",
        f"Monitor saw {len(f.stalls)} stall(s), worst {worst / 1000:.1f} s",
        "A metadata probe on the mount took longer than the stall threshold.",
        [f"{s.get('at')}: {s.get('op')} {s.get('ms', 0):.0f} ms" for s in f.stalls[:10]],
    )


@rule
def bench_bottleneck(f: Facts):
    b = f.bench
    if not b:
        return
    write, read, net = b.get("write_mbps"), b.get("read_mbps"), b.get("iperf_mbps")
    link = pm.media_speed_mbps(f.client_iface_info.get("media", "")) if f.client_iface_info else None
    ev = [f"{k}: {v}" for k, v in b.items() if isinstance(v, (int, float))]
    if net and (write or read):
        smb = max(write or 0, read or 0) * 8  # MB/s -> Mb/s
        if smb < 0.5 * net:
            yield Finding(
                "performance.smb_below_network", "warning", "performance",
                "SMB throughput is well below raw network throughput",
                "The network is not the limit; look at signing/encryption, FUSE (shfs), array write speed, or CPU.",
                ev,
            )
    elif link and (write or read):
        smb = max(write or 0, read or 0) * 8
        if smb < 0.4 * link:
            yield Finding(
                "performance.smb_below_link", "info", "performance",
                f"SMB throughput uses under 40% of the {link} Mb/s link",
                "Install iperf3 on both ends and re-run `smbfixer bench --iperf` to tell network from storage limits.",
                ev,
            )
    if b.get("small_file_ops_per_s") is not None and b["small_file_ops_per_s"] < 50:
        yield Finding(
            "performance.metadata", "warning", "performance", "Small-file operations are slow",
            f"{b['small_file_ops_per_s']:.0f} create/stat/delete ops per second. Finder browsing and git/npm style "
            "workloads are dominated by this; fruit, exclusive shares and low latency help most.",
            ev,
        )
