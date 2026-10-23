# SMB Fixer

Diagnose and tune SMB file sharing between a **macOS client** and a **Samba host**, starting with
**Unraid 7.x**. SMB Fixer looks at both ends of the connection at once — client and server logs,
negotiated connection parameters, network path, host storage layout — and explains *why* a share
is slow or locks up, then proposes concrete configuration changes for each side.

It is read-only by default: it never changes the Mac or the server. Every recommendation is printed
with the reason for it and, where relevant, the tradeoff (for example, turning off packet signing).

## What it checks

| Area | Examples |
| --- | --- |
| Connection | negotiated dialect, packet signing, encryption, multichannel channels, session reconnects |
| Client config | `/etc/nsmb.conf` (including files that are malformed), `.DS_Store` writing, Wi‑Fi joining multichannel |
| Network | route/interface, link speed and duplex, MTU and end-to-end jumbo frames, loss/latency/jitter, NIC error counters |
| Samba config | `vfs_fruit` presence and order, socket buffer overrides, oplocks/leases, strict sync, SMB1, durable handles for Time Machine, multichannel |
| Unraid storage | user shares behind the FUSE layer (`shfs`) vs exclusive shares, array spin-down, iowait, memory, `/var/log` usage |
| Logs | groups macOS `smbfs` kernel messages into *trouble episodes* (stalls, server disconnects, reconnects, failed I/O), detects stuck reconnect loops and hourly patterns, and correlates episodes with host events (disk spin-ups, NIC resets, I/O errors, Samba errors) on a shared clock |
| Live | `monitor` probes the mount for stalls while streaming both logs, then shows what happened around each stall |
| Throughput | `bench` measures sequential and small-file performance on the mount, optionally against raw network (iperf3) and host disk speed |

## Install

Requires Python 3.11+ on the Mac. No third-party packages.

```bash
git clone https://github.com/focher/smb-fixer.git
cd smb-fixer
python3 -m pip install --user .
```

Or run it in place with `python3 -m smbfixer ...`.

## Set up SSH to Unraid

Host-side checks run over SSH with key authentication (no passwords are stored or prompted for).

1. On the Mac: `ssh-keygen -t ed25519` (accept the defaults), then `cat ~/.ssh/id_ed25519.pub`.
2. In the Unraid web UI: **Users > root > SSH authorized keys**, paste the key, **Apply**.
3. Test: `ssh root@tower.local true`

## Configure

```bash
smbfixer init        # writes ./smbfixer.toml
```

Edit `host.address` and `client.mount_point` (the share as mounted in Finder, e.g. `/Volumes/media`).
Any setting can also be given on the command line: `--host`, `--user`, `--mount`.

## Use

```bash
smbfixer check                 # collect from both ends, analyse, recommend
smbfixer check --no-host       # client-side only (no SSH needed)
smbfixer check -f md > report.md
smbfixer monitor               # watch live; reproduce the problem, then Ctrl-C
smbfixer monitor --samba-debug 2   # temporarily raise smbd logging (restored on exit)
smbfixer bench --iperf --host-disk # separate network, protocol and storage limits
smbfixer collect -o snap.json  # save raw data; analyse later with: smbfixer analyze snap.json
```

`check` saves the raw snapshot and a Markdown report under `./reports/`. These can contain host
names, user names and file names from your logs, so they are not meant to be committed.

Exit status is `2` when a critical finding (or, for `monitor`, a stall) was seen, otherwise `0`.

### Writes performed

- `bench` writes a temporary file and a temporary folder of small files on the mount and deletes them.
- `bench --host-disk` writes a temporary file inside the share's path on the host and deletes it.
- `monitor --samba-debug N` changes the running smbd debug level and restores it on exit.

Nothing else writes to either machine.

## Applying recommendations

The report ends with merged snippets:

- **`/etc/nsmb.conf` (client)** — replace the file's contents with the snippet
  (`sudo nano /etc/nsmb.conf`), then unmount and remount the share.
- **`/boot/config/smb-extra.conf` (host)** — the same file as Unraid's *Settings > SMB > SMB Extras*.
  Paste the snippet there and click Apply, or edit the file and run `smbcontrol smbd reload-config`.
- **Unraid web UI** steps are listed by menu path.

Change one thing at a time and re-run `smbfixer check` (or `bench`) to confirm the effect.

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install pytest
.venv/bin/python -m pytest
```

Parsers live in `smbfixer/parse/`, collectors in `smbfixer/collect/`, and diagnostic rules in
`smbfixer/analysis/rules.py`. Each rule is a small function that takes the parsed facts and yields
findings; tests feed recorded command output through the whole pipeline.
