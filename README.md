# SMB Fixer

Diagnose and tune SMB file sharing between a **macOS client** and a **Samba host**, starting with
**Unraid 7.x**. SMB Fixer looks at both ends of the connection at once — client and server logs,
negotiated connection parameters, network path, host storage layout — and explains *why* a share
is slow or locks up, then proposes concrete configuration changes for each side.

`check` is read-only: it never changes the Mac or the server. Every recommendation says **which
machine** it is for, why, and — where relevant — the tradeoff (for example, turning off packet
signing). `apply` then makes the changes the app can safely make itself, and lists the rest by machine.

> **Where to run it:** everything below is typed in **Terminal on the Mac** (prompt ending in `%`),
> not in the Unraid web terminal. The app reaches the server over SSH on its own.

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

## Install (on the Mac)

Requires Python 3.11+. No third-party packages.

```bash
git clone https://github.com/focher/smb-fixer.git
cd smb-fixer
python3 -m pip install --user .
```

Or run it in place with `python3 -m smbfixer ...`.

## Set up SSH to Unraid

Host-side checks run over SSH with key authentication (no passwords are stored or prompted for).

1. **On the Mac** (Terminal): `ssh-keygen -t ed25519` (accept the defaults), then
   `pbcopy < ~/.ssh/id_ed25519.pub` to copy the public key.
2. **In the Unraid web UI** (any browser): **Settings > Management Access > Use SSH: Yes**, then
   **Users > root > SSH authorized keys**, paste the key, **Apply**.
3. **On the Mac**: `ssh -o BatchMode=yes root@tower.local true` must return without asking for a
   password. (Running this from the Unraid terminal instead fails with "Host key verification failed".)

## Configure (on the Mac)

```bash
smbfixer init        # writes ./smbfixer.toml
```

Edit `host.address` and `client.mount_point` (the share as mounted in Finder, e.g. `/Volumes/media`).
Any setting can also be given on the command line: `--host`, `--user`, `--mount`.

## Use (on the Mac)

```bash
smbfixer check                 # collect from both ends, analyse, recommend
smbfixer apply                 # make the [auto] changes, asking before each one
smbfixer apply --dry-run       # show exactly what apply would change
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
- `apply` makes the changes described below, and only after you confirm them.

Nothing else writes to either machine.

## Applying recommendations

Every step in the report is tagged with where it happens and how:

| Tag | Meaning |
| --- | --- |
| `[auto]` | `smbfixer apply` can make this change itself |
| `[you]` | must be done by hand, at the place shown |
| `[check]` | a command that only looks; it changes nothing |

The report ends with **What to do, by machine**:

**On this Mac** — `[auto]`
- `/etc/nsmb.conf` (SMB client settings). `apply` backs up the file to
  `/etc/nsmb.conf.smbfixer-<time>`, writes the new one with `sudo` (it asks for your Mac password),
  and checks the result. Unmount and remount the share (or restart the Mac) for it to take effect.
- Simple settings such as `defaults write com.apple.desktopservices DSDontWriteNetworkStores`.

**On the Unraid server** — `[auto]`
- `/boot/config/smb-extra.conf`, the same text as **Settings > SMB > SMB Extras** in the web UI.
  `apply` copies the old file to `/boot/config/smb-extra.conf.smbfixer-<time>`, writes the new one over
  SSH, validates the complete Samba configuration with `testparm`, **restores the backup if the check
  fails**, and otherwise reloads Samba with `smbcontrol smbd reload-config`. Settings that affect the
  connection itself (socket options, interfaces) apply to new connections, so reconnect the share.

**In the Unraid web UI** — `[you]`
- Steps are listed by menu path (for example *Settings > Docker > Docker custom network type*).
  These stay manual because Unraid applies them through its own services, and some require stopping
  Docker or the array.

**On the network** — `[you]`
- Cables, switch ports, jumbo frames and Wi‑Fi placement.

Changes marked as a **tradeoff** (turning off packet signing, `strict sync = no`, …) are never made
silently: `apply` asks about each one, and `apply --yes` skips them unless you also pass
`--include-tradeoffs`.

Change one thing at a time and re-run `smbfixer check` (or `bench`) to confirm the effect. To undo a
file change, copy the `.smbfixer-<time>` backup back over the file.

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install pytest
.venv/bin/python -m pytest
```

Parsers live in `smbfixer/parse/`, collectors in `smbfixer/collect/`, and diagnostic rules in
`smbfixer/analysis/rules.py`. Each rule is a small function that takes the parsed facts and yields
findings; tests feed recorded command output through the whole pipeline.
