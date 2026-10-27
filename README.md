# SMB Fixer

Diagnose and tune SMB file sharing between a **Mac** and a **Samba server**, built first for
**Unraid 7.x**. SMB Fixer looks at both ends of the connection at once: the Mac's SMB client log,
the server's Samba and system logs, the negotiated connection, the network path and the server's
storage layout. It explains *why* a share is slow, beachballs Finder, or makes copies fail, and
proposes concrete configuration changes for each machine. It can make the safe ones itself.

Some things it has caught on real systems:

- Copies failing in both directions at once because Unraid ships with asynchronous I/O off, so a
  slow array write blocked the whole connection, and the Mac then couldn't reclaim its open files
  after reconnecting.
- Time Machine refusing to back up because durable handles were missing their prerequisites.
- A malformed `/etc/nsmb.conf` that silently disabled the Mac's SMB settings.
- Replies leaving the server through Docker's macvlan shim instead of the bridge.
- Finder hangs that line up, to the second, with array disks spinning up.

`check` only reads; it never changes anything. Every recommendation says **which machine** it
applies to, why, and what it costs (for example, turning off packet signing). `apply` makes the
changes the app can make safely, each one shown and confirmed first, with a backup.

---

## Contents

1. [Requirements](#requirements)
2. [Install (on the Mac)](#install-on-the-mac)
3. [Set up SSH to the server](#set-up-ssh-to-the-server)
4. [Configure (on the Mac)](#configure-on-the-mac)
5. [First run](#first-run)
6. [Reading the report](#reading-the-report)
7. [Applying changes](#applying-changes)
8. [Catching a hang live](#catching-a-hang-live)
9. [Measuring throughput](#measuring-throughput)
10. [Command reference](#command-reference)
11. [What it reads and writes](#what-it-reads-and-writes)
12. [Undoing a change](#undoing-a-change)
13. [Troubleshooting](#troubleshooting)
14. [Limitations](#limitations)
15. [Development](#development)

> **Where to run it:** every command in this guide is typed in **Terminal on the Mac** (the prompt
> ends in `%`), not in the Unraid web terminal. SMB Fixer reaches the server over SSH by itself.
> The only steps done elsewhere are marked **In the Unraid web UI**.

## Requirements

| Machine | Needs |
| --- | --- |
| Mac | macOS 13 or later (tested on 15), Python 3.11+, the share mounted in Finder |
| Server | Unraid 7.x (tested on 7.3) or another Linux Samba 4.x server, SSH enabled, key login as `root` (or a user that can run `testparm`, `smbstatus` and read `/var/log`) |
| Optional | `iperf3` on both machines for `bench --iperf` (`brew install iperf3`; on Unraid via a plugin) |

No third-party Python packages are used.

The `python3` that comes with macOS's command line tools is 3.9, which is too old. Check with
`python3 --version`. If it says 3.9, install a newer Python first:

```bash
brew install python@3.13
```

(or use the installer from [python.org](https://www.python.org/downloads/macos/)).

## Install (on the Mac)

**Option A: pipx** (simplest; puts `smbfixer` on your PATH)

```bash
brew install pipx
pipx ensurepath
pipx install git+https://github.com/focher/smb-fixer.git
```

Upgrade later with `pipx upgrade smbfixer`.

**Option B: a clone with its own virtual environment** (useful if you want to read or change the code)

```bash
git clone https://github.com/focher/smb-fixer.git
cd smb-fixer
python3 -m venv .venv
.venv/bin/pip install .
```

Then run it as `.venv/bin/smbfixer` (or activate the environment with `source .venv/bin/activate`
and type `smbfixer`). Upgrade with `git pull && .venv/bin/pip install .`.

Check it works:

```bash
smbfixer --version
```

## Set up SSH to the server

Host-side checks run over SSH with a key. SMB Fixer never stores or asks for a password; it uses
`BatchMode`, so it fails cleanly instead of prompting.

1. **On the Mac**: create a key if you don't have one, and copy the public half.

   ```bash
   ssh-keygen -t ed25519
   ```

   Accept the defaults, then:

   ```bash
   pbcopy < ~/.ssh/id_ed25519.pub
   ```

2. **In the Unraid web UI** (any browser):
   - **Settings > Management Access > Use SSH: Yes**, **Apply**.
   - **Users > root > SSH authorized keys**: paste the key, **Apply**.

   On another Samba server, append the key to `~/.ssh/authorized_keys` for the user you will use.

3. **On the Mac**: connect once by hand to accept the server's host key.

   ```bash
   ssh root@tower.local true
   ```

   Answer `yes` to the fingerprint prompt. Then confirm key login works without any prompt:

   ```bash
   ssh -o BatchMode=yes root@tower.local 'cat /etc/unraid-version'
   ```

Replace `tower.local` with your server's name or IP address. You can skip SSH entirely and run
client-side checks only with `--no-host`, but most findings need both ends.

## Configure (on the Mac)

1. Mount the share in Finder (**Go > Connect to Server**, `smb://tower.local/media`) and note where
   it appears: `ls /Volumes`.
2. Create the config file in the folder you will run SMB Fixer from:

   ```bash
   smbfixer init
   ```

   This writes `./smbfixer.toml`. You can also keep it at `~/.config/smbfixer/config.toml` so it is
   found from any folder.
3. Edit at least these two lines:

   ```toml
   [host]
   address = "tower.local"          # server name or IP
   ssh_user = "root"

   [client]
   mount_point = "/Volumes/media"   # where Finder mounted the share
   ```

Everything else has sensible defaults:

| Setting | Default | Meaning |
| --- | --- | --- |
| `host.ssh_port` | `22` | SSH port |
| `host.ssh_key` | your SSH default | key file, if not the default one |
| `host.platform` | `auto` | `unraid` or `samba` to override detection |
| `client.share` | the mounted share name | share name on the server, if it differs |
| `collect.log_minutes` | `60` | how far back to read the Mac's SMB log (use `180` or more to cover a whole problem session) |
| `collect.host_log_lines` | `3000` | how many lines of each server log to read |
| `collect.ping_count` | `10` | pings used to measure loss and jitter |
| `monitor.probe_interval` | `2.0` | seconds between `monitor` probes |
| `monitor.stall_threshold_ms` | `1500` | a probe slower than this counts as a stall |
| `bench.size_mb` | `512` | size of the sequential test file |
| `bench.small_files` | `200` | number of files in the small-file test |

Any setting can be overridden per run: `--host`, `--user`, `--mount`, or a different file with `-c`.

## First run

Ideally run it shortly after the problem happened (or while it is happening), so the logs still hold it:

```bash
smbfixer check
```

It takes about 30 seconds. The report prints to the terminal and is also saved as Markdown, together
with the raw data, under `./reports/`.

## Reading the report

The header shows what was found: server and macOS versions, the share, SMB dialect, and the network
path on both ends (for example `Host path: br0 -> eth0, eth1`).

Each finding has a severity:

| Mark | Severity | Meaning |
| --- | --- | --- |
| `✖` | critical | explains failures or lockups; fix first |
| `▲` | warning | costs speed or reliability |
| `●` | info | context, or an optional improvement |

Below each finding are its evidence lines (log samples, counters, settings) and the steps to take.
Every step is tagged with how it gets done and where:

| Tag | Meaning |
| --- | --- |
| `[auto]` | `smbfixer apply` can make this change itself |
| `[you]` | done by hand, at the place shown |
| `[check]` | a command that only looks; it changes nothing |

The report ends with **What to do, by machine**: the same steps grouped under *On this Mac*,
*On the Unraid server*, *In the Unraid web UI* and *On the network*. For each config file it shows
the complete new file, which is exactly what `apply` would write.

A few notes on reading it:

- **Trouble episodes** group the Mac's SMB log into bursts of stalls, reconnects and failed I/O:
  what you experienced as one hang. When the server logged something at the same moment (a disk
  spinning up, a Samba error, a NIC reset), the correlation finding shows both, on one clock.
- The logs reach back over the window you configured, so a problem you have already fixed can still
  show up until it ages out. Check the episode times against when you made the change.
- **Idle closes** (Samba closing a session nothing was using, often after a Time Machine backup) are
  normal and reported as info.

## Applying changes

Preview first:

```bash
smbfixer apply --dry-run
```

Then apply:

```bash
smbfixer apply
```

It shows each change as a diff and asks before making it.

**On this Mac:** `/etc/nsmb.conf` (SMB client settings).
- `apply` backs the file up to `/etc/nsmb.conf.smbfixer-<time>` and writes the new one with `sudo`, which asks for your Mac password.
- It then reads the file back to check it.
- **Eject and remount the share** (or restart the Mac) for the change to take effect.

Simple settings such as `defaults write com.apple.desktopservices DSDontWriteNetworkStores -bool true` are also run here.

**On the Unraid server:** `/boot/config/smb-extra.conf`. This is the same text as **Settings > SMB > SMB Extras** in the web UI.
- `apply` copies the old file to `/boot/config/smb-extra.conf.smbfixer-<time>` and writes the new one over SSH.
- It then validates the complete Samba configuration with `testparm`, and **restores the backup if the check fails**.
- If the check passes, it reloads Samba with `smbcontrol smbd reload-config`. Most settings take effect on the existing connection at once.
- Connection-level settings (`socket options`, `interfaces`) wait until the share reconnects.

On a non-Unraid Samba server, `apply` leaves the Samba config alone and prints the settings to merge
into `smb.conf` yourself.

**In the Unraid web UI:** always by hand. These steps are listed by menu path, for example *Settings > Docker > Docker custom network type*. Unraid applies these through its own services, and some need Docker or the array stopped.

**On the network:** cables, switch ports, jumbo frames and Wi‑Fi placement.

Changes marked **tradeoff** are never made silently. These include turning off packet signing, `strict sync = no` (only safe with a UPS), and pinning the interface list. `apply` asks about each one separately. `apply --yes` skips them unless you also pass `--include-tradeoffs`.

Change one thing at a time, then run `smbfixer check` again to confirm the effect.

## Catching a hang live

When the problem is intermittent, watch it happen:

```bash
smbfixer monitor
```

It touches the mount every couple of seconds and times the response, while streaming the Mac's SMB
log and the server's logs. Reproduce the problem (copy a big folder, open the slow directory), then
press **Ctrl-C**. The summary lists every stall with what both machines logged around it.

```bash
smbfixer monitor --samba-debug 2
```

This temporarily raises Samba's log level on the server for more detail, and restores it on exit.

## Measuring throughput

```bash
smbfixer bench
```

This runs a sequential read/write test and a small-file test on the mount.

```bash
smbfixer bench --iperf --host-disk
```

This also measures the raw network (iperf3) and the share's disks directly on the server. Comparing
the three numbers shows whether the limit is the network, SMB itself, or the storage.

## Command reference

| Command | What it does |
| --- | --- |
| `smbfixer init` | write an example `smbfixer.toml` here |
| `smbfixer check` | collect from both machines, analyse, print and save the report |
| `smbfixer check -v` | show every evidence line |
| `smbfixer check -f md > report.md` | Markdown output (`-f json` for JSON) |
| `smbfixer check --no-host` | Mac only, no SSH |
| `smbfixer check --bench` | include a throughput test |
| `smbfixer apply [--dry-run] [--yes] [--include-tradeoffs]` | make the `[auto]` changes |
| `smbfixer apply --no-host` / `--no-client` | change only the Mac / only the server |
| `smbfixer monitor [--duration N] [--samba-debug N]` | watch live for stalls |
| `smbfixer bench [--size MB] [--files N] [--iperf] [--host-disk]` | measure throughput |
| `smbfixer collect -o snap.json` | save raw data only |
| `smbfixer analyze snap.json` | analyse a saved snapshot (no access to either machine needed) |

Global options: `-c FILE`, `--host`, `--user`, `--mount`. The exit status is `2` when a critical
finding (or, for `monitor`, a stall) was seen, `1` when an `apply` step failed, and `0` otherwise.

## What it reads and writes

**Reads**

- **On the Mac:**
  - `smbutil statshares` and `multichannel`, `mount`, `/etc/nsmb.conf` and `~/Library/Preferences/nsmb.conf`
  - interface and route information, and `ping`
  - the unified log for the `smbfs` kernel extension
- **On the server:**
  - `testparm`, `smbstatus`, Unraid's share/disk/network config under `/boot/config` and `/var/local/emhttp`
  - `ip`, `ethtool`, `vmstat`, `df`
  - `/var/log/samba` and `/var/log/syslog`

**Writes**

- `check`: only its own files under `./reports/` on the Mac.
- `bench`: a temporary file and folder on the mount, deleted afterwards; `--host-disk` writes a temporary file in the share's path on the server.
- `monitor --samba-debug N`: changes the running smbd debug level and restores it on exit.
- `apply`: only the changes described above, after you confirm them.

**Privacy:** saved reports and snapshots contain host names, IP addresses, user names and file
names from your logs. Review them before posting one in an issue or forum. Nothing is sent anywhere
except over your own SSH connection to your server.

## Undoing a change

Every file `apply` writes is backed up next to the original with a `.smbfixer-<time>` suffix.

**On the Mac:**

```bash
sudo cp /etc/nsmb.conf.smbfixer-20260101-120000 /etc/nsmb.conf
```

Then eject and remount the share.

**On the Unraid server** (over SSH from the Mac):

```bash
ssh root@tower.local 'cp /boot/config/smb-extra.conf.smbfixer-20260101-120000 /boot/config/smb-extra.conf && smbcontrol smbd reload-config'
```

Or paste the old text back into **Settings > SMB > SMB Extras** in the web UI.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `Host key verification failed` | You ran the SSH test on the server, or have never connected from the Mac. Run `ssh root@tower.local true` **on the Mac** and accept the fingerprint. |
| `Permission denied (publickey)` | The key isn't in the server's authorized keys (Unraid: **Users > root**), or `host.ssh_key` points at the wrong file. |
| `mount point '/Volumes/…' is not mounted`, or "No mounted share from this host was found" | Mount the share in Finder first and set `client.mount_point` to the exact path from `ls /Volumes`. |
| pip says the package `requires a different Python`, or syntax errors at start | You are on macOS's Python 3.9; install a newer one (see [Requirements](#requirements)). |
| Few or no client log events | Increase `collect.log_minutes` so the window covers when the problem happened. |
| `sudo` prompt during `apply` | Expected: `/etc/nsmb.conf` is owned by root. Type your Mac password. |
| A finding persists after you fixed it | Old log entries are still inside the window; check the episode times, or wait and re-run. |

## Limitations

- The client side is macOS only.
- Unraid is the tested server. On other Linux Samba servers the checks work, but Unraid-specific
  findings are skipped and `apply` does not edit the server's Samba config.
- Recommendations are based on what the logs and settings show. They are a strong starting point,
  not a guarantee; re-check after each change.

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install -e . pytest
.venv/bin/python -m pytest
```

Parsers live in `smbfixer/parse/`, collectors in `smbfixer/collect/`, diagnostic rules in
`smbfixer/analysis/rules.py`, and the change engine in `smbfixer/apply.py` and
`smbfixer/configedit.py`. Each rule is a small function that takes the parsed facts and yields
findings. The tests feed recorded command output through the whole pipeline, so a new rule can be
tested without either machine.

Bug reports are most useful with the output of `smbfixer check -v` (after removing anything private)
or the snapshot file from `./reports/`.

## License

[MIT](LICENSE)
