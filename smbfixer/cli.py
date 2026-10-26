"""Command line interface."""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from smbfixer import __version__, bench, report
from smbfixer import config as config_mod
from smbfixer.analysis import analyze
from smbfixer.collect import collect, resolve
from smbfixer.runner import SSH
from smbfixer.snapshot import Snapshot


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="smbfixer", description="Diagnose and tune macOS <-> Samba (Unraid) SMB.")
    p.add_argument("--version", action="version", version=f"smbfixer {__version__}")
    p.add_argument("-c", "--config", help="config file (default ./smbfixer.toml or ~/.config/smbfixer/config.toml)")
    p.add_argument("--host", help="host address (overrides config)")
    p.add_argument("--user", help="SSH user (overrides config)")
    p.add_argument("--mount", help="local mount point of the share (overrides config)")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="write an example smbfixer.toml in the current directory")

    c = sub.add_parser("check", help="collect from both ends, analyse, and print recommendations")
    _output_args(c)
    c.add_argument("--no-host", action="store_true", help="skip SSH collection on the host")
    c.add_argument("--no-client", action="store_true", help="skip local collection")
    c.add_argument("--bench", action="store_true", help="also run the throughput benchmark")
    c.add_argument("--save-dir", default="reports", help="where to store snapshot + report (default ./reports)")
    c.add_argument("--no-save", action="store_true", help="do not write snapshot/report files")

    co = sub.add_parser("collect", help="collect raw diagnostics into a snapshot file")
    co.add_argument("-o", "--output", default=None, help="snapshot path (default reports/snapshot-<time>.json)")
    co.add_argument("--no-host", action="store_true")
    co.add_argument("--no-client", action="store_true")

    a = sub.add_parser("analyze", help="analyse a saved snapshot")
    a.add_argument("snapshot")
    _output_args(a)

    m = sub.add_parser("monitor", help="watch the live connection and both logs for stalls")
    m.add_argument("--duration", type=float, help="seconds to run (default: until Ctrl-C)")
    m.add_argument("--no-host", action="store_true")
    m.add_argument("--samba-debug", type=int, metavar="N",
                   help="temporarily raise smbd debug level on the host (restored on exit)")

    ap = sub.add_parser("apply", help="make the [auto] changes from the report on the Mac and the server")
    ap.add_argument("--dry-run", action="store_true", help="show what would change and stop")
    ap.add_argument("-y", "--yes", action="store_true",
                    help="apply without asking (tradeoff changes are still skipped unless --include-tradeoffs)")
    ap.add_argument("--include-tradeoffs", action="store_true",
                    help="also apply changes that trade safety or compatibility for speed")
    ap.add_argument("--no-host", action="store_true", help="only change the Mac")
    ap.add_argument("--no-client", action="store_true", help="only change the server")

    b = sub.add_parser("bench", help="measure SMB throughput and small-file latency")
    b.add_argument("--size", type=int, help="sequential test size in MB")
    b.add_argument("--files", type=int, help="number of small files")
    b.add_argument("--iperf", action="store_true", help="also measure raw network with iperf3 (both ends)")
    b.add_argument("--host-disk", action="store_true",
                   help="also measure the share's storage directly on the host (writes a temp file there)")
    return p


def _output_args(p) -> None:
    p.add_argument("-f", "--format", choices=["text", "md", "json"], default="text")
    p.add_argument("-v", "--verbose", action="store_true", help="show all evidence lines")


def load_config(args) -> config_mod.Config:
    cfg = config_mod.load(args.config)
    if args.host:
        cfg.host.address = args.host
    if args.user:
        cfg.host.ssh_user = args.user
    if args.mount:
        cfg.client.mount_point = args.mount
    return cfg


def progress(side: str, result) -> None:
    mark = "ok" if result.ok else f"rc={result.returncode}"
    print(f"  {side:<6} {result.name:<16} {mark:<7} {result.duration:5.1f}s", file=sys.stderr)


def render(facts, findings, fmt: str, verbose: bool = False) -> str:
    if fmt == "md":
        return report.markdown(facts, findings)
    if fmt == "json":
        return report.as_json(facts, findings)
    return report.text(facts, findings, verbose=verbose)


def require_host(cfg) -> None:
    if not cfg.host.address:
        sys.exit("host.address is not set: run `smbfixer init` and edit smbfixer.toml, or pass --host")


def run_bench(cfg, mount: str, *, iperf: bool, host_disk: bool, share_path: str = "") -> dict:
    if not mount or not Path(mount).is_dir():
        sys.exit(f"mount point {mount!r} is not mounted; set client.mount_point or pass --mount")
    print(f"benchmarking {mount} ({cfg.bench.size_mb} MB sequential, {cfg.bench.small_files} small files)...",
          file=sys.stderr)
    results = bench.sequential(mount, cfg.bench.size_mb)
    results.update(bench.small_files(mount, cfg.bench.small_files))
    if (iperf or host_disk) and cfg.host.address:
        ssh = SSH(cfg.host)
        if iperf:
            results.update(bench.iperf(ssh, resolve(cfg.host.address) or cfg.host.address))
        if host_disk:
            if share_path:
                results.update(bench.host_disk(ssh, share_path, cfg.bench.size_mb))
            else:
                results["host_disk_error"] = "share path on host unknown"
    return results


def cmd_check(args, cfg) -> int:
    if not args.no_host:
        require_host(cfg)
    print("collecting...", file=sys.stderr)
    snap = collect(cfg, client=not args.no_client, host=not args.no_host, progress=progress)
    if args.bench:
        facts, _ = analyze(snap)
        snap.meta["bench"] = run_bench(cfg, snap.meta.get("mount_point", ""), iperf=True, host_disk=False,
                                       share_path=facts.share_conf.get("path", ""))
    facts, findings = analyze(snap)
    output = render(facts, findings, args.format, args.verbose)
    print(output)
    if not args.no_save:
        stamp = time.strftime("%Y%m%d-%H%M%S")
        outdir = Path(args.save_dir)
        snap.save(outdir / f"snapshot-{stamp}.json")
        (outdir / f"report-{stamp}.md").write_text(report.markdown(facts, findings))
        print(f"saved {outdir}/snapshot-{stamp}.json and report-{stamp}.md", file=sys.stderr)
    return 2 if any(f.severity == "critical" for f in findings) else 0


def cmd_collect(args, cfg) -> int:
    if not args.no_host:
        require_host(cfg)
    snap = collect(cfg, client=not args.no_client, host=not args.no_host, progress=progress)
    path = Path(args.output or f"reports/snapshot-{time.strftime('%Y%m%d-%H%M%S')}.json")
    snap.save(path)
    print(path)
    return 0


def cmd_analyze(args, cfg) -> int:
    facts, findings = analyze(Snapshot.load(Path(args.snapshot)))
    print(render(facts, findings, args.format, args.verbose))
    return 0


def cmd_monitor(args, cfg) -> int:
    from smbfixer.monitor import Monitor, summarize
    from smbfixer.collect.macos import guess_mount

    mount = cfg.client.mount_point
    if not mount:
        from smbfixer.runner import run_local
        snap = Snapshot(meta={"host_address": cfg.host.address, "host_ip": resolve(cfg.host.address)})
        snap.add("client", run_local("mount", ["mount", "-t", "smbfs"]))
        mount = guess_mount(snap)
    if not mount:
        sys.exit("no SMB mount found; mount the share or set client.mount_point")
    session = Monitor(cfg, mount, use_host=not args.no_host, samba_debug=args.samba_debug).run(args.duration)
    print("\n".join(["", "Summary", *summarize(session)]))
    return 2 if session.stalls else 0


def cmd_bench(args, cfg) -> int:
    if args.size:
        cfg.bench.size_mb = args.size
    if args.files:
        cfg.bench.small_files = args.files
    share_path = ""
    if args.host_disk:
        require_host(cfg)
        snap = collect(cfg, client=True, host=True)
        facts, _ = analyze(snap)
        share_path = facts.share_conf.get("path", "")
        cfg.client.mount_point = cfg.client.mount_point or snap.meta.get("mount_point", "")
    results = run_bench(cfg, cfg.client.mount_point, iperf=args.iperf, host_disk=args.host_disk,
                        share_path=share_path)
    width = max(len(k) for k in results)
    for k, v in results.items():
        print(f"{k:<{width}}  {v}")
    return 0


def cmd_init(args, cfg) -> int:
    path = Path("smbfixer.toml")
    if path.exists():
        sys.exit("smbfixer.toml already exists")
    path.write_text(config_mod.EXAMPLE)
    print(f"wrote {path}; edit host.address and client.mount_point")
    return 0


def ask(prompt: str) -> bool:
    try:
        return input(prompt).strip().lower() in {"y", "yes"}
    except EOFError:
        return False


def cmd_apply(args, cfg) -> int:
    from smbfixer import apply as apply_mod

    if not args.no_host:
        require_host(cfg)
    print("collecting current state...", file=sys.stderr)
    snap = collect(cfg, client=not args.no_client, host=not args.no_host)
    facts, findings = analyze(snap)
    recs = report.all_recs(findings)
    if args.no_host:
        recs = [r for r in recs if r.side != "host"]
    if args.no_client:
        recs = [r for r in recs if r.side != "client"]
    interactive = sys.stdin.isatty() and not args.yes and not args.dry_run
    chosen = apply_mod.choose(recs, include_tradeoffs=args.include_tradeoffs, interactive=interactive, ask=ask)
    skipped = [r for r in recs if r.automatic and r not in chosen]
    ssh = SSH(cfg.host) if cfg.host.address and not args.no_host else None
    try:
        changes = apply_mod.plan(facts, chosen, ssh)
    except apply_mod.ApplyError as exc:
        sys.exit(str(exc))

    if not changes:
        print("Nothing for smbfixer to change automatically.")
    for i, ch in enumerate(changes, 1):
        print(f"\n[{i}/{len(changes)}] {ch.machine}: {ch.title}")
        print("\n".join(f"    {line}" for line in ch.preview.splitlines()))
    if skipped:
        print("\nSkipped (tradeoffs, not chosen):")
        print("\n".join(f"  - {r.machine}: {r.action}" for r in skipped))
    if args.dry_run or not changes:
        _print_manual(recs)
        return 0
    if not args.yes and not sys.stdin.isatty():
        sys.exit("not a terminal: re-run with --yes to apply without prompts")

    failed = 0
    for ch in changes:
        if not args.yes and not ask(f"\nApply '{ch.title}' on the {ch.machine}? [y/N] "):
            print("  skipped")
            continue
        try:
            print(f"  {ch.run()}")
        except apply_mod.ApplyError as exc:
            failed += 1
            print(f"  FAILED: {exc}", file=sys.stderr)
    _print_manual(recs)
    print("\nRun `smbfixer check` to confirm the result.")
    return 1 if failed else 0


def _print_manual(recs) -> None:
    from smbfixer.analysis.model import MACHINE_HEADINGS

    groups = report.by_machine([r for r in recs if not r.automatic])
    if not any(groups.values()):
        return
    print("\nStill to do by hand:")
    for machine, heading in MACHINE_HEADINGS.items():
        items = groups.get(machine, [])
        if items:
            print(f"  {heading}")
            print("\n".join(f"    [{report.tag(r)}] {r.action}" for r in items))


COMMANDS = {
    "init": cmd_init, "check": cmd_check, "collect": cmd_collect, "apply": cmd_apply,
    "analyze": cmd_analyze, "monitor": cmd_monitor, "bench": cmd_bench,
}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    cfg = load_config(args)
    try:
        return COMMANDS[args.command](args, cfg)
    except KeyboardInterrupt:
        return 130
