"""Command line interface.

Each feature is a subcommand. To add one later (say `diff` or `ports`):
  1. write a `cmd_<name>(args)` function
  2. register it in `build_parser()` with set_defaults(func=cmd_<name>)
"""

import argparse
import asyncio
import json
import shutil
from pathlib import Path

from .config import DEFAULT_CONFIG, load_mikrotik_settings, load_networks, resolve_targets
from .enrich import enrich_hosts
from .mikrotik import (
    ARP_COMMAND,
    ADDRESS_COMMAND,
    LEASE_COMMAND,
    RouterError,
    add_router_only_hosts,
    apply_router_data,
    label_router_hosts,
    parse_arp,
    parse_leases,
    parse_router_addresses,
    run_router_command,
)
from .models import HostResult
from .neighbors import apply_neighbors, load_mac_prefixes, read_neighbors
from .report import _clip, format_inventory
from .scanner import sweep
from .storage import DEFAULT_DATA_DIR, build_run_record, load_latest, save_run, update_latest


def cmd_sweep(args: argparse.Namespace) -> int:
    try:
        networks = load_networks(args.config) if args.config.exists() else {}
        targets = resolve_targets(args.networks, networks)
    except ValueError as exc:
        print(f"error: {exc}")
        return 2
    if not targets:
        print(f"error: no networks to scan (looked for {args.config})")
        return 2

    if args.enrich and not shutil.which("nmap"):
        print("error: --enrich needs nmap (Fedora: sudo dnf install nmap)")
        return 2

    # label -> list of HostResult, scanned one network at a time
    prefixes = load_mac_prefixes()
    all_results = {}
    for label, cidr in targets.items():
        results = asyncio.run(sweep(cidr, concurrency=args.concurrency, retries=args.retries))
        # Read the ARP table right after the sweep, while its entries are fresh.
        apply_neighbors([r for r in results if r.alive], read_neighbors(), prefixes)
        if args.enrich:
            asyncio.run(enrich_hosts([r for r in results if r.alive]))
        all_results[label] = results

    record = build_run_record(targets, all_results)
    saved_to = None if args.no_save else save_run(record, args.data_dir)

    if args.json:
        print(json.dumps(record, indent=2))
        return 0

    for label, results in all_results.items():
        alive = [r for r in results if r.alive]
        print(f"\n== {label} ({targets[label]}) ==")
        print(f"{'IP ADDRESS':<16}{'RTT(ms)':>8}  {'HOSTNAME':<26}{'VENDOR':<22}PORTS")
        for r in alive:
            ports = ",".join(r.open_ports) or "-"
            print(
                f"{r.ip:<16}{r.rtt_ms:>8}  {_clip(r.hostname or '-', 25):<26}"
                f"{_clip(r.vendor or '-', 21):<22}{ports}"
            )
            details = [
                f"{name}: {value}"
                for name, value in (("mac", r.mac), ("web", r.http_title), ("cert", r.tls_name))
                if value
            ]
            if details:
                print(f"    {' | '.join(details)}")
        print(f"{len(alive)} of {len(results)} hosts responded")
    if saved_to:
        print(f"\nSaved to {saved_to}")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    """Print the combined inventory from the latest saved sweep."""
    record = load_latest(args.data_dir)
    if record is None:
        print(f"error: no saved sweep in {args.data_dir}. Run `sweep` first.")
        return 2
    unknown = [n for n in args.networks if n not in record["networks"]]
    if unknown:
        print(f"error: unknown network {', '.join(unknown)} (saved: {', '.join(record['networks'])})")
        return 2
    print(format_inventory(record, args.networks, args.find, args.wide))
    return 0


def cmd_mikrotik(args: argparse.Namespace) -> int:
    """Fill in names and MACs on the latest saved sweep using the MikroTik router."""
    record = load_latest(args.data_dir)
    if record is None:
        print(f"error: no saved sweep in {args.data_dir}. Run `sweep` first.")
        return 2

    settings = load_mikrotik_settings(args.config) if args.config.exists() else {}
    router = args.router or settings.get("host")
    user = args.user or settings.get("user")
    key = args.key or settings.get("key")
    if not router or not user:
        print("error: need --router and --user, or a [mikrotik] section in the config file")
        return 2

    try:
        lease_text = run_router_command(router, user, LEASE_COMMAND, key=key)
        arp_text = run_router_command(router, user, ARP_COMMAND, key=key)
        address_text = run_router_command(router, user, ADDRESS_COMMAND, key=key)
    except RouterError as exc:
        print(f"error: {exc}")
        return 2

    leases, arp = parse_leases(lease_text), parse_arp(arp_text)
    router_ips = parse_router_addresses(address_text)
    prefixes = load_mac_prefixes()

    networks = {
        label: (net["cidr"], [HostResult(**h) for h in net["hosts"]])
        for label, net in record["networks"].items()
    }
    pinged = 0
    for _, hosts in networks.values():
        for host in hosts:
            if host.alive and "ping" not in host.source:
                host.source.insert(0, "ping")  # runs saved before sources were tracked
        apply_router_data(hosts, leases, arp, prefixes)
        label_router_hosts(hosts, router_ips)
        pinged += sum(h.alive for h in hosts)

    added, merged = add_router_only_hosts(networks, leases, prefixes)

    for label, (cidr, hosts) in networks.items():
        net = record["networks"].setdefault(label, {"cidr": cidr, "scanned": 0})
        net["hosts"] = [h.to_dict() for h in hosts]

    update_latest(record, args.data_dir)
    print(f"Router returned {len(leases)} active leases and {len(arp)} ARP entries.")
    print(f"{pinged} devices answered ping; the router added {added} more.")
    if merged:
        print(f"{merged} extra IPs were matched to devices already listed (same MAC).")
    print("Updated latest.json.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="netwatch", description="Home network tools")
    sub = parser.add_subparsers(dest="command", required=True)

    p_sweep = sub.add_parser("sweep", help="ping sweep one or more networks")
    p_sweep.add_argument(
        "networks",
        nargs="*",
        help="names from the config file or raw CIDRs; omit to scan all configured networks",
    )
    p_sweep.add_argument(
        "--config", type=Path, default=DEFAULT_CONFIG, help="networks file (default: networks.toml)"
    )
    p_sweep.add_argument("-c", "--concurrency", type=int, default=64)
    p_sweep.add_argument(
        "--retries", type=int, default=1, help="extra ping attempts for silent hosts (default 1)"
    )
    p_sweep.add_argument("--json", action="store_true", help="output JSON")
    p_sweep.add_argument(
        "--enrich", action="store_true", help="run nmap on live hosts for hostname/ports/MAC"
    )
    p_sweep.add_argument("--no-save", action="store_true", help="do not write results to disk")
    p_sweep.add_argument(
        "--data-dir", type=Path, default=DEFAULT_DATA_DIR, help="where run history is saved"
    )
    p_sweep.set_defaults(func=cmd_sweep)

    p_list = sub.add_parser("list", help="show the combined inventory from the last sweep")
    p_list.add_argument("networks", nargs="*", help="only these networks (default: all)")
    p_list.add_argument("--find", help="only devices matching this text (name, MAC, vendor, ...)")
    p_list.add_argument("--wide", action="store_true", help="add MAC and full details")
    p_list.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    p_list.set_defaults(func=cmd_list)

    p_mt = sub.add_parser("mikrotik", help="add names/MACs from the router to the last sweep")
    p_mt.add_argument("--router", help="router address (or [mikrotik] host in the config)")
    p_mt.add_argument("--user", help="router login (or [mikrotik] user in the config)")
    p_mt.add_argument("--key", help="SSH private key file (or [mikrotik] key in the config)")
    p_mt.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    p_mt.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    p_mt.set_defaults(func=cmd_mikrotik)

    return parser


def main() -> int:
    args = build_parser().parse_args()
    return args.func(args)
