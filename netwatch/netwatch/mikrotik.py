"""Pull device names and MACs from a MikroTik router over SSH.

The router is the DHCP server and routes every subnet, so it knows each device's
real MAC, the hostname the device announced, and any comment you typed into the
lease in WinBox. We run two read-only commands and parse their `terse` output.

RouterOS terse output looks like:
    0 D address=10.1.1.5 mac-address=AA:BB:... server=Some Server status=bound host-name=Thing
Values are NOT quoted, so they can contain spaces ("server=Wireless DHCP Network").
That is why we split on "the next key=" instead of on whitespace.
"""

import ipaddress
import re
import subprocess
from pathlib import Path

from .models import HostResult
from .neighbors import MISSING_VENDORS, lookup_vendor

LEASE_COMMAND = "/ip dhcp-server lease print terse without-paging"
ARP_COMMAND = "/ip arp print terse without-paging"
ADDRESS_COMMAND = "/ip address print terse without-paging"
ROUTER_NAME = "router"

# Leading flag letters (D = dynamic, X = disabled, ...) come right after the index.
_FLAGS = re.compile(r"^(?:[A-Z]+\s+)*")
# key=value, where the value runs until the next " key=" or the end of the line.
_PAIR = re.compile(r"([a-z][a-z0-9-]*)=(.*?)(?=\s+[a-z][a-z0-9-]*=|\s*$)")


class RouterError(RuntimeError):
    pass


def build_ssh_command(host: str, user: str, command: str, key: str | None = None) -> list[str]:
    """Build the ssh command line.

    With a key we use it exclusively and turn on BatchMode, so a bad key fails
    straight away with an error instead of waiting at a password prompt.
    Without a key, ControlMaster keeps one password login open for a minute.
    """
    cmd = ["ssh", "-o", "ConnectTimeout=8"]
    if key:
        key_path = str(Path(key).expanduser())
        cmd += ["-i", key_path, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes"]
    else:
        cmd += [
            "-o", "ControlMaster=auto",
            "-o", "ControlPersist=60",
            "-o", "ControlPath=/tmp/netwatch-%C",
        ]  # fmt: skip
    cmd += [f"{user}@{host}", command]
    return cmd


def run_router_command(
    host: str, user: str, command: str, timeout: float = 60, key: str | None = None
) -> str:
    """Run one RouterOS command over ssh and return its output."""
    cmd = build_ssh_command(host, user, command, key)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        raise RouterError("ssh is not installed")
    except subprocess.TimeoutExpired:
        raise RouterError(f"timed out talking to {host}")
    if proc.returncode != 0:
        raise RouterError(proc.stderr.strip() or f"ssh exited with {proc.returncode}")
    return proc.stdout


def parse_terse(text: str) -> list[dict[str, str]]:
    """Turn RouterOS terse output into a list of {key: value} dicts."""
    rows = []
    for line in text.splitlines():
        match = re.match(r"^\s*(\d+)\s+(.*)$", line)
        if not match:
            continue  # blank lines, shell prompts, and so on
        rest = _FLAGS.sub("", match.group(2), count=1)
        row = {key: value.strip() for key, value in _PAIR.findall(rest)}
        if row:
            rows.append(row)
    return rows


def parse_leases(text: str) -> dict[str, dict]:
    """{ip: info} for leases that are currently bound (the device is on the network)."""
    leases: dict[str, dict] = {}
    for row in parse_terse(text):
        ip = row.get("active-address") or row.get("address")
        if not ip or row.get("status") != "bound":
            continue  # 'waiting' leases are old and could belong to another device now
        mac = row.get("active-mac-address") or row.get("mac-address")
        leases[ip] = {
            "mac": mac.upper() if mac else None,
            "hostname": row.get("host-name") or None,
            "comment": row.get("comment") or None,
            "dhcp_class": row.get("class-id") or None,
        }
    return leases


def parse_arp(text: str) -> dict[str, str]:
    """{ip: MAC} from the router's ARP table, skipping failed lookups."""
    arp: dict[str, str] = {}
    for row in parse_terse(text):
        ip, mac = row.get("address"), row.get("mac-address")
        if ip and mac and row.get("status") != "failed":
            arp[ip] = mac.upper()
    return arp


def parse_router_addresses(text: str) -> set[str]:
    """The router's own interface IPs (the gateways), from /ip address print."""
    addrs = set()
    for row in parse_terse(text):
        address = row.get("address", "")
        if address:
            addrs.add(address.split("/")[0])
    return addrs


def label_router_hosts(hosts: list[HostResult], router_ips: set[str]) -> int:
    """Name hosts that are the router's own interfaces. Returns how many were set."""
    count = 0
    for host in hosts:
        if host.ip in router_ips and host.hostname in (None, "", "_gateway"):
            host.hostname = ROUTER_NAME
            count += 1
    return count


def add_router_only_hosts(
    networks: dict[str, tuple[str, list[HostResult]]],
    leases: dict[str, dict],
    prefixes: dict[str, str],
) -> tuple[int, int]:
    """Add devices the router knows about but ping never saw.

    Identity is the MAC, not the IP: if a lease's MAC already belongs to a host we
    have under a different IP, that is the same device that changed address, so we
    record the extra IP on it instead of listing the device twice.

    `networks` maps label -> (cidr, hosts) and is modified in place.
    Returns (devices added, extra IPs merged into existing devices).
    """
    all_hosts = [h for _, hosts in networks.values() for h in hosts]
    by_ip = {h.ip: h for h in all_hosts}
    by_mac = {h.mac: h for h in all_hosts if h.mac}

    added = merged = 0
    for ip in sorted(leases, key=ipaddress.ip_address):
        if ip in by_ip:
            continue  # already have this address (apply_router_data filled it in)
        lease = leases[ip]
        mac = lease.get("mac")

        twin = by_mac.get(mac) if mac else None
        if twin is not None:
            if ip not in twin.alt_ips:
                twin.alt_ips.append(ip)
            merged += 1
            continue

        host = HostResult(
            ip=ip,
            alive=False,  # it did not answer ping; the router says it holds a lease
            mac=mac,
            vendor=lookup_vendor(mac, prefixes) if mac else None,
            hostname=lease.get("hostname"),
            comment=lease.get("comment"),
            dhcp_class=lease.get("dhcp_class"),
            source=["dhcp"],
        )
        label = _network_label(networks, ip)
        networks[label][1].append(host)
        by_ip[ip] = host
        if mac:
            by_mac[mac] = host
        added += 1

    for _, hosts in networks.values():
        hosts.sort(key=lambda h: ipaddress.ip_address(h.ip))
    return added, merged


def _network_label(networks: dict[str, tuple[str, list[HostResult]]], ip: str) -> str:
    """Which scanned network contains this IP? Falls back to an 'unscanned' bucket."""
    address = ipaddress.ip_address(ip)
    for label, (cidr, _) in networks.items():
        try:
            if address in ipaddress.ip_network(cidr, strict=False):
                return label
        except ValueError:
            continue  # the unscanned bucket has no real CIDR
    networks.setdefault("unscanned", ("(not scanned)", []))
    return "unscanned"


def apply_router_data(
    hosts: list[HostResult],
    leases: dict[str, dict],
    arp: dict[str, str],
    prefixes: dict[str, str],
) -> int:
    """Fill blank fields from the router. Returns how many hosts had a lease."""
    matched = 0
    for host in hosts:
        lease = leases.get(host.ip, {})
        if lease:
            matched += 1
            if "dhcp" not in host.source:
                host.source.append("dhcp")

        mac = host.mac or lease.get("mac") or arp.get(host.ip)
        if mac:
            host.mac = mac
            if host.vendor in MISSING_VENDORS:  # also upgrades old "Private" values
                host.vendor = lookup_vendor(mac, prefixes)

        for field in ("hostname", "comment", "dhcp_class"):
            if getattr(host, field) is None and lease.get(field):
                setattr(host, field, lease[field])
    return matched
