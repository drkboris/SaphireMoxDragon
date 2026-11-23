"""MAC addresses and vendors without root.

Pinging a host on your own subnet makes the kernel ARP for it, so its MAC lands
in the neighbor table (`ip neigh`). We read that table after a sweep, then look
up the vendor from nmap's MAC prefix file. Hosts behind a router never appear in
the table, so they keep mac = None.
"""

import ipaddress
import re
import subprocess
from pathlib import Path

from .models import HostResult

NMAP_MAC_PREFIXES = Path("/usr/share/nmap/nmap-mac-prefixes")
# Full IEEE registry copies. Fedora ships the first (package: hwdata), Debian the second.
# They are far more complete than nmap's list, so they are tried first.
PREFIX_FILES = [
    Path("/usr/share/hwdata/oui.txt"),
    Path("/usr/share/ieee-data/oui.txt"),
    NMAP_MAC_PREFIXES,
]
# Vendor values that mean "we don't really know" and may be replaced by a better lookup.
MISSING_VENDORS = {None, "Private"}

# IEEE format:  "04-F4-1C   (hex)\t\tMikroTik"  (and a "(base 16)" twin line)
_IEEE_LINE = re.compile(
    r"^([0-9A-Fa-f]{6}|[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})\s+\((?:hex|base 16)\)\s+(\S.*)$"
)
# nmap format:  "04F41C MikroTik"
_NMAP_LINE = re.compile(r"^([0-9A-Fa-f]{6})\s+(\S.*)$")


def parse_ip_neigh(text: str) -> dict[str, str]:
    """Parse `ip neigh show` output into {ip: MAC}. IPv4 entries with a MAC only."""
    neighbors: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.split()
        if not parts or "lladdr" not in parts:
            continue  # FAILED / INCOMPLETE entries have no MAC
        try:
            if ipaddress.ip_address(parts[0]).version != 4:
                continue
        except ValueError:
            continue
        neighbors[parts[0]] = parts[parts.index("lladdr") + 1].upper()
    return neighbors


def read_neighbors() -> dict[str, str]:
    try:
        out = subprocess.run(
            ["ip", "neigh", "show"], capture_output=True, text=True, timeout=5
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return {}
    return parse_ip_neigh(out.stdout)


def _parse_prefix_line(line: str) -> tuple[str, str] | None:
    """Read one line of either supported file format into (PREFIX, vendor name)."""
    if line.startswith("#"):
        return None
    match = _IEEE_LINE.match(line) or _NMAP_LINE.match(line)
    if not match:
        return None
    return match.group(1).replace("-", "").upper(), match.group(2).strip()


def load_mac_prefixes(path: Path | None = None) -> dict[str, str]:
    """Build {'04F41C': 'MikroTik', ...} from every vendor file we can find.

    With no argument, files in PREFIX_FILES are read in order and the first file
    that knows a prefix wins. "Private" entries are skipped so another file can
    still supply a real name.
    """
    paths = [path] if path else PREFIX_FILES
    prefixes: dict[str, str] = {}
    for file in paths:
        if not file.exists():
            continue
        for line in file.read_text(errors="replace").splitlines():
            parsed = _parse_prefix_line(line)
            if parsed and parsed[1] != "Private":
                prefixes.setdefault(parsed[0], parsed[1])
    return prefixes


def lookup_vendor(mac: str, prefixes: dict[str, str]) -> str | None:
    # Bit 0x02 of the first byte marks a locally administered address. Phones
    # use these for per-network "private" MACs, so no vendor can be looked up.
    if int(mac[:2], 16) & 0x02:
        return "(randomized MAC)"
    key = mac.replace(":", "").replace("-", "").upper()[:6]
    return prefixes.get(key)


def apply_neighbors(
    hosts: list[HostResult], neighbors: dict[str, str], prefixes: dict[str, str]
) -> None:
    """Fill mac/vendor in place for hosts we don't already have them for."""
    for host in hosts:
        mac = host.mac or neighbors.get(host.ip)
        if not mac:
            continue
        host.mac = mac
        if host.vendor in MISSING_VENDORS:
            host.vendor = lookup_vendor(mac, prefixes)
