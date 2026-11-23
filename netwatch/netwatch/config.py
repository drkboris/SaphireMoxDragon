"""Load named networks from a TOML file and resolve CLI targets."""

import ipaddress
import tomllib
from pathlib import Path

DEFAULT_CONFIG = Path("networks.toml")


def load_networks(path: Path) -> dict[str, str]:
    """Read the [networks] table and validate every CIDR up front."""
    with open(path, "rb") as f:  # tomllib wants a binary file handle
        data = tomllib.load(f)

    networks = data.get("networks", {})
    for name, cidr in networks.items():
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            raise ValueError(f"Bad CIDR for '{name}' in {path}: {cidr}") from exc
    return networks


def resolve_targets(requested: list[str], networks: dict[str, str]) -> dict[str, str]:
    """Map label -> CIDR for what the user asked to scan.

    - no names given: scan everything in the config
    - a name from the config (e.g. "dmz"): scan that network
    - a raw CIDR (e.g. "192.168.1.0/24"): scan it, labeled by the CIDR itself
    """
    if not requested:
        return dict(networks)

    targets: dict[str, str] = {}
    for item in requested:
        if item in networks:
            targets[item] = networks[item]
            continue
        try:
            ipaddress.ip_network(item, strict=False)
        except ValueError:
            known = ", ".join(networks) or "none"
            raise ValueError(f"'{item}' is not a known network name or CIDR (known: {known})")
        targets[item] = item
    return targets


def load_mikrotik_settings(path: Path) -> dict[str, str]:
    """Read the optional [mikrotik] table: host = "...", user = "...", key = "..." (optional)."""
    with open(path, "rb") as f:
        data = tomllib.load(f)
    return data.get("mikrotik", {})
