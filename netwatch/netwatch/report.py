"""Human-readable views of a saved sweep."""

import ipaddress

from .enrich import tidy_title


def _clip(text: str, width: int) -> str:
    return text if len(text) <= width else text[: width - 1] + "…"


def _name(host: dict) -> str:
    name = host.get("hostname")
    comment = host.get("comment")
    if name and comment:
        return f"{name} ({comment})"
    return name or (f"({comment})" if comment else "-")


def _details(host: dict, wide: bool) -> str:
    parts = []
    title = tidy_title(host.get("http_title"))
    if title:
        parts.append(f"web: {title}")
    if host.get("tls_name"):
        parts.append(f"cert: {host['tls_name']}")
    if host.get("open_ports"):
        parts.append("ports: " + ", ".join(host["open_ports"]))
    # The DHCP class can be long, so show it only when nothing else describes the device.
    if host.get("dhcp_class") and (wide or not parts):
        parts.append(f"dhcp: {host['dhcp_class']}")
    return "; ".join(parts)


def _matches(host: dict, text: str) -> bool:
    """Case-insensitive search across every field of a host."""
    needle = text.lower()
    values = [
        str(v) for v in host.values() if isinstance(v, (str, float, int)) and not isinstance(v, bool)
    ]
    values += [str(item) for v in host.values() if isinstance(v, list) for item in v]
    return any(needle in value.lower() for value in values)


def format_inventory(
    record: dict,
    networks: list[str] | None = None,
    find: str | None = None,
    wide: bool = False,
) -> str:
    """One table per network, combining devices seen by ping and by the router."""
    lines = [f"Sweep from {record.get('timestamp', '?')}"]
    for label, net in record["networks"].items():
        if networks and label not in networks:
            continue
        hosts = sorted(net["hosts"], key=lambda h: ipaddress.ip_address(h["ip"]))
        if find:
            hosts = [h for h in hosts if _matches(h, find)]
            if not hosts:
                continue
        up = sum(1 for h in hosts if h["alive"])
        lines.append(f"\n== {label} ({net['cidr']}): {len(hosts)} devices, {up} answered ping ==")
        if not hosts:
            continue

        mac_header = f"{'MAC':<19}" if wide else ""
        lines.append(f"{'IP':<16}{'PING':<6}{mac_header}{'NAME':<28}{'VENDOR':<26}DETAILS")
        for h in hosts:
            mac_col = f"{(h.get('mac') or '-'):<19}" if wide else ""
            details = _details(h, wide)
            lines.append(
                f"{h['ip']:<16}{('yes' if h['alive'] else 'no'):<6}{mac_col}"
                f"{_clip(_name(h), 27):<28}{_clip(h.get('vendor') or '-', 25):<26}"
                f"{details if wide else _clip(details, 90)}"
            )
    return "\n".join(lines)
