"""Data structures shared across netwatch modules."""

from dataclasses import dataclass, asdict, field


@dataclass
class HostResult:
    ip: str
    alive: bool
    rtt_ms: float | None = None  # round trip time, None if no reply
    # Filled in by enrichment (nmap). All optional, so a plain sweep still works.
    hostname: str | None = None
    mac: str | None = None
    vendor: str | None = None
    os_guess: str | None = None
    comment: str | None = None  # note you typed on the router's DHCP lease
    dhcp_class: str | None = None  # DHCP vendor class, e.g. "android-dhcp-14" or "MSFT 5.0"
    http_title: str | None = None  # page title from the first web port that has one
    tls_name: str | None = None  # certificate common name from the first TLS port
    open_ports: list[str] = field(default_factory=list)  # e.g. "22/ssh"
    # Which sources have seen this device: "ping", "dhcp" (router lease).
    source: list[str] = field(default_factory=list)
    # Other IPs the router reports for the same MAC (the device changed address).
    alt_ips: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)
