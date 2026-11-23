"""Add identifying info to live hosts using nmap.

We run `nmap -oX -` (XML to stdout) and parse it with the standard library,
so there is no extra Python dependency. Only nmap itself must be installed:
    sudo dnf install nmap

What you get depends on where you scan from:
  - hostname: reverse DNS, works across VLANs if your DNS has PTR records
  - open ports/services: works across VLANs, subject to firewall rules
  - MAC + vendor: only for hosts on the SAME VLAN/subnet as your laptop
    (a routed hop hides the MAC)
  - OS guess: needs root (sudo) and is unreliable across routed hops
"""

import asyncio
import os
import xml.etree.ElementTree as ET
from collections.abc import Awaitable, Callable

from .models import HostResult

# A runner takes an IP and returns nmap's XML output as text.
# Injectable so tests can feed in canned XML without nmap installed.
NmapRunner = Callable[[str], Awaitable[str]]


REDIRECT_PREFIX = "Did not follow redirect to "


def tidy_title(title: str | None) -> str | None:
    """Turn nmap's 'Did not follow redirect to X' into the shorter 'redirects to X'."""
    if title and title.startswith(REDIRECT_PREFIX):
        return f"redirects to {title[len(REDIRECT_PREFIX):]}"
    return title


def _first_line(text: str) -> str:
    lines = text.strip().splitlines()
    return lines[0].strip() if lines else ""


def parse_nmap_xml(xml_text: str) -> dict:
    """Pull the fields we care about out of nmap XML. Pure function, easy to test."""
    if not xml_text.strip():
        return {}
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return {}

    host = root.find("host")
    if host is None:
        return {}

    info: dict = {}

    hostname = host.find("hostnames/hostname")
    if hostname is not None:
        info["hostname"] = hostname.get("name")

    for addr in host.findall("address"):
        if addr.get("addrtype") == "mac":
            info["mac"] = addr.get("addr")
            info["vendor"] = addr.get("vendor")

    ports = []
    redirect = None  # used only if no port gives a real page title
    for port in host.findall("ports/port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue

        service = port.find("service")
        name = service.get("name") if service is not None else "unknown"
        label = f"{port.get('portid')}/{name}"
        if service is not None:
            if service.get("method") == "table":
                label += "?"  # nmap only guessed from the port number
            product = " ".join(filter(None, [service.get("product"), service.get("version")]))
            if product:
                label += f" ({product})"
        ports.append(label)

        for script in port.findall("script"):
            if script.get("id") == "http-title" and "http_title" not in info:
                title = _first_line(script.get("output", ""))
                if title.startswith(REDIRECT_PREFIX):
                    redirect = redirect or tidy_title(title)
                elif title and not title.startswith("Site doesn't have a title"):
                    info["http_title"] = title
            elif script.get("id") == "ssl-cert" and "tls_name" not in info:
                cn = script.find("table[@key='subject']/elem[@key='commonName']")
                if cn is not None and cn.text:
                    info["tls_name"] = cn.text
    if redirect and "http_title" not in info:
        info["http_title"] = redirect
    info["open_ports"] = ports

    best_os = host.find("os/osmatch")
    if best_os is not None:
        info["os_guess"] = best_os.get("name")

    return info


async def run_nmap(ip: str, timeout_s: float = 180.0) -> str:
    """Run nmap against one host and return the XML. Empty string on failure."""
    cmd = [
        "nmap", "-Pn", "-T4", "--top-ports", "100",
        "-sV", "--version-light",  # probe open ports to identify the real service
        "--script", "http-title,ssl-cert",
        "-oX", "-", ip,
    ]  # fmt: skip
    if os.geteuid() == 0:  # OS detection needs root
        cmd.insert(1, "-O")
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
    except (asyncio.TimeoutError, FileNotFoundError):
        return ""
    return stdout.decode(errors="replace")


async def enrich_hosts(
    hosts: list[HostResult],
    concurrency: int = 8,
    runner: NmapRunner = run_nmap,
) -> None:
    """Fill in extra fields on each live host, in place."""
    semaphore = asyncio.Semaphore(concurrency)

    async def one(host: HostResult) -> None:
        async with semaphore:
            info = parse_nmap_xml(await runner(host.ip))
        for key, value in info.items():
            setattr(host, key, value)

    await asyncio.gather(*(one(h) for h in hosts if h.alive))
