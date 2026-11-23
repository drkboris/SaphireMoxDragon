"""Async ping sweep.

We shell out to the system `ping` command instead of crafting ICMP packets,
because raw sockets need root. The command-building is the only part that
differs per OS, so it lives in one small function.
"""

import asyncio
import ipaddress
import platform
import time
from collections.abc import Awaitable, Callable
from functools import partial

from .models import HostResult

# A "pinger" takes an IP string and returns a HostResult.
# Swapping this out (for tests, or a TCP-connect check later) is the main
# extension point of the scanner.
Pinger = Callable[[str], Awaitable[HostResult]]


def build_ping_command(ip: str, timeout_s: float = 1.0) -> list[str]:
    """Return the ping command for the current OS."""
    system = platform.system()
    if system == "Windows":
        return ["ping", "-n", "1", "-w", str(int(timeout_s * 1000)), ip]
    if system == "Darwin":  # macOS takes the timeout in milliseconds
        return ["ping", "-c", "1", "-W", str(int(timeout_s * 1000)), ip]
    return ["ping", "-c", "1", "-W", str(max(1, int(timeout_s))), ip]  # Linux


async def _ping_once(ip: str, timeout_s: float) -> float | None:
    """One ping attempt. Returns the round trip in ms, or None if there was no reply."""
    cmd = build_ping_command(ip, timeout_s)
    start = time.perf_counter()
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        # Hard cap so one stuck process can never hang the whole sweep.
        await asyncio.wait_for(proc.wait(), timeout=timeout_s + 2)
    except (asyncio.TimeoutError, FileNotFoundError):
        return None
    if proc.returncode == 0:
        return round((time.perf_counter() - start) * 1000, 1)
    return None


async def ping_host(ip: str, timeout_s: float = 1.0, retries: int = 1) -> HostResult:
    """Ping a host, trying again `retries` times if there is no reply.

    Wi-Fi devices in power-save mode often miss a single ping, so one retry
    recovers many of them at the cost of a slower sweep.
    """
    for _ in range(retries + 1):
        rtt = await _ping_once(ip, timeout_s)
        if rtt is not None:
            return HostResult(ip=ip, alive=True, rtt_ms=rtt, source=["ping"])
    return HostResult(ip=ip, alive=False)


def expand_network(cidr: str) -> list[str]:
    """Turn '192.168.1.0/24' into a list of usable host IPs."""
    network = ipaddress.ip_network(cidr, strict=False)
    return [str(ip) for ip in network.hosts()]


async def sweep(
    cidr: str,
    concurrency: int = 64,
    pinger: Pinger | None = None,
    retries: int = 1,
) -> list[HostResult]:
    """Ping every host in a network, `concurrency` at a time."""
    if pinger is None:
        pinger = partial(ping_host, retries=retries)
    ips = expand_network(cidr)
    semaphore = asyncio.Semaphore(concurrency)

    async def bounded(ip: str) -> HostResult:
        async with semaphore:
            return await pinger(ip)

    results = await asyncio.gather(*(bounded(ip) for ip in ips))
    # Sort numerically by IP rather than as strings ("10" before "9").
    return sorted(results, key=lambda r: ipaddress.ip_address(r.ip))
