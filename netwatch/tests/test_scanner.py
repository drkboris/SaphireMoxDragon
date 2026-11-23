import asyncio

from netwatch.models import HostResult
from netwatch.scanner import expand_network, sweep


def test_expand_network_skips_network_and_broadcast():
    ips = expand_network("192.168.1.0/30")
    assert ips == ["192.168.1.1", "192.168.1.2"]


def test_sweep_uses_injected_pinger_and_sorts_numerically():
    async def fake_pinger(ip: str) -> HostResult:
        # pretend only .2 and .10 are alive
        alive = ip.endswith((".2", ".10"))
        return HostResult(ip=ip, alive=alive, rtt_ms=1.0 if alive else None)

    results = asyncio.run(sweep("10.0.0.0/28", pinger=fake_pinger))
    alive = [r.ip for r in results if r.alive]
    assert alive == ["10.0.0.2", "10.0.0.10"]  # .2 before .10, not string order


def test_ping_host_retries_after_a_missed_reply(monkeypatch):
    from netwatch import scanner

    replies = iter([None, 12.5])  # first attempt silent, second answers

    async def fake_once(ip, timeout_s):
        return next(replies)

    monkeypatch.setattr(scanner, "_ping_once", fake_once)
    result = asyncio.run(scanner.ping_host("10.0.0.5", retries=1))
    assert result.alive and result.rtt_ms == 12.5 and result.source == ["ping"]

    replies = iter([None])
    result = asyncio.run(scanner.ping_host("10.0.0.5", retries=0))
    assert not result.alive  # no retries means one attempt only
