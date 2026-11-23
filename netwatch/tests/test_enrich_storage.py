import asyncio
import json

from netwatch.enrich import enrich_hosts, parse_nmap_xml
from netwatch.models import HostResult
from netwatch.storage import build_run_record, load_latest, save_run

SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.1.10.5" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Raspberry Pi"/>
    <hostnames><hostname name="pi.home.lan" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
      <port protocol="tcp" portid="23"><state state="closed"/><service name="telnet"/></port>
    </ports>
    <os><osmatch name="Linux 5.X" accuracy="95"/></os>
  </host>
</nmaprun>"""


def test_parse_nmap_xml_full():
    info = parse_nmap_xml(SAMPLE_XML)
    assert info["hostname"] == "pi.home.lan"
    assert info["mac"] == "AA:BB:CC:DD:EE:FF"
    assert info["vendor"] == "Raspberry Pi"
    assert info["open_ports"] == ["22/ssh", "80/http"]  # closed port excluded
    assert info["os_guess"] == "Linux 5.X"


def test_parse_nmap_xml_handles_garbage():
    assert parse_nmap_xml("") == {}
    assert parse_nmap_xml("not xml at all") == {}


def test_enrich_hosts_only_touches_live_hosts():
    calls = []

    async def fake_runner(ip: str) -> str:
        calls.append(ip)
        return SAMPLE_XML

    hosts = [HostResult("10.1.10.5", True, 1.0), HostResult("10.1.10.6", False)]
    asyncio.run(enrich_hosts(hosts, runner=fake_runner))
    assert calls == ["10.1.10.5"]
    assert hosts[0].hostname == "pi.home.lan"
    assert hosts[1].hostname is None


def test_save_and_load_latest(tmp_path):
    results = {"dmz": [HostResult("10.1.99.2", True, 0.8), HostResult("10.1.99.3", False)]}
    record = build_run_record({"dmz": "10.1.99.0/24"}, results)
    assert record["networks"]["dmz"]["scanned"] == 2
    assert len(record["networks"]["dmz"]["hosts"]) == 1  # only live hosts stored

    run_path = save_run(record, tmp_path)
    assert run_path.exists()
    assert load_latest(tmp_path) == json.loads(run_path.read_text())


def test_load_latest_when_nothing_saved(tmp_path):
    assert load_latest(tmp_path) is None
