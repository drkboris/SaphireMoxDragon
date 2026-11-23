from netwatch.enrich import parse_nmap_xml
from netwatch.models import HostResult
from netwatch.neighbors import apply_neighbors, load_mac_prefixes, lookup_vendor, parse_ip_neigh

NEIGH_OUTPUT = """\
192.168.4.1 dev wlp2s0 lladdr aa:bb:cc:00:11:22 REACHABLE
192.168.4.47 dev wlp2s0 lladdr 3c:2a:f4:01:02:03 STALE
192.168.4.99 dev wlp2s0  FAILED
fe80::1 dev wlp2s0 lladdr aa:bb:cc:00:11:22 router STALE
"""


def test_parse_ip_neigh_skips_failed_and_ipv6():
    assert parse_ip_neigh(NEIGH_OUTPUT) == {
        "192.168.4.1": "AA:BB:CC:00:11:22",
        "192.168.4.47": "3C:2A:F4:01:02:03",
    }


def test_load_prefixes_and_lookup(tmp_path):
    f = tmp_path / "prefixes"
    f.write_text("# comment\n3C2AF4 Brother Industries\n001A2B Example Corp\n")
    prefixes = load_mac_prefixes(f)
    assert lookup_vendor("3C:2A:F4:01:02:03", prefixes) == "Brother Industries"
    assert lookup_vendor("00:11:22:33:44:55", prefixes) is None  # unknown prefix


def test_lookup_vendor_flags_randomized_mac():
    # 0x02 bit set in first byte: locally administered / private address
    assert lookup_vendor("DA:A1:19:00:00:01", {}) == "(randomized MAC)"


def test_apply_neighbors_fills_only_missing_fields():
    hosts = [
        HostResult("192.168.4.47", True, 1.0),
        HostResult("192.168.4.200", True, 1.0),  # routed or unknown, not in table
        HostResult("192.168.4.1", True, 1.0, mac="AA:AA:AA:AA:AA:AA", vendor="Kept"),
    ]
    neighbors = {"192.168.4.47": "3C:2A:F4:01:02:03", "192.168.4.1": "BB:BB:BB:BB:BB:BB"}
    apply_neighbors(hosts, neighbors, {"3C2AF4": "Brother Industries"})
    assert (hosts[0].mac, hosts[0].vendor) == ("3C:2A:F4:01:02:03", "Brother Industries")
    assert hosts[1].mac is None
    assert (hosts[2].mac, hosts[2].vendor) == ("AA:AA:AA:AA:AA:AA", "Kept")  # not overwritten


DETAIL_XML = """<nmaprun><host>
  <address addr="192.168.4.47" addrtype="ipv4"/>
  <ports>
    <port protocol="tcp" portid="80"><state state="open"/>
      <service name="http" product="Embedded HTTPD" version="1.0" method="probed"/>
      <script id="http-title" output="Brother HL-L2350DW series&#10;second line"/>
    </port>
    <port protocol="tcp" portid="443"><state state="open"/>
      <service name="https" method="probed"/>
      <script id="ssl-cert" output="...">
        <table key="subject"><elem key="commonName">BRW3C2AF4.local</elem></table>
      </script>
    </port>
    <port protocol="tcp" portid="9999"><state state="open"/>
      <service name="abyss" method="table"/>
    </port>
  </ports>
</host></nmaprun>"""


def test_parse_service_details_title_cert_and_guess_marker():
    info = parse_nmap_xml(DETAIL_XML)
    assert info["open_ports"] == [
        "80/http (Embedded HTTPD 1.0)",
        "443/https",
        "9999/abyss?",  # '?' = guessed from the port number only
    ]
    assert info["http_title"] == "Brother HL-L2350DW series"  # first line only
    assert info["tls_name"] == "BRW3C2AF4.local"
