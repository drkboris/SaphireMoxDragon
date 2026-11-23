from netwatch import neighbors
from netwatch.enrich import parse_nmap_xml, tidy_title
from netwatch.models import HostResult
from netwatch.neighbors import apply_neighbors, load_mac_prefixes
from netwatch.report import format_inventory

IEEE_SAMPLE = (
    "OUI/MA-L\t\t\tOrganization\n"
    "company_id\t\t\tOrganization\n"
    "\t\t\t\tAddress\n"
    "\n"
    "00-00-0C   (hex)\t\tCisco Systems, Inc\n"
    "00000C     (base 16)\t\tCisco Systems, Inc\n"
    "\t\t\t\t170 WEST TASMAN DRIVE\n"
    "\t\t\t\tSAN JOSE  CA  95134\n"
    "\n"
    "04-F4-1C   (hex)\t\tMikroTik\n"
    "04F41C     (base 16)\t\tMikroTik\n"
    "\n"
    "D4-AD-FC   (hex)\t\tPrivate\n"
    "D4ADFC     (base 16)\t\tPrivate\n"
)


def test_load_ieee_format_skips_private_and_address_lines(tmp_path):
    f = tmp_path / "oui.txt"
    f.write_text(IEEE_SAMPLE)
    assert load_mac_prefixes(f) == {"00000C": "Cisco Systems, Inc", "04F41C": "MikroTik"}


def test_default_sources_prefer_ieee_and_fall_back_to_nmap(tmp_path, monkeypatch):
    ieee = tmp_path / "oui.txt"
    ieee.write_text(IEEE_SAMPLE)
    nmap = tmp_path / "nmap-mac-prefixes"
    nmap.write_text("04F41C Old Name\nD4ADFC Real Vendor Inc\n")
    monkeypatch.setattr(neighbors, "PREFIX_FILES", [tmp_path / "missing.txt", ieee, nmap])

    prefixes = load_mac_prefixes()
    assert prefixes["04F41C"] == "MikroTik"  # IEEE file wins over nmap's list
    assert prefixes["D4ADFC"] == "Real Vendor Inc"  # IEEE says Private, nmap fills the gap


def test_apply_neighbors_upgrades_private_vendor():
    host = HostResult("192.168.7.228", True, 1.0, mac="D4:AD:FC:B9:DD:0C", vendor="Private")
    apply_neighbors([host], {}, {"D4ADFC": "Real Vendor Inc"})
    assert host.vendor == "Real Vendor Inc"


def test_tidy_title():
    assert tidy_title("Did not follow redirect to https://10.0.0.1/") == "redirects to https://10.0.0.1/"
    assert tidy_title("Pi-hole") == "Pi-hole"
    assert tidy_title(None) is None


def _xml(*ports):
    return f"<nmaprun><host><ports>{''.join(ports)}</ports></host></nmaprun>"


def _port(portid, title):
    return (
        f'<port protocol="tcp" portid="{portid}"><state state="open"/>'
        f'<service name="http" method="probed"/>'
        f'<script id="http-title" output="{title}"/></port>'
    )


def test_redirect_is_only_a_fallback_title():
    only_redirect = parse_nmap_xml(_xml(_port(80, "Did not follow redirect to https://h/start.html")))
    assert only_redirect["http_title"] == "redirects to https://h/start.html"

    both = parse_nmap_xml(_xml(_port(80, "Did not follow redirect to https://h/"), _port(443, "Real Title")))
    assert both["http_title"] == "Real Title"  # a real title beats the redirect note


RECORD = {
    "timestamp": "2026-11-21T21:29:09",
    "networks": {
        "wireless": {
            "cidr": "192.168.4.0/22",
            "hosts": [
                {"ip": "192.168.7.9", "alive": False, "hostname": "iPhone", "comment": None,
                 "mac": "A2:34:D2:30:44:4C", "vendor": "(randomized MAC)", "open_ports": [],
                 "http_title": None, "tls_name": None, "dhcp_class": None},
                {"ip": "192.168.4.47", "alive": True, "hostname": "EPSON471D6C", "comment": None,
                 "mac": "68:55:D4:47:1D:6C", "vendor": "Seiko Epson", "open_ports": ["515/printer"],
                 "http_title": "Did not follow redirect to https://192.168.4.47/",
                 "tls_name": "EPSON471D6C", "dhcp_class": None},
            ],
        },
        "dmz": {"cidr": "10.1.99.0/24", "hosts": []},
    },
}  # fmt: skip


def test_format_inventory_sorts_by_ip_and_tidies_titles():
    out = format_inventory(RECORD)
    assert out.index("192.168.4.47") < out.index("192.168.7.9")  # numeric IP order
    assert "wireless (192.168.4.0/22): 2 devices, 1 answered ping" in out
    assert "web: redirects to https://192.168.4.47/" in out
    assert "Did not follow" not in out


def test_format_inventory_filters_and_wide_mode():
    assert "192.168.7.9" not in format_inventory(RECORD, find="epson")
    assert "dmz" not in format_inventory(RECORD, find="epson")  # empty networks are hidden
    assert "dmz" not in format_inventory(RECORD, networks=["wireless"])
    wide = format_inventory(RECORD, wide=True)
    assert "68:55:D4:47:1D:6C" in wide and "MAC" in wide
    assert "68:55:D4:47:1D:6C" not in format_inventory(RECORD)
