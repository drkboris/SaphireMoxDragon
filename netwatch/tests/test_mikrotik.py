from netwatch.cli import build_parser, cmd_mikrotik
from netwatch.mikrotik import apply_router_data, parse_arp, parse_leases, parse_terse
from netwatch.models import HostResult
from netwatch.storage import build_run_record, load_latest, save_run

# Lines follow the real RouterOS 7.18 terse format; names are made up.
LEASES = """\
 0 D address=192.168.7.253 mac-address=40:CA:63:32:1F:CA address-lists= server=Wireless DHCP Network dhcp-option= status=bound expires-after=24m19s last-seen=5m41s active-address=192.168.7.253 active-mac-address=40:CA:63:32:1F:CA active-server=Wireless DHCP Network host-name=Samsung-Microwave
 5 D address=192.168.7.228 mac-address=D4:AD:FC:B9:DD:0C address-lists= server=Wireless DHCP Network dhcp-option= status=bound expires-after=17m40s last-seen=12m20s active-address=192.168.7.228 active-mac-address=D4:AD:FC:B9:DD:0C active-server=Wireless DHCP Network
 6   comment=Test Tablet address=192.168.7.242 mac-address=5A:35:7B:D2:C2:EB client-id=1:5a:35:7b:d2:c2:eb address-lists= server=Wireless DHCP Network dhcp-option= status=bound expires-after=24m54s last-seen=5m6s active-address=192.168.7.242 active-mac-address=5A:35:7B:D2:C2:EB active-client-id=1:5a:35:7b:d2:c2:eb active-server=Wireless DHCP Network host-name=Galaxy-Tab-A8 class-id=android-dhcp-14
 8   comment=Old Tablet address=192.168.7.230 mac-address=4A:17:FD:8B:CC:FE client-id=1:4a:17:fd:8b:cc:fe address-lists= server=Wireless DHCP Network dhcp-option= status=waiting last-seen=30w3d19h24m12s host-name=Old-Tab
20 D address=192.168.5.86 mac-address=4C:B9:EA:DE:71:62 address-lists= server=Wireless DHCP Network dhcp-option= status=bound expires-after=23m31s last-seen=6m29s active-address=192.168.5.86 active-mac-address=4C:B9:EA:DE:71:62 active-server=Wireless DHCP Network class-id=udhcp 1.20.2
31 D address=192.168.4.71 mac-address=2C:8D:48:91:B0:00 address-lists= server=Wireless DHCP Network dhcp-option= status=bound expires-after=24m43s last-seen=5m17s active-address=192.168.4.71 active-mac-address=2C:8D:48:91:B0:00 active-server=Wireless DHCP Network host-name=Eufy Device
"""

ARP = """\
 12 D  address=10.1.50.2 mac-address=AA:BB:CC:DD:EE:FF interface=server published=no status=reachable
 13 D  address=10.1.50.99 interface=server published=no status=failed
"""


def test_parse_terse_handles_flags_empty_values_and_spaces():
    rows = parse_terse(LEASES)
    first = rows[0]
    assert first["address"] == "192.168.7.253"
    assert first["address-lists"] == ""  # empty value
    assert first["server"] == "Wireless DHCP Network"  # spaces in value
    assert first["host-name"] == "Samsung-Microwave"
    assert rows[2]["comment"] == "Test Tablet"  # line with no flag letter
    assert rows[4]["class-id"] == "udhcp 1.20.2"  # space in last value
    assert rows[5]["host-name"] == "Eufy Device"


def test_parse_terse_ignores_prompts_and_blank_lines():
    assert parse_terse("\nuser@host:~$ ssh router\npassword: \n") == []


def test_parse_leases_keeps_only_bound_and_picks_fields():
    leases = parse_leases(LEASES)
    assert "192.168.7.230" not in leases  # status=waiting
    assert leases["192.168.7.253"]["hostname"] == "Samsung-Microwave"
    assert leases["192.168.7.228"]["hostname"] is None  # device sent no name
    tablet = leases["192.168.7.242"]
    assert tablet["comment"] == "Test Tablet"
    assert tablet["dhcp_class"] == "android-dhcp-14"
    assert tablet["mac"] == "5A:35:7B:D2:C2:EB"
    assert leases["192.168.5.86"]["dhcp_class"] == "udhcp 1.20.2"


def test_parse_arp_skips_failed_entries():
    assert parse_arp(ARP) == {"10.1.50.2": "AA:BB:CC:DD:EE:FF"}


def test_apply_router_data_fills_blanks_and_never_overwrites():
    hosts = [
        HostResult("192.168.7.253", True, 1.0),
        HostResult("192.168.7.242", True, 1.0, hostname="kept-name"),
        HostResult("10.1.50.2", True, 1.0),  # no lease, but in ARP
        HostResult("10.1.50.77", True, 1.0),  # unknown to the router
    ]
    prefixes = {"40CA63": "Example Vendor"}
    matched = apply_router_data(hosts, parse_leases(LEASES), parse_arp(ARP), prefixes)

    assert matched == 2
    assert hosts[0].hostname == "Samsung-Microwave"
    assert hosts[0].mac == "40:CA:63:32:1F:CA"
    assert hosts[0].vendor == "Example Vendor"
    assert hosts[1].hostname == "kept-name"  # existing value preserved
    assert hosts[1].comment == "Test Tablet"
    assert hosts[1].vendor == "(randomized MAC)"  # 0x5A has the private-address bit set
    assert hosts[2].mac == "AA:BB:CC:DD:EE:FF"  # from ARP
    assert hosts[3].mac is None


def test_cmd_mikrotik_updates_saved_run(tmp_path, monkeypatch):
    results = {"wireless": [HostResult("192.168.7.253", True, 2.0)]}
    save_run(build_run_record({"wireless": "192.168.4.0/22"}, results), tmp_path)

    def fake_router(host, user, command, key=None):
        if "ip address" in command:
            return ADDRS
        return LEASES if "lease" in command else ARP

    monkeypatch.setattr("netwatch.cli.run_router_command", fake_router)
    args = build_parser().parse_args(
        ["mikrotik", "--router", "r", "--user", "u", "--data-dir", str(tmp_path)]
    )
    assert cmd_mikrotik(args) == 0

    latest = load_latest(tmp_path)
    hosts = latest["networks"]["wireless"]["hosts"]
    host = next(h for h in hosts if h["ip"] == "192.168.7.253")
    assert host["hostname"] == "Samsung-Microwave"
    assert host["source"] == ["ping", "dhcp"]
    # leases that did not answer ping were added, flagged as router-only
    tablet = next(h for h in hosts if h["ip"] == "192.168.7.242")
    assert tablet["alive"] is False and tablet["source"] == ["dhcp"]
    # the original run file was updated too, not just latest.json
    run_file = tmp_path / latest["run_file"]
    assert "Samsung-Microwave" in run_file.read_text()


def test_cmd_mikrotik_without_saved_sweep(tmp_path, capsys):
    args = build_parser().parse_args(["mikrotik", "--data-dir", str(tmp_path)])
    assert cmd_mikrotik(args) == 2
    assert "Run `sweep` first" in capsys.readouterr().out


def test_parse_arp_real_router_lines_with_two_letter_flags():
    # Captured from RouterOS 7.18: flags are "DC" (dynamic, complete).
    real = (
        "   0 DC address=192.168.7.254 mac-address=C8:E3:06:2E:74:0D interface=wireless "
        "published=no status=reachable \n"
        "   1 DC address=192.168.4.29 mac-address=98:03:8E:00:73:4B interface=wireless "
        "published=no status=stale \n"
    )
    assert parse_arp(real) == {
        "192.168.7.254": "C8:E3:06:2E:74:0D",
        "192.168.4.29": "98:03:8E:00:73:4B",
    }


def test_router_only_hosts_dedupe_by_mac_and_pick_the_right_network():
    from netwatch.mikrotik import add_router_only_hosts

    # Pinged at .253; the router now says the same MAC holds .100 (address changed).
    pinged = HostResult("192.168.7.253", True, 1.0, mac="40:CA:63:32:1F:CA", source=["ping"])
    networks = {
        "wireless": ("192.168.4.0/22", [pinged]),
        "work": ("10.1.20.0/24", []),
    }
    leases = {
        "192.168.7.100": {"mac": "40:CA:63:32:1F:CA", "hostname": "x", "comment": None, "dhcp_class": None},
        "192.168.4.71": {"mac": "2C:8D:48:91:B0:00", "hostname": "Eufy Device", "comment": None, "dhcp_class": None},
        "10.1.20.20": {"mac": "AC:1A:3D:D4:A8:77", "hostname": "laptop", "comment": None, "dhcp_class": "MSFT 5.0"},
        "172.16.0.5": {"mac": None, "hostname": "odd", "comment": None, "dhcp_class": None},
    }  # fmt: skip
    added, merged = add_router_only_hosts(networks, leases, {})

    assert (added, merged) == (3, 1)
    assert pinged.alt_ips == ["192.168.7.100"]  # same device, not listed twice
    assert [h.ip for h in networks["wireless"][1]] == ["192.168.4.71", "192.168.7.253"]
    assert networks["work"][1][0].hostname == "laptop"
    assert networks["unscanned"][1][0].ip == "172.16.0.5"  # outside every scanned range


def test_running_mikrotik_twice_does_not_duplicate(tmp_path, monkeypatch):
    results = {"wireless": [HostResult("192.168.7.253", True, 2.0, source=["ping"])]}
    save_run(build_run_record({"wireless": "192.168.4.0/22"}, results), tmp_path)
    monkeypatch.setattr(
        "netwatch.cli.run_router_command", lambda h, u, c, key=None: ADDRS if "ip address" in c else (LEASES if "lease" in c else ARP)
    )
    args = build_parser().parse_args(
        ["mikrotik", "--router", "r", "--user", "u", "--data-dir", str(tmp_path)]
    )
    cmd_mikrotik(args)
    first = len(load_latest(tmp_path)["networks"]["wireless"]["hosts"])
    cmd_mikrotik(args)
    assert len(load_latest(tmp_path)["networks"]["wireless"]["hosts"]) == first


ADDRS = (
    " 0   address=10.1.50.1/24 network=10.1.50.0 interface=server\n"
    " 1 D address=192.168.4.1/22 network=192.168.4.0 interface=wireless\n"
)


def test_router_addresses_named_router():
    from netwatch.mikrotik import label_router_hosts, parse_router_addresses

    ips = parse_router_addresses(ADDRS)
    assert ips == {"10.1.50.1", "192.168.4.1"}
    hosts = [HostResult(ip="10.1.50.1", alive=True), HostResult(ip="10.1.50.2", alive=True),
             HostResult(ip="192.168.4.1", alive=True, hostname="_gateway")]
    assert label_router_hosts(hosts, ips) == 2
    assert hosts[0].hostname == "router" and hosts[2].hostname == "router"
    assert hosts[1].hostname is None


def test_router_label_keeps_real_names():
    from netwatch.mikrotik import label_router_hosts

    h = HostResult(ip="10.1.1.1", alive=True, hostname="mybox")
    assert label_router_hosts([h], {"10.1.1.1"}) == 0 and h.hostname == "mybox"


def test_ssh_command_with_key_is_non_interactive():
    from netwatch.mikrotik import build_ssh_command

    cmd = build_ssh_command("r", "netwatch", "/ip arp print", key="/k/id")
    assert cmd[cmd.index("-i") + 1] == "/k/id"
    assert "BatchMode=yes" in cmd and "IdentitiesOnly=yes" in cmd
    assert "ControlMaster=auto" not in cmd
    assert cmd[-2:] == ["netwatch@r", "/ip arp print"]


def test_ssh_command_without_key_keeps_password_flow():
    from netwatch.mikrotik import build_ssh_command

    cmd = build_ssh_command("r", "admin", "x")
    assert "-i" not in cmd and "BatchMode=yes" not in cmd
    assert "ControlMaster=auto" in cmd


def test_key_from_config_reaches_router_call(tmp_path, monkeypatch):
    import netwatch.cli as cli

    seen = []
    monkeypatch.setattr(
        cli, "run_router_command", lambda h, u, c, key=None: seen.append(key) or ""
    )
    cfg = tmp_path / "n.toml"
    cfg.write_text('[mikrotik]\nhost="r"\nuser="u"\nkey="~/.ssh/k"\n')
    (tmp_path / "latest.json").write_text('{"networks": {}}')
    args = cli.build_parser().parse_args(
        ["mikrotik", "--config", str(cfg), "--data-dir", str(tmp_path)]
    )
    cli.cmd_mikrotik(args)
    assert seen and seen[0] == "~/.ssh/k"
