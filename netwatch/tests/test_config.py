import pytest

from netwatch.config import load_networks, resolve_targets


def write_config(tmp_path, body: str):
    path = tmp_path / "networks.toml"
    path.write_text(body)
    return path


def test_load_networks(tmp_path):
    path = write_config(tmp_path, '[networks]\nfamily = "10.1.10.0/24"\ndmz = "10.1.99.0/24"\n')
    assert load_networks(path) == {"family": "10.1.10.0/24", "dmz": "10.1.99.0/24"}


def test_load_networks_rejects_bad_cidr(tmp_path):
    path = write_config(tmp_path, '[networks]\nbroken = "10.1.10.0/99"\n')
    with pytest.raises(ValueError, match="broken"):
        load_networks(path)


NETS = {"family": "10.1.10.0/24", "dmz": "10.1.99.0/24"}


def test_resolve_defaults_to_all():
    assert resolve_targets([], NETS) == NETS


def test_resolve_by_name_and_cidr():
    result = resolve_targets(["dmz", "192.168.5.0/24"], NETS)
    assert result == {"dmz": "10.1.99.0/24", "192.168.5.0/24": "192.168.5.0/24"}


def test_resolve_unknown_name():
    with pytest.raises(ValueError, match="nope"):
        resolve_targets(["nope"], NETS)
