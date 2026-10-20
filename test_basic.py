"""Offline tests: catalog schema, compose templates, safe defaults. No Docker required."""
import json
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import owasp_lab_manager as m  # noqa: E402


def test_catalog_valid():
    data = json.loads((ROOT / "catalog.json").read_text())
    ids = set()
    for e in data["apps"]:
        assert m.validate_app(e) == [], e["id"]
        assert e["id"] not in ids
        ids.add(e["id"])
    assert {"juice-shop", "webgoat", "webwolf", "crapi", "shepherd", "mutillidae"} <= ids


def test_aliases_resolve():
    apps, problems = m.load_catalog()
    assert problems == []
    by = {a.id: a for a in apps}
    assert by["webwolf"].alias_of in by


@pytest.mark.parametrize("name", ["juice-shop", "webgoat"])
def test_templates_are_safe(name):
    doc = yaml.safe_load((ROOT / "compose" / f"{name}.yml").read_text())
    for svc in doc["services"].values():
        assert not svc.get("privileged")
        assert "volumes" not in svc, "no host mounts expected"
        assert all("docker.sock" not in str(v) for v in svc.get("volumes", []))
        for port in svc["ports"]:
            assert port.startswith("${LAB_BIND:-127.0.0.1}:"), port


def test_url_building_and_env(monkeypatch, tmp_path):
    monkeypatch.setattr(m, "LAB_HOME", tmp_path)
    monkeypatch.setattr(m, "STATE_FILE", tmp_path / "state.json")
    lab = m.Lab(m.parse_args([]))
    wg = lab.by_id["webgoat"]
    assert lab.url_for(wg, wg.ports[0]) == "http://127.0.0.1:8080/WebGoat"
    sh = lab.by_id["shepherd"]
    env = lab.app_env(sh)
    assert env["HTTP_PORT"] == "127.0.0.1:8080"          # localhost-bound override
    assert lab.app_env(lab.by_id["crapi"])["LISTEN_IP"] == "127.0.0.1"


def test_port_in_use_detects_listener():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    assert m.port_in_use("127.0.0.1", s.getsockname()[1])
    s.close()


def test_http_probe_refuses_non_loopback():
    good, detail = m.http_probe("http://example.com/")
    assert not good and "localhost" in detail


def test_cleanup_only_targets_prefix(monkeypatch, tmp_path):
    monkeypatch.setattr(m, "LAB_HOME", tmp_path)
    monkeypatch.setattr(m, "STATE_FILE", tmp_path / "state.json")
    lab = m.Lab(m.parse_args(["--dry-run"]))
    calls = []
    monkeypatch.setattr(lab, "run", lambda cmd, **kw: calls.append(cmd) or m.Result(0, ""))
    lab._remove_networks(["someone-elses-project", "owasplab-juice-shop"])
    assert all("owasplab-" in " ".join(c) for c in calls)
