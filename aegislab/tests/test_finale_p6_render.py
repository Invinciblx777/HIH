"""Finale P6 task R: the public read-only demo on Render.

R1  render.yaml at the repo root deploys aegislab/app.py read-only, with the settings the task fixes.
R2  the per-client verifier limit reads only the header named by AEGIS_CLIENT_IP_HEADER when it is set (Render:
    CF-Connecting-IP, which its edge overwrites). A forged X-Real-IP or X-Forwarded-For then cannot open a new bucket, a
    missing or malformed value lands in one shared bucket, and the global limit still applies. Unset, the P1 behaviour is
    unchanged (test_finale_p1_public_demo.py covers it).

Container-free: FastAPI TestClient against the real console app.
"""
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
REPO = ROOT.parent
sys.path.insert(0, str(ROOT))

from aegis import console, lab_session, runs, store  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

HOST = "aegislab-demo.example"  # placeholder host: the real Render URL is not known when these tests are written
CF = "cf-connecting-ip"


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "VAR", tmp_path / "var")
    monkeypatch.setattr(runs, "_signer", None)
    for k in ("AEGIS_DEMO_MODE", "AEGIS_CONSOLE_LAUNCH_CODE", "AEGIS_CONSOLE_HOSTS", "VERCEL", "RENDER",
              console.CLIENT_IP_HEADER_ENV):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("AEGIS_PUBLIC_DEMO", "1")
    lab_session.reset()
    console.reset_public_limits()
    yield
    lab_session.reset()
    console.reset_public_limits()


@pytest.fixture
def render(monkeypatch):
    monkeypatch.setenv(console.CLIENT_IP_HEADER_ENV, "CF-Connecting-IP")
    return TestClient(console.app, base_url="https://" + HOST)


def h(**extra):
    return {"Origin": "https://" + HOST, "Sec-Fetch-Site": "same-origin", **{k.replace("_", "-"): v for k, v in extra.items()}}


def verify(client, headers):
    return client.post("/api/lab/bundles/NOPE/verify", headers=headers).status_code  # 404: counted by the limit, cheap


# ------------------------------------------------------------------ R2: client IP behind Render
def test_P6R01_forged_forwarding_headers_do_not_open_a_new_bucket(render, monkeypatch):
    monkeypatch.setattr(console, "PUBLIC_RATE_CLIENT", (3, 60.0))
    for i in range(3):
        assert verify(render, h(**{CF: "198.51.100.7", "X-Real-IP": "192.0.2.%d" % i})) == 404
    for forged in ({"X-Real-IP": "203.0.113.50"}, {"X-Forwarded-For": "203.0.113.51, 10.0.0.1"},
                   {"X-Forwarded-For": "203.0.113.52", "X-Real-IP": "203.0.113.53", "True-Client-IP": "203.0.113.54"}):
        assert verify(render, h(**{CF: "198.51.100.7"}, **forged)) == 429, forged


def test_P6R02_another_proxy_set_address_is_another_bucket(render, monkeypatch):
    monkeypatch.setattr(console, "PUBLIC_RATE_CLIENT", (2, 60.0))
    for _ in range(2):
        assert verify(render, h(**{CF: "198.51.100.7"})) == 404
    assert verify(render, h(**{CF: "198.51.100.7"})) == 429
    assert verify(render, h(**{CF: "2001:db8::7"})) == 404
    assert verify(render, h(**{CF: "2001:DB8:0::7"})) == 404  # same address, normalised: same bucket
    assert verify(render, h(**{CF: "2001:db8::7"})) == 429


@pytest.mark.parametrize("bad", [None, "", "not-an-ip", "198.51.100.7, 10.0.0.1", "198.51.100.7:443", "x" * 200])
def test_P6R03_missing_or_malformed_value_shares_one_bucket(render, monkeypatch, bad):
    monkeypatch.setattr(console, "PUBLIC_RATE_CLIENT", (2, 60.0))
    extra = {} if bad is None else {CF: bad}
    for i in range(2):  # the P1 headers are ignored, so they cannot spread these requests over buckets
        assert verify(render, h(**extra, **{"X-Real-IP": "192.0.2.%d" % i, "X-Forwarded-For": "192.0.2.%d" % i})) == 404
    assert verify(render, h(**{"X-Real-IP": "192.0.2.99"})) == 429  # no header at all: the same shared bucket
    assert verify(render, h(**{CF: "198.51.100.8"})) == 404        # a well-formed address is unaffected


def test_P6R04_global_limit_still_applies(render, monkeypatch):
    monkeypatch.setattr(console, "PUBLIC_RATE_GLOBAL", (4, 60.0))
    for i in range(4):
        assert verify(render, h(**{CF: "192.0.2.%d" % i})) == 404
    r = render.post("/api/lab/bundles/NOPE/verify", headers=h(**{CF: "192.0.2.200"}))
    assert r.status_code == 429 and r.json()["detail"] == console.PUBLIC_RATE_MESSAGE and r.headers["retry-after"] == "60"


@pytest.mark.parametrize("value,expected", [("CF-Connecting-IP", CF), ("  x-client-ip ", "x-client-ip"), ("peer", "peer"),
                                            ("PEER", "peer"), ("bad header", "peer"), ("x_real_ip", "peer"), ("", None)])
def test_P6R05_header_setting_is_parsed_strictly(monkeypatch, value, expected):
    monkeypatch.setenv(console.CLIENT_IP_HEADER_ENV, value)
    assert console._client_ip_header() == expected


def test_P6R06_peer_setting_uses_only_the_tcp_peer(monkeypatch):
    monkeypatch.setenv(console.CLIENT_IP_HEADER_ENV, "peer")
    monkeypatch.setattr(console, "PUBLIC_RATE_CLIENT", (2, 60.0))
    c = TestClient(console.app, base_url="https://" + HOST)
    for i in range(2):
        assert verify(c, h(**{CF: "192.0.2.%d" % i, "X-Real-IP": "192.0.2.%d" % i})) == 404
    assert verify(c, h(**{CF: "192.0.2.9", "X-Real-IP": "192.0.2.9"})) == 429


def test_P6R07_unset_keeps_the_p1_header_chain():
    c = TestClient(console.app, base_url="https://" + HOST)
    r = c.get("/api/lab/status")
    assert r.json()["public_demo_rate_limit"]["client_ip_from"] == "x-real-ip, then x-forwarded-for"


def test_P6R08_status_names_the_configured_header(render):
    st = render.get("/api/lab/status").json()
    assert st["public_demo"] is True and st["public_demo_rate_limit"]["client_ip_from"] == CF
    assert st["public_demo_rate_limit"]["per_client"]["requests"] == 10 and st["public_demo_rate_limit"]["global"]["requests"] == 60


def test_P6R09_writes_are_still_refused_with_the_header_set(render):
    assert render.get("/session/start", params={"code": "x"}, follow_redirects=False).status_code == 403
    r = render.post("/api/lab/runs", json={"stop_after": "created"}, headers=h(**{CF: "198.51.100.7"}))
    assert r.status_code == 403 and r.json()["detail"].startswith("public read-only demo:")


def _app_env(extra):
    env = {k: v for k, v in os.environ.items() if k not in ("RENDER", console.CLIENT_IP_HEADER_ENV, "AEGIS_PUBLIC_DEMO")}
    env.update(extra, AEGIS_VAR=os.environ.get("TMPDIR", "/tmp") + "/aegis-p6-apptest", PYTHONDONTWRITEBYTECODE="1")
    code = ("import os, app; print(os.environ.get('AEGIS_PUBLIC_DEMO'), os.environ.get('AEGIS_CLIENT_IP_HEADER'))")
    return subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env, capture_output=True, text=True, timeout=60)


@pytest.mark.parametrize("extra,expected", [({"RENDER": "true"}, "1 cf-connecting-ip"),
                                            ({"RENDER": "true", "AEGIS_CLIENT_IP_HEADER": "peer"}, "1 peer"),
                                            ({}, "1 None"),  # Vercel or local: the P1 chain
                                            ({"AEGIS_PUBLIC_DEMO": "0"}, "1 None")])
def test_P6R10_app_entry_point(extra, expected):
    r = _app_env(extra)
    assert r.returncode == 0, r.stderr
    assert r.stdout.split("\n")[-2] == expected


@pytest.mark.parametrize("value,present", [("198.51.100.7", True), ("2001:db8::7", True), (None, False), ("", False),
                                           ("not-an-ip", False), ("198.51.100.7, 10.0.0.1", False), ("198.51.100.7:443", False)])
def test_P6R14_status_says_whether_the_client_ip_header_arrived_without_echoing_it(render, value, present):
    hdrs = {"X-Real-IP": "192.0.2.77", "X-Forwarded-For": "192.0.2.78"}  # forged P1 headers never make it true
    if value is not None:
        hdrs[CF] = value
    r = render.get("/api/lab/status", headers=hdrs)
    assert r.json()["public_demo_rate_limit"]["client_ip_header_present"] is present
    for leak in ("198.51.100.7", "2001:db8::7", "192.0.2.77", "192.0.2.78", "not-an-ip"):
        assert leak not in r.text


@pytest.mark.parametrize("env,hdrs,present", [(None, {"X-Real-IP": "192.0.2.5"}, True),
                                              (None, {"X-Forwarded-For": "192.0.2.6, 10.0.0.1"}, True),
                                              (None, {}, False),  # unset and no proxy header: the TCP peer does not count
                                              ("peer", {}, False),  # TestClient's peer is "testclient", not an address
                                              ("x-client-ip", {"X-Client-IP": "192.0.2.7"}, True)])
def test_P6R15_present_flag_follows_the_configured_source(monkeypatch, env, hdrs, present):
    if env:
        monkeypatch.setenv(console.CLIENT_IP_HEADER_ENV, env)
    c = TestClient(console.app, base_url="https://" + HOST)
    st = c.get("/api/lab/status", headers=hdrs).json()
    assert st["public_demo_rate_limit"]["client_ip_header_present"] is present
    assert "192.0.2." not in c.get("/api/lab/status", headers=hdrs).text


def test_P6R16_present_flag_is_absent_outside_public_mode(monkeypatch):
    monkeypatch.delenv("AEGIS_PUBLIC_DEMO")
    st = TestClient(console.app, base_url="http://127.0.0.1:8400").get("/api/lab/status").json()
    assert "public_demo_rate_limit" not in st and "public_demo" not in st


# ------------------------------------------------------------------ R1: the blueprint
def _blueprint():
    return (REPO / "render.yaml").read_text()


def _field(text, key):
    m = re.search(r"^\s*-?\s*%s:\s*(.+?)\s*(#.*)?$" % re.escape(key), text, re.M)
    assert m, key
    return m.group(1)


def test_P6R11_blueprint_has_the_fixed_settings():
    t = _blueprint()
    assert t.count("- type:") == 1 and _field(t, "type") == "web"
    want = {"runtime": "python", "rootDir": "aegislab", "region": "singapore", "branch": "main",
            "healthCheckPath": "/api/lab/status", "autoDeployTrigger": "commit",
            "buildCommand": "pip install -r requirements.txt -c constraints.txt"}
    for k, v in want.items():
        assert _field(t, k) == v, k
    start = _field(t, "startCommand")
    assert start.startswith("uvicorn app:app --host 0.0.0.0 --port $PORT --no-server-header")
    assert "--no-proxy-headers" in start and "forwarded-allow-ips" not in start
    assert _field(t, "plan") in ("free", "0.5c-512mb") and "spins down" in t.lower().replace("spin down", "spins down")
    assert not re.search(r"^\s*autoDeploy:", t, re.M)  # deprecated field; autoDeployTrigger replaces it


def test_P6R12_blueprint_sets_the_client_ip_header_and_a_tested_python():
    t = _blueprint()
    keys = re.findall(r"- key:\s*(\S+)", t)
    vals = re.findall(r"^\s+value:\s*(\S+)", t, re.M)
    env = dict(zip(keys, vals))
    assert env["AEGIS_CLIENT_IP_HEADER"].lower() == CF
    major_minor = re.fullmatch(r"(3)\.(\d+)\.\d+", env["PYTHON_VERSION"])
    assert major_minor and int(major_minor.group(2)) >= 12  # requires-python >=3.12, fully qualified as Render requires
    ci = (REPO / ".github/workflows/release-gates.yml").read_text()
    assert 'python-version: "%s.%s"' % major_minor.groups() in ci  # the same minor version the CI gates run


def test_P6R13_app_still_forces_public_mode_and_is_the_entry_point():
    src = (ROOT / "app.py").read_text()
    assert 'os.environ["AEGIS_PUBLIC_DEMO"] = "1"' in src and "from aegis.console import app  # noqa: E402,F401" in src
    assert _field(_blueprint(), "startCommand").split()[1] == "app:app"
