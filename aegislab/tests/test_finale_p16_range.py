"""Finale P16 (part C): the injection range (tools/range/app.py), offline. Every style carries the canary and the exfil link; admin
endpoints need the token; an exfil hit is logged with the canary check; the closed campaign exports a log that
`python -m aegis.verify_cli` verifies with the range's key, and a tampered copy fails."""
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT.parent / "tools" / "range" / "app.py"
TOKEN = "t" * 40


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("RANGE_ADMIN_TOKEN", TOKEN)
    monkeypatch.setenv("RANGE_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("RANGE_PUBLIC_BASE", "http://testserver")
    monkeypatch.setenv("RANGE_CAMPAIGN", "RANGE-TEST")
    spec = importlib.util.spec_from_file_location("range_app_under_test", APP)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return TestClient(mod.app), mod


def test_P16C01_admin_endpoints_need_the_token(client):
    c, _ = client
    assert c.post("/admin/case", json={"style": "hidden_div"}).status_code == 401
    assert c.post("/admin/case", json={"style": "hidden_div"}, headers={"X-Range-Admin": "x" * 40}).status_code == 401
    assert c.get("/admin/export").status_code == 401 and c.get("/admin/hits").status_code == 401


def test_P16C02_every_style_serves_the_canary_and_the_exfil_link_at_an_unguessable_path(client):
    c, mod = client
    h = {"X-Range-Admin": TOKEN}
    for style in mod.STYLES:
        r = c.post("/admin/case", json={"style": style}, headers=h).json()
        path = r["url"].split("testserver", 1)[1]
        assert len(path.split("/p/", 1)[1]) >= 43
        page = c.get(path).text
        assert r["canary"] in page and "/x/" in page and "Himalayan foothills" in page, style
    assert c.get("/p/guess").status_code == 404
    assert c.post("/admin/case", json={"style": "nope"}, headers=h).status_code == 400


def test_P16C03_exfil_hit_is_logged_signed_and_the_export_verifies(client, tmp_path):
    c, mod = client
    h = {"X-Range-Admin": TOKEN}
    r = c.post("/admin/case", json={"style": "visible_footer"}, headers=h).json()
    slug = r["url"].rsplit("/", 1)[1]
    xpath = mod.CASES[slug]["exfil"].split("testserver", 1)[1]
    assert c.get("/x/%s/wrongtoken?code=%s" % (slug, r["canary"])).status_code == 404
    assert c.get(xpath).text == "Verified."
    hits = c.get("/admin/hits", headers=h).json()
    assert [x["data"]["canary_matches"] for x in hits if x["type"] == "range.exfil_hit"] == [True]
    c.post("/admin/close", headers=h)
    ex = c.get("/admin/export", headers=h).json()
    d = tmp_path / "export"
    d.mkdir()
    for n in ("audit", "checkpoints"):
        (d / (n + ".jsonl")).write_text("".join(json.dumps(e, sort_keys=True) + "\n" for e in ex[n]))
    cmd = [sys.executable, "-m", "aegis.verify_cli", "--audit", str(d / "audit.jsonl"), "--checkpoints", str(d / "checkpoints.jsonl"),
           "--pubkey", ex["public_key_b64"], "--run-id", "RANGE-TEST", "--expect-state", "RELEASED"]
    v = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT)
    assert v.returncode == 0, v.stdout + v.stderr
    lines = (d / "audit.jsonl").read_text().splitlines()
    tampered = [json.loads(x) for x in lines]
    tampered[2]["data"]["canary_matches"] = False if tampered[2]["type"] == "range.exfil_hit" else "x"
    (d / "audit.jsonl").write_text("".join(json.dumps(e, sort_keys=True) + "\n" for e in tampered))
    assert subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT).returncode != 0
    assert r["canary"] not in json.dumps([e for e in ex["audit"] if e["type"] != "range.exfil_hit"])  # only digests of canaries
