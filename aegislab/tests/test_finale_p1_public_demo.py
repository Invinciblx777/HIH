"""Finale P1: the public read-only demo (AEGIS_PUBLIC_DEMO=1, the hosted site) and the HTTPS Origin fix.

F1  an https Origin for the same host is accepted (the hosted site's Verify returned 403); a foreign Origin is still refused.
F2  read-only is enforced in code: no launch code, no operator session, every state-changing endpoint refused, live
    execution off even where Podman exists; a bare VERCEL variable no longer lifts the loopback Host guard.
F9  the public verifier is rate-limited, globally and per client IP (429 with a fixed message).
Outside public mode the console behaves as before.

Container-free: FastAPI TestClient against the real console app; verify and tamper run the real verifier subprocess.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from aegis import console, lab_session, runs, runtime, store  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

PUBLIC_HOST = "aegislab.vercel.app"
LIVE = {"available": True, "rootless": True, "image": runtime.IMAGE, "image_present": True}
BUNDLE = "DEMO-001-RELEASED"

# Every state-changing request the console or the mounted control plane answers, with a body that would pass validation.
WRITES = [
    ("POST", "/api/lab/runs", {"stop_after": "created"}),
    ("POST", "/api/lab/runs/LAB-001/defence", {"profile": "sample"}),
    ("POST", "/api/lab/runs/LAB-001/freeze", None),
    ("POST", "/api/lab/runs/LAB-001/start", None),
    ("POST", "/api/lab/scenarios/prohibited-access/run", {"run_id": "LAB-001"}),
    ("POST", "/api/lab/scenarios/sandbox-containment/run", {}),
    ("POST", "/api/lab/probe", {"role": "reviewer", "op": "release", "run_id": "LAB-001"}),
    ("POST", "/api/lab/runs/LAB-001/tamper-suite", None),
    ("POST", "/api/lab/session/end", None),
    ("POST", "/api/runs", {"run_id": "PUB-001"}),
    ("POST", "/api/runs/PUB-001/freeze", None),
    ("POST", "/api/runs/PUB-001/release", None),
    ("PUT", "/api/lab/runs", {}),
    ("DELETE", "/api/lab/runs/LAB-001", None),
]


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "VAR", tmp_path / "var")
    monkeypatch.setattr(runs, "_signer", None)
    for k in ("AEGIS_DEMO_MODE", "AEGIS_CONSOLE_LAUNCH_CODE", "AEGIS_CONSOLE_HOSTS", "AEGIS_PUBLIC_DEMO", "VERCEL"):
        monkeypatch.delenv(k, raising=False)
    lab_session.reset()
    console.reset_public_limits()
    with console._cache_lock:
        console._cache.clear()
    yield
    lab_session.reset()
    console.reset_public_limits()
    with console._cache_lock:
        console._cache.clear()


@pytest.fixture
def public(monkeypatch):
    monkeypatch.setenv("AEGIS_PUBLIC_DEMO", "1")
    return TestClient(console.app, base_url="https://" + PUBLIC_HOST)


@pytest.fixture
def local():
    return TestClient(console.app, base_url="http://127.0.0.1:8400")


def origin(host, scheme="https"):
    return {"Origin": "%s://%s" % (scheme, host), "Sec-Fetch-Site": "same-origin"}


def login(client):
    r = client.get("/session/start", params={"code": lab_session.launch_code()}, follow_redirects=False)
    assert r.status_code == 303, r.text
    return r, {"X-Aegis-CSRF": client.get("/api/lab/session").json()["csrf"]}


# ------------------------------------------------------------------ F1: Origin
def test_https_origin_for_the_same_host_is_accepted_on_the_public_demo(public):
    r = public.post("/api/lab/bundles/%s/verify" % BUNDLE, headers=origin(PUBLIC_HOST))
    assert r.status_code == 200, r.text
    assert r.json()["matches_expectation"] is True and r.json()["result"]["ok"] is True


def test_https_origin_for_the_same_host_is_accepted_on_loopback(local):
    _, csrf = login(local)
    r = local.post("/api/lab/bundles/%s/verify" % BUNDLE, headers={**csrf, **origin("127.0.0.1:8400")})
    assert r.status_code == 200, r.text
    r = local.post("/api/lab/bundles/%s/verify" % BUNDLE, headers={**csrf, **origin("127.0.0.1:8400", "http")})
    assert r.status_code == 200, r.text


@pytest.mark.parametrize("bad", ["https://evil.example", "http://evil.example", "https://aegislab.vercel.app.evil.example",
                                 "https://127.0.0.1:8401", "null"])
def test_foreign_origin_is_refused(public, local, bad):
    for c in (public, local):
        r = c.post("/api/lab/bundles/%s/verify" % BUNDLE, headers={"Origin": bad})
        assert r.status_code == 403 and "Origin does not match" in r.json()["detail"]
    r = public.post("/api/lab/bundles/%s/verify" % BUNDLE, headers={"Sec-Fetch-Site": "cross-site"})
    assert r.status_code == 403 and "Sec-Fetch-Site" in r.json()["detail"]


def test_session_cookie_is_secure_over_https_only(monkeypatch):
    plain = TestClient(console.app, base_url="http://127.0.0.1")
    r, _ = login(plain)
    assert "secure" not in r.headers["set-cookie"].lower()
    lab_session.reset()
    tls = TestClient(console.app, base_url="https://127.0.0.1")
    r, _ = login(tls)
    assert "; secure" in r.headers["set-cookie"].lower()
    # behind a TLS proxy that only sets X-Forwarded-Proto: Secure as well (the cookie then never travels over plain http)
    proxied = TestClient(console.app, base_url="http://127.0.0.1", headers={"X-Forwarded-Proto": "https"})
    r = proxied.get("/session/start", params={"code": lab_session.launch_code()}, follow_redirects=False)
    assert r.status_code == 303 and "; secure" in r.headers["set-cookie"].lower()


# ------------------------------------------------------------------ F2: read-only public demo
def test_public_demo_issues_and_accepts_no_launch_code(public):
    assert lab_session.launch_code() == ""
    assert not (store.VAR / "console" / "launch_code").exists()
    with pytest.raises(RuntimeError):
        lab_session.issue()
    sid, why = lab_session.start("x" * 32)
    assert sid is None and "public read-only demo" in why
    r = public.get("/session/start", params={"code": "x" * 32}, follow_redirects=False)
    assert r.status_code == 403 and "public read-only demo" in r.json()["detail"]
    assert "set-cookie" not in r.headers
    s = public.get("/api/lab/session").json()
    assert s["authenticated"] is False and s["public_demo"] is True


def test_public_demo_ignores_a_session_started_before_it_was_switched_on(local, monkeypatch):
    _, csrf = login(local)
    assert local.get("/api/lab/session").json()["authenticated"] is True
    monkeypatch.setenv("AEGIS_PUBLIC_DEMO", "1")
    assert lab_session.get(local.cookies.get(lab_session.COOKIE)) is None
    assert local.get("/api/lab/session").json()["authenticated"] is False


@pytest.mark.parametrize("method,path,body", WRITES)
def test_public_demo_refuses_every_write(public, method, path, body):
    tok = store.tokens()["operator"]  # even with a real control-plane token
    for headers in (origin(PUBLIC_HOST), {**origin(PUBLIC_HOST), "X-Aegis-Token": tok}, {}):
        r = public.request(method, path, json=body, headers=headers)
        assert r.status_code == 403, (method, path, r.status_code, r.text)
        assert r.json()["detail"].startswith("public read-only demo:")
    assert not store.p("runs").exists() or not any(store.p("runs").iterdir())


def test_public_demo_is_degraded_even_with_podman(public, monkeypatch):
    monkeypatch.setattr(console, "_podman_status", lambda: LIVE)
    s = public.get("/api/lab/status").json()
    assert s["public_demo"] is True and s["mode"] == "degraded"
    assert s["execution_modes"]["live"] == "UNAVAILABLE" and "public read-only demo" in s["mode_reason"]
    assert "verify bundles with the independent verifier" in s["public_demo_allows"]
    with pytest.raises(HTTPException) as e:
        console._require_live()
    assert e.value.status_code == 503


def test_public_demo_keeps_reads(public):
    for path in ("/", "/console/console.js", "/api/lab/bundles", "/api/lab/replay", "/api/lab/scenarios", "/api/lab/tamper-modes",
                 "/api/lab/journal", "/api/lab/timeline", "/api/health"):
        assert public.get(path).status_code == 200, path
    assert public.get("/api/demo/identities").status_code != 200


def test_bare_vercel_variable_keeps_the_host_guard(monkeypatch):
    monkeypatch.setenv("VERCEL", "1")
    c = TestClient(console.app, base_url="https://" + PUBLIC_HOST)
    for path in ("/", "/api/lab/status", "/api/health"):
        assert c.get(path).status_code == 421
    assert c.post("/api/lab/bundles/%s/verify" % BUNDLE, headers=origin(PUBLIC_HOST)).status_code == 421
    for value in ("0", "true", "yes", ""):
        monkeypatch.setenv("AEGIS_PUBLIC_DEMO", value)
        assert c.get("/api/health").status_code == 421, value


def test_app_entry_point_forces_public_mode(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_VAR", str(tmp_path / "app-var"))  # app.py only defaults it; keep it out of later tests
    monkeypatch.setenv("AEGIS_PUBLIC_DEMO", "0")
    src = (ROOT / "app.py").read_text()
    assert 'os.environ["AEGIS_PUBLIC_DEMO"] = "1"' in src
    exec(compile(src.replace("from aegis.console import app  # noqa: E402,F401", ""), "app.py", "exec"), {})
    assert lab_session.public_demo()


def test_verify_and_tamper_work_in_public_mode_and_record_nothing(public):
    r = public.post("/api/lab/bundles/VAL-001-TAMPERED/verify", headers=origin(PUBLIC_HOST))
    assert r.status_code == 200 and r.json()["result"]["ok"] is False and r.json()["matches_expectation"] is True
    r = public.post("/api/lab/bundles/%s/tamper" % BUNDLE, json={"mode": "truncate_tail"}, headers=origin(PUBLIC_HOST))
    assert r.status_code == 200, r.text
    t = r.json()
    assert t["verdict"] == "PASS" and t["original_unchanged"] and t["copy_deleted"]
    assert not store.p("lab", "journal.jsonl").exists() and not store.p("lab", "results").exists()
    assert public.post("/api/lab/bundles/%s/tamper" % BUNDLE, json={"mode": "nope"}, headers=origin(PUBLIC_HOST)).status_code == 400


# ------------------------------------------------------------------ F9: public rate limit
def test_public_verifier_rate_limit_per_client(public, monkeypatch):
    monkeypatch.setattr(console, "PUBLIC_RATE_CLIENT", (3, 60.0))
    a, b = {**origin(PUBLIC_HOST), "X-Real-IP": "198.51.100.7"}, {**origin(PUBLIC_HOST), "X-Real-IP": "203.0.113.9"}
    for _ in range(3):
        assert public.post("/api/lab/bundles/NOPE/verify", headers=a).status_code == 404  # counted, cheap
    r = public.post("/api/lab/bundles/%s/verify" % BUNDLE, headers=a)
    assert r.status_code == 429 and r.json()["detail"] == console.PUBLIC_RATE_MESSAGE and r.headers["retry-after"] == "60"
    assert public.post("/api/lab/bundles/%s/tamper" % BUNDLE, json={"mode": "truncate_tail"}, headers=a).status_code == 429
    assert public.post("/api/lab/bundles/NOPE/verify", headers=b).status_code == 404  # another client is not affected
    assert public.get("/api/lab/bundles", headers=a).status_code == 200  # reads are not limited


def test_public_verifier_rate_limit_global(public, monkeypatch):
    monkeypatch.setattr(console, "PUBLIC_RATE_GLOBAL", (4, 60.0))
    for i in range(4):
        assert public.post("/api/lab/bundles/NOPE/verify", headers={**origin(PUBLIC_HOST), "X-Real-IP": "192.0.2.%d" % i}).status_code == 404
    r = public.post("/api/lab/bundles/NOPE/verify", headers={**origin(PUBLIC_HOST), "X-Forwarded-For": "192.0.2.200, 10.0.0.1"})
    assert r.status_code == 429 and r.json()["detail"] == console.PUBLIC_RATE_MESSAGE


def test_rate_limit_window_expires(public, monkeypatch):
    monkeypatch.setattr(console, "PUBLIC_RATE_CLIENT", (1, 60.0))
    clock = [1000.0]
    monkeypatch.setattr(console.time, "monotonic", lambda: clock[0])
    assert console._public_rate_ok("192.0.2.1") and not console._public_rate_ok("192.0.2.1")
    clock[0] += 61
    assert console._public_rate_ok("192.0.2.1")


def test_concurrency_cap_is_unchanged():
    assert console._verify_slots._initial_value == 2


# ------------------------------------------------------------------ outside public mode: unchanged
def test_local_mode_is_unchanged(local, monkeypatch):
    s = local.get("/api/lab/status").json()
    assert "public_demo" not in s and not any(k.startswith("public_demo") for k in s)
    assert s["identity_model"].startswith("operator session (loopback launch link")
    assert local.get("/api/lab/session").json() == {"authenticated": False, "how": "Open the launch link printed by scripts/start_prototype.sh."}
    r = local.post("/api/lab/runs", json={"stop_after": "created"})
    assert r.status_code == 403 and "operator session required" in r.json()["detail"]
    r = local.post("/api/lab/bundles/%s/tamper" % BUNDLE, json={"mode": "truncate_tail"})
    assert r.status_code == 403 and "operator session required" in r.json()["detail"]
    assert TestClient(console.app, base_url="https://" + PUBLIC_HOST).get("/api/health").status_code == 421
    monkeypatch.setattr(console, "PUBLIC_RATE_CLIENT", (1, 60.0))
    for _ in range(3):  # no public rate limit outside public mode
        assert local.post("/api/lab/bundles/NOPE/verify").status_code == 404
    _, csrf = login(local)
    r = local.post("/api/lab/bundles/%s/tamper" % BUNDLE, json={"mode": "truncate_tail"}, headers=csrf)
    assert r.status_code == 200 and r.json()["verdict"] == "PASS"
    assert store.p("lab", "journal.jsonl").exists()  # recorded as before
