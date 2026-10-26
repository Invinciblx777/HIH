"""Phase R3: hardening of the prototype console.

* request bodies are limited by the bytes actually received (chunked, missing or misleading Content-Length), both at the ASGI
  layer and through a real uvicorn server on a loopback socket;
* the launch code is single-use, expires, and a new login ends the browser's previous session;
* lifecycle retries and duplicates do not create extra workloads (idempotency key, concurrent requests);
* refusals after release are reported exactly where the control plane recorded them (signed chain, post-terminal file, or not
  at all), and the signed chain is never reopened;
* evidence verification fails closed (symbolic links, verifier that cannot start, unexpected exit codes, malformed bundles,
  concurrent tamper demonstrations).

Container-free: the broker's workloads are in-process fakes (tests/test_r2_lab.py), the control plane, gates, audit log,
signing and the verifier subprocess are real.
"""
import asyncio
import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from aegis import console, lab_session, runs, store  # noqa: E402
from aegis.audit import read_jsonl  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from test_r2_lab import fake_host, isolated, login, sealed_run, wait_state  # noqa: E402,F401  (fixtures and helpers)

LIMIT = console.MAX_BODY


@pytest.fixture
def client():
    return TestClient(console.app, base_url="http://127.0.0.1")


def lab_runs():
    return console._lab_runs()


# ------------------------------------------------------------------ body limit, ASGI layer
def _drive(mw_app, messages, headers=()):
    """Run the BodyLimit middleware on one request whose body arrives as `messages`; return (status, app_called, consumed)."""
    seen = {"called": False, "consumed": 0}
    out = []

    async def inner(scope, receive, send):
        seen["called"] = True
        msg = await receive()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"%d" % len(msg.get("body", b""))})

    queue = list(messages)

    async def receive():
        seen["consumed"] += 1
        return queue.pop(0) if queue else {"type": "http.disconnect"}

    async def send(msg):
        out.append(msg)

    scope = {"type": "http", "method": "POST", "path": "/x", "headers": [(k.encode(), v.encode()) for k, v in headers]}
    asyncio.run(console.BodyLimit(inner, limit=mw_app)(scope, receive, send))
    start = next((m for m in out if m["type"] == "http.response.start"), None)
    return (start["status"] if start else None), seen["called"], seen["consumed"], out


def test_streamed_body_over_the_limit_never_reaches_the_app_and_reading_stops():
    chunk = {"type": "http.request", "body": b"a" * 1000, "more_body": True}
    status, called, consumed, out = _drive(4096, [dict(chunk) for _ in range(1000)])
    assert status == 413 and not called
    assert consumed == 5  # stops at the first chunk past 4096 bytes, not after 1000 chunks
    assert (b"connection", b"close") in next(m for m in out if m["type"] == "http.response.start")["headers"]


def test_body_at_the_limit_is_replayed_intact_to_the_app():
    parts = [{"type": "http.request", "body": b"b" * 1024, "more_body": True} for _ in range(3)]
    parts.append({"type": "http.request", "body": b"b" * 1024, "more_body": False})
    status, called, _, out = _drive(4096, parts)
    assert status == 200 and called and out[-1]["body"] == b"4096"


@pytest.mark.parametrize("cl", ["abc", "-1", "1, 2", " "])
def test_malformed_content_length_is_refused(cl):
    status, called, consumed, _ = _drive(4096, [{"type": "http.request", "body": b"{}"}], headers=[("content-length", cl)])
    assert status == 400 and not called and consumed == 0


def test_conflicting_content_lengths_are_refused():
    status, called, _, _ = _drive(4096, [], headers=[("content-length", "2"), ("content-length", "3")])
    assert status == 400 and not called


def test_declared_oversize_is_refused_without_reading_the_body():
    status, called, consumed, _ = _drive(4096, [], headers=[("content-length", "4097")])
    assert status == 413 and not called and consumed == 0


def test_client_disconnect_mid_body_runs_nothing():
    status, called, _, out = _drive(4096, [{"type": "http.request", "body": b"x", "more_body": True}])
    assert status is None and not called and out == []


# ------------------------------------------------------------------ body limit through the console app
def _chunks(total, size=16 * 1024):
    def gen():
        sent = 0
        while sent < total:
            n = min(size, total - sent)
            sent += n
            yield b" " * n
    return gen()


def test_oversized_bodies_change_no_session_or_run_state(client, fake_host):
    h = login(client)
    big = b'{"stop_after": "created", "timing_bucket_ms": 0, "pad": "' + b"x" * LIMIT + b'"}'
    assert client.post("/api/lab/runs", content=big, headers={**h, "Content-Type": "application/json"}).status_code == 413
    r = client.post("/api/lab/runs", content=_chunks(LIMIT + 1), headers={**h, "Content-Type": "application/json"})
    assert r.status_code == 413 and "too large" in r.json()["detail"]
    assert lab_runs() == []
    assert client.get("/api/lab/session").json()["authenticated"] is True
    rid = client.post("/api/lab/runs", json={"stop_after": "created", "timing_bucket_ms": 0}, headers=h).json()["run_id"]
    # an endpoint that never reads its body is protected too: the oversized request does not freeze the run
    r = client.post("/api/lab/runs/%s/freeze" % rid, content=_chunks(LIMIT + 1), headers=h)
    assert r.status_code == 413 and runs.Run(rid).state == "CREATED"
    assert client.post("/api/lab/runs/%s/freeze" % rid, headers=h).status_code == 200


def test_small_chunked_body_without_content_length_is_accepted(client, fake_host):
    h = login(client)
    body = json.dumps({"stop_after": "created", "timing_bucket_ms": 0}).encode()
    r = client.post("/api/lab/runs", content=iter([body[:10], body[10:]]), headers={**h, "Content-Type": "application/json"})
    assert r.status_code == 200, r.text


def test_mounted_control_plane_is_covered_by_the_limit(client):
    tok = store.tokens()["blue_participant"]
    r = client.post("/api/runs/LAB-001/defence-config", content=_chunks(LIMIT + 10), headers={"X-Aegis-Token": tok,
                                                                                            "Content-Type": "application/json"})
    assert r.status_code == 413


def test_malformed_json_fails_predictably_without_a_traceback(client, fake_host):
    h = login(client)
    r = client.post("/api/lab/runs", content=b'{"stop_after": "created",', headers={**h, "Content-Type": "application/json"})
    assert r.status_code == 422
    assert "Traceback" not in r.text and not [t for t in store.tokens().values() if t in r.text]
    assert lab_runs() == []


# ------------------------------------------------------------------ body limit through a real uvicorn server
@pytest.fixture(scope="module")
def live_console(tmp_path_factory):
    var = tmp_path_factory.mktemp("r3_console_var")
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    code = "r3-test-code-" + "k" * 24
    env = {k: v for k, v in os.environ.items() if not k.startswith("AEGIS_MODEL") and k != "AEGIS_DEMO_MODE"}
    env.update(AEGIS_VAR=str(var), AEGIS_CONSOLE_LAUNCH_CODE=code, PYTHONDONTWRITEBYTECODE="1")
    log = open(var / "uvicorn.log", "w")
    proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "aegis.console:app", "--host", "127.0.0.1", "--port", str(port),
                             "--log-level", "warning"], cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), 0.3).close()
            break
        except OSError:
            time.sleep(0.2)
    else:
        proc.kill()
        raise RuntimeError("console did not start")
    yield {"port": port, "code": code, "var": var, "proc": proc}
    proc.terminate()
    try:
        proc.wait(15)
    except subprocess.TimeoutExpired:
        proc.kill()
    log.close()


def _raw(port, head, body=b"", chunked_parts=None, read_timeout=20):
    """Send one HTTP/1.1 request on a raw socket. Returns (status line, headers text, body bytes)."""
    c = socket.create_connection(("127.0.0.1", port), 10)
    try:
        c.sendall(head.encode() + b"\r\n")
        try:
            if chunked_parts is not None:
                for part in chunked_parts:
                    c.sendall(b"%x\r\n%s\r\n" % (len(part), part))
                c.sendall(b"0\r\n\r\n")
            elif body:
                c.sendall(body)
        except OSError:
            pass  # the server may close the connection while the client is still sending an oversized body
        c.settimeout(read_timeout)
        data = b""
        try:
            while True:
                d = c.recv(65536)
                if not d:
                    break
                data += d
                if b"\r\n\r\n" in data:
                    hdr, _, rest = data.partition(b"\r\n\r\n")
                    cl = [int(l.split(b":")[1]) for l in hdr.split(b"\r\n") if l.lower().startswith(b"content-length:")]
                    if cl and len(rest) >= cl[0]:
                        break
        except OSError:
            pass
    finally:
        c.close()
    hdr, _, rest = data.partition(b"\r\n\r\n")
    lines = hdr.decode(errors="replace").split("\r\n")
    return lines[0], "\n".join(lines[1:]), rest


def _head(port, method, path, extra=""):
    return "%s %s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nContent-Type: application/json\r\n%s" % (method, path, port, extra)


def _session(live):
    port = live["port"]
    status, hdrs, _ = _raw(port, "GET /session/start?code=%s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n" % (_code(live), port))
    assert " 303 " in status, status
    sid = [l for l in hdrs.split("\n") if l.lower().startswith("set-cookie:")][0].split("=", 1)[1].split(";")[0]
    status, _, body = _raw(port, "GET /api/lab/session HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nCookie: aegis_console=%s\r\n" % (port, sid))
    return sid, json.loads(body)["csrf"]


def _code(live):
    return (live["var"] / "console" / "launch_code").read_text().strip()


def test_real_server_refuses_a_streamed_body_without_content_length(live_console):
    port = live_console["port"]
    parts = [b"a" * 65536 for _ in range(64)]  # 4 MiB, chunked, no Content-Length
    status, hdrs, body = _raw(port, _head(port, "POST", "/api/lab/runs", "Transfer-Encoding: chunked\r\n"), chunked_parts=parts)
    assert " 413 " in status, status
    assert "connection: close" in hdrs.lower() and b"too large" in body


def test_real_server_refuses_a_declared_oversize_and_a_misleading_length(live_console):
    port = live_console["port"]
    status, _, _ = _raw(port, _head(port, "POST", "/api/lab/runs", "Content-Length: %d\r\n" % (LIMIT + 1)), body=b"{}")
    assert " 413 " in status
    # declares 20 bytes but sends far more: the server frames the request by the declared length, so the extra bytes
    # never become part of this body; they are refused as a malformed next request on the same connection
    status, _, body = _raw(port, _head(port, "POST", "/api/lab/runs", "Content-Length: 20\r\n"), body=b'{"stop_after":"x"}  ' + b"z" * 600_000)
    assert " 403 " in status or " 422 " in status, status
    assert b"Traceback" not in body


def test_real_server_survives_repeated_oversized_requests_and_keeps_the_session(live_console):
    port = live_console["port"]
    sid, csrf = _session(live_console)
    auth = "Cookie: aegis_console=%s\r\nX-Aegis-CSRF: %s\r\n" % (sid, csrf)
    for _ in range(12):
        status, _, _ = _raw(port, _head(port, "POST", "/api/lab/runs", auth + "Transfer-Encoding: chunked\r\n"),
                            chunked_parts=[b" " * 65536 for _ in range(8)])
        assert " 413 " in status, status
    status, _, body = _raw(port, "GET /api/lab/session HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nCookie: aegis_console=%s\r\n" % (port, sid))
    assert " 200 " in status and json.loads(body)["authenticated"] is True and json.loads(body)["csrf"] == csrf
    status, _, _ = _raw(port, "GET /api/lab/status HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n" % port, read_timeout=60)
    assert " 200 " in status
    assert not (live_console["var"] / "runs").exists() or not [d for d in (live_console["var"] / "runs").iterdir() if d.name.startswith("LAB-")]


def test_real_server_small_chunked_request_and_malformed_json(live_console):
    port = live_console["port"]
    sid, csrf = _session(live_console)
    auth = "Cookie: aegis_console=%s\r\nX-Aegis-CSRF: %s\r\n" % (sid, csrf)
    status, _, body = _raw(port, _head(port, "POST", "/api/lab/runs", auth + "Transfer-Encoding: chunked\r\n"),
                           chunked_parts=[b'{"stop_after": ', b'"created", "bogus": 1}'])
    assert " 422 " in status, status  # read and parsed (unknown field refused), not mistaken for an oversize
    status, _, body = _raw(port, _head(port, "POST", "/api/lab/runs", auth + "Content-Length: 9\r\n"), body=b'{"stop_af')
    assert " 422 " in status and b"Traceback" not in body


def test_real_server_refuses_foreign_host_headers(live_console):
    port = live_console["port"]
    status, hdrs, _ = _raw(port, "GET /api/lab/session HTTP/1.1\r\nHost: attacker.example:%d\r\n" % port)
    assert " 421 " in status and "cache-control: no-store" in hdrs.lower()


# ------------------------------------------------------------------ launch code and session
def test_launch_code_works_once_and_is_replaced_by_a_fresh_private_one(client):
    code = lab_session.launch_code()
    assert client.get("/session/start", params={"code": code}, follow_redirects=False).status_code == 303
    again = TestClient(console.app, base_url="http://127.0.0.1").get("/session/start", params={"code": code}, follow_redirects=False)
    assert again.status_code == 403 and "already used" in again.text and "set-cookie" not in again.headers
    f = store.p("console", "launch_code")
    assert f.read_text().strip() != code and f.stat().st_mode & 0o777 == 0o600
    assert lab_session.launch_code() == f.read_text().strip()


def test_concurrent_use_of_one_launch_code_starts_exactly_one_session():
    code = lab_session.launch_code()
    results, barrier = [], threading.Barrier(8)

    def go():
        barrier.wait()
        results.append(lab_session.start(code)[0])
    threads = [threading.Thread(target=go) for _ in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert sum(1 for r in results if r) == 1


def test_unused_launch_code_expires(client):
    code = lab_session.launch_code()
    old = time.time() - lab_session.LAUNCH_TTL_S - 5
    os.utime(store.p("console", "launch_code"), (old, old))
    r = client.get("/session/start", params={"code": code}, follow_redirects=False)
    assert r.status_code == 403 and "expired" in r.text and "--link" in r.text
    fresh = lab_session.launch_code()
    assert fresh != code
    assert client.get("/session/start", params={"code": fresh}, follow_redirects=False).status_code == 303


def test_issuing_a_new_link_invalidates_the_unused_one(client):
    old = lab_session.launch_code()
    new = lab_session.issue()  # what scripts/start_prototype.sh --link does
    assert client.get("/session/start", params={"code": old}, follow_redirects=False).status_code == 403
    assert client.get("/session/start", params={"code": new}, follow_redirects=False).status_code == 303


def test_launcher_environment_code_is_single_use_too(client, monkeypatch):
    env_code = "launcher-provided-code-" + "q" * 20
    monkeypatch.setenv("AEGIS_CONSOLE_LAUNCH_CODE", env_code)
    lab_session.reset()
    assert lab_session.launch_code() == env_code
    assert client.get("/session/start", params={"code": env_code}, follow_redirects=False).status_code == 303
    assert lab_session.launch_code() != env_code
    assert client.get("/session/start", params={"code": env_code}, follow_redirects=False).status_code == 403


def test_a_planted_session_id_is_never_adopted(client):
    planted = "attacker-chosen-session-id-0123456789"
    assert client.get("/api/lab/session", headers={"Cookie": "%s=%s" % (lab_session.COOKIE, planted)}).json()["authenticated"] is False
    r = client.get("/session/start", params={"code": lab_session.launch_code()}, headers={"Cookie": "%s=%s" % (lab_session.COOKIE, planted)},
                   follow_redirects=False)
    assert r.status_code == 303 and planted not in r.headers["set-cookie"]


def test_a_new_login_ends_the_previous_session(client, fake_host):
    h1 = login(client)
    first = client.cookies.get(lab_session.COOKIE)
    h2 = login(client)
    second = client.cookies.get(lab_session.COOKIE)
    assert second != first and h2 != h1
    stale = TestClient(console.app, base_url="http://127.0.0.1")
    stale.cookies.set(lab_session.COOKIE, first)
    assert stale.get("/api/lab/session").json()["authenticated"] is False
    assert stale.post("/api/lab/runs", json={"stop_after": "created"}, headers=h1).status_code == 403


def test_csrf_token_is_bound_to_its_session(client, fake_host):
    h1 = login(client)
    other = TestClient(console.app, base_url="http://127.0.0.1")
    login(other)
    # a valid CSRF token of another session does not authorise this one
    assert other.post("/api/lab/runs", json={"stop_after": "created"}, headers=h1).status_code == 403
    assert lab_runs() == []


def test_idle_and_absolute_session_expiry(client, fake_host, monkeypatch):
    from types import SimpleNamespace
    h = login(client)
    now = time.time()
    t = [now + lab_session.IDLE_TTL_S + 1]
    monkeypatch.setattr(lab_session, "time", SimpleNamespace(time=lambda: t[0]))  # the session module's clock only
    assert client.get("/api/lab/session").json()["authenticated"] is False
    assert client.post("/api/lab/runs", json={"stop_after": "created"}, headers=h).status_code == 403
    t[0] = now
    h = login(client)
    for _ in range(int(lab_session.SESSION_TTL_S / 3600) + 1):  # active every hour: idle timer refreshed, absolute limit reached
        t[0] += 3600
        client.get("/api/lab/session")
    assert client.get("/api/lab/session").json()["authenticated"] is False


def test_session_responses_are_not_cached_and_leak_no_referrer(client):
    r = client.get("/session/start", params={"code": lab_session.launch_code()}, follow_redirects=False)
    assert r.headers["cache-control"] == "no-store" and r.headers["referrer-policy"] == "no-referrer"
    assert "code" not in r.headers["location"]
    bad = client.get("/session/start", params={"code": "nope" * 6}, follow_redirects=False)
    assert bad.headers["cache-control"] == "no-store"
    assert client.get("/api/lab/session").headers["cache-control"] == "no-store"


# ------------------------------------------------------------------ lifecycle: duplicates, retries, concurrency
def test_idempotency_key_returns_the_original_run_instead_of_a_second_one(client, fake_host):
    h = login(client)
    body = {"stop_after": "created", "timing_bucket_ms": 0}
    a = client.post("/api/lab/runs", json=body, headers={**h, "X-Aegis-Idempotency-Key": "click-0001-aaaa"})
    b = client.post("/api/lab/runs", json=body, headers={**h, "X-Aegis-Idempotency-Key": "click-0001-aaaa"})
    assert a.status_code == b.status_code == 200
    assert a.json()["run_id"] == b.json()["run_id"] and a.json()["replayed"] is False and b.json()["replayed"] is True
    assert lab_runs() == [a.json()["run_id"]]
    c = client.post("/api/lab/runs", json=body, headers={**h, "X-Aegis-Idempotency-Key": "click-0002-bbbb"})
    assert c.json()["run_id"] != a.json()["run_id"] and len(lab_runs()) == 2
    assert client.post("/api/lab/runs", json=body, headers={**h, "X-Aegis-Idempotency-Key": "bad key!"}).status_code == 422
    # a key is bound to its caller: another session reusing it creates its own run, it does not receive this one
    other = TestClient(console.app, base_url="http://127.0.0.1")
    h2 = login(other)
    d = other.post("/api/lab/runs", json=body, headers={**h2, "X-Aegis-Idempotency-Key": "click-0001-aaaa"})
    assert d.status_code == 200 and d.json()["replayed"] is False and d.json()["run_id"] not in (a.json()["run_id"], c.json()["run_id"])


def test_concurrent_duplicate_creates_spawn_one_run(client, fake_host):
    h = login(client)
    out, barrier = [], threading.Barrier(8)

    def go():
        barrier.wait()
        out.append(client.post("/api/lab/runs", json={"stop_after": "created", "timing_bucket_ms": 0},
                               headers={**h, "X-Aegis-Idempotency-Key": "double-click-77"}))
    threads = [threading.Thread(target=go) for _ in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert {r.status_code for r in out} <= {200, 409}
    assert len(lab_runs()) == 1
    assert {r.json()["run_id"] for r in out if r.status_code == 200} == set(lab_runs())


def test_concurrent_starts_launch_one_broker(client, fake_host):
    h = login(client)
    rid = client.post("/api/lab/runs", json={"stop_after": "created", "timing_bucket_ms": 0}, headers=h).json()["run_id"]
    assert client.post("/api/lab/runs/%s/freeze" % rid, headers=h).status_code == 200
    out, barrier = [], threading.Barrier(6)

    def go():
        barrier.wait()
        out.append(client.post("/api/lab/runs/%s/start" % rid, headers=h).status_code)
    threads = [threading.Thread(target=go) for _ in range(6)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert sorted(out).count(200) == 1 and set(out) <= {200, 409}
    assert wait_state(rid, "SEALED") == "SEALED"
    log = read_jsonl(store.run_dir(rid) / "audit.jsonl")  # one broker: the fake workload's single attack and one seal
    assert [e["type"] for e in log].count("attack.evaluated") == 1 and [e["type"] for e in log].count("run.sealed") == 1


def test_unsupported_transitions_fail_cleanly_and_leave_state(client, fake_host):
    h = login(client)
    rid = sealed_run(client, h)
    for step in ("freeze", "start"):
        r = client.post("/api/lab/runs/%s/%s" % (rid, step), headers=h)
        assert r.status_code == 409 and runs.Run(rid).state == "SEALED"
    r = client.post("/api/lab/runs/%s/defence" % rid, json={"profile": "none"}, headers=h)
    assert r.status_code == 409 and runs.Run(rid).state == "SEALED"
    assert client.post("/api/lab/scenarios/authorized-release/run", json={"run_id": rid}, headers=h).json()["verdict"] == "PASS"
    again = client.post("/api/lab/scenarios/authorized-release/run", json={"run_id": rid}, headers=h)
    assert again.status_code == 409 and runs.Run(rid).state == "RELEASED"
    assert runs.verify_run(rid)["ok"] and runs.verify_run(rid)["terminal_verified"]


def test_authorisation_is_checked_before_the_host_is_described(client, monkeypatch):
    monkeypatch.setattr(console, "_podman_status", lambda: {"available": False, "reason": "podman info failed for this user"})
    for path in ("/api/lab/runs/LAB-001/freeze", "/api/lab/runs/LAB-001/start", "/api/lab/runs"):
        r = client.post(path, json={"stop_after": "created"} if path.endswith("runs") else None)
        assert r.status_code == 403 and "operator session" in r.json()["detail"], (path, r.text)


# ------------------------------------------------------------------ audit honesty after release
def _released(client, h):
    rid = sealed_run(client, h)
    assert client.post("/api/lab/scenarios/authorized-release/run", json={"run_id": rid}, headers=h).json()["verdict"] == "PASS"
    return rid


def test_refusal_on_a_sealed_run_is_reported_as_a_signed_chain_entry(client, fake_host):
    h = login(client)
    rid = sealed_run(client, h)
    p = client.post("/api/lab/probe", json={"role": "red_participant", "op": "artifacts", "run_id": rid}, headers=h).json()
    assert p["status"] == 403 and p["recording"]["where"] == "audit_chain" and p["recording"]["signed_chain"] is True
    assert p["audit"] and p["post_terminal"] == []


def test_refusal_after_release_is_reported_as_unsigned_and_the_chain_stays_closed(client, fake_host):
    h = login(client)
    rid = _released(client, h)
    audit = store.run_dir(rid) / "audit.jsonl"
    before, vault_before = audit.read_bytes(), store.vault_path(rid).read_bytes()
    p = client.post("/api/lab/probe", json={"role": "observer", "op": "artifacts", "run_id": rid}, headers=h).json()
    assert p["status"] == 403 and p["decision"] == "denied"
    assert p["audit"] == [] and p["recording"]["where"] == "post_terminal" and p["recording"]["signed_chain"] is False
    assert len(p["post_terminal"]) == 1 and p["post_terminal"][0]["signed"] is False
    assert p["post_terminal"][0]["data"] == {"op": "read_artifacts", "reason": "no identity"}
    assert audit.read_bytes() == before and store.vault_path(rid).read_bytes() == vault_before
    v = runs.verify_run(rid)
    assert v["ok"] and v["terminal_verified"]
    log = client.get("/api/lab/runs/%s/audit" % rid).json()
    assert log["after_close"]["closed"] is True and log["after_close"]["recorded"] == 1 and log["after_close"]["signed"] is False
    assert all("seq" not in e for e in log["after_close"]["entries"])
    assert log["total"] == len(before.splitlines())


def test_unlogged_requests_are_reported_as_not_recorded(client, fake_host):
    h = login(client)
    rid = sealed_run(client, h)
    for role, op in (("observer", "verify"), ("forged", "artifacts"), ("blue_participant", "evidence")):
        p = client.post("/api/lab/probe", json={"role": role, "op": op, "run_id": rid}, headers=h).json()
        assert p["recording"]["where"] == "not_recorded" and p["audit"] == [] and p["post_terminal"] == [], (role, op, p)


# ------------------------------------------------------------------ evidence verification fails closed
def test_symbolic_links_in_a_lab_bundle_are_refused(client, fake_host, tmp_path):
    h = login(client)
    rid = _released(client, h)
    bundle = store.p("bundles", rid)
    outside = tmp_path / "elsewhere.jsonl"
    outside.write_bytes((bundle / "audit.jsonl").read_bytes())
    (bundle / "audit.jsonl").unlink()
    (bundle / "audit.jsonl").symlink_to(outside)
    v = client.post("/api/lab/bundles/%s/verify" % rid).json()
    assert v["exit_code"] is None and "symbolic link" in v["error"] and v["matches_expectation"] is False
    assert client.post("/api/lab/bundles/%s/tamper" % rid, json={"mode": "edit_event"}, headers=h).status_code == 409
    assert client.get("/api/lab/bundles/%s/download" % rid).status_code == 409


def test_a_symlinked_bundle_directory_is_not_offered(client, fake_host, tmp_path):
    h = login(client)
    rid = _released(client, h)
    bundle = store.p("bundles", rid)
    moved = tmp_path / "real_bundle"
    bundle.rename(moved)
    bundle.symlink_to(moved, target_is_directory=True)
    assert rid not in [b["id"] for b in client.get("/api/lab/bundles").json()]
    assert client.post("/api/lab/bundles/%s/verify" % rid).status_code == 404


def test_verifier_that_cannot_start_is_no_verdict(client, monkeypatch):
    monkeypatch.setattr(console.sys, "executable", "/nonexistent/python-for-aegislab")
    v = client.post("/api/lab/bundles/DEMO-001-RELEASED/verify").json()
    assert v["exit_code"] is None and "could not be started" in v["error"] and v["matches_expectation"] is False


@pytest.mark.parametrize("code,ok,expected,match", [(2, True, "DEMO-001-RELEASED", False), (0, False, "DEMO-001-RELEASED", False),
                                                   (0, True, "VAL-001-TAMPERED", False), (2, False, "VAL-001-TAMPERED", False),
                                                   (0, True, "DEMO-001-RELEASED", True), (1, False, "VAL-001-TAMPERED", True)])
def test_only_the_exact_exit_code_and_verdict_pair_counts(client, monkeypatch, code, ok, expected, match):
    real = subprocess.run

    def fake(cmd, **kw):
        if "aegis.verify_cli" in cmd:
            return subprocess.CompletedProcess(cmd, code, stdout=json.dumps({"ok": ok}), stderr="")
        return real(cmd, **kw)
    monkeypatch.setattr(console.subprocess, "run", fake)
    assert client.post("/api/lab/bundles/%s/verify" % expected).json()["matches_expectation"] is match


def test_malformed_lab_bundle_is_rejected_without_a_crash(client, fake_host):
    h = login(client)
    rid = _released(client, h)
    (store.p("bundles", rid) / "audit.jsonl").write_text('{"seq": 1, "broken\nnot json at all\n')
    r = client.post("/api/lab/bundles/%s/verify" % rid)
    assert r.status_code == 200
    v = r.json()
    assert v["matches_expectation"] is False and v["exit_code"] != 0 and not (v.get("result") or {}).get("ok")


def test_status_does_not_cache_an_inconclusive_shipped_verification(client, monkeypatch):
    real = console._verify_bundle
    calls = []

    def flaky(b, path=None, quiet=False):
        calls.append(1)
        return {"exit_code": None, "result": None} if len(calls) == 1 else real(b, path, quiet)
    monkeypatch.setattr(console, "_verify_bundle", flaky)
    assert client.get("/api/lab/status").json()["integrity_shipped_bundle"]["exit_code"] is None
    second = client.get("/api/lab/status").json()["integrity_shipped_bundle"]
    assert second["exit_code"] == 0 and second["ok"] is True
    client.get("/api/lab/status")
    assert len(calls) == 2  # the conclusive result is cached


def test_concurrent_tamper_demonstrations_leave_the_original_and_no_copies(client, fake_host):
    h = login(client)
    b = console._bundles()["DEMO-001-RELEASED"]
    before = console._digests(b["abs"])
    out, barrier = [], threading.Barrier(4)

    def go(mode):
        barrier.wait()
        out.append(client.post("/api/lab/bundles/DEMO-001-RELEASED/tamper", json={"mode": mode}, headers=h))
    threads = [threading.Thread(target=go, args=(m,)) for m in ("edit_event", "truncate_tail", "rehash_chain", "substitute_key")]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert {r.status_code for r in out} <= {200, 429} and any(r.status_code == 200 for r in out)
    for r in out:
        if r.status_code == 200:
            j = r.json()
            assert j["verdict"] == "PASS" and j["original_unchanged"] and j["copy_deleted"], j
    assert console._digests(b["abs"]) == before
    assert not list(store.p("lab").glob("tamper-*"))
    results = sorted(store.p("lab", "results").glob("*.json"))
    assert len({f.name[:5] for f in results}) == len(results) == sum(r.status_code == 200 for r in out)


def test_bundle_ids_are_registry_keys_not_paths(client):
    for bid in ("..%2F..%2Fvar%2Fkeys", "..", "DEMO-001-RELEASED%2F..%2F..", "%2Fetc%2Fpasswd", "LAB-001"):
        r = client.get("/api/lab/bundles/%s/download" % bid)
        assert r.status_code == 404, bid
    assert client.get("/api/lab/bundles/DEMO-001-LEGACY/download").status_code == 409
    assert client.get("/api/lab/bundles/VAL-001-TAMPERED/download").status_code == 409
