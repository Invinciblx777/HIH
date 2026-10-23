"""Optional real-model adapter: opt-in, stateless, fail-safe, key-free. Uses a local fake HTTP server only."""
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from aegis import model_client as mc  # noqa: E402
from aegis import runs, runtime, store  # noqa: E402

KEY = "sk-test-SECRET-KEY-0123456789"


class Fake(BaseHTTPRequestHandler):
    mode = "ok"
    seen = []

    def log_message(self, *a):
        pass

    def _send(self, code, body, headers=None):
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        for k, v in {"Content-Type": "application/json", **(headers or {})}.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        Fake.seen.append(("GET", self.path, dict(self.headers), None))
        self._send(200, {"data": [{"id": "m"}]})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        Fake.seen.append(("POST", self.path, dict(self.headers), body))
        m = Fake.mode
        if m == "500":
            return self._send(500, {"error": "internal " + KEY})
        if m == "401":
            return self._send(401, {"error": "bad key " + KEY})
        if m == "slow":
            time.sleep(1.5)
        if m == "badjson":
            return self._send(200, b"{not json")
        if m == "shape":
            return self._send(200, {"choices": []})
        if m == "huge":
            return self._send(200, b"x" * ((1 << 20) + 10))
        if m == "redirect":
            return self._send(302, b"", {"Location": "http://127.0.0.1:1/steal"})
        self._send(200, {"choices": [{"message": {"content": "echo: " + body["messages"][0]["content"][:40]}}],
                         "usage": {"prompt_tokens": 3}})


@pytest.fixture
def server():
    Fake.mode, Fake.seen = "ok", []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Fake)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield "http://127.0.0.1:%d/v1" % srv.server_address[1]
    srv.shutdown()


def cfg(base, **kw):
    env = {"AEGIS_MODEL_BACKEND": "openai_compatible", "AEGIS_MODEL_BASE_URL": base, "AEGIS_MODEL_NAME": "m",
           "AEGIS_MODEL_API_KEY": KEY, "AEGIS_MODEL_TIMEOUT_S": "0.5"}
    env.update(kw)
    return mc.load_config(env)


# ------------------------------------------------------------- opt-in and configuration
def test_stub_is_default_and_nothing_is_enabled_automatically(monkeypatch):
    for k in list(os.environ):
        if k.startswith("AEGIS_MODEL"):
            monkeypatch.delenv(k)
    assert mc.load_config().backend == "stub" and mc.load_config().describe() == {"backend": "stub"}
    monkeypatch.setenv("AEGIS_MODEL_BASE_URL", "http://127.0.0.1:9/v1")  # a URL alone enables nothing
    assert mc.load_config().backend == "stub"


@pytest.mark.parametrize("env", [
    {"AEGIS_MODEL_BACKEND": "openai_compatible"},
    {"AEGIS_MODEL_BACKEND": "openai_compatible", "AEGIS_MODEL_BASE_URL": "http://127.0.0.1:1/v1"},
    {"AEGIS_MODEL_BACKEND": "openai", "AEGIS_MODEL_BASE_URL": "http://127.0.0.1:1/v1", "AEGIS_MODEL_NAME": "m"},
    {"AEGIS_MODEL_BACKEND": "openai_compatible", "AEGIS_MODEL_BASE_URL": "ftp://127.0.0.1/v1", "AEGIS_MODEL_NAME": "m"},
    {"AEGIS_MODEL_BACKEND": "openai_compatible", "AEGIS_MODEL_BASE_URL": "http://u:p@127.0.0.1/v1", "AEGIS_MODEL_NAME": "m"},
    {"AEGIS_MODEL_BACKEND": "openai_compatible", "AEGIS_MODEL_BASE_URL": "http://127.0.0.1/v1?x=1", "AEGIS_MODEL_NAME": "m"},
    {"AEGIS_MODEL_BACKEND": "openai_compatible", "AEGIS_MODEL_BASE_URL": "https://api.example.com/v1", "AEGIS_MODEL_NAME": "m"},
    {"AEGIS_MODEL_BACKEND": "openai_compatible", "AEGIS_MODEL_BASE_URL": "http://0.0.0.0:8081/v1", "AEGIS_MODEL_NAME": "m"},
    {"AEGIS_MODEL_BACKEND": "openai_compatible", "AEGIS_MODEL_BASE_URL": "http://127.0.0.1:1/v1", "AEGIS_MODEL_NAME": "m",
     "AEGIS_MODEL_EXTRA_JSON": '{"messages": []}'},
    {"AEGIS_MODEL_BACKEND": "openai_compatible", "AEGIS_MODEL_BASE_URL": "http://127.0.0.1:1/v1", "AEGIS_MODEL_NAME": "m",
     "AEGIS_MODEL_TIMEOUT_S": "0"},
])
def test_bad_or_unsafe_configuration_raises_instead_of_falling_back(env):
    with pytest.raises(mc.ModelBackendError) as e:
        mc.load_config(env)
    assert e.value.kind == "config"


def test_remote_endpoint_needs_explicit_flag():
    env = {"AEGIS_MODEL_BACKEND": "openai_compatible", "AEGIS_MODEL_BASE_URL": "https://models.example.com/v1",
           "AEGIS_MODEL_NAME": "m"}
    with pytest.raises(mc.ModelBackendError):
        mc.load_config(env)
    assert mc.load_config({**env, "AEGIS_MODEL_ALLOW_REMOTE": "1"}).describe()["loopback_only"] is False


def test_key_file_must_be_private(tmp_path):
    kf = tmp_path / "key"
    kf.write_text(KEY + "\n")
    env = {"AEGIS_MODEL_BACKEND": "openai_compatible", "AEGIS_MODEL_BASE_URL": "http://127.0.0.1:1/v1",
           "AEGIS_MODEL_NAME": "m", "AEGIS_MODEL_API_KEY_FILE": str(kf)}
    kf.chmod(0o644)
    with pytest.raises(mc.ModelBackendError):
        mc.load_config(env)
    kf.chmod(0o600)
    assert mc.load_config(env).api_key == KEY
    with pytest.raises(mc.ModelBackendError):
        mc.load_config({**env, "AEGIS_MODEL_API_KEY_FILE": str(tmp_path / "missing")})


def test_key_never_in_repr_describe_or_str():
    c = cfg("http://127.0.0.1:1/v1")
    assert KEY not in repr(c) and KEY not in json.dumps(c.describe()) and KEY not in str(c)
    assert c.describe()["api_key_configured"] is True


# ------------------------------------------------------------- request shape: stateless, no shared context
def test_requests_are_stateless_and_carry_no_session_identifiers(server):
    c = mc.OpenAICompatibleClient(cfg(server))
    assert c.generate("first secret prompt ALPHA")["text"].startswith("echo: first")
    c.generate("second prompt BETA")
    posts = [b for m, p, h, b in Fake.seen if m == "POST"]
    assert len(posts) == 2
    for b in posts:
        assert len(b["messages"]) == 1 and b["messages"][0]["role"] == "user"
        assert not ({"user", "session", "conversation", "previous_response_id", "n"} & set(b))
        assert b["temperature"] == 0 and b["stream"] is False and b["cache_prompt"] is False
    assert "ALPHA" not in json.dumps(posts[1])


def test_api_key_only_in_authorization_header(server):
    c = mc.OpenAICompatibleClient(cfg(server))
    c.ping()
    c.generate("hello")
    for m, path, headers, body in Fake.seen:
        assert headers["Authorization"] == "Bearer " + KEY
        assert KEY not in json.dumps(body or {}) and KEY not in path


def test_proxy_environment_is_ignored(server, monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:9")
    assert mc.OpenAICompatibleClient(cfg(server)).generate("hi")["text"] == "echo: hi"


# ------------------------------------------------------------- failures fail safe, without secrets
@pytest.mark.parametrize("mode,kind", [("500", "unavailable"), ("401", "auth"), ("slow", "timeout"),
                                       ("badjson", "bad_response"), ("shape", "bad_response"), ("huge", "bad_response"),
                                       ("redirect", "unavailable")])
def test_backend_failures_raise_fixed_secret_free_errors(server, mode, kind):
    Fake.mode = mode
    with pytest.raises(mc.ModelBackendError) as e:
        mc.OpenAICompatibleClient(cfg(server)).generate("hello")
    assert e.value.kind == kind
    assert KEY not in str(e.value) and KEY not in repr(e.value) and e.value.__cause__ is None


def test_unreachable_server_is_unavailable_not_stub_fallback():
    c = mc.OpenAICompatibleClient(cfg("http://127.0.0.1:9/v1"))
    with pytest.raises(mc.ModelBackendError) as e:
        c.ping()
    assert e.value.kind == "unavailable"


def test_redirect_target_is_never_contacted(server):
    Fake.mode = "redirect"
    with pytest.raises(mc.ModelBackendError):
        mc.OpenAICompatibleClient(cfg(server)).generate("hello")
    assert len([1 for m, *_ in Fake.seen if m == "POST"]) == 1


# ------------------------------------------------------------- broker integration (no containers)
@pytest.fixture
def broker(monkeypatch, server):
    monkeypatch.setattr(store, "VAR", Path(os.environ.get("TMPDIR", "/tmp")) / ("aegis-mc-%d" % time.time_ns()))
    monkeypatch.setattr(runs, "_signer", None)
    monkeypatch.setattr(runtime, "image_id", lambda *a: "0" * 64)
    monkeypatch.setattr(runtime, "image_repo_digest", lambda *a: "sha256:t")
    monkeypatch.setattr(runtime, "environment", lambda: {})
    for k, v in {"AEGIS_MODEL_BACKEND": "openai_compatible", "AEGIS_MODEL_BASE_URL": server, "AEGIS_MODEL_NAME": "m",
                 "AEGIS_MODEL_API_KEY": KEY, "AEGIS_MODEL_TIMEOUT_S": "0.5"}.items():
        monkeypatch.setenv(k, v)
    runs.create_run("T-MC", timing_bucket_ms=0)
    manifest = runs.freeze("T-MC")
    run = runs.Run("T-MC")
    run.update(state="RUNNING")
    b = runs.Broker(run)
    b._mk_spool("red")
    b.model_cfg = mc.load_config()
    b.model_client = mc.OpenAICompatibleClient(b.model_cfg)
    b.call = lambda role, msg, timeout=15.0: {"ok": True, "verdict": "allow", "rule": None}
    return b, manifest


def test_manifest_records_backend_without_key(broker):
    b, manifest = broker
    assert manifest["model"]["backend"] == "openai_compatible" and manifest["model"]["api_key_configured"] is True
    assert KEY not in json.dumps(manifest)
    for f in (b.run.dir / "manifest.json", b.run.dir / "audit.jsonl", b.run.dir / "monitor.jsonl"):
        assert KEY not in f.read_text()


def test_real_model_path_end_to_end_and_model_error_becomes_uniform_refusal(broker):
    from aegis.crypto import commitment
    b, _ = broker
    for i, mode in enumerate(["ok", "500", "ok"]):
        Fake.mode = mode
        aid, payload = "A%02d" % i, "prompt number %d" % i
        b.handle("0000%02d.json" % (i * 2), {"op": "commit", "commitments": [{"attack_id": aid, "digest": commitment("n", payload)}]})
        b.handle("0000%02d.json" % (i * 2 + 1), {"op": "attack", "attack_id": aid, "payload": payload, "nonce": "n"})
    arts = [json.loads(l) for l in (b.run.dir / "sealed/artifacts.jsonl").read_text().splitlines()]
    assert [a["outcome"] for a in arts] == ["safe_output", "model_error", "safe_output"]
    assert arts[1]["final_output"] == runs.UNIFORM_REFUSAL and arts[1]["model_output"] is None
    reply = json.loads((b.spool["red"] / "in" / "000003.json").read_text())
    assert reply["output"] == runs.UNIFORM_REFUSAL and "500" not in json.dumps(reply)
    text = (b.run.dir / "audit.jsonl").read_text() + (b.run.dir / "monitor.jsonl").read_text()
    assert KEY not in text and '"kind": "unavailable"' in text


def test_three_consecutive_model_errors_abort_the_run(broker):
    b, _ = broker
    Fake.mode = "500"
    assert b.generate("a") is None and b.generate("b") is None
    with pytest.raises(runs.GateError):
        b.generate("c")


def test_backend_change_after_freeze_is_rejected(broker, monkeypatch):
    b, _ = broker
    monkeypatch.setenv("AEGIS_MODEL_NAME", "a-different-model")
    with pytest.raises(runs.GateError):
        runs.Broker(b.run).start_workloads()


def test_invalid_backend_config_blocks_freeze(monkeypatch, tmp_path):
    monkeypatch.setattr(store, "VAR", tmp_path / "v")
    monkeypatch.setenv("AEGIS_MODEL_BACKEND", "openai_compatible")  # no URL, no model
    runs.create_run("T-BADCFG")
    with pytest.raises(runs.GateError):
        runs.freeze("T-BADCFG")
