"""Finale P3: the model adapter's UNIX-socket transport (model server in a container with --network none) and the declared
model identity that is recorded in the frozen manifest. No real model is needed: a tiny OpenAI-compatible fake listens on a
UNIX socket in a private temporary directory."""
import json
import os
import socket
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from aegis import model_client as mc

SHA = "74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db"
KEY = "p3-test-key-value"


class _UnixHTTPServer(HTTPServer):
    address_family = socket.AF_UNIX

    def server_bind(self):
        self.socket.bind(self.server_address)

    def get_request(self):
        req, _ = self.socket.accept()
        return req, ("local", 0)


def _fake(path, seen):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, obj):
            raw = json.dumps(obj).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            seen.append(("GET", self.path, self.headers.get("Authorization"), None))
            self._send({"data": [{"id": "local"}]})

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            seen.append(("POST", self.path, self.headers.get("Authorization"), body))
            self._send({"choices": [{"message": {"content": "hello over the socket"}}], "usage": {"prompt_tokens": 3}})

    srv = _UnixHTTPServer(path, H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.fixture
def sockdir():
    base = os.environ.get("XDG_RUNTIME_DIR") or "/tmp"
    d = tempfile.mkdtemp(prefix="p3t.", dir=base if len(base) < 40 else "/tmp")
    os.chmod(d, 0o700)
    yield Path(d)
    for f in Path(d).iterdir():
        f.unlink()
    os.rmdir(d)


def _env(sock, **kw):
    e = {"AEGIS_MODEL_BACKEND": "openai_compatible", "AEGIS_MODEL_BASE_URL": "http://localhost/v1", "AEGIS_MODEL_NAME": "local",
         "AEGIS_MODEL_API_KEY": KEY, "AEGIS_MODEL_UNIX_SOCKET": str(sock), "AEGIS_MODEL_TIMEOUT_S": "5"}
    e.update(kw)
    return e


def test_generate_and_ping_over_unix_socket(sockdir):
    sock, seen = sockdir / "llama.sock", []
    srv = _fake(str(sock), seen)
    try:
        cl = mc.OpenAICompatibleClient(mc.load_config(_env(sock)))
        cl.ping()
        out = cl.generate("hi")
    finally:
        srv.shutdown()
        srv.server_close()
    assert out["text"] == "hello over the socket"
    assert [s[:2] for s in seen] == [("GET", "/v1/models"), ("POST", "/v1/chat/completions")]
    assert all(s[2] == "Bearer " + KEY for s in seen)
    body = seen[1][3]
    assert body["cache_prompt"] is False and len(body["messages"]) == 1 and "user" not in body


def test_describe_records_transport_and_identity_without_key(sockdir):
    sock = sockdir / "llama.sock"
    d = mc.load_config(_env(sock, AEGIS_MODEL_FILE_NAME="qwen2.5-0.5b-instruct-q4_k_m.gguf", AEGIS_MODEL_FILE_SHA256=SHA,
                            AEGIS_MODEL_SERVER="llama.cpp b11819 CPU", AEGIS_MODEL_SERVER_ISOLATION="rootless-podman-network-none")).describe()
    assert d["transport"] == "unix_socket" and d["unix_socket"] == str(sock)
    assert d["declared_identity"] == {"model_file": "qwen2.5-0.5b-instruct-q4_k_m.gguf", "model_sha256": SHA,
                                      "inference_server": "llama.cpp b11819 CPU", "server_isolation": "rootless-podman-network-none"}
    assert KEY not in json.dumps(d)


def test_tcp_manifest_unchanged_without_new_settings():
    env = {"AEGIS_MODEL_BACKEND": "openai_compatible", "AEGIS_MODEL_BASE_URL": "http://127.0.0.1:8081/v1", "AEGIS_MODEL_NAME": "m"}
    d = mc.load_config(env).describe()
    assert "transport" not in d and "unix_socket" not in d and "declared_identity" not in d
    assert sorted(d) == ["api_key_configured", "backend", "endpoint", "extra_body_fields", "loopback_only", "max_tokens", "model",
                         "stateless_requests", "timeout_s"]


@pytest.mark.parametrize("over", [
    {"AEGIS_MODEL_UNIX_SOCKET": "relative/llama.sock"},
    {"AEGIS_MODEL_UNIX_SOCKET": "/" + "x" * 120 + ".sock"},
    {"AEGIS_MODEL_BASE_URL": "http://127.0.0.1:9/v1"},
    {"AEGIS_MODEL_BASE_URL": "https://localhost/v1"},
    {"AEGIS_MODEL_ALLOW_REMOTE": "1"},
    {"AEGIS_MODEL_FILE_SHA256": "ABC"},
    {"AEGIS_MODEL_FILE_SHA256": SHA.upper()},
    {"AEGIS_MODEL_FILE_NAME": "../etc/passwd"},
    {"AEGIS_MODEL_FILE_NAME": "a b"},
    {"AEGIS_MODEL_SERVER": "x" * 200},
    {"AEGIS_MODEL_SERVER": "<script>"},
    {"AEGIS_MODEL_SERVER_ISOLATION": "gvisor"},
])
def test_invalid_socket_or_identity_settings_refused(sockdir, over):
    with pytest.raises(mc.ModelBackendError) as e:
        mc.load_config(_env(sockdir / "llama.sock", **over))
    assert e.value.kind == "config"


def test_isolation_label_must_match_transport():
    tcp = {"AEGIS_MODEL_BACKEND": "openai_compatible", "AEGIS_MODEL_BASE_URL": "http://127.0.0.1:8081/v1", "AEGIS_MODEL_NAME": "m"}
    with pytest.raises(mc.ModelBackendError):
        mc.load_config({**tcp, "AEGIS_MODEL_SERVER_ISOLATION": "rootless-podman-network-none"})
    assert mc.load_config({**tcp, "AEGIS_MODEL_SERVER_ISOLATION": "host-process"}).describe()["declared_identity"] == {"server_isolation": "host-process"}


def test_socket_in_group_or_world_accessible_dir_refused(sockdir):
    sock, seen = sockdir / "llama.sock", []
    srv = _fake(str(sock), seen)
    try:
        cl = mc.OpenAICompatibleClient(mc.load_config(_env(sock)))
        for mode in (0o750, 0o701, 0o777):
            os.chmod(sockdir, mode)
            with pytest.raises(mc.ModelBackendError) as e:
                cl.generate("hi")
            assert e.value.kind == "config"
        os.chmod(sockdir, 0o700)
        assert cl.generate("hi")["text"]
    finally:
        os.chmod(sockdir, 0o700)
        srv.shutdown()
        srv.server_close()
    assert len([s for s in seen if s[0] == "POST"]) == 1  # nothing was sent while the directory was open


def test_non_socket_and_missing_socket(sockdir):
    f = sockdir / "llama.sock"
    f.write_text("not a socket")
    with pytest.raises(mc.ModelBackendError) as e:
        mc.OpenAICompatibleClient(mc.load_config(_env(f))).ping()
    assert e.value.kind == "config"
    f.unlink()
    with pytest.raises(mc.ModelBackendError) as e:
        mc.OpenAICompatibleClient(mc.load_config(_env(f))).ping()
    assert e.value.kind == "unavailable"


def test_symlinked_socket_refused(sockdir):
    sock, seen = sockdir / "real.sock", []
    srv = _fake(str(sock), seen)
    try:
        link = sockdir / "llama.sock"
        link.symlink_to(sock)
        with pytest.raises(mc.ModelBackendError) as e:
            mc.OpenAICompatibleClient(mc.load_config(_env(link))).ping()
        assert e.value.kind == "config" and not seen
    finally:
        srv.shutdown()
        srv.server_close()


def test_cache_guard_still_applies_over_socket(sockdir):
    with pytest.raises(mc.ModelBackendError):
        mc.load_config(_env(sockdir / "llama.sock", AEGIS_MODEL_EXTRA_JSON='{"cache_prompt": true}'))
