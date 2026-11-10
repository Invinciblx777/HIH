"""Optional real-model backend (OpenAI-compatible chat endpoint). The deterministic stub stays the default.

Opt-in only, through environment variables read by the trusted control plane:

    AEGIS_MODEL_BACKEND=stub                  default; the stub model worker runs in its own container
    AEGIS_MODEL_BACKEND=openai_compatible     the broker calls the endpoint below instead of the stub
    AEGIS_MODEL_BASE_URL=http://127.0.0.1:8081/v1   required; must be loopback unless AEGIS_MODEL_ALLOW_REMOTE=1
    AEGIS_MODEL_NAME=<model id>               required
    AEGIS_MODEL_API_KEY=<secret>              optional; or AEGIS_MODEL_API_KEY_FILE=<path, mode 0600>
    AEGIS_MODEL_TIMEOUT_S=30                  per-request timeout
    AEGIS_MODEL_MAX_TOKENS=96
    AEGIS_MODEL_EXTRA_JSON='{"cache_prompt": false}'   extra request fields (default targets llama.cpp)
    AEGIS_UNSAFE_EXPERIMENT_SHARED_PROMPT_CACHE=1     the ONLY way to send cache_prompt=true (see below); experiments only
    AEGIS_MODEL_UNIX_SOCKET=/abs/path/llama.sock      optional (finale P3): connect over this UNIX socket instead of TCP, for a
                                              model server in a container with --network none; BASE_URL must then be
                                              http://localhost/... (its host only fills the Host header)
    AEGIS_MODEL_UNIX_SOCKET_OWNER_UID=<uid>   optional (finale P4): the host UID the socket must be owned by. The sandboxed server
                                              runs under --userns auto as a subordinate UID, not as the broker; the launcher
                                              records that one mapped UID here. Unset: the socket must be the broker's own
    AEGIS_MODEL_FILE_NAME / AEGIS_MODEL_FILE_SHA256 / AEGIS_MODEL_SERVER / AEGIS_MODEL_SERVER_ISOLATION
                                              optional (finale P3): the model identity declared by the operator's launcher
                                              (scripts/start_model_server.sh hashes the file it serves); recorded in the frozen
                                              manifest and the audit log, so a run names the weights that answered it

Security properties (each is covered by tests/test_model_client.py):
  * nothing is enabled automatically; a missing or invalid setting raises instead of falling back to the stub
  * every request is stateless: one user message, no history, no session or user identifier is sent
  * no proxy and no redirect is followed; non-loopback endpoints need an explicit flag because prompts leave the host
  * AEGIS_MODEL_TIMEOUT_S bounds the WHOLE exchange (connect, headers, body), not each socket operation, so a server that
    sends one byte at a time cannot hold the broker longer than the timeout
  * only a 200 reply with a JSON content type and at most MAX_RESPONSE_BYTES is accepted
  * the API key is only ever placed in the Authorization header; errors, audit entries and evidence carry
    fixed, key-free messages
  * failures, timeouts and malformed replies raise ModelBackendError with a fixed message; the broker turns that into a
    uniform refusal for red and fails the run closed after repeated errors
  * a UNIX socket is used only when it is a socket (not a link) owned by the EXPECTED owner (this user, or the one mapped UID
    in AEGIS_MODEL_UNIX_SOCKET_OWNER_UID; never "any owner") inside a directory owned by this user that no one else can
    enter: no group or other bits, and no ACL entry except, at most, that same expected UID; anything else is refused with
    ModelBackendError("config") before connecting
  * cache_prompt=true is refused: it turns the server's prompt (KV) cache back on, and experiment E3 measured a cross-session
    cached-token oracle with AUC 1.00 under it. Only AEGIS_UNSAFE_EXPERIMENT_SHARED_PROMPT_CACHE=1 lets it through, for the
    positive-control experiments; describe() then carries "unsafe_shared_prompt_cache_experiment": true, so the opt-in is in
    the frozen run manifest and in the audit entry model.session_opened

What this does NOT do: it cannot clear state inside the inference server (prefix/KV cache, GPU memory).
Whether such state is reachable from another session is something the experiments in
evaluation/model_experiments.py measure; the adapter only guarantees that AegisLab itself sends no shared context.
"""
import http.client
import ipaddress
import json
import os
import re
import socket
import stat
import threading
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

from . import userns

MAX_RESPONSE_BYTES = 1 << 20
MAX_TEXT = 8000
UNSAFE_CACHE_OPT_IN = "AEGIS_UNSAFE_EXPERIMENT_SHARED_PROMPT_CACHE"
UNIX_PATH_MAX = 107  # sun_path is 108 bytes including the terminating NUL
_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}")
_SHA_RE = re.compile(r"[0-9a-f]{64}")
_LABEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._()+,/:-]{0,95}")
ISOLATION_KINDS = ("host-process", "rootless-podman-network-none")


class ModelBackendError(RuntimeError):
    """Raised with a fixed, secret-free message. ``kind`` is one of unavailable|timeout|bad_response|auth|config."""

    def __init__(self, kind: str):
        super().__init__("model backend error: " + kind)
        self.kind = kind


@dataclass(frozen=True)
class ModelConfig:
    backend: str = "stub"
    base_url: str = ""
    model: str = ""
    api_key: str = field(default="", repr=False, compare=False)
    timeout_s: float = 30.0
    max_tokens: int = 96
    extra: tuple = ()
    allow_remote: bool = False
    unsafe_shared_prompt_cache: bool = False
    unix_socket: str = ""
    identity: tuple = ()  # declared (name, value) pairs: model_file, model_sha256, inference_server, server_isolation
    unix_socket_owner: int = -1  # finale P4: expected owner UID of the socket; -1 = this user (the P3 behaviour)

    def describe(self) -> dict:
        """Everything that may appear in manifests, audit entries and evidence. Never contains the key."""
        if self.backend == "stub":
            return {"backend": "stub"}
        u = urllib.parse.urlsplit(self.base_url)
        out = {"backend": self.backend, "model": self.model, "endpoint": "%s://%s%s" % (u.scheme, u.netloc, u.path),
               "loopback_only": not self.allow_remote, "api_key_configured": bool(self.api_key),
               "timeout_s": self.timeout_s, "max_tokens": self.max_tokens,
               "extra_body_fields": sorted(k for k, _ in self.extra), "stateless_requests": True}
        if self.unsafe_shared_prompt_cache:  # only present when opted in, so ordinary manifests are unchanged
            out["unsafe_shared_prompt_cache_experiment"] = True
        if self.unix_socket:  # the following keys are only present when configured, so earlier manifests are unchanged
            out["transport"] = "unix_socket"
            out["unix_socket"] = self.unix_socket
            if self.unix_socket_owner >= 0:
                out["unix_socket_owner_uid"] = self.unix_socket_owner
        if self.identity:
            out["declared_identity"] = dict(self.identity)
        return out


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def load_config(env=None) -> ModelConfig:
    env = os.environ if env is None else env
    backend = (env.get("AEGIS_MODEL_BACKEND") or "stub").strip().lower()
    if backend == "stub":
        return ModelConfig()
    if backend != "openai_compatible":
        raise ModelBackendError("config")
    base, model = (env.get("AEGIS_MODEL_BASE_URL") or "").strip(), (env.get("AEGIS_MODEL_NAME") or "").strip()
    if not base or not model:
        raise ModelBackendError("config")
    u = urllib.parse.urlsplit(base)
    if u.scheme not in ("http", "https") or not u.hostname or u.username or u.password or u.query or u.fragment:
        raise ModelBackendError("config")
    allow_remote = env.get("AEGIS_MODEL_ALLOW_REMOTE") == "1"
    if not _is_loopback(u.hostname) and not allow_remote:
        raise ModelBackendError("config")
    key = env.get("AEGIS_MODEL_API_KEY", "")
    key_file = env.get("AEGIS_MODEL_API_KEY_FILE")
    if key_file and not key:
        try:
            if Path(key_file).stat().st_mode & 0o077:
                raise ModelBackendError("config")  # a group/world readable key file is refused
            key = Path(key_file).read_text().strip()
        except OSError:
            raise ModelBackendError("config") from None
    try:
        extra = json.loads(env.get("AEGIS_MODEL_EXTRA_JSON", '{"cache_prompt": false}'))
        timeout, max_tokens = float(env.get("AEGIS_MODEL_TIMEOUT_S", "30")), int(env.get("AEGIS_MODEL_MAX_TOKENS", "96"))
    except (ValueError, TypeError):
        raise ModelBackendError("config")
    if not isinstance(extra, dict) or set(extra) & {"messages", "model", "stream", "user", "n", "max_tokens"} \
            or not (0 < timeout <= 600) or not (0 < max_tokens <= 1024):
        raise ModelBackendError("config")
    # Anything but an explicit false re-enables the shared prompt cache (llama.cpp treats a missing field as true in some
    # versions and any truthy value as true), so a missing, null or non-boolean value is replaced or refused, never passed on.
    unsafe = env.get(UNSAFE_CACHE_OPT_IN) == "1"
    if "cache_prompt" not in extra or extra["cache_prompt"] is None:
        extra["cache_prompt"] = False
    if not isinstance(extra["cache_prompt"], bool) or (extra["cache_prompt"] and not unsafe):
        raise ModelBackendError("config")
    sock = (env.get("AEGIS_MODEL_UNIX_SOCKET") or "").strip()
    if sock and (not sock.startswith("/") or "\x00" in sock or len(sock.encode()) > UNIX_PATH_MAX or allow_remote
                 or u.scheme != "http" or u.hostname != "localhost"):
        raise ModelBackendError("config")
    owner = (env.get("AEGIS_MODEL_UNIX_SOCKET_OWNER_UID") or "").strip()
    if owner and (not sock or not owner.isdigit() or int(owner) == os.geteuid() or not 0 < int(owner) < 2**32 - 1):
        raise ModelBackendError("config")  # only with a socket, and a mapped UID is never the broker's own
    ident = []
    for var, key_, rx in (("AEGIS_MODEL_FILE_NAME", "model_file", _NAME_RE), ("AEGIS_MODEL_FILE_SHA256", "model_sha256", _SHA_RE),
                          ("AEGIS_MODEL_SERVER", "inference_server", _LABEL_RE)):
        v = (env.get(var) or "").strip()
        if v:
            if not rx.fullmatch(v):
                raise ModelBackendError("config")
            ident.append((key_, v))
    iso = (env.get("AEGIS_MODEL_SERVER_ISOLATION") or "").strip()
    if iso:
        if iso not in ISOLATION_KINDS or (iso == ISOLATION_KINDS[1]) != bool(sock):
            raise ModelBackendError("config")  # a server without network is only reachable over the socket, and vice versa
        ident.append(("server_isolation", iso))
    return ModelConfig("openai_compatible", base.rstrip("/"), model, key, timeout, max_tokens,
                       tuple(sorted(extra.items())), allow_remote, unsafe and extra["cache_prompt"], sock, tuple(sorted(ident)),
                       int(owner) if owner else -1)


def check_unix_socket(path: str, owner: int = -1):
    """Refuse a socket that someone else could have placed or could also use. The socket must be a socket (lstat: a symlink
    is refused) owned by the EXPECTED owner: this user when ``owner`` is -1, else exactly ``owner`` (the sandboxed server's
    mapped subordinate UID, finale P4). Its directory must be owned by this user, with no group or other permission bits;
    a POSIX ACL on it may name at most that same expected owner (the launcher's grant), nothing else."""
    try:
        st, dst = os.lstat(path), os.lstat(os.path.dirname(path))
    except OSError:
        raise ModelBackendError("unavailable") from None
    uid = os.geteuid()
    want = uid if owner is None or owner < 0 else owner
    if not stat.S_ISSOCK(st.st_mode) or st.st_uid != want or not stat.S_ISDIR(dst.st_mode) or dst.st_uid != uid:
        raise ModelBackendError("config")
    try:
        ok = userns.private_to(os.path.dirname(path), uid, () if want == uid else (want,))
    except (OSError, ValueError):
        ok = False
    if not ok:
        raise ModelBackendError("config")


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout, owner=-1):
        super().__init__("localhost", timeout=timeout)
        self._unix_path = path
        self._owner = owner

    def connect(self):
        check_unix_socket(self._unix_path, self._owner)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            s.connect(self._unix_path)
        except OSError:
            s.close()
            raise
        self.sock = s


class OpenAICompatibleClient:
    def __init__(self, cfg: ModelConfig):
        if cfg.backend != "openai_compatible":
            raise ModelBackendError("config")
        self.cfg = cfg

    def _request(self, method, path, body=None, timeout_s=None):
        """One HTTP exchange over http.client: no proxy handling and no redirect handling exist in it, so neither can
        happen. A watchdog closes the socket when the total time budget is spent. timeout_s (finale P4) may only shorten the
        configured budget, for the broker's deadline-mode cut-off; closing the connection makes llama.cpp stop generating."""
        budget = self.cfg.timeout_s if timeout_s is None else max(0.001, min(float(timeout_s), self.cfg.timeout_s))
        headers = {"Content-Type": "application/json", "Accept": "application/json", "Connection": "close"}
        if self.cfg.api_key:
            headers["Authorization"] = "Bearer " + self.cfg.api_key
        data = json.dumps(body).encode() if body is not None else None
        u = urllib.parse.urlsplit(self.cfg.base_url + path)
        if self.cfg.unix_socket:
            conn = _UnixHTTPConnection(self.cfg.unix_socket, budget, self.cfg.unix_socket_owner)
        else:
            factory = http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection
            conn = factory(u.hostname, u.port, timeout=budget)
        expired = threading.Event()
        live = []  # the connected socket; http.client drops conn.sock once a reply says "Connection: close", the body is still unread

        def cut():
            expired.set()
            for sock in list(live):
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

        watchdog = threading.Timer(budget, cut)
        watchdog.daemon = True
        watchdog.start()
        try:
            try:
                conn.request(method, u.path, body=data, headers=headers)
                live.append(conn.sock)
                if expired.is_set():
                    cut()
                resp = conn.getresponse()
                status, ctype = resp.status, resp.getheader("Content-Type", "")
                length = resp.getheader("Content-Length", "")
                oversize = length.isdigit() and int(length) > MAX_RESPONSE_BYTES
                raw = resp.read(MAX_RESPONSE_BYTES + 1) if status == 200 and not oversize else b""
            except TimeoutError:
                raise ModelBackendError("timeout") from None
            except ConnectionError:  # refused, reset, or the server went away before it answered
                raise ModelBackendError("timeout" if expired.is_set() else "unavailable") from None
            except http.client.HTTPException:  # malformed status line or headers, truncated body
                raise ModelBackendError("timeout" if expired.is_set() else "bad_response") from None
            except OSError:
                raise ModelBackendError("timeout" if expired.is_set() else "unavailable") from None
        finally:
            watchdog.cancel()
            conn.close()
        if expired.is_set():
            raise ModelBackendError("timeout")
        if status in (401, 403):
            raise ModelBackendError("auth")
        if status != 200:
            raise ModelBackendError("unavailable")
        if oversize or len(raw) > MAX_RESPONSE_BYTES:
            raise ModelBackendError("bad_response")
        if ctype.split(";")[0].strip().lower() != "application/json":
            raise ModelBackendError("bad_response")
        try:
            return json.loads(raw)
        except (ValueError, RecursionError):
            raise ModelBackendError("bad_response") from None

    def ping(self):
        """Availability check before a run starts; a failure fails the run closed, never falls back to the stub."""
        self._request("GET", "/models")

    def generate(self, prompt: str, timeout_s=None) -> dict:
        """One stateless completion. Returns {"text", "usage"}; only ``text`` ever reaches red or blue. timeout_s: see _request."""
        body = {**dict(self.cfg.extra), "model": self.cfg.model, "stream": False, "max_tokens": self.cfg.max_tokens,
                "temperature": 0, "messages": [{"role": "user", "content": prompt[:8000]}]}
        reply = self._request("POST", "/chat/completions", body, timeout_s)
        try:
            text = reply["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            raise ModelBackendError("bad_response") from None
        if not isinstance(text, str):
            raise ModelBackendError("bad_response")
        usage = reply.get("usage") if isinstance(reply.get("usage"), dict) else {}
        return {"text": text[:MAX_TEXT], "usage": usage}
