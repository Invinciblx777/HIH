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

Security properties (each is covered by tests/test_model_client.py):
  * nothing is enabled automatically; a missing or invalid setting raises instead of falling back to the stub
  * every request is stateless: one user message, no history, no session or user identifier is sent
  * no proxy and no redirect is followed; non-loopback endpoints need an explicit flag because prompts leave the host
  * the API key is only ever placed in the Authorization header; errors, audit entries and evidence carry
    fixed, key-free messages
  * failures, timeouts and malformed replies raise ModelBackendError with a fixed message; the broker turns that into a
    uniform refusal for red and fails the run closed after repeated errors

What this does NOT do: it cannot clear state inside the inference server (prefix/KV cache, GPU memory).
Whether such state is reachable from another session is something the experiments in
evaluation/model_experiments.py measure; the adapter only guarantees that AegisLab itself sends no shared context.
"""
import ipaddress
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

MAX_RESPONSE_BYTES = 1 << 20
MAX_TEXT = 8000


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

    def describe(self) -> dict:
        """Everything that may appear in manifests, audit entries and evidence. Never contains the key."""
        if self.backend == "stub":
            return {"backend": "stub"}
        u = urllib.parse.urlsplit(self.base_url)
        return {"backend": self.backend, "model": self.model, "endpoint": "%s://%s%s" % (u.scheme, u.netloc, u.path),
                "loopback_only": not self.allow_remote, "api_key_configured": bool(self.api_key),
                "timeout_s": self.timeout_s, "max_tokens": self.max_tokens,
                "extra_body_fields": sorted(k for k, _ in self.extra), "stateless_requests": True}


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
    return ModelConfig("openai_compatible", base.rstrip("/"), model, key, timeout, max_tokens,
                       tuple(sorted(extra.items())), allow_remote)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):
        return None


class OpenAICompatibleClient:
    def __init__(self, cfg: ModelConfig):
        if cfg.backend != "openai_compatible":
            raise ModelBackendError("config")
        self.cfg = cfg
        # ProxyHandler({}) ignores HTTP(S)_PROXY from the environment; the redirect handler refuses redirects
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)

    def _request(self, method, path, body=None):
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.cfg.api_key:
            headers["Authorization"] = "Bearer " + self.cfg.api_key
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.cfg.base_url + path, data=data, headers=headers, method=method)
        try:
            with self._opener.open(req, timeout=self.cfg.timeout_s) as resp:
                raw = resp.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            raise ModelBackendError("auth" if exc.code in (401, 403) else "unavailable") from None
        except TimeoutError:
            raise ModelBackendError("timeout") from None
        except urllib.error.URLError as exc:
            raise ModelBackendError("timeout" if isinstance(exc.reason, TimeoutError) else "unavailable") from None
        except OSError:
            raise ModelBackendError("unavailable") from None
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ModelBackendError("bad_response")
        try:
            return json.loads(raw)
        except (ValueError, RecursionError):
            raise ModelBackendError("bad_response") from None

    def ping(self):
        """Availability check before a run starts; a failure fails the run closed, never falls back to the stub."""
        self._request("GET", "/models")

    def generate(self, prompt: str) -> dict:
        """One stateless completion. Returns {"text", "usage"}; only ``text`` ever reaches red or blue."""
        body = {**dict(self.cfg.extra), "model": self.cfg.model, "stream": False, "max_tokens": self.cfg.max_tokens,
                "temperature": 0, "messages": [{"role": "user", "content": prompt[:8000]}]}
        reply = self._request("POST", "/chat/completions", body)
        try:
            text = reply["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            raise ModelBackendError("bad_response") from None
        if not isinstance(text, str):
            raise ModelBackendError("bad_response")
        usage = reply.get("usage") if isinstance(reply.get("usage"), dict) else {}
        return {"text": text[:MAX_TEXT], "usage": usage}
