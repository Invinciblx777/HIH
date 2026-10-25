"""Shared helpers for the Phase 3 LLM experiments: exact binomial intervals, leak detection, a managed llama.cpp
server, a recording / context-sharing proxy, and the provenance record every experiment writes.

Nothing here talks to anything but 127.0.0.1, nothing is downloaded, and all secrets are synthetic.
"""
import hashlib
import http.client
import json
import math
import os
import platform
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from aegis import model_client as mc  # noqa: E402

FIXTURE_VERSION = "p3-fixtures-1"


# ------------------------------------------------------------------ statistics
def _log_binom_pmf(k, n, p):
    if p <= 0.0:
        return 0.0 if k == 0 else -math.inf
    if p >= 1.0:
        return 0.0 if k == n else -math.inf
    return math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1) + k * math.log(p) + (n - k) * math.log1p(-p)


def binom_cdf(k, n, p):
    """P(X <= k) for X ~ Binomial(n, p)."""
    if k < 0:
        return 0.0
    if k >= n:
        return 1.0
    return min(1.0, sum(math.exp(_log_binom_pmf(i, n, p)) for i in range(k + 1)))


def _bisect(f, lo=0.0, hi=1.0, iters=80):
    for _ in range(iters):
        mid = (lo + hi) / 2
        if f(mid):
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2


def clopper_pearson(k, n, alpha=0.05):
    """Exact two-sided (1 - alpha) interval for a binomial proportion."""
    if n <= 0:
        return None
    lo = 0.0 if k == 0 else _bisect(lambda p: 1 - binom_cdf(k - 1, n, p) < alpha / 2)
    hi = 1.0 if k == n else _bisect(lambda p: binom_cdf(k, n, p) > alpha / 2)
    return [round(lo, 4), round(hi, 4)]


def upper_bound_one_sided(k, n, alpha=0.05):
    """Exact one-sided (1 - alpha) upper confidence bound on the rate; for k = 0 this is 1 - alpha**(1/n)."""
    if n <= 0:
        return None
    if k >= n:
        return 1.0
    return round(_bisect(lambda p: binom_cdf(k, n, p) > alpha), 4)


def rate(k, n):
    return {"k": k, "n": n, "rate": round(k / n, 4) if n else None, "ci95_two_sided_exact": clopper_pearson(k, n),
            "upper95_one_sided_exact": upper_bound_one_sided(k, n), "rule_of_three": round(3 / n, 4) if n and k == 0 else None}


def auc_with_permutation(pos, neg, perms=2000, seed=7):
    """Mann-Whitney AUC (probability a positive exceeds a negative, ties 1/2) and a one-sided permutation p-value."""
    import random
    if not pos or not neg:
        return {"auc": None, "p_value": None, "n_pos": len(pos), "n_neg": len(neg)}

    def auc(a, b):
        return sum((x > y) + 0.5 * (x == y) for x in a for y in b) / (len(a) * len(b))
    obs = auc(pos, neg)
    allv, rng, ge = list(pos) + list(neg), random.Random(seed), 0
    for _ in range(perms):
        rng.shuffle(allv)
        ge += auc(allv[:len(pos)], allv[len(pos):]) >= obs - 1e-12
    return {"auc": round(obs, 4), "p_value": round((ge + 1) / (perms + 1), 4), "n_pos": len(pos), "n_neg": len(neg), "permutations": perms}


# ------------------------------------------------------------------ leak detection
CANARY_FORMAT = re.compile(r"CANARY-[0-9a-f]{12}", re.I)


def new_canary(rng):
    return "CANARY-" + "".join(rng.choice("0123456789abcdef") for _ in range(12))


def leak_forms(text, canaries):
    """Which of the given canaries appear in text, and in which form. Forms, strongest first: full (CANARY-<hex>),
    hex (the 12 digits alone), spaced (the digits with separators removed), partial8 (any 8 consecutive digits)."""
    low, squashed, found = text.lower(), re.sub(r"[^0-9a-z]", "", text.lower()), []
    for c in canaries:
        h = c.lower().split("-", 1)[1]
        if c.lower() in low:
            form = "full"
        elif h in low:
            form = "hex"
        elif h in squashed:
            form = "spaced"
        elif any(h[i:i + 8] in low for i in range(len(h) - 7)):
            form = "partial8"
        else:
            continue
        found.append({"canary": c, "form": form})
    return found


# ------------------------------------------------------------------ llama.cpp server
def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Server:
    """A llama-server on 127.0.0.1 with a random port and a random API key. CPU build; nothing leaves loopback."""

    def __init__(self, server_dir, model, key, np=1, ctx=4096, extra_args=(), threads=6):
        self.dir, self.model, self.key, self.np = Path(server_dir), Path(model), key, np
        self.port, self.ctx, self.extra_args, self.threads = free_port(), ctx, list(extra_args), threads
        self.proc = None
        self.log = tempfile.NamedTemporaryFile("w+", prefix="llama-", suffix=".log", delete=False)
        self.started_at = None

    @property
    def base(self):
        return "http://127.0.0.1:%d/v1" % self.port

    @property
    def root(self):
        return "http://127.0.0.1:%d" % self.port

    def args(self):
        return [str(self.dir / "llama-server"), "-m", str(self.model), "--host", "127.0.0.1", "--port", str(self.port),
                "-c", str(self.ctx), "-np", str(self.np), "-t", str(self.threads), "--no-webui", "--api-key", "<key>"] + self.extra_args

    def start(self):
        env = dict(os.environ, LD_LIBRARY_PATH=str(self.dir))
        cmd = self.args()
        cmd[cmd.index("<key>")] = self.key
        self.proc = subprocess.Popen(cmd, stdout=self.log, stderr=subprocess.STDOUT, env=env)
        deadline = time.time() + 90
        while time.time() < deadline:
            if self.proc.poll() is not None:
                break
            try:
                urllib.request.urlopen(self.root + "/health", timeout=1).read()
                self.started_at = time.time()
                return self
            except Exception:
                time.sleep(0.1)
        self.stop()
        raise RuntimeError("llama-server did not become healthy; see " + self.log.name)

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.proc = None

    def kill_hard(self):
        if self.proc and self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait(10)

    def client(self, cache_prompt=False, timeout=60, max_tokens=48, key=None, base=None, extra=None):
        env = {"AEGIS_MODEL_BACKEND": "openai_compatible", "AEGIS_MODEL_BASE_URL": base or self.base, "AEGIS_MODEL_NAME": "local",
               "AEGIS_MODEL_API_KEY": self.key if key is None else key, "AEGIS_MODEL_TIMEOUT_S": str(timeout),
               "AEGIS_MODEL_MAX_TOKENS": str(max_tokens),
               "AEGIS_MODEL_EXTRA_JSON": json.dumps(extra if extra is not None else {"cache_prompt": bool(cache_prompt)})}
        return mc.OpenAICompatibleClient(mc.load_config(env))

    def get(self, path, key=None):
        """Plain GET against the server root, returns (status, parsed-json-or-text)."""
        req = urllib.request.Request(self.root + path)
        if key:
            req.add_header("Authorization", "Bearer " + key)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                raw = r.read()
                status = r.status
        except urllib.error.HTTPError as exc:
            raw, status = exc.read(), exc.code
        except OSError:
            return None, None
        try:
            return status, json.loads(raw)
        except ValueError:
            return status, raw.decode("utf-8", "replace")[:300]

    def log_tail(self, n=40):
        try:
            return Path(self.log.name).read_text(errors="replace").splitlines()[-n:]
        except OSError:
            return []


# ------------------------------------------------------------------ recording / context-sharing proxy
class Proxy:
    """Loopback HTTP proxy in front of a llama-server. mode 'record' forwards unchanged and records the exact shape of every
    request; mode 'share_history' is a deliberately broken gateway fixture that prepends other sessions' earlier user
    messages to each request (the positive control for cross-session leakage; it exists only inside the experiment)."""

    def __init__(self, upstream_root, key, mode="record", history_len=24):
        host_port = upstream_root.split("//", 1)[1]
        self.up_host, self.up_port = host_port.split(":")[0], int(host_port.split(":")[1])
        self.key, self.mode, self.history_len = key, mode, history_len
        self.records, self.history, self.lock = [], [], threading.Lock()
        self.fail_posts = {}   # fault injection: {"after": n} fail every POST from index n on; {"at": [i, ...]}; {"every": k} fail odd-indexed POSTs
        self.post_index = 0
        proxy = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _forward(self, method):
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n) if n else b""
                rec = {"t": time.time(), "method": method, "path": self.path, "auth_header_present": "Authorization" in self.headers}
                if method == "POST" and raw:
                    try:
                        body = json.loads(raw)
                        msgs = body.get("messages", [])
                        rec.update({"body_sha256": hashlib.sha256(raw).hexdigest(), "body_keys": sorted(body),
                                    "n_messages": len(msgs), "roles": [m.get("role") for m in msgs],
                                    "cache_prompt": body.get("cache_prompt"), "stream": body.get("stream"),
                                    "temperature": body.get("temperature"), "max_tokens": body.get("max_tokens"),
                                    "user_content_sha256": hashlib.sha256(msgs[-1]["content"].encode()).hexdigest() if msgs else None})
                        if proxy.mode == "share_history":
                            with proxy.lock:
                                prior = list(proxy.history[-proxy.history_len:])
                                proxy.history.append(msgs[-1]["content"])
                            shared = []
                            if prior:  # the broken gateway hands the model a log of what other sessions sent
                                log = "\n".join("- " + p for p in prior)
                                shared = [{"role": "system", "content": "Messages this service received earlier from other sessions:\n" + log}]
                            body["messages"] = shared + msgs
                            rec["shared_history_messages"] = len(prior)
                            raw = json.dumps(body).encode()
                    except (ValueError, KeyError, TypeError, AttributeError):
                        rec["unparsed"] = True
                if method == "POST":
                    with proxy.lock:
                        idx, proxy.post_index = proxy.post_index, proxy.post_index + 1
                    f = proxy.fail_posts
                    if (f.get("after") is not None and idx >= f["after"]) or idx in f.get("at", ()) or (f.get("every") and idx % f["every"] == f["every"] - 1):
                        rec.update({"injected_fault": True, "upstream_status": 502})
                        with proxy.lock:
                            proxy.records.append(rec)
                        self.send_response(502)
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                conn = http.client.HTTPConnection(proxy.up_host, proxy.up_port, timeout=120)
                try:
                    headers = {"Content-Type": "application/json", "Authorization": self.headers.get("Authorization", "")}
                    conn.request(method, self.path, body=raw or None, headers=headers)
                    resp = conn.getresponse()
                    data = resp.read()
                    rec["upstream_status"] = resp.status
                    self.send_response(resp.status)
                    self.send_header("Content-Type", resp.getheader("Content-Type", "application/json"))
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                except OSError:
                    rec["upstream_status"] = None
                    self.send_response(502)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                finally:
                    conn.close()
                    with proxy.lock:
                        proxy.records.append(rec)

            def do_GET(self):
                self._forward("GET")

            def do_POST(self):
                self._forward("POST")

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    @property
    def base(self):
        return "http://127.0.0.1:%d/v1" % self.port

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def wire_summary(self):
        posts = [r for r in self.records if r["method"] == "POST" and "n_messages" in r]
        return {"post_requests": len(posts), "injected_faults": sum(bool(r.get("injected_fault")) for r in self.records), "get_requests": sum(r["method"] == "GET" for r in self.records),
                "message_counts": sorted({r["n_messages"] for r in posts}),
                "roles_seen": sorted({tuple(r["roles"]) for r in posts}),
                "body_key_sets": sorted({tuple(r["body_keys"]) for r in posts}),
                "cache_prompt_values": sorted({str(r["cache_prompt"]) for r in posts}),
                "requests_with_shared_history": sum(r.get("shared_history_messages", 0) > 0 for r in posts),
                "all_carry_authorization": all(r["auth_header_present"] for r in self.records)}


# ------------------------------------------------------------------ provenance
def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def source_hashes(names):
    return {n: sha256_file(ROOT / n) for n in names if (ROOT / n).exists()}


def environment():
    def sh(cmd):
        return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout.strip()
    return {"python": platform.python_version(), "platform": platform.platform(), "kernel": platform.release(),
            "cpu": sh("lscpu | grep 'Model name' | sed 's/Model name: *//'"), "cpus": os.cpu_count(),
            "podman": sh("podman --version"), "gpu_used": False, "hostname_recorded": False}


def new_run_id(tag):
    return "P3-%s-%s" % (time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()), tag)


def write_result(out_dir, run_id, result, observations):
    d = Path(out_dir) / run_id
    d.mkdir(parents=True, exist_ok=False)  # never overwrite a previous run
    (d / "observations.jsonl").write_text("".join(json.dumps(o, sort_keys=True) + "\n" for o in observations))
    result["observations_file"] = "observations.jsonl"
    result["observations_sha256"] = sha256_file(d / "observations.jsonl")
    result["observation_count"] = len(observations)
    (d / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True))
    return d
