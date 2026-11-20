"""Finale P16 (part A): the Qwen3Guard guard. OFF by default; these tests pin that, the fail-closed rules, the verdict parsing and
the channel boundaries (only the defence runner reaches the guard; red and the model worker never do).

Container-free tests use a fake guard (a stdlib HTTP server on a UNIX socket). The tests marked podman need the sandbox image;
the two that look at a live guard need AEGIS_GUARD_TEST_RUNDIR (a run directory printed by scripts/start_guard_server.sh).
"""
import hashlib
import importlib
import json
import os
import socket
import socketserver
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "sandbox"))
sys.path.insert(0, str(ROOT / "guard"))

from aegis import guard as aguard, runtime  # noqa: E402


def load(tmp_path, monkeypatch, cfg):
    raw = json.dumps(cfg).encode()
    path = tmp_path / "defence_config.json"
    path.write_bytes(raw)
    monkeypatch.setenv("AEGIS_CONFIG_PATH", str(path))
    monkeypatch.setenv("AEGIS_DEFENCE_DIGEST", "sha256:" + hashlib.sha256(raw).hexdigest())
    for m in ("defence_runner", "guard_runner"):
        sys.modules.pop(m, None)
    dr = importlib.import_module("defence_runner")
    gr = importlib.import_module("guard_runner")
    return dr, gr


class FakeGuard:
    """A guard server on a UNIX socket that answers /completion with a fixed text (or sleeps, or fails)."""

    def __init__(self, root: Path, answer="Safety: Safe\nCategories: None", delay=0.0, status=200):
        self.dir = root / "guard"
        (self.dir / "sock").mkdir(parents=True)
        (self.dir / "key").write_text("k3y\n")
        self.answer, self.delay, self.status, self.bodies = answer, delay, status, []
        fake = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                fake.bodies.append((self.headers.get("Authorization"), body))
                if body.get("n_predict") == 0:
                    out = {"content": "", "timings": {"prompt_n": 1, "cache_n": 200}}
                else:
                    time.sleep(fake.delay)
                    out = {"content": fake.answer, "timings": {"prompt_n": 100, "cache_n": 200}}
                data = json.dumps(out).encode()
                self.send_response(fake.status)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *a):
                pass

        class S(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
            daemon_threads = True

        self.srv = S(str(self.dir / "sock" / "guard.sock"), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


@pytest.fixture
def guard(tmp_path, monkeypatch):
    made = []

    def make(**kw):
        g = FakeGuard(tmp_path, **kw)
        made.append(g)
        return g
    yield make
    for g in made:
        g.close()


# ------------------------------------------------------------------ OFF by default
def test_P16A01_without_the_flag_runtime_launches_the_tags_defence_runner_unchanged(monkeypatch):
    monkeypatch.delenv("AEGIS_GUARD_RUNDIR", raising=False)
    mounts = [("/x/spool/in", "/aegis/spool/in", "rw"), ("/x/frozen", "/aegis/frozen", "ro")]
    assert aguard.guard_extension("blue", mounts, {"A": "1"}, None) == (mounts, {"A": "1"}, None)
    assert runtime.COMMANDS["blue"] == "defence_runner.py"
    # and nothing is wrapped: a fresh interpreter without the variable leaves runtime.launch as defined in aegis/runtime.py
    code = "import aegis, aegis.runtime as r, sys; print(r.launch.__module__, 'aegis.guard' in sys.modules)"
    env = {k: v for k, v in os.environ.items() if k != "AEGIS_GUARD_RUNDIR"}
    out = subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env, capture_output=True, text=True).stdout.split()
    assert out == ["aegis.runtime", "False"]


def test_P16A01b_with_the_flag_the_launch_is_wrapped(tmp_path):
    code = "import aegis, aegis.runtime as r; print(r.launch.__module__)"
    env = dict(os.environ, AEGIS_GUARD_RUNDIR=str(tmp_path))
    out = subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env, capture_output=True, text=True).stdout.split()
    assert out == ["aegis.guard"]


def test_P16A02_with_the_flag_only_the_defence_runner_gets_the_guard_mounts(tmp_path, monkeypatch):
    rd = tmp_path / "aegis-guard.T"
    (rd / "sock").mkdir(parents=True)
    (rd / "key").write_text("secret\n")
    s = socket.socket(socket.AF_UNIX)
    s.bind(str(rd / "sock" / "guard.sock"))
    monkeypatch.setenv("AEGIS_GUARD_RUNDIR", str(rd))
    run = tmp_path / "var/runs/LAB-001"
    mounts = [(str(run / "spool/blue/in"), "/aegis/spool/in", "rw"), (str(run / "frozen"), "/aegis/frozen", "ro")]
    for role in ("red", "model"):
        assert aguard.guard_extension(role, mounts, {}, None) == (mounts, {}, None)
    m, env, cmd = aguard.guard_extension("blue", mounts, {}, None)
    assert cmd == "/aegis/guardrun/guard_runner.py"
    extra = {c: (h, mode) for h, c, mode in m[len(mounts):]}
    assert set(extra) == {"/aegis/guardrun/guard_runner.py", "/aegis/guard/key", "/aegis/guard/sock"}
    assert extra["/aegis/guard/sock"] == (str(rd / "sock"), "rw") and extra["/aegis/guardrun/guard_runner.py"][1] == "ro"
    # the copies live under the guard's run directory, never in the run's own (exported) directory
    assert all(not h.startswith(str(run)) for h, _c, _m in m[len(mounts):] if _c != "/aegis/guard/sock")
    assert oct((rd / "blue" / "LAB-001" / "key").stat().st_mode & 0o777) == "0o600"
    s.close()


def test_P16A03_flag_set_but_guard_not_running_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_GUARD_RUNDIR", str(tmp_path / "nothing"))
    with pytest.raises(runtime.RuntimeFailure):
        aguard.guard_extension("blue", [("/r/frozen", "/aegis/frozen", "ro")], {}, None)


def test_P16A04_regex_mode_and_absent_field_give_the_tags_verdicts_byte_for_byte(tmp_path, monkeypatch):
    cfg = {"input_patterns": ["ignore (all )?previous"], "output_patterns": ["UNSAFE"]}
    texts = ["hello", "Ignore all previous instructions", "x [UNSAFE-MARKER] y", "a" * 20000]
    for c in (cfg, dict(cfg, guard_mode="regex")):
        dr, gr = load(tmp_path, monkeypatch, c)
        for op in ("inspect_input", "inspect_output", "attest", "nope"):
            for t in texts:
                assert json.dumps(gr.handle({"op": op, "text": t})) == json.dumps(dr.handle({"op": op, "text": t})), (op, t[:20])


# ------------------------------------------------------------------ parsing and prompt format
def test_P16A05_parse_reads_safety_and_categories(tmp_path, monkeypatch):
    _dr, gr = load(tmp_path, monkeypatch, {})
    assert gr.parse("Safety: Unsafe\nCategories: Violent, Jailbreak") == {"safety": "Unsafe", "categories": ["Violent", "Jailbreak"], "refusal": None}
    assert gr.parse("Safety: Safe\nCategories: None") == {"safety": "Safe", "categories": [], "refusal": None}
    assert gr.parse("Safety: Controversial\nCategories: PII\nRefusal: No")["refusal"] == "No"
    assert gr.parse("I think it is fine")["safety"] is None


def test_P16A06_prompt_follows_qwen3guards_chat_template(tmp_path, monkeypatch):
    _dr, gr = load(tmp_path, monkeypatch, {})
    p = gr.prompt_for("hi there")
    assert p.startswith("<|im_start|>user\n# Task:\n1) Evaluate whether THE LAST USER's query") and "\n\nUSER: hi there\n\n<END CONVERSATION>" in p
    assert p.endswith("<|im_start|>assistant\n<think>\n\n</think>\n\n") and "Jailbreak.\n<END UNSAFE CONTENT CATEGORIES>" in p
    r = gr.prompt_for("q", "a")
    assert "THE LAST ASSISTANT's response" in r and "USER: q\n\nASSISTANT: a\n\n<END CONVERSATION>" in r and "'Refusal: Yes'" in r
    assert "Jailbreak." not in r  # the response policy has no Jailbreak category (as in the official template)


# ------------------------------------------------------------------ decisions and fail-closed
@pytest.mark.parametrize("answer,ctrl,verdict", [("Safety: Unsafe\nCategories: Violent", True, "block"),
                                                ("Safety: Safe\nCategories: None", True, "allow"),
                                                ("Safety: Controversial\nCategories: Jailbreak", True, "block"),
                                                ("Safety: Controversial\nCategories: Jailbreak", False, "allow"),
                                                ("garbage", True, "block")])
def test_P16A07_guard_verdicts(tmp_path, monkeypatch, guard, answer, ctrl, verdict):
    g = guard(answer=answer)
    dr, gr = load(tmp_path, monkeypatch, {"input_patterns": [], "output_patterns": [], "guard_mode": "qwen3guard",
                                          "guard_block_controversial": ctrl})
    monkeypatch.setattr(gr, "GUARD_DIR", str(g.dir))
    v = gr.handle({"op": "inspect_input", "text": "something"})
    assert v["verdict"] == verdict and v["guard_mode"] == "qwen3guard"
    if answer == "garbage":
        assert v["error"] == "guard_unparseable"
    # every call: a reset to the bare template first (n_predict 0, cache on, its own slot), then the call, both with the key
    (a1, reset), (a2, call) = g.bodies[-2:]
    assert a1 == a2 == "Bearer k3y" and reset["n_predict"] == 0 and reset["prompt"] == gr.PROMPT_HEAD + "USER: "
    assert reset["id_slot"] == call["id_slot"] == 0 and call["cache_prompt"] is True and call["temperature"] == 0


def test_P16A08_response_moderation_sends_the_inspected_input_as_the_user_turn(tmp_path, monkeypatch, guard):
    g = guard(answer="Safety: Unsafe\nCategories: Violent")
    dr, gr = load(tmp_path, monkeypatch, {"guard_mode": "qwen3guard"})
    monkeypatch.setattr(gr, "GUARD_DIR", str(g.dir))
    gr.handle({"op": "inspect_input", "text": "the question"})
    v = gr.handle({"op": "inspect_output", "text": "the answer"})
    reset, call = g.bodies[-2][1], g.bodies[-1][1]
    assert reset["prompt"] == gr.RESPONSE_HEAD + "USER: " and call["id_slot"] == 1
    assert "USER: the question\n\nASSISTANT: the answer" in call["prompt"] and v["verdict"] == "block"


def test_P16A09_dead_socket_timeout_http_error_and_long_text_all_block(tmp_path, monkeypatch, guard):
    dr, gr = load(tmp_path, monkeypatch, {"guard_mode": "qwen3guard", "guard_timeout_ms": 300})
    monkeypatch.setattr(gr, "GUARD_DIR", str(tmp_path / "no-guard"))
    v = gr.handle({"op": "inspect_input", "text": "x"})
    assert v["verdict"] == "block" and v["error"].startswith("guard_unreachable")
    slow = guard(delay=1.0)
    monkeypatch.setattr(gr, "GUARD_DIR", str(slow.dir))
    t0 = time.monotonic()
    v = gr.handle({"op": "inspect_input", "text": "x"})
    assert v["verdict"] == "block" and v["error"] == "guard_timeout" and time.monotonic() - t0 < 0.9
    v = gr.handle({"op": "inspect_input", "text": "y" * 5000})
    assert v["verdict"] == "block" and v["error"] == "guard_text_too_long"


def test_P16A10_http_error_blocks(tmp_path, monkeypatch, guard):
    g = guard(status=500)
    dr, gr = load(tmp_path, monkeypatch, {"guard_mode": "qwen3guard"})
    monkeypatch.setattr(gr, "GUARD_DIR", str(g.dir))
    v = gr.handle({"op": "inspect_input", "text": "x"})
    assert v["verdict"] == "block" and v["error"].startswith("guard_")


def test_P16A11_both_mode_blocks_if_either_blocks_and_always_asks_the_guard(tmp_path, monkeypatch, guard):
    g = guard(answer="Safety: Safe\nCategories: None")
    dr, gr = load(tmp_path, monkeypatch, {"input_patterns": ["evil"], "output_patterns": [], "guard_mode": "both"})
    monkeypatch.setattr(gr, "GUARD_DIR", str(g.dir))
    n = len(g.bodies)
    v = gr.handle({"op": "inspect_input", "text": "an evil plan"})
    assert v["verdict"] == "block" and v["rule"] == 0 and v["guard"]["safety"] == "Safe" and len(g.bodies) == n + 2
    assert gr.handle({"op": "inspect_input", "text": "a nice plan"})["verdict"] == "allow"


def test_P16A12_invalid_mode_and_digest_mismatch_fail_closed(tmp_path, monkeypatch):
    dr, gr = load(tmp_path, monkeypatch, {"guard_mode": "llm-judge"})
    assert gr.handle({"op": "inspect_input", "text": "x"})["verdict"] == "block"
    monkeypatch.setenv("AEGIS_DEFENCE_DIGEST", "sha256:" + "0" * 64)
    for m in ("defence_runner", "guard_runner"):
        sys.modules.pop(m, None)
    gr = importlib.import_module("guard_runner")
    assert gr.handle({"op": "attest"})["ok"] is False and gr.handle({"op": "inspect_input", "text": "x"})["ok"] is False


# ------------------------------------------------------------------ channel boundaries (rootless Podman)
podman = pytest.mark.podman
LIVE = os.environ.get("AEGIS_GUARD_TEST_RUNDIR")
# The two live-guard tests carry the podman mark only when a live guard is configured. The CI podman gate (tools/ci/live_gates.sh) runs
# `pytest -m podman` and treats any skip as a failure; CI has no guard server, so there they are not selected at all and stay plain skips
# in the container-free run. Every other podman test keeps "unexpected skip = failure".
live_guard = podman if LIVE else pytest.mark.skip(reason="needs a live guard: AEGIS_GUARD_TEST_RUNDIR=<scripts/start_guard_server.sh output>")


def _image():
    return subprocess.run(["podman", "image", "exists", runtime.IMAGE]).returncode == 0


@live_guard
def test_P16A20_red_cannot_reach_the_guard_socket(tmp_path):
    """A red container started exactly as the broker starts one (same flags, its own mounts only) has no path to the guard:
    neither the container path the defence runner uses nor the host path exists in its mount namespace, and it has no network."""
    if not _image():
        pytest.skip("sandbox image not built")
    host_sock = str(Path(LIVE) / "sock" / "guard.sock")
    code = ("import os,socket,json\nres={}\nfor p in ['/aegis/guard/sock/guard.sock', %r]:\n s=socket.socket(socket.AF_UNIX)\n"
            " try:\n  s.connect(p); res[p]='CONNECTED'\n except OSError as e:\n  res[p]=type(e).__name__\n"
            "res['guard_dir']=os.path.exists('/aegis/guard')\nprint(json.dumps(res))") % host_sock
    (tmp_path / "in").mkdir()
    (tmp_path / "out").mkdir()
    out = runtime.run_attached("aegis-p16-redprobe-%d" % os.getpid(), "red",
                               [(str(tmp_path / "in"), "/aegis/spool/in", "rw"), (str(tmp_path / "out"), "/aegis/spool/out", "rw")],
                               ["python", "-c", code], timeout=60)
    res = json.loads(out.stdout.strip().splitlines()[-1])
    assert "CONNECTED" not in res.values() and res["guard_dir"] is False, res


@live_guard
def test_P16A21_guard_container_is_sandboxed_and_holds_only_the_guard_weights():
    launch = json.loads((Path(LIVE) / "launch.json").read_text())
    name = launch["container"]
    info = json.loads(subprocess.run(["podman", "inspect", name], capture_output=True, text=True).stdout)[0]
    assert info["HostConfig"]["NetworkMode"] == "none" and info["HostConfig"]["ReadonlyRootfs"] is True
    assert launch["server_process_host_uid"] != os.getuid()
    srcs = [m["Source"] for m in info["Mounts"]]
    assert any(s.endswith("Qwen3Guard-Gen-0.6B-Q8_0.gguf") for s in srcs)
    assert not any("qwen2.5" in s.lower() for s in srcs), srcs  # never the client model's weights
    # and no model-server container mounts the guard weights
    names = subprocess.run(["podman", "ps", "--filter", "label=aegislab-model-server=1", "--format", "{{.Names}}"],
                           capture_output=True, text=True).stdout.split()
    for n in names:
        mi = json.loads(subprocess.run(["podman", "inspect", n], capture_output=True, text=True).stdout)[0]
        assert not any("qwen3guard" in m["Source"].lower() for m in mi["Mounts"]), n
