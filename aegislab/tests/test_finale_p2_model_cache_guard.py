"""Finale P2, Phase 3 residual: cache_prompt=true is refused unless an explicit, loudly named experiment opt-in is set.

Experiment E3 measured a cross-session cached-token oracle with AUC 1.00 when llama.cpp's prompt cache is on
(cache_prompt=true). Before P2, AEGIS_MODEL_EXTRA_JSON='{"cache_prompt": true}' turned it back on with no guard. Now only
AEGIS_UNSAFE_EXPERIMENT_SHARED_PROMPT_CACHE=1 lets it through, and the opt-in is recorded in the frozen run manifest and the
audit log. The evaluation harness (llm_common, llm_isolation, model_experiments) sets the opt-in for its cache-on controls
only, so the E3 positive control still runs. Local fake HTTP server only; no model, no container.
"""
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "evaluation"))

from aegis import model_client as mc  # noqa: E402
from aegis import runs, runtime, store  # noqa: E402
from aegis.audit import read_jsonl  # noqa: E402

OPT_IN = "AEGIS_UNSAFE_EXPERIMENT_SHARED_PROMPT_CACHE"
assert mc.UNSAFE_CACHE_OPT_IN == OPT_IN


def env(extra=None, **more):
    e = {"AEGIS_MODEL_BACKEND": "openai_compatible", "AEGIS_MODEL_BASE_URL": "http://127.0.0.1:1/v1", "AEGIS_MODEL_NAME": "m"}
    if extra is not None:
        e["AEGIS_MODEL_EXTRA_JSON"] = extra
    e.update(more)
    return e


@pytest.fixture(autouse=True)
def isolated_var(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "VAR", tmp_path / "var")
    monkeypatch.setattr(runs, "_signer", None)
    monkeypatch.setattr(runtime, "image_id", lambda *a: "0" * 64)
    monkeypatch.setattr(runtime, "image_repo_digest", lambda *a: "sha256:t")
    monkeypatch.setattr(runtime, "environment", lambda: {})
    for k in [k for k in os.environ if k.startswith("AEGIS_MODEL")] + [OPT_IN]:
        monkeypatch.delenv(k, raising=False)


# ------------------------------------------------------------------ the guard
@pytest.mark.parametrize("extra", ['{"cache_prompt": true}', '{"cache_prompt": true, "top_k": 1}'])
def test_cache_prompt_true_is_refused_without_the_opt_in(extra):
    with pytest.raises(mc.ModelBackendError) as e:
        mc.load_config(env(extra))
    assert e.value.kind == "config"


@pytest.mark.parametrize("value", ["true", "yes", "on", "0", "", "TRUE"])
def test_only_the_exact_value_1_opts_in(value):
    with pytest.raises(mc.ModelBackendError):
        mc.load_config(env('{"cache_prompt": true}', **{OPT_IN: value}))


@pytest.mark.parametrize("bad", ['{"cache_prompt": 1}', '{"cache_prompt": "true"}', '{"cache_prompt": "false"}', '{"cache_prompt": [true]}'])
def test_a_non_boolean_cache_prompt_is_refused_even_with_the_opt_in(bad):
    for e in (env(bad), env(bad, **{OPT_IN: "1"})):
        with pytest.raises(mc.ModelBackendError):
            mc.load_config(e)


@pytest.mark.parametrize("extra", [None, "{}", '{"cache_prompt": null}', '{"cache_prompt": false}', '{"top_k": 1}'])
def test_missing_null_or_false_means_an_explicit_false_on_the_wire(extra):
    cfg = mc.load_config(env(extra))
    assert dict(cfg.extra)["cache_prompt"] is False
    assert cfg.unsafe_shared_prompt_cache is False
    assert "unsafe_shared_prompt_cache_experiment" not in cfg.describe()


def test_the_opt_in_alone_changes_nothing_when_cache_prompt_is_false():
    plain = mc.load_config(env('{"cache_prompt": false}'))
    opted = mc.load_config(env('{"cache_prompt": false}', **{OPT_IN: "1"}))
    assert plain == opted and plain.describe() == opted.describe()


class Fake(BaseHTTPRequestHandler):
    bodies = []

    def log_message(self, *a):
        pass

    def _send(self, body):
        raw = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        self._send({"data": [{"id": "m"}]})

    def do_POST(self):
        Fake.bodies.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
        self._send({"choices": [{"message": {"content": "ok"}}]})


@pytest.fixture
def server():
    Fake.bodies = []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Fake)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield "http://127.0.0.1:%d/v1" % srv.server_address[1]
    srv.shutdown()


def test_with_the_opt_in_the_request_carries_cache_prompt_true_and_describe_says_so(server):
    cfg = mc.load_config(env('{"cache_prompt": true}', AEGIS_MODEL_BASE_URL=server, **{OPT_IN: "1"}))
    assert cfg.describe()["unsafe_shared_prompt_cache_experiment"] is True
    mc.OpenAICompatibleClient(cfg).generate("hello")
    assert Fake.bodies[-1]["cache_prompt"] is True


def test_default_request_still_sends_cache_prompt_false(server):
    mc.OpenAICompatibleClient(mc.load_config(env(None, AEGIS_MODEL_BASE_URL=server))).generate("hello")
    assert Fake.bodies[-1]["cache_prompt"] is False


# ------------------------------------------------------------------ recorded in the run manifest and the audit log
def _start_with(monkeypatch, server, opted):
    for k, v in env('{"cache_prompt": true}' if opted else None, AEGIS_MODEL_BASE_URL=server).items():
        monkeypatch.setenv(k, v)
    if opted:
        monkeypatch.setenv(OPT_IN, "1")
    rid = "T-UNSAFE" if opted else "T-SAFE"
    runs.create_run(rid, timing_bucket_ms=0)
    manifest = runs.freeze(rid)
    run = runs.Run(rid)
    run.update(state="RUNNING")
    b = runs.Broker(run)
    monkeypatch.setattr(runtime, "launch", lambda *a, **k: None)
    monkeypatch.setattr(runtime, "inspect_security", lambda name: {"network_mode": "none"})
    b.call = lambda role, msg, timeout=15.0: {"ok": True, "config_digest": manifest["defence_config_digest"]}
    b.start_workloads()
    return run, manifest


def test_the_opt_in_is_recorded_in_the_manifest_the_audit_log_and_as_a_live_warning(monkeypatch, server):
    run, manifest = _start_with(monkeypatch, server, opted=True)
    assert manifest["model"]["unsafe_shared_prompt_cache_experiment"] is True
    opened = [e for e in read_jsonl(run.dir / "audit.jsonl") if e["type"] == "model.session_opened"][0]["data"]
    assert opened["unsafe_shared_prompt_cache_experiment"] is True
    assert opened["backend"]["unsafe_shared_prompt_cache_experiment"] is True
    mon = [e for e in read_jsonl(run.dir / "monitor.jsonl") if e["type"] == "model.session_opened"][0]
    assert mon["decision"] == "warning" and "UNSAFE EXPERIMENT" in mon["summary"]


def test_an_ordinary_real_model_run_records_the_opt_in_as_false(monkeypatch, server):
    run, manifest = _start_with(monkeypatch, server, opted=False)
    assert "unsafe_shared_prompt_cache_experiment" not in manifest["model"]
    opened = [e for e in read_jsonl(run.dir / "audit.jsonl") if e["type"] == "model.session_opened"][0]["data"]
    assert opened["unsafe_shared_prompt_cache_experiment"] is False
    mon = [e for e in read_jsonl(run.dir / "monitor.jsonl") if e["type"] == "model.session_opened"][0]
    assert "decision" not in mon and "UNSAFE" not in mon["summary"]


def test_the_opt_in_cannot_be_added_after_freeze(monkeypatch, server):
    """A run frozen without the opt-in cannot start with it: the model description differs from the frozen manifest."""
    for k, v in env(None, AEGIS_MODEL_BASE_URL=server).items():
        monkeypatch.setenv(k, v)
    runs.create_run("T-LATE", timing_bucket_ms=0)
    runs.freeze("T-LATE")
    monkeypatch.setenv("AEGIS_MODEL_EXTRA_JSON", '{"cache_prompt": true}')
    monkeypatch.setenv(OPT_IN, "1")
    run = runs.Run("T-LATE")
    run.update(state="RUNNING")
    with pytest.raises(runs.GateError, match="differs from the frozen manifest"):
        runs.Broker(run).start_workloads()


# ------------------------------------------------------------------ the experiment harness still reaches the cache-on control
def test_llm_common_client_opts_in_only_for_the_cache_on_control():
    import llm_common
    srv = llm_common.Server("/nonexistent", "/nonexistent.gguf", "k")
    assert srv.client(cache_prompt=True).cfg.describe()["unsafe_shared_prompt_cache_experiment"] is True
    assert dict(srv.client(cache_prompt=True).cfg.extra)["cache_prompt"] is True
    assert "unsafe_shared_prompt_cache_experiment" not in srv.client(cache_prompt=False).cfg.describe()
    assert srv.client(extra={"cache_prompt": True}).cfg.unsafe_shared_prompt_cache is True
    assert OPT_IN not in os.environ, "the client opts in through its own config, not the process environment"


def test_llm_isolation_run_environment_sets_and_clears_the_opt_in():
    import llm_isolation as li
    li.set_model_env("http://127.0.0.1:1/v1", "k", cache=True)
    try:
        assert os.environ[OPT_IN] == "1" and mc.load_config().unsafe_shared_prompt_cache is True
        li.set_model_env("http://127.0.0.1:1/v1", "k", cache=False)
        assert OPT_IN not in os.environ and mc.load_config().unsafe_shared_prompt_cache is False
        li.set_model_env("http://127.0.0.1:1/v1", "k", cache=True)
    finally:
        li.clear_model_env()
    assert OPT_IN not in os.environ and not any(k.startswith("AEGIS_MODEL") for k in os.environ)


def test_model_experiments_client_opts_in_only_for_cache_on():
    import model_experiments as me
    s = me.LlamaServer("/nonexistent", "/nonexistent.gguf", "k", port=1)
    assert s.client(cache_prompt=True).cfg.unsafe_shared_prompt_cache is True
    assert s.client(cache_prompt=False).cfg.unsafe_shared_prompt_cache is False
