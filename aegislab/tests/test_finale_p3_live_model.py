"""Finale P3: live real-model path without a model (labels, launcher guards, checker rules). The end-to-end runs with the real
model are scripts/real_model_demo.sh and scripts/real_model_console_check.py (they need the model files)."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "evaluation"))
import check_claims  # noqa: E402

from aegis import console, model_client as mc  # noqa: E402

SHA = "74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db"
SOCK_DESC = {"backend": "openai_compatible", "model": "local", "endpoint": "http://localhost/v1", "loopback_only": True, "transport": "unix_socket",
             "unix_socket": "/run/user/1000/aegis-model.x/sock/llama.sock",
             "declared_identity": {"model_file": "qwen2.5-0.5b-instruct-q4_k_m.gguf", "model_sha256": SHA, "inference_server": "llama.cpp CPU b11819",
                                   "server_isolation": "rootless-podman-network-none"}}


# ------------------------------------------------------------------ labels
def test_real_model_badge_names_file_sha_server_and_loopback():
    i = console.model_identity(SOCK_DESC)
    for want in ("REAL MODEL · LIVE", "qwen2.5-0.5b-instruct-q4_k_m.gguf", SHA[:12], "llama.cpp CPU", "loopback"):
        assert want in i["badge"]
    assert "UNIX socket" in i["reachability"] and "--network none" in i["reachability"]


def test_tcp_badge_and_legacy_server_label():
    d = dict(SOCK_DESC, transport=None, declared_identity=dict(SOCK_DESC["declared_identity"], inference_server="llama.cpp b11819 CPU"))
    i = console.model_identity(d)
    assert "llama.cpp CPU (b11819)" in i["badge"] and "TCP 127.0.0.1" in i["reachability"]


def test_undeclared_identity_says_so_and_remote_is_flagged():
    i = console.model_identity({"backend": "openai_compatible", "model": "m", "loopback_only": False})
    assert "sha256 not declared" in i["badge"] and "REMOTE" in i["badge"] and i["loopback"] is False


def test_status_label_real_live_and_unreachable(monkeypatch):
    env = {"AEGIS_MODEL_BACKEND": "openai_compatible", "AEGIS_MODEL_BASE_URL": "http://127.0.0.1:9/v1", "AEGIS_MODEL_NAME": "local",
           "AEGIS_MODEL_FILE_SHA256": SHA, "AEGIS_MODEL_FILE_NAME": "qwen2.5-0.5b-instruct-q4_k_m.gguf"}
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    console._cache.pop("model-ping", None)
    s = console._model_status()   # nothing listens on port 9: the probe fails within its 2 s budget
    assert s["label"] == "REAL MODEL · UNREACHABLE" and s["reachable"] is False and "fails closed" in s["detail"]
    console._cache["model-ping"] = (__import__("time").monotonic(), True)
    s = console._model_status()
    assert s["label"] == "REAL MODEL · LIVE" and SHA[:12] in s["badge"]
    console._cache.pop("model-ping", None)


def test_stub_status_unchanged(monkeypatch):
    for k in [k for k in os.environ if k.startswith("AEGIS_MODEL")]:
        monkeypatch.delenv(k)
    assert console._model_status() == {"backend": "stub", "label": "STUB MODEL",
                                       "detail": "deterministic stub model worker in a fresh container per run; not an LLM"}


def test_run_mode_comes_from_the_runs_frozen_manifest(tmp_path):
    (tmp_path / "manifest.json").write_text(json.dumps({"model": SOCK_DESC}))
    mode, ident = console._run_mode(tmp_path)
    assert mode == "LIVE SANDBOX / REAL MODEL" and ident["model_sha256_prefix"] == SHA[:12]
    (tmp_path / "manifest.json").write_text(json.dumps({"model": {"backend": "stub"}}))
    assert console._run_mode(tmp_path) == ("LIVE SANDBOX / STUB MODEL", None)
    (tmp_path / "manifest.json").unlink()
    assert console._run_mode(tmp_path) == ("LIVE SANDBOX / STUB MODEL", None)


def test_console_ui_labels_and_footer():
    js = (ROOT / "web/console/console.js").read_text()
    html = (ROOT / "web/console/index.html").read_text()
    assert "LIVE SANDBOX · REAL MODEL · LIVE" in js and "LIVE SANDBOX · STUB MODEL" in js
    assert 'id="foot-mode"' in html and "read-only public demo</span>" not in html   # the footer no longer claims public demo everywhere


# ------------------------------------------------------------------ launcher and wrapper guards
LAUNCHER = ROOT / "scripts/start_model_server.sh"


def test_launcher_closes_what_the_build_allows_and_keeps_the_key_off_command_lines():
    s = LAUNCHER.read_text()
    for flag in ("--api-key-file", "--no-cache-prompt", "--cache-ram 0", "--no-cache-idle-slots", "--no-kv-unified", "--ctx-checkpoints 0",
                 "--cache-reuse 0", "--no-slots", "--no-webui", "--no-agent", "--offline", "--network none", "--read-only", "--cap-drop ALL",
                 "no-new-privileges", "--pids-limit", "--memory", ":ro,Z"):
        assert flag in s, flag
    code = "\n".join(l for l in s.splitlines() if not l.lstrip().startswith("#"))
    assert "--api-key " not in code and "--slot-save-path" not in code and "--metrics" not in code and "--props" not in code
    assert "umask 077" in s and 'chmod 600 "$RUN/key"' in s


def test_launcher_refuses_without_mode_and_on_foreign_stop_dir(tmp_path):
    r = subprocess.run(["bash", str(LAUNCHER)], capture_output=True, text=True)
    assert r.returncode == 1 and "--sandbox or --host-process" in r.stderr
    (tmp_path / "launch.json").write_text("{}")
    r = subprocess.run(["bash", str(LAUNCHER), "--stop", str(tmp_path)], capture_output=True, text=True)
    assert r.returncode == 1 and "refusing to remove" in r.stderr and tmp_path.exists()


def test_launcher_refuses_a_model_with_the_wrong_hash(tmp_path):
    srv = tmp_path / "srv"
    srv.mkdir()
    (srv / "llama-server").write_text("#!/bin/sh\necho 'version: 0 (build 1, x)'\n")
    (srv / "llama-server").chmod(0o755)
    (tmp_path / "m.gguf").write_bytes(b"not the model")
    r = subprocess.run(["bash", str(LAUNCHER), "--host-process", "--model", str(tmp_path / "m.gguf"), "--server-dir", str(srv),
                        "--expect-model-sha256", SHA], capture_output=True, text=True)
    assert r.returncode == 1 and "differs from --expect-model-sha256" in r.stderr


def test_real_model_console_wrapper_scrubs_unsafe_settings_and_never_falls_back():
    s = (ROOT / "scripts/start_real_model_console.sh").read_text()
    assert "unset AEGIS_UNSAFE_EXPERIMENT_SHARED_PROMPT_CACHE" in s and "unset AEGIS_DEMO_MODE" in s
    assert "AEGIS_VAR=\"$ROOT/var/console-real\"" in s and "nothing falls back to the stub" in s
    assert "--expect-model-sha256 " + SHA in s
    assert (ROOT / "scripts/start_prototype.sh").read_text().count("the console always uses the deterministic stub model") == 1


# ------------------------------------------------------------------ checker rules
def test_23_oct_runs_need_the_p3_acknowledgement_exactly(monkeypatch):
    """With only the P2 file the 23 Oct runs fail again (P3 changed model_client, llm_common, llm_isolation), so the P3 file is
    doing the work, and it accepts only the exact current hashes (the P2 drift tests prove the one-byte case)."""
    if not (check_claims.P3 / "INDEX.json").exists():
        pytest.skip("no saved Phase 3 evidence")
    rows, _ = check_claims.phase3_rows()
    assert all(r[3] for r in rows if "security-relevant sources" in r[0])
    monkeypatch.setattr(check_claims, "SOURCE_DRIFT_FILES", check_claims.SOURCE_DRIFT_FILES[:1])
    rows, _ = check_claims.phase3_rows()
    failing = [r for r in rows if "security-relevant sources" in r[0] and not r[3]]
    assert failing and all("model_client.py" in r[2] for r in failing)


def test_p3_acknowledgement_covers_only_the_three_p3_files_and_all_say_unaffected():
    d = json.loads((check_claims.SOURCE_DRIFT_FILES[1]).read_text())
    assert sorted(c["path"] for c in d["changes"]) == ["aegis/model_client.py", "evaluation/llm_common.py", "evaluation/llm_isolation.py"]
    for c in d["changes"]:
        assert sorted(c["claims"]) == ["E1_canary_matrix", "E2_pipeline_canary", "E3_kv_cache_oracle", "E4_injection_output_isolation", "E5_failure_handling"]
        assert all(v["affects"] is False and len(v["why"]) > 80 for v in c["claims"].values())


def test_remeasured_runs_may_not_rely_on_an_acknowledgement(monkeypatch, tmp_path):
    """While the 10 Nov runs were the current real-model set (Part E), an acknowledged row failed. Finale P4 made them history:
    Part E then accepts acknowledged rows, and the same rule applies to the current set, Part F (tests/test_finale_p4_source_drift.py)."""
    fake = [("E1_canary_matrix: security-relevant sources unchanged since the run", "d", "recorded on x; acknowledged change, does not affect E1: a", True)]
    monkeypatch.setattr(check_claims, "phase3_rows", lambda base=None, report=None: (fake, {}) if base is not None else ([], {}))
    if not (check_claims.P3F / "INDEX.json").exists():
        pytest.skip("no finale P3 evidence")
    monkeypatch.setattr(check_claims, "P4F", tmp_path / "no_p4")  # as before P4: Part E is the current set
    rows, _, _ = check_claims.finale_p3_rows()
    src = [r for r in rows if "security-relevant sources" in r[0]]
    assert src and not src[0][3]


def test_latest_real_model_prefers_the_newest_set(monkeypatch, tmp_path):
    monkeypatch.setattr(check_claims, "P4F", tmp_path / "nothing_p4")  # finale P4 is newer still; see test_finale_p4_source_drift.py
    monkeypatch.setattr(check_claims, "P3F", tmp_path / "nothing")
    assert check_claims.latest_real_model()[0] == check_claims.P3
    (tmp_path / "llm").mkdir()
    (tmp_path / "llm" / "INDEX.json").write_text("[]")
    monkeypatch.setattr(check_claims, "P3F", tmp_path / "llm")
    base, label = check_claims.latest_real_model()
    assert base == tmp_path / "llm" and "10 Nov" in label
