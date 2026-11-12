"""Finale P4, task 1: the default timing policy. A run created without a timing choice gets 250 ms buckets with the stub model
and deadline release (runs.REAL_MODEL_DEADLINE_MS, or AEGIS_TIMING_DEADLINE_MS) with a real-model backend; an explicit choice is
always honoured, so every experiment and demo that passes one is unchanged."""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient  # noqa: E402

from aegis import api, runs, runtime, store  # noqa: E402

REAL = {"AEGIS_MODEL_BACKEND": "openai_compatible", "AEGIS_MODEL_BASE_URL": "http://127.0.0.1:9/v1", "AEGIS_MODEL_NAME": "local"}


@pytest.fixture(autouse=True)
def isolated_var(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "VAR", tmp_path / "var")
    monkeypatch.setattr(runs, "_signer", None)
    monkeypatch.setattr(runtime, "image_id", lambda *a: "0" * 64)
    monkeypatch.setattr(runtime, "environment", lambda: {})
    for k in list(REAL) + ["AEGIS_TIMING_DEADLINE_MS", "AEGIS_VAULT", "AEGIS_ANCHORS"]:
        monkeypatch.delenv(k, raising=False)


def real(monkeypatch, **extra):
    for k, v in {**REAL, **extra}.items():
        monkeypatch.setenv(k, v)


def test_P4TD01_stub_default_is_unchanged_250_ms_buckets():
    assert runs.default_timing() == {"timing_bucket_ms": 250}
    pol = runs.create_run("T-T01").record["policy"]
    assert pol["timing_bucket_ms"] == 250 and "timing_mode" not in pol


def test_P4TD02_real_model_default_is_deadline_release_without_shadow(monkeypatch):
    real(monkeypatch)
    assert runs.default_timing() == {"timing_bucket_ms": 0, "timing_deadline_ms": runs.REAL_MODEL_DEADLINE_MS}
    pol = runs.create_run("T-T02").record["policy"]
    assert pol["timing_mode"] == "deadline" and pol["timing_deadline_ms"] == 1400 and pol["timing_bucket_ms"] == 0
    assert pol["shadow_model_on_refusal"] is False


def test_P4TD03_an_explicit_choice_is_always_honoured(monkeypatch):
    real(monkeypatch)
    assert runs.create_run("T-T03A", timing_bucket_ms=250).record["policy"] == {
        "timing_bucket_ms": 250, "reset_strategy": "fresh-container", "forbidden_probes": True}
    assert runs.create_run("T-T03B", timing_bucket_ms=0).record["policy"]["timing_bucket_ms"] == 0
    assert runs.create_run("T-T03C", timing_deadline_ms=900).record["policy"]["timing_deadline_ms"] == 900


def test_P4TD04_deadline_override_and_invalid_values(monkeypatch):
    real(monkeypatch, AEGIS_TIMING_DEADLINE_MS="2000")
    assert runs.create_run("T-T04").record["policy"]["timing_deadline_ms"] == 2000
    monkeypatch.setenv("AEGIS_TIMING_DEADLINE_MS", "fast")
    with pytest.raises(runs.GateError):
        runs.create_run("T-T04B")
    monkeypatch.setenv("AEGIS_TIMING_DEADLINE_MS", "50")  # below DEADLINE_MIN_MS
    with pytest.raises(runs.GateError):
        runs.create_run("T-T04C")
    monkeypatch.setenv("AEGIS_MODEL_BACKEND", "something-else")
    with pytest.raises(runs.GateError):
        runs.default_timing()


def test_P4TD05_the_api_applies_the_default_only_when_the_field_is_omitted(monkeypatch):
    c = TestClient(api.app)
    h = {"X-Aegis-Token": store.tokens()["operator"]}
    assert c.post("/api/runs", json={"run_id": "T-T05A"}, headers=h).json()["policy"]["timing_bucket_ms"] == 250
    real(monkeypatch)
    assert c.post("/api/runs", json={"run_id": "T-T05B"}, headers=h).json()["policy"]["timing_mode"] == "deadline"
    assert c.post("/api/runs", json={"run_id": "T-T05C", "timing_bucket_ms": 250}, headers=h).json()["policy"]["timing_bucket_ms"] == 250
