"""Finale P2, finding F7: the tenant-storage race in runs.ensure_tenant_storage().

On an empty state directory the first create_run copies the sample attack pack and defence config into tenant storage.
The old code copied straight to the final path, so a concurrent creator could find the file already present but only half
written and fail on its JSON (the flake seen in test_P2L03 on a cold var/). The fix copies to a private name and renames it.

The regression test makes the race deterministic: the copy is paused after half of the file is written, and while it is
paused the final path must either not exist or hold the whole file. It fails on the old code and passes on the new.
"""
import json
import shutil
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from aegis import runs, runtime, store  # noqa: E402

_real_copy = shutil.copy


@pytest.fixture(autouse=True)
def isolated_var(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "VAR", tmp_path / "var")
    monkeypatch.setattr(runs, "_signer", None)
    monkeypatch.setattr(runtime, "image_id", lambda *a: "0" * 64)
    monkeypatch.setattr(runtime, "image_repo_digest", lambda *a: "sha256:t")
    monkeypatch.setattr(runtime, "environment", lambda: {})


def paused_copy(monkeypatch):
    """Replace shutil.copy so that copying a sample writes half the bytes, signals, waits, then writes the rest."""
    half_written, proceed = threading.Event(), threading.Event()
    real = shutil.copy

    def copy(src, dst, *a, **kw):
        if Path(src).parent != runs.SAMPLES:
            return real(src, dst, *a, **kw)
        data = Path(src).read_bytes()
        with open(dst, "wb") as fh:
            fh.write(data[: len(data) // 2])
            fh.flush()
            half_written.set()
            assert proceed.wait(10), "test did not release the paused copy"
            fh.write(data[len(data) // 2:])
        return dst
    monkeypatch.setattr(shutil, "copy", copy)
    return half_written, proceed


def test_F7_a_paused_copy_never_exposes_a_half_written_tenant_file(monkeypatch):
    half_written, proceed = paused_copy(monkeypatch)
    dst = store.p("tenants", "red", "attack_pack.json")
    t = threading.Thread(target=runs.ensure_tenant_storage, daemon=True)
    t.start()
    try:
        assert half_written.wait(10), "the copy never started"
        if dst.exists():  # what a concurrent create_run would read at this moment
            json.loads(dst.read_text())  # old code: JSONDecodeError on the half-written file
    finally:
        proceed.set()
        t.join(10)
    assert not t.is_alive()
    assert json.loads(dst.read_text()) == json.loads((runs.SAMPLES / "attack_pack.json").read_text())
    assert json.loads(store.p("tenants", "blue", "defence_config.json").read_text()) == json.loads(
        (runs.SAMPLES / "defence_config.json").read_text())


def test_F7_a_concurrent_create_during_the_paused_copy_succeeds(monkeypatch):
    """The end-to-end form of the same race: one creator is inside the paused first copy, a second creator runs to completion."""
    half_written, proceed = paused_copy(monkeypatch)
    first = {}
    t = threading.Thread(target=lambda: first.setdefault("run", runs.create_run("F7-A", timing_bucket_ms=0)), daemon=True)
    t.start()
    try:
        assert half_written.wait(10)
        # the second creator copies too (the file is not at its final path yet) or reads a complete file; it must not see half
        monkeypatch.setattr(shutil, "copy", _real_copy)
        runs.create_run("F7-B", timing_bucket_ms=0)
    finally:
        proceed.set()
        t.join(10)
    assert runs.Run("F7-A").state == "CREATED" and runs.Run("F7-B").state == "CREATED"
    assert not list(store.p("tenants", "red").glob(".tmp-*")), "no temporary copy is left behind"


def test_F7_no_temporary_file_is_left_after_normal_use():
    runs.ensure_tenant_storage()
    runs.ensure_tenant_storage()
    for tenant in ("red", "blue"):
        assert [p.name for p in store.p("tenants", tenant).iterdir()] in (["attack_pack.json"], ["defence_config.json"])
