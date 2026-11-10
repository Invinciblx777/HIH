"""Finale P4, task 5: small pins. The sandbox base image is pinned by digest everywhere it is named; the model-server launcher
refuses a libgomp whose sha256 differs from the pinned one (and leaves no key behind); pyproject.toml is consistent with the
README, CI and uv.lock, and pytest is not a runtime dependency.
"""
import os
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
REPO = ROOT.parent
sys.path.insert(0, str(ROOT))

from aegis import runtime  # noqa: E402

DIGEST_REF = re.compile(r"docker\.io/library/python@sha256:[0-9a-f]{64}")


def test_P4P01_base_image_is_pinned_by_the_same_digest_everywhere():
    ref = runtime.BASE_IMAGE
    assert DIGEST_REF.fullmatch(ref)
    froms = [ln.split()[1] for ln in (ROOT / "Containerfile").read_text().splitlines() if ln.startswith("FROM ")]
    assert froms == [ref]
    for script in ("scripts/quickstart.sh", "scripts/start_prototype.sh"):
        text = (ROOT / script).read_text()
        assert ref in text and "python:3.12-slim\n" not in text and "pull -q docker.io/library/python:3.12-slim" not in text, script
    assert ref in (ROOT / "README.md").read_text()


def test_P4P02_pyproject_names_the_project_and_keeps_pytest_out_of_the_runtime():
    p = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    assert p["name"] == "aegislab"
    names = [re.split(r"[<>=~! ]", d, 1)[0] for d in p["dependencies"]]
    assert "pytest" not in names and {"fastapi", "uvicorn", "cryptography", "httpx"} <= set(names)  # httpx: console TestClient
    dev = tomllib.loads((ROOT / "pyproject.toml").read_text())["dependency-groups"]["dev"]
    assert any(d.startswith("pytest") for d in dev)


def test_P4P03_requires_python_matches_readme_ci_vercel_and_the_lock():
    rp = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["requires-python"]
    assert rp == ">=3.12"
    lock = (ROOT / "uv.lock").read_text()
    assert 'requires-python = ">=3.12"' in lock and '\nname = "aegislab"\n' in lock and '\nname = "app"\n' not in lock
    assert (ROOT / ".python-version").read_text().strip() == "3.12"  # Vercel's runtime
    ci = (REPO / ".github/workflows/release-gates.yml").read_text()
    assert re.search(r'python-version: "3\.(1[2-9])"', ci)
    assert "Python 3.12 or newer" in (REPO / "README.md").read_text() and "Python 3.12+" in (ROOT / "README.md").read_text()


@pytest.mark.skipif(not shutil.which("podman"), reason="needs podman (the launcher checks the sandbox image first)")
def test_P4P04_launcher_refuses_a_changed_libgomp_and_removes_its_key(tmp_path):
    if subprocess.run(["podman", "image", "exists", runtime.IMAGE]).returncode:
        pytest.skip("sandbox image not built")
    models = tmp_path / "models"
    srv = models / "llama.cpp-b11819/llama-b11819"
    srv.mkdir(parents=True)
    (models / "qwen2.5-0.5b-instruct-q4_k_m.gguf").write_bytes(b"not a model")
    fake = srv / "llama-server"
    fake.write_text("#!/bin/sh\necho 'version: 1 (build 11819)'\n")
    fake.chmod(0o755)
    gomp = tmp_path / "libgomp.so.1"
    gomp.write_bytes(b"a different library")
    rt = Path(os.environ.get("XDG_RUNTIME_DIR") or "/tmp")
    before = set(rt.glob("aegis-model.*"))
    env = dict(os.environ, AEGIS_MODELS_DIR=str(models), AEGIS_LIBGOMP=str(gomp))
    r = subprocess.run(["bash", str(ROOT / "scripts/start_model_server.sh"), "--sandbox"], env=env, capture_output=True, text=True, timeout=60)
    assert r.returncode == 1 and "libgomp sha256" in r.stderr and "refusing a changed library" in r.stderr
    assert set(rt.glob("aegis-model.*")) == before  # the run directory with the API key was removed
