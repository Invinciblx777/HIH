"""Identify the code under test. The project is not a git repository, so a hash of its source files stands in."""
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def code_revision():
    h = hashlib.sha256()
    files = [p for d in ("aegis", "sandbox", "evaluation", "scripts", "tests", "samples") for p in sorted((ROOT / d).rglob("*"))
             if p.is_file() and "__pycache__" not in p.parts and p.suffix in (".py", ".sh", ".json")]
    for p in files:
        h.update(str(p.relative_to(ROOT)).encode() + b"\0" + p.read_bytes())
    return {"tree_sha256": "sha256:" + h.hexdigest(), "files": len(files),
            "note": "not a git repository; hash over aegis/ sandbox/ evaluation/ scripts/ tests/ samples/ (*.py, *.sh, *.json)"}
