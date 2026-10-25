"""Filesystem layout for the prototype's state (SQLite/PostgreSQL proposed later).

var/
  keys/broker_ed25519.pem         trusted signing key
  keys/tokens.json                local demo identities (operator, reviewer, ...)
  tenants/red/attack_pack.json    red team private storage
  tenants/blue/defence_config.json blue team private storage
  reviewer_vault/<run>.jsonl      checkpoints retained outside the run directory
  anchors/<run>.terminal.json     signed terminal checkpoint, written once, mode 0444
  canaries.jsonl                  canary registry (control plane only)
  runs/<run>/
    run.json                      lifecycle state
    manifest.json                 frozen configuration
    audit.jsonl / checkpoints.jsonl  restricted audit store
    monitor.jsonl                 redacted monitoring stream
    private/red/                  per-run copy of red inputs (mounted ro in red only)
    frozen/                       frozen defence config (mounted ro in defence runner only)
    sealed/                       payloads, outputs, verdicts (released only after the gate)
    spool/{red,blue,model}/{in,out}
"""
import json
import os
import secrets
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VAR = Path(os.environ.get("AEGIS_VAR", ROOT / "var"))


def p(*parts) -> Path:
    return VAR.joinpath(*parts)


def run_dir(run_id: str) -> Path:
    return p("runs", run_id)


def vault_path(run_id: str) -> Path:
    """Reviewer vault. AEGIS_VAULT may point at separately mounted or append-only storage."""
    return Path(os.environ.get("AEGIS_VAULT") or p("reviewer_vault")) / (run_id + ".jsonl")


def anchor_path(run_id: str) -> Path:
    """Terminal anchor store. AEGIS_ANCHORS may point at storage the run-directory writer cannot reach."""
    return Path(os.environ.get("AEGIS_ANCHORS") or p("anchors")) / (run_id + ".terminal.json")


def write_json(path: Path, obj):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp")
    with os.fdopen(fd, "w") as fh:
        json.dump(obj, fh, indent=2, sort_keys=True)
    os.replace(tmp, path)


def read_json(path: Path, default=None):
    path = Path(path)
    if not path.exists():
        return default
    return json.loads(path.read_text())


def append_jsonl(path: Path, obj):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as fh:
        fh.write(json.dumps(obj, sort_keys=True) + "\n")


def tokens() -> dict:
    path = p("keys", "tokens.json")
    tok = read_json(path)
    if tok is None:
        tok = {role: secrets.token_urlsafe(24)
               for role in ("operator", "reviewer", "blue_participant", "red_participant")}
        write_json(path, tok)
        os.chmod(path, 0o600)
    return tok
