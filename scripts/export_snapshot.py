"""Export a static snapshot of the local control plane for offline viewing of the website.

    python scripts/export_snapshot.py            # writes web/snapshot/*.json
Opening web/ without the API (e.g. `python -m http.server -d web`) then shows this snapshot,
labelled "Static snapshot exported from a local prototype run (actions disabled)".
Only data the API exposes to an observer is exported, plus evidence for released runs.
"""
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient  # noqa: E402

from aegis import api, evidence, store  # noqa: E402
from aegis.verify_cli import TAMPER_MODES  # noqa: E402

OUT = ROOT / "web" / "snapshot"


def main():
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)
    c = TestClient(api.app)
    rev = {"X-Aegis-Token": store.tokens()["reviewer"]}
    runs = c.get("/api/runs").json()
    (OUT / "runs.json").write_text(json.dumps(runs))
    for r in runs:
        rid = r["id"]
        (OUT / ("run_%s.json" % rid)).write_text(json.dumps(c.get("/api/runs/" + rid).json()))
        (OUT / ("events_%s.json" % rid)).write_text(json.dumps(c.get("/api/runs/%s/events" % rid).json()))
        if r["state"] == "RELEASED":
            rep = c.get("/api/runs/%s/evidence" % rid).json()
            (OUT / ("evidence_%s.json" % rid)).write_text(json.dumps(rep))
            (OUT / ("evidence_%s.md" % rid)).write_text(evidence.markdown(rep))
            (OUT / ("verify_%s.json" % rid)).write_text(json.dumps(c.get("/api/runs/%s/verify" % rid).json()))
    for mode in TAMPER_MODES:
        res = c.post("/api/runs/DEMO-001/tamper-test", json={"mode": mode}, headers=rev).json()
        (OUT / ("tamper_DEMO-001_%s.json" % mode)).write_text(json.dumps(res))
    shutil.copy(ROOT / "evidence" / "results.json", OUT / "results.json")
    print("snapshot:", len(list(OUT.iterdir())), "files in", OUT)


if __name__ == "__main__":
    main()
