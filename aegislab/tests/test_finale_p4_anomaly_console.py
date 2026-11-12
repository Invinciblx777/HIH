"""Finale P4, task 4: the console shows the anomaly detectors to the operator (and reviewer) only.

Uses the R2 lab fixtures: a real console, a real Broker whose containers are in-process fakes, and its scripted forbidden
requests (five denials of four distinct operations), which fire the denial-burst and forbidden-sweep detectors.
"""
from pathlib import Path

from fastapi.testclient import TestClient

from test_r2_lab import client, fake_host, isolated, login, sealed_run  # noqa: F401  (pytest fixtures)
from aegis import anomaly, console, store


def test_P4A30_operator_sees_detectors_thresholds_and_alerts_participants_are_refused(client, fake_host):  # noqa: F811
    h = login(client)
    rid = sealed_run(client, h)
    d = client.get("/api/lab/runs/%s/anomalies" % rid).json()
    assert [x["name"] for x in d["detectors"]] == list(anomaly.DETECTORS)
    assert all(x["threshold"] and x["rationale"] for x in d["detectors"])
    fired = {x["name"]: x["fired"] for x in d["detectors"]}
    assert fired["denial_burst"] == 1 and fired["forbidden_sweep"] == 1 and d["sealed_summary"] is True
    assert {a["detector"] for a in d["alerts"]} == {"denial_burst", "forbidden_sweep"} and all(a["signed"] for a in d["alerts"])
    # the signed audit view labels them and keeps only the detector's name, threshold and occurrence
    log = client.get("/api/lab/runs/%s/audit" % rid, params={"type": "anomaly.alert"}).json()["entries"]
    assert {e["decision"] for e in log} == {"alert"} and all(set(e["data"]) <= {"detector", "threshold", "occurrence"} for e in log)
    other = TestClient(console.app, base_url="http://127.0.0.1")
    assert other.get("/api/lab/runs/%s/anomalies" % rid).status_code == 403
    assert other.get("/api/lab/runs/%s/anomalies" % rid, headers={"X-Aegis-Token": store.tokens()["red_participant"]}).status_code == 403
    assert other.get("/api/lab/runs/%s/anomalies" % rid, headers={"X-Aegis-Token": store.tokens()["reviewer"]}).status_code == 200


def test_P4A31_console_script_renders_the_detector_panel_in_the_signed_log_view():
    js = (Path(__file__).resolve().parent.parent / "web/console/console.js").read_text()
    assert "/anomalies" in js and "Anomaly detectors" in js and '"alert", "failed"' in js
