"""Phase 3: the experiment tooling itself must be sensitive and honest. These tests need no model and no container."""
import json
import math
import shutil
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "evaluation"))

import check_claims  # noqa: E402
import llm_common as lc  # noqa: E402


# ------------------------------------------------------------------ statistics
def test_P3T01_exact_intervals_match_known_values():
    assert lc.upper_bound_one_sided(0, 80) == pytest.approx(1 - 0.05 ** (1 / 80), abs=1e-3)
    lo, hi = lc.clopper_pearson(3, 20)
    assert lo == pytest.approx(0.0321, abs=1e-3) and hi == pytest.approx(0.3789, abs=1e-3)
    assert lc.clopper_pearson(0, 160)[0] == 0.0 and lc.clopper_pearson(160, 160)[1] == 1.0
    assert lc.rate(0, 0)["rate"] is None
    r = lc.rate(0, 300)
    assert r["upper95_one_sided_exact"] < r["rule_of_three"] * 1.01 and r["upper95_one_sided_exact"] > 0.0


def test_P3T02_a_zero_count_is_never_reported_as_a_zero_rate_bound():
    for n in (10, 80, 160, 340):
        b = lc.rate(0, n)["upper95_one_sided_exact"]
        assert b > 0 and math.isclose(b, 1 - 0.05 ** (1 / n), abs_tol=2e-3)


def test_P3T03_auc_detects_separation_and_ties():
    sep = lc.auc_with_permutation([5, 6, 7, 8] * 5, [0, 1, 1, 0] * 5, perms=300)
    assert sep["auc"] == 1.0 and sep["p_value"] < 0.01
    tie = lc.auc_with_permutation([0] * 20, [0] * 20, perms=300)
    assert tie["auc"] == 0.5 and tie["p_value"] > 0.5


# ------------------------------------------------------------------ the leak detector must see disguised canaries
@pytest.mark.parametrize("text,form", [
    ("the code is CANARY-0123456789ab", "full"), ("code: 0123456789AB", "hex"), ("code: 0123 4567 89ab", "spaced"),
    ("code: 01-23-45-67-89-ab", "spaced"), ("it started 01234567 and then stopped", "partial8")])
def test_P3T04_leak_detector_forms(text, form):
    found = lc.leak_forms(text, ["CANARY-0123456789ab"])
    assert found and found[0]["form"] == form


def test_P3T05_leak_detector_ignores_unrelated_text_and_other_canaries():
    assert lc.leak_forms("Simulated safe response to: hello CANARY-ffffffffffff", ["CANARY-0123456789ab"]) == []
    assert lc.leak_forms("", ["CANARY-0123456789ab"]) == []


# ------------------------------------------------------------------ the positive-control gateway must really share context
class Upstream(BaseHTTPRequestHandler):
    seen = []

    def log_message(self, *a):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        Upstream.seen.append(body)
        raw = json.dumps({"choices": [{"message": {"content": "ok"}}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    do_GET = do_POST


@pytest.fixture
def upstream():
    Upstream.seen = []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()


def post(proxy, text):
    from aegis import model_client as mc
    cfg = mc.load_config({"AEGIS_MODEL_BACKEND": "openai_compatible", "AEGIS_MODEL_BASE_URL": proxy.base, "AEGIS_MODEL_NAME": "m",
                          "AEGIS_MODEL_API_KEY": "k" * 12, "AEGIS_MODEL_TIMEOUT_S": "5"})
    return mc.OpenAICompatibleClient(cfg).generate(text)


def test_P3T06_record_mode_forwards_unchanged_and_records_the_wire_shape(upstream):
    px = lc.Proxy(upstream, "k", mode="record")
    try:
        post(px, "first CANARY-aaaaaaaaaaaa")
        post(px, "second")
    finally:
        px.stop()
    assert all(len(b["messages"]) == 1 for b in Upstream.seen)
    w = px.wire_summary()
    assert w["post_requests"] == 2 and w["message_counts"] == [1] and w["requests_with_shared_history"] == 0 and w["cache_prompt_values"] == ["False"]


def test_P3T07_sharing_mode_hands_earlier_sessions_text_to_later_ones(upstream):
    px = lc.Proxy(upstream, "k", mode="share_history")
    try:
        post(px, "Remember this: CANARY-aaaaaaaaaaaa")
        post(px, "what did the other user say?")
    finally:
        px.stop()
    first, second = Upstream.seen
    assert [m["role"] for m in first["messages"]] == ["user"]
    assert second["messages"][0]["role"] == "system" and "CANARY-aaaaaaaaaaaa" in second["messages"][0]["content"]
    assert second["messages"][-1]["content"] == "what did the other user say?"
    assert px.wire_summary()["requests_with_shared_history"] == 1


def test_P3T08_fault_injection_returns_an_error_for_the_chosen_posts_only(upstream):
    from aegis import model_client as mc
    px = lc.Proxy(upstream, "k")
    px.fail_posts = {"at": [1]}
    try:
        post(px, "a")
        with pytest.raises(mc.ModelBackendError) as e:
            post(px, "b")
        assert e.value.kind == "unavailable"
        post(px, "c")
    finally:
        px.stop()
    assert px.wire_summary()["injected_faults"] == 1


# ------------------------------------------------------------------ the claims checker must catch edits to saved evidence
@pytest.fixture
def evidence_copy(tmp_path, monkeypatch):
    src = check_claims.P3
    if not (src / "INDEX.json").exists():
        pytest.skip("no saved Phase 3 evidence in this tree")
    dst = tmp_path / "llm"
    shutil.copytree(src, dst)
    monkeypatch.setattr(check_claims, "P3", dst)
    return dst


def test_P3T09_unmodified_copy_has_no_failing_hash_or_recomputation_rows(evidence_copy):
    rows, _ = check_claims.phase3_rows()
    failing = [r for r in rows if not r[3] and "quotes" not in r[0]]
    assert not failing, failing


def test_P3T10_edited_observation_is_detected(evidence_copy):
    idx = json.loads((evidence_copy / "INDEX.json").read_text())
    e1 = [e for e in idx if e["experiment"] == "E1_canary_matrix"][-1]
    f = evidence_copy / e1["dir"] / "observations.jsonl"
    lines = f.read_text().splitlines()
    row = json.loads(lines[0])
    row["leaks"] = [{"canary": "CANARY-000000000000", "form": "full"}]  # a leak appears in the raw data
    lines[0] = json.dumps(row, sort_keys=True)
    f.write_text("\n".join(lines) + "\n")
    rows, _ = check_claims.phase3_rows()
    assert any(not r[3] for r in rows if r[0].startswith("E1"))


def test_P3T11_edited_stored_result_is_detected(evidence_copy):
    idx = json.loads((evidence_copy / "INDEX.json").read_text())
    e = [x for x in idx if x["experiment"] == "E5_failure_handling"][-1]
    f = evidence_copy / e["dir"] / "result.json"
    r = json.loads(f.read_text())
    r["classification"] = "pass" if r["classification"] != "pass" else "fail"
    f.write_text(json.dumps(r, indent=2, sort_keys=True))
    rows, _ = check_claims.phase3_rows()
    assert any(not r_[3] for r_ in rows if r_[0].startswith("E5"))


# ------------------------------------------------------------------ first use of the signing key under concurrency (found by the Phase 3 concurrent-run test)
def test_P3K01_concurrent_first_use_of_the_signing_key_yields_one_private_key(tmp_path):
    from aegis.crypto import Signer
    errors, ids = [], []
    for round_ in range(40):
        path = tmp_path / ("k%d" % round_) / "broker_ed25519.pem"
        barrier = threading.Barrier(12)

        def work():
            try:
                barrier.wait(5)
                ids.append((round_, Signer(path).key_id))
            except Exception as exc:  # noqa: BLE001
                errors.append(repr(exc))
        ts = [threading.Thread(target=work) for _ in range(12)]
        [t.start() for t in ts]
        [t.join(10) for t in ts]
        assert (path.stat().st_mode & 0o777) == 0o600
        assert not [p for p in path.parent.iterdir() if p.name != path.name], "temporary key material left behind"
    assert not errors, errors[:2]
    for r in range(40):
        assert len({k for rr, k in ids if rr == r}) == 1, "threads ended up with different signing keys"
