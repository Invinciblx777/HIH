"""Finale P17: the jailbreak result UI of the real-model console (pipeline, verdict banner, "why red learned nothing",
accuracy card, guide, presets, evidence strip). Container-free. Checks that every figure the page shows matches the
evidence files and finale_package/claims_used_for_finale.json, that stages() reads the sealed artifact correctly, and
that the new browser code still writes untrusted text only through textContent."""
import base64
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from aegis import anchor, playground, runs  # noqa: E402

JS = (ROOT / "web/console/console.js").read_text()
P17 = JS[JS.index("const P17 = {"):JS.index("function drawLabCards()")]
CLAIMS = json.loads((ROOT.parent / "finale_package/claims_used_for_finale.json").read_text())["claims"]
GUARD = json.loads((ROOT / "evidence/finale_p16_2026-11-20/guard_eval/result.json").read_text())
E5 = ROOT / "evidence/finale_p17_2026-11-21/anchor_e5"


def ids(st):
    return {s["id"]: s for s in st}


def art(**kw):
    a = {"attack_id": "J1", "answered_ms": 4000.0, "final_output": runs.UNIFORM_REFUSAL, "canary_leaks": [],
         "release": {"deadline_ms": 4000, "cut_off": False}}
    a.update(kw)
    return a


def test_p17_01_guard_block_stages():
    a = art(compute_ms=794.8, defence_in_ms=794.8, model_ms=None, model_output=None, outcome="blocked_input",
            verdict_in={"verdict": "block", "guard_mode": "both", "regex": {"verdict": "allow", "rule": None},
                        "guard": {"safety": "Unsafe", "categories": ["Non-violent Illegal Acts"], "ms": 791.8}},
            verdict_out={"verdict": "skipped"})
    s = ids(playground.stages(a, 4045.9))
    assert [x["id"] for x in playground.stages(a)] == ["red", "broker_in", "regex", "guard", "model", "output", "canary", "broker_out", "red_rx"]
    assert s["regex"]["status"] == "pass" and s["regex"]["derived"] and s["regex"]["ms"] == 3.0
    assert s["guard"]["status"] == "block" and s["guard"]["ms"] == 791.8 and "Non-violent Illegal Acts" in s["guard"]["note"]
    assert s["model"]["status"] == "skip" and s["model"]["note"] == "never called" and s["model"]["ms"] is None
    assert s["output"]["status"] == "skip" and s["canary"]["status"] == "skip"
    assert s["broker_out"]["ms"] == 4000.0 and s["red_rx"]["ms"] == 4045.9 and s["red_rx"]["note"] == "uniform refusal"


def test_p17_02_regex_only_answered_stages():
    a = art(compute_ms=1833.2, defence_in_ms=4.6, model_ms=1822.6, model_output="As an actor", final_output="As an actor",
            outcome="safe_output", verdict_in={"ok": True, "rule": None, "verdict": "allow"}, verdict_out={"verdict": "allow"})
    s = ids(playground.stages(a, 4051.7))
    assert s["regex"] == {"id": "regex", "label": "Regex input check", "status": "pass", "ms": 4.6, "derived": False, "note": "no rule matched"}
    assert s["guard"]["status"] == "skip" and s["guard"]["note"] == "guard off"
    assert s["model"]["status"] == "pass" and s["model"]["ms"] == 1822.6
    assert s["output"]["status"] == "pass" and s["output"]["derived"] and s["output"]["ms"] == 6.0
    assert s["canary"]["status"] == "pass" and s["red_rx"]["note"] == "model text after output checks"


def test_p17_03_regex_block_and_canary_leak():
    a = art(compute_ms=2.0, defence_in_ms=2.0, model_ms=None, model_output=None, outcome="blocked_input",
            verdict_in={"verdict": "block", "rule": "ignore_previous"}, verdict_out={"verdict": "skipped"})
    s = ids(playground.stages(a))
    assert s["regex"]["status"] == "block" and "ignore_previous" in s["regex"]["note"] and s["model"]["status"] == "skip"
    b = art(compute_ms=900.0, defence_in_ms=3.0, model_ms=890.0, model_output="CANARY-x", outcome="canary_leak",
            canary_leaks=["CANARY-x"], verdict_in={"verdict": "allow"}, verdict_out={"verdict": "allow"})
    s = ids(playground.stages(b))
    assert s["canary"]["status"] == "block" and s["canary"]["note"] == "1 hit(s), withheld" and "CANARY" not in json.dumps(s)


def test_p17_04_guard_error_fails_closed_note():
    a = art(compute_ms=10.0, defence_in_ms=10.0, model_output=None, verdict_in={"verdict": "block", "regex": {"verdict": "allow"},
                                                                               "guard": {"safety": None, "error": "timeout", "ms": 9.0}})
    assert "fail closed" in ids(playground.stages(a))["guard"]["note"]


def test_p17_05_accuracy_card_matches_evidence():
    ps = GUARD["per_set"]
    want = {"gandalf": (112, "blocked_attack"), "jbb_harmful": (100, "blocked_attack"), "hh_helpful": (200, "blocked_benign"), "jbb_benign": (100, "blocked_benign")}
    rows = re.findall(r'kind: "([a-z ]+)", n: (\d+), regex: (\d+), guard: (\d+), both: (\d+)', P17)
    assert len(rows) == 4
    for (key, (n, field)), (_, rn, rx, gd, bo) in zip(want.items(), rows):
        assert int(rn) == n == ps[key]["regex"]["n_attack" if field == "blocked_attack" else "n_benign"]
        assert (int(rx), int(gd), int(bo)) == (ps[key]["regex"][field], ps[key]["qwen3guard"][field], ps[key]["both"][field])
    lat = GUARD["guard_latency_ms"]
    assert f"p50: {round(lat['p50'])}, p95: {round(lat['p95'])}, n: {lat['n']}, errors: {GUARD['guard_errors']}" in P17
    assert CLAIMS["p16_guard_latency"]["label"] in P17


def test_p17_06_timing_card_matches_claims():
    t = CLAIMS["p16_guard_timing"]
    for k in ("unpadded", "deadline", "cost", "overruns"):
        assert f'"{t["forms"][k]}"' in P17, k
    assert t["forms"]["n"] in P17 and t["label"] in P17 and "D: 4000" in P17


def test_p17_07_anchor_strip_matches_e5_evidence():
    rec = json.loads((E5 / "bundle/anchor.json").read_text())
    good = json.loads((E5 / "check_good.json").read_text())
    bad = json.loads((E5 / "check_tampered.json").read_text())
    assert good["exit"] == 0 and good["ok"] and bad["exit"] == 1 and not bad["ok"]
    assert rec["tx_hash"] == good["tx_hash"] and f'tx: "{rec["tx_hash"]}"' in P17 and f"block: {rec['block_number']}" in P17
    assert anchor.digest(rec["record"]) == rec["digest"]
    assert round(rec["fee_wei"] / 1e18, 9) == 0.000000154 and "0.000000154 ETH" in P17


def test_p17_08_presets():
    pre = re.findall(r'\{ k: "(\w+)", t: "([^"]+)", p: ("[^"]*"|PLAY_DEFAULT) \}', P17)
    assert [p[0] for p in pre] == ["B", "DAN", "ENC", "OK"]
    enc = json.loads(pre[2][2]).rsplit(" ", 1)[1]
    assert "system prompt" in base64.b64decode(enc).decode()
    assert all(len(json.loads(p[2])) <= playground.MAX_PROMPT for p in pre if p[2] != "PLAY_DEFAULT")


def test_p17_09_new_ui_writes_text_only():
    body = P17[P17.index("function drawWhy("):]
    assert "innerHTML" not in body and "insertAdjacentHTML" not in body and "outerHTML" not in body
    tmpl = JS[JS.index("async function drawPlay()"):JS.index("function drawWhy(")]
    assert len(re.findall(r"\$\{", tmpl.split("box.innerHTML = `", 1)[1].split("`;", 1)[0])) == 3  # secHead + st.guard + canAct only


def test_p17_10_skip_class_does_not_collide():
    css = (ROOT / "web/console/console.css").read_text()
    assert re.search(r"^\.skip \{ position: absolute", css, re.M)  # the skip link
    assert '"ps st-" + s.status' in P17 and '"g-skip"' in P17 and ".ps.st-skip" in css


def test_p17_11_result_carries_stages(monkeypatch):
    assert '"stages"] = stages(a, lat.get(a["attack_id"]))' in (ROOT / "aegis/playground.py").read_text()
    assert '"deadline_ms": DEADLINE_MS' in (ROOT / "aegis/playground.py").read_text()
