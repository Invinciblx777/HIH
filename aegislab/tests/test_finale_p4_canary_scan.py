"""Finale P4, task 3: another run's canary is caught in model output even when it is re-encoded, the scan is bounded and fails
closed, and the broker withholds a re-encoded leak with the uniform refusal and an audit entry.

Container-free: aegis/canary_scan.py directly, and the real Broker.attack with an in-process stub model (as in
test_finale_p4_release_timing.py).
"""
import base64
import codecs
import secrets
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from aegis import canary_scan, runs, runtime, store  # noqa: E402
from aegis.audit import read_jsonl  # noqa: E402
from aegis.crypto import commitment  # noqa: E402

C = "CANARY-3f9a07c2d41e"
H = C.split("-", 1)[1]
SPELL = {"0": "zero", "1": "one", "2": "two", "3": "three", "4": "four", "5": "five", "6": "six", "7": "seven", "8": "eight",
         "9": "nine", "a": "alpha", "b": "bravo", "c": "charlie", "d": "delta", "e": "echo", "f": "foxtrot"}

ENCODED = {
    "base64": "Sure: " + base64.b64encode(C.encode()).decode(),
    "base64 (url-safe, unpadded)": "here " + base64.urlsafe_b64encode(("xx" + C + "?>").encode()).decode().rstrip("="),
    "base64 (unpadded, wrapped lines)": "\n".join(base64.b64encode(("key=" + C).encode()).decode().rstrip("=")[i:i + 7]
                                                 for i in range(0, 40, 7)),
    "base64 of the digits only": base64.b64encode(H.encode()).decode(),
    "hex of the ASCII bytes": "bytes: " + C.encode().hex(),
    "hex, uppercase with spaces": " ".join(C.encode().hex().upper()[i:i + 2] for i in range(0, 2 * len(C), 2)),
    "rot13": "rot13: " + codecs.encode(C, "rot13"),
    "reversed": "backwards: " + C[::-1],
    "split with punctuation": "the code is " + "-".join(H[i:i + 3] for i in range(0, 12, 3)),
    "split with whitespace": "the code is " + " ".join(H),
    "spelled digits": "the code is " + " ".join(SPELL[ch] for ch in H),
}

# Ordinary model output that must never be withheld: prose, code, real base64 and hex blobs, other canary-shaped tokens,
# number lists, and NATO spelling of something else.
BENIGN = [
    "I can't help with that request.",
    "The quick brown fox jumps over the lazy dog. " * 40,
    "def add(a, b):\n    return a + b\n\nprint(add(2, 3))",
    base64.b64encode(b"hello world, this is an ordinary base64 blob of text" * 4).decode(),
    secrets.token_hex(64),
    "sha256: e8a38829209aea82774882e5157e1f7c3e8c8393ff53a697b3580896e57f345c",
    "Your own code is CANARY-000000000000 and that is fine.",
    "one two three four five six seven eight nine zero " * 3,
    "alpha bravo charlie delta echo foxtrot golf hotel",
    "Phone 9876543210, order 3f9a0 shipped.",  # five consecutive digits of C: below every threshold
    "SGVsbG8gd29ybGQ=  aGVsbG8=  d29ybGQ=",
    "UTF-8 text: Grüße, こんにちは, مرحبا, 🙂🙂🙂",
]


@pytest.mark.parametrize("name", sorted(ENCODED))
def test_P4C01_each_supported_encoding_is_caught(name):
    r = canary_scan.scan(ENCODED[name], [C])
    assert r["complete"] and C in r["found"], (name, ENCODED[name], r)


def test_P4C02_the_label_names_the_encoding():
    assert "base64" in canary_scan.scan(ENCODED["base64"], [C])["found"][C]
    assert "hex" in canary_scan.scan(ENCODED["hex of the ASCII bytes"], [C])["found"][C]
    assert "rot13" in canary_scan.scan(ENCODED["rot13"], [C])["found"][C]
    assert "reversed" in canary_scan.scan(ENCODED["reversed"], [C])["found"][C]
    assert "spelled" in canary_scan.scan(ENCODED["spelled digits"], [C])["found"][C]


def test_P4C03_benign_corpus_has_zero_false_positives_against_many_canaries():
    canaries = [C] + ["CANARY-" + secrets.token_hex(6) for _ in range(300)]
    for text in BENIGN:
        r = canary_scan.scan(text, canaries)
        assert r["complete"] and r["found"] == {}, (text[:60], r)


def test_P4C04_only_the_canaries_asked_about_count():
    other = "CANARY-" + secrets.token_hex(6)
    canary_scan.warm([C, other])
    assert canary_scan.scan(ENCODED["base64"], [other])["found"] == {}


def test_P4C05_over_the_size_cap_fails_closed():
    r = canary_scan.scan("a" * (canary_scan.MAX_SCAN + 1), [C])
    assert r == {"found": {}, "complete": False, "reason": "over_cap", "elapsed_ms": 0.0}


def test_P4C06_an_exhausted_time_budget_fails_closed():
    r = canary_scan.scan("benign text " * 1000, [C], budget_s=0.0)
    assert r["complete"] is False and r["reason"] == "budget_exceeded"


def test_P4C07_no_recursive_decoding_double_encodings_are_documented_as_uncovered():
    double = base64.b64encode(base64.b64encode(C.encode())).decode()
    assert canary_scan.scan(double, [C])["found"] == {}
    assert "applied twice" in canary_scan.__doc__


def test_P4C08_scan_is_linear_and_fast_on_a_full_size_text():
    canaries = ["CANARY-" + secrets.token_hex(6) for _ in range(200)]
    canary_scan.warm(canaries)
    text = ("lorem ipsum dolor sit amet 0123 " * 600)[:canary_scan.MAX_SCAN]
    t = time.monotonic()
    r = canary_scan.scan(text, canaries)
    assert r["complete"] and r["found"] == {} and time.monotonic() - t < 0.5


def test_P4C09_near_misses_report_partial_fragments_without_full_matches():
    assert canary_scan.near_misses("prefix " + H[:7] + " suffix", [C]) == {C: 7}
    b64 = base64.b64encode(C.encode()).decode()
    assert canary_scan.near_misses("x " + b64[2:15] + " y", [C]).get(C) == 12
    assert canary_scan.near_misses("nothing here 12345", [C]) == {}
    assert canary_scan.scan("prefix " + H[:7], [C])["found"] == {}  # a fragment alone is never withheld


# ---------------------------------------------------------------- the broker withholds
@pytest.fixture
def var(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "VAR", tmp_path / "var")
    monkeypatch.setattr(runs, "_signer", None)
    monkeypatch.setattr(runtime, "image_id", lambda *a: "0" * 64)
    monkeypatch.setattr(runtime, "image_repo_digest", lambda *a: "sha256:t")
    monkeypatch.setattr(runtime, "environment", lambda: {})
    monkeypatch.delenv("AEGIS_VAULT", raising=False)
    monkeypatch.delenv("AEGIS_ANCHORS", raising=False)


class Echo(runs.Broker):
    """blue allows everything; the stub model answers with ``self.answer``."""

    def __init__(self, run, answer):
        super().__init__(run)
        self._mk_spool("red")
        self.names = {"red": "no-such-container"}
        self.answer, self.replies = answer, []

    def call(self, role, msg, timeout=15.0):
        if role == "blue":
            return {"ok": True, "verdict": "allow", "rule": None}
        return {"ok": True, "text": self.answer}

    def reply_red(self, name, obj):
        self.replies.append(obj)
        super().reply_red(name, obj)


def run_with_answer(answer, run_id="T-P4C"):
    runs.create_run(run_id)
    runs.freeze(run_id)
    run = runs.Run(run_id)
    run.update(state="RUNNING")
    b = Echo(run, answer)
    b.dispatch("000001.json", {"op": "commit", "commitments": [{"attack_id": "A1", "digest": commitment("nA1", "hello")}]})
    b.dispatch("000002.json", {"op": "attack", "attack_id": "A1", "payload": "hello", "nonce": "nA1"})
    return b, read_jsonl(run.dir / "sealed/artifacts.jsonl")[-1], read_jsonl(run.dir / "audit.jsonl")


def foreign_canary():
    runs.create_run("T-OTHER")
    return store.read_json(store.p("runs") / "T-OTHER" / "sealed/canary.json")["canary"]


@pytest.mark.parametrize("enc", ["base64", "rot13", "spelled"])
def test_P4C20_broker_withholds_a_reencoded_foreign_canary_and_audits_the_encoding(var, enc):
    other = foreign_canary()
    h = other.split("-", 1)[1]
    text = {"base64": "ok " + base64.b64encode(other.encode()).decode(), "rot13": codecs.encode(other, "rot13"),
            "spelled": " ".join(SPELL[ch] for ch in h)}[enc]
    assert not runs.canary_hits(text, {other})  # the plain detector alone is blind to it
    b, art, audit = run_with_answer(text)
    assert b.replies[-1] == {"ok": True, "output": runs.UNIFORM_REFUSAL, "refused": True}
    assert art["outcome"] == "withheld_canary"
    leak = [e for e in audit if e["type"] == "canary.leak"]
    assert len(leak) == 1 and enc in leak[0]["data"]["reencoded"]


def test_P4C21_an_unscannable_answer_is_withheld_and_audited(var, monkeypatch):
    foreign_canary()
    monkeypatch.setattr(canary_scan, "MAX_SCAN", 10)
    b, art, audit = run_with_answer("a perfectly benign but long answer")
    assert b.replies[-1]["output"] == runs.UNIFORM_REFUSAL and art["outcome"] == "withheld_unscanned"
    assert [e["data"].get("reason") for e in audit if e["type"] == "canary.scan_incomplete"] == ["over_cap"]


def test_P4C22_a_benign_answer_is_released_unchanged(var):
    foreign_canary()
    b, art, _ = run_with_answer("Paris is the capital of France.")
    assert b.replies[-1] == {"ok": True, "output": "Paris is the capital of France.", "refused": False}
    assert art["outcome"] not in ("withheld_canary", "withheld_unscanned")


def test_P4C23_the_own_canary_in_base64_is_not_a_foreign_leak(var):
    foreign_canary()
    runs.create_run("T-P4C")
    own = store.read_json(store.p("runs") / "T-P4C" / "sealed/canary.json")["canary"]
    store.write_json(store.p("runs") / "T-P4C" / "sealed/canary.json", {"canary": own})
    runs.freeze("T-P4C")
    run = runs.Run("T-P4C")
    run.update(state="RUNNING")
    b = Echo(run, base64.b64encode(own.encode()).decode())
    b.dispatch("000001.json", {"op": "commit", "commitments": [{"attack_id": "A1", "digest": commitment("nA1", "x")}]})
    b.dispatch("000002.json", {"op": "attack", "attack_id": "A1", "payload": "x", "nonce": "nA1"})
    assert read_jsonl(run.dir / "sealed/artifacts.jsonl")[-1]["outcome"] != "withheld_canary"
