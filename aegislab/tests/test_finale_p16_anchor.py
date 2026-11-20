"""Finale P16 (part E): optional Base mainnet terminal anchor. OFF by default; every test here uses a fake JSON-RPC chain (no network).
The one live test only READS: AEGIS_ANCHOR_LIVE=1 AEGIS_ANCHOR_LIVE_BUNDLE=<exported bundle with anchor.json>
AEGIS_ANCHOR_LIVE_ADDRESS=<anchor address> runs check() against the real RPCs; it never sends a transaction."""
import json
import os
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from aegis import anchor, evidence, runs, runtime, store  # noqa: E402

PK_HEX = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"   # public test vector, never funded
PK_ADDR = "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23"
U1, U2 = "https://rpc-one.invalid", "https://rpc-two.invalid"


@pytest.fixture(autouse=True)
def isolated_var(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "VAR", tmp_path / "var")
    monkeypatch.setattr(runs, "_signer", None)
    monkeypatch.setattr(runtime, "image_id", lambda *a: "0" * 64)
    monkeypatch.setattr(runtime, "image_repo_digest", lambda *a: "sha256:t")
    monkeypatch.setattr(runtime, "environment", lambda: {})
    monkeypatch.delenv("AEGIS_DEMO_MODE", raising=False)
    monkeypatch.setenv("AEGIS_ANCHOR_KEY", str(tmp_path / "no-such.key"))
    monkeypatch.delenv("AEGIS_ANCHOR_RPCS", raising=False)
    if anchor.installed():  # flags-ON gate run: the explicit tests below drive post() themselves
        monkeypatch.setattr(runs.Run, "terminal_checkpoint", anchor._orig_terminal)
    yield
    anchor.wait_all(5)


@pytest.fixture
def key(tmp_path):
    p = tmp_path / "anchor.key"
    p.write_text(PK_HEX + "\n")
    os.chmod(p, 0o600)
    return p


class FakeChain:
    """Just enough of a Base node: decodes the signed type-2 transaction, recovers the sender and mines it at once."""

    def __init__(self, chain_id=8453, base_fee=5_000_000, offline=False, balance=10**16, l1=123_456):
        self.chain_id, self.base_fee, self.offline, self.balance, self.l1 = chain_id, base_fee, offline, balance, l1
        self.block, self.t0, self.txs, self.receipts, self.nonces, self.sent, self.calls = 30_000_000, 1_800_000_000, {}, {}, {}, [], []

    def __call__(self, url, method, params):
        self.calls.append(method)
        if self.offline:
            raise anchor.Offline("URLError")
        return getattr(self, method)(*params)

    def eth_chainId(self):
        return hex(self.chain_id)

    def eth_blockNumber(self):
        return hex(self.block)

    def eth_getTransactionCount(self, addr, tag):
        return hex(self.nonces.get(addr.lower(), 0))

    def eth_getBlockByNumber(self, n, full):
        num = self.block if n == "latest" else int(n, 16)
        return {"number": hex(num), "baseFeePerGas": hex(self.base_fee), "timestamp": hex(self.t0 + 2 * (num - 30_000_000))}

    def eth_maxPriorityFeePerGas(self):
        return hex(1_000_000)

    def eth_estimateGas(self, call):
        data = bytes.fromhex(call["data"][2:])
        return hex(21_000 + sum(16 if b else 4 for b in data))

    def eth_sendRawTransaction(self, raw_hex):
        import rlp
        from eth_keys import keys
        raw = bytes.fromhex(raw_hex[2:])
        assert raw[0] == 2
        f = rlp.decode(raw[1:])
        i = lambda b: int.from_bytes(b, "big")  # noqa: E731
        h = anchor.keccak(b"\x02" + rlp.encode(f[:9]))
        sender = keys.Signature(vrs=(i(f[9]), i(f[10]), i(f[11]))).recover_public_key_from_msg_hash(h).to_checksum_address()
        txh = "0x" + anchor.keccak(raw).hex()
        self.block += 1
        self.nonces[sender.lower()] = self.nonces.get(sender.lower(), 0) + 1
        self.txs[txh] = {"hash": txh, "from": sender.lower(), "to": "0x" + f[5].hex(), "input": "0x" + f[7].hex(), "chainId": hex(i(f[0])),
                         "value": hex(i(f[6])), "nonce": hex(i(f[1])), "blockNumber": hex(self.block)}
        self.receipts[txh] = {"status": "0x1", "blockNumber": hex(self.block), "blockHash": "0x" + "ab" * 32, "gasUsed": hex(21_752),
                              "effectiveGasPrice": hex(self.base_fee + 1_000_000), "l1Fee": hex(123_456)}
        self.sent.append(txh)
        self.block += 2
        return txh

    def eth_getBalance(self, addr, tag):
        return hex(self.balance)

    def eth_call(self, call, tag):
        assert call["to"] == anchor.GAS_PRICE_ORACLE and call["data"][2:10] == anchor.keccak(b"getL1Fee(bytes)")[:4].hex() == "49948e0e"
        return hex(self.l1)

    def eth_getTransactionByHash(self, h):
        return self.txs.get(h)

    def eth_getTransactionReceipt(self, h):
        return self.receipts.get(h)


def released_run(rid="ANCHOR-1"):
    """A run taken to RELEASED without containers (sealed the way the broker seals, then the real release gate)."""
    runs.create_run(rid)
    runs.freeze(rid)
    run = runs.Run(rid)
    run.update(state="RUNNING")
    run.log("run.sealed", "control-plane", {"complete": True, "evaluated": 1, "outcomes": {"blocked_input": 1},
                                            "sealed_artifacts_digest": "sha256:" + "ab" * 32})
    run.update(state="SEALED", sealed_at=time.time(), complete=True, outcomes={"blocked_input": 1})
    rel = runs.release(rid)
    assert rel["state"] == "RELEASED"
    return run


def snapshot(run):
    names = ["run.json", "audit.jsonl", "checkpoints.jsonl"]
    out = {n: (run.dir / n).read_bytes() for n in names if (run.dir / n).exists()}
    out["vault"] = store.vault_path(run.id).read_bytes()
    out["anchor_store"] = store.anchor_path(run.id).read_bytes()
    return out


def bundle_with_anchor(tmp_path, chain, key, rid="ANCHOR-1"):
    released_run(rid)
    rec = anchor.post(rid, rpc=chain, urls=[U1], key=key, poll_s=0)
    assert rec["status"] == "confirmed", rec
    b = tmp_path / ("bundle-" + rid)
    evidence.export_bundle(rid, b)
    anchor.post(rid, rpc=chain, urls=[U1], key=key, bundle=b)
    return b, rec


def test_P16E01_digest_is_deterministic_and_independent_of_key_order():
    r = {k: i for i, k in enumerate(anchor.RECORD_KEYS)}
    shuffled = dict(reversed(list(r.items())))
    assert anchor.digest(r) == anchor.digest(shuffled) == anchor.digest(json.loads(json.dumps(r)))
    assert len(bytes.fromhex(anchor.digest(r))) == 32


def test_P16E02_the_nonce_changes_the_digest_and_is_32_random_bytes():
    released_run()
    a, b = anchor.build_record("ANCHOR-1"), anchor.build_record("ANCHOR-1")
    assert len(bytes.fromhex(a["nonce"])) == 32 and a["nonce"] != b["nonce"]
    assert anchor.digest(a) != anchor.digest(b)
    assert anchor.digest(a) == anchor.digest(anchor.build_record("ANCHOR-1", nonce=a["nonce"]))


def test_P16E03_on_chain_payload_is_prefix_plus_digest_and_carries_no_clear_text(tmp_path, key):
    chain = FakeChain()
    run = released_run("SECRET-TEAM-RUN-42")
    rec = anchor.post(run.id, rpc=chain, urls=[U1], key=key, poll_s=0)
    data = bytes.fromhex(chain.txs[rec["tx_hash"]]["input"][2:])
    assert len(data) == 47 and data[:15] == b"AEGIS-ANCHOR-v1" and data[15:].hex() == rec["digest"]
    assert set(rec["record"]) == set(anchor.RECORD_KEYS)
    for clear in (b"SECRET", b"TEAM", b"RUN-42", b"Ignore", b"A02", b"blocked", str(tmp_path).encode(), b"127.0.0.1"):
        assert clear not in data
    assert "SECRET-TEAM-RUN-42" not in anchor.canonical(rec["record"]).decode()  # run id only as its sha256


def test_P16E04_flag_off_nothing_is_imported_or_wrapped():
    env = {k: v for k, v in os.environ.items() if not k.startswith("AEGIS_ANCHOR")}
    code = ("import aegis, aegis.runs as r, sys; print(r.Run.terminal_checkpoint.__qualname__, 'aegis.anchor' in sys.modules, "
            "any(m.split('.')[0] in ('eth_keys', 'rlp', 'Crypto', 'web3', 'eth_account') for m in sys.modules))")
    out = subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env, capture_output=True, text=True).stdout.split()
    assert out == ["Run.terminal_checkpoint", "False", "False"]
    on = subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=dict(env, AEGIS_ANCHOR_CHAIN="base"), capture_output=True, text=True).stdout.split()
    assert on[1] == "True" and on[2] == "False"  # ON: the hook is in, the signer libraries still load only when a key is used


def test_P16E05_flag_off_a_release_makes_no_socket_call_and_writes_no_anchor_file(tmp_path):
    env = {k: v for k, v in os.environ.items() if not k.startswith("AEGIS_ANCHOR")}
    env["AEGIS_VAR"] = str(tmp_path / "v")
    code = r'''
import socket, sys, time
sys.path.insert(0, "tests")
calls = []
def nope(self, *a):
    calls.append(a); raise OSError("blocked by test")
socket.socket.connect = nope
socket.create_connection = lambda *a, **k: nope(None, *a)
from aegis import runtime
runtime.image_id = lambda *a: "0" * 64; runtime.image_repo_digest = lambda *a: "sha256:t"; runtime.environment = lambda: {}
import test_finale_p16_anchor as t
run = t.released_run("OFF-1")
time.sleep(0.5)
print(len(calls), (run.dir / "anchor.json").exists(), "aegis.anchor" in sys.modules and __import__("aegis.anchor").anchor.installed())
'''
    p = subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env, capture_output=True, text=True)
    assert p.stdout.split() == ["0", "False", "False"], p.stderr[-2000:]


def test_P16E06_good_bundle_checks_exit_0_with_two_agreeing_rpcs(tmp_path, key):
    chain = FakeChain()
    b, rec = bundle_with_anchor(tmp_path, chain, key)
    assert (b / "anchor.json").is_file() and stat.S_IMODE((b / "anchor.json").stat().st_mode) == 0o600
    res = anchor.check(b, PK_ADDR, rpc=chain, urls=[U1, U2])
    assert res["exit"] == 0 and res["ok"], res
    assert res["block_number"] == rec["block_number"] and res["confirmations"] >= 1 and "2 RPCs agree" in res["checks"][-1]
    assert anchor.check(b, PK_ADDR.lower(), rpc=chain, urls=[U1])["exit"] == 0


def test_P16E07_tampered_bundle_two_audit_lines_deleted_exits_1(tmp_path, key):
    chain = FakeChain()
    b, _ = bundle_with_anchor(tmp_path, chain, key)
    bad = tmp_path / "tampered"
    shutil.copytree(b, bad)
    lines = (bad / "audit.jsonl").read_text().splitlines()
    (bad / "audit.jsonl").write_text("\n".join(lines[:-2]) + "\n")
    res = anchor.check(bad, PK_ADDR, rpc=chain, urls=[U1])
    assert res["exit"] == 1 and "audit log does not verify" in res["findings"][0]
    v = subprocess.run([sys.executable, "-m", "aegis.verify_cli", "--bundle", str(bad)], cwd=ROOT, capture_output=True, text=True)
    assert v.returncode != 0


def test_P16E08_resigned_history_with_new_record_contradicts_the_chain(tmp_path, key):
    """The attack the anchor exists for: the forger rewrites anchor.json's record for a re-signed history. The digest no longer
    matches the on-chain data (or, if anchor.json's digest is left, the recomputed one)."""
    chain = FakeChain()
    b, rec = bundle_with_anchor(tmp_path, chain, key)
    a = json.loads((b / "anchor.json").read_text())
    a["record"]["nonce"] = "00" * 32
    a["digest"] = anchor.digest(a["record"])
    (b / "anchor.json").write_text(json.dumps(a))
    res = anchor.check(b, PK_ADDR, rpc=chain, urls=[U1])
    assert res["exit"] == 1 and "on-chain data differs" in res["findings"][0]
    a["record"]["terminal_hash"] = "sha256:" + "11" * 32
    (b / "anchor.json").write_text(json.dumps(a))
    assert anchor.check(b, PK_ADDR, rpc=chain, urls=[U1])["exit"] == 1


def test_P16E09_wrong_sender_exits_1(tmp_path, key):
    chain = FakeChain()
    b, rec = bundle_with_anchor(tmp_path, chain, key)
    assert anchor.check(b, "0x" + "11" * 20, rpc=chain, urls=[U1])["exit"] == 1
    chain.txs[rec["tx_hash"]]["from"] = "0x" + "22" * 20
    res = anchor.check(b, PK_ADDR, rpc=chain, urls=[U1])
    assert res["exit"] == 1 and "not the pinned anchor address" in res["findings"][0]


def test_P16E10_wrong_chain_id_aborts_before_signing_or_sending(key):
    chain = FakeChain(chain_id=1)
    run = released_run()
    rec = anchor.post(run.id, rpc=chain, urls=[U1], key=key, poll_s=0)
    assert rec["status"] == "aborted" and "not Base mainnet" in rec["last_error"] and not chain.sent
    assert chain.calls == ["eth_chainId"]


def test_P16E11_fee_above_the_ceiling_is_not_sent(key):
    chain = FakeChain(base_fee=anchor.MAX_FEE_PER_GAS_WEI + 1)
    run = released_run()
    rec = anchor.post(run.id, rpc=chain, urls=[U1], key=key, poll_s=0)
    assert rec["status"] == "pending" and not chain.sent and "ceiling" in rec["last_error"]


def test_P16E11b_balance_short_of_worst_case_cost_aborts_with_a_clear_message_and_sends_nothing(key):
    chain = FakeChain(balance=10_000, l1=50_000)
    run = released_run()
    rec = anchor.post(run.id, rpc=chain, urls=[U1], key=key, poll_s=0)
    assert rec["status"] == "aborted" and not chain.sent and "is SHORT of" in rec["last_error"] and "L1 data fee 50000 wei" in rec["last_error"]
    c = rec["cost_check"]
    assert c["need_wei"] == c["l2_max_wei"] + 62_500 and not c["ok"]
    chain.balance = c["need_wei"]  # exactly enough: sent
    assert anchor.post(run.id, rpc=chain, urls=[U1], key=key, poll_s=0)["status"] == "confirmed" and len(chain.sent) == 1


def test_P16E12_offline_queues_then_flush_posts_once_and_post_is_idempotent(key):
    chain = FakeChain(offline=True)
    run = released_run()
    before = snapshot(run)
    rec = anchor.post(run.id, rpc=chain, urls=[U1], key=key, poll_s=0)
    assert rec["status"] == "pending" and rec["last_error"].startswith("offline") and anchor.pending() == [run.id]
    q = anchor.queue_path()
    assert stat.S_IMODE(q.stat().st_mode) == 0o600
    nonce = rec["record"]["nonce"]
    chain.offline = False
    out = anchor.flush(rpc=chain, urls=[U1], key=key, poll_s=0)
    assert out[0]["status"] == "confirmed" and len(chain.sent) == 1 and anchor.pending() == []
    again = anchor.post(run.id, rpc=chain, urls=[U1], key=key, poll_s=0)
    assert again["tx_hash"] == out[0]["tx_hash"] and len(chain.sent) == 1 and again["record"]["nonce"] == nonce
    assert snapshot(run) == before


def test_P16E13_failed_posts_never_change_run_state_or_evidence(tmp_path, key):
    run = released_run()
    before = snapshot(run)

    def broken(url, method, params):
        raise anchor.RpcError("insufficient funds for gas * price + value")
    for rpc, k in ((FakeChain(offline=True), key), (broken, key), (FakeChain(chain_id=10), key), (FakeChain(), tmp_path / "missing.key")):
        anchor.post(run.id, rpc=rpc, urls=[U1], key=k, poll_s=0)
    assert snapshot(run) == before and runs.Run(run.id).state == "RELEASED" and runs.verify_run(run.id)["ok"]
    rp = anchor.receipt_path(run.id)
    assert stat.S_IMODE(rp.stat().st_mode) == 0o600 and json.loads(rp.read_text())["status"] == "error"


def test_P16E14_missing_key_makes_no_network_call_and_is_not_queued(tmp_path):
    chain = FakeChain()
    run = released_run()
    rec = anchor.post(run.id, rpc=chain, urls=[U1], key=tmp_path / "missing.key")
    assert rec["status"] == "error" and chain.calls == [] and anchor.pending() == []
    loose = tmp_path / "loose.key"
    loose.write_text(PK_HEX)
    os.chmod(loose, 0o644)
    assert anchor.post(run.id, rpc=chain, urls=[U1], key=loose)["status"] == "error" and chain.calls == []


def test_P16E15_keygen_writes_0600_refuses_to_overwrite_and_prints_only_the_address(tmp_path):
    p = tmp_path / "cfg" / "base_anchor.key"
    env = dict(os.environ, AEGIS_ANCHOR_KEY=str(p))
    r = subprocess.run([sys.executable, "-m", "aegis.anchor", "keygen"], cwd=ROOT, env=env, capture_output=True, text=True)
    assert r.returncode == 0 and stat.S_IMODE(p.stat().st_mode) == 0o600
    raw = p.read_text().strip()
    assert len(raw) == 64 and raw not in r.stdout + r.stderr and r.stdout.strip().startswith("0x") and len(r.stdout.strip()) == 42
    a = subprocess.run([sys.executable, "-m", "aegis.anchor", "address"], cwd=ROOT, env=env, capture_output=True, text=True)
    assert a.stdout.strip() == r.stdout.strip() and raw not in a.stdout
    again = subprocess.run([sys.executable, "-m", "aegis.anchor", "keygen"], cwd=ROOT, env=env, capture_output=True, text=True)
    assert again.returncode == 1 and p.read_text().strip() == raw


def test_P16E16_known_vector_address_and_signed_tx_recovers_to_sender(key):
    pk = anchor._private_key(key)
    assert anchor.address_of(pk) == PK_ADDR
    chain = FakeChain()
    raw, h = anchor.sign_tx(pk, nonce=7, max_priority=1, max_fee=2, gas=30_000, to=PK_ADDR, data=anchor.payload("ab" * 32))
    assert chain.eth_sendRawTransaction("0x" + raw.hex()) == h
    t = chain.txs[h]
    assert t["from"] == PK_ADDR.lower() == t["to"] and t["chainId"] == hex(8453) and t["value"] == "0x0" and t["nonce"] == hex(7)


def test_P16E17_check_exit_2_when_missing_pending_or_unreachable_and_1_when_rpcs_disagree(tmp_path, key):
    chain = FakeChain()
    b, rec = bundle_with_anchor(tmp_path, chain, key)
    assert anchor.check(b, PK_ADDR, rpc=FakeChain(offline=True), urls=[U1])["exit"] == 2
    assert anchor.check(b, PK_ADDR, rpc=FakeChain(), urls=[U1])["exit"] == 2  # a node that never saw the tx
    other = FakeChain()
    other.txs, other.receipts = dict(chain.txs), {k: dict(v, blockHash="0x" + "cd" * 32) for k, v in chain.receipts.items()}
    other.block = chain.block
    split = lambda url, m, p: (chain if url == U1 else other)(url, m, p)  # noqa: E731
    res = anchor.check(b, PK_ADDR, rpc=split, urls=[U1, U2])
    assert res["exit"] == 1 and "disagree" in res["findings"][0]
    nob = tmp_path / "no-anchor"
    shutil.copytree(b, nob)
    (nob / "anchor.json").unlink()
    assert anchor.check(nob, PK_ADDR, rpc=chain, urls=[U1])["exit"] == 2
    a = json.loads((b / "anchor.json").read_text())
    a.update(tx_hash=None, status="pending")
    (nob / "anchor.json").write_text(json.dumps(a))
    assert anchor.check(nob, PK_ADDR, rpc=chain, urls=[U1])["exit"] == 2


def test_P16E18_hook_posts_after_the_terminal_checkpoint_without_touching_the_run(key, monkeypatch):
    chain = FakeChain()
    monkeypatch.setattr(anchor, "jsonrpc", chain)
    monkeypatch.setattr(anchor, "RECEIPT_TIMEOUT_S", 5)
    monkeypatch.setenv("AEGIS_ANCHOR_KEY", str(key))
    monkeypatch.setenv("AEGIS_ANCHOR_RPCS", U1)
    monkeypatch.setattr(runs.Run, "terminal_checkpoint", anchor._wrap(runs.Run.terminal_checkpoint))  # the original (fixture)
    run = released_run("HOOK-1")
    anchor.wait_all(20)
    rec = json.loads(anchor.receipt_path(run.id).read_text())
    assert rec["status"] == "confirmed" and len(chain.sent) == 1 and runs.Run(run.id).state == "RELEASED"
    assert runs.verify_run(run.id)["ok"] and anchor.post(run.id, rpc=chain, urls=[U1], key=key)["tx_hash"] == rec["tx_hash"]
    assert len(chain.sent) == 1


def test_P16E20_demo_report_copies_the_receipt_checks_it_and_never_sends(tmp_path, key, monkeypatch):
    chain = FakeChain()
    monkeypatch.setattr(anchor, "jsonrpc", chain)
    monkeypatch.setenv("AEGIS_ANCHOR_RPCS", U1)
    monkeypatch.setenv("AEGIS_ANCHOR_KEY", str(key))
    released_run("DEMO-1")
    b = tmp_path / "b"
    evidence.export_bundle("DEMO-1", b)
    assert anchor.demo_report("DEMO-1", b, timeout=1)["exit"] == 2 and not chain.sent and not (b / "anchor.json").exists()
    anchor.post("DEMO-1", poll_s=0)
    n = len(chain.sent)
    rep = anchor.demo_report("DEMO-1", b, timeout=1)
    assert rep["exit"] == 0 and rep["line"].startswith("anchored on Base: block ") and rep["line"].endswith("check exit 0")
    assert rep["pinned"] == PK_ADDR and (b / "anchor.json").is_file() and len(chain.sent) == n == 1


@pytest.mark.skipif(os.environ.get("AEGIS_ANCHOR_LIVE") != "1", reason="live Base mainnet read: set AEGIS_ANCHOR_LIVE=1, _BUNDLE and _ADDRESS")
def test_P16E19_live_check_of_a_real_anchored_bundle():
    res = anchor.check(os.environ["AEGIS_ANCHOR_LIVE_BUNDLE"], os.environ["AEGIS_ANCHOR_LIVE_ADDRESS"])
    assert res["exit"] == 0, res
