"""Finale P16 (part E): publish a 32-byte commitment to the terminal checkpoint on Base mainnet. OFF unless AEGIS_ANCHOR_CHAIN=base.

Why. A forger who steals the broker's Ed25519 key AND replaces every retained copy of the evidence can re-sign a different history
(THREAT_MODEL rows 6 and 10). Once one commitment to the genuine terminal checkpoint sits in a public, timestamped chain that the forger
cannot rewrite, a later re-signed history contradicts it. This closes the gap from the moment the anchor lands, not before.

What goes on-chain: one 0-value EIP-1559 transaction (type 2, chain ID 8453) from the anchor wallet TO ITSELF whose data is exactly
b"AEGIS-ANCHOR-v1" (15 bytes) + digest (32 bytes). No contract, no token, nothing else. digest = sha256 of the canonical JSON
(sort_keys, separators=(",", ":")) of the anchor record:

    {v: 1, chain_id: 8453, run_id_hash: sha256(run_id) hex, terminal_hash, head, event_count, cp_seq, state, key_id, pubkey_b64, nonce}

The random 32-byte nonce stops anyone guessing the record from the digest. Prompts, outputs, run IDs in clear, team names, IPs and paths
never leave this machine. The record is kept locally in var/runs/<id>/anchor.json (mode 0600) with the tx hash, block and fee.

    AEGIS_ANCHOR_CHAIN=base      turn the anchor ON (aegis/__init__.py installs the hook only then; unset = nothing imported, no network)
    AEGIS_ANCHOR_KEY=/abs/path   anchor wallet key (default ~/.config/aegislab/base_anchor.key, mode 0600, outside the repository)
    AEGIS_ANCHOR_RPCS=url[,url]  JSON-RPC endpoints (default mainnet.base.org + base-rpc.publicnode.com). Transactions are sent through the
                                 first; check() requires every configured endpoint to agree.

Hook: install() wraps runs.Run.terminal_checkpoint from outside runs.py (runs.py is pinned by saved experiments). After the original has
written the signed terminal checkpoint (RELEASED or FAILED) a daemon thread calls post(run_id). An anchor failure NEVER changes run state,
sealing, release or the evidence: post() only writes anchor.json, var/anchor_queue.jsonl and var/anchor.lock.
Offline venue: the RPC unreachable -> the run is queued ("pending") and `python -m aegis.anchor flush` posts it later.
A missing or unreadable key is an error that is NOT queued and makes no network call.

    python -m aegis.anchor keygen | address | post --run-id ID [--bundle DIR] | flush | check --bundle DIR --address 0x...

check exits 0 only if every check passes, 1 on any mismatch, 2 when the anchor is missing, pending or the RPC is unreachable.
"""
import argparse
import fcntl
import hashlib
import json
import os
import secrets
import shutil
import stat
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

from . import store
from .audit import checkpoint_hash, read_jsonl, verify

CHAIN_ID = 8453
PREFIX = b"AEGIS-ANCHOR-v1"
DEFAULT_RPCS = ("https://mainnet.base.org", "https://base-rpc.publicnode.com")
DEFAULT_KEY = Path.home() / ".config" / "aegislab" / "base_anchor.key"
MAX_FEE_PER_GAS_WEI = 1_000_000_000      # hard ceiling: 1 gwei (Base base fee is normally ~0.001-0.05 gwei)
MAX_PRIORITY_FEE_WEI = 10_000_000        # 0.01 gwei
MAX_GAS = 60_000                         # a 47-byte self-transfer needs ~21 800
L1_FEE_MARGIN = (5, 4)                   # the balance must cover 1.25 x the L1 data fee quoted now (it is charged at inclusion)
GAS_PRICE_ORACLE = "0x420000000000000000000000000000000000000F"   # OP Stack predeploy on Base: getL1Fee(bytes)
RECEIPT_TIMEOUT_S = 60.0
RPC_TIMEOUT_S = 10.0
RECORD_KEYS = ("v", "chain_id", "run_id_hash", "terminal_hash", "head", "event_count", "cp_seq", "state", "key_id", "pubkey_b64", "nonce")

_orig_terminal = None
_threads = []


class Offline(Exception):
    """The RPC could not be reached (network down, DNS, timeout, HTTP 5xx): queue and retry later."""


class RpcError(Exception):
    """The RPC answered with a JSON-RPC error."""


class Abort(Exception):
    """A safety check failed (wrong chain, fee above the ceiling, bad signature): nothing is sent."""


# ---------------------------------------------------------------- record and digest

def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def record_from_checkpoint(cp: dict, pubkey_b64: str, nonce: str = None) -> dict:
    if not isinstance(cp, dict) or cp.get("reason") != "terminal" or cp.get("state") not in ("RELEASED", "FAILED"):
        raise ValueError("not a signed terminal checkpoint")
    return {"v": 1, "chain_id": CHAIN_ID, "run_id_hash": hashlib.sha256(cp["run_id"].encode()).hexdigest(),
            "terminal_hash": checkpoint_hash(cp), "head": cp["head"], "event_count": cp["event_count"], "cp_seq": cp["cp_seq"],
            "state": cp["state"], "key_id": cp["key_id"], "pubkey_b64": pubkey_b64,
            "nonce": nonce if nonce is not None else secrets.token_hex(32)}


def build_record(run_id: str, nonce: str = None) -> dict:
    """The record for a run with a terminal checkpoint in the anchor store (written once, mode 0444, outside the run directory)."""
    from .runs import signer
    cp = store.read_json(store.anchor_path(run_id))
    if not cp:
        raise ValueError("run %s has no terminal checkpoint" % run_id)
    return record_from_checkpoint(cp, signer().public_b64(), nonce)


def digest(record: dict) -> str:
    return hashlib.sha256(canonical(record)).hexdigest()


def payload(dig: str) -> bytes:
    return PREFIX + bytes.fromhex(dig)


# ---------------------------------------------------------------- wallet (eth-keys, rlp, pycryptodome: imported only here)

def keccak(data: bytes) -> bytes:
    from Crypto.Hash import keccak as _k
    return _k.new(digest_bits=256, data=data).digest()


def key_path(env=None) -> Path:
    env = os.environ if env is None else env
    return Path((env.get("AEGIS_ANCHOR_KEY") or "").strip() or DEFAULT_KEY)


def _private_key(path: Path):
    from eth_keys import keys
    st = os.stat(path)
    if not stat.S_ISREG(st.st_mode) or stat.S_IMODE(st.st_mode) != 0o600 or st.st_uid != os.getuid():
        raise ValueError("anchor key must be a regular file, mode 0600, owned by this user")
    raw = path.read_text().strip()
    return keys.PrivateKey(bytes.fromhex(raw[2:] if raw.startswith("0x") else raw))


def address_of(pk) -> str:
    return pk.public_key.to_checksum_address()


def keygen(path: Path) -> str:
    """Create a new secp256k1 key at path (0600). Refuses to overwrite. Returns only the address."""
    from eth_keys import keys
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    raw = secrets.token_bytes(32)
    pk = keys.PrivateKey(raw)  # raises for the (astronomically unlikely) out-of-range value
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)  # FileExistsError if present: never overwrite
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, (raw.hex() + "\n").encode())
    finally:
        os.close(fd)
    return address_of(pk)


def sign_tx(pk, *, nonce: int, max_priority: int, max_fee: int, gas: int, to: str, data: bytes, chain_id: int = CHAIN_ID):
    """EIP-1559 (type 2) transaction: 0x02 || rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gas, to, value, data,
    accessList, yParity, r, s]); the signed hash is keccak256(0x02 || rlp(first nine fields)). Returns (raw bytes, tx hash hex).
    The signature is recovered and compared with the sender before anything is returned."""
    import rlp
    fields = [chain_id, nonce, max_priority, max_fee, gas, bytes.fromhex(to[2:]), 0, data, []]
    h = keccak(b"\x02" + rlp.encode(fields))
    sig = pk.sign_msg_hash(h)
    if sig.recover_public_key_from_msg_hash(h).to_checksum_address() != address_of(pk):
        raise Abort("signature does not recover to the anchor address")
    raw = b"\x02" + rlp.encode(fields + [sig.v, sig.r, sig.s])
    return raw, "0x" + keccak(raw).hex()


# ---------------------------------------------------------------- JSON-RPC (urllib, no web3)

def rpcs(env=None) -> list:
    env = os.environ if env is None else env
    v = (env.get("AEGIS_ANCHOR_RPCS") or "").strip()
    return [u.strip() for u in v.split(",") if u.strip()] if v else list(DEFAULT_RPCS)


def jsonrpc(url: str, method: str, params: list):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(url, data=body, method="POST", headers={"Content-Type": "application/json",
                                                                         "User-Agent": "aegislab-anchor/1"})
    try:
        with urllib.request.urlopen(req, timeout=RPC_TIMEOUT_S) as r:
            out = json.loads(r.read(1 << 20))
    except urllib.error.HTTPError as e:
        if e.code >= 500 or e.code == 429:
            raise Offline("HTTP %d" % e.code) from None
        raise RpcError("HTTP %d" % e.code) from None
    except (urllib.error.URLError, OSError, TimeoutError, ValueError) as e:
        raise Offline(type(e).__name__) from None
    if out.get("error"):
        raise RpcError(str(out["error"].get("message", out["error"]))[:200])
    return out.get("result")


def _hex(n) -> int:
    return int(n, 16) if isinstance(n, str) else int(n)


# ---------------------------------------------------------------- local files

def receipt_path(run_id: str) -> Path:
    return store.run_dir(run_id) / "anchor.json"


def queue_path() -> Path:
    return store.p("anchor_queue.jsonl")


def _write_0600(path: Path, obj):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name("." + path.name + ".%d.tmp" % os.getpid())
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        os.fchmod(fh.fileno(), 0o600)
        fh.write(json.dumps(obj, sort_keys=True, indent=2) + "\n")
    os.replace(tmp, path)


def _queue(run_id: str, status: str, **kw):
    q = queue_path()
    q.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(q, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a") as fh:
        os.fchmod(fh.fileno(), 0o600)
        fh.write(json.dumps(dict(kw, run_id=run_id, status=status, ts=round(time.time(), 3)), sort_keys=True) + "\n")


def pending() -> list:
    """Run IDs whose latest queue line is not final (confirmed)."""
    last = {}
    for e in read_jsonl(queue_path()):
        last[e["run_id"]] = e["status"]
    return [r for r, s in last.items() if s not in ("confirmed", "dropped")]


class _Lock:
    """One anchor transaction at a time per var/ (hook thread, CLI post and flush in other processes): never two txs for one run."""

    def __enter__(self):
        p = store.p("anchor.lock")
        p.parent.mkdir(parents=True, exist_ok=True)
        self.fh = open(p, "a")
        fcntl.flock(self.fh, fcntl.LOCK_EX)
        return self

    def __exit__(self, *a):
        fcntl.flock(self.fh, fcntl.LOCK_UN)
        self.fh.close()


# ---------------------------------------------------------------- post

def post(run_id: str, *, rpc=None, urls=None, key=None, receipt_timeout=RECEIPT_TIMEOUT_S, poll_s=2.0, bundle=None) -> dict:
    """Anchor one run. Idempotent: a run with a tx already sent is only polled, never sent twice. Never raises for network trouble
    (the run is queued); raises ValueError only when the run has no terminal checkpoint. Returns the receipt dict."""
    rpc = rpc or jsonrpc
    urls = urls or rpcs()
    with _Lock():
        rp = receipt_path(run_id)
        rec = store.read_json(rp) if rp.exists() else None
        if rec and rec.get("status") == "confirmed":
            _copy_to_bundle(rp, bundle)
            return rec
        try:
            pk = _private_key(Path(key) if key else key_path())
        except (OSError, ValueError, ImportError) as e:
            out = dict(rec or {}, status="error", error="key:" + type(e).__name__, at=round(time.time(), 3))
            if "record" not in out:
                out["record"] = build_record(run_id)
                out["digest"] = digest(out["record"])
            _write_0600(rp, out)
            return out
        frm = address_of(pk)
        if not rec or "record" not in rec:
            record = build_record(run_id)
            rec = {"record": record, "digest": digest(record), "from": frm, "status": "pending", "tx_hash": None,
                   "block_number": None, "block_timestamp": None, "posted_at": None, "rpc": urls[0]}
        rec["from"] = frm
        if rec.get("status") != "submitted":
            rec["status"] = "pending"
        _write_0600(rp, rec)
        _queue(run_id, "pending", digest=rec["digest"])
        try:
            if not rec.get("tx_hash"):
                _send(rec, pk, rpc, urls[0])
                _write_0600(rp, rec)
            _await(rec, rpc, urls[0], receipt_timeout, poll_s)
        except Offline as e:
            rec["last_error"] = "offline:" + str(e)
        except RpcError as e:
            rec["last_error"] = "rpc:" + str(e)
        except Abort as e:
            rec["last_error"] = "abort:" + str(e)
            if not rec.get("tx_hash"):
                rec["status"] = "aborted"
        _write_0600(rp, rec)
        _queue(run_id, rec["status"], tx_hash=rec.get("tx_hash"), error=rec.get("last_error"))
        if rec["status"] == "confirmed":
            _copy_to_bundle(rp, bundle)
        return rec


def _send(rec: dict, pk, rpc, url):
    cid = _hex(rpc(url, "eth_chainId", []))
    if cid != CHAIN_ID:
        raise Abort("RPC chain ID %d is not Base mainnet (%d)" % (cid, CHAIN_ID))
    frm = address_of(pk)
    data = payload(rec["digest"])
    nonce = _hex(rpc(url, "eth_getTransactionCount", [frm, "pending"]))
    base = _hex(rpc(url, "eth_getBlockByNumber", ["latest", False])["baseFeePerGas"])
    try:
        prio = min(_hex(rpc(url, "eth_maxPriorityFeePerGas", [])), MAX_PRIORITY_FEE_WEI)
    except RpcError:
        prio = 1_000_000
    max_fee = min(2 * base + prio, MAX_FEE_PER_GAS_WEI)
    if base + prio > MAX_FEE_PER_GAS_WEI:
        raise Offline("base fee %d wei above the %d wei ceiling: retry later" % (base, MAX_FEE_PER_GAS_WEI))
    call = {"from": frm, "to": frm, "value": "0x0", "data": "0x" + data.hex()}
    gas = _hex(rpc(url, "eth_estimateGas", [call]))
    gas = gas + gas // 10
    if gas > MAX_GAS:
        raise Abort("gas estimate %d above %d" % (gas, MAX_GAS))
    raw, tx_hash = sign_tx(pk, nonce=nonce, max_priority=prio, max_fee=max_fee, gas=gas, to=frm, data=data)
    rec["cost_check"] = cost = cost_check(rpc, url, frm, raw, gas, max_fee)  # signed but not sent yet
    if not cost["ok"]:
        raise Abort(cost["message"])
    rec.update(status="submitted", tx_hash=tx_hash, nonce=nonce, gas_limit=gas, max_fee_per_gas=max_fee,
               max_priority_fee_per_gas=prio, posted_at=round(time.time(), 3), rpc=url, raw_tx="0x" + raw.hex())
    try:
        got = rpc(url, "eth_sendRawTransaction", ["0x" + raw.hex()])
    except RpcError as e:
        if "already known" not in str(e).lower():
            rec.update(status="pending", tx_hash=None, raw_tx=None)
            raise
        got = tx_hash
    if (got or "").lower() != tx_hash.lower():
        raise Abort("RPC returned tx hash %s, expected %s" % (got, tx_hash))


def l1_fee(rpc, url, raw: bytes) -> int:
    """L1 data fee quoted by Base's GasPriceOracle for these exact signed bytes (eth_call getL1Fee(bytes))."""
    sel = keccak(b"getL1Fee(bytes)")[:4]
    pad = raw + b"\x00" * (-len(raw) % 32)
    call = sel + (32).to_bytes(32, "big") + len(raw).to_bytes(32, "big") + pad
    return _hex(rpc(url, "eth_call", [{"to": GAS_PRICE_ORACLE, "data": "0x" + call.hex()}, "latest"]))


def cost_check(rpc, url, frm: str, raw: bytes, gas: int, max_fee: int) -> dict:
    """Worst-case cost = gas limit x maxFeePerGas (L2) + 1.25 x quoted L1 data fee; the balance must cover it. Fails closed."""
    try:
        l1 = l1_fee(rpc, url, raw)
    except RpcError as e:
        return {"ok": False, "message": "cannot quote the L1 data fee (%s): not sending" % e}
    bal = _hex(rpc(url, "eth_getBalance", [frm, "pending"]))
    l2 = gas * max_fee
    need = l2 + l1 * L1_FEE_MARGIN[0] // L1_FEE_MARGIN[1]
    out = {"balance_wei": bal, "l2_max_wei": l2, "l1_quote_wei": l1, "need_wei": need, "ok": bal >= need}
    out["message"] = ("balance %d wei (%.8f ETH) %s estimated worst case %d wei (%.8f ETH) = L2 gas %d x maxFee %d wei (%d wei) + 1.25 x "
                      "L1 data fee %d wei" % (bal, bal / 1e18, "covers" if out["ok"] else "is SHORT of", need, need / 1e18, gas, max_fee,
                                              l2, l1))
    return out


def _await(rec: dict, rpc, url, timeout, poll_s):
    end = time.monotonic() + timeout
    while True:
        r = rpc(url, "eth_getTransactionReceipt", [rec["tx_hash"]])
        if r:
            break
        if time.monotonic() >= end:
            if rec.get("raw_tx") and not rpc(url, "eth_getTransactionByHash", [rec["tx_hash"]]):
                try:  # dropped from the pool (or never arrived): rebroadcast the same signed bytes; same nonce, same hash
                    rpc(url, "eth_sendRawTransaction", [rec["raw_tx"]])
                except RpcError:
                    pass
            return
        time.sleep(poll_s)
    blk = rpc(url, "eth_getBlockByNumber", [r["blockNumber"], False])
    gas_used, price = _hex(r["gasUsed"]), _hex(r.get("effectiveGasPrice") or "0x0")
    l1 = _hex(r.get("l1Fee") or "0x0")
    rec.update(status="confirmed" if _hex(r["status"]) == 1 else "reverted", block_number=_hex(r["blockNumber"]),
               block_hash=r["blockHash"], block_timestamp=_hex(blk["timestamp"]), gas_used=gas_used, effective_gas_price=price,
               l1_fee_wei=l1, fee_wei=gas_used * price + l1, raw_tx=None)
    rec.pop("last_error", None)


def _copy_to_bundle(rp: Path, bundle):
    if bundle:
        dst = Path(bundle) / "anchor.json"
        shutil.copyfile(rp, dst)
        os.chmod(dst, 0o600)


def flush(**kw) -> list:
    """Post every queued run that is not yet confirmed."""
    out = []
    for rid in pending():
        try:
            r = post(rid, **kw)
            out.append({"run_id": rid, "status": r.get("status"), "tx_hash": r.get("tx_hash"), "error": r.get("last_error") or r.get("error")})
        except Exception as e:  # noqa: BLE001  (one bad run does not stop the rest)
            out.append({"run_id": rid, "status": "error", "error": type(e).__name__})
    return out


# ---------------------------------------------------------------- check

def check(bundle_dir, expected_address: str, *, rpc=None, urls=None) -> dict:
    """Fail-closed check of an exported bundle against its on-chain anchor. Returns {"exit": 0|1|2, ...}."""
    rpc = rpc or jsonrpc
    urls = urls or rpcs()
    b = Path(bundle_dir)
    res = {"ok": False, "exit": 2, "checks": [], "findings": [], "rpcs": list(urls)}

    def done(code, finding=None):
        if finding:
            res["findings"].append(finding)
        res["exit"], res["ok"] = code, code == 0
        return res

    def ok(name):
        res["checks"].append(name)

    if not (b / "anchor.json").is_file():
        return done(2, "no anchor.json in the bundle")
    try:
        anc = json.loads((b / "anchor.json").read_text())
        cp = json.loads((b / "terminal_anchor.json").read_text())
        pub = (b / "broker_public_key.b64").read_text().strip()
        record = anc["record"]
    except (OSError, ValueError, KeyError, TypeError) as e:
        return done(1, "bundle or anchor.json unreadable: %s" % type(e).__name__)
    try:
        expected_record = record_from_checkpoint(cp, pub, record.get("nonce"))
    except (ValueError, KeyError, TypeError, AttributeError):
        return done(1, "terminal_anchor.json is not a terminal checkpoint")
    if sorted(record) != sorted(RECORD_KEYS) or record != expected_record:
        bad = sorted(k for k in RECORD_KEYS if record.get(k) != expected_record.get(k))
        return done(1, "anchor record does not match the bundle's terminal checkpoint (%s)" % ", ".join(bad or ["keys"]))
    ok("record matches terminal_anchor.json + broker_public_key.b64")
    dig = digest(record)
    if anc.get("digest") != dig:
        return done(1, "anchor.json digest differs from the recomputed digest")
    ok("digest recomputed")
    v = verify(read_jsonl(b / "audit.jsonl"), read_jsonl(b / "reviewer_checkpoints.jsonl"), record["pubkey_b64"],
               run_id=cp["run_id"], expected_state=record["state"], anchor=cp, expected_terminal_hash=record["terminal_hash"])
    if not v["ok"]:
        res["audit_findings"] = [f.get("issue") for f in v["findings"]][:5]
        return done(1, "audit log does not verify against the anchored terminal checkpoint")
    ok("audit chain + signed checkpoints verify against the anchored terminal hash")
    txh = anc.get("tx_hash")
    res["tx_hash"] = txh
    if not txh:
        return done(2, "anchor is %s: no transaction yet" % anc.get("status"))
    want_data = "0x" + payload(dig).hex()
    seen = []
    for url in urls:
        try:
            cid = _hex(rpc(url, "eth_chainId", []))
            tx = rpc(url, "eth_getTransactionByHash", [txh])
            rc = rpc(url, "eth_getTransactionReceipt", [txh])
            head = _hex(rpc(url, "eth_blockNumber", []))
        except (Offline, RpcError) as e:
            return done(2, "RPC %s unreachable or failing (%s)" % (url, e))
        if cid != CHAIN_ID:
            return done(1, "RPC %s is on chain %d, not %d" % (url, cid, CHAIN_ID))
        if not tx or not rc:
            return done(2, "transaction %s not (yet) mined according to %s" % (txh, url))
        frm, to = (tx.get("from") or "").lower(), (tx.get("to") or "").lower()
        if frm != expected_address.lower():
            return done(1, "sender %s is not the pinned anchor address" % tx.get("from"))
        if to != frm:
            return done(1, "transaction is not to the sender itself")
        if (tx.get("input") or tx.get("data") or "").lower() != want_data:
            return done(1, "on-chain data differs from prefix + recomputed digest")
        if _hex(tx.get("chainId") or "0x0") != CHAIN_ID:
            return done(1, "transaction chainId is not %d" % CHAIN_ID)
        if _hex(tx.get("value") or "0x0") != 0:
            return done(1, "transaction value is not 0")
        if _hex(rc.get("status") or "0x0") != 1:
            return done(1, "transaction failed on-chain (status 0)")
        bn = _hex(rc["blockNumber"])
        if head - bn + 1 < 1:
            return done(2, "fewer than 1 confirmation")
        blk = rpc(url, "eth_getBlockByNumber", [rc["blockNumber"], False])
        seen.append((bn, rc.get("blockHash"), _hex(blk["timestamp"]), head - bn + 1))
    if len({s[:3] for s in seen}) != 1:
        return done(1, "RPCs disagree about the transaction's block: %s" % [s[:2] for s in seen])
    ok("on-chain: from pinned, to self, data = prefix + digest, status 1, chain 8453, >= 1 confirmation"
       + (", %d RPCs agree" % len(seen) if len(seen) > 1 else " (single RPC trusted)"))
    bn, bh, ts, conf = seen[0]
    res.update(block_number=bn, block_hash=bh, block_timestamp=ts, confirmations=min(s[3] for s in seen),
               block_time_utc=time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts)),
               minutes_after_terminal_checkpoint=round((ts - float(cp["ts"])) / 60.0, 2), state=record["state"],
               terminal_hash=record["terminal_hash"])
    return done(0)


def demo_report(run_id: str, bundle, timeout=RECEIPT_TIMEOUT_S + 30) -> dict:
    """For the playground and try_jailbreak (flag ON only): wait for the hook's post, copy anchor.json into the exported bundle and check
    it against the pinned address (AEGIS_ANCHOR_ADDRESS, else the address of the configured key). Sends nothing itself."""
    wait_all(timeout)
    rp = receipt_path(run_id)
    rec = store.read_json(rp) if rp.exists() else None
    if not rec:
        return {"line": "Base anchor: no receipt yet (the run is unaffected)", "exit": 2}
    if rec.get("status") != "confirmed":
        return {"line": "Base anchor %s (%s); the run is unaffected" % (rec.get("status"), rec.get("last_error") or rec.get("error") or "no tx yet"),
                "exit": 2, "status": rec.get("status")}
    _copy_to_bundle(rp, bundle)
    try:
        pinned = (os.environ.get("AEGIS_ANCHOR_ADDRESS") or "").strip() or address_of(_private_key(key_path()))
    except (OSError, ValueError, ImportError):
        return {"line": "anchored on Base: block %s, tx %s…, check not run (no pinned address)" % (rec["block_number"], rec["tx_hash"][:10]), "exit": 2}
    res = check(bundle, pinned)
    return {"line": "anchored on Base: block %s, tx %s…, check exit %d" % (rec["block_number"], rec["tx_hash"][:10], res["exit"]),
            "exit": res["exit"], "pinned": pinned, "tx_hash": rec["tx_hash"], "block_number": rec["block_number"], "fee_wei": rec.get("fee_wei"),
            "findings": res["findings"]}


# ---------------------------------------------------------------- hook

def _post_quietly(run_id, var=None):
    try:
        if var is not None and store.VAR != var:  # the state directory changed under us (tests): never write elsewhere
            return
        post(run_id)
    except Exception:  # noqa: BLE001  (an anchor failure never reaches the run)
        pass


def _wrap(orig):
    def terminal_checkpoint(self, state):
        cp = orig(self, state)
        t = threading.Thread(target=_post_quietly, args=(self.id, store.VAR), name="anchor-" + self.id, daemon=True)
        _threads.append(t)
        t.start()
        return cp
    terminal_checkpoint.__doc__ = orig.__doc__
    return terminal_checkpoint


def install():
    """Wrap runs.Run.terminal_checkpoint once (idempotent). The original runs unchanged; the post happens afterwards, in a thread."""
    global _orig_terminal
    if _orig_terminal is not None:
        return
    from . import runs
    _orig_terminal = runs.Run.terminal_checkpoint
    runs.Run.terminal_checkpoint = _wrap(_orig_terminal)


def installed() -> bool:
    return _orig_terminal is not None


def wait_all(timeout=RECEIPT_TIMEOUT_S + 30):
    end = time.monotonic() + timeout
    for t in list(_threads):
        t.join(max(0.0, end - time.monotonic()))


# ---------------------------------------------------------------- CLI

def _summary(rec: dict) -> dict:
    keep = ("status", "tx_hash", "from", "block_number", "block_timestamp", "gas_used", "effective_gas_price", "l1_fee_wei", "fee_wei",
            "digest", "last_error", "error", "rpc")
    return {k: rec.get(k) for k in keep if rec.get(k) is not None}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m aegis.anchor", description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("keygen", help="create the anchor wallet key (refuses to overwrite); prints only the address")
    sub.add_parser("address", help="print the anchor wallet address")
    p = sub.add_parser("post", help="anchor one run's terminal checkpoint (idempotent)")
    p.add_argument("--run-id", required=True)
    p.add_argument("--bundle", help="also copy anchor.json into this exported bundle directory")
    sub.add_parser("flush", help="post every queued run")
    c = sub.add_parser("check", help="check an exported bundle against its on-chain anchor")
    c.add_argument("--bundle", required=True)
    c.add_argument("--address", required=True, help="the anchor wallet address, pinned out of band")
    a = ap.parse_args(argv)
    if a.cmd == "keygen":
        try:
            print(keygen(key_path()))
        except FileExistsError:
            print("refusing to overwrite the existing key at %s" % key_path(), file=sys.stderr)
            return 1
        return 0
    if a.cmd == "address":
        print(address_of(_private_key(key_path())))
        return 0
    if a.cmd == "post":
        rec = post(a.run_id, bundle=a.bundle)
        print(json.dumps(_summary(rec), indent=2, sort_keys=True))
        return 0 if rec.get("status") == "confirmed" else 2
    if a.cmd == "flush":
        out = flush()
        print(json.dumps(out, indent=2, sort_keys=True))
        return 0 if all(o.get("status") == "confirmed" for o in out) else 2
    res = check(a.bundle, a.address)
    print(json.dumps(res, indent=2, sort_keys=True))
    return res["exit"]


if __name__ == "__main__":
    sys.exit(main())
