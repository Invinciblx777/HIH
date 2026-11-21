"""Finale P19: "Aegis Chat", a chat with the local model where Aegis Guard always sits between the user and the model.
LOCAL real-model console only, behind the same gate as the playground (AEGIS_PLAYGROUND=1, operator session, CSRF on writes,
never a role token, never the public demo: the public demo refuses every POST/DELETE that is not a bundle verify/tamper).

Every message is one real broker run (create_run / freeze / start with a 1-entry pack, deadline 4000 ms):
user -> broker -> Aegis Guard input check (regex + input hardening + Qwen3Guard, guard_mode "both", guard_harden on, guard_max_chars 1000) -> model
(only if allowed) -> output check + canary scan -> broker -> user. The payload is the last 3 turns plus the new message, capped
at 1000 characters (oldest text dropped first), so the guard judges the whole conversation.
The reply is the run's final_output and nothing else: no model_output, no regex-only comparison. Blocked: the uniform refusal.
"Aegis Guard" = regex rules + input hardening + Qwen3Guard-Gen-0.6B (Qwen, Apache-2.0), run in its own sandbox.

POST /api/lab/chat {"session"?, "message"} -> {"session", "title", "reply": {...}}; GET /api/lab/chat/sessions;
GET /api/lab/chat/sessions/{id}; DELETE /api/lab/chat/sessions/{id}. One message in flight per session (409 otherwise).
Sessions: JSON per session under the console's var dir (var/.../chat/<id>.json).
"""
import json
import re
import secrets
import tempfile
import threading
import time
from pathlib import Path

from fastapi import Header, HTTPException, Request

from . import runs, store

DEADLINE_MS = 4000
MAX_PAYLOAD = 1000
TURNS = 3
TITLE_LEN = 48
_SID = re.compile(r"[a-f0-9]{16}")
_SAFE_RID = re.compile(r"CHAT-\d{3,6}-G")
MAX_MESSAGE = 8000  # a single message over MAX_PAYLOAD is sent whole; the guard (guard_max_chars = MAX_PAYLOAD) refuses it unscanned: never cut and passed
_lock = threading.Lock()
_inflight = set()
_run_lock = threading.Lock()  # one broker run at a time across chats (run ids and the one model)


def _dir():
    d = store.p("chat")
    d.mkdir(parents=True, exist_ok=True)
    return d


def _path(sid):
    if not _SID.fullmatch(sid or ""):
        raise HTTPException(404, "no such chat")
    return _dir() / (sid + ".json")


def load(sid):
    p = _path(sid)
    s = store.read_json(p, None)
    if not isinstance(s, dict):
        raise HTTPException(404, "no such chat")
    return s


def save(s):
    _path(s["id"]).write_text(json.dumps(s, ensure_ascii=False))


def new_session():
    s = {"id": secrets.token_hex(8), "title": "New chat", "created": time.time(), "messages": []}
    save(s)
    return s


def sessions():
    out = []
    for f in _dir().glob("*.json"):
        s = store.read_json(f, None)
        if isinstance(s, dict) and _SID.fullmatch(str(s.get("id", ""))):
            out.append({"id": s["id"], "title": s.get("title") or "New chat", "created": s.get("created"), "n": len(s.get("messages") or [])})
    return sorted(out, key=lambda x: x.get("created") or 0, reverse=True)


def build_payload(history, message):
    """The last TURNS exchanges plus the new message, newest last, capped at MAX_PAYLOAD characters (oldest text dropped)."""
    lines = []
    for m in (history or [])[-2 * TURNS:]:
        lines.append(("User: " if m.get("role") == "user" else "Assistant: ") + str(m.get("text", "")))
    if len(message) > MAX_PAYLOAD:  # sent whole, no context: the guard judges it or refuses it (fail closed), never cut and passed
        return message
    tail = "User: " + message if lines else message
    out = "\n".join(lines + [tail])
    if len(out) > MAX_PAYLOAD:
        out = out[-MAX_PAYLOAD:]
    return out


GUARD_ERR = {"guard_timeout": "guard timeout", "guard_text_too_long": "guard length limit"}
LAYERS = ("regex", "input hardening", "Qwen3Guard", "output check", "canary scan", "guard timeout", "guard length limit",
          "guard unavailable", "time limit")


def _num(v):
    return round(float(v), 1) if isinstance(v, (int, float)) and not isinstance(v, bool) else None


def decision(a):
    """(layer, category) for a run's sealed artifact. layer is one of LAYERS, or None when the answer was released.
    category is the badge text after "blocked · ". Never the bare word "deadline": a time-out is named as what it is."""
    vin = a.get("verdict_in") or {}
    g = vin.get("guard") or {}
    rx = vin.get("regex") if isinstance(vin.get("regex"), dict) else (None if g else vin)
    fo = a.get("final_output")
    if vin.get("verdict") == "block":
        if rx and rx.get("verdict") == "block":
            rule = rx.get("rule")
            if rx.get("error"):
                return "regex", "input rule time budget (fail-closed)"
            if isinstance(rule, str) and not rule.startswith("base:"):
                return "input hardening", "input hardening rule"
            return "regex", "input rule"
        err = g.get("error")
        if err:
            layer = GUARD_ERR.get(err, "guard unavailable")
            return layer, layer + " (fail-closed)"
        cats = g.get("categories") or []
        cats = cats if isinstance(cats, list) else [str(cats)]
        return "Qwen3Guard", ", ".join(map(str, cats)) or str(g.get("safety") or "Unsafe")
    if a.get("canary_leaks"):
        return "canary scan", "canary leak withheld"
    if (a.get("verdict_out") or {}).get("verdict") == "block":
        return "output check", "output check"
    if (a.get("release") or {}).get("cut_off"):
        return "time limit", "checks not finished in time (fail-closed)"
    if not isinstance(fo, str) or fo.strip().rstrip(".") == runs.UNIFORM_REFUSAL.rstrip("."):
        return "time limit" if fo is None else "output check", "refused (fail-closed)"
    return None, None


def category(a):
    return decision(a)[1]


def _count(path):
    try:
        return sum(1 for l in Path(path).read_text().splitlines() if l.strip())
    except OSError:
        return 0


def ops(a, run_dir=None):
    """The operator view of one message, from the run's sealed data only. Timings and verdicts; never model text."""
    vin = a.get("verdict_in") or {}
    g = vin.get("guard") or {}
    rx = vin.get("regex") if isinstance(vin.get("regex"), dict) else {}
    din, gms, mms, cms = _num(a.get("defence_in_ms")), _num(g.get("ms")), _num(a.get("model_ms")), _num(a.get("compute_ms"))
    called = mms is not None and vin.get("verdict") == "allow"
    rel = a.get("release") or {}
    released = _num(a.get("answered_ms"))
    layer, cat = decision(a)
    out_ms = round(cms - din - mms, 1) if called and None not in (cms, din, mms) else None
    hv = (rx.get("harden") or {}) if isinstance(rx.get("harden"), dict) else {}
    cats = g.get("categories") or []
    return {"layer": layer, "category": cat,
            "guard": {"safety": g.get("safety"), "categories": cats if isinstance(cats, list) else [str(cats)], "ms": gms,
                      "error": g.get("error"), "view_checked": bool(g.get("view_checked"))},
            "regex_rule": rx.get("rule") if isinstance(rx.get("rule"), (str, int)) else None,
            "harden_techniques": [str(t) for t in (hv.get("techniques") or [])][:8],
            "input_ms": din, "model_ms": mms if called else None, "model_called": called, "output_ms": out_ms,
            "internal_ms": cms, "released_ms": released, "deadline_ms": rel.get("deadline_ms", DEADLINE_MS),
            "padding_ms": round(released - cms, 1) if None not in (released, cms) else None,
            "cut_off": bool(rel.get("cut_off")), "overrun": bool(released is not None and released > (rel.get("deadline_ms") or DEADLINE_MS) + 50),
            "canary_hits": len(a.get("canary_leaks") or []),
            "audit_entries": _count(Path(run_dir) / "audit.jsonl") if run_dir else 0,
            "audit_signed": _count(Path(run_dir) / "checkpoints.jsonl") > 0 if run_dir else False}


def _pct(xs, q):
    xs = sorted(xs)
    if not xs:
        return None
    k = max(0, min(len(xs) - 1, -(-q * len(xs) // 100) - 1))  # nearest rank
    return round(xs[int(k)], 1)


def stats(messages):
    """Session stats from the stored replies: counts, blocked by layer, guard latency p50/p95 (nearest rank), overruns, leaks."""
    reps = [m for m in (messages or []) if m.get("role") == "assistant"]
    blocked = [m for m in reps if m.get("verdict") == "blocked"]
    by = {}
    for m in blocked:
        k = (m.get("ops") or {}).get("layer") or "unknown"
        by[k] = by.get(k, 0) + 1
    gms = [m["ops"]["guard"]["ms"] for m in reps if isinstance(((m.get("ops") or {}).get("guard") or {}).get("ms"), (int, float))
           and m["ops"]["guard"].get("error") != "guard_text_too_long"]  # refused unscanned: no guard call to time
    return {"messages": len(reps), "allowed": len(reps) - len(blocked), "blocked": len(blocked), "blocked_by_layer": by,
            "guard_p50_ms": _pct(gms, 50), "guard_p95_ms": _pct(gms, 95), "guard_n": len(gms),
            "overruns": sum(1 for m in reps if (m.get("ops") or {}).get("overrun")),
            "canary_leaks": sum((m.get("ops") or {}).get("canary_hits") or 0 for m in reps)}


def reply_from(a, rid, run_dir=None):
    """The ONLY fields a chat reply carries. Never model_output (nor any model text other than the released final_output)."""
    fo = a.get("final_output")
    if not isinstance(fo, str):
        fo = runs.UNIFORM_REFUSAL
    o = ops(a, run_dir)
    blocked = fo == runs.UNIFORM_REFUSAL or o["layer"] is not None
    if blocked:
        fo = runs.UNIFORM_REFUSAL
    ms = a.get("answered_ms")
    return {"text": fo, "verdict": "blocked" if blocked else "allowed", "category": (o["category"] or "refused") if blocked else None,
            "released_ms": round(ms) if isinstance(ms, (int, float)) else None, "run_id": rid, "ops": o}


def run_message(payload):
    """One real broker run with a 1-entry pack; returns the sealed artifact for the entry (or {} if the run failed)."""
    from llm_isolation import make_pack  # evaluation/ (playground.register puts it on sys.path)
    from . import playground
    with _run_lock:
        return _run_locked(payload, playground, make_pack)


def _run_locked(payload, playground, make_pack):
    rid = playground._next_id("CHAT")
    work = Path(tempfile.mkdtemp(prefix="aegis-chat-"))
    try:
        make_pack(work / "pack.json", [{"id": "M1", "category": "chat message", "payload": payload}])
        base = json.loads((playground.ROOT / "samples/defence_config.json").read_text())
        dc = work / "defence.json"
        dc.write_text(json.dumps(dict(base, guard_mode="both", guard_harden=True, guard_max_chars=MAX_PAYLOAD)))
        rid = rid + "-G"
        runs.create_run(rid, attack_pack=str(work / "pack.json"), defence_config=str(dc), timing_deadline_ms=DEADLINE_MS)
        runs.freeze(rid)
        runs.start(rid, wait=True)
        arts = [x for x in playground._jsonl(runs.Run(rid).dir / "sealed/artifacts.jsonl") if x.get("attack_id") == "M1"]
        return (arts[-1] if arts else {}), rid
    finally:
        import shutil
        shutil.rmtree(work, ignore_errors=True)


def register(app, authorize, gate):
    """Routes, added by playground.register (same gate: AEGIS_PLAYGROUND=1, operator session, never the public demo)."""

    @app.get("/api/lab/chat/sessions")
    def chat_list(request: Request, x_aegis_token: str = Header(None)):
        gate(request, authorize, x_aegis_token)
        return {"sessions": sessions()}

    @app.get("/api/lab/chat/sessions/{sid}")
    def chat_get(sid: str, request: Request, x_aegis_token: str = Header(None)):
        gate(request, authorize, x_aegis_token)
        s = load(sid)
        return dict(s, stats=stats(s.get("messages")))

    @app.delete("/api/lab/chat/sessions/{sid}")
    def chat_delete(sid: str, request: Request, x_aegis_token: str = Header(None)):
        gate(request, authorize, x_aegis_token)
        p = _path(sid)
        with _lock:
            if sid in _inflight:
                raise HTTPException(409, "a message is still being checked in this chat")
            if not p.exists():
                raise HTTPException(404, "no such chat")
            p.unlink()
        return {"deleted": sid}

    @app.post("/api/lab/chat")
    async def chat_send(request: Request, x_aegis_token: str = Header(None)):
        gate(request, authorize, x_aegis_token)
        try:
            body = await request.json()
        except ValueError:
            raise HTTPException(400, "JSON body required")
        body = body if isinstance(body, dict) else {}
        msg = str(body.get("message") or "").strip()
        if not 1 <= len(msg) <= MAX_MESSAGE:
            raise HTTPException(400, "message must be 1-%d characters" % MAX_MESSAGE)
        sid = body.get("session")
        s = load(str(sid)) if sid else new_session()
        with _lock:
            if s["id"] in _inflight:
                raise HTTPException(409, "one message at a time: Aegis Guard is still checking the last one")
            _inflight.add(s["id"])
        try:
            payload = build_payload(s.get("messages"), msg)
            import asyncio
            a, rid = await asyncio.to_thread(run_message, payload)
            rep = reply_from(a, rid, runs.Run(rid).dir if _SAFE_RID.fullmatch(str(rid)) else None)
            s = load(s["id"])
            if not s.get("messages"):
                s["title"] = msg[:TITLE_LEN] + ("…" if len(msg) > TITLE_LEN else "")
            s["messages"] = (s.get("messages") or []) + [{"role": "user", "text": msg, "t": time.time()},
                                                         dict(rep, role="assistant", t=time.time())]
            save(s)
            return {"session": s["id"], "title": s["title"], "reply": rep, "stats": stats(s["messages"])}
        finally:
            with _lock:
                _inflight.discard(s["id"])
