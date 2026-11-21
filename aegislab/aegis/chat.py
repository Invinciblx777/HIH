"""Finale P19: "Aegis Chat", a chat with the local model where Aegis Guard always sits between the user and the model.
LOCAL real-model console only, behind the same gate as the playground (AEGIS_PLAYGROUND=1, operator session, CSRF on writes,
never a role token, never the public demo: the public demo refuses every POST/DELETE that is not a bundle verify/tamper).

Every message is one real broker run (create_run / freeze / start with a 1-entry pack, deadline 4000 ms):
user -> broker -> Aegis Guard input check (regex + input hardening + Qwen3Guard, guard_mode "both", guard_harden on) -> model
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
    tail = "User: " + message if lines else message
    out = "\n".join(lines + [tail])
    if len(out) > MAX_PAYLOAD:
        out = out[-MAX_PAYLOAD:]
    return out


def category(a):
    """A short reason for a blocked reply, from the run's sealed artifact (no text of the prompt or the model)."""
    vin = a.get("verdict_in") or {}
    g = vin.get("guard") or {}
    rx = vin.get("regex") if isinstance(vin.get("regex"), dict) else (None if g else vin)
    if vin.get("verdict") == "block":
        if rx and rx.get("verdict") == "block":
            return "input rule"
        if g.get("error"):
            return "guard unavailable (fail closed)"
        cats = g.get("categories") or []
        cats = cats if isinstance(cats, list) else [str(cats)]
        return ", ".join(map(str, cats)) or ("input " + str(g.get("safety") or "unsafe")).lower()
    if a.get("canary_leaks"):
        return "canary leak"
    if (a.get("verdict_out") or {}).get("verdict") == "block":
        return "output check"
    if (a.get("release") or {}).get("cut_off"):
        return "deadline"
    return "refused"


def reply_from(a, rid):
    """The ONLY fields a chat reply carries. Never model_output."""
    fo = a.get("final_output")
    if not isinstance(fo, str):
        fo = runs.UNIFORM_REFUSAL
    blocked = fo == runs.UNIFORM_REFUSAL
    ms = a.get("answered_ms")
    return {"text": fo, "verdict": "blocked" if blocked else "allowed", "category": category(a) if blocked else None,
            "released_ms": round(ms) if isinstance(ms, (int, float)) else None, "run_id": rid}


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
        dc.write_text(json.dumps(dict(base, guard_mode="both", guard_harden=True)))
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
        return load(sid)

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
        if not 1 <= len(msg) <= MAX_PAYLOAD:
            raise HTTPException(400, "message must be 1-%d characters" % MAX_PAYLOAD)
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
            rep = reply_from(a, rid)
            s = load(s["id"])
            if not s.get("messages"):
                s["title"] = msg[:TITLE_LEN] + ("…" if len(msg) > TITLE_LEN else "")
            s["messages"] = (s.get("messages") or []) + [{"role": "user", "text": msg, "t": time.time()},
                                                         dict(rep, role="assistant", t=time.time())]
            save(s)
            return {"session": s["id"], "title": s["title"], "reply": rep}
        finally:
            with _lock:
                _inflight.discard(s["id"])
