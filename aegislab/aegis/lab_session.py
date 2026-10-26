"""Operator session for the local prototype console (Phase R2).

The browser never receives a role token. Instead, the person who launched the console proves it once with a launch code
that only the launcher prints (and that is stored mode 0600 in the state directory). The console then sets an opaque
session cookie (HttpOnly, SameSite=Strict, path /) and gives the page a per-session CSRF token. Every state-changing lab
request needs the cookie, the CSRF token in the X-Aegis-CSRF header, and a same-origin Origin / Sec-Fetch-Site.

What a session is: the single local operator of this console. Inside that session the console drives the demonstration
roles (operator, reviewer, blue and red participant) server-side, with the control plane's own tokens, through the
unchanged role checks. It is not multi-user authentication: everybody who holds the launch link is that one operator.
"""
import hmac
import os
import secrets
import threading
import time

from . import store

COOKIE = "aegis_console"
CSRF_HEADER = "x-aegis-csrf"
SESSION_TTL_S = 8 * 3600       # absolute lifetime
IDLE_TTL_S = 2 * 3600          # idle lifetime
MAX_SESSIONS = 16
MAX_FAILURES = 20              # wrong launch codes before a lockout
LOCKOUT_S = 60

_lock = threading.Lock()
_sessions = {}                 # sid -> {"csrf", "created", "seen"}
_failures = {"n": 0, "until": 0.0}
_code = {"value": None, "var": None}


def launch_code() -> str:
    """The launch code for this state directory: AEGIS_CONSOLE_LAUNCH_CODE when the launcher set one, otherwise a random
    code written once to $AEGIS_VAR/console/launch_code (mode 0600)."""
    with _lock:
        if _code["value"] and _code["var"] == str(store.VAR):
            return _code["value"]
        env = os.environ.get("AEGIS_CONSOLE_LAUNCH_CODE", "")
        if len(env) >= 20:
            value = env
        else:
            path = store.p("console", "launch_code")
            path.parent.mkdir(parents=True, exist_ok=True)
            try:
                value = path.read_text().strip()
            except FileNotFoundError:
                value = ""
            if len(value) < 20:
                value = secrets.token_urlsafe(24)
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w") as fh:
                    fh.write(value + "\n")
        _code.update(value=value, var=str(store.VAR))
        return value


def start(code: str):
    """Exchange the launch code for a new session id, or return (None, reason)."""
    now = time.time()
    with _lock:
        if now < _failures["until"]:
            return None, "too many wrong launch codes; wait a minute"
    if not code or not hmac.compare_digest(code.encode(), launch_code().encode()):
        with _lock:
            _failures["n"] += 1
            if _failures["n"] >= MAX_FAILURES:
                _failures.update(n=0, until=now + LOCKOUT_S)
        return None, "invalid launch code"
    with _lock:
        _failures["n"] = 0
        _expire(now)
        while len(_sessions) >= MAX_SESSIONS:
            del _sessions[min(_sessions, key=lambda s: _sessions[s]["seen"])]
        sid = secrets.token_urlsafe(32)
        _sessions[sid] = {"csrf": secrets.token_urlsafe(24), "created": now, "seen": now}
    return sid, None


def _expire(now):
    for sid in [s for s, v in _sessions.items() if now - v["created"] > SESSION_TTL_S or now - v["seen"] > IDLE_TTL_S]:
        del _sessions[sid]


def get(sid):
    """The session for a cookie value, or None. Refreshes the idle timer."""
    if not sid:
        return None
    now = time.time()
    with _lock:
        _expire(now)
        for key, sess in _sessions.items():  # constant-time comparison against every live session id
            if hmac.compare_digest(key.encode(), sid.encode()):
                sess["seen"] = now
                return dict(sess, expires_at=min(sess["created"] + SESSION_TTL_S, now + IDLE_TTL_S))
    return None


def csrf_ok(sess, header) -> bool:
    return bool(sess and header and hmac.compare_digest(sess["csrf"].encode(), header.encode()))


def end(sid):
    with _lock:
        _sessions.pop(sid, None)


def reset():
    """Forget every session and the cached code (tests, state-directory change)."""
    with _lock:
        _sessions.clear()
        _failures.update(n=0, until=0.0)
        _code.update(value=None, var=None)
