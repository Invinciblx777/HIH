"""Operator session for the local prototype console (Phase R2).

The browser never receives a role token. Instead, the person who launched the console proves it once with a launch code
that only the launcher prints (and that is stored mode 0600 in the state directory). The console then sets an opaque
session cookie (HttpOnly, SameSite=Strict, path /) and gives the page a per-session CSRF token. Every state-changing lab
request needs the cookie, the CSRF token in the X-Aegis-CSRF header, and a same-origin Origin / Sec-Fetch-Site.

Phase R3: the launch code is single-use and short-lived. A successful exchange replaces it at once with a fresh code (written
to the same file, mode 0600) that nobody has seen, so the link left in browser history, terminal scroll-back or a screen
recording cannot start a second session. An unused code expires after LAUNCH_TTL_S. `scripts/start_prototype.sh --link`
prints a link with a fresh code for a console that is already running. Starting a session ends the session the browser
already held (no fixation: the server always picks the session id).

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
LAUNCH_TTL_S = 2 * 3600        # an unused launch code expires
MAX_SESSIONS = 16
MAX_FAILURES = 20              # wrong launch codes before a lockout
LOCKOUT_S = 60

_lock = threading.Lock()
_sessions = {}                 # sid -> {"csrf", "created", "seen"}
_failures = {"n": 0, "until": 0.0}
_env_adopted = set()           # state directories whose AEGIS_CONSOLE_LAUNCH_CODE was already taken over (it is single-use too)


def _code_file():
    return store.p("console", "launch_code")


def _write_code(value):
    """Replace the code file atomically (mode 0600). Its modification time is the code's issue time."""
    path = _code_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(".launch_code.%s.tmp" % secrets.token_hex(4))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(value + "\n")
    os.replace(tmp, path)


def _current(now):
    """(code, issued_at) from the file, or (None, None) when there is no usable code. Caller holds _lock."""
    var = str(store.VAR)
    env = os.environ.get("AEGIS_CONSOLE_LAUNCH_CODE", "")
    if var not in _env_adopted:
        _env_adopted.add(var)
        if len(env) >= 20:  # the launcher's code becomes the current code once; after use it is replaced like any other
            _write_code(env)
    try:
        path = _code_file()
        value, issued = path.read_text().strip(), path.stat().st_mtime
    except FileNotFoundError:
        return None, None
    return (value, issued) if len(value) >= 20 else (None, None)


def issue() -> str:
    """Write a fresh launch code (replacing any previous one) and return it."""
    with _lock:
        _current(time.time())  # an unadopted launcher code must not resurface after this one
        value = secrets.token_urlsafe(24)
        _write_code(value)
        return value


def launch_code() -> str:
    """The current unused launch code for this state directory, issuing a new one if there is none or it expired.
    The file $AEGIS_VAR/console/launch_code (mode 0600) always holds the code that works now; the launcher writes it with
    issue(). AEGIS_CONSOLE_LAUNCH_CODE, if set (manual starts, tests), is taken over once per process and state directory,
    so a process started again with the same environment value would accept that value once more."""
    now = time.time()
    with _lock:
        value, issued = _current(now)
        if value and now - issued <= LAUNCH_TTL_S:
            return value
        value = secrets.token_urlsafe(24)
        _write_code(value)
        return value


def start(code: str):
    """Exchange the launch code for a new session id, or return (None, reason). The code is consumed: it is replaced by a
    fresh one in the same critical section, so two requests with the same code cannot both succeed."""
    now = time.time()
    with _lock:
        if now < _failures["until"]:
            return None, "too many wrong launch codes; wait a minute"
        value, issued = _current(now)
        good = bool(code and value and hmac.compare_digest(code.encode(), value.encode()))
        if good and now - issued > LAUNCH_TTL_S:
            return None, "this launch code expired; print a new link with scripts/start_prototype.sh --link"
        if not good:
            _failures["n"] += 1
            if _failures["n"] >= MAX_FAILURES:
                _failures.update(n=0, until=now + LOCKOUT_S)
            return None, "invalid or already used launch code"
        _write_code(secrets.token_urlsafe(24))  # single use
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
    if not sid:
        return
    with _lock:
        for key in [k for k in _sessions if hmac.compare_digest(k.encode(), sid.encode())]:
            del _sessions[key]


def reset():
    """Forget every session and the failure counter (tests, state-directory change)."""
    with _lock:
        _sessions.clear()
        _failures.update(n=0, until=0.0)
        _env_adopted.clear()
