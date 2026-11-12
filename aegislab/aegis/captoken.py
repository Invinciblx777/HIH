"""Finale P4, SHOULD 6: signed, expiring capability tokens scoped to one run, one role and a list of operations.

Before P4 the API knew only the four global role tokens (var/keys/tokens.json): a red participant's token worked on every
run, forever. A capability token narrows that. It is

    aegcap1.<base64url(canonical JSON claims)>.<base64url(Ed25519 signature)>

with claims {"v": 1, "run": run id, "role": role, "ops": [operations], "iat": issued, "exp": expiry, "jti": random id}.
It is signed with its own key, var/keys/capability_ed25519.pem, never with the evidence key (broker_ed25519.pem): a
leaked or misused capability key can mint API access but cannot forge an audit checkpoint, and the evidence key never
signs anything a client chose. Both keys are 0600 files in var/keys, which runtime._check_mounts refuses to mount into any
container.

Rules (enforced by issue() and verify(), tested in tests/test_finale_p4_captoken.py):
  * ops must be a subset of what the role may do (ROLE_OPS); a token can only narrow a role, never widen it;
  * lifetime at most MAX_TTL_S (1 h), at least 1 s; expired tokens are refused (no clock skew allowance);
  * a token is accepted only on its own run and only for the operations it lists;
  * issuance needs a global role token, not a capability token (no delegation chains). The operator may issue tokens for
    operator and the two participants; only the reviewer may issue reviewer tokens (the operator cannot mint the right to
    release). Every issuance is an audit entry (capability.issued) with jti, role, ops and expiry, never the token.
  * Revocation is by expiry only, or for all tokens at once by replacing the capability key (Future: a revocation list).
"""
import base64
import json
import secrets
import time

from . import store
from .crypto import Signer, canonical, verify_signature

PREFIX = "aegcap1."
MAX_TTL_S = 3600
ROLE_OPS = {
    "operator": ("detail", "events", "freeze", "start", "defence_config", "tamper_test"),
    "reviewer": ("detail", "events", "release", "artifacts", "evidence", "tamper_test"),
    "blue_participant": ("detail", "events", "defence_config", "artifacts", "evidence"),
    "red_participant": ("detail", "events", "artifacts", "evidence"),
}
ISSUERS = {"operator": ("operator", "blue_participant", "red_participant"), "reviewer": ("reviewer",)}
_signers = {}


class CapabilityError(Exception):
    """status: 401 (not a valid token) or 403 (valid, but not for this run or operation)."""

    def __init__(self, status, msg):
        super().__init__(msg)
        self.status = status


def signer() -> Signer:
    """The capability key (created on first use, 0600, next to but separate from the evidence key)."""
    path = store.p("keys", "capability_ed25519.pem")
    if path not in _signers:
        _signers[path] = Signer(path)
    return _signers[path]


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def is_capability(token) -> bool:
    return isinstance(token, str) and token.startswith(PREFIX)


def issue(issuer_role: str, run_id: str, role: str, ops, ttl_s: int, now=None) -> tuple:
    """(token, claims). ValueError on a request the rules above refuse."""
    if role not in ISSUERS.get(issuer_role, ()):
        raise ValueError("role '%s' may not issue capabilities for role '%s'" % (issuer_role, role))
    ops = sorted(set(ops or ()))
    if not ops or not set(ops) <= set(ROLE_OPS[role]):
        raise ValueError("ops must be a non-empty subset of %s" % ", ".join(ROLE_OPS[role]))
    if not isinstance(ttl_s, int) or isinstance(ttl_s, bool) or not 1 <= ttl_s <= MAX_TTL_S:
        raise ValueError("ttl_s must be between 1 and %d seconds" % MAX_TTL_S)
    now = int(time.time() if now is None else now)
    claims = {"v": 1, "run": run_id, "role": role, "ops": ops, "iat": now, "exp": now + ttl_s, "jti": secrets.token_hex(12)}
    sig = base64.b64decode(signer().sign(claims))
    return PREFIX + _b64(canonical(claims)) + "." + _b64(sig), claims


def verify(token: str, run_id: str, op: str, now=None) -> dict:
    """The claims of a valid token for this run and operation; CapabilityError otherwise."""
    try:
        body, sig = token[len(PREFIX):].split(".")
        raw = _unb64(body)
        claims = json.loads(raw)
        ok = isinstance(claims, dict) and canonical(claims) == raw and verify_signature(
            signer().public_b64(), claims, base64.b64encode(_unb64(sig)).decode())
    except (ValueError, TypeError, UnicodeDecodeError):
        ok = False
    if not ok or claims.get("v") != 1 or claims.get("role") not in ROLE_OPS:
        raise CapabilityError(401, "invalid capability token")
    if not isinstance(claims.get("exp"), int) or (time.time() if now is None else now) >= claims["exp"]:
        raise CapabilityError(401, "capability token expired")
    if claims.get("run") != run_id:
        raise CapabilityError(403, "capability token is for another run")
    if op not in claims.get("ops", ()) or op not in ROLE_OPS[claims["role"]]:
        raise CapabilityError(403, "capability token does not grant '%s'" % op)
    return claims
