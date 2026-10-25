"""Hashing, commitments and signing helpers (trusted control plane)."""
import base64
import hashlib
import hmac
import json
import os
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def canonical(obj) -> bytes:
    """Deterministic JSON encoding used for every hash and signature."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def file_digest(path) -> str:
    return sha256(Path(path).read_bytes())


def commitment(nonce: str, payload: str) -> str:
    """Attack commitment: H(nonce || 0x00 || payload). Matches sandbox/red_agent.py."""
    return sha256((nonce + "\x00" + payload).encode())


def verify_commitment(digest: str, nonce: str, payload: str) -> bool:
    return hmac.compare_digest(digest, commitment(nonce, payload))


class Signer:
    """Ed25519 checkpoint signer. The private key is a trusted component."""

    def __init__(self, key_path: Path):
        key_path = Path(key_path)
        if not key_path.exists():
            # Created complete and private (mkstemp is mode 0600) and published with an atomic link: a concurrent first use can neither
            # read a half-written key nor end up with a different key, and the key is never readable by group or others.
            key_path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=key_path.parent, prefix=".key-")
            try:
                with os.fdopen(fd, "wb") as fh:
                    fh.write(Ed25519PrivateKey.generate().private_bytes(
                        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
                try:
                    os.link(tmp, key_path)
                except FileExistsError:
                    pass  # another thread or process won; its key is the key
            finally:
                os.unlink(tmp)
        self.key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        self.public_raw = self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.key_id = sha256(self.public_raw)[:23]

    def public_b64(self) -> str:
        return base64.b64encode(self.public_raw).decode()

    def sign(self, obj) -> str:
        return base64.b64encode(self.key.sign(canonical(obj))).decode()


def verify_signature(public_b64: str, obj, sig_b64: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(public_b64)).verify(
            base64.b64decode(sig_b64), canonical(obj))
        return True
    except Exception:
        return False
