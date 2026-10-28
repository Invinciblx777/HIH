"""Vercel entry point: the unchanged console app as a read-only public demo (no podman, no operator session, state in /tmp)."""
import os

os.environ.setdefault("AEGIS_VAR", "/tmp/aegis")
os.environ.setdefault("AEGIS_PUBLIC_DEMO", "1")
from aegis.console import app  # noqa: E402,F401
