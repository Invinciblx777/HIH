"""Vercel entry point: the unchanged console app as a read-only public demo (no podman, no operator session, state in /tmp).

Finale P1: AEGIS_PUBLIC_DEMO=1 is forced here, not defaulted, so a project setting cannot turn the hosted site into a
writable console. The console then refuses the launch link, every state-changing request except bundle verify and tamper on
a disposable copy, and live execution (aegis/console.py, aegis/lab_session.py)."""
import os

os.environ.setdefault("AEGIS_VAR", "/tmp/aegis")
os.environ["AEGIS_PUBLIC_DEMO"] = "1"
from aegis.console import app  # noqa: E402,F401
