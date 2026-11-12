"""Hosted entry point (Render, primary; Vercel, secondary): the unchanged console app as a read-only public demo (no podman,
no operator session, state in /tmp).

Finale P1: AEGIS_PUBLIC_DEMO=1 is forced here, not defaulted, so a project setting cannot turn the hosted site into a
writable console. The console then refuses the launch link, every state-changing request except bundle verify and tamper on
a disposable copy, and live execution (aegis/console.py, aegis/lab_session.py).

Finale P6: on Render (which sets RENDER=true on every service) the per-client verifier limit reads CF-Connecting-IP, the
header the edge overwrites, unless AEGIS_CLIENT_IP_HEADER names another; render.yaml sets it explicitly too. Render appends
to X-Forwarded-For, so the P1 default (X-Real-IP, then the first X-Forwarded-For entry) would let a client choose its own
bucket there."""
import os

os.environ.setdefault("AEGIS_VAR", "/tmp/aegis")
os.environ["AEGIS_PUBLIC_DEMO"] = "1"
if os.environ.get("RENDER"):
    os.environ.setdefault("AEGIS_CLIENT_IP_HEADER", "cf-connecting-ip")
from aegis.console import app  # noqa: E402,F401
