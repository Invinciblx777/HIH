"""AegisLab: secure infrastructure for adversarial AI evaluation (hackathon prototype)."""
import os as _os

if _os.environ.get("AEGIS_GUARD_RUNDIR", "").strip():  # finale P16 (part A): OFF unless set; see aegis/guard.py
    from . import guard as _guard
    _guard.install()
if _os.environ.get("AEGIS_N8N_WEBHOOK", "").strip():  # finale P16 (part B): OFF unless set; see aegis/notify.py
    from . import notify as _notify
    _notify.install()
