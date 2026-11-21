"""Stage settings for a slower laptop CPU, loaded only by scripts/stage_tinyfish_console.sh (PYTHONPATH) and only in the
console's uvicorn process. No pinned file is changed (MANIFEST.sha256 stays valid).

Why: on this laptop (Intel i9-9880H inside Docker Desktop) one Qwen3Guard call takes 1.2-2 s, against ~0.6 s on the machine
the team measured on. With the playground's fixed budgets (guard call 1500 ms, release deadline 4000 ms) most guard calls time
out and fail closed, so the card would report blocks that are timeouts, not verdicts. This raises, for playground and
Outside-In runs only:
  * the release deadline: AEGIS_STAGE_DEADLINE_MS (default 10000); the card prints the deadline it used;
  * the guard call budget: AEGIS_STAGE_GUARD_TIMEOUT_MS (default 4000, the runner accepts 100..5000), written into the
    run's defence config BEFORE it is frozen, so it is part of the signed config digest.
Fail-closed behaviour, isolation, sealing, release and verification are unchanged.
"""
import json
import os
import sys

if os.environ.get("AEGIS_STAGE_SLOW_CPU") == "1" and os.path.basename((sys.argv or [""])[0]) == "uvicorn":
    sys.path.insert(0, os.getcwd())
    from aegis import playground as _pg

    _deadline = int(os.environ.get("AEGIS_STAGE_DEADLINE_MS", "10000"))
    _guard_ms = int(os.environ.get("AEGIS_STAGE_GUARD_TIMEOUT_MS", "4000"))
    _pg.DEADLINE_MS = _deadline
    _real_runs = _pg.runs

    class _StageRuns:
        def __getattr__(self, name):
            return getattr(_real_runs, name)

        def create_run(self, run_id, **kw):
            path = kw.get("defence_config")
            if path:
                with open(path) as f:
                    cfg = json.load(f)
                if cfg.get("guard_mode", "regex") != "regex":
                    cfg["guard_timeout_ms"] = _guard_ms
                    with open(path, "w") as f:
                        json.dump(cfg, f)
            return _real_runs.create_run(run_id, **kw)

    _pg.runs = _StageRuns()
    print("stage settings: playground deadline %d ms, guard call budget %d ms (scripts/stage/sitecustomize.py)" % (
        _deadline, _guard_ms), file=sys.stderr, flush=True)
