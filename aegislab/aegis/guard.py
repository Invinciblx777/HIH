"""Finale P16 (part A): wire the Qwen3Guard guard into the defence runner's launch. OFF unless AEGIS_GUARD_RUNDIR is set.

aegis/__init__.py calls install() only when AEGIS_GUARD_RUNDIR is set (scripts/start_guard_server.sh prints the directory and
writes guard.env). install() wraps aegis.runtime.launch so that, for the defence runner's container ("blue") only:

  * the guard server's socket directory is mounted at /aegis/guard/sock (rw: connecting to a UNIX socket needs write);
  * a copy of the guard's API key is mounted read-only at /aegis/guard/key;
  * a copy of guard/guard_runner.py is mounted read-only and started instead of the image's defence_runner.py.

Both copies are made under the guard's run directory ($XDG_RUNTIME_DIR/aegis-guard.*/blue/<run>/, removed with the guard), never
in the run's own directory, which is sealed and exported. Red's and the model worker's launches pass through unchanged, so they
never get a path to the guard. Set but not running: the launch fails (no fallback to the regex-only runner).

Why a wrapper and not an edit of aegis/runtime.py or aegis/runs.py: both files are pinned by saved experiments (the finale P4
user-namespace proof and the LLM isolation runs record their sha256; check_claims.py fails on drift). With the variable unset
nothing here is imported and every run is the tag's, byte for byte. The sandbox image is unchanged as well: guard_runner.py is not
under sandbox/ (Containerfile: COPY sandbox/).
"""
import os
import shutil
from pathlib import Path

from . import runtime

GUARD_RUNNER = Path(__file__).resolve().parent.parent / "guard" / "guard_runner.py"
HARDEN = Path(__file__).resolve().parent / "harden.py"                                  # finale P18
HARDEN_RULES = Path(__file__).resolve().parent.parent / "guard" / "harden_rules.json"
_orig_launch = None


def guard_extension(role: str, mounts: list, env: dict, cmd):
    """(mounts, env, cmd) for one launch: unchanged unless AEGIS_GUARD_RUNDIR is set and the role is the defence runner."""
    rundir = os.environ.get("AEGIS_GUARD_RUNDIR", "").strip()
    if role != "blue" or not rundir or cmd is not None:
        return mounts, env, cmd
    frozen = next((h for h, c, _m in mounts if c == "/aegis/frozen"), None)
    sock = Path(rundir) / "sock"
    if frozen is None or not (sock / "guard.sock").exists() or not (Path(rundir) / "key").is_file():
        raise runtime.RuntimeFailure("AEGIS_GUARD_RUNDIR is set but the guard server is not running there (fail closed, no fallback)")
    gdir = Path(rundir) / "blue" / Path(frozen).parent.name
    gdir.mkdir(mode=0o700, parents=True, exist_ok=True)
    shutil.copyfile(GUARD_RUNNER, gdir / "guard_runner.py")
    shutil.copyfile(Path(rundir) / "key", gdir / "key")
    # finale P18: the hardening module and its rules beside the runner (read-only); used only when the frozen config asks for it
    shutil.copyfile(HARDEN, gdir / "harden.py")
    shutil.copyfile(HARDEN_RULES, gdir / "harden_rules.json")
    os.chmod(gdir / "key", 0o600)
    mounts = list(mounts) + [(str(gdir / "guard_runner.py"), "/aegis/guardrun/guard_runner.py", "ro"),
                             (str(gdir / "harden.py"), "/aegis/guardrun/harden.py", "ro"),
                             (str(gdir / "harden_rules.json"), "/aegis/guardrun/harden_rules.json", "ro"),
                             (str(gdir / "key"), "/aegis/guard/key", "ro"), (str(sock), "/aegis/guard/sock", "rw")]
    return mounts, dict(env), "/aegis/guardrun/guard_runner.py"


def install():
    """Wrap runtime.launch once (idempotent)."""
    global _orig_launch
    if _orig_launch is not None:
        return
    _orig_launch = runtime.launch

    def launch(name, role, mounts, env, cmd=None):
        mounts, env, cmd = guard_extension(role, mounts, env, cmd)
        return _orig_launch(name, role, mounts, env, cmd)
    launch.__doc__ = _orig_launch.__doc__
    runtime.launch = launch


def installed() -> bool:
    return _orig_launch is not None
