"""Record a real terminal session (asciinema-style) for the finale slides and videos. Nothing is typed in afterwards.

    python record_term.py AEGISLAB_DIR OUT.json CMD [CMD ...]
    python record_term.py --txt OUT.json        (re-derive OUT.txt from the raw recording)

Runs an interactive bash in a pseudo-terminal (128 x 34) inside the aegislab/ checkout, types each command, waits for the
prompt to return, then types `echo "exit code: $?"`. Every byte the terminal printed is stored with its real timestamp,
so a renderer can replay it 1:1 (render_video.py) and the plain transcript can be checked (OUT.txt, ANSI removed).

Environment: every AEGIS_* variable is removed (the demos start fresh); PYTHONWARNINGS=ignore keeps a third-party
DeprecationWarning (which prints the venv's absolute path) out of the recording; INPUTRC turns off bracketed paste so the
prompt is a plain "$ ". Nothing else is changed.
"""
import base64
import fcntl
import json
import os
import pty
import re
import select
import struct
import subprocess
import sys
import termios
import time

COLS, ROWS = 128, 34


def plain(raw):
    """ANSI and carriage returns removed; readline's soft wrap of a long typed command (" \\r") is undone."""
    t = re.sub(r" \r(?!\n)", "", raw.decode("utf-8", "replace"))
    return re.sub(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07]*\x07|\r", "", t)


if sys.argv[1] == "--txt":  # re-derive OUT.txt from a recorded OUT.json
    rec = json.load(open(sys.argv[2]))
    open(re.sub(r"\.json$", "", sys.argv[2]) + ".txt", "w").write(plain(b"".join(base64.b64decode(e[1]) for e in rec["events"])))
    sys.exit(0)
work, out_path, cmds = sys.argv[1], sys.argv[2], sys.argv[3:]

pid, fd = pty.fork()
if pid == 0:
    os.chdir(work)
    env = {k: v for k, v in os.environ.items() if not k.startswith("AEGIS_")}
    rc = "/tmp/aegis-p5-inputrc"
    open(rc, "w").write("set enable-bracketed-paste off\n")  # no \e[?2004h before each prompt
    env.update(INPUTRC=rc, TERM="xterm-256color", PS1="$ ", COLUMNS=str(COLS), LINES=str(ROWS), PYTHONDONTWRITEBYTECODE="1", PYTHONWARNINGS="ignore")
    os.execvpe("bash", ["bash", "--norc", "--noprofile", "-i"], env)

fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))
T0 = time.monotonic()
events, marks = [], []
buf = b""


def pump(seconds, until=None):
    global buf
    end = time.monotonic() + seconds
    seen_from = len(buf)
    while time.monotonic() < end:
        r, _, _ = select.select([fd], [], [], 0.02)
        if r:
            try:
                data = os.read(fd, 65536)
            except OSError:
                return False
            if not data:
                return False
            events.append([round(time.monotonic() - T0, 4), base64.b64encode(data).decode()])
            buf += data
            if until is not None and until in buf[seen_from:]:
                return True
    return until is None


def send(text, per_char=0.0):
    for ch in text:
        os.write(fd, ch.encode())
        pump(per_char)


assert pump(10, b"$ "), "no shell prompt"
pump(0.6)
exits = []
for i, cmd in enumerate(cmds):
    marks.append([round(time.monotonic() - T0, 4), "cmd%d" % i])
    send(cmd, per_char=0.03)
    send("\r")
    assert pump(1800, b"\r\n$ "), "prompt did not return after: " + cmd
    send('echo "exit code: $?"\r')
    pump(5, b"\r\n$ ")
    m = re.findall(rb"exit code: (\d+)", buf)
    exits.append(int(m[-1]) if m else None)
    pump(1.0)
marks.append([round(time.monotonic() - T0, 4), "end"])
send("exit\r")
pump(2)
os.waitpid(pid, 0)

meta = {
    "recorded_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "cols": COLS, "rows": ROWS, "commands": cmds, "exit_codes": exits,
    "workdir_git_head": subprocess.run(["git", "-C", work, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip(),
    "workdir_dirty": bool(subprocess.run(["git", "-C", work, "status", "--porcelain", "--", "."], capture_output=True, text=True).stdout.strip()),
    "note": "Raw pty output with real timestamps; inputs were typed by this script; nothing was edited afterwards.",
}
json.dump({"meta": meta, "events": events, "marks": marks}, open(out_path, "w"))
open(re.sub(r"\.json$", "", out_path) + ".txt", "w").write(plain(buf))
print(json.dumps(meta))
