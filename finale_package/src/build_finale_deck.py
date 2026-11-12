"""Build the Grand Finale deck (12 slides) on the official Hack in Hills '26 template, with speaker notes on every slide.

    python build_finale_deck.py CLAIMS.json MEDIA_DIR OUT.pptx

CLAIMS.json is finale_package/claims_used_for_finale.json (written by aegislab/evaluation/check_finale_presentation.py
--write-claims). Every figure on a slide or in the notes is taken from it through F(key, form) and printed with the claim's
type label (LIVE / RE-MEASURED <date> / RECORDED <date>); none is typed here. MEDIA_DIR holds the P5 screenshots (screens/)
and the terminal images rendered from the recorded P5 transcripts (term/). Drawing helpers and the template are the rc4
ones (presentation_src/deckkit.py, presentation_src/official_template.pptx), used read-only.
"""
import copy
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO / "presentation_src"))
from deckkit import *  # noqa: F401,F403,E402
from pptx.opc.constants import RELATIONSHIP_TYPE as RT  # noqa: E402
from PIL import Image  # noqa: E402

TEMPLATE = REPO / "presentation_src" / "official_template.pptx"
GH = "github.com/Invinciblx777/HIH"
DEMO_URL = "aegislab-demo.onrender.com"
CODE = "main (finale P1-P5 merged 12 Nov 2026); media recorded on 9145592"
C = {}
MEDIA = Path(".")


def F(key, form):
    return C[key]["forms"][form]


def L(key):
    return C[key]["label"]


def FL(key, form):
    return "%s (%s)" % (F(key, form), L(key))


def notes_l(sl, body):
    """Speaker notes; a line that quotes a claim gets the claim's type label appended if the line does not carry it yet."""
    out = []
    for ln in body.strip("\n").split("\n"):
        need = []
        for c in C.values():
            if c["label"] not in ln and c["label"] not in need and any(f in ln for f in c["forms"].values()):
                need.append(c["label"])
        out.append(ln + ("" if not need else " [%s]" % "; ".join(need)))
    notes(sl, "\n".join(out))


def shot(name):
    p = MEDIA / "screens" / name
    if not p.exists():
        raise SystemExit("missing screenshot " + str(p))
    return p


def term(name):
    p = MEDIA / "term" / name
    if not p.exists():
        raise SystemExit("missing terminal image " + str(p))
    return p


def pic_h(path, w):
    im = Image.open(path)
    return w * im.size[1] / im.size[0]


def pic_fit(sl, path, x, y, w, h, border=LINE):
    """Picture scaled to fit inside w x h, centred horizontally, top-aligned."""
    im = Image.open(path)
    r = min(w / im.size[0], h / im.size[1])
    pw, ph = im.size[0] * r, im.size[1] * r
    picture(sl, path, x + (w - pw) / 2, y, w=pw, border=border)
    return pw, ph


def tag(sl, x, y, typ):
    col = {"LIVE": (WHITE, GREEN), "RE-MEASURED": (WHITE, BLUE), "RECORDED": (WHITE, AMBER)}[typ.split()[0]]
    return chip(sl, x, y, typ, col[0], col[1], size=12)


def footer(sl, extra=""):
    text(sl, 0.7, 10.78, 18.6, 0.32, [[("Code shown: " + CODE + " · every figure from finale_package/claims_used_for_finale.json" + extra, {})]], size=11, color=SLATE)


def card(sl, x, y, w, h, title, body, col=NAVY, fill=WHITE, tsize=17, bsize=14.5):
    paras = [[(title, {"bold": True, "font": HEAD, "size": tsize, "color": col})]] + [[(b, {"size": bsize, "color": INK})] if isinstance(b, str) else b for b in body]
    return text(sl, x, y, w, h, paras, size=bsize, fill=fill, line=LINE, shape=MSO_SHAPE.ROUNDED_RECTANGLE, radius=0.06, margin=0.16, spacing=3)


def bar(sl, x, y, w, frac, col, h=0.34):
    text(sl, x, y, w, h, "", fill=SLATE_SOFT, shape=MSO_SHAPE.RECTANGLE)
    if frac > 0:
        text(sl, x, y, max(w * frac, 0.05), h, "", fill=col, shape=MSO_SHAPE.RECTANGLE)


# ------------------------------------------------------------------------------------------------ slides
def s1(sl):
    text(sl, 0.7, 4.7, 9.6, 0.45, "GRAND FINALE · HACK IN HILLS ’26 · TRACK 04", size=20, bold=True, color=ORANGE, font=HEAD)
    text(sl, 0.7, 5.15, 9.6, 1.0, "AegisLab", size=58, bold=True, color=NAVY, font=HEAD)
    text(sl, 0.7, 6.25, 9.6, 0.55, "Secure infrastructure for adversarial AI safety testing", size=24, bold=True, color=INK)
    text(sl, 0.7, 6.95, 9.3, 2.4, [[("The problem. ", {"bold": True, "color": NAVY}),
                                   ("A red team attacks, a blue team defends, and the model under test answers, all on one system. "
                                    "If red can read the defence, if one session can read another's data through the model, or if a "
                                    "result can be edited afterwards, the score measures the leak, not the model.", {})],
                                  [("Why isolation decides validity: ", {"bold": True, "color": ORANGE}),
                                   ("a safety finding is only as credible as the boundaries of the test that produced it.", {"bold": True})]],
         size=19, color=SLATE, spacing=8)
    text(sl, 0.7, 9.55, 9.6, 1.0, [[("Team Tech Mavericks", {"bold": True, "color": INK})],
                                   [(GH + "  ·  read-only demo: " + DEMO_URL, {"bold": True, "color": NAVY, "font": "IBM Plex Mono", "size": 15})]], size=18)
    y = 4.75
    rows = [("Isolate", "rootless sandboxes, no network, one trusted broker, separate user namespaces", ORANGE),
            ("Measure", "every boundary attacked with recorded tests, controls that must leak, and stated sample sizes", BLUE),
            ("Prove", "hash-chained, signed audit log that a reviewer verifies offline; a tampered copy is rejected", GREEN)]
    for t1, t2, col in rows:
        text(sl, 10.7, y, 8.6, 1.55, [[(t1, {"bold": True, "font": HEAD, "size": 26, "color": col})], [(t2, {"size": 17, "color": SLATE})]],
             size=17, fill=WHITE, line=LINE, shape=MSO_SHAPE.ROUNDED_RECTANGLE, radius=0.08, margin=0.2, anchor="m")
        y += 1.75
    text(sl, 10.7, 10.05, 8.6, 0.5, "Labels on every figure: LIVE · RE-MEASURED <date> · RECORDED <date>", size=13, color=SLATE)
    notes_l(sl, """
OPENING, slide 1 (about 30 seconds of the 6-minute talk)
We are Tech Mavericks, and this is AegisLab, for Track 04: securing adversarial AI safety testing infrastructure.

The problem: in an AI safety evaluation a red team attacks, a blue team defends, and the model under test answers, on one system. If red can read the blue team's rules, if one session can read another's data through the model, or if anyone can edit the result afterwards, the score no longer measures the model. It measures the leak. So isolation is not an operations detail: it decides whether the evaluation is valid at all.

AegisLab does three things: it isolates (rootless sandboxes with no network, one trusted broker, separate user namespaces), it measures (each boundary is attacked by recorded tests with controls that must leak), and it proves (a signed, hash-chained audit log that a reviewer verifies offline).

Every figure in this deck carries a label. LIVE means the presented code produces it when it runs; you will see some of those runs today. RE-MEASURED means measured again on the finale code on the date shown. RECORDED means measured earlier and not re-run.

Code shown: main, with finale P1 to P5 merged on 12 Nov 2026. The screenshots and terminal recordings were made on commit 9145592, the finale P4 code. The public read-only demo runs on Render and serves main.
""")


def s2(sl):
    header(sl, "THREAT MODEL", "Who must not see what, and where each rule is enforced")
    frame(sl, 0.7, 3.0, 5.4, 7.45, RED, fill=RED_SOFT)
    text(sl, 0.95, 3.1, 5.0, 0.4, "UNTRUSTED WORKLOADS", size=15, bold=True, color=RED, font=HEAD)
    text(sl, 0.95, 3.45, 5.0, 0.35, "rootless · no network · own user namespace", size=14, color=SLATE)
    box(sl, 1.0, 4.0, 4.8, 1.4, "Red team", ["attack payloads, private pack"], line=RED, tcol=RED, tsize=21, ssize=16)
    box(sl, 1.0, 5.95, 4.8, 1.4, "Blue defence runner", ["frozen defence configuration"], line=BLUE, tcol=BLUE, tsize=21, ssize=16)
    box(sl, 1.0, 7.9, 4.8, 1.5, "Model under test", ["session state · prompt cache"], line=SLATE, tsize=21, ssize=16)
    arrow(sl, [(3.4, 5.4), (3.4, 5.95)], RED, 3, dash=True, both=True)
    circle(sl, 3.17, 5.44, 0.46, "F1", RED, size=13)
    circle(sl, 5.55, 7.65, 0.46, "F3", RED, size=13)
    frame(sl, 6.9, 3.0, 5.2, 7.45, NAVY, fill=MIST)
    text(sl, 7.1, 3.1, 4.8, 0.4, "TRUSTED CONTROL PLANE (HOST)", size=15, bold=True, color=NAVY, font=HEAD)
    box(sl, 7.2, 4.0, 4.6, 2.3, "Trusted broker", ["identity = which mailbox", "checks commitments", "withholds foreign canaries"], fill=ORANGE_SOFT, line=ORANGE, line_w=3, tsize=21, ssize=16)
    box(sl, 7.2, 6.8, 4.6, 1.55, "Audit · sealed store · gate", ["hash chain · signed checkpoints"], line=NAVY, tsize=19, ssize=16)
    box(sl, 7.2, 8.75, 4.6, 1.35, "Evidence signing key", ["host user only, 0600"], line=AMBER, tcol=AMBER, fill=AMBER_SOFT, tsize=18, ssize=15)
    arrow(sl, [(5.8, 4.7), (7.2, 4.7)], GREEN, 3, both=True)
    arrow(sl, [(5.8, 6.65), (6.55, 6.65), (6.55, 5.4), (7.2, 5.4)], GREEN, 3, both=True)
    arrow(sl, [(5.8, 8.65), (6.55, 8.65), (6.55, 5.9), (7.2, 5.9)], GREEN, 3, both=True)
    text(sl, 5.85, 4.2, 1.3, 0.4, "mailbox", size=14, bold=True, color=GREEN, align="c", fill=WHITE, shape=MSO_SHAPE.RECTANGLE)
    arrow(sl, [(9.5, 6.3), (9.5, 6.8)], NAVY, 3)
    arrow(sl, [(5.8, 9.9), (7.2, 9.5)], RED, 3, dash=True)
    circle(sl, 6.25, 9.55, 0.46, "F4", RED, size=13)
    lx = 12.6
    text(sl, lx, 3.0, 6.9, 0.4, "FORBIDDEN FLOWS (each one attacked in a test)", size=15, bold=True, color=RED, font=HEAD)
    items = [("F1", "Red reads the defence rules", "config mounted only into the defence runner, read-only, digest attested"),
             ("F2", "Anyone reads results before release", "sealed store and role gate: refused until a reviewer releases"),
             ("F3", "One session reads another's data", "one stateless message per request, prompt cache off, foreign canaries withheld"),
             ("F4", "A tenant reaches the broker's files or key", "no-follow mailbox I/O; containers run on their own host UIDs"),
             ("F5", "A record is changed unnoticed", "hash chain, signed terminal checkpoint, reviewer countersignature"),
             ("F6", "Red signals blue through monitoring", "participants see run-level events only until SEALED")]
    y = 3.45
    for t_, t1, t2 in items:
        circle(sl, lx, y + 0.05, 0.42, t_, RED, size=12)
        text(sl, lx + 0.55, y - 0.04, 6.3, 0.95, [[(t1, {"bold": True, "size": 15})], [(t2, {"size": 13, "color": SLATE})]], size=15)
        y += 0.93
    text(sl, lx, 9.1, 6.9, 1.35, [[("Tested, not assumed (%s): " % L("role_matrix"), {"bold": True, "color": NAVY}),
                                   ("role × operation × state matrix, %s, %s, %s; none unexpectedly permitted." % (F("role_matrix", "attempts"), F("role_matrix", "denied"), F("role_matrix", "allowed")), {})]],
         size=14.5, fill=WHITE, line=LINE, shape=MSO_SHAPE.ROUNDED_RECTANGLE, radius=0.08, margin=0.15, anchor="m")
    footer(sl)
    notes_l(sl, """
THREAT MODEL, slide 2 (about 30 seconds)
Parties: red holds attack payloads, blue holds a frozen defence configuration, the model holds session state and a prompt cache, a reviewer must trust the result, and observers watch. One trusted broker sits between them.

Six forbidden flows, each attacked in a recorded test:
F1 red reading the defence rules; F2 anyone reading results before a reviewer releases them; F3 one session reading another's data through the model; F4 a tenant reaching the broker's files or the signing key; F5 a record changed unnoticed; F6 red signalling blue through the monitoring stream (closed in the finale work: participants see run-level events only until the run is SEALED, and the stream never carries a red-chosen string).

Tested, not assumed (%s): the role, operation and state matrix made %s with %s and %s; none unexpectedly permitted. Evidence: %s.

Trusted and not defended: the broker and its signing key, and the shared host kernel and container runtime. That is our residual-risk slide later.
""" % (L("role_matrix"), F("role_matrix", "attempts"), F("role_matrix", "denied"), F("role_matrix", "allowed"), C["role_matrix"]["evidence"][0]))


def s3(sl):
    header(sl, "ARCHITECTURE", "Five layers, a sandboxed model server, a user-namespace split")
    tw = 3.6
    box(sl, 0.7, 3.0, tw, 1.35, "Red sandbox", ["private attack pack"], fill=RED_SOFT, line=RED, tcol=RED, tsize=19, ssize=14)
    box(sl, 0.7, 4.65, tw, 1.35, "Blue defence runner", ["frozen config, read-only"], fill=BLUE_SOFT, line=BLUE, tcol=BLUE, tsize=18, ssize=14)
    box(sl, 0.7, 6.3, tw, 1.35, "Model worker (stub)", ["fresh container per run"], fill=SLATE_SOFT, line=SLATE, tsize=18, ssize=14)
    box(sl, 0.7, 7.95, tw, 1.75, "Sandboxed model server", ["llama.cpp CPU, Qwen2.5-0.5B", "--network none, UNIX socket"], fill=SLATE_SOFT, line=NAVY, tsize=18, ssize=14)
    text(sl, 0.7, 9.8, tw, 0.75, [[("each container on its own subordinate host UID (F4)", {"bold": True})]], size=12.5, color=NAVY, align="c")
    frame(sl, 5.0, 2.95, 5.4, 6.8, NAVY, fill=MIST)
    text(sl, 5.2, 3.03, 5.0, 0.4, "TRUSTED CONTROL PLANE · host user", size=14, bold=True, color=NAVY, font=HEAD)
    box(sl, 5.3, 3.55, 4.8, 1.9, "Trusted broker", ["identity bound to mailbox", "routes · checks · withholds · quotas"], fill=AMBER_SOFT, line=AMBER, line_w=3, tsize=20, ssize=15)
    box(sl, 5.3, 5.8, 2.3, 1.45, "Audit chain", ["signed checkpoints", "anomaly alerts"], line=NAVY, tsize=16, ssize=13)
    box(sl, 7.8, 5.8, 2.3, 1.45, "Result gate", ["SEALED, verified,", "reviewer releases"], line=GREEN, tsize=16, ssize=13)
    box(sl, 5.3, 7.55, 4.8, 1.0, "Evidence signing key", ["0600, host user only"], line=AMBER, fill=AMBER_SOFT, tcol=AMBER, tsize=16, ssize=13)
    box(sl, 5.3, 8.7, 4.8, 0.9, "Capability tokens", ["run-scoped, separate key"], line=SLATE, tsize=15, ssize=13)
    for yy, col in ((3.67, RED), (5.32, BLUE), (6.97, SLATE), (8.8, NAVY)):
        arrow(sl, [(4.3, yy), (4.65, yy), (4.65, 4.5), (5.3, 4.5)], col, 2.5, both=True)
    text(sl, 4.05, 3.18, 1.3, 0.35, "mailbox / socket", size=11, bold=True, color=NAVY, align="c")
    arrow(sl, [(6.45, 5.45), (6.45, 5.8)], NAVY, 3)
    arrow(sl, [(7.6, 6.5), (7.8, 6.5)], GREEN, 3)
    box(sl, 10.9, 3.0, 2.8, 1.45, "Reviewer", ["countersigns the", "terminal checkpoint"], line=GREEN, tcol=GREEN, tsize=17, ssize=13)
    box(sl, 10.9, 4.85, 2.8, 1.45, "Strict verifier", ["separate program", "pinned key + hash"], line=GREEN, tcol=GREEN, tsize=17, ssize=13)
    box(sl, 10.9, 6.7, 2.8, 1.45, "Observers", ["run-level events", "until SEALED"], line=SLATE, tsize=17, ssize=13)
    arrow(sl, [(10.4, 3.7), (10.9, 3.7)], GREEN, 2.5, dash=True)
    arrow(sl, [(12.3, 4.45), (12.3, 4.85)], GREEN, 3)
    arrow(sl, [(10.4, 7.4), (10.9, 7.4)], SLATE, 2.5, dash=True)
    text(sl, 10.9, 8.45, 2.8, 1.3, [[("F4 split, %s" % L("f4_userns"), {"bold": True, "color": BLUE, "size": 12.5})],
                                     [("%s, %s; broker %s; key unreadable: %s" % (F("f4_userns", "containers"), F("f4_userns", "inside"), F("f4_userns", "broker"), F("f4_userns", "errno")), {"size": 12.5})]],
         size=12.5, fill=WHITE, line=BLUE, shape=MSO_SHAPE.ROUNDED_RECTANGLE, radius=0.08, margin=0.1)
    for n_, (x, y) in zip("12345", [(0.5, 2.85), (9.75, 3.4), (9.75, 5.65), (0.5, 7.8), (13.45, 4.7)]):
        circle(sl, x, y, 0.48, n_, ORANGE, size=15)
    lx = 14.3
    text(sl, lx, 3.0, 5.2, 0.4, "WHAT EACH LAYER ENFORCES", size=15, bold=True, color=NAVY, font=HEAD)
    layers = [("1", "Container limits", "rootless Podman, --network none, read-only root, no capabilities, no-new-privileges, pids/memory/CPU caps, --userns auto, non-root user"),
              ("2", "One controlled path", "file mailbox with no-follow I/O, size and type checks, per-tenant quotas; the model only via a 0700 UNIX socket"),
              ("3", "Role and run identity", "identity from the mailbox; server-side role gate; run-scoped capability tokens; reviewer-only release"),
              ("4", "Model and session isolation", "one stateless message per request, prompt cache off and guarded, foreign canaries withheld in plain and re-encoded form"),
              ("5", "Audit and verification", "hash chain, signed terminal checkpoint, reviewer countersignature, independent strict verifier")]
    y = 3.45
    for k_, t1, t2 in layers:
        circle(sl, lx, y + 0.04, 0.42, k_, ORANGE, size=14)
        text(sl, lx + 0.55, y - 0.05, 4.65, 1.4, [[(t1, {"bold": True, "size": 15})], [(t2, {"size": 12.5, "color": SLATE})]], size=14)
        y += 1.42
    footer(sl)
    notes_l(sl, """
ARCHITECTURE, slide 3 (about 40 seconds). Walk left to right.

Left: the workloads. Red, blue and the stub model worker are separate rootless Podman containers: no network, read-only root, all capabilities dropped, no-new-privileges, pids, memory and CPU limits. The real model, llama.cpp on CPU with Qwen2.5-0.5B, runs in its own rootless container with no network at all: the broker reaches it only through a UNIX socket in a 0700 directory.

The finale change on this slide is the user-namespace split (F4). Every container runs as a non-root user inside and on its own subordinate host UID outside; the broker, which owns the evidence signing key, is a different host user. %s: %s, %s, distinct %s, none the broker's %s, and the key bind-mounted into a container is unreadable (%s). Evidence: %s.

Centre: the trusted broker. Identity comes from which mailbox a message is in, never from the message. It routes, checks commitments, withholds foreign canaries, and enforces per-tenant quotas. Every decision goes into the hash-chained audit log.

Right: the reviewer releases and countersigns, the strict verifier is a separate program with a pinned key and terminal hash, and observers see only run-level events until the run is sealed.

What is still trusted: the broker and its key, and the shared host kernel. A host-user compromise still reaches the key; see the residual-risk slide.
""" % (L("f4_userns"), F("f4_userns", "containers"), F("f4_userns", "inside"), F("f4_userns", "hosts"), F("f4_userns", "broker"), F("f4_userns", "errno"), C["f4_userns"]["evidence"][0]))


def s4(sl):
    header(sl, "LIVE DEMO PLAN", "What you will see run, and what is recorded")
    rows = [("1", "Real model, live", "scripts/real_model_demo.sh", "%s in %s: stateless sessions, a leak the model makes is withheld (also in base64), strict verify" % (F("real_model_demo", "checks"), F("real_model_demo", "secs")), "LIVE"),
            ("2", "Console run card", "start_real_model_console.sh", "REAL MODEL · LIVE, deadline release at %s, run sealed" % F("deadline_default", "D"), "LIVE"),
            ("3", "Evidence", "Evidence page / verify_cli", "strict verify: %s; tampered copy: %s" % (F("verify_cli_live", "ok"), F("verify_cli_live", "bad")), "LIVE"),
            ("4", "F4 proof table", "evaluation/p4_userns_proof.py", "%s: every container on its own host UID, none the broker's" % F("f4_proof_live", "checks"), "LIVE"),
            ("5", "Fallback if the venue fails", "walkthrough video (offline)", "the same steps recorded on the presented code; labelled RECORDED on screen", "RECORDED 12 Nov 2026")]
    y = 3.0
    for n_, t1, cmd, res, typ in rows:
        circle(sl, 0.7, y + 0.2, 0.55, n_, ORANGE if n_ != "5" else AMBER, size=16)
        text(sl, 1.45, y, 10.7, 1.25, [[(t1, {"bold": True, "font": HEAD, "size": 17}), ("   " + cmd, {"font": "IBM Plex Mono", "size": 12.5, "color": SLATE})],
                                         [(res, {"size": 14})]], size=14, fill=WHITE, line=LINE, shape=MSO_SHAPE.ROUNDED_RECTANGLE, radius=0.08, margin=0.12, anchor="m")
        tag(sl, 10.2 - (0.9 if typ != "LIVE" else 0), y + 0.05, typ)
        y += 1.38
    text(sl, 0.7, 10.05, 11.4, 0.6, [[("Expected counts are from the rehearsal on the presented code; a LIVE run on stage must reproduce them. ", {}),
                                       ("The launch link is never shown.", {"bold": True})]], size=13, color=SLATE)
    p = shot("02e_run_card_crop_desktop.png")
    pw, ph = pic_fit(sl, p, 12.6, 3.0, 6.9, 6.6, border=NAVY)
    text(sl, 12.6, 3.0 + ph + 0.08, 6.9, 0.7, [[("SCREENSHOT ", {"bold": True, "color": GREEN}), ("of the real console, 12 Nov 2026: the run card of a real-model run", {"color": SLATE})]], size=12.5)
    footer(sl)
    notes_l(sl, """
LIVE DEMO PLAN, slide 4 (spoken in 15 seconds; the demo itself takes about 2 minutes of the 6-minute talk)
What you will see, in this order:
1. LIVE: scripts/real_model_demo.sh with the real model. It shows that sessions are stateless, that a leak the model makes is withheld by the broker (including a base64-encoded canary), and that the exported bundle verifies strictly. Expected: %s in %s (the rehearsal on the presented code; the stage run must reproduce it).
2. LIVE: the console started with scripts/start_real_model_console.sh. The run card says REAL MODEL · LIVE and "deadline release at %s"; the launch link is opened off-screen and never shown.
3. LIVE: the Evidence page or verify_cli: strict verification gives %s, a tampered copy gives %s.
4. LIVE if time allows: the F4 proof table, %s.
5. If anything fails at the venue: the offline walkthrough video, recorded on the presented code and labelled RECORDED on screen.
Fallback line if a live step fails: "The venue run failed; here is the same step recorded on the same code on 12 November, and the transcript is in the repository."
""" % (F("real_model_demo", "checks"), F("real_model_demo", "secs"), F("deadline_default", "D"), F("verify_cli_live", "ok"), F("verify_cli_live", "bad"), F("f4_proof_live", "checks")))


def s5(sl):
    header(sl, "LEAKAGE RESULTS WITH A REAL MODEL", "No leak detected, and the controls show the probes see one")
    w = chip(sl, 0.7, 2.98, L("e1_isolation"), WHITE, BLUE, size=13)
    text(sl, 0.9 + w, 2.95, 11.5, 0.45, "Qwen2.5-0.5B Q4_K_M · llama.cpp CPU, sandboxed model server · finale P4 code", size=13.5, color=SLATE, anchor="m")
    rows = [("E1 isolation: another session's canary recovered", F("e1_isolation", "sessions"), F("e1_isolation", "trials"), 0.0, GREEN),
            ("E1 negative control (nothing planted)", F("e1_negative", "text"), "", 0.0, GREEN),
            ("E1 positive control: history shared on purpose (must leak)", F("e1_positive", "history"), "", 1.0, ORANGE),
            ("E1 positive control: context-sharing gateway (must leak)", F("e1_positive", "gateway"), "", 13 / 16.0 if F("e1_positive", "gateway_slash") == "13/16" else 0.8, ORANGE),
            ("E2 full pipeline: broker + sandboxes + real model", F("e2_isolation", "runs"), F("e2_isolation", "attacks") + ", " + F("e2_isolation", "red"), 0.0, GREEN),
            ("E2 context-sharing control: leaks withheld by the broker", F("e2_control", "runs"), F("e2_control", "withheld") + ", " + F("e2_control", "red"), 0.5, ORANGE)]
    y = 3.6
    for t1, big, sub, frac, col in rows:
        text(sl, 0.7, y, 8.3, 0.36, [[(t1, {"bold": True})]], size=15)
        bar(sl, 0.7, y + 0.42, 6.2, frac, col, h=0.3)
        text(sl, 7.05, y + 0.3, 5.3, 0.5, [[(big, {"bold": True, "font": HEAD, "size": 19, "color": col})]], size=19, anchor="m")
        if sub:
            text(sl, 0.7, y + 0.74, 11.5, 0.3, sub, size=12.5, color=SLATE)
        y += 1.08
    cards = [("E3 prompt cache", ["cache off: %s with cached tokens" % F("e3_cache_off", "text"), "cache on (control): cached-token %s" % F("e3_cache_on", "auc")]),
             ("E4 injection", ["%s, %s" % (F("e4_injection", "attacks"), F("e4_injection", "reached")), "%s to red; %s denied" % (F("e4_injection", "protected"), F("e4_injection", "replays"))]),
             ("E5 failure handling", ["%s hold" % F("e5_failure", "text"), "backend down: fail closed, uniform refusal"])]
    x = 12.9
    yy = 3.0
    for t1, b in cards:
        card(sl, x, yy, 6.6, 1.4, t1 + " · " + L("e3_cache_off"), b, tsize=15, bsize=13.5)
        yy += 1.52
    card(sl, x, yy, 6.6, 1.75, "Second model · " + L("second_model"), ["Qwen2.5-1.5B, reduced run (E1 + E3):", "%s (%s); %s" % (F("second_model", "trials"), F("second_model", "sessions"), F("second_model", "controls"))], col=AMBER, tsize=15, bsize=13.5)
    text(sl, 0.7, 10.05, 18.6, 0.6, [[("No leak detected is not no leak: ", {"bold": True, "color": RED}),
                                       ("one-sided 95%% upper bound %s, %s (%s). One model at full scale, CPU only, one host." % (F("e1_bound", "trials"), F("e1_bound", "sessions"), L("e1_bound")), {})]], size=14)
    footer(sl)
    notes_l(sl, """
LEAKAGE RESULTS, slide 5 (about 40 seconds)
Real model: Qwen2.5-0.5B on llama.cpp, CPU, in the sandboxed server. All of this was %s on the finale P4 code; evidence %s.
E1, direct adapter: %s and %s recovered another session's canary. The probes can see a leak: with history shared on purpose %s leaked, through a context-sharing gateway %s; with nothing planted, %s.
E2, the full pipeline (broker, sandboxes, real model): %s had a foreign canary, %s. In the context-sharing control the model did leak in %s; the broker withheld %s and %s.
E3: with the prompt cache off, %s showed cached tokens; with it on (the control) the cached-token %s.
E4: %s, %s, %s to red, %s denied. E5: %s hold.
Second model (%s): Qwen2.5-1.5B, reduced run: %s, %s, %s.
Say it plainly: no leak detected is not the same as no leak. The one-sided 95%% upper bound is %s and %s. One model at full scale, one reduced, CPU only, one host; GPU untested.
""" % (L("e1_isolation"), C["e1_isolation"]["evidence"][0], F("e1_isolation", "sessions"), F("e1_isolation", "trials"), F("e1_positive", "history"), F("e1_positive", "gateway"), F("e1_negative", "text"),
       F("e2_isolation", "runs"), F("e2_isolation", "red"), F("e2_control", "runs"), F("e2_control", "withheld"), F("e2_control", "red"),
       F("e3_cache_off", "text"), F("e3_cache_on", "auc"), F("e4_injection", "attacks"), F("e4_injection", "reached"), F("e4_injection", "protected"), F("e4_injection", "replays"), F("e5_failure", "text"),
       L("second_model"), F("second_model", "trials"), F("second_model", "sessions"), F("second_model", "controls"), F("e1_bound", "trials"), F("e1_bound", "sessions")))


def s6(sl):
    header(sl, "THE TIMING STORY", "Our own test found a 250 ms leak; deadline release fixed it")
    # step 1: stub result
    card(sl, 0.7, 3.0, 5.9, 2.0, "1 · Stub model: 250 ms buckets work", ["held-out accuracy %s" % F("timing_stub", "acc250"), "chance level; %s per answer" % F("timing_stub", "cost"), [(L("timing_stub"), {"bold": True, "color": BLUE, "size": 12.5})]], col=GREEN, tsize=16, bsize=14)
    card(sl, 0.7, 5.2, 5.9, 2.0, "2 · Real model: the same padding leaks", ["one execution: %s" % F("timing_p3_single", "acc250"), "the refusal decision stays readable from latency", [(L("timing_p3_single"), {"bold": True, "color": AMBER, "size": 12.5})]], col=RED, tsize=16, bsize=14)
    card(sl, 0.7, 7.4, 5.9, 2.5, "3 · Fix: deadline release", ["every reply leaves at t0 + D, answered or refused; a slow model is cut off and refused",
                                                                 "default now: %s (%s)" % (F("deadline_default", "D"), L("deadline_default")), "stub keeps 250 ms buckets"], col=GREEN, tsize=16, bsize=14)
    # chart: three executions, three settings
    x0, y0 = 7.2, 3.0
    text(sl, x0, y0, 12.2, 0.4, [[("THREE EXECUTIONS, REAL MODEL, BALANCED CLASSES  ", {"bold": True, "color": NAVY, "font": HEAD}), (L("timing_deadline_real"), {"bold": True, "color": BLUE})]], size=14)
    acc250 = [float(v) for v in F("timing_250_real", "acc").split()[1].split("/")]
    accd = [float(v) for v in F("timing_deadline_real", "acc").split()[1].split("/")]
    base = [float(v) for v in F("timing_deadline_real", "base").split()[1].split("/")]
    ch_y, ch_h, ch_w = y0 + 0.6, 3.6, 12.0
    # axis 0.4 .. 1.0
    lo, hi = 0.4, 1.0

    def ypos(v):
        return ch_y + ch_h * (hi - v) / (hi - lo)
    text(sl, x0 + 0.9, ch_y, ch_w - 0.9, ch_h, "", fill=WHITE, line=LINE, shape=MSO_SHAPE.RECTANGLE)
    for v, lab in ((1.0, "1.0"), (0.7, "0.7"), (0.5, "0.5")):
        text(sl, x0, ypos(v) - 0.17, 0.8, 0.34, lab, size=12, color=SLATE, align="r", anchor="m")
    text(sl, x0 + 0.9, ypos(0.5), ch_w - 0.9, 0.02, "", fill=SLATE, shape=MSO_SHAPE.RECTANGLE)
    groups = [("250 ms buckets", acc250, RED), ("deadline release", accd, GREEN)]
    gx = x0 + 1.4
    for gi, (gname, vals, col) in enumerate(groups):
        for i, v in enumerate(vals):
            bx = gx + gi * 5.6 + i * 1.6
            text(sl, bx, ypos(v), 1.1, ch_y + ch_h - ypos(v), "", fill=col, shape=MSO_SHAPE.RECTANGLE)
            if gi == 1:
                text(sl, bx - 0.15, ypos(base[i]) - 0.02, 1.4, 0.05, "", fill=INK, shape=MSO_SHAPE.RECTANGLE)
        text(sl, gx + gi * 5.6 - 0.2, ch_y + ch_h + 0.05, 4.8, 0.4, [[(gname, {"bold": True, "color": col})]], size=14, align="c")
    text(sl, x0, ch_y + ch_h + 0.5, 12.2, 1.15, [[("250 ms buckets: %s, %s in every execution: leak detected." % (F("timing_250_real", "acc"), F("timing_250_real", "p")), {"color": RED, "bold": True})],
                                                 [("Deadline release: %s against %s (black ticks); %s." % (F("timing_deadline_real", "acc"), F("timing_deadline_real", "base"), F("timing_deadline_real", "p")), {"color": INK})],
                                                 [("Third execution %s: below 0.05 but above the pre-declared %s, so no leak detected (inconclusive as to absence). Reported as measured." % (F("timing_deadline_real", "p3"), F("timing_deadline_real", "alpha")), {"color": AMBER, "bold": True})]],
         size=13.5, spacing=2)
    text(sl, x0, 9.35, 12.2, 1.1, [[("Cost (%s): " % L("timing_deadline_cost"), {"bold": True, "color": NAVY}),
                                    ("%s per answered request; %s of model calls cut off (D per execution %s). " % (F("timing_deadline_cost", "cost"), F("timing_deadline_cost", "cutoff"), F("timing_deadline_cost", "D_each")), {}),
                                    ("D is host- and model-specific and must be re-calibrated elsewhere.", {"bold": True})]],
         size=13.5, fill=MIST, line=LINE, shape=MSO_SHAPE.ROUNDED_RECTANGLE, radius=0.08, margin=0.14, anchor="m")
    footer(sl)
    notes_l(sl, """
THE TIMING STORY, slide 6 (about 45 seconds). This is the slide where we show a result that changed.
1. With the stub model, 250 ms response buckets bring a latency classifier to chance: %s (%s), at %s per answer.
2. When we ran the same timing test against the real model, it broke: one execution gave %s (%s). Real-model latency spans many 250 ms buckets, and refusals never reach the model, so the decision stays readable. Our own harness found this; nobody reported it to us.
3. The fix is deadline release: every reply, answered or refused, leaves at t0 plus D; a model that has not answered in time is cut off and red gets the uniform refusal. We ran it three times with balanced classes (%s):
   250 ms buckets: %s, %s each time: leak detected.
   Deadline release: %s, against majority baselines %s, %s.
   The third execution's %s is below 0.05 but above the threshold we declared before measuring, %s (Bonferroni over nine tests). So the verdict is "no leak detected", which is inconclusive as to absence, and we show the number instead of hiding it.
Cost (%s): %s per answered request, %s of model calls cut off, D per execution %s. The default for a real-model backend is now %s (%s); the stub keeps 250 ms.
Limits: one host, one model, one classifier, n per execution as in the evidence; D must be re-calibrated on other hardware. Evidence: %s.
""" % (F("timing_stub", "acc250"), L("timing_stub"), F("timing_stub", "cost"), F("timing_p3_single", "acc250"), L("timing_p3_single"), L("timing_deadline_real"),
       F("timing_250_real", "acc"), F("timing_250_real", "p"), F("timing_deadline_real", "acc"), F("timing_deadline_real", "base"), F("timing_deadline_real", "p"),
       F("timing_deadline_real", "p3"), F("timing_deadline_real", "alpha"), L("timing_deadline_cost"), F("timing_deadline_cost", "cost"), F("timing_deadline_cost", "cutoff"),
       F("timing_deadline_cost", "D_each"), F("deadline_default", "D_eq"), L("deadline_default"), C["timing_deadline_real"]["evidence"][0]))


def s7(sl):
    header(sl, "AUDIT INTEGRITY", "Chained, signed, countersigned, independently verified")
    steps = [("Hash chain", "each entry carries the previous entry's hash"), ("Signed checkpoints", "Ed25519 over the chain, kept in a reviewer vault"),
             ("Terminal checkpoint", "binds the final entry: truncation is detectable"), ("Countersignature", "reviewer signs the terminal checkpoint (Partial)"),
             ("Strict verifier", "separate program; pinned key and terminal hash")]
    x = 0.7
    for i, (t1, t2) in enumerate(steps):
        box(sl, x, 3.0, 3.5, 1.45, t1, [t2], line=NAVY if i != 3 else AMBER, tcol=NAVY if i != 3 else AMBER, fill=WHITE if i != 3 else AMBER_SOFT, tsize=16, ssize=12.5)
        if i < 4:
            arrow(sl, [(x + 3.5, 3.72), (x + 3.8, 3.72)], NAVY, 2.5)
        x += 3.78
    pa = term("t5_verify.png")
    pw, ph = pic_fit(sl, pa, 0.7, 4.75, 9.6, 4.3, border=NAVY)
    text(sl, 0.7, 4.75 + ph + 0.05, 9.6, 0.4, [[("LIVE ", {"bold": True, "color": GREEN}), ("recorded transcript, 12 Nov 2026: strict verify, then a one-field edit of a copy", {"color": SLATE})]], size=12)
    pb = term("t3_step7.png")
    pw2, ph2 = pic_fit(sl, pb, 10.6, 4.75, 8.7, 4.3, border=NAVY)
    text(sl, 10.6, 4.75 + ph2 + 0.05, 8.7, 0.4, [[("LIVE ", {"bold": True, "color": GREEN}), ("security_demo.sh step 7: a broker-key forgery and the stated limit", {"color": SLATE})]], size=12)
    text(sl, 0.7, 9.55, 18.6, 1.0, [[("Tamper suite (%s): " % L("tamper"), {"bold": True, "color": NAVY}),
                                     ("%s, each detected in %s; CLI %s, %s. " % (F("tamper", "categories"), F("tamper", "trials"), F("tamper", "genuine"), F("tamper", "tampered")), {}),
                                     ("Countersignature is Partial: ", {"bold": True, "color": AMBER}),
                                     ("it stops a broker-key forgery only while the reviewer key is off the broker host.", {})]],
         size=14, fill=MIST, line=LINE, shape=MSO_SHAPE.ROUNDED_RECTANGLE, radius=0.08, margin=0.14, anchor="m")
    footer(sl)
    notes_l(sl, """
AUDIT INTEGRITY, slide 7 (about 30 seconds)
The broker appends a digest of every decision to a hash chain, signs checkpoints with Ed25519 and copies them to a reviewer vault. At release it signs a terminal checkpoint that binds the last entry, so deleting entries from the end is detectable. New for the finale: the reviewer countersigns that terminal checkpoint with a separate key, and verify_cli can require both signatures.
Left terminal (LIVE, recorded on the presented code): strict verification of the P4 bundle with the key pinned and the countersignature required gives %s. Changing one field in a copy of the audit log gives %s.
Right terminal (LIVE, security_demo.sh step 7): a forger who holds the broker key and replaces every retained copy produces history that verifies on its own; with the reviewer countersignature required it is refused. The stated limit: a forger who holds both keys still succeeds, so the countersignature is Partial: it helps only when the reviewer key is on a different machine.
Tamper suite (%s): %s, each detected in %s; the CLI accepted %s and rejected %s. Evidence: %s.
""" % (F("verify_cli_live", "ok"), F("verify_cli_live", "bad"), L("tamper"), F("tamper", "categories"), F("tamper", "trials"), F("tamper", "genuine"), F("tamper", "tampered"), C["tamper"]["evidence"][0]))


def s8(sl):
    header(sl, "HARDENING ADDED FOR THE FINALE", "We closed the gaps a judge would press on, and measured each fix")
    items = [("F4 · user namespaces", ["containers never run as the key owner", "%s, %s, %s (%s)" % (F("f4_userns", "inside"), F("f4_userns", "hosts"), F("f4_userns", "errno"), L("f4_userns"))], BLUE),
             ("Re-encoded canaries", ["base64, hex, rot13, reversed, split and spelled-out forms of a foreign canary are withheld", "still missed: double encoding, ciphers, paraphrase"], ORANGE),
             ("Anomaly detectors", ["%s in the signed log (%s): denial bursts, forbidden sweeps, mailbox violations, canary near-misses, cut-offs, latency drift" % (F("detectors", "n"), L("detectors")), "thresholds fixed, not tuned on adversarial traffic"], NAVY),
             ("Capability tokens", ["run-scoped, operation-scoped, at most one hour; only the reviewer mints release rights", "no revocation list yet"], GREEN),
             ("Mailbox quotas", ["%s (%s); over a limit the tenant is cut off and the run seals incomplete" % (F("quotas", "text"), L("quotas"))], RED),
             ("Monitor side channel closed", ["participants see run-level events only until SEALED; no red-chosen string in the stream", "cache guard: cache_prompt=true refused unless an explicit unsafe opt-in"], SLATE)]
    x, y = 0.7, 3.0
    for i, (t1, b, col) in enumerate(items):
        card(sl, x, y, 6.0, 2.2, t1, b, col=col, tsize=16, bsize=13)
        x += 6.3
        if i % 3 == 2:
            x, y = 0.7, y + 2.4
    p = term("t4_f4_table.png")
    pw, ph = pic_fit(sl, p, 0.7, 7.75, 9.0, 2.55, border=NAVY)
    text(sl, 0.7, 7.75 + ph + 0.04, 9.0, 0.35, [[("LIVE ", {"bold": True, "color": GREEN}), ("recorded transcript, 12 Nov 2026: the F4 proof table (evaluation/p4_userns_proof.py)", {"color": SLATE})]], size=12)
    text(sl, 10.0, 7.85, 9.3, 2.7, [[("Also pinned: ", {"bold": True, "color": NAVY}), ("the sandbox base image by digest; pyproject and uv.lock corrected.", {})],
                                     [("Not done: ", {"bold": True, "color": RED}), ("gVisor or Kata (runsc not installed on the test host); key in a KMS or HSM.", {})],
                                     [("Anomaly panel: ", {"bold": True, "color": GREEN}), ("the Audit page of a real-model lab run shows each detector, its threshold and its rationale (walkthrough video).", {"color": SLATE})]],
         size=14, spacing=6)
    footer(sl)
    notes_l(sl, """
FINALE HARDENING, slide 8 (about 30 seconds; in the 3-minute version skip to the residual-risk slide)
Six changes since Round 2, each with tests and, where it matters, a live measurement:
F4: containers never run as the key owner. %s, %s, the key bind-mounted into a container gives %s (%s). Before, a container escape was key theft; now a host-user compromise still is.
Re-encoded canaries: the broker now withholds base64, hex, rot13, reversed, split and spelled-out forms of another run's canary. It still misses double encoding, other ciphers, homoglyphs and paraphrase. The detector is the second line; server-side isolation is the first.
Anomaly detectors: %s write alerts into the signed log (%s). Thresholds are fixed and were not tuned on adversarial traffic, so an attacker below every threshold is not flagged.
Capability tokens: run-scoped and operation-scoped, at most one hour, the operator cannot mint the right to release. No revocation list yet.
Mailbox quotas: %s (%s).
Monitor side channel (F3 in our analysis): participants see run-level events only until the run is SEALED.
Not done: gVisor or Kata (not installed on the test host), and a KMS or HSM for the key.
""" % (F("f4_userns", "inside"), F("f4_userns", "hosts"), F("f4_userns", "errno"), L("f4_userns"), F("detectors", "n"), L("detectors"), F("quotas", "text"), L("quotas")))


def s9(sl):
    header(sl, "DEPLOYABILITY", "Rootless, CPU only, offline, checked in CI, and a read-only public demo")
    cards_ = [("Rootless Podman", ["no root, no daemon; one Fedora laptop; the sandbox image pinned by digest"]),
              ("CPU only, offline", ["llama.cpp on CPU; the model and server binary checked by sha256; nothing downloaded at the venue"]),
              ("Checked, not trusted", ["release gates in CI on every push", "%s (%s); check_claims %s (%s)" % (F("tests", "passed"), L("tests"), F("check_claims", "total"), L("check_claims"))]),
              ("Public read-only demo", [DEMO_URL + ": browse evidence, verify a bundle, tamper with a disposable copy", "no operator session, no runs, no containers; rate-limited"])]
    y = 3.0
    for t1, b in cards_:
        card(sl, 0.7, y, 8.4, 1.62, t1, b, tsize=16, bsize=13.5)
        y += 1.77
    text(sl, 0.7, 10.1, 8.4, 0.5, [[("Why read-only: ", {"bold": True, "color": RED}), ("a live operator console on a public URL would expose run control; it stays loopback-only.", {})]], size=13)
    p1 = shot("09_public_overview_desktop.png")
    pw, ph = pic_fit(sl, p1, 9.6, 3.0, 7.0, 5.0, border=NAVY)
    p2 = shot("10_public_verify_phone.png")
    pic_fit(sl, p2, 16.85, 3.0, 2.45, 5.6, border=NAVY)
    text(sl, 9.6, 8.75, 9.7, 1.6, [[("SCREENSHOTS ", {"bold": True, "color": GREEN}), ("12 Nov 2026, the presented code run locally with AEGIS_PUBLIC_DEMO=1: degraded mode, header 'Public demo'; phone: bundle verify accepted.", {"color": SLATE})],
                                    [("The hosted site serves origin/main until P1–P4 are merged; the verify fix is in P1.", {"bold": True, "color": AMBER})]], size=12.5, spacing=4)
    footer(sl)
    notes_l(sl, """
DEPLOYABILITY, slide 9 (about 25 seconds)
Everything runs on one ordinary laptop: rootless Podman (no root, no daemon), a sandbox image pinned by digest, llama.cpp on CPU, and model files checked by sha256, so nothing has to be downloaded at the venue.
Checked, not trusted: the release gates run in CI on every push. On this branch: %s (%s); check_claims.py recomputes every quoted figure from the raw files, %s (%s).
The public demo at %s is read-only by design: anyone can browse the evidence, verify a bundle with the independent verifier, and tamper with a disposable copy to see it rejected. It has no operator session, cannot create runs, has no containers, and is rate-limited. A live operator console on a public URL would expose run control, so the live console stays on loopback.
The public demo runs on Render from main, so the verify fix from P1 is live there. The screenshots are of the presented code run locally in the same public mode.
""" % (F("tests", "passed"), L("tests"), F("check_claims", "total"), L("check_claims"), DEMO_URL))


def s10(sl):
    header(sl, "RESIDUAL RISKS", "What would still fail, stated before you ask")
    risks = [("Host compromise", "the signing key is a 0600 file of the host user: a kernel exploit that gains that user can forge evidence. Countersignature: Partial (reviewer key off-host only)."),
             ("Deadline D is host- and model-specific", "calibrated on one laptop for Qwen2.5-0.5B; elsewhere re-calibrate. Too short: more cut-offs. Too long: only latency."),
             ("No leak detected is not absence", "one classifier, one host; cache, memory-bandwidth and CPU-contention channels not measured; post-cut-off generation not measured as a channel."),
             ("Canary detector gaps", "double encoding, other bases, ciphers, homoglyphs, translation, paraphrase, a token split across replies."),
             ("Anomaly thresholds not tuned", "fixed, never trained on adversarial traffic: an attacker below every threshold is not flagged."),
             ("Capability tokens", "no revocation list; the API has no TLS (loopback only)."),
             ("Shared kernel", "containers share the host kernel; gVisor and Kata not tried."),
             ("Coverage", "one host; one model at full scale (0.5B) plus a reduced 1.5B run; CPU only; GPU and accelerator KV-cache isolation untested.")]
    x, y = 0.7, 3.0
    for i, (t1, t2) in enumerate(risks):
        text(sl, x, y, 9.1, 1.68, [[(t1, {"bold": True, "font": HEAD, "size": 17, "color": RED})], [(t2, {"size": 15})]], size=15,
             fill=RED_SOFT if i in (0, 2) else WHITE, line=RED if i in (0, 2) else LINE, shape=MSO_SHAPE.ROUNDED_RECTANGLE, radius=0.06, margin=0.14)
        y += 1.82
        if i == 3:
            x, y = 10.2, 3.0
    text(sl, 0.7, 10.3, 18.6, 0.4, "Source: docs/finale/P4_REPORT.md section 5 and aegislab/THREAT_MODEL.md section 10.", size=12.5, color=SLATE)
    footer(sl)
    notes_l(sl, """
RESIDUAL RISKS, slide 10 (about 30 seconds; never skip this slide, in any version of the talk)
Read the two highlighted ones aloud. First: host compromise. The evidence signing key is still a 0600 file of the host user. A kernel exploit that becomes that user can forge evidence. The reviewer countersignature only helps if the reviewer key lives on another machine, so we call it Partial. Second: "no leak detected" is not "no leak". It is one classifier on one host, and we did not measure cache, memory-bandwidth or CPU-contention channels.
The others: the deadline is calibrated for one host and one model; the canary detector misses double encodings and paraphrase; the anomaly thresholds were never tuned on adversarial traffic; capability tokens have no revocation list and the API has no TLS; containers share the kernel and we did not try gVisor; and our figures cover one host, one model at full scale plus a reduced 1.5B run, CPU only. GPU isolation is untested.
""")


def s11(sl):
    header(sl, "FUTURE SCOPE", "What we would build next, in the order the residual risks ask for it")
    items = [("Key custody", "signing key in a KMS or HSM, rotation, a transparency log for terminal checkpoints", "closes: host compromise", AMBER),
             ("Stronger sandbox", "gVisor or Kata containers, one VM per tenant for high-assurance runs", "closes: shared kernel", RED),
             ("GPU and accelerator isolation", "KV-cache and CUDA-context tests on a GPU server, multi-slot inference servers", "closes: coverage", BLUE),
             ("Semantic leak detection", "paraphrase- and translation-aware detectors next to the canary scan", "closes: detector gaps", ORANGE),
             ("Adversarially tuned detectors", "thresholds fitted on red-team traffic, with false-positive budgets", "closes: untuned thresholds", NAVY),
             ("Multi-party operation", "token revocation, TLS and SSO, reviewer on a separate machine by default", "closes: tokens, Partial countersignature", GREEN)]
    x, y = 0.7, 3.0
    for i, (t1, t2, t3, col) in enumerate(items):
        text(sl, x, y, 9.1, 2.0, [[(t1, {"bold": True, "font": HEAD, "size": 18, "color": col})], [(t2, {"size": 14.5})], [(t3, {"size": 13, "color": SLATE, "italic": True})]],
             size=14, fill=WHITE, line=LINE, shape=MSO_SHAPE.ROUNDED_RECTANGLE, radius=0.06, margin=0.16, spacing=3)
        y += 2.2
        if i == 2:
            x, y = 10.2, 3.0
    text(sl, 0.7, 9.75, 18.6, 0.7, [[("Not claimed: ", {"bold": True, "color": RED}), ("production readiness, a third-party audit, invulnerability, model robustness to prompt injection, any customer or certification.", {})]], size=14)
    footer(sl)
    notes_l(sl, """
FUTURE SCOPE, slide 11 (about 15 seconds; skip in the 3-minute version)
Each item answers one residual risk: key custody in a KMS or HSM with rotation and a transparency log; gVisor or Kata, or a VM per tenant; GPU and accelerator KV-cache isolation tests; paraphrase-aware leak detection; detector thresholds fitted on red-team traffic; and multi-party operation with token revocation, TLS, SSO and the reviewer on a separate machine.
We do not claim production readiness, a third-party audit, invulnerability, robustness of the model itself, or any customer or certification.
""")


def s12(sl):
    text(sl, 0.7, 4.75, 12.2, 0.45, "AEGISLAB · TECH MAVERICKS", size=20, bold=True, color=ORANGE, font=HEAD)
    text(sl, 0.7, 5.2, 12.4, 0.9, "Isolate, measure, prove", size=36, bold=True, color=NAVY, font=HEAD)
    members = [("Abdul Munaf Z", "Solution architect & integration engineer", ORANGE), ("Likhith Sai N", "Sandbox security & infrastructure engineer", BLUE),
               ("Sreeram Rajesh", "Product interface & evaluation engineer", GREEN)]
    y = 6.3
    for name, role, col in members:
        circle(sl, 0.7, y, 0.75, "".join(p[0] for p in name.split()[:2]), col, size=18)
        text(sl, 1.65, y - 0.05, 11.0, 0.9, [[(name, {"bold": True, "font": HEAD, "size": 21, "color": INK})], [(role, {"size": 16, "color": col, "bold": True})]], size=16)
        y += 1.1
    text(sl, 0.7, 9.65, 12.6, 1.0, [[("Code and evidence: ", {"bold": True}), (GH, {"bold": True, "color": NAVY, "font": "IBM Plex Mono", "size": 17})],
                                    [("Read-only demo: ", {"bold": True}), ("https://" + DEMO_URL, {"bold": True, "color": NAVY, "font": "IBM Plex Mono", "size": 17})]], size=17)
    text(sl, 13.2, 5.2, 6.2, 4.8, [[("Thank", {})], [("you!", {})]], size=150, font="Caveat", bold=True, color=INK, align="c", anchor="m")
    notes_l(sl, """
CLOSE, slide 12 (about 15 seconds)
AegisLab isolates the parties of an AI safety test, measures every boundary with controls that must leak, and proves the result with evidence a reviewer verifies offline. We showed what holds, what changed when we tested against a real model, and what would still fail.
Abdul Munaf Z, solution architect and integration engineer; Likhith Sai N, sandbox security and infrastructure engineer; Sreeram Rajesh, product interface and evaluation engineer.
Code and evidence: github.com/Invinciblx777/HIH. Read-only demo: aegislab-demo.onrender.com. Thank you; we are happy to take questions.
""")


# ------------------------------------------------------------------------------------------------ assembly
def duplicate(prs, src):
    new = prs.slides.add_slide(src.slide_layout)
    for shp in list(new.shapes):
        shp._element.getparent().remove(shp._element)
    for shp in src.shapes:
        el = copy.deepcopy(shp._element)
        for blip in el.iter(qn("a:blip")):
            rid = blip.get(qn("r:embed"))
            if rid:
                blip.set(qn("r:embed"), new.part.relate_to(src.part.related_part(rid), RT.IMAGE))
        new.shapes._spTree.append(el)
    return new


def build(out):
    prs = Presentation(str(TEMPLATE))
    slides = list(prs.slides)
    content = slides[1]
    extra = [duplicate(prs, content) for _ in range(4)]
    lst = prs.slides._sldIdLst
    ids = list(lst)
    closing = ids[7]
    lst.remove(closing)
    lst.append(closing)
    slides = list(prs.slides)
    for s in slides:
        clear(s)
    for f, s in zip([s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12], slides):
        f(s)
    for s in slides:
        for st in list(s.shapes._spTree.iter(qn("p:style"))):
            st.getparent().remove(st)
    prs.core_properties.title = "Tech Mavericks · AegisLab · Hack in Hills ’26 Track 04 · Grand Finale"
    prs.core_properties.author = "Tech Mavericks"
    prs.save(out)
    print(out, len(slides), "slides")


if __name__ == "__main__":
    claims, media, out = sys.argv[1:4]
    C.update(json.loads(Path(claims).read_text())["claims"])
    MEDIA = Path(media)
    build(out)
