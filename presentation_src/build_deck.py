"""Build Tech_Mavericks_AegisLab_Submission.pptx (eight slides) on the official Hack in Hills '26 template.

    python build_deck.py official_template.pptx claims.json validation_results.json terminal_dir out.pptx

Keeps the template's eight slides, banner, logos, mountain photo, fonts and 20 x 11.25 in size; template placeholder text is removed and
native, editable shapes are drawn on top. Every figure on a slide is formatted from claims.json, which `evaluation/check_presentation.py
--dump-claims` recomputes from the raw evidence (the token formats are shared with the checker, so slide text and checker cannot drift).
Terminal images in terminal_dir are renders of the real transcript recorded by `scripts/judge_demo.sh --record`.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "aegislab" / "evaluation"))

from deckkit import *  # noqa: F401,F403,E402
from deckkit import _font  # noqa: E402,F401
from PIL import Image  # noqa: E402
from check_presentation import TOKENS  # noqa: E402

D = {}
V = {}
TERM = Path(".")


def T(key, i=None):
    t = TOKENS[key](D)
    return t if i is None else t[i]


def fnum(x):
    return "{:,}".format(x)


def pic_h(path, w):
    im = Image.open(path)
    return w * im.size[1] / im.size[0]


def bar_row(sl, x, y, w, title, k, nden, color, tag=None, sub=None, track_w=None, size=17):
    """One horizontal bar: title above, bar track with fill k/nden, count label on the right."""
    tw = track_w or (w - 2.2)
    text(sl, x, y, w, 0.36, [[(title, {"bold": True, "size": size})]], size=size)
    by = y + 0.4
    text(sl, x, by, tw, 0.32, "", fill=SLATE_SOFT, shape=MSO_SHAPE.RECTANGLE)
    if k:
        text(sl, x, by, max(tw * k / nden, 0.06), 0.32, "", fill=color, shape=MSO_SHAPE.RECTANGLE)
    text(sl, x + tw + 0.15, by - 0.1, 2.1, 0.5, [[("%d / %d" % (k, nden), {"bold": True, "font": HEAD, "size": 24, "color": color})]], size=24, anchor="m")
    if sub:
        text(sl, x, by + 0.36, w, 0.3, sub, size=14, color=SLATE)
    if tag:
        text(sl, x + tw - 2.0, y - 0.02, 2.0, 0.36, [[(tag, {"bold": True})]], size=13, color=color, align="r", anchor="m")


# ------------------------------------------------------------------ slides
def s1(sl):
    text(sl, 0.7, 4.75, 9.4, 0.45, "TEAM", size=22, bold=True, color=ORANGE, font=HEAD)
    text(sl, 0.7, 5.2, 9.4, 1.0, "Tech Mavericks", size=54, bold=True, color=NAVY, font=HEAD)
    text(sl, 0.7, 6.3, 9.6, 0.6, [[("AegisLab", {"bold": True, "color": ORANGE, "font": HEAD, "size": 30})]], size=26)
    text(sl, 0.7, 6.9, 9.6, 0.5, "Controlled, measurable, adversarial AI testing infrastructure", size=23, bold=True, color=INK)
    text(sl, 0.7, 7.55, 9.1, 1.75, [[("The challenge: ", {"bold": True, "color": NAVY}),
                                    ("red-team attacks, blue-team defences and the model under test must coexist without leaking protected "
                                     "state, or the evaluation itself becomes invalid. AegisLab keeps them apart, measures what crosses, and "
                                     "hands the reviewer evidence that can be checked.", {})]], size=20, color=SLATE)
    text(sl, 0.7, 9.55, 9.4, 1.0, [[("Hack in Hills ’26 · Track 04", {"bold": True, "color": INK})],
                                   [("Securing Adversarial AI Safety Testing Infrastructure (Bayora)", {"color": SLATE})]], size=18)
    members = [("Abdul Munaf Z", "Solution architect & integration engineer",
                "Threat model, trusted broker, API integration, overall demonstration", ORANGE),
               ("Likhith Sai N", "Sandbox security & infrastructure engineer",
                "Workload isolation, network policies, identities, resource controls, deployment", BLUE),
               ("Sreeram Rajesh", "Product interface & evaluation engineer",
                "Website, run reports, audit verification, test harness, presentation assets", GREEN)]
    y = 4.85
    for name, role, resp, col in members:
        card = text(sl, 10.6, y, 8.7, 1.72, "", fill=WHITE, line=LINE, shape=MSO_SHAPE.ROUNDED_RECTANGLE, radius=0.1)
        card.name = "Member " + name
        circle(sl, 10.9, y + 0.43, 0.86, "".join(p[0] for p in name.split()[:2]), col, size=20)
        text(sl, 12.05, y + 0.2, 7.1, 1.4, [[(name, {"bold": True, "font": HEAD, "size": 24, "color": INK})],
                                            [(role, {"bold": True, "size": 17, "color": col})],
                                            [(resp, {"size": 16, "color": SLATE})]], size=16)
        y += 1.9
    text(sl, 10.6, 10.6, 8.7, 0.35, "Roles are the responsibilities each member owns in this project.", size=14, color=SLATE)
    notes(sl, """
OPENING (about 15 seconds on stage; the video opens with the problem)
We are Tech Mavericks. Our project is AegisLab, built for Track 04: Securing Adversarial AI Safety Testing Infrastructure, set by Bayora.

The problem in one sentence: red-team attacks, blue-team defences and the model under test have to run side by side, and none of them may learn the others' protected state. If they do, the evaluation result is no longer a valid safety finding.

What AegisLab is: controlled, measurable, adversarial AI testing infrastructure. Controlled: sandboxes with no network and one brokered path. Measurable: every boundary is tested with recorded attacks, controls and sample sizes. Adversarial: we attacked our own broker and ran a real local model through the same checks.

Team (proposed responsibilities, not claims of prior expertise): Abdul Munaf Z, solution architect and integration engineer; Likhith Sai N, sandbox security and infrastructure engineer; Sreeram Rajesh, product interface and evaluation engineer.

What is real and what is not: a working local prototype (Python control plane, rootless Podman sandboxes, deterministic stub model, optional real-model adapter, web console, verifier) and recorded experiments. Nothing is deployed publicly and no URL is published. Everything labelled proposed is not built.
""")


def s2(sl):
    header(sl, "THREAT MODEL", "Who must not see what, and where each rule is enforced")
    # untrusted tenants
    frame(sl, 0.7, 3.0, 5.6, 7.55, RED, fill=RED_SOFT, name="Untrusted tenants")
    text(sl, 0.95, 3.1, 5.2, 0.4, "UNTRUSTED WORKLOADS", size=15, bold=True, color=RED, font=HEAD)
    text(sl, 0.95, 3.45, 5.2, 0.35, "no network · rootless · read-only root", size=14, color=SLATE)
    box(sl, 1.0, 4.0, 5.0, 1.45, "Red team", ["attack payloads, private pack"], line=RED, tcol=RED, tsize=22, ssize=17)
    box(sl, 1.0, 6.0, 5.0, 1.45, "Blue defence runner", ["frozen defence configuration"], line=BLUE, tcol=BLUE, tsize=22, ssize=17)
    box(sl, 1.0, 8.0, 5.0, 1.55, "Model worker", ["session state · prompt cache"], line=SLATE, tsize=22, ssize=17)
    # forbidden flows between tenants
    arrow(sl, [(3.5, 5.45), (3.5, 6.0)], RED, 3, dash=True, both=True)
    circle(sl, 3.27, 5.48, 0.46, "F1", RED, size=13)
    circle(sl, 5.75, 7.75, 0.46, "F3", RED, size=13)
    text(sl, 1.0, 9.65, 5.0, 0.7, "F3 · session N must not read session N+1", size=14, color=RED, bold=True, anchor="m")
    # trusted control plane
    frame(sl, 7.3, 3.0, 5.3, 7.55, NAVY, fill=MIST, name="Trusted control plane")
    text(sl, 7.5, 3.1, 4.9, 0.4, "TRUSTED CONTROL PLANE (HOST)", size=15, bold=True, color=NAVY, font=HEAD)
    box(sl, 7.6, 4.0, 4.7, 2.5, "Trusted broker", ["identity = which mailbox", "checks commitments", "withholds foreign canaries"],
        fill=ORANGE_SOFT, line=ORANGE, line_w=3, tsize=22, ssize=17)
    box(sl, 7.6, 7.0, 4.7, 1.7, "Audit · sealed store · gate", ["hash chain · signed checkpoints"], line=NAVY, tsize=20, ssize=17)
    box(sl, 7.6, 9.0, 4.7, 1.2, "Signing key", ["never reachable by tenants"], line=AMBER, tcol=AMBER, fill=AMBER_SOFT, tsize=19, ssize=16)
    # allowed flows (green) tenant -> broker
    for yy in (4.7, 5.15, 6.7):
        pass
    arrow(sl, [(6.0, 4.72), (7.6, 4.72)], GREEN, 3, both=True)
    arrow(sl, [(6.0, 6.72), (6.9, 6.72), (6.9, 5.5), (7.6, 5.5)], GREEN, 3, both=True)
    arrow(sl, [(6.0, 8.78), (6.9, 8.78), (6.9, 6.0), (7.6, 6.0)], GREEN, 3, both=True)
    text(sl, 6.1, 4.2, 1.3, 0.4, "mailbox", size=14, bold=True, color=GREEN, align="c", fill=WHITE, shape=MSO_SHAPE.RECTANGLE)
    arrow(sl, [(9.95, 6.5), (9.95, 7.0)], NAVY, 3)
    # tenants -> signing key / audit (forbidden)
    arrow(sl, [(6.0, 9.9), (7.6, 9.6)], RED, 3, dash=True)
    circle(sl, 6.45, 9.65, 0.46, "F4", RED, size=13)
    # right column: reviewer + observer
    box(sl, 13.2, 4.0, 2.55, 2.5, "Reviewer", ["releases,", "verifies"], line=GREEN, tcol=GREEN, tsize=20, ssize=16)
    box(sl, 13.2, 7.0, 2.55, 1.7, "Observer", ["redacted", "events only"], line=SLATE, tsize=20, ssize=16)
    arrow(sl, [(12.3, 7.85), (13.2, 7.85)], SLATE, 2.5, dash=True)
    arrow(sl, [(12.3, 5.25), (13.2, 5.25)], GREEN, 3)
    text(sl, 12.15, 4.55, 1.2, 0.4, "release", size=13, bold=True, color=GREEN, align="c", fill=WHITE, shape=MSO_SHAPE.RECTANGLE)
    arrow(sl, [(13.2, 7.2), (12.3, 6.2)], RED, 3, dash=True)
    circle(sl, 12.35, 6.55, 0.46, "F2", RED, size=13)
    # forbidden flow F5 label
    # legend column
    lx = 16.1
    text(sl, lx, 3.0, 3.4, 0.4, "FORBIDDEN FLOWS", size=15, bold=True, color=RED, font=HEAD)
    items = [("F1", "Red reads the defence rules", "config mounted only into the defence runner, read-only"),
             ("F2", "Anyone reads results before release", "sealed store, role gate: 403 until RELEASED"),
             ("F3", "One session reads another's data", "one stateless message per request, cache off"),
             ("F4", "A tenant reaches the broker's files or key", "no-follow mailbox I/O, separate mounts"),
             ("F5", "A record is changed unnoticed", "hash chain, signed terminal checkpoint")]
    y = 3.45
    for tag, t1, t2 in items:
        circle(sl, lx, y + 0.05, 0.42, tag, RED, size=12)
        text(sl, lx + 0.55, y - 0.04, 2.85, 1.1, [[(t1, {"bold": True, "size": 15})], [(t2, {"size": 13, "color": SLATE})]], size=15)
        y += 1.1
    rm = D["role_matrix"]
    text(sl, 13.2, 9.25, 6.3, 1.3, [[("Tested, not assumed: ", {"bold": True, "color": NAVY}),
                                     ("%d role × operation × state attempts: %d / %d expected denials denied, %d unexpectedly permitted."
                                      % (rm["attempted"], rm["denied"], rm["expected_deny"], rm["unexpectedly_permitted"]), {})]],
         size=16, color=INK, fill=WHITE, line=LINE, shape=MSO_SHAPE.ROUNDED_RECTANGLE, radius=0.08, margin=0.15, anchor="m")
    text(sl, 7.3, 10.62, 12.2, 0.4, [[("━ permitted via the broker      ", {"color": GREEN, "bold": True}),
                                      ("┅ forbidden (each one is attacked in a test)      ", {"color": RED, "bold": True}),
                                      ("amber: trusted, not defended", {"color": AMBER, "bold": True})]], size=14)
    notes(sl, """
THREAT MODEL (about 45 seconds)
Parties: a red team holding attack payloads, a blue team holding a frozen defence configuration, a model worker with session and cache state, a reviewer who must trust the result, and an observer with a redacted view. One trusted broker sits between them.

Forbidden flows (F1 to F5), each one attacked in a recorded test:
F1: red reading the defence rules. The frozen config is mounted only into the defence runner, read-only, and its digest is attested.
F2: anyone reading results before release. Sealed store and a server-side role gate: 403 for observer, red, blue and a reviewer before RELEASED.
F3: one session reading another's data. One stateless user message per request, no session identifier, a fresh worker per run for the stub, cache_prompt false for the real model, and the broker withholds another run's canary from model output.
F4: a tenant reaching the broker's files or the signing key. Mailbox I/O is descriptor-relative with no-follow; in/ and out/ are separate mounts a tenant cannot rename.
F5: a record changed unnoticed. Hash chain, signed terminal checkpoint, copies the reviewer keeps, and a separate strict verifier.

Where enforcement happens: container flags (no network, read-only root, all capabilities dropped, no-new-privileges, pids/memory/CPU limits, SELinux labels), the broker, the API role gate, and the verifier.

What is trusted and not defended (amber): the broker and its signing key; the host kernel and container runtime.

Evidence: role matrix evidence/phase2_2026-10-23/role_matrix_extended.json: 560 attempted, 419 of 419 expected denials denied, 141 of 141 expected successes succeeded, 0 unexpectedly permitted, 0 secret-marker hits. Not covered: operations that launch containers, run-scoped identities (tokens are global per role).

Likely question: why not just separate Docker containers? Because you also need a single mediated channel with identity bound to the channel, a frozen config, committed attacks, a model-state check and evidence an outsider can verify.
""")


def s3(sl):
    header(sl, "ARCHITECTURE", "Five enforcement layers around one trusted broker")
    # tenants
    box(sl, 0.7, 3.1, 3.5, 1.5, "Red sandbox", ["private attack pack"], fill=RED_SOFT, line=RED, tcol=RED, tsize=20, ssize=16)
    box(sl, 0.7, 5.0, 3.5, 1.5, "Blue defence runner", ["frozen config, read-only"], fill=BLUE_SOFT, line=BLUE, tcol=BLUE, tsize=19, ssize=16)
    box(sl, 0.7, 6.9, 3.5, 2.05, "Model worker", ["stub: fresh container per run", "real model: loopback server"], fill=SLATE_SOFT, line=SLATE, tsize=20, ssize=15)
    text(sl, 0.7, 9.0, 3.5, 0.4, "no network · read-only root", size=12, color=SLATE, align="c")
    # control plane
    frame(sl, 5.3, 3.0, 5.2, 6.15, NAVY, fill=MIST, name="Trust boundary")
    text(sl, 5.5, 3.08, 4.8, 0.4, "TRUSTED CONTROL PLANE (HOST)", size=14, bold=True, color=NAVY, font=HEAD)
    box(sl, 5.6, 3.6, 4.6, 2.0, "Trusted broker", ["identity bound to mailbox", "routes · checks · withholds"], fill=AMBER_SOFT, line=AMBER, line_w=3, tsize=21, ssize=16)
    box(sl, 5.6, 6.0, 2.2, 1.45, "Audit chain", ["signed checkpoints"], line=NAVY, tsize=17, ssize=14)
    box(sl, 8.0, 6.0, 2.2, 1.45, "Result gate", ["SEALED + verified"], line=GREEN, tsize=17, ssize=14)
    box(sl, 5.6, 7.75, 4.6, 1.2, "Signing key", ["held by the broker's user"], line=AMBER, fill=AMBER_SOFT, tcol=AMBER, tsize=17, ssize=14)
    # arrows tenants <-> broker
    arrow(sl, [(4.2, 3.85), (5.6, 3.85)], RED, 3, both=True)
    arrow(sl, [(4.2, 5.75), (4.9, 5.75), (4.9, 4.6), (5.6, 4.6)], BLUE, 3, both=True)
    arrow(sl, [(4.2, 7.9), (4.9, 7.9), (4.9, 5.2), (5.6, 5.2)], SLATE, 3, both=True)
    text(sl, 4.3, 3.4, 1.3, 0.35, "mailbox", size=13, bold=True, color=RED, align="c")
    arrow(sl, [(6.7, 5.6), (6.7, 6.0)], NAVY, 3)
    arrow(sl, [(7.8, 6.72), (8.0, 6.72)], GREEN, 3)
    # outside: reviewer vault, verifier, observer
    box(sl, 11.2, 3.1, 2.7, 1.5, "Reviewer vault", ["signed checkpoints kept"], line=NAVY, tsize=17, ssize=14)
    box(sl, 11.2, 5.0, 2.7, 1.5, "Strict verifier", ["separate program", "bundle + vault"], line=GREEN, tcol=GREEN, tsize=17, ssize=14)
    box(sl, 11.2, 6.9, 2.7, 1.5, "Observer view", ["redacted events"], line=SLATE, tsize=17, ssize=14)
    arrow(sl, [(10.5, 3.85), (11.2, 3.85)], NAVY, 2.5, dash=True)
    arrow(sl, [(12.55, 4.6), (12.55, 5.0)], GREEN, 3)
    arrow(sl, [(10.5, 7.65), (11.2, 7.65)], SLATE, 2.5, dash=True)

    # shared host bar
    text(sl, 0.7, 9.45, 13.2, 1.1, [[("RESIDUAL TRUST (not defended)  ", {"bold": True, "font": HEAD, "size": 15}),
                                     ("shared host kernel · container runtime · the trusted broker and its signing key", {"size": 17})]],
         size=17, color=AMBER, fill=AMBER_SOFT, line=AMBER, shape=MSO_SHAPE.ROUNDED_RECTANGLE, radius=0.12, margin=0.2, anchor="m")
    for n_, (x, y) in zip("12345", [(0.55, 2.95), (9.95, 3.45), (9.95, 5.85), (0.55, 6.8), (11.05, 4.9)]):
        circle(sl, x, y, 0.5, n_, ORANGE, size=15)
    # fix circle on layer 2 + 3 locations: 1 tenants, 2 broker, 3 identity (blue), 4 model, 5 verifier
    # layers legend
    lx = 14.4
    text(sl, lx, 3.0, 5.1, 0.4, "WHAT EACH LAYER ENFORCES", size=15, bold=True, color=NAVY, font=HEAD)
    layers = [("1", "Container limits", "rootless Podman, --network none, read-only root, no capabilities, no-new-privileges, pids/memory/CPU caps"),
              ("2", "Controlled broker path", "file mailbox; in/ and out/ separate mounts; no-follow descriptor I/O; size and type checks"),
              ("3", "Role and run identity", "identity from the mailbox, not the message; server-side role gate; release only when SEALED and verified"),
              ("4", "Model and session isolation", "one user message per request; no session id; cache_prompt false; foreign canaries withheld"),
              ("5", "Audit and verification", "hash chain, signed terminal checkpoint, retained copies, independent strict verifier")]
    y = 3.5
    for k_, t1, t2 in layers:
        circle(sl, lx, y + 0.04, 0.42, k_, ORANGE, size=14)
        text(sl, lx + 0.55, y - 0.05, 4.55, 1.4, [[(t1, {"bold": True, "size": 16})], [(t2, {"size": 14, "color": SLATE})]], size=15)
        y += 1.38
    notes(sl, """
SECURITY ARCHITECTURE (about 60 seconds). Walk left to right.

Tenants (left): the red sandbox, the blue defence runner and the model worker are separate rootless Podman containers with --network none, a read-only root filesystem, all capabilities dropped, no-new-privileges, pids/memory/CPU limits and a private SELinux label (verified from inside and with podman inspect: evidence/phase2_2026-10-23/effective_container_settings.json). Layer 1.

Broker (centre): the only path out of a sandbox is a file mailbox. in/ and out/ are separate mount points, so a tenant can fill them but cannot rename or replace them; the broker opens them through directory descriptors with no-follow and creates reply files with O_EXCL under unpredictable names. Layer 2. Identity comes from which mailbox a message arrived in, never from a field in the message; the API checks roles server-side and the result gate opens only when the run is SEALED, the chain verifies and a reviewer asks. Layer 3.

Model worker: in the stub path it is a fresh container per run. In the real-model path there is no AegisLab-managed worker: the model is whatever sits behind a loopback URL, reached only by the broker's adapter, which sends one user message per request, no session or run identifier, cache_prompt false, and withholds another run's canary or a control-plane secret from the output. Layer 4. Honest note: for the real model, state isolation also depends on the inference server honouring cache_prompt (tested for llama.cpp) and on the operator.

Audit (centre and right): the broker appends digests (never payloads) to a hash-chained log, signs checkpoints, and writes the checkpoints to a reviewer vault. At release it signs a terminal checkpoint that binds the final entry. A separate verifier program checks chain, checkpoints and terminal state. Layer 5.

Residual trust (amber): the broker and its signing key, and the shared host kernel and container runtime. A compromised broker signs false but internally consistent records (test P2A20). A signing-key holder who replaces every retained copy defeats the scheme unless the reviewer recorded the terminal hash independently (test P2A11, --expect-terminal-hash). Tenant processes run as the same host user as the control plane in this prototype; separation rests on the sandbox, not on Unix users.

Stack: Python control plane (FastAPI), rootless Podman with crun, Ed25519 and SHA-256, vanilla JS console, JSON files. Local API on loopback only; no TLS, rate limit or request-body limit.
""")


def s4(sl):
    header(sl, "ADVERSARIAL DEMONSTRATION", "A hostile sandbox plants a symlink and a FIFO in the broker's mailbox")
    rows = [("THREAT", "Tenant code turns the broker's reply write into an overwrite of the audit log, or hangs the broker.", RED),
            ("PROTECTED", "audit.jsonl (the hash-chained run log) and the broker's availability.", NAVY),
            ("ATTEMPT", "Real rootless container, no network, read-only root: plant a symlink and a FIFO at guessed temp names; rename or remove the mailbox directory.", ORANGE),
            ("RESULT", "Planted entries ignored; replies delivered as regular files; victim file intact; nothing created outside; the broker never blocked.", GREEN),
            ("TESTS", "P2B01 · P2B03 · P2B05 · P2B32 · P2C01 · P2C02, all in the suite (%s passed)." % V["tests_passed"], BLUE)]
    y = 3.0
    for k_, t_, col in rows:
        text(sl, 0.7, y, 1.9, 0.9, [[(k_, {"bold": True, "font": HEAD, "size": 15})]], size=15, color=WHITE, fill=col, align="c", anchor="m",
             shape=MSO_SHAPE.ROUNDED_RECTANGLE, radius=0.12)
        text(sl, 2.8, y - 0.02, 6.9, 1.2, t_, size=17, color=INK, anchor="m")
        y += 1.12
    text(sl, 0.7, 8.75, 9.0, 1.75, [[("HISTORICAL · before the fix  ", {"bold": True, "color": AMBER, "font": HEAD, "size": 14})],
                                    [("The same attack on the Phase 1 broker made it overwrite the audit log: ", {"size": 17}),
                                     ("victim audit.jsonl intact: False", {"bold": True, "size": 17, "color": RED}),
                                     (" (recorded 23 Oct, evidence/phase2_2026-10-23/before_fix/11_poc_mailbox.txt). Found by our own Phase 2 attack, then fixed.", {"size": 17})]],
         size=17, fill=AMBER_SOFT, line=AMBER, shape=MSO_SHAPE.ROUNDED_RECTANGLE, radius=0.06, margin=0.18, anchor="m")
    p = TERM / "term_mailbox.png"
    w = 8.4
    picture(sl, p, 10.9, 3.0, w=w, border=NAVY)
    ph = pic_h(p, w)
    text(sl, 10.9, 3.0 + ph + 0.1, 8.4, 0.7, [[("RECORDED ", {"bold": True, "color": GREEN}),
                                                ("live run of scripts/judge_demo.sh, step 3 · stub model · current code · 23 Oct 2026", {"color": SLATE})]], size=14)
    text(sl, 10.9, 3.0 + ph + 0.8, 8.4, 0.95, [[("Also blocked: ", {"bold": True, "color": NAVY}),
                                                ("%d / %d replayed model-generated release messages were denied by the gate (real-model run, E4)."
                                                 % (D["e4_gate_denied"], D["e4_gate_attempts"]), {})]],
         size=16, fill=WHITE, line=LINE, shape=MSO_SHAPE.ROUNDED_RECTANGLE, radius=0.08, margin=0.15, anchor="m")
    notes(sl, """
ADVERSARIAL DEMONSTRATION (about 60 seconds; live demo: scripts/judge_demo.sh, step 3)
Threat: code inside a tenant sandbox attacks the broker's own mailbox. The broker has to write replies into a directory the tenant can write to.

What we found in our own Phase 2 attack: on the Phase 1 broker, a symlink planted at the broker's predictable temporary name made the broker write its reply through the link and overwrite the run's audit log (shown from a real hardened container). Replacing the mailbox directory with a symlink redirected every later write. A FIFO at the temporary name blocked the broker forever. These were real defects, five of thirteen Phase 2 findings were HIGH.

Fix (code in aegis/runs.py): in/ and out/ are separate mount points the tenant cannot rename or remove; the broker opens the mailbox through a directory descriptor with no-follow, creates the reply with O_CREAT|O_EXCL|O_NOFOLLOW|O_NONBLOCK under an unpredictable name, and renames it into place, replacing whatever the tenant left at the final name.

What the recording shows (genuine output, current code, stub model): inside the sandbox the symlink and the FIFO are created successfully (the tenant can write its own mailbox) while renaming or removing the mailbox directory is refused (errno 30, the root filesystem is read-only). The broker then writes two replies: both arrive as regular files, the victim file outside the mailbox is intact, nothing is created outside, and the writes finish in about a millisecond instead of blocking.

The amber box is HISTORICAL: it quotes the recorded result from the Phase 1 broker, not a re-run. We cannot re-run the old code from the current tree.

Regression tests (all in the suite): P2B01, P2B02, P2B05, P2B06 (symlink, hard link, directory replacement), P2B03 and P2B32 (FIFO), P2C01 and P2C02 (from inside a real container). They were run against the unmodified Phase 1 code first and failed there.

Also on this slide: 282 of 282 replayed model-generated gate messages were denied (experiment E4): text produced by the real model was replayed to the mailbox and API as if a malicious red agent forwarded it; none changed run state.

Limits: devices (character/block special files) cannot be created unprivileged and were not tested; the HTTP layer was tested only on loopback; a compromised broker or kernel escape is out of scope.
""")


def s5(sl):
    header(sl, "REAL-MODEL EVIDENCE", "Real model: no cross-session leak seen, and the controls show it could")
    chip(sl, 0.7, 2.98, "real model · not the stub", WHITE, NAVY, size=14)
    text(sl, 4.75, 2.95, 8.0, 0.45, "Qwen2.5-0.5B Q4_K_M · llama.cpp on CPU · loopback only", size=16, color=SLATE, anchor="m")
    # panel A
    text(sl, 0.7, 3.5, 12.2, 0.4, "A · DIRECT ADAPTER  (16 sessions per cell, 10 probe wordings per session)", size=15, bold=True, color=NAVY, font=HEAD)
    e1i, e1n, e1h, e1g = D["e1_iso"], D["e1_neg"], D["e1_hist"], D["e1_gw"]
    bar_row(sl, 0.7, 3.95, 12.2, "Isolation: %d cells, fresh and reused server, cache on and off" % e1i["cells"], e1i["leak_sessions"], e1i["sessions"], GREEN,
            sub="sessions that recovered another session's canary · %s trials" % fnum(e1i["trials"]))
    bar_row(sl, 0.7, 5.03, 12.2, "Negative control: nothing planted", e1n["leak_sessions"], e1n["sessions"], GREEN, sub="%s trials" % fnum(e1n["trials"]))
    bar_row(sl, 0.7, 6.11, 12.2, "Positive control: history shared on purpose", e1h["leak_sessions"], e1h["sessions"], ORANGE, tag="MUST LEAK", sub="%d of %d trials leaked" % (e1h["leaks"], e1h["trials"]))
    bar_row(sl, 0.7, 7.19, 12.2, "Positive control: context-sharing gateway", e1g["leak_sessions"], e1g["sessions"], ORANGE, tag="MUST LEAK", sub="%d of %d trials leaked; the first session cannot leak by construction" % (e1g["leaks"], e1g["trials"]))
    # panel B
    text(sl, 0.7, 8.5, 12.2, 0.4, "B · FULL PIPELINE  (broker + rootless sandboxes + real model, 12 attacks per run)", size=15, bold=True, color=NAVY, font=HEAD)
    e2i, e2n, e2g = D["e2_iso"], D["e2_neg"], D["e2_gw"]
    cols = [("Isolation runs", e2i["runs_leaking"], e2i["runs"], GREEN, "%d attacks" % e2i["attacks"]),
            ("Negative control", e2n["runs_leaking"], e2n["runs"], GREEN, "nothing planted"),
            ("Gateway control", e2g["runs_leaking"], e2g["runs"], ORANGE, "%d withheld, %d reached red" % (e2g["withheld"], e2g["red"]))]
    x = 0.7
    for t_, k_, n_, col, sub in cols:
        text(sl, x, 9.0, 3.95, 1.6, [[(t_, {"bold": True, "size": 16})], [("%d / %d runs" % (k_, n_), {"bold": True, "font": HEAD, "size": 26, "color": col})],
                                      [("foreign canary in raw model output · " + sub, {"size": 13, "color": SLATE})]], size=16, fill=WHITE, line=col,
             shape=MSO_SHAPE.ROUNDED_RECTANGLE, radius=0.08, margin=0.14, anchor="m")
        x += 4.12
    # right: read carefully
    text(sl, 13.3, 3.0, 6.2, 7.6, [
        [("READ THIS WITH THE LIMITS", {"bold": True, "font": HEAD, "color": NAVY, "size": 15})],
        [("", {"size": 6})],
        [("Not proof of zero. ", {"bold": True}), ("One-sided 95%% upper bound: %s of sessions (%s of trials), for this probe set, model and server." % (T("e1_bound_sessions", 0), T("e1_bound_trials", 0)), {})],
        [("", {"size": 6})],
        [("Weak probes. ", {"bold": True}), ("%s (%s) stayed silent even when context was shared on purpose; their zeros carry no weight." % (T("e1_silent", 0), T("e1_silent", 1)), {})],
        [("", {"size": 6})],
        [("What it tests. ", {"bold": True}), ("Application-level session isolation in this setup. Not GPU memory, accelerator KV-cache or hardware side channels: untested.", {})],
        [("", {"size": 6})],
        [("Injection. ", {"bold": True}), ("%d attacks, 0 protected values in red-visible output or monitoring: an information-flow result, not model robustness." % D["e4_attacks"], {})],
        [("", {"size": 6})],
        [("Failure handling. ", {"bold": True}), ("%s model-outage checks hold." % T("e5", 0), {})],
    ], size=17, color=INK, fill=WHITE, line=LINE, shape=MSO_SHAPE.ROUNDED_RECTANGLE, radius=0.04, margin=0.25)
    notes(sl, """
REAL-MODEL EVIDENCE (about 60 seconds). This slide shows precomputed results from the saved Phase 3 runs, not a live inference.

Setup: Qwen2.5-0.5B-Instruct Q4_K_M on a CPU-only llama.cpp server (build 11819) bound to 127.0.0.1 with a random port and key, temperature 0, 48 max tokens. The deterministic stub is the default everywhere else.

Panel A (experiment E1, run P3-20261023T084629Z-E1_canary_matrix): a session plants a random canary, then ten probe wordings try to recover it from a context that does not share it. Seven isolation cells (reused server cache off, reused server cache on, three orderings including concurrent; fresh server per session): 0 of 104 sessions, 0 of 1,040 trials. Negative control (nothing planted): 0 of 32 sessions, 0 of 320 trials. Positive controls: history shared on purpose leaked in 16 of 16 sessions; a gateway that hands other sessions' messages to the model leaked in 13 of 16. This is how we know a zero means something: the same probes, detector and model do recover a canary when context is shared.

Panel B (experiment E2): the whole pipeline with the real model. 0 of 26 isolation runs (312 attacks) had a foreign canary in raw model output, and 0 reached red. Negative control: 0 of 4 runs. Gateway control: 2 of 4 runs had a foreign canary in model output; the broker withheld 15 attacks and 0 reached red.

How do you know it is isolation and not refusal? The detector looks for the planted token, its digits and fragments in the output; the controls show the probes do elicit it when context is shared; and the negative control shows the detector does not fire on coincidence.

What the numbers do not say: zero observed leaks in a finite experiment do not prove zero risk. Upper bounds: 2.84% of sessions, 0.29% of trials (the per-trial figure treats trials as independent, so it is the weaker bar). Only one 0.5B model and ten probe wordings were tested. Three probes (Q01, Q08, Q10) stayed silent even in the shared-context control, so their zeros carry no weight. A model that follows instructions better may reproduce content this one does not. The canary detector does not recognise every re-encoding, for example base64. GPU memory, accelerator KV cache and hardware side channels were not tested.

Injection (E4): 72 attacks (69 reached the model); 0 protected values in red-visible output or monitoring. The model had no hidden context to reveal, so this is an information-flow result, not evidence about the model's robustness. Failure handling (E5): 9 of 9 checks, including a real SIGKILL of the server mid-request.
""")


def s6(sl):
    header(sl, "AUDIT INTEGRITY & REPRODUCIBILITY", "A released run verifies; with 3 entries removed it does not")
    pa, pb = TERM / "term_verify_ok.png", TERM / "term_verify_bad.png"
    w = 6.85
    ha, hb = pic_h(pa, w), pic_h(pb, w)
    text(sl, 0.7, 2.95, w, 0.5, [[("COMPLETE RUN · exit 0", {"bold": True, "font": HEAD, "size": 16, "color": WHITE})]], size=16, fill=GREEN, align="c", anchor="m",
         shape=MSO_SHAPE.ROUNDED_RECTANGLE, radius=0.2)
    picture(sl, pa, 0.7, 3.55, w=w, border=GREEN)
    text(sl, 0.7 + w + 0.25, 2.95, w, 0.5, [[("TAMPERED COPY · exit 1", {"bold": True, "font": HEAD, "size": 16, "color": WHITE})]], size=16, fill=RED, align="c", anchor="m",
         shape=MSO_SHAPE.ROUNDED_RECTANGLE, radius=0.2)
    picture(sl, pb, 0.7 + w + 0.25, 3.55, w=w, border=RED)
    yb = 3.55 + max(ha, hb) + 0.12
    text(sl, 0.7, yb, 2 * w + 0.25, 0.5, [[("RECORDED ", {"bold": True, "color": GREEN}), ("scripts/judge_demo.sh, steps 4 and 5 · run JD-1 · key and terminal hash pinned by the reviewer · 3 entries removed from a copy", {"color": SLATE})]], size=14)
    # flow strip
    yf = yb + 0.7
    steps = [("run RELEASED", NAVY), ("terminal checkpoint signed", NAVY), ("bundle exported", NAVY), ("strict verify: pinned key + noted hash", GREEN)]
    sw, gap = (2 * w + 0.25 - 3 * 0.35) / 4, 0.35
    for i, (t_, col) in enumerate(steps):
        x = 0.7 + i * (sw + gap)
        text(sl, x, yf, sw, 0.95, [[(t_, {"bold": True, "size": 15, "color": col})]], size=15, fill=WHITE, line=col, align="c", anchor="m",
             shape=MSO_SHAPE.ROUNDED_RECTANGLE, radius=0.15, margin=0.08)
        if i < 3:
            arrow(sl, [(x + sw + 0.03, yf + 0.47), (x + sw + gap - 0.03, yf + 0.47)], NAVY, 2.5)
    rx = 15.15
    text(sl, rx, 2.95, 4.35, 5.55, [
        [("REPRODUCE IT", {"bold": True, "font": HEAD, "color": NAVY, "size": 15})],
        [("", {"size": 5})],
        [("bash scripts/quickstart.sh", {"font": "IBM Plex Mono", "size": 13.5, "bold": True})],
        [("%s stages pass; %s tests passed" % (T("quickstart", 0), V["tests_passed"]), {"size": 15.5})],
        [("", {"size": 5})],
        [("bash scripts/judge_demo.sh", {"font": "IBM Plex Mono", "size": 13.5, "bold": True})],
        [("%s checks, a few seconds, offline" % T("judge_demo", 0), {"size": 15.5})],
        [("", {"size": 5})],
        [("bash scripts/security_demo.sh", {"font": "IBM Plex Mono", "size": 13.5, "bold": True})],
        [("%s checks plus 1 documented limit" % T("demo", 0), {"size": 15.5})],
        [("", {"size": 5})],
        [("python evaluation/check_claims.py", {"font": "IBM Plex Mono", "size": 13.5, "bold": True})],
        [("recomputes quoted figures from raw files (%s checks)" % T("checker", 0), {"size": 15.5})],
    ], size=16, fill=MIST, line=LINE, shape=MSO_SHAPE.ROUNDED_RECTANGLE, radius=0.04, margin=0.22, anchor="m")
    text(sl, rx, 8.7, 4.35, 2.0, [[("In progress is not complete. ", {"bold": True, "color": AMBER}),
                                  ("A log still being written is reported terminal_verified: false and never counts as a strict pass; the legacy DEMO-001 predates terminal checkpoints and is rejected by design.", {})]],
         size=14.5, fill=AMBER_SOFT, line=AMBER, shape=MSO_SHAPE.ROUNDED_RECTANGLE, radius=0.06, margin=0.18, anchor="m")
    notes(sl, """
AUDIT INTEGRITY AND REPRODUCIBILITY (about 45 seconds; live: scripts/judge_demo.sh, steps 4 and 5)
Left, green: a completed run, JD-1, is RELEASED. The broker's terminal checkpoint is signed and binds the final audit entry. The reviewer verifies the exported bundle with the strict verifier, pinning the broker's public key and the terminal hash noted at release. Result: ok true, terminal_verified true, exit 0. These panels are the genuine output of the recorded demo run.

Right, red: the same bundle with the last three audit entries removed from a COPY (the original is untouched). The verifier reports truncation, because a signed checkpoint covers entries that no longer exist, and exits 1.

Distinguish in-progress from complete: while a run is still being written, the log can be checked with --allow-in-progress, which reports terminal_verified false and a warning; it is never counted as a pass of strict verification. The old shipped DEMO-001 (before terminal checkpoints existed) is rejected by strict verification by design; the closeout DEMO-001_released bundle passes.

Earlier recorded verification results (from the validated test suite, evidence/validation_2026-10-22): 19 tamper categories across 30 runs were all detected; truncation was 0 of 30 before the terminal checkpoint and is now caught.

Reproducibility: quickstart.sh runs eight stages from a clean copy, including the full test suite. judge_demo.sh is the short offline path. security_demo.sh is the longer original demo. check_claims.py and check_presentation.py recompute the figures in the deck from raw files.

Limits (state them): a compromised trusted broker can sign false but internally consistent records (test P2A20). A holder of the signing key who replaces every retained copy produces a history that verifies, unless the reviewer has an independent terminal commitment, for example the terminal hash noted at release (test P2A11). The verifier is also trusted code.
""")


def s7(sl):
    header(sl, "PERFORMANCE, LIMITS & DEPLOYMENT", "What it costs, and exactly where the guarantees stop")
    cw = 6.0
    text(sl, 0.7, 3.0, cw, 0.4, "MEASURED COST (one host, CPU)", size=15, bold=True, color=NAVY, font=HEAD)
    items = [("Broker hop", "%s median, idle host, stub model" % T("idle", 0), 1.15),
             ("Timing padding, 250 ms", "Classifier accuracy %s vs %s unpadded; +%s per answered request. Lowers one classifier's accuracy; does not show the timing channel is gone." % (T("timing", 1), T("timing", 0), T("timing", 2).lstrip("+")), 2.15),
             ("Real model on CPU", "Qwen2.5-0.5B on a loopback-only endpoint: median %s per request, prompt cache off." % T("e3_latency", 0), 1.5),
             ("Inference state", "cache_prompt true: a second session confirms a guess (cached tokens %s vs %s, AUC 1.00). AegisLab sends false: %s trials cached, 0 / 14 after restart." % (T("e3_on", 0), T("e3_on", 1), T("e3_off", 0)), 2.15)]
    y = 3.5
    for t1, t2, h in items:
        text(sl, 0.7, y, cw, h, [[(t1, {"bold": True, "size": 17.5})], [(t2, {"size": 15.5, "color": SLATE})]], size=16, fill=WHITE, line=LINE,
             shape=MSO_SHAPE.ROUNDED_RECTANGLE, radius=0.06, margin=0.16, anchor="m")
        y += h + 0.1
    x2 = 0.7 + cw + 0.3
    text(sl, x2, 3.0, cw, 0.4, "RESIDUAL RISK: NOT PROVEN AWAY", size=15, bold=True, color=RED, font=HEAD)
    risks = [("Trusted broker and signing key", "A compromised broker signs false but consistent records. A key thief who replaces every copy defeats the scheme unless the reviewer holds an independent terminal hash.", 2.45),
             ("Shared host", "Kernel, container runtime and hardware side channels are shared. GPU memory and accelerator KV cache were not tested.", 1.95),
             ("One model, one detector", "One 0.5B model and ten probe wordings; 3 probes silent under shared context. The canary detector misses re-encodings such as base64.", 2.25)]
    y = 3.5
    for t1, t2, h in risks:
        text(sl, x2, y, cw, h, [[(t1, {"bold": True, "size": 17.5, "color": RED})], [(t2, {"size": 15.5, "color": INK})]], size=16, fill=RED_SOFT, line=RED,
             shape=MSO_SHAPE.ROUNDED_RECTANGLE, radius=0.06, margin=0.16, anchor="m")
        y += h + 0.1
    x3 = x2 + cw + 0.3
    text(sl, x3, 3.0, cw, 0.4, "DEPLOYMENT", size=15, bold=True, color=NAVY, font=HEAD)
    text(sl, x3, 3.5, cw, 3.0, [[("TODAY · implemented", {"bold": True, "color": GREEN, "size": 14, "font": HEAD})],
                                [("One host, rootless Podman, API on loopback only, JSON files, local demo tokens. Real model optional, loopback only, key never logged.", {"size": 15.5})]],
         size=16, fill=GREEN_SOFT, line=GREEN, shape=MSO_SHAPE.ROUNDED_RECTANGLE, radius=0.06, margin=0.16, anchor="m")
    text(sl, x3, 6.6, cw, 3.95, [[("NEXT · proposed, not built", {"bold": True, "color": BLUE, "size": 14, "font": HEAD})],
                                 [("Signer outside the control-plane user · run-scoped identities · vault on separate storage · refuse cache_prompt true unless explicitly shared · microVM per tenant · GPU model server behind its own boundary", {"size": 15.5})]],
         size=16, fill=BLUE_SOFT, line=BLUE, shape=MSO_SHAPE.ROUNDED_RECTANGLE, radius=0.06, margin=0.16, anchor="m")
    notes(sl, """
PERFORMANCE, LIMITS AND DEPLOYMENT (about 45 seconds)
Measured cost, one host (AMD Ryzen 7 7735HS, Fedora, rootless Podman 5.8.9):
- Broker mailbox hop: median %s on an idle host with the stub model (three executions, n=1000 each).
- Timing mitigation: a simple classifier separating refused from answered responses reaches held-out accuracy %s without padding; with 250 ms buckets it is %s, not distinguishable from chance in these runs, at +%s per answered request. This lowers one classifier's accuracy. It does not establish that the timing channel is removed: one weak classifier, a constant-latency stub, three executions.
- Real-model path: Qwen2.5-0.5B on CPU through llama.cpp on loopback. Median client latency about %s per request with the prompt cache off.
- Inference state (experiment E3): with cache_prompt true the server reuses an earlier prompt's cached tokens; a second session can confirm a guess about earlier prompt content (cached tokens %s vs %s, AUC 1.00, latency AUC 1.00). AegisLab sends cache_prompt false: %s trials showed cached tokens and 0 of 14 after a process restart. This is a CPU prompt cache only. GPU memory, accelerator KV cache and hardware side channels were not tested. An operator can still re-open the oracle with AEGIS_MODEL_EXTRA_JSON; a guard is a recommended next step.

Residual risks: (1) trusted broker and signing key: compromise means false but consistent records; key theft plus replacing every retained copy defeats the scheme without an independent terminal hash. (2) Shared host kernel, container runtime, hardware. (3) One 0.5B model, ten probe wordings, three silent probes. (4) The canary detector protects canaries and registered secrets and does not recognise re-encodings such as base64 (test P3B02d, marked LIMIT). (5) Tokens are global per role; the API has no TLS, rate limit or body limit; run on loopback. (6) The release gate does not refuse a run sealed as incomplete after model errors; the report says so.

Deployment: today one host with rootless Podman. Proposed, not built: signer in its own process or KMS, run-scoped identities, vault on separate storage, microVM per tenant, GPU model server behind its own boundary with no shared prefix cache.
""" % (T("idle", 0), T("timing", 0), T("timing", 1), T("timing", 2).lstrip("+"), T("e3_latency", 0), T("e3_on", 0), T("e3_on", 1), T("e3_off", 0).replace(" / ", " of ")))


def s8(sl):
    text(sl, 0.7, 4.75, 12.2, 0.45, "AEGISLAB · TECH MAVERICKS", size=20, bold=True, color=ORANGE, font=HEAD)
    text(sl, 0.7, 5.2, 12.4, 0.9, "Three contributions, with their limits stated", size=34, bold=True, color=NAVY, font=HEAD)
    contrib = [("1", "Enforced information-flow boundaries", "No-network sandboxes, one brokered path. %d / %d expected denials denied in a %d-case role matrix; the hostile-mailbox attack is blocked in a real sandbox."
                % (D["role_matrix"]["denied"], D["role_matrix"]["expected_deny"], D["role_matrix"]["attempted"]), ORANGE),
               ("2", "Reproducible adversarial validation, real model included", "%s sessions leaked, and the controls that must leak did (%s, %s). One command reproduces it."
                % (T("e1_sessions", 0), T("e1_hist", 0), T("e1_gw", 0)), BLUE),
               ("3", "Verifiable evidence with explicit residual risk", "A signed terminal checkpoint; a tampered copy is rejected. Trusted broker, shared host, detector limits and untested hardware are stated.", GREEN)]
    y = 6.3
    for k_, t1, t2, col in contrib:
        circle(sl, 0.7, y + 0.08, 0.62, k_, col, size=20)
        text(sl, 1.55, y - 0.02, 11.4, 1.2, [[(t1, {"bold": True, "font": HEAD, "size": 21, "color": INK})], [(t2, {"size": 17.5, "color": SLATE})]], size=17)
        y += 1.2
    text(sl, 0.7, 9.95, 12.4, 0.6, [[("Why it matters: ", {"bold": True, "color": ORANGE}), ("a safety finding is only as credible as the test that produced it.", {"bold": True, "color": NAVY})]], size=20, anchor="m")
    text(sl, 0.7, 10.6, 12.4, 0.4, "Abdul Munaf Z · Likhith Sai N · Sreeram Rajesh", size=15, color=SLATE)
    text(sl, 13.2, 5.2, 6.2, 4.8, [[("Thank", {})], [("you!", {})]], size=150, font="Caveat", bold=True, color=INK, align="c", anchor="m")
    notes(sl, """
CONCLUSION (about 30 seconds)
Three evidence-backed contributions:
1. Enforced information-flow boundaries. Sandboxes with no network, one trusted broker, role gating, no-follow mailbox I/O. Evidence: role matrix (560 attempted, 419 of 419 expected denials denied, 0 unexpectedly permitted), and the hostile-mailbox attack blocked in a real container (regression tests P2B01, P2B03, P2B05, P2C01, P2C02).
2. Reproducible adversarial validation with real-model experiments. A real local model, through the adapter and the full pipeline: 0 of 104 sessions leaked, with controls that leak (16 of 16 and 13 of 16). Scope: one 0.5B model, ten probe wordings, CPU, loopback. quickstart.sh and judge_demo.sh reproduce the checks offline.
3. Cryptographically verifiable evaluation evidence with explicit residual-risk disclosure. Signed terminal checkpoint; a copy with three entries removed is rejected. We also state what is trusted: the broker and its key, the host kernel, the detector's blind spots, and GPU and hardware isolation we did not test.

Why it matters for AI safety evaluation: a finding that a defence held, or that a model leaked, is only worth what the test environment is worth. If attacks, defences and model state can cross, the number means nothing. AegisLab makes those boundaries enforceable, checkable by a third party, and honest about where they stop.

We do not claim: invulnerability, GPU or physical KV-cache isolation, protection against a compromised broker, model robustness to prompt injection, or any deployment, customer, partner or certification.
""")


def build(template, out):
    prs = Presentation(template)
    slides = list(prs.slides)
    for s in slides:
        clear(s)
    s1(slides[0]); s2(slides[1]); s3(slides[2]); s4(slides[3]); s5(slides[4]); s6(slides[5]); s7(slides[6]); s8(slides[7])
    for s in slides:
        for st in list(s.shapes._spTree.iter(qn("p:style"))):
            st.getparent().remove(st)
    prs.core_properties.title = "Tech Mavericks · AegisLab · Hack in Hills ’26 Track 04"
    prs.core_properties.author = "Tech Mavericks"
    prs.save(out)
    print(out)


if __name__ == "__main__":
    tpl, claims, val, term, out = sys.argv[1:6]
    D.update(json.loads(Path(claims).read_text()))
    V.update(json.loads(Path(val).read_text()))
    D["validation"] = dict(V)
    TERM = Path(term)
    build(tpl, out)
