"""Finale P5: one source of truth for every figure in the Grand Finale package, and a checker that enforces it.

    python evaluation/check_finale_presentation.py                   # exit 0 only if every check passes
    python evaluation/check_finale_presentation.py --write-claims    # (re)write finale_package/claims_used_for_finale.json
    python evaluation/check_finale_presentation.py --extra FILE ...  # also check text files outside the repository
                                                                     # (e.g. the elevator-pitch recording script)
    python evaluation/check_finale_presentation.py --root DIR        # check a copy of the package (used by the negative tests)

Where the figures come from (nothing is typed in here):
  * evaluation/check_claims.py, Parts A-F: it is run as a subprocess (exit 0 and every part total required), and its claim
    strings and Part E / Part F rows are read through its own functions;
  * named evidence files in the repository: the deadline-timing aggregate.json of finale P4, the recorded terminal
    transcripts of the P5 rehearsal (finale_package/terminal/*.txt) and the P5 gate summary
    (finale_package/evidence/p5_gate_counts.txt);
  * code constants of the presented code (the real-model deadline, the anomaly detectors, the mailbox quotas).

Every figure carries a type:
  LIVE                  produced by the presented code when it runs (a demo re-run on stage, a checker, a code constant);
                        the number shown is the one from the P5 rehearsal capture, and the stage run must reproduce it;
  RE-MEASURED <date>    measured again on the finale code (P4 tree, 11 Nov 2026);
  RECORDED <date>       measured earlier and not re-run on the final code.

The checker:
  1. claims_used_for_finale.json equals what this module derives now (so a stale file fails);
  2. in every finale document (deck slides and speaker notes, FINALE_SCRIPT.md, FINALE_JUDGE_QA.md, the caption files,
     HANDOUT.md, the finale block of README.md, and any --extra file) each occurrence of a claim's display form is masked
     and its unit (a line; a caption cue with its neighbours; a whole slide) must carry that claim's type label;
  3. after masking claims and the structural patterns below (dates, clock times, slide/step/section numbers, identifiers
     such as E1 or Qwen2.5-0.5B, paths, hashes, HTTP codes), no digit may remain: a figure that is not a claim, or a claim
     with a wrong number, is a failure;
  4. the deck has speaker notes on every slide; a deck is required, the other documents are required too.
"""
import argparse
import json
import re
import subprocess
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
REL = ROOT.parent
PKG = "finale_package"
CLAIMS = PKG + "/claims_used_for_finale.json"
DECK = PKG + "/Tech_Mavericks_AegisLab_Finale.pptx"
TEXT_DOCS = [PKG + "/FINALE_SCRIPT.md", PKG + "/FINALE_JUDGE_QA.md", PKG + "/HANDOUT.md",
             PKG + "/captions/AegisLab_Finale_Judge_Cut.srt", PKG + "/captions/AegisLab_Finale_Walkthrough.srt", "RC4_PACKAGE_HISTORICAL.md"]
README_BLOCK = ("README.md", "<!-- finale:start -->", "<!-- finale:end -->")
PRESENTED = "main (finale P1-P5 merged 12 Nov 2026; screenshots and recordings made on 9145592)"
D11, D10, D12 = "2026-11-11", "2026-11-10", "2026-11-12"
P4F = "aegislab/evidence/finale_p4_2026-11-11"
P3F = "aegislab/evidence/finale_p3_2026-11-10"
TERM = PKG + "/terminal"
GATES = PKG + "/evidence/p5_gate_counts.txt"


def label(typ, date=None):
    if typ == "LIVE":
        return "LIVE"
    y, m, d = date.split("-")
    return "%s %d %s %s" % (typ, int(d), {"10": "Oct", "11": "Nov"}[m], y)


def label_re(typ, date=None):
    if typ == "LIVE":
        return r"\bLIVE\b"
    y, m, d = date.split("-")
    return r"\b%s %d %s(?: %s)?\b" % (typ, int(d), {"10": "Oct", "11": "Nov"}[m], y)


def _num(s, pat, n=1):
    m = re.search(pat, s)
    if not m:
        raise SystemExit("cannot find %r in %r" % (pat, s[:200]))
    return m.group(n)


def _run_check_claims(root):
    p = subprocess.run([sys.executable, str(root / "aegislab/evaluation/check_claims.py")], capture_output=True, text=True, cwd=str(root / "aegislab"))
    out = p.stdout
    parts = {}
    for key, pat in (("A", r"(\d+)/(\d+) quoted numbers match"), ("B", r"(\d+)/(\d+) timing checks pass"), ("C", r"(\d+)/(\d+) Phase 3 checks pass"),
                     ("D", r"(\d+)/(\d+) re-measured checks pass"), ("E", r"(\d+)/(\d+) finale P3 checks pass"), ("F", r"(\d+)/(\d+) finale P4 checks pass")):
        m = re.search(pat, out)
        parts[key] = (int(m.group(1)), int(m.group(2))) if m else None
    return p.returncode, parts, out


def _term(root, name):
    p = root / TERM / name
    if not p.exists():
        raise SystemExit("missing recorded transcript %s" % p)
    return p.read_text()


def derive(root=REL):
    """Every claim of the finale package, derived now. Returns the JSON-able dict."""
    sys.path.insert(0, str(root / "aegislab/evaluation"))
    sys.path.insert(0, str(root / "aegislab"))
    import check_claims as cc
    rc, parts, _ = _run_check_claims(root)
    if rc != 0 or any(v is None or v[0] != v[1] for v in parts.values()):
        raise SystemExit("check_claims.py must pass every part first: exit %s, %s" % (rc, parts))
    frows, fc = cc.finale_p4_rows(False)
    erows, ec, _ = cc.finale_p3_rows(False)
    if not all(r[3] for r in frows) or not all(r[3] for r in erows):
        raise SystemExit("Part E or F rows fail")
    C = {}

    def add(key, forms, typ, date, evidence, source, quote=None):
        C[key] = {"forms": forms, "type": typ, "date": date, "label": label(typ, date), "evidence": evidence, "source": source}
        if quote:
            C[key]["quote"] = quote

    # ---- real model, Qwen2.5-0.5B, re-measured on the P4 tree (Part F)
    ev = [P4F + "/llm_final/INDEX.json", P4F + "/README.md"]
    q = fc["p4_e1_trials"]
    lk, tr, ses = _num(q, r"(\d+) of (\d+) isolation trials", 1), _num(q, r"(\d+) of (\d+) isolation trials", 2), _num(q, r"\((\d+) of (\d+) sessions", 2)
    add("e1_isolation", {"trials": "%s of %s isolation trials" % (lk, tr), "sessions": "%s of %s sessions" % (lk, ses),
                         "sessions_slash": "%s / %s sessions" % (lk, ses), "trials_short": "%s of %s trials" % (lk, tr)},
        "RE-MEASURED", D11, ev, "check_claims.py Part F p4_e1_trials", q)
    q = fc["p4_e1_bound"]
    add("e1_bound", {"trials": _num(q, r"([\d.]+%) of trials") + " of trials", "sessions": _num(q, r"([\d.]+%) of sessions") + " of sessions"},
        "RE-MEASURED", D11, ev, "check_claims.py Part F p4_e1_bound", q)
    q = fc["p4_e1_neg"]
    add("e1_negative", {"text": _num(q, r"(\d+ of \d+) negative-control trials") + " negative-control trials"}, "RE-MEASURED", D11, ev, "check_claims.py Part F p4_e1_neg", q)
    q = fc["p4_e1_pos"]
    h, g = _num(q, r"shared history (\d+ of \d+) sessions"), _num(q, r"sharing gateway (\d+ of \d+) sessions")
    add("e1_positive", {"history": h + " sessions", "gateway": g + " sessions", "history_slash": h.replace(" of ", "/"), "gateway_slash": g.replace(" of ", "/")},
        "RE-MEASURED", D11, ev, "check_claims.py Part F p4_e1_pos", q)
    q = fc["p4_e2_iso"]
    add("e2_isolation", {"runs": _num(q, r"(\d+ of \d+) isolation runs") + " isolation runs", "attacks": _num(q, r"\((\d+) attacks\)") + " attacks",
                         "red": _num(q, r"; (\d+) reached red") + " reached red"}, "RE-MEASURED", D11, ev, "check_claims.py Part F p4_e2_iso", q)
    q = fc["p4_e2_pos"]
    add("e2_control", {"runs": _num(q, r"in (\d+ of \d+) runs") + " runs", "withheld": _num(q, r"(\d+) attacks withheld") + " attacks withheld",
                       "red": _num(q, r", (\d+) reached red") + " reached red"}, "RE-MEASURED", D11, ev, "check_claims.py Part F p4_e2_pos", q)
    q = fc["p4_e3_off"]
    add("e3_cache_off", {"text": _num(q, r"in (\d+ of \d+) trials") + " trials"}, "RE-MEASURED", D11, ev, "check_claims.py Part F p4_e3_off", q)
    q = fc["p4_e3_on"]
    add("e3_cache_on", {"auc": "AUC " + _num(q, r"AUC ([\d.]+/[\d.]+)")}, "RE-MEASURED", D11, ev, "check_claims.py Part F p4_e3_on", q)
    q = fc["p4_e3_wall"]
    add("e3_latency_off", {"auc": "AUC " + _num(q, r"cache_prompt=false ([\d.]+/[\d.]+)")}, "RE-MEASURED", D11, ev, "check_claims.py Part F p4_e3_wall", q)
    q = fc["p4_e4"]
    add("e4_injection", {"attacks": _num(q, r"(\d+) injection attacks") + " injection attacks", "reached": _num(q, r"\((\d+) reached the model\)") + " reached the model",
                         "protected": _num(q, r": (\d+) protected values") + " protected values", "replays": _num(q, r"(\d+ of \d+) replayed") + " replayed"},
        "RE-MEASURED", D11, ev, "check_claims.py Part F p4_e4", q)
    q = fc["p4_e5"]
    add("e5_failure", {"text": _num(q, r"(\d+ of \d+) checks") + " checks"}, "RE-MEASURED", D11, ev, "check_claims.py Part F p4_e5", q)
    q = fc["p4_hardening"]
    add("server_hardening", {"text": _num(q, r"in (\d+ of \d+) broker-style trials") + " broker-style trials"}, "RE-MEASURED", D11,
        [P4F + "/model_server_hardening/"], "check_claims.py Part F p4_hardening", q)
    q = fc["p4_userns"]
    uids = _num(q, r"distinct host UIDs ([\d/]+)")
    add("f4_userns", {"containers": _num(q, r"F4: (\d+) containers") + " containers", "inside": "container UID " + _num(q, r"container UID (\d+)"),
                      "hosts": "host UIDs " + uids, "broker": "UID " + _num(q, r"broker's UID (\d+)"), "errno": "errno " + _num(q, r"errno (\d+)")},
        "RE-MEASURED", D11, [P4F + "/userns_proof_final/"], "check_claims.py Part F p4_userns", q)
    # ---- real-model timing, three executions (Part F) and the deadline aggregate
    q, qc = fc["p4_timing_deadline"], fc["p4_timing_deadline_cost"]
    agg = json.loads((root / P4F / "timing_deadline/aggregate.json").read_text())
    acc250 = _num(q, r"250 ms buckets: accuracy ([\d./]+)")
    accd = _num(q, r"deadline: accuracy ([\d./]+)")
    pd = [float(x) for x in _num(q, r"deadline: accuracy [\d./]+ \(baseline-adjusted [^,]+, p ([\d./]+)\)").split("/")]
    p250 = [float(x) for x in _num(q, r"250 ms buckets: accuracy [\d./]+ \(baseline-adjusted [^,]+, p ([\d./]+)\)").split("/")]
    base = agg["settings"]["deadline"]["majority_baseline"]
    import timing_deadline as td
    cost = [int(x) for x in _num(qc, r"\(median, vs unpadded\): ([+\d/]+) ms").replace("+", "").split("/")]
    cut = [float(x) for x in _num(qc, r"reached the model: ([\d./]+)").split("/")]
    tev = [P4F + "/timing_deadline/aggregate.json", P4F + "/README.md"]
    add("timing_250_real", {"acc": "accuracy " + acc250, "p": "p = %.3f" % max(p250)}, "RE-MEASURED", D11, tev, "check_claims.py Part F p4_timing_deadline", q)
    add("timing_deadline_real", {"acc": "accuracy " + accd, "base": "baselines " + "/".join("%.3f" % b for b in base),
                                 "p": "p = " + "/".join("%.3f" % x for x in pd), "p3": "p = %.3f" % pd[2],
                                 "alpha": "0.05/9 = %.4f" % td.ALPHA},
        "RE-MEASURED", D11, tev, "check_claims.py Part F p4_timing_deadline; aggregate.json majority_baseline; timing_deadline.ALPHA", q)
    add("timing_deadline_cost", {"cost": "+%d to +%d ms" % (min(cost), max(cost)), "cost_each": "/".join("+%d" % c for c in cost) + " ms",
                                 "cutoff": "%d–%d %%" % (round(min(cut) * 100), round(max(cut) * 100)),
                                 "D_each": "/".join(str(x) for x in agg["deadline_ms"]) + " ms"},
        "RE-MEASURED", D11, tev, "check_claims.py Part F p4_timing_deadline_cost; aggregate.json deadline_ms", qc)
    q = fc["p4_timing_stub"]
    add("timing_stub", {"acc250": _num(q, r"([\d.]+-[\d.]+) at 250 ms").replace("-", "–") + " at 250 ms", "pooled": "pooled " + _num(q, r"pooled at 250 ms ([\d.]+)"),
                        "unpadded": _num(q, r"accuracy ([\d.]+-[\d.]+) at 0 ms").replace("-", "–") + " unpadded",
                        "cost": _num(q, r"cost (\+\d+) to") + " ms"},
        "RE-MEASURED", D11, [P4F + "/timing_stub/aggregate.json"], "check_claims.py Part F p4_timing_stub", q)
    # ---- recorded on the P3 tree (Part E), not re-run on the P4 tree
    q = ec["f_timing"]
    add("timing_p3_single", {"acc250": "%s at 250 ms" % _num(q, r"([\d.]+) at 250 ms"), "acc1600": "%s at 1600 ms" % _num(q, r"([\d.]+) at 1600 ms"),
                             "p1600": "p = %.3f" % float(_num(q, r"at 1600 ms \(p=([\d.]+)\)"))},
        "RECORDED", D10, [P3F + "/timing_real_model/", P3F + "/README.md"], "check_claims.py Part E f_timing", q)
    q, qb, qp = ec["s_e1_trials"], ec["s_e1_bound"], ec["s_e1_pos"]
    add("second_model", {"trials": _num(q, r"(\d+ of \d+) isolation trials") + " isolation trials", "sessions": _num(q, r"\((\d+ of \d+) sessions") + " sessions",
                         "controls": "controls %s and %s" % (_num(qp, r"shared history (\d+ of \d+)"), _num(qp, r"sharing gateway (\d+ of \d+)")),
                         "bound": _num(qb, r"([\d.]+%) of trials") + " of trials"},
        "RECORDED", D10, [P3F + "/llm_qwen2.5-1.5b/"], "check_claims.py Part E s_e1_trials, s_e1_bound, s_e1_pos", q)
    # ---- container-only measurements re-run on the P4 tree (Part F, the Part D checks on the P4 directory)
    rr = {r[0].split(": ", 1)[1]: r[2] for r in frows if r[0].startswith("P4 re-measured on ")}
    tag = next(r[0] for r in frows if r[0].startswith("P4 re-measured on "))
    commit = _num(tag, r"re-measured on (\w+)")
    iso = rr["unauthorized API cases denied, none succeeded"]
    aud = rr["every tamper category detected in every trial"]
    cli = rr["CLI genuine bundles accepted, tampered rejected"]
    rm = rr["extended role x operation x state matrix"]
    e2s = rr["E2 red sandbox: forbidden requests, connects, foreign paths"]
    add("api_matrix", {"denied": _num(iso, r"^(\d+/\d+)") + " unauthorized cases denied", "markers": _num(rr["secret markers in public GET bodies"], r"^(\d+ in \d+)") + " public bodies",
                       "traversal": _num(rr["traversal cases rejected"], r"^(\d+/\d+)") + " traversal"},
        "RE-MEASURED", D11, [P4F + "/validation/isolation_matrix.json"], "check_claims.py Part F 'P4 re-measured on %s'" % commit)
    add("tamper", {"categories": _num(aud, r"^(\d+/\d+) categories") + " tamper categories", "trials": _num(aud, r"categories (\d+/\d+)") + " trials",
                   "genuine": _num(cli, r"^(\d+/\d+)") + " genuine bundles accepted", "tampered": _num(cli, r", (\d+/\d+)") + " tampered copies rejected"},
        "RE-MEASURED", D11, [P4F + "/validation/audit_tamper.json"], "check_claims.py Part F 'P4 re-measured on %s'" % commit)
    add("role_matrix", {"attempts": _num(rm, r"^(\d+) attempts") + " attempts", "denied": _num(rm, r"attempts, (\d+/\d+) denied") + " denied",
                        "allowed": _num(rm, r"denied, (\d+/\d+) allowed") + " allowed"},
        "RE-MEASURED", D11, [P4F + "/role_matrix_extended.json"], "check_claims.py Part F 'P4 re-measured on %s'" % commit)
    add("sandbox_e2", {"requests": _num(e2s, r"^(\d+/\d+)") + " forbidden requests denied", "connects": _num(e2s, r"^\d+/\d+, (\d+/\d+)") + " connects failed"},
        "RE-MEASURED", D11, [P4F + "/e1_e9_rerun/results.json"], "check_claims.py Part F 'P4 re-measured on %s'" % commit)
    # ---- checkers, code constants (LIVE)
    tot = sum(v[1] for v in parts.values())
    add("check_claims", {"total": "%d/%d checks" % (tot, tot), "f": "Part F %d/%d" % parts["F"]}, "LIVE", None,
        ["aegislab/evaluation/check_claims.py"], "check_claims.py exit 0; Parts A-F: " + ", ".join("%s %d/%d" % (k, v[0], v[1]) for k, v in sorted(parts.items())))
    from aegis import anomaly, runs
    qm = runs.MailboxQuota
    add("deadline_default", {"D": "t0 + %d ms" % runs.REAL_MODEL_DEADLINE_MS, "D_eq": "D = %d ms" % runs.REAL_MODEL_DEADLINE_MS,
                             "reserve": "%d ms before the deadline" % runs.DEADLINE_RESERVE_MS},
        "LIVE", None, ["aegislab/aegis/runs.py"], "aegis.runs.REAL_MODEL_DEADLINE_MS, DEADLINE_RESERVE_MS")
    add("detectors", {"n": "%d detectors" % len(anomaly.DETECTORS)}, "LIVE", None, ["aegislab/aegis/anomaly.py"], "len(aegis.anomaly.DETECTORS)")
    add("quotas", {"text": "%s messages per run, %d per %d s, %d MiB, %d outbox entries" % ("{:,}".format(qm.MESSAGES), qm.RATE_N, int(qm.RATE_S), qm.BYTES // (1024 * 1024), qm.FILES)},
        "LIVE", None, ["aegislab/aegis/runs.py"], "aegis.runs.MailboxQuota")
    # ---- live demos: the counts of the recorded P5 rehearsal (the stage run must reproduce them)
    t = _term(root, "t1_real_model_demo.txt")
    m = re.search(r"(\d+)/(\d+) checks PASS · LIVE REAL MODEL · (\d+) s", t)
    add("real_model_demo", {"checks": "%s/%s checks" % (m.group(1), m.group(2)), "secs": "about %s s" % m.group(3)}, "LIVE", None,
        [TERM + "/t1_real_model_demo.txt", "aegislab/scripts/real_model_demo.sh"], "recorded P5 rehearsal transcript")
    t = _term(root, "t2_judge_demo.txt")
    m = re.search(r"(\d+)/(\d+) checks behaved as expected", t)
    add("judge_demo", {"checks": "%s/%s checks" % (m.group(1), m.group(2))}, "LIVE", None, [TERM + "/t2_judge_demo.txt", "aegislab/scripts/judge_demo.sh"], "recorded P5 rehearsal transcript")
    t = _term(root, "t3_security_demo.txt")
    m = re.search(r"(\d+)/(\d+) checks behaved as expected", t)
    lim = re.search(r"(\d+) documented limit\(s\) demonstrated", t)
    add("security_demo", {"checks": "%s/%s checks" % (m.group(1), m.group(2)), "limits": "%s stated limits" % lim.group(1)}, "LIVE", None,
        [TERM + "/t3_security_demo.txt", "aegislab/scripts/security_demo.sh"], "recorded P5 rehearsal transcript")
    t = _term(root, "t4_f4_proof.txt")
    m = re.search(r"checks: (\d+)/(\d+) hold", t)
    add("f4_proof_live", {"checks": "%s/%s F4 checks" % (m.group(1), m.group(2))}, "LIVE", None, [TERM + "/t4_f4_proof.txt", "aegislab/evaluation/p4_userns_proof.py"], "recorded P5 rehearsal transcript")
    t = _term(root, "t5_verify_cli.txt")
    codes = [int(x) for x in re.findall(r"exit code: (\d+)", t)]
    add("verify_cli_live", {"ok": "exit code %d" % codes[0], "bad": "exit code %d" % codes[-1]}, "LIVE", None, [TERM + "/t5_verify_cli.txt", "aegislab/aegis/verify_cli.py"],
        "recorded P5 rehearsal transcript: strict verify, then the tampered copy")
    t = _term(root, "t6_real_model_console_check.txt")
    m = re.search(r"(\d+)/(\d+) checks PASS", t)
    add("console_check", {"checks": "%s/%s browser checks" % (m.group(1), m.group(2))}, "LIVE", None,
        [TERM + "/t6_real_model_console_check.txt", "aegislab/scripts/real_model_console_check.py"], "recorded P5 rehearsal transcript")
    # ---- test and gate counts of the P5 validation (recorded on this branch before the deck was built)
    g = (root / GATES).read_text()
    add("tests", {"passed": "%s tests passed" % _num(g, r"pytest_all_passed=(\d+)"), "browser": "%s browser tests" % _num(g, r"browser=(\d+/\d+)"),
                  "presentation": "check_presentation %s" % _num(g, r"check_presentation=(\d+/\d+)")},
        "RECORDED", D12, [GATES], "P5 gate run, see docs/finale/P5_REPORT.md")
    return {"note": "Generated by aegislab/evaluation/check_finale_presentation.py --write-claims. Do not edit by hand.",
            "presented_code": PRESENTED,
            "types": {"LIVE": "produced by the presented code when it runs (a demo re-run on stage, a checker, a code constant); the number is the P5 rehearsal's, the stage run must reproduce it",
                      "RE-MEASURED": "measured again on the finale P4 code", "RECORDED": "measured earlier, not re-run on the final code"},
            "check_claims_parts": {k: "%d/%d" % v for k, v in sorted(parts.items())},
            "claims": C}


# --------------------------------------------------------------------------------------------- document checks
STRUCTURAL = [
    r"\b[Qq]uestions? \d+(?:(?:,| and|–|-)\s*\d+)*",                     # question lists ("questions 6, 11, 12"), before the single form
    r"(?i)\b\d{1,2}(?:[–-]\d{1,2})? (?:Oct|Nov|Dec)\w*(?: 2026)?\b", r"(?i)\b(?:Oct|Nov)\w* \d{1,2}(?:[–-]\d{1,2})?\b", r"\b2026-\d\d-\d\d(?:T[\d:]+Z)?\b", r"\b2026\b",
    r"\b\d{1,2}:\d{2}(?::\d{2})?(?:[,.]\d{3})?\b",                     # clock / cue times
    r"\b\d+(?:[–-]\d+)?[- ](?:minute|second|min\b)\w*",                  # talk lengths
    r"\b(?:[Ss]lides?|[Ss]teps?|[Ss]ection|[Ii]tems?|Part|[Rr]ows?|[Oo]ption|Track|[Pp]hase|Round|[Cc]heck|[Rr]isk|[Qq]uestion|Q|[Cc]ue|[Ll]ine)s? #?\d+(?:[–-]\d+)?(?: of \d+)?\b",
    r"^\s*(?:#+\s*)?\d+[.)]\s", r"^\s*\|\s*\d+\s*\|",                   # list / table row numbers
    r"\b\d{3,4}\s?[×x]\s?\d{3,4}\b",                                    # resolutions
    r"\bHTTP \d{3}\b", r"\b\d+\.\d+\.\d+\.\d+\b", r"\b[0-9a-f]{7,64}\b",
    r"\b250 ms(?: buckets?| padding| bucket padding)?\b", r"\b1600 ms bucket\b", r"\bmax_tokens \d+\b", r"\bport \d+\b",
    r"\b(?:Python|Podman|uv|llama\.cpp) \d+(?:\.\d+)*\b", r"[’']26\b", r"\b\d+ ?[×x] ?\d+ in\b",
    r"\b0\.05\b(?!/)", r"\b\d+-slide\b", r"\b95 ?% (?:upper bound|CI|confidence)", r"\b0[0-7]{3}\b", r"\b[A-Z_]+=\d+\b", r"\b(?:MUST|SHOULD|OPTIONAL) \d+\b",
    r"^\s*\|\s*\d+(?:,\s*\d+)*\s*\|",  # item columns
    r"(?i)\btrack \d+\b", r"^\d$", r"^\d · ", r"^[01]\.\d$",                       # deck: track number, step circles, chart axis ticks
    r"\[SLIDE \d+\]", r"\b[A-Z]+-\d{3}\b", r"^\*\*\d+\.\s",                      # cue markers, run IDs (LAB-001), numbered Q&A
]
IDENT = r"[\w.]*[A-Za-z_][\w.]*"   # E1, Qwen2.5, 0.5B, b11819, finale_p4, runs.py
PATHLIKE = r"[\w.~<>-]*[A-Za-z_][\w.<>-]*/[\w./<>-]*|[\w./<>-]*/[\w.<>-]*[A-Za-z_][\w./<>-]*|\S+\.\w+:\d+(?:[-–]\d+)?"


def deck_units(path):
    slides, notes = {}, {}
    with zipfile.ZipFile(path) as z:
        for nm in z.namelist():
            m = re.fullmatch(r"ppt/(slides/slide|notesSlides/notesSlide)(\d+)\.xml", nm)
            if not m:
                continue
            xml = z.read(nm).decode("utf8")
            paras = ["".join(re.findall(r"<a:t>([^<]*)</a:t>", x)) for x in xml.split("</a:p>")]
            txt = "\n".join(x.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"').replace("&apos;", "'") for x in paras if x)
            (slides if m.group(1).startswith("slides") else notes)[int(m.group(2))] = txt
    if notes:  # the notes slide carries the slide number as a field; drop a trailing bare number line
        notes = {k: re.sub(r"\n\d+\s*$", "", v) for k, v in notes.items()}
    return slides, notes


def srt_units(text):
    cues = [b.split("\n")[2:] for b in text.strip().split("\n\n") if b.strip()]
    flat = [" ".join(c) for c in cues]
    return [(flat[i], " ".join(flat[max(0, i - 1):i + 2])) for i in range(len(flat))]


def check_text(units, claims, where):
    """units: [(text_to_scan, context_for_labels)]. Returns a list of problems."""
    forms = sorted(((f, k) for k, c in claims.items() for f in c["forms"].values()), key=lambda x: -len(x[0]))
    problems = []
    for n, (txt, ctx) in enumerate(units, 1):
        masked = txt
        for f, k in forms:
            if f in masked:
                if not re.search(label_re(claims[k]["type"], claims[k]["date"]), ctx):
                    problems.append("%s unit %d: '%s' (%s) without its type label '%s'" % (where, n, f, k, claims[k]["label"]))
                masked = masked.replace(f, " ⁘ ")
        masked = re.sub(PATHLIKE, " ", masked)
        for pat in STRUCTURAL:
            masked = re.sub(pat, " ", masked, flags=re.M)
        masked = re.sub(IDENT, " ", masked)
        left = re.findall(r"[+-]?\d[\d,.]*\s?%?", masked)
        if left:
            problems.append("%s unit %d: figure(s) %s not from claims_used_for_finale.json: '%s'" % (where, n, left[:4], txt.strip()[:110]))
    return problems


def check_docs(root, claims, extra=()):
    rows = []
    deck = root / DECK
    if deck.exists():
        slides, notes = deck_units(deck)
        rows.append(("deck: %d slides, speaker notes on every slide" % len(slides), bool(slides) and all((notes.get(i) or "").strip() for i in slides), "%d notes" % len(notes)))
        for i in sorted(slides):
            p = check_text([(slides[i], slides[i])], claims, "slide %d" % i)
            rows.append(("deck slide %d: figures from the claims file, each with its type label" % i, not p, "; ".join(p)[:300] or "ok"))
            lines = [ln for ln in notes.get(i, "").splitlines() if ln.strip()]
            p = check_text([(ln, ln) for ln in lines], claims, "notes %d" % i)
            rows.append(("deck notes %d: figures from the claims file, each with its type label" % i, not p, "; ".join(p)[:300] or "ok"))
    else:
        rows.append(("deck present: " + DECK, False, "missing"))
    docs = [(d, root / d) for d in TEXT_DOCS] + [(str(e), Path(e)) for e in extra]
    for name, p in docs:
        if not p.exists():
            rows.append(("%s present" % name, False, "missing"))
            continue
        t = p.read_text()
        units = srt_units(t) if name.endswith(".srt") else [(ln, ln) for ln in t.splitlines()]
        prob = check_text(units, claims, name)
        rows.append(("%s: figures from the claims file, each with its type label" % name, not prob, "; ".join(prob)[:400] or "ok"))
    rp, a, b = README_BLOCK
    t = (root / rp).read_text() if (root / rp).exists() else ""
    if a in t and b in t:
        block = t.split(a, 1)[1].split(b, 1)[0]
        prob = check_text([(ln, ln) for ln in block.splitlines()], claims, "README.md finale block")
        rows.append(("README.md finale block: figures from the claims file, each with its type label", not prob, "; ".join(prob)[:400] or "ok"))
    else:
        rows.append(("README.md has the finale block", False, "markers missing"))
    return rows


def run(root=REL, extra=(), rederive=True):
    rows = []
    cp = root / CLAIMS
    if not cp.exists():
        return [("claims file present: " + CLAIMS, False, "missing")]
    stored = json.loads(cp.read_text())
    if rederive:
        now = derive(root)
        rows.append(("claims_used_for_finale.json equals the figures derived now (check_claims Parts A-F, evidence files, transcripts)", now == stored,
                     "equal" if now == stored else "differs: %s" % sorted(k for k in set(now["claims"]) | set(stored["claims"]) if now["claims"].get(k) != stored["claims"].get(k))))
    claims = stored["claims"]
    rows.append(("every claim has a type label and an evidence path", all(c["type"] in ("LIVE", "RE-MEASURED", "RECORDED") and c["evidence"] and c["label"] for c in claims.values()),
                 "%d claims" % len(claims)))
    rows += check_docs(root, claims, extra)
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write-claims", action="store_true")
    ap.add_argument("--extra", nargs="*", default=[])
    ap.add_argument("--root", default=str(REL))
    ap.add_argument("--no-rederive", action="store_true", help="skip re-deriving the claims (negative tests on a copy)")
    a = ap.parse_args()
    root = Path(a.root)
    if a.write_claims:
        d = derive(root)
        (root / CLAIMS).parent.mkdir(parents=True, exist_ok=True)
        (root / CLAIMS).write_text(json.dumps(d, indent=1, ensure_ascii=False) + "\n")
        print("wrote %s: %d claims" % (CLAIMS, len(d["claims"])))
        return 0
    rows = run(root, a.extra, not a.no_rederive)
    for lbl, ok, found in rows:
        print("%-4s %-100s %s" % ("ok" if ok else "FAIL", lbl[:100], found))
    bad = sum(not r[1] for r in rows)
    print("\n%d/%d finale presentation checks pass" % (len(rows) - bad, len(rows)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
