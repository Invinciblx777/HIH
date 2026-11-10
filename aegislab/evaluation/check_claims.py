"""Recompute the headline numbers quoted in the deck, addendum and Judge_QA from the raw result files.

    python evaluation/check_claims.py            # exit 0 only if every quoted number matches its source file
    python evaluation/check_claims.py --full     # also re-run the permutation tests from the raw timing data (~5 min)

Part A: each quoted headline number against the value in the saved result file. Nothing is measured here.
Part B (timing): recomputed from the RAW per-request and per-round-trip files of the three
closeout executions, never from a number typed into this script:
  1. each raw file still has the sha256 recorded when the execution ran;
  2. held-out accuracy recomputed from the raw requests (same grouped 5-fold procedure) equals result.json;
  3. round-trip median / p99 / percentage increase recomputed from the raw valid blocks equal result.json;
  4. every timing number is then formatted from those recomputed values and must appear VERBATIM in each document that
     is meant to quote it (Markdown files and the deck's slide and speaker-note text);
  5. numbers that have no saved source (timing execution 1, a console record only) may appear in the current documents only
     on a line that says it is historical / unverified.
Part C (Phase 3, LLM experiments): every figure is recomputed from the raw observations.jsonl of the experiment runs listed in
evidence/phase3_2026-10-23/llm/INDEX.json (result and observation hashes, source-file hashes, denominators, exact intervals,
control sensitivity), and the Phase 3 report must quote the recomputed figures verbatim. The classification stored in a run is
printed, never assumed; a stored figure that differs from the recomputed one is a failure.
"""
import hashlib
import json
import os
import random
import re
import statistics
import sys
import tempfile
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
REL = ROOT.parent
V = ROOT / "evidence" / "validation_2026-10-22"
CO = ROOT / "evidence" / "closeout_2026-10-22" / "timing"


def load(name):
    return json.loads((V / name).read_text())


# ----------------------------------------------------------------------------------------------- timing (Part B)
TIMING_DOCS = {  # claim keys each document is required to quote verbatim; chosen here, not read back from the documents
    "README_FIRST.md": ["acc0", "acc250", "cost250"],
    "Judge_QA.md": ["acc0", "acc250", "cost250", "idle"],  # Phase 4 Q&A quotes the figures it needs; the full set stays in the addendum
    "VALIDATION_ADDENDUM_2026-10-22.md": ["acc0", "acc100", "acc250", "acc500", "pmin", "pool250", "cost250", "idle", "limited", "limited_inc",
                                          "unres", "unres_inc", "unres_p99", "unres_p99_inc"],
    "RELEASE_READINESS_REPORT.md": ["acc250", "cost250", "unres_inc"],
    "aegislab/README.md": ["acc0", "acc250"],
    "aegislab/THREAT_MODEL.md": ["acc250", "unres_inc"],
    "deck:slide7": ["acc0", "acc250", "cost250"],  # Phase 4 deck: slide 7 is "Performance, limits & deployment"
    "deck:notes7": ["acc0", "acc250", "cost250"],
}
CURRENT_DOCS = [d for d in TIMING_DOCS] + ["aegislab/evidence/closeout_2026-10-22/README.md"]
# phrasings of the superseded or unsourced numbers (regexes; bare numbers such as 0.545 are legitimate values elsewhere)
STALE = [r"0\.41\s*(?:–|-|to)\s*0\.545", r"0\.545 \(0\.19\)", r"\b0\.595\b", r"\b0\.515 \(0\.40\)", r"\b4\.62\b", r"8\.2 ?ms", r"\+70%", r"\+22%",
         r"two of three", r"twelve uncorrected", r"2\.54\s*(?:–|-)\s*2\.72", r"2\.72\s*(?:–|-)\s*2\.92", r"3\.23\s*(?:–|-)\s*4\.62", r"0\.48 to 0\.58", r"90/90 foreign paths"]
HISTORICAL = re.compile(r"histor|unverified|15 Oct|superseded|console record|not reproduced", re.I)


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def doc_text(name, deck_cache={}):
    """Markdown file text, or the text runs of one deck slide / notes page (paragraph per line)."""
    if name.startswith("deck:"):
        if not deck_cache:
            with zipfile.ZipFile(REL / "Tech_Mavericks_AegisLab_Submission.pptx") as z:
                for n in z.namelist():
                    m = re.fullmatch(r"ppt/(slides/slide|notesSlides/notesSlide)(\d+)\.xml", n)
                    if m:
                        xml = z.read(n).decode("utf8")
                        paras = ["".join(re.findall(r"<a:t>([^<]*)</a:t>", x)) for x in xml.split("</a:p>")]
                        deck_cache[("slide" if m.group(1).startswith("slides") else "notes") + m.group(2)] = "\n".join(
                            x.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">") for x in paras if x)
        return deck_cache.get(name[5:])
    p = REL / name
    return p.read_text() if p.exists() else None


def timing_rows(full):
    """Recompute everything from the raw files. Returns (rows, claims) where rows = (claim, source, found, ok)."""
    os.environ.setdefault("AEGIS_VAR", tempfile.mkdtemp(prefix="aegis-check-"))
    sys.path.insert(0, str(ROOT))
    sys.path.insert(0, str(HERE))
    import timing_eval as te  # the experiment's own classifier and statistics, imported unchanged
    rows, execs = [], sorted(p for p in CO.glob("exec*_seed*") if p.is_dir())
    ok_all = len(execs) == 3
    rows.append(("three timing executions are saved under evidence/closeout_2026-10-22/timing", "closeout/timing", "%d found" % len(execs), ok_all))
    acc, ps, cost, rtt, pairs_k, pairs_n = {b: [] for b in te.BUCKETS}, {b: [] for b in te.BUCKETS}, [], {}, {b: 0 for b in te.BUCKETS}, {b: 0 for b in te.BUCKETS}
    for d in execs:
        res = json.loads((d / "result.json").read_text())
        rows.append(("%s: COMPLETE, no unusable run or RTT block" % d.name, "result.json", "%s, %d unusable runs, %d unusable blocks" % (
            res["status"], len(res["unusable"]), len(res["unusable_rtt_blocks"])), res["status"] == "COMPLETE" and not res["unusable"] and not res["unusable_rtt_blocks"]))
        changed = [n for n, h in res["raw_files_sha256"].items() if sha(d / n) != h]
        rows.append(("%s: raw files unchanged since the run" % d.name, "sha256 in result.json", "changed: %s" % (changed or "none"), not changed))
        meta = json.loads((d / "raw_runs.json").read_text())
        bad = {m["run_id"] for m in meta if "unusable" in m}
        cls = [json.loads(x) for x in (d / "raw_classification.jsonl").read_text().splitlines()]
        for b in te.BUCKETS:
            r = [(c["rep"], c["latency_ms"], c["refused"]) for c in cls if c["bucket_ms"] == b and c["run_id"] not in bad]
            pairs = te.grouped_cv(r, 5, random.Random(res["seed"]))
            a = round(te.score(pairs)[0], 3)
            want = res["conditions"][str(b)]
            good = a == want["heldout_accuracy"] and want["majority_baseline"] == 0.5 and want["n_refused"] == want["n_answered"] == 100
            rows.append(("%s: %3d ms held-out accuracy recomputed from %d raw requests" % (d.name[:5], b, len(r)), "raw_classification.jsonl", "%.3f (result.json %.3f)" % (a, want["heldout_accuracy"]), good))
            if full:
                pv = te.analyse(r, res["seed"])["permutation_p"]
                rows.append(("%s: %3d ms permutation p recomputed (1000 shuffles)" % (d.name[:5], b), "raw_classification.jsonl", "%.4f (result.json %.4f)" % (pv, want["permutation_p"]), pv == want["permutation_p"]))
            acc[b].append(a)
            ps[b].append(want["permutation_p"])
            pairs_k[b] += sum(p == y for p, y in pairs)
            pairs_n[b] += len(pairs)
            if b == 250:
                cost.append(want["added_median_latency_for_answered_requests_ms"])
        blocks = json.loads((d / "rtt_blocks.json").read_text())
        samples = [json.loads(x) for x in (d / "raw_rtt.jsonl").read_text().splitlines()]
        for cond in res["broker_mailbox_rtt"]:
            ok_blocks = {b["block"] for b in blocks if b["condition"] == cond and b["valid"]}
            v = [x["rtt_ms"] for x in samples if x["block"] in ok_blocks and not x["warmup"]]
            st = te.pcts(v)
            want = res["broker_mailbox_rtt"][cond]
            good = st["median_ms"] == want["median_ms"] and st["p99_ms"] == want["p99_ms"] and st["n"] == want["n"]
            rtt.setdefault(cond, []).append((st, v))
            rows.append(("%s: RTT %-20s median/p99 recomputed from %d raw round trips" % (d.name[:5], cond[:20], st["n"]), "raw_rtt.jsonl", "%.2f / %.2f ms (result.json %.2f / %.2f)" % (
                st["median_ms"], st["p99_ms"], want["median_ms"], want["p99_ms"]), good))
    idle_c = "idle"
    conds = [c for c in rtt if c != idle_c]
    lim = next(c for c in conds if c.startswith("limited"))
    unr = next(c for c in conds if c.startswith("unrestricted"))

    def pct(c, key):  # increase over the same execution's idle samples; definition in timing_closeout.py docstring
        return [100 * (rtt[c][i][0][key] - rtt[idle_c][i][0][key]) / rtt[idle_c][i][0][key] for i in range(len(execs))]

    def rng(vals, f="%.3f"):
        return f % min(vals) + "–" + f % max(vals)

    def prange(vals):
        return "%+.1f%% to %+.1f%%" % (min(vals), max(vals))
    k250, n250 = pairs_k[250], pairs_n[250]
    lo, hi = te.wilson(k250, n250)
    claims = {
        "acc0": rng(acc[0]), "acc100": rng(acc[100]), "acc250": rng(acc[250]), "acc500": rng(acc[500]),
        "pmin": "%.3f" % min(min(ps[b]) for b in (100, 250, 500)),
        "pool250": "%.3f (95%% CI %.3f–%.3f, n=%d)" % (k250 / n250, lo, hi, n250),
        "cost250": "+%d to +%d ms" % (round(min(cost)), round(max(cost))),
        "idle": rng([x[0]["median_ms"] for x in rtt[idle_c]], "%.2f") + " ms",
        "limited": rng([x[0]["median_ms"] for x in rtt[lim]], "%.2f") + " ms",
        "limited_inc": prange(pct(lim, "median_ms")),
        "unres": rng([x[0]["median_ms"] for x in rtt[unr]], "%.2f") + " ms",
        "unres_inc": prange(pct(unr, "median_ms")),
        "unres_p99": rng([x[0]["p99_ms"] for x in rtt[unr]], "%.2f") + " ms",
        "unres_p99_inc": prange(pct(unr, "p99_ms")),
    }
    # the percentage increase must agree with what the execution itself stored (result.json), to 1 decimal
    stored = [json.loads((d / "result.json").read_text())["broker_mailbox_rtt"][unr]["increase_vs_idle"]["median_pct"] for d in execs]
    rows.append(("RTT increase over idle recomputed from raw equals the stored increase", "result.json", "%s vs %s" % (
        [round(x, 1) for x in pct(unr, "median_ms")], stored), [round(x, 1) for x in pct(unr, "median_ms")] == stored))
    for doc, keys in TIMING_DOCS.items():
        t = doc_text(doc)
        for k in keys:
            rows.append(("%s quotes %s = %s" % (doc, k, claims[k]), "recomputed", "present" if t and claims[k] in t else ("document missing" if t is None else "NOT FOUND"), bool(t and claims[k] in t)))
    for doc in CURRENT_DOCS:
        t = doc_text(doc) or ""
        stale = [(tok, ln.strip()[:90]) for ln in t.splitlines() for tok in STALE if re.search(tok, ln) and not HISTORICAL.search(ln)]
        rows.append(("%s: no unsourced / superseded number presented as current" % doc, "STALE list", "none" if not stale else "; ".join("%s in '%s'" % x for x in stale[:3]), not stale))
    return rows, claims


# ----------------------------------------------------------------------------------------------- acknowledged source drift
# A saved experiment records the sha256 of the security-relevant sources it ran on, and its row fails ("DRIFT") when one of
# them changes. A change can be acknowledged, never silently: a dated file under evidence/ names, per file, the hash the runs
# recorded (old_sha256), the hash the file has after the change (new_sha256), the commit, a one-line reason, and for every
# experiment whether the change affects what it measured and why. A difference is accepted ONLY when the file's current hash
# equals an acknowledged new_sha256 for the recorded old_sha256 AND that acknowledgement says, with a reason, that the change
# does not affect that experiment. A further edit, an unacknowledged change, or one acknowledged as affecting the measurement
# still fails. The list of acknowledgement files is fixed here (this file is pinned by MANIFEST.sha256), not discovered.
SOURCE_DRIFT_FILES = (ROOT / "evidence" / "finale_rebaseline_2026-11-10" / "SOURCE_DRIFT.json",
                      ROOT / "evidence" / "finale_p3_2026-11-10" / "SOURCE_DRIFT.json")  # finale P3: keeps the 23 Oct runs checkable


def source_drift_acks(files=None):
    """{path: [acknowledged change, ...]} from the acknowledgement files that exist."""
    acks = {}
    for f in SOURCE_DRIFT_FILES if files is None else files:
        f = Path(f)
        if f.exists():
            for c in json.loads(f.read_text())["changes"]:
                acks.setdefault(c["path"], []).append(dict(c, ack_file=f.name))
    return acks


def source_drift(recorded, experiment, acks=None):
    """Compare the source hashes a run recorded with the tree now. Returns (unacknowledged, acknowledged) lists of paths."""
    acks = source_drift_acks() if acks is None else acks
    bad, ok = [], []
    for k, h in sorted(recorded.items()):
        p = ROOT / k
        if not p.exists():
            continue
        cur = hashlib.sha256(p.read_bytes()).hexdigest()
        if cur == h:
            continue
        hit = [a for a in acks.get(k, []) if a.get("old_sha256") == h and a.get("new_sha256") == cur
               and (a.get("claims") or {}).get(experiment, {}).get("affects") is False
               and str((a.get("claims") or {}).get(experiment, {}).get("why", "")).strip()]
        (ok if hit else bad).append(k)
    return bad, ok


def phase3_provenance(base=None):
    """For the demos and checkers: per saved Phase 3 experiment, the revision it was recorded on and which of its sources
    changed since (acknowledged or not). Nothing here is re-measured. base: an INDEX.json directory (default the 23 Oct runs)."""
    base = P3 if base is None else base
    out = []
    if not (base / "INDEX.json").exists():
        return out
    latest = {}
    for e in json.loads((base / "INDEX.json").read_text()):
        latest[e["experiment"]] = e
    acks = source_drift_acks()
    for exp, e in sorted(latest.items()):
        res = json.loads((base / e["dir"] / "result.json").read_text())
        bad, ok = source_drift(res["source_sha256"], exp, acks)
        out.append({"experiment": exp, "dir": e["dir"], "base": base.relative_to(ROOT).as_posix() if base.is_relative_to(ROOT) else str(base),
                    "recorded_utc": res["timestamp_utc"],
                    "recorded_tree": res["code_revision"]["tree_sha256"], "acknowledged": ok, "unacknowledged": bad,
                    "commits": sorted({a["commit"][:12] for k in ok for a in acks[k]})})
    return out


# ----------------------------------------------------------------------------------------------- re-measured (Part D)
RB = ROOT / "evidence" / "finale_rebaseline_2026-11-10"


def remeasured_rows():
    """Part D: the measurements that need no real model, re-run on the finale P2 code (REMEASURED.json names the commit, the
    commands and the raw-file hashes). Each row checks a security property and prints the re-measured figure next to the one
    recorded on 22/23 Oct; Part A keeps checking the recorded figures. Returns rows (claim, source, found, ok)."""
    if not (RB / "REMEASURED.json").exists():
        return []
    idx = json.loads((RB / "REMEASURED.json").read_text())
    tag = "re-measured on %s" % idx["code_commit"][:7]
    changed = [n for n, h in idx["raw_files_sha256"].items() if not (RB / n).exists() or sha(RB / n) != h]
    rows = [("%s: raw files unchanged since the re-measurement" % tag, "REMEASURED.json", "changed: %s" % (changed or "none"), not changed)]
    if changed:
        return rows
    iso, aud = json.loads((RB / "validation/isolation_matrix.json").read_text()), json.loads((RB / "validation/audit_tamper.json").read_text())
    oiso, oaud = load("isolation_matrix.json"), load("audit_tamper.json")
    rm = json.loads((RB / "role_matrix_extended.json").read_text())["totals"]
    orm = json.loads((ROOT / "evidence/phase2_2026-10-23/role_matrix_extended.json").read_text())["totals"]
    e2 = json.loads((RB / "e1_e9_rerun/results.json").read_text())["E2_cross_tenant"]
    cats, ocats = aud["categories"], oaud["categories"]
    cli, gap = aud["cli_level"], aud["original_gap_case"]

    def f(d, *k):
        return "/".join(str(d[x]) for x in k)
    rows += [
        ("%s: unauthorized API cases denied, none succeeded" % tag, "validation/isolation_matrix.json",
         "%s (22 Oct %s), %d succeeded" % (f(iso, "denied_as_expected", "cases_expect_deny"), f(oiso, "denied_as_expected", "cases_expect_deny"), iso["unauthorized_succeeded"]),
         iso["denied_as_expected"] == iso["cases_expect_deny"] and iso["unauthorized_succeeded"] == 0),
        ("%s: secret markers in public GET bodies" % tag, "validation/isolation_matrix.json",
         "%d in %d (22 Oct %d in %d)" % (iso["secret_marker_hits"], iso["public_get_bodies_scanned"], oiso["secret_marker_hits"], oiso["public_get_bodies_scanned"]),
         iso["secret_marker_hits"] == 0 and iso["public_get_bodies_scanned"] > 0),
        ("%s: traversal cases rejected" % tag, "validation/isolation_matrix.json",
         "%s (22 Oct %s)" % (f(iso, "path_traversal_rejected", "path_traversal_cases"), f(oiso, "path_traversal_rejected", "path_traversal_cases")),
         iso["path_traversal_rejected"] == iso["path_traversal_cases"] > 0),
        ("%s: every tamper category detected in every trial" % tag, "validation/audit_tamper.json",
         "%d/%d categories %d/%d (22 Oct %d categories)" % (sum(c["detected"] == c["trials"] for c in cats.values()), len(cats), min(c["detected"] for c in cats.values()),
                                                           max(c["trials"] for c in cats.values()), len(ocats)),
         all(c["detected"] == c["trials"] > 0 for c in cats.values()) and sorted(cats) == sorted(ocats)),
        ("%s: clean logs accepted and terminal verified" % tag, "validation/audit_tamper.json",
         "%d / %d of %d runs" % (aud["clean_runs_verify"], aud["clean_runs_terminal_verified"], aud["runs"]),
         aud["clean_runs_verify"] == aud["clean_runs_terminal_verified"] == aud["runs"] > 0),
        ("%s: truncation with only the freeze checkpoint: fail-closed" % tag, "validation/audit_tamper.json",
         "%d/%d" % (gap["new_rules_detected_fail_closed"], gap["trials"]), gap["new_rules_detected_fail_closed"] == gap["trials"] > 0),
        ("%s: CLI genuine bundles accepted, tampered rejected" % tag, "validation/audit_tamper.json",
         "%s, %s (22 Oct %s, %s)" % (f(cli, "genuine_accepted", "bundles"), f(cli, "tampered_rejected", "tampered_total"),
                                    f(oaud["cli_level"], "genuine_accepted", "bundles"), f(oaud["cli_level"], "tampered_rejected", "tampered_total")),
         cli["genuine_accepted"] == cli["bundles"] > 0 and cli["tampered_rejected"] == cli["tampered_total"] > 0),
        ("%s: extended role x operation x state matrix" % tag, "role_matrix_extended.json",
         "%d attempts, %d/%d denied, %d/%d allowed, %d hits (23 Oct %d attempts)" % (rm["attempted"], rm["denied"], rm["expected_deny"], rm["allowed"], rm["expected_allow"],
                                                                                   rm["secret_hits"], orm["attempted"]),
         rm["unexpectedly_permitted"] == rm["wrongly_denied"] == rm["test_errors"] == rm["secret_hits"] == 0 and rm["attempted"] > 0),
        ("%s: E2 red sandbox: forbidden requests, connects, foreign paths" % tag, "e1_e9_rerun/results.json",
         "%s, %s, %s" % (f(e2["forbidden_broker_requests"], "denied", "attempts"), f(e2["network_connect_attempts"], "failed", "attempts"),
                         f(e2["foreign_paths_checked"], "absent", "checks")),
         e2["forbidden_broker_requests"]["denied"] == e2["forbidden_broker_requests"]["attempts"] > 0
         and e2["network_connect_attempts"]["failed"] == e2["network_connect_attempts"]["attempts"] > 0
         and e2["foreign_paths_checked"]["absent"] == e2["foreign_paths_checked"]["checks"] > 0),
    ]
    return rows


# ----------------------------------------------------------------------------------------------- Phase 3 (Part C)
P3 = ROOT / "evidence" / "phase3_2026-10-23" / "llm"
P3_REPORT = "PHASE3_LLM_SECURITY_REPORT.md"


def _jsonl(path):
    return [json.loads(l) for l in Path(path).read_text().splitlines() if l.strip()]


def phase3_rows(base=None, report=None):
    """Returns (rows, claims). Each row: (claim, source, found, ok). Nothing here is typed in as a desired result.
    base: the INDEX.json directory (default: the 23 Oct runs, P3); report: the document (relative to the package root) that must
    quote the recomputed figures verbatim (default PHASE3_LLM_SECURITY_REPORT.md). The M1-M6 revalidation rows belong to the
    23 Oct directory only."""
    old = base is None
    base = P3 if base is None else base
    report = P3_REPORT if report is None else report
    rows, claims = [], {}
    if not (base / "INDEX.json").exists():
        return [("Phase 3 LLM evidence present", "INDEX.json", "not present (skipped)", True)], claims
    sys.path.insert(0, str(HERE))
    from llm_common import auc_with_permutation, rate, sha256_file, source_hashes
    index = json.loads((base / "INDEX.json").read_text())
    latest = {}
    for e in index:  # a later entry of the same experiment supersedes an earlier one; earlier runs stay on disk
        latest[e["experiment"]] = e
    runs_ = {}
    acks = source_drift_acks()
    for exp, e in sorted(latest.items()):
        d = base / e["dir"]
        res = json.loads((d / "result.json").read_text())
        obs = _jsonl(d / "observations.jsonl")
        runs_[exp] = (res, obs)
        drift, acked = source_drift(res["source_sha256"], exp, acks)
        found = ("DRIFT: " + ", ".join(drift) if drift else
                 "recorded on %s (%s); acknowledged change, does not affect %s: %s" % (
                     res["code_revision"]["tree_sha256"][:19], res["timestamp_utc"][:10], exp.split("_")[0], ", ".join(acked))
                 if acked else "no drift")
        rows += [
            ("%s: result.json hash equals INDEX entry" % exp, e["dir"], e["result_sha256"][:12], sha256_file(d / "result.json") == e["result_sha256"]),
            ("%s: observations.jsonl hash and count recorded" % exp, e["dir"], "%d observations" % len(obs),
             sha256_file(d / "observations.jsonl") == res["observations_sha256"] and len(obs) == res["observation_count"]),
            ("%s: security-relevant sources unchanged since the run" % exp, e["dir"], found, not drift),
            ("%s: provenance fields present" % exp, e["dir"], res["run_id"],
             all(k in res for k in ("run_id", "timestamp_utc", "model_backend", "config", "seed", "fixture_version", "environment", "limitations", "classification"))
             and res["model_backend"].get("model_sha256") and res["classification"] in ("pass", "fail", "inconclusive", "not_run")),
        ]
    # ---- E1: canary matrix
    if "E1_canary_matrix" in runs_:
        res, obs = runs_["E1_canary_matrix"]
        cells = {}
        for o in obs:
            c = cells.setdefault((o["condition"], o["ordering"]), {"trials": 0, "leaking": 0, "sessions": set(), "leak_sessions": set()})
            c["trials"] += 1
            c["leaking"] += bool(o["leaks"])
            c["sessions"].add(o["session"])
            if o["leaks"]:
                c["leak_sessions"].add(o["session"])
        stored = {(c["condition"], c["ordering"]): c for c in res["summary"]["cells"]}
        agree = all(k in stored and stored[k]["trials"] == v["trials"] and stored[k]["trials_leaking"] == v["leaking"]
                    and stored[k]["sessions_leaking"] == len(v["leak_sessions"]) and stored[k]["sessions"] == len(v["sessions"]) for k, v in cells.items())
        rows.append(("E1: every cell's trials / leaking trials / leaking sessions recomputed from observations", "E1 observations", "%d cells" % len(cells), agree and len(cells) == len(stored)))
        iso = [v for k, v in cells.items() if k[0].startswith(("reused_server", "fresh_server"))]
        it, il = sum(v["trials"] for v in iso), sum(v["leaking"] for v in iso)
        isn, isl = sum(len(v["sessions"]) for v in iso), sum(len(v["leak_sessions"]) for v in iso)
        neg = [v for k, v in cells.items() if k[0].startswith("negative")]
        nt, nl = sum(v["trials"] for v in neg), sum(v["leaking"] for v in neg)
        ph = next(v for k, v in cells.items() if k[0] == "positive_control_shared_history")
        pg = next(v for k, v in cells.items() if k[0] == "positive_control_sharing_gateway")
        r_t, r_s = rate(il, it), rate(isl, isn)
        pooled = res["summary"]["isolation_pooled"]
        rows.append(("E1: pooled interval equals the exact interval recomputed here", "result.json",
                     "%s / %s" % (r_t["upper95_one_sided_exact"], r_s["upper95_one_sided_exact"]),
                     pooled["trial_rate"] == r_t and pooled["session_rate"] == r_s))
        claims["e1_trials"] = "%d of %d isolation trials leaked (%d of %d sessions)" % (il, it, isl, isn)
        claims["e1_bound"] = "one-sided 95%% upper bound %.2f%% of trials, %.2f%% of sessions" % (100 * r_t["upper95_one_sided_exact"], 100 * r_s["upper95_one_sided_exact"])
        claims["e1_neg"] = "%d of %d negative-control trials leaked" % (nl, nt)
        claims["e1_pos"] = "positive controls: shared history %d of %d sessions, sharing gateway %d of %d sessions" % (
            len(ph["leak_sessions"]), len(ph["sessions"]), len(pg["leak_sessions"]), len(pg["sessions"]))
        claims["e1_class"] = "E1 classification: %s" % res["classification"]
    # ---- E2: pipeline canary
    if "E2_pipeline_canary" in runs_:
        res, obs = runs_["E2_pipeline_canary"]
        by = {}
        for o in obs:
            cond = o["condition"]
            c = by.setdefault(cond, {"runs": set(), "attacks": 0, "model": set(), "red": 0, "flag": 0, "withheld": 0, "reached": 0})
            c["runs"].add(o["run"])
            c["attacks"] += 1
            c["reached"] += o["verdict_in"] == "allow"
            if o["foreign_in_model_output"]:
                c["model"].add(o["run"])
            c["red"] += bool(o["foreign_in_final_output"])
            c["flag"] += bool(o["broker_canary_leaks"])
            c["withheld"] += o["outcome"] in ("withheld_canary", "withheld_secret")
        stored = {c["condition"]: c for c in res["summary"]["cells"]}
        agree = all(stored[k]["runs"] == len(v["runs"]) and stored[k]["attacks_total"] == v["attacks"] and stored[k]["runs_with_foreign_in_model_output"] == len(v["model"])
                    and stored[k]["foreign_canary_in_final_output_seen_by_red"] == v["red"] and stored[k]["broker_flagged_attacks"] == v["flag"] for k, v in by.items())
        rows.append(("E2: per-condition runs / attacks / foreign-canary counts recomputed from observations", "E2 observations", "%d conditions" % len(by), agree and set(by) == set(stored)))
        iso = [v for k, v in by.items() if not k.startswith(("negative", "positive"))]
        ir, il_, ia = sum(len(v["runs"]) for v in iso), sum(len(v["model"]) for v in iso), sum(v["attacks"] for v in iso)
        ired = sum(v["red"] for v in iso)
        pos = next(v for k, v in by.items() if k.startswith("positive"))
        neg = next(v for k, v in by.items() if k.startswith("negative"))
        claims["e2_iso"] = "%d of %d isolation runs (%d attacks) had a foreign canary in raw model output; %d reached red" % (il_, ir, ia, ired)
        claims["e2_pos"] = "context-sharing control: foreign canary in raw model output in %d of %d runs, %d attacks withheld from red, %d reached red" % (
            len(pos["model"]), len(pos["runs"]), pos["withheld"], pos["red"])
        claims["e2_neg"] = "negative control: %d of %d runs" % (len(neg["model"]), len(neg["runs"]))
        claims["e2_class"] = "E2 classification: %s" % res["classification"]
    # ---- E3: KV / prompt cache
    if "E3_kv_cache_oracle" in runs_:
        res, obs = runs_["E3_kv_cache_oracle"]
        stored = {c["cell"]: c for c in res["summary"]["cells"]}
        ok = True
        out = {}
        for cell in stored:
            rows_ = [o for o in obs if o["cell"] == cell]
            pos = [o["cached_tokens"] or 0 for o in rows_ if o["guess_correct"]]
            neg = [o["cached_tokens"] or 0 for o in rows_ if not o["guess_correct"]]
            a = auc_with_permutation(pos, neg, perms=1000)
            wp = [o["wall_ms"] for o in rows_ if o["guess_correct"]]
            wn = [o["wall_ms"] for o in rows_ if not o["guess_correct"]]
            w = auc_with_permutation(wn, wp, perms=1000)  # P(wrong guess slower than correct guess)
            out[cell] = (a, len(pos), len(neg), w)
            ok &= a == stored[cell]["cached_tokens_oracle"] and w == stored[cell]["client_wall_ms_oracle_wrong_slower"]
        rows.append(("E3: cached-token AUC and permutation p recomputed for %d cells" % len(stored), "E3 observations", "%d cells" % len(stored), ok))
        on = [c for c in out if "cache_on" in c and "fresh" not in c]
        off = [c for c in out if "cache_off" in c]
        claims["e3_on"] = "cache_prompt=true: cached-token AUC %s with %d+%d trials per cell in %d cells" % (
            "/".join("%.2f" % out[c][0]["auc"] for c in on), out[on[0]][1], out[on[0]][2], len(on))
        claims["e3_wall"] = "client-visible latency, wrong guess slower than correct guess (AUC): cache_prompt=true %s, cache_prompt=false %s" % (
            "/".join("%.2f" % out[c][3]["auc"] for c in on), "/".join("%.2f" % out[c][3]["auc"] for c in off))
        claims["e3_off"] = "cache_prompt=false (AegisLab default): cached tokens observed in %d of %d trials" % (
            sum((o["cached_tokens"] or 0) > 0 for o in obs if o["cell"] in off), sum(o["cell"] in off for o in obs))
        fresh = [o for o in obs if "fresh" in o["cell"]]
        claims["e3_fresh"] = "fresh process per trial: cached tokens observed in %d of %d trials" % (sum((o["cached_tokens"] or 0) > 0 for o in fresh), len(fresh))
        claims["e3_class"] = "E3 classification: %s" % res["classification"]
    # ---- E4: injection and output isolation
    if "E4_injection_output_isolation" in runs_:
        res, obs = runs_["E4_injection_output_isolation"]
        s = res["summary"]
        reached = sum(o["verdict_in"] == "allow" for o in obs)
        red = sum(bool(o["markers_in_final_output"] or o["foreign_in_final_output"]) for o in obs)
        rows.append(("E4: attack, reached-model and red-visible-hit counts recomputed from observations", "E4 observations", "%d / %d / %d" % (len(obs), reached, red),
                     s["attacks_total"] == len(obs) and s["attacks_reaching_model"] == reached and s["markers_or_foreign_canaries_in_red_visible_output"] == red))
        g = s["gate_replay"]
        claims["e4"] = "%d injection attacks (%d reached the model): %d protected values in red-visible output; %d of %d replayed model-generated gate messages denied, %d changed run state" % (
            len(obs), reached, red, g["denied_or_rejected"], g["attempts"], g["state_changed"])
        claims["e4_class"] = "E4 classification: %s" % res["classification"]
    # ---- E5: failure handling
    if "E5_failure_handling" in runs_:
        res, obs = runs_["E5_failure_handling"]
        cases = {o["case"]: o for o in obs}
        k = cases["kill_server_during_request"]
        sus, inter, flap, hlt, down = (cases[n] for n in ("sustained_failure_after_3_attacks", "intermittent_two_isolated_errors", "every_other_request_fails", "healthy_control", "unreachable_at_start"))
        recomputed = {
            "kill_mid_request_gives_fixed_error_without_hang": k["adapter_error_kind"] in ("unavailable", "timeout", "bad_response") and not k["hung_past_timeout"] and not k["returned_text"],
            "recovers_after_restart": k.get("next_request_after_restart_ok") is True,
            "sustained_failure_fails_run_closed": sus["final_state"] == "FAILED" and sus["terminal_verified"] and sus["audit_verifies"] and sus["release_attempt_status"] != 200,
            "no_artifacts_readable_from_failed_run": all(c != 200 for c in sus["artifact_read_status_before_release"].values()),
            "intermittent_errors_mark_run_incomplete": inter["final_state"] == "SEALED" and inter["complete"] is False and inter["model_backend_errors"] == 2,
            "flapping_backend_marks_run_incomplete": flap["final_state"] == "FAILED" or flap["complete"] is False,
            "healthy_control_complete": hlt["final_state"] == "SEALED" and hlt["complete"] is True and hlt["model_backend_errors"] == 0,
            "unreachable_start_fails_closed": down["final_state"] == "FAILED" and down["audit_verifies"] and down["evaluated"] == 0,
            "api_key_in_no_run_file": not any(o.get("api_key_in_run_files") for o in obs),
        }
        rows.append(("E5: all failure-handling checks recomputed from the recorded cases", "E5 observations", "%d/%d" % (sum(recomputed.values()), len(recomputed)),
                     recomputed == res["summary"]["checks"]))
        claims["e5"] = "failure handling: %d of %d checks hold" % (sum(recomputed.values()), len(recomputed))
        claims["e5_class"] = "E5 classification: %s" % res["classification"]
    # ---- P0 revalidation of the earlier model experiments on the Phase 2 and Phase 3 trees
    for label, rel in (("Phase 2 tree (unmodified rc2)", "revalidation_rc2_unmodified/model_experiments_rc2_unmodified.json"),
                       ("Phase 3 tree", "revalidation_candidate_tree/model_experiments_phase3_tree.json")) if old else ():
        f = base / rel
        if not f.exists():
            rows.append(("M1-M6 revalidation on the %s present" % label, rel, "missing", False))
            continue
        m = json.loads(f.read_text())
        key = "m_rc2" if "rc2" in rel else "m_p3"
        claims[key] = m_claim(label, m)
        rows.append(("M1-M6 revalidation on the %s: raw file readable, tree hash recorded" % label, rel, m["code_revision"]["tree_sha256"][:19], True))
    # ---- the report must quote exactly these figures
    rep = REL / report
    text = rep.read_text() if rep.exists() else None
    for k, v in sorted(claims.items()):
        rows.append(("%s quotes: %s" % (Path(report).name, v[:90]), "recomputed", "present" if text and v in text else ("report missing" if text is None else "NOT FOUND"), bool(text and v in text)))
    return rows, claims


def m_claim(label, m):
    m1_, m45_ = m["M1_canary_isolation"], m["M4_M5_access_and_monitoring"]
    m6_ = m["M6_failure_behaviour"]
    return "%s: canary leaks %d/%d and %d/%d, marker hits %d in %d responses, API key in run files: %d, failure cases ending FAILED with a verified terminal checkpoint: %d of 3" % (
        label, m1_["cache_prompt_false"]["leaks"], m1_["cache_prompt_false"]["probe_trials"], m1_["cache_prompt_true"]["leaks"], m1_["cache_prompt_true"]["probe_trials"],
        m45_["marker_hits"], m45_["responses_scanned"], len(m45_["api_key_found_in_run_files"]),
        sum(m6_[c]["final_state"] == "FAILED" and m6_[c]["terminal_checkpoint_verified"] for c in ("timeout_50ms", "wrong_api_key", "server_down_before_run")))



# ----------------------------------------------------------------------------------------------- finale P3 (Part E)
# The Phase 3 experiments re-run with the restored real model on the P3 code (10 Nov 2026), plus the P3-only evidence: the
# hardened model-server check, one real-model timing execution, the live real-model console bundle and a second model.
# These are the CURRENT real-model figures; Part C keeps the 23 Oct runs checkable as history.
P3F_DIR = ROOT / "evidence" / "finale_p3_2026-11-10"
P3F = P3F_DIR / "llm"
P3F_SECOND = P3F_DIR / "llm_qwen2.5-1.5b"
P3F_README = "aegislab/evidence/finale_p3_2026-11-10/README.md"


def latest_real_model():
    """(INDEX directory, label) of the newest real-model experiment set: what demos and the console should quote."""
    if (P3F / "INDEX.json").exists():
        return P3F, "re-measured 10 Nov 2026 on the finale P3 code"
    return P3, "recorded 23 Oct 2026"


def _dir_run(base, prefix):
    runs_ = sorted(d for d in base.iterdir() if d.is_dir() and d.name.startswith(prefix)) if base.exists() else []
    return runs_[-1] if runs_ else None


def finale_p3_rows(full=False):
    """Part E. Returns (rows, claims, comparison). comparison: [(figure, 23 Oct, 10 Nov)] printed side by side, not pass/fail."""
    rows, claims, comp = [], {}, []
    if not (P3F / "INDEX.json").exists():
        return [("finale P3 real-model evidence present", "finale_p3_2026-11-10/llm/INDEX.json", "not present (skipped)", True)], claims, comp
    sys.path.insert(0, str(HERE))
    from llm_common import auc_with_permutation, sha256_file, source_hashes
    r, c = phase3_rows(P3F, P3F_README)
    for row in r:  # the re-measured runs must not depend on any acknowledgement: their sources are the current ones
        if "security-relevant sources unchanged" in row[0]:
            row = (row[0] + " (no acknowledgement allowed)", row[1], row[2], row[3] and row[2] == "no drift")
        rows.append(("10 Nov " + row[0], row[1], row[2], row[3]))
    claims.update({"f_" + k: v for k, v in c.items()})
    _, old = phase3_rows()
    for k in sorted(c):
        if k in old:
            comp.append((k, old[k], c[k]))
    if (P3F_SECOND / "INDEX.json").exists():
        r2, c2 = phase3_rows(P3F_SECOND, P3F_README)
        rows += [("1.5B " + x[0], x[1], x[2], x[3] and ("security-relevant" not in x[0] or x[2] == "no drift")) for x in r2]
        claims.update({"s_" + k: "Qwen2.5-1.5B: " + v for k, v in c2.items()})
    # M1-M6, unmodified script, on the P3 tree
    mf = P3F_DIR / "model_experiments_M1_M6.json"
    if mf.exists():
        m = json.loads(mf.read_text())
        claims["f_m"] = m_claim("finale P3 tree (10 Nov 2026)", m)
        rows.append(("10 Nov M1-M6 on the finale P3 tree: raw file readable, tree hash recorded", mf.name, m["code_revision"]["tree_sha256"][:19], True))
        oldm = json.loads((P3 / "revalidation_candidate_tree/model_experiments_phase3_tree.json").read_text())
        comp.append(("M1-M6", m_claim("Phase 3 tree", oldm), claims["f_m"]))
    # hardened model server (scripts/start_model_server.sh)
    hd = _dir_run(P3F_DIR / "model_server_hardening", "P3H-")
    if hd:
        res = json.loads((hd / "result.json").read_text())
        obs = _jsonl(hd / "observations.jsonl")
        ok_hash = sha256_file(hd / "observations.jsonl") == res["observations_sha256"] and len(obs) == res["observation_count"]
        drift = [k for k, h in res["source_sha256"].items() if (ROOT / k).exists() and sha256_file(ROOT / k) != h]
        cells = {}
        for o in obs:
            cells.setdefault(o["cell"], []).append(o)
        recomputed = {k: (sum(o["cached_tokens"] > 0 for o in v), auc_with_permutation([o["cached_tokens"] for o in v if o["guess_correct"]],
                                                                                    [o["cached_tokens"] for o in v if not o["guess_correct"]], perms=1000)["auc"])
                      for k, v in cells.items()}
        stored = {x["cell"]: (x["trials_with_cached_tokens"], x["cached_tokens_oracle"]["auc"]) for x in res["cells"]}
        closed = [k for k in recomputed if not k.startswith("control") and k.endswith(("/aegislab", "/field_absent"))]
        rows += [("P3 hardened server: observation hash and count", hd.name, "%d observations" % len(obs), ok_hash),
                 ("P3 hardened server: sources unchanged since the check (launcher, adapter, checker)", hd.name, "drift: %s" % (drift or "none"), not drift),
                 ("P3 hardened server: per-cell cached-token counts and AUC recomputed", hd.name, "%d cells" % len(recomputed), recomputed == stored),
                 ("P3 hardened server: 0 cached tokens for broker-style and field-absent requests, both modes", hd.name,
                  ", ".join("%s %d" % (k, recomputed[k][0]) for k in closed), bool(closed) and all(recomputed[k][0] == 0 for k in closed)),
                 ("P3 hardened server: every recorded check holds", hd.name, "%d/%d" % (sum(res["checks"].values()), len(res["checks"])),
                  all(res["checks"].values()) and res["classification"] == "pass")]
        n = 2 * res["trials_per_class"]
        claims["f_hardening"] = ("hardened launcher: cached prompt tokens in %d of %d broker-style trials and %d of %d field-absent trials (host process and sandbox); "
                                 "a client sending cache_prompt=true still gets them (AUC %s)" % (
                                     sum(recomputed[k][0] for k in closed if k.endswith("/aegislab")), n * sum(k.endswith("/aegislab") for k in closed),
                                     sum(recomputed[k][0] for k in closed if k.endswith("/field_absent")), n * sum(k.endswith("/field_absent") for k in closed),
                                     "/".join("%.2f" % recomputed[k][1] for k in sorted(recomputed) if k.endswith("/client_true"))))
    # one real-model timing execution
    td = P3F_DIR / "timing_real_model"
    if (td / "result.json").exists():
        import random as _r
        import timing_eval as te
        res = json.loads((td / "result.json").read_text())
        changed = [n for n, h in res["raw_files_sha256"].items() if sha(td / n) != h]
        rows.append(("P3 real-model timing: raw files unchanged", "timing_real_model", "changed: %s" % (changed or "none"), not changed and res["status"] == "COMPLETE"))
        if not changed:
            meta = json.loads((td / "raw_runs.json").read_text())
            bad = {m_["run_id"] for m_ in meta if "unusable" in m_}
            raw = _jsonl(td / "raw_classification.jsonl")
            ok, parts = True, []
            for b in res["padding_intervals_ms"]:
                rws = [(x["rep"], x["latency_ms"], x["refused"]) for x in raw if x["bucket_ms"] == b and x["run_id"] not in bad]
                if full:
                    a = te.analyse(rws, res["seed"])
                    acc, pv = a["heldout_accuracy"], a["permutation_p"]
                    ok &= acc == res["conditions"][str(b)]["heldout_accuracy"] and pv == res["conditions"][str(b)]["permutation_p"]
                else:
                    acc = round(te.score(te.grouped_cv(rws, 5, _r.Random(res["seed"])))[0], 3)
                    pv = res["conditions"][str(b)]["permutation_p"]
                    ok &= acc == res["conditions"][str(b)]["heldout_accuracy"]
                parts.append((b, acc, res["conditions"][str(b)]["majority_baseline"], pv, len(rws)))
            cal = res["calibration"]
            calraw = _jsonl(td / "raw_calibration.jsonl")
            ans = sorted(x["latency_ms"] for x in calraw if not x["refused"])
            p99 = ans[round(0.99 * (len(ans) - 1))]
            ok_cal = abs(p99 - cal["answered"]["p99_ms"]) < 0.01 and cal["p99_bucket_ms"] == int(-(-p99 // 100) * 100)
            rows.append(("P3 real-model timing: calibration p99 and the p99 bucket recomputed from raw", "raw_calibration.jsonl",
                         "p99 %.1f ms -> bucket %d ms" % (p99, cal["p99_bucket_ms"]), ok_cal))
            rows.append(("P3 real-model timing: held-out accuracy recomputed%s" % (" and permutation p re-run" if full else ""), "raw_classification.jsonl",
                         "; ".join("%d ms acc %.3f p %.4f" % (b, acc, pv) for b, acc, _, pv, _ in parts), ok))
            claims["f_timing"] = ("real-model timing, ONE execution, 10 Nov 2026 (calibration: answered p50 %.0f ms, p99 %.0f ms): held-out accuracy %s (majority baseline %s)" % (
                cal["answered"]["median_ms"], cal["answered"]["p99_ms"],
                ", ".join("%.3f at %d ms (p=%.4f)" % (acc, b, pv) for b, acc, _, pv, _ in parts), "/".join("%.3f" % x[2] for x in parts)))
    # the live real-model console bundle (exported by the reviewer release in the Playwright run)
    lb = P3F_DIR / "live_console_bundle" / "LAB-001"
    if lb.is_dir():
        import subprocess
        pr = subprocess.run([sys.executable, "-m", "aegis.verify_cli", "--bundle", str(lb), "--run-id", "LAB-001", "--expect-state", "RELEASED"],
                            capture_output=True, text=True, cwd=ROOT)
        try:
            v = json.loads(pr.stdout)
        except ValueError:
            v = {}
        audit = _jsonl(lb / "audit.jsonl")
        so = next((e for e in audit if e["type"] == "model.session_opened"), {})
        ident = ((so.get("data") or {}).get("backend") or {}).get("declared_identity") or {}
        rows.append(("P3 live console run LAB-001 (real model): strict verification", "live_console_bundle/LAB-001", "exit %d, terminal_verified %s" % (pr.returncode, v.get("terminal_verified")),
                     pr.returncode == 0 and v.get("ok") is True and v.get("terminal_verified") is True))
        rows.append(("P3 live console run LAB-001: the signed log names the weights and the sandboxed server", "audit.jsonl",
                     "%s %s %s" % (ident.get("model_file"), (ident.get("model_sha256") or "")[:12], ident.get("server_isolation")),
                     (ident.get("model_sha256") or "").startswith("74a4da8c") and ident.get("server_isolation") == "rootless-podman-network-none"))
    # the evidence README must quote every Part E figure verbatim
    text = (REL / P3F_README).read_text() if (REL / P3F_README).exists() else None
    for k, v in sorted(claims.items()):
        if k.startswith(("f_hardening", "f_timing", "f_m")) or k.startswith("s_"):
            rows.append(("README quotes: %s" % v[:90], "recomputed", "present" if text and v in text else ("README missing" if text is None else "NOT FOUND"), bool(text and v in text)))
    return rows, claims, comp

def main():
    full = "--full" in sys.argv[1:]
    iso, aud, mod = load("isolation_matrix.json"), load("audit_tamper.json"), load("model_experiments.json")
    e19 = json.loads((V / "e1_e9_rerun" / "results.json").read_text())
    e2 = e19["E2_cross_tenant"]
    cats = aud["categories"]
    m1, m3, m45 = mod["M1_canary_isolation"], mod["M3_fresh_vs_reused_worker"], mod["M4_M5_access_and_monitoring"]
    gap = aud["original_gap_case"]
    rows = [
        (2, "181/181 unauthorized cases denied", "isolation_matrix.json", "%d/%d" % (iso["denied_as_expected"], iso["cases_expect_deny"]), "181/181"),
        (2, "0 unauthorized successes", "isolation_matrix.json", str(iso["unauthorized_succeeded"]), "0"),
        (2, "0 marker hits in 216 public bodies", "isolation_matrix.json", "%d in %d" % (iso["secret_marker_hits"], iso["public_get_bodies_scanned"]), "0 in 216"),
        (2, "92/92 traversal cases rejected", "isolation_matrix.json", "%d/%d" % (iso["path_traversal_rejected"], iso["path_traversal_cases"]), "92/92"),
        (3, "19 tamper categories", "audit_tamper.json", str(len(cats)), "19"),
        (3, "every category 30/30 detected", "audit_tamper.json", "%d/%d categories 30/30" % (sum(c["detected"] == c["trials"] == 30 for c in cats.values()), len(cats)), "19/19 categories 30/30"),
        (3, "clean logs 30/30 accepted, terminal verified 30/30", "audit_tamper.json", "%d / %d" % (aud["clean_runs_verify"], aud["clean_runs_terminal_verified"]), "30 / 30"),
        (3, "truncation: 0/30 old rules, 30/30 fail-closed", "audit_tamper.json", "%d / %d" % (gap["old_rules_detected (require_terminal=False)"], gap["new_rules_detected_fail_closed"]), "0 / 30"),
        (3, "CLI: 10/10 genuine accepted, 40/40 tampered rejected", "audit_tamper.json", "%d/%d, %d/%d" % (aud["cli_level"]["genuine_accepted"], aud["cli_level"]["bundles"], aud["cli_level"]["tampered_rejected"], aud["cli_level"]["tampered_total"]), "10/10, 40/40"),
        (5, "real model: 0/80 and 0/80 canary leaks", "model_experiments.json", "%d/%d, %d/%d" % (m1["cache_prompt_false"]["leaks"], m1["cache_prompt_false"]["probe_trials"], m1["cache_prompt_true"]["leaks"], m1["cache_prompt_true"]["probe_trials"]), "0/80, 0/80"),
        (5, "real model: 0 hits in 270 responses, 66 markers", "model_experiments.json", "%d in %d, %d markers" % (m45["marker_hits"], m45["responses_scanned"], m45["distinct_markers"]), "0 in 270, 66 markers"),
        (5, "real model: 21/21 unauthorized reads refused", "model_experiments.json", "%d/%d" % (m45["unauthorized_artifact_reads_attempted"] - m45["unauthorized_artifact_reads_succeeded"], m45["unauthorized_artifact_reads_attempted"]), "21/21"),
        (5, "reused server: 162 cached prompt tokens vs 0 fresh", "model_experiments.json", "%d vs %d" % (m3["reused_worker_cache_prompt_true"]["probe_cached_tokens_median"], m3["fresh_worker_new_process_per_session"]["probe_cached_tokens_max"]), "162 vs 0"),
        (1, "E2 re-run: 150/150 forbidden requests denied, 90/90 connects failed, 240/240 foreign paths absent", "e1_e9_rerun/results.json",
         "%d/%d, %d/%d, %d/%d" % (e2["forbidden_broker_requests"]["denied"], e2["forbidden_broker_requests"]["attempts"], e2["network_connect_attempts"]["failed"],
                                  e2["network_connect_attempts"]["attempts"], e2["foreign_paths_checked"]["absent"], e2["foreign_paths_checked"]["checks"]), "150/150, 90/90, 240/240"),
    ]
    bad = 0
    print("%-3s %-62s %-26s %s" % ("obj", "claim", "source", "found"))
    for obj, claim, src, found, want in rows:
        ok = want is None or found == want
        bad += not ok
        print("%-3d %-62s %-26s %s%s" % (obj, claim, src, found, "" if ok else "   <-- MISMATCH (expected %s)" % want))
    print("\n%d/%d quoted numbers match their source files" % (sum(1 for r in rows if r[4] is None or r[3] == r[4]), len(rows)))
    print("(Part A figures were recorded on 22 Oct 2026, code tree %s; the security-relevant ones are re-measured on the finale P2 code in Part D)"
          % load("audit_tamper.json")["code_revision"]["tree_sha256"][:19])
    trows, claims = timing_rows(full)
    print("\nTIMING: recomputed from raw per-request / per-round-trip files%s" % (" (incl. permutation tests)" if full else ""))
    for claim, src, found, ok in trows:
        print("%-4s %-100s %-26s %s" % ("ok" if ok else "FAIL", claim[:100], src, found))
    tbad = sum(not r[3] for r in trows)
    print("\n%d/%d timing checks pass" % (len(trows) - tbad, len(trows)))
    print("timing claims as they must be quoted: " + json.dumps(claims, ensure_ascii=False))
    prow, pclaims = phase3_rows()
    print("\nPHASE 3 (LLM experiments): recomputed from the raw observation files")
    for claim, src, found, ok in prow:
        print("%-4s %-100s %-26s %s" % ("ok" if ok else "FAIL", claim[:100], src[:26], found))
    pbad = sum(not r[3] for r in prow)
    print("\n%d/%d Phase 3 checks pass" % (len(prow) - pbad, len(prow)))
    print("Phase 3 claims as they must be quoted: " + json.dumps(pclaims, ensure_ascii=False))
    drows = remeasured_rows()
    print("\nRE-MEASURED on the finale P2 code (evidence/finale_rebaseline_2026-11-10): security properties from the raw files")
    for claim, src, found, ok in drows:
        print("%-4s %-100s %-26s %s" % ("ok" if ok else "FAIL", claim[:100], src[:26], found))
    dbad = sum(not r[3] for r in drows)
    print("\n%d/%d re-measured checks pass" % (len(drows) - dbad, len(drows)))
    erows, eclaims, comp = finale_p3_rows(full)
    print("\nFINALE P3 (real model re-measured on the P3 code, evidence/finale_p3_2026-11-10): recomputed from the raw files")
    for claim, src, found, ok in erows:
        print("%-4s %-100s %-26s %s" % ("ok" if ok else "FAIL", claim[:100], src[:26], found))
    ebad = sum(not r[3] for r in erows)
    print("\n%d/%d finale P3 checks pass" % (len(erows) - ebad, len(erows)))
    if comp:
        print("\nreal-model figures, 23 Oct 2026 (Part C, historical) vs 10 Nov 2026 (Part E, current):")
        for k, o, n in comp:
            print("  %-9s 23 Oct: %s\n  %-9s 10 Nov: %s%s" % (k, o, "", n, "" if o.replace("Phase 3 tree", "") == n.replace("finale P3 tree (10 Nov 2026)", "") else "   <-- differs"))
    print("finale P3 claims as they must be quoted: " + json.dumps(eclaims, ensure_ascii=False))
    return 1 if (bad or tbad or pbad or dbad or ebad) else 0


if __name__ == "__main__":
    sys.exit(main())
