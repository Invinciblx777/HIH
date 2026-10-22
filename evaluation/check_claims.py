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
    "Judge_QA.md": ["acc0", "acc100", "acc250", "acc500", "cost250", "idle", "limited", "unres", "unres_inc", "unres_p99"],
    "VALIDATION_ADDENDUM_2026-10-22.md": ["acc0", "acc100", "acc250", "acc500", "pmin", "pool250", "cost250", "idle", "limited", "limited_inc",
                                          "unres", "unres_inc", "unres_p99", "unres_p99_inc"],
    "RELEASE_READINESS_REPORT.md": ["acc250", "cost250", "unres_inc"],
    "aegislab/README.md": ["acc0", "acc250"],
    "aegislab/THREAT_MODEL.md": ["acc250", "unres_inc"],
    "deck:slide6": ["acc250"],
    "deck:notes6": ["acc0", "acc250", "cost250"],
    "deck:notes7": ["acc250"],
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
    trows, claims = timing_rows(full)
    print("\nTIMING: recomputed from raw per-request / per-round-trip files%s" % (" (incl. permutation tests)" if full else ""))
    for claim, src, found, ok in trows:
        print("%-4s %-100s %-26s %s" % ("ok" if ok else "FAIL", claim[:100], src, found))
    tbad = sum(not r[3] for r in trows)
    print("\n%d/%d timing checks pass" % (len(trows) - tbad, len(trows)))
    print("timing claims as they must be quoted: " + json.dumps(claims, ensure_ascii=False))
    return 1 if (bad or tbad) else 0


if __name__ == "__main__":
    sys.exit(main())
