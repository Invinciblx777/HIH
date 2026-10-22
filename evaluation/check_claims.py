"""Recompute the headline numbers quoted in the deck, addendum and Judge_QA from the raw result files.

    python evaluation/check_claims.py            # exit 0 only if every quoted number matches its source file

Each row: Track 04 objective, the claim as quoted, the raw file it comes from, the value found. Nothing is measured here;
this only stops a quoted number from drifting away from the file that produced it.
"""
import json
import sys
from pathlib import Path

V = Path(__file__).resolve().parent.parent / "evidence" / "validation_2026-10-22"


def load(name):
    return json.loads((V / name).read_text())


def main():
    iso, aud, mod = load("isolation_matrix.json"), load("audit_tamper.json"), load("model_experiments.json")
    tim = [load(f) for f in ("timing.json", "timing_execution_2.json")]
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
        (2, "timing, no padding: held-out accuracy about 0.80 in both saved executions", "timing*.json", "/".join("%.2f" % t["conditions"]["0"]["heldout_accuracy"] for t in tim), "0.80/0.80"),
        (2, "timing, 250 ms: 0.41 and 0.52 (chance 0.50), cost about +200 ms", "timing*.json", "/".join("%.2f" % t["conditions"]["250"]["heldout_accuracy"] for t in tim) + ", +%d ms" % round(tim[0]["conditions"]["250"]["added_median_latency_for_answered_requests_ms"]), "0.41/0.52, +198 ms"),
        (1, "broker mailbox RTT idle median 2.5-2.7 ms (n=500)", "timing*.json", "/".join("%.2f" % t["broker_mailbox_rtt"]["idle"]["median_ms"] for t in tim), "2.64/2.54"),
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
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
