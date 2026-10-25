"""Phase 4: check that the presentation package tells the same story as the raw evidence.

    python evaluation/check_presentation.py                    # exit 0 only if every check passes
    python evaluation/check_presentation.py --dump-claims F    # write the recomputed figures the deck builder formats (JSON)
    python evaluation/check_presentation.py --validation V     # V = validation_results.json (test counts of the executed validation)

Nothing here is typed in as a desired result. The figures come from evaluation/check_claims.py (which recomputes them from the raw
observations / timing files) plus the extra recomputations in derive(). The claim-to-evidence matrix (PHASE4_CLAIM_MATRIX.json) names, for each
claim, the documents that must quote it and the tokens (formatted here from the recomputed figures) that must be present. Checks:

  1. every artifact path named in the matrix exists in the release;
  2. every token of every claim is present in every document the matrix lists for it (deck slide text, speaker notes, voice-over,
     captions, storyboard, Judge_QA, README);
  3. no figure from an earlier release (144 / 297 tests, 0/30 truncation, 0.80 -> 0.57 timing, ...) is presented as current in any
     presentation document;
  4. every mandatory qualification phrase is present on the slide that carries the claim it qualifies;
  5. the deck has exactly 8 slides and every slide has speaker notes; the SRT is well formed and agrees with the spoken text.
"""
import argparse
import json
import re
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
REL = ROOT.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT))

P3 = ROOT / "evidence" / "phase3_2026-10-23" / "llm"
DECK = "Tech_Mavericks_AegisLab_Submission.pptx"
MATRIX = "PHASE4_CLAIM_MATRIX.json"
DOCS = {"vo": "Voiceover_Script.txt", "srt": "Captions.srt", "storyboard": "Storyboard_Timestamped.txt", "qa": "Judge_QA.md", "readme": "README_FIRST.md",
        "report": "PHASE4_PRESENTATION_REPORT.md", "matrix_md": "PHASE4_CLAIM_MATRIX.md"}
# presentation documents that must not carry an earlier figure as current
PRESENTATION = ["vo", "srt", "storyboard", "qa", "readme"] + ["deck:slide%d" % i for i in range(1, 9)] + ["deck:notes%d" % i for i in range(1, 9)]
STALE = [r"\b144 (?:automated )?tests", r"\b297 (?:tests|passed)", r"\b0/30\b", r"0\.80\s*(?:→|->|to)\s*0\.57", r"\b0\.57\b", r"\b30/30 detected; truncation",
         r"truncation 0/30", r"\b13 automated tests", r"\b33/33\b", r"~?2\.6[–-]2\.8\s*ms", r"stub model worker\b(?!.*not)", r"\+37\.5%", r"\b4\.62\b"]
HISTORICAL = re.compile(r"histor|superseded|earlier release|Phase 1|Phase 2|15 Oct|did not reproduce|unverified|before the fix|rc3|previous", re.I)


def jl(path):
    return [json.loads(x) for x in Path(path).read_text().splitlines() if x.strip()]


def derive(validation=None):
    """Figures recomputed from raw evidence. Returns a flat dict of numbers and strings."""
    import check_claims as cc
    rows, c3 = cc.phase3_rows()
    trows, ct = cc.timing_rows(False)
    d = {"p3_rows_ok": all(r[3] for r in rows), "timing_rows_ok": all(r[3] for r in trows), "p3_rows": len(rows), "timing_rows": len(trows)}
    d.update({"claim_" + k: v for k, v in c3.items()})
    d.update({"timing_" + k: v for k, v in ct.items()})
    index = {e["experiment"]: e for e in json.loads((P3 / "INDEX.json").read_text())}
    d["run_ids"] = {k.split("_")[0]: v["dir"] for k, v in index.items()}
    # E1 isolation, controls, per-probe sensitivity
    e1 = jl(P3 / index["E1_canary_matrix"]["dir"] / "observations.jsonl")
    sess = {}
    for o in e1:
        s = sess.setdefault((o["condition"], o["ordering"]), {"sessions": set(), "leak_sessions": set(), "trials": 0, "leaks": 0})
        s["sessions"].add(o["session"])
        s["trials"] += 1
        if o["leaks"]:
            s["leaks"] += 1
            s["leak_sessions"].add(o["session"])

    def pool(pred):
        cells = [v for k, v in sess.items() if pred(k[0])]
        return {"sessions": sum(len(v["sessions"]) for v in cells), "leak_sessions": sum(len(v["leak_sessions"]) for v in cells),
                "trials": sum(v["trials"] for v in cells), "leaks": sum(v["leaks"] for v in cells), "cells": len(cells)}
    d["e1_iso"] = pool(lambda c: c.startswith(("reused_server", "fresh_server")))
    d["e1_neg"] = pool(lambda c: c.startswith("negative"))
    d["e1_hist"] = pool(lambda c: c == "positive_control_shared_history")
    d["e1_gw"] = pool(lambda c: c == "positive_control_sharing_gateway")
    per = {}
    for o in e1:
        if o["condition"] == "positive_control_shared_history":
            per.setdefault(o["probe"], set())
            if o["leaks"]:
                per[o["probe"]].add(o["session"])
    d["e1_probes"] = len(per)
    d["e1_silent_probes"] = sorted(p for p, v in per.items() if not v)
    # E2
    e2 = jl(P3 / index["E2_pipeline_canary"]["dir"] / "observations.jsonl")
    by = {}
    for o in e2:
        c = by.setdefault(o["condition"], {"runs": set(), "model": set(), "attacks": 0, "red": 0, "withheld": 0})
        c["runs"].add(o["run"])
        c["attacks"] += 1
        c["red"] += bool(o["foreign_in_final_output"])
        c["withheld"] += o["outcome"] in ("withheld_canary", "withheld_secret")
        if o["foreign_in_model_output"]:
            c["model"].add(o["run"])

    def pool2(pred):
        cs = [v for k, v in by.items() if pred(k)]
        return {"runs": sum(len(v["runs"]) for v in cs), "runs_leaking": sum(len(v["model"]) for v in cs), "attacks": sum(v["attacks"] for v in cs),
                "red": sum(v["red"] for v in cs), "withheld": sum(v["withheld"] for v in cs)}
    d["e2_iso"] = pool2(lambda k: not k.startswith(("negative", "positive")))
    d["e2_neg"] = pool2(lambda k: k.startswith("negative"))
    d["e2_gw"] = pool2(lambda k: k.startswith("positive"))
    # E3
    import statistics
    e3 = jl(P3 / index["E3_kv_cache_oracle"]["dir"] / "observations.jsonl")
    cells = {}
    for o in e3:
        cells.setdefault(o["cell"], []).append(o)
    med = lambda xs: statistics.median(xs)  # noqa: E731
    on, off = cells["np1_cache_on"], [o for k, v in cells.items() if "cache_off" in k for o in v]
    d["e3_on_cached_correct"] = med([o["cached_tokens"] or 0 for o in on if o["guess_correct"]])
    d["e3_on_cached_wrong"] = med([o["cached_tokens"] or 0 for o in on if not o["guess_correct"]])
    d["e3_on_wall_correct"] = round(med([o["wall_ms"] for o in on if o["guess_correct"]]))
    d["e3_on_wall_wrong"] = round(med([o["wall_ms"] for o in on if not o["guess_correct"]]))
    d["e3_off_wall_median"] = round(med([o["wall_ms"] for o in off]))
    d["e3_off_trials"] = len(off)
    d["e3_off_cached"] = sum((o["cached_tokens"] or 0) > 0 for o in off)
    # E4 / E5
    e4 = jl(P3 / index["E4_injection_output_isolation"]["dir"] / "observations.jsonl")
    d["e4_attacks"], d["e4_reached"] = len(e4), sum(o["verdict_in"] == "allow" for o in e4)
    res4 = json.loads((P3 / index["E4_injection_output_isolation"]["dir"] / "result.json").read_text())["summary"]["gate_replay"]
    d["e4_gate_attempts"], d["e4_gate_denied"] = res4["attempts"], res4["denied_or_rejected"]
    # Phase 2 role matrix
    rm = json.loads((ROOT / "evidence" / "phase2_2026-10-23" / "role_matrix_extended.json").read_text())["totals"]
    d["role_matrix"] = {k: rm[k] for k in ("attempted", "expected_deny", "denied", "unexpectedly_permitted", "expected_allow", "allowed", "secret_hits")}
    if validation:
        d["validation"] = json.loads(Path(validation).read_text())
    return d


# ---- token formatters: the text that a document must contain for a claim, formatted from recomputed figures
def n(x):
    return "{:,}".format(x)


TOKENS = {
    "e1_sessions": lambda d: ["%d / %d" % (d["e1_iso"]["leak_sessions"], d["e1_iso"]["sessions"]), n(d["e1_iso"]["trials"])],
    "e1_bound_sessions": lambda d: [re.search(r"([\d.]+)% of trials, ([\d.]+)% of sessions", d["claim_e1_bound"]).group(2) + "%"],
    "e1_bound_trials": lambda d: [re.search(r"([\d.]+)% of trials", d["claim_e1_bound"]).group(1) + "%"],
    "e1_neg": lambda d: ["%d / %d" % (d["e1_neg"]["leak_sessions"], d["e1_neg"]["sessions"]), n(d["e1_neg"]["trials"])],
    "e1_hist": lambda d: ["%d / %d" % (d["e1_hist"]["leak_sessions"], d["e1_hist"]["sessions"])],
    "e1_gw": lambda d: ["%d / %d" % (d["e1_gw"]["leak_sessions"], d["e1_gw"]["sessions"])],
    "e1_silent": lambda d: [", ".join(d["e1_silent_probes"]), "%d of %d" % (len(d["e1_silent_probes"]), d["e1_probes"])],
    "e2_iso": lambda d: ["%d / %d" % (d["e2_iso"]["runs_leaking"], d["e2_iso"]["runs"])],
    "e2_neg": lambda d: ["%d / %d" % (d["e2_neg"]["runs_leaking"], d["e2_neg"]["runs"])],
    "e2_gw": lambda d: ["%d / %d" % (d["e2_gw"]["runs_leaking"], d["e2_gw"]["runs"])],
    "e3_on": lambda d: [str(int(d["e3_on_cached_correct"])), str(int(d["e3_on_cached_wrong"])), "1.00"],
    "e3_off": lambda d: ["%d / %d" % (d["e3_off_cached"], d["e3_off_trials"])],
    "e3_latency": lambda d: ["%d ms" % d["e3_off_wall_median"]],
    "e4_attacks": lambda d: [str(d["e4_attacks"])],
    "e4_gate": lambda d: ["%d / %d" % (d["e4_gate_denied"], d["e4_gate_attempts"])],
    "e5": lambda d: [re.search(r"(\d+) of (\d+) checks", d["claim_e5"]).group(0).replace(" of ", " / ").replace(" checks", "")],
    "role_matrix": lambda d: [str(d["role_matrix"]["attempted"]), "%d / %d" % (d["role_matrix"]["denied"], d["role_matrix"]["expected_deny"])],
    "timing": lambda d: [d["timing_acc0"], d["timing_acc250"], d["timing_cost250"]],
    "idle": lambda d: [d["timing_idle"]],
    "tests": lambda d: ["%d" % d["validation"]["tests_passed"]],
    "quickstart": lambda d: ["%d / %d" % (d["validation"]["quickstart_pass"], d["validation"]["quickstart_total"])],
    "demo": lambda d: ["%d / %d" % (d["validation"]["demo_pass"], d["validation"]["demo_total"])],
    "judge_demo": lambda d: ["%d / %d" % (d["validation"]["judge_demo_pass"], d["validation"]["judge_demo_total"])],
    "checker": lambda d: ["%d / %d" % (d["validation"]["claims_pass"], d["validation"]["claims_total"])],
}


def doc_text(name, cache={}):
    if name.startswith("deck:"):
        if not cache:
            with zipfile.ZipFile(REL / DECK) as z:
                for nm in z.namelist():
                    m = re.fullmatch(r"ppt/(slides/slide|notesSlides/notesSlide)(\d+)\.xml", nm)
                    if m:
                        xml = z.read(nm).decode("utf8")
                        paras = ["".join(re.findall(r"<a:t>([^<]*)</a:t>", x)) for x in xml.split("</a:p>")]
                        cache[("slide" if m.group(1).startswith("slides") else "notes") + m.group(2)] = "\n".join(
                            x.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"') for x in paras if x)
        return cache.get(name[5:])
    p = REL / DOCS.get(name, name)
    if not p.exists():
        return None
    t = p.read_text()
    if name == "srt":  # cue text only, joined, so a claim that spans two cues is still found
        t = " ".join(ln for ln in t.splitlines() if ln and not ln.isdigit() and "-->" not in ln)
    return t


def norm(s):
    return re.sub(r"\s+", " ", s.replace("\u00a0", " ").replace("\u2009", " ").replace("\u202f", " "))


def run_checks(validation=None):
    d = derive(validation)
    rows = []

    def add(label, ok, found=""):
        rows.append((label, bool(ok), found))
    add("Phase 3 figures recomputed from raw observations (%d checks of check_claims.py)" % d["p3_rows"], d["p3_rows_ok"], "all pass" if d["p3_rows_ok"] else "FAIL")
    add("timing figures recomputed from raw files (%d checks)" % d["timing_rows"], d["timing_rows_ok"], "all pass" if d["timing_rows_ok"] else "FAIL")
    mp = REL / MATRIX
    if not mp.exists():
        add("claim matrix present (%s)" % MATRIX, False, "missing")
        return rows, d
    matrix = json.loads(mp.read_text())
    add("claim matrix present, %d claims" % len(matrix["claims"]), len(matrix["claims"]) > 0)
    # deck structure
    try:
        from_deck = [doc_text("deck:slide%d" % i) for i in range(1, 9)]
        notes = [doc_text("deck:notes%d" % i) for i in range(1, 9)]
        add("deck has 8 slides, each with speaker notes", all(from_deck) and all(notes) and doc_text("deck:slide9") is None, "%d slides, %d notes" % (sum(bool(x) for x in from_deck), sum(bool(x) for x in notes)))
    except Exception as e:  # noqa: BLE001
        add("deck readable", False, str(e)[:80])
    for c in matrix["claims"]:
        for a in c.get("artifacts", []):
            p = REL / a
            add("%s artifact exists: %s" % (c["id"], a[-60:]), p.exists(), "present" if p.exists() else "MISSING")
        for key in c.get("tokens", []):
            for doc in c.get("appears_in", []):
                toks = TOKENS[key](d)
                if doc in ("vo", "srt", "storyboard") or doc.startswith("deck:notes"):  # spoken form: "0 / 104" is read and captioned as "0 of 104"
                    toks = [x.replace(" / ", " of ") for x in toks]
                t = doc_text(doc)
                miss = [x for x in toks if t is None or norm(x) not in norm(t)]
                add("%s %s quotes %s in %s" % (c["id"], key, toks, doc), t is not None and not miss, "present" if t is not None and not miss else ("document missing" if t is None else "NOT FOUND: %s" % miss))
        for doc, phrase in c.get("qualifiers", []):
            t = doc_text(doc)
            add("%s qualifier on %s: '%s'" % (c["id"], doc, phrase), t is not None and norm(phrase).lower() in norm(t).lower(), "present" if t and norm(phrase).lower() in norm(t).lower() else "NOT FOUND")
    for doc in PRESENTATION:
        t = doc_text(doc)
        if t is None:
            add("%s present" % doc, False, "missing")
            continue
        stale = [(tok, ln.strip()[:80]) for ln in t.splitlines() for tok in STALE if re.search(tok, ln) and not HISTORICAL.search(ln)]
        add("%s: no earlier-release figure presented as current" % doc, not stale, "none" if not stale else "; ".join("%s in '%s'" % x for x in stale[:3]))
    # SRT well formed; captions agree with the voice-over text
    srt = (REL / DOCS["srt"]).read_text() if (REL / DOCS["srt"]).exists() else None  # raw, with cue numbers and times
    vo = doc_text("vo")
    if srt and vo:
        blocks = [b for b in srt.strip().split("\n\n") if b.strip()]
        okfmt = all(re.match(r"\d+\n\d\d:\d\d:\d\d,\d{3} --> \d\d:\d\d:\d\d,\d{3}\n.+", b, re.S) for b in blocks)
        add("captions: %d well-formed cues" % len(blocks), okfmt and len(blocks) > 10)
        cap_words = re.sub(r"[^a-z0-9% ]", "", " ".join(" ".join(b.split("\n")[2:]) for b in blocks).lower().replace("-", " ")).split()
        body = [ln for ln in vo.splitlines() if ln.strip() and not ln.startswith(("[", "Spoken words", "AegisLab ·", "Same words"))]
        vo_words = re.sub(r"[^a-z0-9% ]", "", " ".join(body).lower().replace("-", " ")).split()
        add("captions contain exactly the spoken words of the voice-over script", cap_words == vo_words, "%d vs %d words" % (len(cap_words), len(vo_words)))
        last = blocks[-1].split("\n")[1].split(" --> ")[1]
        h, m, rest = last.split(":")
        s_, ms = rest.split(",")
        add("last caption ends within 120 s", int(h) * 3600 + int(m) * 60 + int(s_) + int(ms) / 1000 <= 120.0, last)
    return rows, d


def write_matrix_md(src, dst):
    m = json.loads(Path(src).read_text())
    lines = ["# Claim-to-evidence matrix (Phase 4)", "", m["note"], "",
             "Status: **current** = recomputed from raw evidence of this release; **precomputed** = recorded earlier by the real-model experiments and recomputed from their saved raw files, not run live; **historical** = a recorded result of an earlier code version, never re-run.", "",
             "| ID | Claim (as presented) | Where | Evidence artifact(s) | Run / experiment ID | Verify with | Limitation that must travel with it | Status |", "|---|---|---|---|---|---|---|---|"]
    for c in m["claims"]:
        lines.append("| %s | %s | %s | %s | %s | %s | %s | %s |" % (c["id"], c["claim"], c["where"], "<br>".join("`%s`" % a for a in c["artifacts"]), c["run_id"],
                                                                      "`%s`" % c["command"], c["limitation"], c["status"]))
    Path(dst).write_text("\n".join(lines) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write-matrix-md", nargs=2, metavar=("JSON", "MD"))
    ap.add_argument("--dump-claims")
    ap.add_argument("--validation")
    a = ap.parse_args()
    if a.write_matrix_md:
        write_matrix_md(*a.write_matrix_md)
        return 0
    if a.dump_claims:
        d = derive(a.validation)
        Path(a.dump_claims).write_text(json.dumps(d, indent=1, default=list, ensure_ascii=False))
        print("wrote", a.dump_claims)
        return 0
    default = ROOT / "evidence" / "phase4_2026-10-23" / "validation_results.json"
    rows, _ = run_checks(a.validation or (str(default) if default.exists() else None))
    for label, ok, found in rows:
        print("%-4s %-110s %s" % ("ok" if ok else "FAIL", label[:110], found))
    bad = sum(not r[1] for r in rows)
    print("\n%d/%d presentation checks pass" % (len(rows) - bad, len(rows)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
