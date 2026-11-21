"""Finale P18: the team's own red-team prompt set, split TUNE / HELD-OUT by hash, measured through the real regex rules and the
real sandboxed Qwen3Guard server (the same request path as evaluation/guard_eval.py), with input hardening OFF and ON.

    .venv/bin/python evaluation/harden_eval.py --prompts DIR --guard-rundir RUN --datasets DATASETS \
        --out evidence/finale_p18_2026-11-21 --detail ../../logs/finale_p18/run [--cutoff-list LIST] [--skip-reference]

Prompt set (DIR, outside the repository; the raw text never leaves it): ONE PROMPT PER FILE. Every regular file in DIR is read
as UTF-8 (latin-1 if that fails) and is one prompt; no file in the set has a numbered or delimited list of several prompts
(checked when the rule was set: no "Prompt N"/"Jailbreak N" markers; the few "---" lines are Markdown rules inside one prompt).
ID = sha256 of the normalised text: Unicode NFC, CRLF/CR -> LF, trailing spaces removed per line, leading/trailing blank space
removed. Two files with the same ID count once. Split: last hex digit of the ID even -> TUNE, odd -> HELD-OUT. A prompt added later
gets its split from the same rule. --cutoff-list (one ID per line) freezes the set to those IDs.

Nothing in the output holds prompt text: results.json has IDs, splits, sizes and aggregates; DETAIL/verdicts.jsonl has per-prompt
verdicts by ID (no text), and is written outside the repository. This script prints aggregates only, never a prompt.

Modes, each with hardening OFF (the P16/P17 system) and ON (aegis/harden.py + guard/harden_rules.json):
  regex          samples/defence_config.json input_patterns (ON: plus the extra rules, on the original and the normalised view)
  guard          Qwen3Guard prompt moderation, Controversial blocks, 1500 ms per call, AS DEPLOYED: text over guard_max_chars
                 (4000) is blocked unscanned (fail closed). ON: the guard also judges the normalised view; either blocks.
  guard_content  the guard's judgement of the text itself: the first 1000 characters (the playground's own prompt cap; every team
                 prompt is longer), so the length rule plays no part, and only a Safety verdict counts (a timeout is reported apart).
                 This is the detection figure; "guard" as deployed blocks every long prompt by length alone.
  both / both_content   regex OR guard / regex OR guard_content
Reference sets (from guard_eval.py, same pinned revisions): HH-RLHF 200 and JBB benign 100 (false positives), Gandalf 112 and JBB
harmful 100 (attacks); short texts, so guard == guard_content there.
Latency: wall time of the guard calls one text needs (OFF: 1 call; ON: 1, or 2 when the normalised view differs), p50/p95/max,
and how many exceed the 4000 ms deadline.
"""
import argparse
import hashlib
import json
import re
import statistics
import sys
import time
import unicodedata
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "evaluation"))
from aegis import harden  # noqa: E402
import guard_eval  # noqa: E402

HEAD = 4000          # guard_max_chars: longer text is blocked unscanned, as deployed
WINDOW = 1000        # the content view: the first 1000 characters (the playground's own prompt cap, MAX_PROMPT)
DEADLINE_MS = 4000


def norm_id_text(raw):
    t = unicodedata.normalize("NFC", raw).replace("\r\n", "\n").replace("\r", "\n")
    return "\n".join(l.rstrip() for l in t.split("\n")).strip()


def read_prompt(p):
    b = p.read_bytes()
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        return b.decode("latin-1")


def load_prompts(d, cutoff=None):
    seen = {}
    files = 0
    for p in sorted(Path(d).iterdir()):
        if not p.is_file():
            continue
        files += 1
        t = norm_id_text(read_prompt(p))
        if not t:
            continue
        pid = hashlib.sha256(t.encode("utf-8")).hexdigest()
        seen.setdefault(pid, t)
    rows = [{"id": k, "split": "TUNE" if int(k[-1], 16) % 2 == 0 else "HELD-OUT", "text": v} for k, v in sorted(seen.items())]
    if cutoff is not None:
        rows = [r for r in rows if r["id"] in cutoff]
    return rows, files


def pct(xs, q):
    return guard_eval.pct(xs, q)


def judge(gr, settings, text, content):
    """One guard decision as deployed (content=False) or on the first WINDOW characters (content=True). In the content view
    only a verdict counts as detection: a timeout or error is fail-closed in deployment but is reported apart, not as a catch."""
    g = gr.judge(text[:WINDOW] if content else text, settings)
    if content and g.get("error"):
        g = dict(g, block=False, failed_closed=True)
    return g


def verdicts(gr, settings, pats, rules, text):
    """Every mode for one text, OFF and ON. Returns (row without text, guard ms OFF, guard ms ON)."""
    norm, tech = harden.normalise(text)
    r_off = any(p.search(text) for p in pats)
    r_on = harden.match(text, norm, pats, rules)["verdict"] == "block"
    long_ = len(text) > HEAD
    g_c = judge(gr, settings, text, True)
    if long_:
        g_d = {"block": True, "safety": None, "ms": 0.0, "error": "guard_text_too_long"}
    elif len(text) <= WINDOW:  # the same call: as deployed, a timeout or error blocks
        g_d = dict(g_c, block=g_c["block"] or bool(g_c.get("failed_closed")))
    else:
        g_d = judge(gr, settings, text, False)
    ms_off = g_d["ms"]
    if norm[:WINDOW] != text[:WINDOW]:
        g_n = judge(gr, settings, norm, True)
    else:
        g_n = {"block": False, "ms": 0.0, "safety": None, "same": True}
    gc_on = g_c["block"] or g_n["block"]
    gd_on = True if long_ else (g_d["block"] or g_n["block"] or bool(g_n.get("failed_closed")))
    ms_on = (0.0 if long_ else g_d["ms"]) + (g_n["ms"] if not long_ else 0.0)
    row = {"chars": len(text), "techniques": tech, "regex_rule_on": harden.match(text, norm, pats, rules)["rule"],
           "off": {"regex": r_off, "guard": g_d["block"], "guard_content": g_c["block"], "both": r_off or g_d["block"],
                   "both_content": r_off or g_c["block"]},
           "on": {"regex": r_on, "guard": gd_on, "guard_content": gc_on, "both": r_on or gd_on, "both_content": r_on or gc_on},
           "guard_original": {k: g_c.get(k) for k in ("safety", "categories", "ms", "error")},
           "guard_normalised": {k: g_n.get(k) for k in ("safety", "categories", "ms", "error", "same")},
           "guard_ms_off": ms_off, "guard_ms_on": ms_on,
           # the content view's guard time (what a long prompt would cost if it were judged rather than refused by length)
           "guard_ms_content_off": g_c["ms"], "guard_ms_content_on": g_c["ms"] + g_n["ms"]}
    return row


MODES = ("regex", "guard", "guard_content", "both", "both_content")


def agg(rows):
    out = {"n": len(rows)}
    for arm in ("off", "on"):
        out[arm] = {m: {"blocked": sum(1 for r in rows if r[arm][m]), "rate": round(sum(1 for r in rows if r[arm][m]) / len(rows), 4) if rows else None}
                    for m in MODES}
    return out


def lat(rows, key):
    xs = [r[key] for r in rows if r[key]]
    return {"p50": pct(xs, 0.5), "p95": pct(xs, 0.95), "max": round(max(xs), 1) if xs else None, "n": len(xs),
            "over_deadline": sum(1 for x in xs if x > DEADLINE_MS)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--prompts", required=True)
    ap.add_argument("--guard-rundir", required=True)
    ap.add_argument("--datasets")
    ap.add_argument("--out", required=True)
    ap.add_argument("--detail", required=True)
    ap.add_argument("--rules", default=str(harden.RULES_FILE))
    ap.add_argument("--cutoff-list")
    ap.add_argument("--skip-reference", action="store_true")
    a = ap.parse_args()
    gr = guard_eval.load_guard_runner()
    gdir = Path(a.guard_rundir)
    gr.GUARD_DIR = str(gdir)
    settings = gr.guard_settings({"guard_mode": "qwen3guard"})
    cfg = json.loads((ROOT / "samples/defence_config.json").read_text())
    pats = [re.compile(p, re.I) for p in cfg["input_patterns"]]
    rules = harden.load_rules(a.rules)
    cutoff = set(Path(a.cutoff_list).read_text().split()) if a.cutoff_list else None
    prompts, files = load_prompts(a.prompts, cutoff)
    gr.warm_up(str(gdir))
    t0 = time.time()
    team = []
    for p in prompts:
        r = verdicts(gr, settings, pats, rules, p["text"])
        team.append(dict(r, id=p["id"], split=p["split"]))
    ref = []
    if not a.skip_reference and a.datasets:
        for t in guard_eval.load_texts(Path(a.datasets)):
            r = verdicts(gr, settings, pats, rules, t["text"])
            ref.append(dict(r, set=t["set"], kind=t["kind"], row=t["row"], text_sha256=hashlib.sha256(t["text"].encode()).hexdigest()))
    wall = round(time.time() - t0, 1)
    det = Path(a.detail)
    det.mkdir(parents=True, exist_ok=True)
    with open(det / "verdicts.jsonl", "w") as f:
        for r in team + ref:
            f.write(json.dumps(r, sort_keys=True) + "\n")
    by = lambda s: [r for r in team if r["split"] == s]  # noqa: E731
    res = {"experiment": "p18_team_redteam_harden", "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "prompt_set": {"files": files, "unique_prompts": len(team), "tune": len(by("TUNE")), "held_out": len(by("HELD-OUT")),
                          "format_rule": "one prompt per file", "id_rule": "sha256 of NFC text, LF line ends, trailing spaces removed, trimmed",
                          "split_rule": "last hex digit of the ID even -> TUNE, odd -> HELD-OUT",
                          "chars": {"min": min((r["chars"] for r in team), default=None), "median": statistics.median([r["chars"] for r in team]) if team else None,
                                    "max": max((r["chars"] for r in team), default=None), "over_guard_max_chars": sum(1 for r in team if r["chars"] > HEAD)},
                          "ids": {"TUNE": [r["id"] for r in by("TUNE")], "HELD-OUT": [r["id"] for r in by("HELD-OUT")]}},
           "team": {"all": agg(team), "TUNE": agg(by("TUNE")), "HELD-OUT": agg(by("HELD-OUT"))},
           "reference": {s: agg([r for r in ref if r["set"] == s]) for s in guard_eval.DATASETS} if ref else None,
           "latency_ms": {"team_content_off": lat(team, "guard_ms_content_off"), "team_content_on": lat(team, "guard_ms_content_on"),
                          "reference_off": lat(ref, "guard_ms_off"), "reference_on": lat(ref, "guard_ms_on"), "deadline_ms": DEADLINE_MS} ,
           "normaliser_techniques_seen": {"team": sorted({t for r in team for t in r["techniques"]}),
                                          "reference_changed": sum(1 for r in ref if r["guard_normalised"].get("same") is not True)},
           "rules": {"file": str(Path(a.rules).relative_to(ROOT)) if Path(a.rules).resolve().is_relative_to(ROOT) else Path(a.rules).name,
                     "n": len(rules), "ids": [r["id"] for r in rules],
                     "sha256": hashlib.sha256(Path(a.rules).read_bytes()).hexdigest() if Path(a.rules).is_file() else None},
           "guard": {"settings": {"block_controversial": settings["block_controversial"], "timeout_ms": int(settings["timeout_s"] * 1000),
                                  "max_chars": settings["max_chars"]}, "model_sha256": json.loads((gdir / "launch.json").read_text())["model_sha256"]},
           "content_window_chars": WINDOW,
           "guard_errors": {"team": sum(1 for r in team if r["guard_original"].get("error") or r["guard_normalised"].get("error")),
                            "reference": sum(1 for r in ref if r["guard_original"].get("error") or r["guard_normalised"].get("error"))},
           "wall_s": wall,
           "source_sha256": {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in
                             ("aegis/harden.py", "evaluation/harden_eval.py", "guard/guard_runner.py", "samples/defence_config.json")}}
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "results.json").write_text(json.dumps(res, indent=1, sort_keys=True) + "\n")
    show = {"prompt_set": {k: v for k, v in res["prompt_set"].items() if k != "ids"}, "team": res["team"], "latency_ms": res["latency_ms"],
            "guard_errors": res["guard_errors"], "wall_s": wall}
    if ref:
        show["reference"] = {s: {arm: {m: v[arm][m]["blocked"] for m in ("regex", "guard", "both")} for arm in ("off", "on")} | {"n": v["n"]}
                             for s, v in res["reference"].items()}
    print(json.dumps(show, indent=1))


if __name__ == "__main__":
    main()
