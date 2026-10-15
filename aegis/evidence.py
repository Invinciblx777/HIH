"""Evidence report for a released run (JSON and Markdown)."""
import time

from . import store
from .audit import read_jsonl
from .runs import Run, check_commitments, verify_run

LIMITATIONS = [
    "Single-host prototype. The host kernel, Podman/crun runtime, broker process and signing key are trusted; "
    "compromise of any of them defeats these guarantees.",
    "Containers share the host kernel and hardware. CPU quotas (and per-tenant cpusets, where the host delegates the "
    "cpuset controller) reduce, but do not remove, cache and timing side channels (shared LLC, memory bandwidth, "
    "kernel scheduling).",
    "The model worker is a deterministic stub that emulates a shared prompt cache. It is not an LLM; GPU inference "
    "isolation (KV cache, CUDA contexts) is not covered by this prototype.",
    "Red learns allow/refuse outcomes through authorised outputs. Uniform refusals and timing buckets limit, but "
    "cannot eliminate, inference of defence behaviour over many queries.",
    "Hash chain plus signed checkpoints detect modification, deletion, reordering and truncation up to the last "
    "checkpoint a reviewer holds. Entries written by a compromised broker before signing are not detectable.",
    "Finite tests: absence of leakage in these runs is evidence for this configuration, not proof of confidentiality.",
]


def build(run_id: str) -> dict:
    run = Run(run_id)
    rec = run.record
    manifest = store.read_json(run.dir / "manifest.json", {})
    arts = read_jsonl(run.dir / "sealed/artifacts.jsonl")
    audit = read_jsonl(run.dir / "audit.jsonl")
    denied = [e for e in audit if e["type"] == "policy.denied"]
    attested = next((e["data"] for e in audit if e["type"] == "defence.attested"), {})
    opened = next((e["data"] for e in audit if e["type"] == "model.session_opened"), {})
    reset = next((e for e in audit if e["type"] in ("model.reset", "model.reset_skipped")), None)
    pack = {a["id"]: a for a in store.read_json(run.dir / "private/red/attack_pack.json", {}).get("attacks", [])}
    probes = [a for a in arts if pack.get(a["attack_id"], {}).get("category") == "cross-run canary probe"]
    prior = [c for c in read_jsonl(store.p("canaries.jsonl")) if c["run_id"] != run_id]
    return {
        "label": "Measured result from the local AegisLab prototype (stub model worker). Not a production system.",
        "generated_at": time.time(),
        "run": {k: rec.get(k) for k in ("id", "state", "created_at", "frozen_at", "started_at", "sealed_at",
                                         "released_at", "policy", "tags", "manifest_digest", "commitments_root")},
        "digests": {
            "manifest": rec.get("manifest_digest"),
            "sandbox_image_id": manifest.get("sandbox_image_id"),
            "base_image_digest": manifest.get("base_image_digest"),
            "defence_config": manifest.get("defence_config_digest"),
            "attack_pack": manifest.get("attack_pack_digest"),
            "signing_key_id": manifest.get("signing_key_id"),
        },
        "environment": manifest.get("environment"),
        "runtime_applied": store.read_json(run.dir / "sealed/runtime_applied.json", {}),
        "sandbox_selfcheck": store.read_json(run.dir / "sealed/red_selfcheck.json", []),
        "defence_attestation": attested,
        "model_state": {"cache_entries_at_start": opened.get("cache_entries_at_start"),
                        "strategy": opened.get("strategy"),
                        "reset": reset["data"] if reset else None},
        "access_control": [{"seq": e["seq"], "actor": e["actor"], **e["data"]} for e in denied],
        "commitments": check_commitments(run_id),
        "outcomes": [{"attack_id": a["attack_id"], "category": pack.get(a["attack_id"], {}).get("category"),
                      "verdict_in": a["verdict_in"].get("verdict"), "verdict_out": a["verdict_out"].get("verdict"),
                      "outcome": a["outcome"], "answered_ms": a["answered_ms"]} for a in arts],
        "outcome_summary": rec.get("outcomes"),
        "canary": {"probes": len(probes), "prior_canaries_checked": len(prior),
                   "leaks": sum(len(a["canary_leaks"]) for a in arts)},
        "audit_verification": verify_run(run_id),
        "checkpoints": read_jsonl(store.p("reviewer_vault", run_id + ".jsonl")),
        "limitations": LIMITATIONS,
    }


def markdown(rep: dict) -> str:
    r, d = rep["run"], rep["digests"]
    v = rep["audit_verification"]
    lines = [
        "# AegisLab evidence report: %s" % r["id"], "",
        "> %s" % rep["label"], "",
        "## Run", "",
        "- State: %s" % r["state"],
        "- Policy: timing bucket %s ms, reset strategy %s" % (r["policy"]["timing_bucket_ms"], r["policy"]["reset_strategy"]),
        "", "## Digests", "",
    ] + ["- %s: `%s`" % (k, v_) for k, v_ in d.items()] + [
        "", "## Audit verification (against reviewer-held checkpoints)", "",
        "- Result: **%s**" % ("PASS" if v["ok"] else "FAIL"),
        "- Entries: %d, checkpoints checked: %d, tail uncovered: %d" % (v["entries"], v["checkpoints_checked"], v["tail_uncovered"]),
    ] + ["- Finding: %s" % f for f in v["findings"]] + [
        "", "## Access-control events (denied)", "",
    ] + ["- #%s %s: %s" % (e["seq"], e.get("op"), e.get("reason")) for e in rep["access_control"]] + [
        "", "## Commitments", "",
        "- Committed %(committed)d, revealed %(revealed)d, verified %(verified)d" % rep["commitments"],
        "", "## Model state", "",
        "- Cache entries at start: %s" % rep["model_state"]["cache_entries_at_start"],
        "- Reset: %s" % (rep["model_state"]["reset"] or {}).get("action", (rep["model_state"]["reset"] or {}).get("note")),
        "", "## Cross-run canary probe", "",
        "- Probes: %(probes)d, prior canaries checked: %(prior_canaries_checked)d, leaks: %(leaks)d" % rep["canary"],
        "", "## Outcomes", "", "| Attack | Category | Input | Output | Outcome |", "|---|---|---|---|---|",
    ] + ["| %(attack_id)s | %(category)s | %(verdict_in)s | %(verdict_out)s | %(outcome)s |" % o for o in rep["outcomes"]] + [
        "", "## Limitations", "",
    ] + ["- " + l for l in rep["limitations"]]
    return "\n".join(lines) + "\n"
