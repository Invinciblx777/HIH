"""Evidence report for a released run (JSON and Markdown)."""
import json
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
    "By default the model worker is a deterministic stub that emulates a shared prompt cache; it is not an LLM. With "
    "AEGIS_MODEL_BACKEND=openai_compatible the broker sends stateless requests to a configured endpoint, but "
    "server-side state (prefix/KV cache, GPU memory) is outside AegisLab's control and hardware side channels are "
    "not tested. See the model_backend field of this report for which one this run used.",
    "Red learns allow/refuse outcomes through authorised outputs. Uniform refusals and timing buckets limit, but "
    "cannot eliminate, inference of defence behaviour over many queries.",
    "Hash chain, chained signed checkpoints and a signed terminal checkpoint detect modification, deletion, "
    "reordering and truncation, provided the reviewer keeps the vault copy or the terminal anchor and pins the "
    "broker public key out of band. An attacker who can rewrite every retained copy AND hold the signing key, "
    "or who controls the verifier, defeats this. Entries a compromised broker signs falsely are not detectable.",
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
    reset = next((e for e in audit if e["type"] in ("model.reset", "model.reset_skipped", "model.session_closed")), None)
    pack = {a["id"]: a for a in store.read_json(run.dir / "private/red/attack_pack.json", {}).get("attacks", [])}
    probes = [a for a in arts if pack.get(a["attack_id"], {}).get("category") == "cross-run canary probe"]
    prior = [c for c in read_jsonl(store.p("canaries.jsonl")) if c["run_id"] != run_id]
    return {
        "label": "Measured result from the local AegisLab prototype (%s). Not a production system." % (
            "stub model worker" if (manifest.get("model") or {"backend": "stub"}).get("backend", "stub") == "stub" else
            "real model through the %s backend, model %s" % (manifest["model"]["backend"], manifest["model"].get("model"))),
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
        "model_backend": manifest.get("model") or {"backend": "stub"},
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
        "completeness": {"complete": rec.get("complete"), "evaluated": len(arts), "attack_count": rec.get("attack_count"),
                         "model_backend_errors": rec.get("model_backend_errors", 0),
                         "note": "complete is false when the tenant mailbox failed or the model backend returned an error for any attack; "
                                 "such attacks are outcome model_error and are not evidence that the defence held"},
        "canary": {"probes": len(probes), "prior_canaries_checked": len(prior),
                   "leaks": sum(len(a["canary_leaks"]) for a in arts)},
        "audit_verification": verify_run(run_id),
        "checkpoints": read_jsonl(store.vault_path(run_id)),
        "terminal_anchor": store.read_json(store.anchor_path(run_id)),
        "post_terminal_events": len(read_jsonl(run.dir / "post_terminal.jsonl")),
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
        "- Terminal checkpoint hash (record it out of band; `verify_cli --expect-terminal-hash`): `%s`" % v.get("terminal_hash"),
        "- Entries: %d, checkpoints checked: %d, tail uncovered: %d" % (v["entries"], v["checkpoints_checked"], v["tail_uncovered"]),
    ] + ["- Finding: %s" % f for f in v["findings"]] + [
        "", "## Access-control events (denied)", "",
    ] + ["- #%s %s: %s" % (e["seq"], e.get("op"), e.get("reason")) for e in rep["access_control"]] + [
        "", "## Commitments", "",
        "- Committed %(committed)d, revealed %(revealed)d, verified %(verified)d" % rep["commitments"],
        "", "## Model state", "",
        "- Cache entries at start: %s" % rep["model_state"]["cache_entries_at_start"],
        "- Reset: %s" % (rep["model_state"]["reset"] or {}).get("action", (rep["model_state"]["reset"] or {}).get("note")),
        "- Model backend: %s" % json.dumps(rep["model_backend"], sort_keys=True),
        "", "## Completeness", "",
        "- Complete: %(complete)s; evaluated %(evaluated)s of %(attack_count)s attacks; model backend errors: %(model_backend_errors)s" % rep["completeness"],
        "", "## Cross-run canary probe", "",
        "- Probes: %(probes)d, prior canaries checked: %(prior_canaries_checked)d, leaks: %(leaks)d" % rep["canary"],
        "", "## Outcomes", "", "| Attack | Category | Input | Output | Outcome |", "|---|---|---|---|---|",
    ] + ["| %(attack_id)s | %(category)s | %(verdict_in)s | %(verdict_out)s | %(outcome)s |" % o for o in rep["outcomes"]] + [
        "", "## Limitations", "",
    ] + ["- " + l for l in rep["limitations"]]
    return "\n".join(lines) + "\n"


def export_bundle(run_id: str, dest) -> dict:
    """Write the reviewer bundle for a terminal run: log, vault checkpoints, signed terminal anchor, public key.
    Refuses runs that are not terminal or do not verify. Never overwrites an existing bundle."""
    import shutil
    from pathlib import Path
    from .runs import signer, verify_run
    run = Run(run_id)
    if run.state not in ("RELEASED", "FAILED"):
        raise ValueError("run %s is %s; only terminal runs can be exported" % (run_id, run.state))
    v = verify_run(run_id)
    if not v["ok"]:
        raise ValueError("refusing to export a run that does not verify: %s" % v["findings"])
    dest = Path(dest)
    if dest.exists() and any(dest.iterdir()):
        raise FileExistsError("%s exists and is not empty; choose another directory" % dest)
    dest.mkdir(parents=True, exist_ok=True)
    shutil.copy(run.dir / "audit.jsonl", dest / "audit.jsonl")
    shutil.copy(store.vault_path(run_id), dest / "reviewer_checkpoints.jsonl")
    shutil.copy(store.anchor_path(run_id), dest / "terminal_anchor.json")
    if (run.dir / "manifest.json").exists():
        shutil.copy(run.dir / "manifest.json", dest / "manifest.json")
    (dest / "broker_public_key.b64").write_text(signer().public_b64() + "\n")
    audit = read_jsonl(run.dir / "audit.jsonl")
    (dest / "bundle.json").write_text(json.dumps({
        "run_id": run_id, "state": run.state, "event_count": len(audit), "final_head": audit[-1]["hash"],
        "signing_key_id": signer().key_id,
        "note": "bundle.json is a convenience index and is not trusted; the signed terminal_anchor.json is."},
        indent=2, sort_keys=True) + "\n")
    rep = build(run_id)
    (dest / "evidence_report.md").write_text(markdown(rep))
    return {"dir": str(dest), "entries": len(audit), "state": run.state}
