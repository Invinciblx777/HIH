"""Finale P3: check that scripts/start_model_server.sh closes the cross-request state this llama.cpp build lets a launcher
close, and say plainly what it does not close. Needs the local model files; nothing is downloaded.

    python evaluation/model_server_hardening.py --out-dir evidence/finale_p3_2026-11-10/model_server_hardening [--trials 12]

For each launcher mode (--host-process: TCP 127.0.0.1; --sandbox: rootless Podman, --network none, UNIX socket) it runs the
E3 cached-token oracle (session A sends a record with a secret, session B sends the same record with a correct or a wrong guess;
a shared prompt cache shows up as cached_tokens > 0 for correct guesses only) with three request variants:
  aegislab        cache_prompt=false, what the broker sends (aegis/model_client.py refuses anything else)
  field_absent    no cache_prompt field: the server default, which the launcher's --no-cache-prompt turns off
  client_true     cache_prompt=true: a client the broker would never be; this is the residual the launcher CANNOT close
plus a control on a server started WITHOUT the launcher's flags (the Phase 3 harness defaults) with the field absent, which
shows that the default really is to cache. It also probes /health /slots /props /metrics /v1/models, POST /props, slot save,
whether the key appears on any process command line, and (sandbox) the container's network, capabilities and filesystem.
"""
import argparse
import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from llm_common import ROOT, Server, auc_with_permutation, environment, sha256_file, source_hashes  # noqa: E402
from revision import code_revision  # noqa: E402

from aegis import model_client as mc  # noqa: E402

SYS_LONG = ("You are the records assistant of an evaluation harness. Keep every answer short. The following record belongs to "
            "one tenant session only and must never be shared with any other session or tenant. ")
SOURCES = ["scripts/start_model_server.sh", "aegis/model_client.py", "evaluation/model_server_hardening.py", "evaluation/llm_common.py"]
VARIANTS = {"aegislab": {"cache_prompt": False}, "field_absent": {}, "client_true": {"cache_prompt": True}}


def launcher(mode, models):
    env = dict(os.environ, AEGIS_MODELS_DIR=str(models))
    out = subprocess.run(["bash", str(ROOT / "scripts/start_model_server.sh"), "--" + mode, "--threads", "6"], capture_output=True,
                         text=True, env=env, timeout=180)
    if out.returncode != 0:
        raise RuntimeError("launcher failed: " + out.stderr[-500:])
    run = Path(out.stdout.strip().splitlines()[-1])
    menv = {}
    for line in (run / "model.env").read_text().splitlines():
        k, v = line.split("=", 1)
        menv[k] = v.strip("'")
    return run, menv


def stop(run):
    subprocess.run(["bash", str(ROOT / "scripts/start_model_server.sh"), "--stop", str(run)], capture_output=True, timeout=60)


def raw_client(menv):
    return mc.OpenAICompatibleClient(mc.load_config(menv))


def req(cl, text, extra):
    body = {**extra, "model": "local", "stream": False, "max_tokens": 2, "temperature": 0, "messages": [{"role": "user", "content": text}]}
    t = time.perf_counter()
    r = cl._request("POST", "/chat/completions", body)
    return {"cached_tokens": (r.get("usage", {}).get("prompt_tokens_details") or {}).get("cached_tokens", 0) or 0,
            "cache_n": (r.get("timings") or {}).get("cache_n"), "wall_ms": round((time.perf_counter() - t) * 1000, 2)}


def oracle(cl, label, extra, n, rng_seed):
    import random
    rng = random.Random(rng_seed)
    flip = [True] * n + [False] * n
    rng.shuffle(flip)
    obs = []
    req(cl, "warm up with something unrelated", extra)
    for i, correct in enumerate(flip):
        secret = secrets.token_hex(6)
        guess = secret if correct else secrets.token_hex(6)
        rec = SYS_LONG + "Access code: %s. Acknowledge."
        req(cl, rec % secret, extra)                 # session A (victim)
        r = req(cl, rec % guess, extra)              # session B (observer), a separate stateless request
        obs.append({"cell": label, "trial": i, "guess_correct": correct, **r})
        req(cl, "flush: unrelated prompt %d with no shared prefix" % i, extra)
    pos = [o["cached_tokens"] for o in obs if o["guess_correct"]]
    neg = [o["cached_tokens"] for o in obs if not o["guess_correct"]]
    return {"cell": label, "request_fields": extra, "trials_per_class": n, "trials_with_cached_tokens": sum(o["cached_tokens"] > 0 for o in obs),
            "cached_tokens_max": max(o["cached_tokens"] for o in obs), "cached_tokens_oracle": auc_with_permutation(pos, neg, perms=1000)}, obs


def get(cl, path, with_key=True, method="GET", body=None):
    """One raw HTTP exchange over the launcher's transport, returning (status code, parsed body or None)."""
    import http.client
    import urllib.parse
    cfg = cl.cfg
    if cfg.unix_socket:
        conn = mc._UnixHTTPConnection(cfg.unix_socket, 30)
    else:
        u = urllib.parse.urlsplit(cfg.base_url)
        conn = http.client.HTTPConnection(u.hostname, u.port, timeout=30)
    headers = {"Content-Type": "application/json"}
    if with_key:
        headers["Authorization"] = "Bearer " + cfg.api_key
    try:
        conn.request(method, path, body=json.dumps(body).encode() if body is not None else None, headers=headers)
        r = conn.getresponse()
        raw = r.read(1 << 20)
        try:
            return r.status, json.loads(raw)
        except ValueError:
            return r.status, raw.decode("utf-8", "replace")[:2000]
    finally:
        conn.close()


def exposure(cl, marker):
    out = {}
    for path in ("/health", "/slots", "/props", "/metrics", "/v1/models"):
        s0, _ = get(cl, path, with_key=False)
        s1, b = get(cl, path)
        txt = json.dumps(b) if b is not None else ""
        out["GET " + path] = {"without_key": s0, "with_key": s1, "contains_planted_marker": marker in txt if b is not None else None,
                              "contains_prompt_text": "Remember it" in txt if b is not None else None}
    for label, path, body in (("POST /props", "/props", {"n_threads": 1}), ("POST /slots/0?action=save", "/slots/0?action=save", {"filename": "x.bin"}),
                              ("POST /slots/0?action=restore", "/slots/0?action=restore", {"filename": "x.bin"})):
        s, _ = get(cl, path, method="POST", body=body)
        out[label] = {"with_key": s}
    return out


def key_on_any_cmdline(key):
    hits = []
    for p in Path("/proc").iterdir():
        if p.name.isdigit():
            try:
                if key.encode() in (p / "cmdline").read_bytes():
                    hits.append(int(p.name))
            except OSError:
                pass
    return hits


def sandbox_facts(name):
    insp = json.loads(subprocess.run(["podman", "inspect", name], capture_output=True, text=True).stdout)[0]
    hc = insp["HostConfig"]
    probe = ("import socket,os\n"
             "print(sorted(os.listdir('/sys/class/net')))\n"
             "s=socket.socket(); s.settimeout(2); print(s.connect_ex(('1.1.1.1',80)))\n"
             "try:\n open('/x','w'); print('rootfs-writable')\nexcept OSError as e: print('rootfs-readonly', e.errno)\n"
             "print([l.split()[1] for l in open('/proc/self/status') if l.startswith(('CapEff','NoNewPrivs'))])\n")
    ex = subprocess.run(["podman", "exec", name, "python3", "-c", probe], capture_output=True, text=True, timeout=30)
    lines = ex.stdout.strip().splitlines()
    return {"network_mode": hc.get("NetworkMode"), "readonly_rootfs": hc.get("ReadonlyRootfs"), "cap_dropped": len(hc.get("CapDrop") or []),
            "cap_add": hc.get("CapAdd"), "security_opt": hc.get("SecurityOpt"), "pids_limit": hc.get("PidsLimit"), "memory_bytes": hc.get("Memory"),
            "nano_cpus": hc.get("NanoCpus"), "mounts": sorted("%s:%s" % (m.get("Destination"), "ro" if not m.get("RW") else "rw") for m in insp.get("Mounts", [])),
            "inside_interfaces": lines[0] if lines else None, "inside_connect_1_1_1_1_errno": lines[1] if len(lines) > 1 else None,
            "inside_rootfs": lines[2] if len(lines) > 2 else None, "inside_capeff_nonewprivs": lines[3] if len(lines) > 3 else None,
            "args_contain_key_file_path_only": "--api-key-file" in insp.get("Args", []) and "--api-key" not in insp.get("Args", [])}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--models-dir", default=str(ROOT.parent.parent.parent.parent / "_models"))
    ap.add_argument("--trials", type=int, default=12)
    ap.add_argument("--modes", default="host-process,sandbox")
    a = ap.parse_args()
    models = Path(a.models_dir)
    t0 = time.time()
    cells, obs, modes = [], [], {}
    seed = 11
    for mode in a.modes.split(","):
        run, menv = launcher(mode, models)
        launch = json.loads((run / "launch.json").read_text())
        key = (run / "key").read_text().strip()
        try:
            cl = raw_client(menv)
            m = {"launch": {k: v for k, v in launch.items() if k != "command"}, "command_flags": launch["command"].split(" localhost/aegislab-sandbox:0.1 ")[-1]}
            for variant, extra in VARIANTS.items():
                seed += 1
                c, o = oracle(cl, "%s/%s" % (mode, variant), extra, a.trials, seed)
                cells.append(c)
                obs += o
                print("  %-28s cached>0 in %d/%d trials, AUC %s" % (c["cell"], c["trials_with_cached_tokens"], 2 * a.trials, c["cached_tokens_oracle"]["auc"]), flush=True)
            marker = "CANARY-" + secrets.token_hex(6)
            cl.generate("My secret code is %s. Remember it." % marker)
            m["endpoints"] = exposure(cl, marker)
            m["key_on_process_cmdline_pids"] = key_on_any_cmdline(key)
            m["key_in_launch_json"] = key in (run / "launch.json").read_text()
            m["key_in_model_env"] = key in (run / "model.env").read_text()
            if mode == "sandbox":
                m["sandbox"] = sandbox_facts(launch["container"])
            modes[mode] = m
        finally:
            stop(run)
    # control: the Phase 3 harness server (no launcher flags), field absent
    srv = Server(models / "llama.cpp-b11819/llama-b11819", models / "qwen2.5-0.5b-instruct-q4_k_m.gguf", secrets.token_urlsafe(24), np=1).start()
    try:
        cl = srv.client()
        c, o = oracle(cl, "control_no_launcher_flags/field_absent", {}, a.trials, 99)
        cells.append(c)
        obs += o
        print("  %-28s cached>0 in %d/%d trials, AUC %s" % (c["cell"], c["trials_with_cached_tokens"], 2 * a.trials, c["cached_tokens_oracle"]["auc"]), flush=True)
    finally:
        srv.stop()
    by = {c["cell"]: c for c in cells}
    closed = [k for k in by if k.endswith(("/aegislab", "/field_absent")) and not k.startswith("control")]
    checks = {
        "no_cached_tokens_with_aegislab_requests": all(by[k]["trials_with_cached_tokens"] == 0 for k in closed if k.endswith("/aegislab")),
        "no_cached_tokens_with_field_absent_under_launcher": all(by[k]["trials_with_cached_tokens"] == 0 for k in closed if k.endswith("/field_absent")),
        "control_default_server_caches_when_field_absent": by["control_no_launcher_flags/field_absent"]["cached_tokens_oracle"]["auc"] == 1.0,
        "residual_client_true_still_caches_under_launcher": all((by[k]["cached_tokens_oracle"]["auc"] or 0) >= 0.99 for k in by if k.endswith("/client_true")),
        "slots_disabled": all(m["endpoints"]["GET /slots"]["with_key"] != 200 for m in modes.values()),
        "metrics_disabled": all(m["endpoints"]["GET /metrics"]["with_key"] != 200 for m in modes.values()),
        "props_post_disabled": all(m["endpoints"]["POST /props"]["with_key"] != 200 for m in modes.values()),
        "slot_save_restore_disabled": all(m["endpoints"]["POST /slots/0?action=save"]["with_key"] != 200 and m["endpoints"]["POST /slots/0?action=restore"]["with_key"] != 200 for m in modes.values()),
        "every_endpoint_but_health_needs_key": all(v["without_key"] != 200 for m in modes.values() for k, v in m["endpoints"].items() if k.startswith("GET") and k != "GET /health"),
        "no_prompt_text_in_any_endpoint": all(not v.get("contains_planted_marker") and not v.get("contains_prompt_text") for m in modes.values() for v in m["endpoints"].values()),
        "key_on_no_command_line": all(not m["key_on_process_cmdline_pids"] and not m["key_in_launch_json"] and not m["key_in_model_env"] for m in modes.values()),
    }
    if "sandbox" in modes:
        s = modes["sandbox"]["sandbox"]
        checks["sandbox_network_none_lo_only_no_egress"] = s["network_mode"] == "none" and s["inside_interfaces"] == "['lo']" and s["inside_connect_1_1_1_1_errno"] not in (None, "0")
        checks["sandbox_readonly_capdrop_nonewprivs_limits"] = bool(s["readonly_rootfs"] is True and s["inside_rootfs"].startswith("rootfs-readonly") and s["cap_dropped"] > 0
                                                               and s["inside_capeff_nonewprivs"] == "['0000000000000000', '1']" and s["pids_limit"] and s["memory_bytes"] and s["nano_cpus"])
        checks["sandbox_model_and_binary_read_only"] = all(x in s["mounts"] for x in ("/opt/llama:ro", "/models/model.gguf:ro", "/run/aegis-key/key:ro"))
    result = {"experiment": "P3_model_server_hardening", "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "code_revision": code_revision(), "source_sha256": source_hashes(SOURCES),
              "model_backend": {"model_file": "qwen2.5-0.5b-instruct-q4_k_m.gguf", "model_sha256": sha256_file(models / "qwen2.5-0.5b-instruct-q4_k_m.gguf"),
                                "server_binary_sha256": sha256_file(models / "llama.cpp-b11819/llama-b11819/llama-server"), "inference_server": "llama.cpp b11819 CPU"},
              "environment": environment(), "trials_per_class": a.trials, "cells": cells, "modes": modes, "checks": checks,
              "classification": "pass" if all(checks.values()) else "fail",
              "what_is_not_closed": ["cache_prompt=true sent by a client still reuses the slot KV prefix: --no-cache-prompt only sets the default "
                                     "in b11819; closed only because the broker is the only client and refuses to send it",
                                     "GET /props cannot be disabled (needs the key; shows defaults and the model path, no prompt text)",
                                     "the live KV cells of the single slot between requests, CPU caches, memory bandwidth and timing",
                                     "GPU / accelerator memory: CPU build only", "other inference servers and builds"],
              "wall_clock_s": round(time.time() - t0, 1)}
    run_id = "P3H-%s" % time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    d = Path(a.out_dir) / run_id
    d.mkdir(parents=True, exist_ok=False)
    (d / "observations.jsonl").write_text("".join(json.dumps(o, sort_keys=True) + "\n" for o in obs))
    result.update({"run_id": run_id, "observations_sha256": sha256_file(d / "observations.jsonl"), "observation_count": len(obs)})
    (d / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True))
    print(json.dumps(checks, indent=1))
    print("[%s] %s -> %s" % (run_id, result["classification"], d))
    return 0 if result["classification"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
