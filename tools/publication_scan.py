#!/usr/bin/env python3
"""Pre-publication scan for the AegisLab repository (standard library only).

Scans every file in the git index (what the next commit publishes) and, with --history, every blob reachable from any ref.
FAIL findings (exit 1): private key blocks, credential-looking strings, secret-bearing or
runtime-state paths (var/, .venv/, .env, *.pem, *.key, tokens.json, model weights), lock files.
WARN findings (exit 0): absolute home paths, e-mail addresses, files over 25 MB.
Accepted WARN findings are listed with a reason in tools/publication_allowlist.txt.

This is a guard rail, not a guarantee: a human still reviews what is published.
Usage: python3 tools/publication_scan.py [--repo PATH] [--history] [--json OUT]
"""
import argparse
import fnmatch
import json
import re
import subprocess
import sys
from pathlib import Path

FAIL_PATHS = ["var/*", "*/var/*", ".venv/*", "*/.venv/*", "*__pycache__*", "*.pyc", ".env", "*.env", ".env.*", "*.pem", "*.key",
              "*id_rsa*", "*id_ed25519*", "*tokens.json", "*signing_key*", "*.gguf", "*.safetensors", "*.ckpt", "*.~lock*", ".~lock*",
              "*.swp", ".pytest_cache/*", "*/.pytest_cache/*"]
FAIL_CONTENT = [
    ("private_key_block", re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    ("openai_style_key", re.compile(rb"\bsk-[A-Za-z0-9_-]{20,}")),
    ("github_token", re.compile(rb"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}")),
    ("huggingface_token", re.compile(rb"\bhf_[A-Za-z0-9]{30,}")),
    ("aws_access_key", re.compile(rb"\bAKIA[0-9A-Z]{16}\b")),
    ("slack_token", re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{10,}")),
    ("google_api_key", re.compile(rb"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("bearer_header", re.compile(rb"Authorization:\s*Bearer\s+[A-Za-z0-9._-]{16,}")),
    ("assigned_api_key", re.compile(rb"api[_-]?key[\"' ]*[:=][\"' ]*[A-Za-z0-9]{24,}", re.I)),
    ("aegis_token_value", re.compile(rb"X-Aegis-Token[\"' ]*[:=][\"' ]*[A-Za-z0-9_-]{16,}")),
]
WARN_CONTENT = [
    ("home_path", re.compile(rb"/home/[A-Za-z0-9._-]+/|/Users/[A-Za-z0-9._-]+/")),
    ("email", re.compile(rb"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+\.[A-Za-z]{2,}(?:\.[A-Za-z]{2,})?")),
]
BIG = 25 * 1024 * 1024


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True).stdout


def load_allowlist(repo):
    p = Path(repo) / "tools" / "publication_allowlist.txt"
    rules = []
    if p.exists():
        for line in p.read_text().splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                kind, pattern = line.split(None, 1)
                rules.append((kind, pattern.strip()))
    return rules


def allowed(rules, kind, path):
    return any(k == kind and fnmatch.fnmatch(path, pat) for k, pat in rules)


def scan_blob(path, data, rules, out, where):
    for pat in FAIL_PATHS:
        if fnmatch.fnmatch(path, pat):
            out.append(("FAIL", "forbidden_path", path, where, pat))
            break
    if len(data) > BIG and not allowed(rules, "large_file", path):
        out.append(("WARN", "large_file", path, where, "%d bytes" % len(data)))
    for name, rx in FAIL_CONTENT:
        m = rx.search(data)
        if m and not allowed(rules, name, path):
            out.append(("FAIL", name, path, where, m.group(0)[:12].decode("latin-1") + "..."))
    if b"\0" in data[:8192]:
        return
    for name, rx in WARN_CONTENT:
        hits = sorted({h.decode("latin-1") for h in rx.findall(data)})
        if hits and not allowed(rules, name, path):
            out.append(("WARN", name, path, where, ", ".join(hits[:3])))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=".")
    ap.add_argument("--history", action="store_true", help="also scan every blob reachable from any ref")
    ap.add_argument("--json")
    a = ap.parse_args()
    repo = Path(a.repo).resolve()
    rules = load_allowlist(repo)
    out, seen = [], set()
    head = [e for e in git(repo, "ls-files", "-s", "-z").split(b"\0") if e]
    for entry in head:
        meta, path = entry.split(b"\t", 1)
        sha = meta.split()[1].decode()
        seen.add(sha)
        scan_blob(path.decode(), git(repo, "cat-file", "blob", sha), rules, out, "index")
    n_hist = 0
    if a.history:
        for line in git(repo, "rev-list", "--all", "--objects").decode().splitlines():
            parts = line.split(" ", 1)
            if len(parts) != 2 or parts[0] in seen:
                continue
            if git(repo, "cat-file", "-t", parts[0]).strip() != b"blob":
                continue
            seen.add(parts[0]); n_hist += 1
            scan_blob(parts[1], git(repo, "cat-file", "blob", parts[0]), rules, out, "history:" + parts[0][:10])
    fails = [f for f in out if f[0] == "FAIL"]
    for f in out:
        print("%s %-18s %s [%s] %s" % f)
    print("scanned: %d files in the index, %d further blobs in history; allowlist rules: %d" % (len(head), n_hist, len(rules)))
    print("result: %d FAIL, %d WARN" % (len(fails), len(out) - len(fails)))
    if a.json:
        Path(a.json).write_text(json.dumps([dict(zip(("level", "kind", "path", "where", "detail"), f)) for f in out], indent=1))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
