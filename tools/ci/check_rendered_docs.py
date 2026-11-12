#!/usr/bin/env python3
"""Fail if a rendered finale document differs from what its template renders to now (standard library only).

finale_package/src/render_docs.py --all rewrites every file in its TARGETS list and the finale block of README.md. A text
edit made only in a rendered file (and not in its template) is silently lost the next time someone renders. This check
renders every template into a temporary directory with render_docs.render_file (the same code the real render runs),
renders the README block with render_docs.render, and compares each result byte for byte with the file in the repository.
Nothing in the repository is written.

Kept in tools/ci/, outside the code_revision hash (aegislab/aegis, sandbox, evaluation, scripts, tests, samples), so adding
it changes neither the revision Render serves nor the tagged build. Run by the release-gates workflow.
Usage: python3 tools/ci/check_rendered_docs.py [--repo PATH]
"""
import argparse
import contextlib
import difflib
import io
import json
import sys
import tempfile
from pathlib import Path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=str(Path(__file__).resolve().parents[2]))
    repo = Path(ap.parse_args().repo).resolve()
    src = repo / "finale_package" / "src"
    sys.path.insert(0, str(src))
    import render_docs as r  # noqa: E402  (the repository's renderer)

    claims = json.loads((repo / "finale_package" / "claims_used_for_finale.json").read_text())["claims"]
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        for tmpl, out in r.TARGETS:
            target = repo / Path(out).resolve().relative_to(r.REPO)
            fresh = Path(tmp) / Path(out).name
            with contextlib.redirect_stdout(io.StringIO()):
                r.render_file(claims, tmpl, fresh)
            rows.append((str(target.relative_to(repo)), tmpl, fresh.read_text(), target.read_text() if target.exists() else None))
    block = r.render((src / "templates" / "README_block.md.tmpl").read_text(), claims).strip("\n")
    readme = (repo / "README.md").read_text()
    a, b = "<!-- finale:start -->", "<!-- finale:end -->"
    current = a + readme.split(a, 1)[1].split(b, 1)[0] + b if a in readme and b in readme else None
    rows.append(("README.md (finale block)", "README_block.md.tmpl", block, current))

    bad = 0
    for name, tmpl, want, have in rows:
        if have == want:
            print("ok    %-50s = %s" % (name, tmpl))
            continue
        bad += 1
        print("FAIL  %-50s differs from %s rendered now" % (name, tmpl))
        if have is None:
            print("      missing (or the README finale markers are missing)")
        else:
            diff = difflib.unified_diff(want.splitlines(), have.splitlines(), "rendered from " + tmpl, name, n=0, lineterm="")
            for ln in list(diff)[:12]:
                print("      " + ln[:160])
    print("%d/%d rendered documents match their templates" % (len(rows) - bad, len(rows)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
