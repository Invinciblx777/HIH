"""AegisLab finale P6 task 7a: projector check of the demo-critical console screens.

    aegislab/.venv-browser/bin/python tools/venue/projector_check.py --out DIR [--port 8413]

Starts the REAL-model console (scripts/start_real_model_console.sh, its own state directory var/console-real, reset first),
makes one lab run LAB-001 through CREATED > FROZEN > RUNNING > SEALED, releases it (authorised-release scenario), then
for every projector resolution (1280x720, 1366x768, 1920x1080) and browser zoom (100 %, 125 %, 150 %) opens:

  lab        the Lab page with the run card of LAB-001
  evidence   Evidence > LAB-001: Verify (accepted) and Tamper (a disposable copy, rejected)
  audit      Audit > signed log of LAB-001 with the anomaly-detector panel open
  experiments

Zoom is emulated as the browser does it: CSS viewport = screen / zoom, device pixel ratio = zoom.
Clipping checks on every screen, each a PASS/FAIL line:
  - the page does not scroll sideways (documentElement.scrollWidth <= innerWidth);
  - no visible element with text is cut off by its own overflow (overflow hidden/clip and scrollWidth > clientWidth + 1,
    or lines hidden by -webkit-line-clamp), visually hidden 1x1 px labels for screen readers excepted,
    and except the elements the console truncates on purpose with an ellipsis (text-overflow: ellipsis), which are listed;
  - every demo-critical element (run card, verify output, tamper output, anomaly panel) lies inside the viewport width.
Screenshots go to DIR (full page), never into the repository. Exit 0 only if every check passes.
"""
import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / "aegislab"
sys.path.insert(0, str(ROOT / "scripts"))
from real_model_console_check import go, run_state, start_console, stop_console  # noqa: E402
from playwright.sync_api import expect, sync_playwright  # noqa: E402

SCREENS = [(1280, 720), (1366, 768), (1920, 1080)]
ZOOMS = [1.0, 1.25, 1.5]
RESULTS = []

CLIP_JS = """(sel) => {
  const vw = window.innerWidth, out = {page_scroll_x: document.documentElement.scrollWidth - vw, clipped: [], ellipsis: [], outside: []};
  for (const el of document.querySelectorAll('body *')) {
    const cs = getComputedStyle(el);
    if (cs.display === 'none' || cs.visibility === 'hidden') continue;
    const r = el.getBoundingClientRect(); if (r.width <= 1 || r.height <= 1) continue;   // also skips visually hidden labels (.vh, 1x1 px)
    if (el.closest('.table-wrap')) continue;           // tables scroll inside their own wrapper on purpose
    const t = (el.innerText || '').trim(); if (!t) continue;
    const ox = cs.overflowX;
    const clamped = cs.webkitLineClamp && cs.webkitLineClamp !== 'none' && el.scrollHeight > el.clientHeight + 1;   // lines cut by line-clamp
    if (((ox === 'hidden' || ox === 'clip') && el.scrollWidth > el.clientWidth + 1) || clamped) {
      const d = {tag: el.tagName.toLowerCase(), id: el.id, cls: el.className && String(el.className).slice(0, 40), text: t.slice(0, 60)};
      (cs.textOverflow === 'ellipsis' ? out.ellipsis : out.clipped).push(d);
    }
  }
  for (const s of sel) {
    const el = document.querySelector(s); if (!el) { out.outside.push(s + ' (missing)'); continue; }
    const r = el.getBoundingClientRect(); if (r.left < -1 || r.right > vw + 1) out.outside.push(s + ' ' + Math.round(r.left) + '..' + Math.round(r.right));
  }
  return out;
}"""


def check(name, ok, detail=""):
    RESULTS.append({"check": name, "ok": bool(ok), "detail": detail})
    print("%s  %s%s" % ("PASS" if ok else "FAIL", name, ("  (" + detail + ")") if detail else ""), flush=True)


def screen(page, out, tag, name, critical):
    page.wait_for_timeout(600)
    r = page.evaluate(CLIP_JS, critical)
    page.screenshot(path=str(out / ("%s_%s.png" % (tag, name))), full_page=True)
    check("%s %s: no sideways scroll" % (tag, name), r["page_scroll_x"] <= 0, "scrollWidth - innerWidth = %d" % r["page_scroll_x"])
    check("%s %s: no clipped text" % (tag, name), not r["clipped"], json.dumps(r["clipped"])[:300])
    check("%s %s: critical elements inside the viewport" % (tag, name), not r["outside"], "; ".join(r["outside"]))
    return r["ellipsis"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--port", type=int, default=8413)
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    proc, link, _ = start_console(a.port, None)
    base = "http://127.0.0.1:%d" % a.port
    ellipses = {}
    try:
        with sync_playwright() as pw:
            br = pw.chromium.launch()
            ctx = br.new_context(viewport={"width": 1440, "height": 900})
            page = ctx.new_page()
            errors = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.goto(link)
            page.wait_for_url("**/#/lab")
            page.select_option("#bucket", "")
            page.select_option("#prof1", "sample")
            page.click("#start-run")
            run_state(page, "CREATED", 30_000)
            page.click("[data-step=freeze]")
            run_state(page, "FROZEN", 30_000)
            page.click("[data-step=start]")
            run_state(page, "SEALED", 600_000)
            go(page, base, "#/lab?open=authorized-release")
            page.click("#do-scn")
            page.click("#confirm-ok")
            expect(page.locator("#scn-result .verdict")).to_contain_text("PASS", timeout=180_000)
            check("set-up: LAB-001 sealed and released with the real model", True)
            state = ctx.storage_state()
            ctx.close()
            for (w, h) in SCREENS:
                for z in ZOOMS:
                    tag = "%dx%d@%d" % (w, h, round(z * 100))
                    c = br.new_context(viewport={"width": round(w / z), "height": round(h / z)}, device_scale_factor=z, storage_state=state)
                    p = c.new_page()
                    p.on("pageerror", lambda e: errors.append(str(e)))
                    go(p, base, "#/lab")
                    run_state(p, "RELEASED", 60_000)
                    ellipses[tag + " lab"] = screen(p, out, tag, "lab", ["#run-box"])
                    go(p, base, "#/evidence?open=LAB-001")
                    p.click("#do-verify")
                    expect(p.locator("#v-out")).to_contain_text("as expected", timeout=90_000)
                    p.select_option("#t-mode", "edit_event")
                    p.click("#do-tamper")
                    expect(p.locator("#t-out .verdict")).to_contain_text("PASS", timeout=90_000)
                    p.locator("#v-out").scroll_into_view_if_needed()
                    ellipses[tag + " evidence"] = screen(p, out, tag, "evidence", ["#v-out", "#t-out"])
                    go(p, base, "#/audit?src=log&run=LAB-001")
                    expect(p.locator("#anom")).to_be_visible(timeout=60_000)
                    p.evaluate("document.querySelector('#anom').open = true")
                    p.locator("#anom").scroll_into_view_if_needed()
                    ellipses[tag + " audit"] = screen(p, out, tag, "audit", ["#anom summary"])
                    go(p, base, "#/experiments")
                    ellipses[tag + " experiments"] = screen(p, out, tag, "experiments", [])
                    c.close()
            check("no page errors", not errors, "; ".join(errors)[:300])
            br.close()
    finally:
        stop_console(proc)
    (out / "projector_results.json").write_text(json.dumps({"utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "results": RESULTS,
                                                           "ellipsis_truncations": {k: v for k, v in ellipses.items() if v}}, indent=1))
    bad = [r for r in RESULTS if not r["ok"]]
    print("\n%d/%d projector checks PASS; %d screens with intentional ellipsis truncation" % (len(RESULTS) - len(bad), len(RESULTS), sum(1 for v in ellipses.values() if v)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
