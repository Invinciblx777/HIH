"""Finale P6: Playwright check of the public read-only demo (desktop and phone): the hosted site, or the local fallback.

    aegislab/.venv-browser/bin/python tools/offline_kit/public_demo_check.py BASE_URL OUT_DIR [--local]

--local: the local public demo on loopback (OFFLINE_KIT.md). There is no proxy in front of it, so client_ip_header_present
is not required to be true; it is reported. Everything else is checked the same way. (From R5's pw_render_check.py.)

Per viewport: status says public_demo and client_ip_header_present; the header shows "Public demo"; Evidence ->
DEMO-001-RELEASED -> Verify is accepted from the page; from the page's own origin, GET /session/start and POST /api/lab/runs
answer 403. Then, in the phone context, verifier calls from the page continue until the per-client limit answers 429, and a
click on Verify shows the limit message. Prints one PASS/FAIL line per check; exit 1 if any check fails.
"""
import json
import sys
import time
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

LOCAL = "--local" in sys.argv[3:]
BASE, OUT = sys.argv[1].rstrip("/"), Path(sys.argv[2])
OUT.mkdir(parents=True, exist_ok=True)
DESK = {"viewport": {"width": 1440, "height": 900}, "device_scale_factor": 1}
PHONE = {"viewport": {"width": 390, "height": 844}, "device_scale_factor": 2, "is_mobile": True, "has_touch": True}
results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print("%s  %s  %s" % ("PASS" if ok else "FAIL", name, detail), flush=True)


def shot(page, name):
    page.wait_for_timeout(700)
    page.screenshot(path=str(OUT / (name + ".png")))
    print("shot", name + ".png", flush=True)


FETCH = """async ([method, path, body]) => {
  const opt = {method, redirect: 'manual', headers: {}};
  if (body !== null) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
  const r = await fetch(path, opt);
  let t = ''; try { t = await r.text(); } catch (e) {}
  return {status: r.status, type: r.type, text: t.slice(0, 300), retry: r.headers.get('retry-after')};
}"""

with sync_playwright() as pw:
    br = pw.chromium.launch()
    for opts, sfx in ((DESK, "desktop"), (PHONE, "phone")):
        ctx = br.new_context(**opts)
        page = ctx.new_page()
        errors = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        t0 = time.time()
        page.goto(BASE + "/#/overview", wait_until="domcontentloaded", timeout=120_000)
        expect(page.locator("header")).to_contain_text("Public demo", timeout=60_000)
        check(sfx + ": header shows Public demo", True, "%.1f s to header" % (time.time() - t0))
        st = page.evaluate("async () => (await fetch('/api/lab/status')).json()")
        rl = st.get("public_demo_rate_limit") or {}
        check(sfx + ": status public_demo true", st.get("public_demo") is True, "mode=%s" % st.get("mode"))
        if LOCAL:
            print("INFO  %s: local, no proxy: client_ip_from=%s client_ip_header_present=%s" % (sfx, rl.get("client_ip_from"), rl.get("client_ip_header_present")))
        else:
            check(sfx + ": status client_ip_header_present true", rl.get("client_ip_header_present") is True,
                  "client_ip_from=%s" % rl.get("client_ip_from"))
        shot(page, "public_overview_" + sfx)
        page.goto(BASE + "/#/evidence?open=DEMO-001-RELEASED", wait_until="domcontentloaded")
        page.click("#do-verify")
        expect(page.locator("#v-out")).to_contain_text("as expected", timeout=120_000)
        out = page.locator("#v-out").inner_text()
        check(sfx + ": Verify DEMO-001-RELEASED accepted from the page", "Accepted" in out or "accepted" in out,
              out.replace("\n", " | ")[:160])
        page.locator("#v-out").scroll_into_view_if_needed()
        shot(page, "public_verify_" + sfx)
        r = page.evaluate(FETCH, ["GET", "/session/start?code=x", None])
        check(sfx + ": GET /session/start from the page -> 403", r["status"] == 403, r["text"][:90])
        r = page.evaluate(FETCH, ["POST", "/api/lab/runs", {"stop_after": "created"}])
        check(sfx + ": POST /api/lab/runs from the page -> 403", r["status"] == 403, r["text"][:90])
        check(sfx + ": no page errors", not errors, "; ".join(errors)[:200])
        if sfx == "phone":
            codes = []
            for _ in range(12):
                r = page.evaluate(FETCH, ["POST", "/api/lab/bundles/NOPE/verify", None])
                codes.append(r["status"])
                if r["status"] == 429:
                    break
            check("phone: per-client limit reached from the page -> 429", codes[-1] == 429 and r["retry"] == "60",
                  "codes after 2 page verifies: %s" % codes)
            page.click("#do-verify")
            expect(page.locator("#toast")).to_contain_text("rate limit", timeout=30_000)  # the console shows errors in a toast
            msg = page.locator("#toast").inner_text()
            check("phone: Verify click while limited shows the limit message (toast)", "rate limit" in msg.lower(), msg.replace("\n", " | ")[:160])
            page.wait_for_timeout(300)
            page.screenshot(path=str(OUT / "public_rate_limited_phone.png"))  # toast hides after 4.2 s
        ctx.close()
    br.close()

(OUT / "pw_results.json").write_text(json.dumps({"base": BASE, "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                                                  "results": [{"check": n, "ok": o, "detail": d} for n, o, d in results]}, indent=1))
print("%d/%d PASS" % (sum(o for _, o, _ in results), len(results)))
sys.exit(0 if all(o for _, o, _ in results) else 1)
