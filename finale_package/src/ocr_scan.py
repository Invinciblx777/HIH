"""OCR every image (screenshots, terminal images, deck pages, video keyframes) and flag anything secret or personal.

    python ocr_scan.py OUT.json DIR [DIR ...]

Flags: launch links or codes (session/start, code=, token=, ?k=), API keys (sk-, key=, Bearer), /home/<account> paths,
the local account name (of whoever runs the scan), browser profile names, e-mail addresses. rapidocr (ONNX, offline). Exit 1 on any hit.
"""
import getpass
import json
import re
import sys
from pathlib import Path

from rapidocr_onnxruntime import RapidOCR

PATTERNS = {"launch_link": r"session/start|/launch\b|[?&](?:code|k|token)=|launch (?:code|url|link):",
            "api_key": r"\bsk-[A-Za-z0-9]{8,}|api[_-]?key\s*[:=]\s*\S{6,}|Bearer\s+\S{8,}",
            "home_path": r"/home/\w+", "account": re.escape(getpass.getuser()), "profile": r"Profile \d|Default profile|\.mozilla|\.config/(?:google-chrome|chromium)",
            "email": r"[\w.+-]+@[\w-]+\.[\w.]+"}
eng = RapidOCR()
out, hits = {}, 0
for d in sys.argv[2:]:
    for p in sorted(Path(d).rglob("*.png")):
        res, _ = eng(str(p))
        txt = " ".join(r[1] for r in (res or []))
        h = {k: re.findall(v, txt, re.I) for k, v in PATTERNS.items()}
        h = {k: v for k, v in h.items() if v}
        out[str(p)] = {"chars": len(txt), "hits": h}
        hits += bool(h)
        if h:
            print("HIT", p, h)
json.dump({"images": len(out), "images_with_hits": hits, "patterns": PATTERNS, "results": out}, open(sys.argv[1], "w"), indent=1)
print("images %d, with hits %d" % (len(out), hits))
sys.exit(1 if hits else 0)
