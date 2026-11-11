"""HANDOUT.md -> HANDOUT.html (A4, one page) for LibreOffice PDF export. Handles only what the handout uses:
# and ## headings, - bullets, **bold**, `code`, paragraphs.

    python handout_pdf.py HANDOUT.md OUT.html
"""
import html
import re
import sys

src, out = sys.argv[1:3]


def inline(t):
    t = html.escape(t)
    t = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", t)
    return re.sub(r"`(.+?)`", r"<code>\1</code>", t)


body, in_list = [], False
for ln in open(src).read().splitlines():
    if ln.startswith("- "):
        if not in_list:
            body.append("<ul>")
            in_list = True
        body.append("<li>%s</li>" % inline(ln[2:]))
        continue
    if in_list:
        body.append("</ul>")
        in_list = False
    if ln.startswith("## "):
        body.append("<h2>%s</h2>" % inline(ln[3:]))
    elif ln.startswith("# "):
        body.append("<h1>%s</h1>" % inline(ln[2:]))
    elif ln.strip():
        body.append("<p>%s</p>" % inline(ln))
if in_list:
    body.append("</ul>")
css = ("@page{size:A4;margin:14mm 16mm} body{font-family:'IBM Plex Sans',sans-serif;font-size:10pt;line-height:1.32;color:#111827}"
       "h1{font-family:Montserrat,sans-serif;font-size:24pt;color:#1e3a8a;margin:0 0 4pt}"
       "h2{font-family:Montserrat,sans-serif;font-size:12.5pt;color:#c2410c;margin:10pt 0 3pt}"
       "p{margin:3pt 0} ul{margin:2pt 0 2pt 14pt;padding:0} li{margin:2pt 0} code{font-family:'IBM Plex Mono',monospace;font-size:9pt}")
open(out, "w").write("<!DOCTYPE html><html><head><meta charset='utf-8'><title>AegisLab handout</title><style>%s</style></head><body>%s</body></html>" % (css, "\n".join(body)))
