"""Render lines of a REAL recorded terminal transcript (scripts/judge_demo.sh --record) as a PNG for the deck and the video.

    python terminal_png.py transcript.json out.png --title "..." --select "start:<text>" "end:<text>" [--cols 78] [--size 26]

The text is taken verbatim from the transcript; only wrapping and colour are added. Nothing is typed in here.
--select picks the lines from the first line that contains <start> up to (not including) the first later line that contains <end>.
--pick keeps only lines that contain one of the given substrings (still verbatim, in order).
"""
import argparse
import json
import textwrap
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

FONTS = Path(__file__).resolve().parent.parent / "aegislab" / "web" / "fonts"
BG, FG, DIM = (14, 22, 36), (225, 232, 242), (140, 154, 174)
GREEN, RED, AMBER, BLUE, WHITE = (88, 214, 141), (255, 107, 107), (255, 191, 96), (120, 180, 255), (255, 255, 255)


def colour(line):
    s = line.strip()
    if "[PASS]" in line:
        return GREEN
    if "[FAIL]" in line or s.startswith("FAILED"):
        return RED
    if "[HISTORICAL]" in line:
        return AMBER
    if "[PRECOMPUTED]" in line:
        return BLUE
    if s.startswith("$"):
        return WHITE
    if "finding:" in s or s.startswith(("ok  ", "terminal_verified")) and "False" in s:
        return RED if "finding" in s or "False" in s else FG
    return FG


def pick_lines(transcript, start=None, end=None, pick=None):
    lines = [x["text"] for x in transcript["lines"]]
    if start:
        i = next(k for k, l in enumerate(lines) if start in l)
        j = next((k for k in range(i + 1, len(lines)) if end and end in lines[k]), len(lines))
        lines = lines[i:j]
    if pick:
        lines = [l for l in lines if any(p in l for p in pick)]
    return [l for l in lines if l.strip() != ""]


def render(lines, out, title, cols=78, size=26, pad=34, bar=64, min_width=None):
    reg = ImageFont.truetype(str(FONTS / "IBMPlexMono-Regular.ttf"), size)
    semi = ImageFont.truetype(str(FONTS / "IBMPlexMono-SemiBold.ttf"), size)
    small = ImageFont.truetype(str(FONTS / "IBMPlexMono-SemiBold.ttf"), int(size * 0.72))
    wrapped = []
    for l in lines:
        indent = len(l) - len(l.lstrip())
        parts = textwrap.wrap(l.rstrip(), cols, subsequent_indent=" " * (indent + 4), drop_whitespace=False, replace_whitespace=False) or [""]
        wrapped += [(p, l) for p in parts]
    cw = reg.getlength("M")
    lh = int(size * 1.42)
    w = int(cw * cols + 2 * pad)
    w = max(w, min_width or 0)
    h = bar + pad // 2 + lh * len(wrapped) + pad
    im = Image.new("RGB", (w, h), BG)
    d = ImageDraw.Draw(im)
    d.rectangle([0, 0, w, bar], fill=(26, 38, 58))
    for k, c in enumerate(((255, 95, 86), (255, 189, 46), (39, 201, 63))):
        d.ellipse([pad + k * 34, bar // 2 - 9, pad + k * 34 + 18, bar // 2 + 9], fill=c)
    d.text((pad + 130, bar // 2), title, font=small, fill=DIM, anchor="lm")
    y = bar + pad // 2
    for p, orig in wrapped:
        c = colour(orig)
        f = semi if c in (GREEN, RED, AMBER, BLUE, WHITE) else reg
        # tags are drawn in colour, the rest of a PASS/FAIL line in the normal colour so long lines stay readable
        for tag in ("[PASS]", "[FAIL]", "[HISTORICAL]", "[PRECOMPUTED]"):
            if tag in p:
                a, b = p.split(tag, 1)
                d.text((pad, y), a, font=reg, fill=FG)
                x = pad + reg.getlength(a)
                d.text((x, y), tag, font=semi, fill=c)
                d.text((x + reg.getlength(tag), y), b, font=reg, fill=FG)
                break
        else:
            d.text((pad, y), p, font=f, fill=c if c != FG else FG)
        y += lh
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    im.save(out)
    return im.size


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("transcript")
    ap.add_argument("out")
    ap.add_argument("--title", default="scripts/judge_demo.sh")
    ap.add_argument("--select", nargs=2, metavar=("START", "END"))
    ap.add_argument("--pick", nargs="*")
    ap.add_argument("--cols", type=int, default=78)
    ap.add_argument("--size", type=int, default=26)
    a = ap.parse_args()
    t = json.loads(Path(a.transcript).read_text())
    ls = pick_lines(t, *(a.select or (None, None)), pick=a.pick)
    print(render(ls, a.out, a.title, a.cols, a.size))
