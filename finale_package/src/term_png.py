"""Render lines of a REAL recorded terminal transcript (record_term.py output, .txt) as a PNG for the finale deck.

    python term_png.py TRANSCRIPT.txt OUT.png --title "..." [--start TEXT] [--end TEXT] [--pick TEXT ...] [--cols 100] [--size 24]

Lines are taken verbatim; only wrapping and colour are added. --start/--end select from the first line containing START up to
(not including) the first later line containing END; --pick keeps only lines containing one of the substrings (in order).
The prompt line of each typed command is kept as "$ <command>". Nothing is typed in here.
"""
import argparse
import textwrap
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

FONTS = Path(__file__).resolve().parents[2] / "aegislab" / "web" / "fonts"
BG, FG, DIM = (14, 22, 36), (225, 232, 242), (140, 154, 174)
GREEN, RED, AMBER, BLUE, WHITE = (88, 214, 141), (255, 107, 107), (255, 191, 96), (120, 180, 255), (255, 255, 255)


def colour(line):
    s = line.strip()
    if "[PASS]" in line or s.startswith(("PASS", "ok ")) or "checks PASS" in line or "behaved as expected" in line or s.startswith("checks:"):
        return GREEN
    if "[FAIL]" in line or s.startswith(("FAIL", "FAILED")) or "finding:" in s or "REJECTED" in line or "rejected" in s and "PASS" not in s:
        return RED
    if "[LIMIT]" in line or "LIMIT" in s[:8]:
        return AMBER
    if "[PRECOMPUTED]" in line or "LIVE REAL MODEL" in line:
        return BLUE
    if s.startswith("$"):
        return WHITE
    if s.startswith("exit code:"):
        return GREEN if s.endswith(": 0") else RED
    return FG


def select(lines, start=None, end=None, pick=None):
    if start:
        i = next(k for k, x in enumerate(lines) if start in x)
        j = next((k for k in range(i + 1, len(lines)) if end and end in lines[k]), len(lines))
        lines = lines[i:j]
    if pick:
        lines = [x for x in lines if any(p in x for p in pick)]
    return lines


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("transcript")
    ap.add_argument("out")
    ap.add_argument("--title", default="")
    ap.add_argument("--start")
    ap.add_argument("--end")
    ap.add_argument("--pick", nargs="*")
    ap.add_argument("--cols", type=int, default=100)
    ap.add_argument("--size", type=int, default=24)
    ap.add_argument("--max-lines", type=int, default=40)
    a = ap.parse_args()
    raw = Path(a.transcript).read_text().splitlines()
    lines = select(raw, a.start, a.end, a.pick)
    wrapped = []
    for ln in lines:
        c = colour(ln)
        parts = textwrap.wrap(ln.rstrip(), a.cols, subsequent_indent="      ", drop_whitespace=False) or [""]
        wrapped += [(p, c) for p in parts]
    wrapped = wrapped[: a.max_lines]
    mono = ImageFont.truetype(str(FONTS / "IBMPlexMono-Regular.ttf"), a.size)
    bold = ImageFont.truetype(str(FONTS / "IBMPlexMono-SemiBold.ttf"), a.size)
    cw, lh = mono.getlength("M"), int(a.size * 1.42)
    pad, top = 28, (64 if a.title else 24)
    W = int(pad * 2 + cw * a.cols)
    H = top + lh * len(wrapped) + pad
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    if a.title:
        d.rectangle([0, 0, W, 48], fill=(30, 41, 59))
        for i, col in enumerate(((255, 95, 86), (255, 189, 46), (39, 201, 63))):
            d.ellipse([18 + i * 24, 17, 32 + i * 24, 31], fill=col)
        d.text((100, 10), a.title, font=bold, fill=DIM)
    y = top
    for t, c in wrapped:
        d.text((pad, y), t, font=bold if c in (GREEN, RED, AMBER) and t.strip()[:1] in "[$PFe" else mono, fill=c)
        y += lh
    img.save(a.out)
    print("wrote", a.out, img.size, len(wrapped), "lines")


if __name__ == "__main__":
    main()
