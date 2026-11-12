"""Render a finale video (1920x1080, H.264 + AAC, burned captions + .srt) from a narration file.

    python render_video.py NARRATION.json TTS_DIR CLAIMS.json MEDIA_DIR OUT.mp4 OUT.srt

NARRATION.json (rendered by render_docs.py from templates/narration_*.json.tmpl) lists segments; each has the spoken
text ("say", Piper), the caption ("caption", burned in and written to the .srt) and a visual:
  {"kind": "title"} / {"kind": "end"}                         drawn cards
  {"kind": "slide", "page": n}                                 page n of the finale deck PDF (MEDIA_DIR/deck/page-NN.png)
  {"kind": "screen", "files": [..]}                            P5 screenshots (MEDIA_DIR/screens/)
  {"kind": "image", "file": ..}                                a terminal image rendered from a transcript (MEDIA_DIR/term/)
  {"kind": "term", "rec": name, "from": mark, "to": mark}      replay of a recorded terminal session (MEDIA_DIR/recordings/
                                                               name.json), the recorded bytes at their recorded times,
                                                               sped up only if the window is longer than the narration
Every visual carries a band that says what it is: RECORDED terminal replay, SCREENSHOT, or DECK. Nothing in a video is
executed during playback; the LIVE label in a caption means the presented code produces the figure when it is run.
MEDIA_DIR/recordings holds the raw recordings (outside the repository); the transcripts in finale_package/terminal/
are the same sessions with ANSI codes removed.
"""
import base64
import json
import re
import sys
from pathlib import Path

import pyte
from PIL import Image, ImageDraw, ImageFont

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO.parent.parent / "demo_video" / "src"))  # round2/demo_video/src: shared media helpers
from media_common import caption_at, encode, load_narration, srt_time  # noqa: E402

narr_p, tts_dir, claims_p, media, out_mp4, out_srt = sys.argv[1:7]
MEDIA = Path(media)
FONTS = REPO / "aegislab" / "web" / "fonts"
W, H, FPS = 1920, 1080, 30
BAND_H, CAP_H = 64, 120
COMMIT = "9145592"
segments = json.load(open(narr_p))["segments"]
claims = json.load(open(claims_p))["claims"]
narr, wavs = load_narration(narr_p, tts_dir)
dur = {k: len(v) / 22050 for k, v in wavs.items()}


def sans(size, weight=500):
    f = ImageFont.truetype(str(FONTS / "IBMPlexSans-var.ttf"), size)
    try:
        f.set_variation_by_axes([weight])
    except Exception:
        pass
    return f


MONO = ImageFont.truetype(str(FONTS / "IBMPlexMono-Regular.ttf"), 20)
MONO_B = ImageFont.truetype(str(FONTS / "IBMPlexMono-SemiBold.ttf"), 20)
BG, INK = (11, 17, 32), (226, 232, 240)
GREEN, BLUE, AMBER, SLATE = (22, 101, 52), (30, 64, 175), (180, 83, 9), (51, 65, 85)
COLORS = {"default": INK, "green": (74, 222, 128), "red": (248, 113, 113), "yellow": (250, 204, 21), "blue": (96, 165, 250),
          "cyan": (34, 211, 238), "magenta": (232, 121, 249), "white": (255, 255, 255)}

# ---------------------------------------------------------------- captions: a claim form or label is never split
PROTECT = sorted({f for c in claims.values() for f in c["forms"].values()} | {"(%s)" % c["label"] for c in claims.values()}, key=len, reverse=True)
NB = " "


def chunks(text, limit=60):
    for p in PROTECT:
        text = text.replace(p, p.replace(" ", NB))
    out = []
    for sent in re.split(r"(?<=[.:?!])\s+(?=[A-Z])", text.strip()):
        cur = ""
        for w in sent.split(" "):
            if cur and len(cur) + 1 + len(w) > limit:
                out.append(cur)
                cur = w
            else:
                cur = (cur + " " + w).strip()
        if cur:
            out.append(cur)
    return [c.replace(NB, " ") for c in out]


LEAD, TAIL = 0.35, 0.55
timeline, speech, t = [], [], 0.0
for seg in segments:
    length = LEAD + dur[seg["key"]] + TAIL + seg.get("hold", 0.0)
    timeline.append((t, t + length, seg))
    speech.append((seg["key"], t + LEAD))
    t += length
TOTAL = t
cues = []
for key, t0 in speech:
    parts = chunks(narr[key]["caption"])
    tot = sum(len(p) for p in parts)
    tt = t0
    for p in parts:
        d = dur[key] * len(p) / tot
        cues.append((tt, tt + d, p))
        tt += d
with open(out_srt, "w") as f:
    for i, (a, b, txt) in enumerate(cues, 1):
        f.write("%d\n%s --> %s\n%s\n\n" % (i, srt_time(a), srt_time(b), txt))


# ---------------------------------------------------------------- drawing
def band(img, color, text, right):
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, W, BAND_H], fill=color)
    d.text((28, 15), text, font=sans(28, 650), fill=(255, 255, 255))
    f = sans(22, 400)
    d.text((W - 28 - d.textlength(right, font=f), 20), right, font=f, fill=(226, 232, 240))


def caption(img, text):
    if not text:
        return
    d = ImageDraw.Draw(img)
    d.rectangle([0, H - CAP_H, W, H], fill=(8, 12, 24))
    f = sans(40, 500)
    w = d.textlength(text, font=f)
    if w > W - 60:
        f = sans(34, 500)
        w = d.textlength(text, font=f)
    d.text(((W - w) / 2, H - CAP_H + 36), text, font=f, fill=(255, 255, 255))


def fit(img, src, box, bg=None):
    x, y, w, h = box
    r = min(w / src.width, h / src.height)
    s = src.resize((int(src.width * r), int(src.height * r)), Image.LANCZOS)
    img.paste(s, (x + (w - s.width) // 2, y + (h - s.height) // 2))
    return s.size


AREA = (40, BAND_H + 16, W - 80, H - CAP_H - BAND_H - 32)


def card_slide(seg):
    img = Image.new("RGB", (W, H), (245, 245, 240))
    p = MEDIA / "deck" / ("page-%02d.png" % seg["visual"]["page"])
    fit(img, Image.open(p).convert("RGB"), AREA)
    band(img, SLATE, "DECK · slide %d · every figure labelled LIVE, RE-MEASURED or RECORDED" % seg["visual"]["page"], "finale deck · code %s" % COMMIT)
    return img


def card_screen(seg):
    img = Image.new("RGB", (W, H), (236, 236, 230))
    files = seg["visual"]["files"]
    ims = [Image.open(MEDIA / "screens" / f).convert("RGB") for f in files]
    if len(ims) == 1:
        fit(img, ims[0], AREA)
    else:  # desktop + phone side by side, widths proportional to aspect at equal height
        x0, y0, aw, ah = AREA
        ws = [im.width * ah / im.height for im in ims]
        sc = min(1.0, (aw - 30 * (len(ims) - 1)) / sum(ws))
        x = x0 + (aw - sum(ws) * sc - 30 * (len(ims) - 1)) / 2
        for im, wd in zip(ims, ws):
            sz = fit(img, im, (int(x), y0, int(wd * sc), int(ah * sc)))
            x += sz[0] + 30
    band(img, BLUE, "SCREENSHOT · AegisLab console · " + seg["visual"].get("what", ""), "captured 12 Nov 2026 · code %s" % COMMIT)
    return img


def card_image(seg):
    img = Image.new("RGB", (W, H), BG)
    fit(img, Image.open(MEDIA / "term" / seg["visual"]["file"]).convert("RGB"), AREA)
    band(img, GREEN, "RECORDED 12 Nov 2026 · terminal transcript · " + seg["visual"].get("what", ""), "code %s · not executed in this video" % COMMIT)
    return img


def card_title(seg):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    d.text((140, 150), "AegisLab", font=sans(110, 700), fill=(255, 255, 255))
    d.text((140, 295), "Secure infrastructure for adversarial AI safety testing", font=sans(44, 500), fill=(203, 213, 225))
    d.text((140, 360), "Team Tech Mavericks · Hack in Hills '26 · Track 04 · Grand Finale · " + seg["visual"].get("cut", ""), font=sans(32, 400), fill=(148, 163, 184))
    rows = [(GREEN, "RECORDED", "terminal replays and screenshots: real runs on the presented code, 12 Nov 2026"),
            (BLUE, "SCREENSHOT", "the real console with the real model; the launch link is never shown"),
            (SLATE, "DECK", "slides; each figure carries LIVE, RE-MEASURED <date> or RECORDED <date>")]
    for i, (c, tag, txt) in enumerate(rows):
        yy = 480 + i * 78
        d.rounded_rectangle([140, yy, 450, yy + 56], radius=10, fill=c)
        f = sans(28, 700)
        d.text((295 - d.textlength(tag, font=f) / 2, yy + 11), tag, font=f, fill=(255, 255, 255))
        d.text((480, yy + 12), txt, font=sans(29, 400), fill=(226, 232, 240))
    d.text((140, 760), "Code: branch finale/p4-hardening, commit %s (not yet merged into main) · narration: synthetic voice (Piper)" % COMMIT,
           font=sans(26, 400), fill=(148, 163, 184))
    return img


def card_end(seg):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    d.text((140, 170), "github.com/Invinciblx777/HIH", font=sans(76, 700), fill=(255, 255, 255))
    d.text((140, 275), "Read-only demo: https://aegislab.vercel.app", font=sans(44, 500), fill=(203, 213, 225))
    d.text((140, 345), "cd aegislab && bash scripts/quickstart.sh && bash scripts/judge_demo.sh", font=ImageFont.truetype(str(FONTS / "IBMPlexMono-Regular.ttf"), 32), fill=(203, 213, 225))
    d.text((140, 470), "AegisLab · Team Tech Mavericks", font=sans(44, 650), fill=(255, 255, 255))
    d.text((140, 535), "Abdul Munaf Z · Likhith Sai N · Sreeram Rajesh", font=sans(34, 500), fill=(148, 163, 184))
    d.text((140, 640), "Single host, CPU only; not production, not third-party audited. Residual risks: FINALE_JUDGE_QA.md.", font=sans(28, 400), fill=(148, 163, 184))
    return img


CARDS = {"slide": card_slide, "screen": card_screen, "image": card_image, "title": card_title, "end": card_end}

# ---------------------------------------------------------------- terminal replay
CW = MONO.getlength("M")
LH = 25


class Replay:
    def __init__(self, seg, length):
        v = seg["visual"]
        rec = json.load(open(MEDIA / "recordings" / (v["rec"] + ".json")))
        self.cols, self.rows = rec["meta"]["cols"], rec["meta"]["rows"]
        marks = {n: tm for tm, n in rec["marks"]}
        a, b = marks[v.get("from", "cmd0")], marks[v.get("to", "end")]
        evs = [(tm - a, base64.b64decode(x)) for tm, x in rec["events"] if a - 0.3 <= tm <= b]
        span = max(0.1, b - a)
        self.speed = max(1.0, span / max(1.0, length - 1.2))
        self.evs = [(max(0.0, tm) / self.speed, data) for tm, data in evs]
        self.screen = pyte.Screen(self.cols, self.rows)
        self.stream = pyte.ByteStream(self.screen)
        self.i = 0
        self.what = v.get("what", v["rec"])

    def advance(self, rt):
        while self.i < len(self.evs) and self.evs[self.i][0] <= rt:
            self.stream.feed(self.evs[self.i][1])
            self.i += 1

    def draw(self):
        img = Image.new("RGB", (W, H), BG)
        d = ImageDraw.Draw(img)
        tx = int((W - self.cols * CW) / 2)
        ty = BAND_H + 28
        d.rectangle([tx - 16, ty - 12, tx + self.cols * CW + 16, ty + self.rows * LH + 8], fill=(15, 23, 42), outline=(51, 65, 85))
        for y in range(self.rows):
            row = self.screen.buffer[y]
            x = 0
            while x < self.cols:
                ch = row[x]
                if ch.data in (" ", ""):
                    x += 1
                    continue
                j, s = x, ""
                while j < self.cols and row[j].fg == ch.fg and row[j].bold == ch.bold:
                    s += row[j].data or " "
                    j += 1
                d.text((tx + x * CW, ty + y * LH), s, font=MONO_B if ch.bold else MONO, fill=COLORS.get(ch.fg, INK))
                x = j
        sp = "real time" if self.speed <= 1.0 else "played at %.1fx" % self.speed
        band(img, GREEN, "RECORDED 12 Nov 2026 · terminal replay · " + self.what, "%s · code %s · not executed in this video" % (sp, COMMIT))
        return img


state = {"seg": None, "obj": None}
static = {}


def frame_at(tm):
    cap = caption_at(cues, tm)
    for a, b, seg in timeline:
        if a <= tm < b:
            break
    v = seg["visual"]
    if v["kind"] != "term":
        if seg["key"] not in static:
            static[seg["key"]] = CARDS[v["kind"]](seg)

        def make(k=seg["key"], cap=cap):
            img = static[k].copy()
            caption(img, cap)
            return img
        return (seg["key"], cap), make
    if state["seg"] != seg["key"]:
        state.update(seg=seg["key"], obj=Replay(seg, b - a))
    r = state["obj"]
    r.advance(tm - a)

    def make(cap=cap):
        img = r.draw()
        caption(img, cap)
        return img
    return (seg["key"], r.i, cap), make


n = encode(out_mp4, W, H, FPS, TOTAL, frame_at, speech, wavs)
print("rendered %s: %.2f s, %d frames, %d caption cues" % (out_mp4, TOTAL, n, len(cues)))
print(json.dumps({"total_s": round(TOTAL, 2), "segments": [(s["key"], round(a, 2), round(b, 2)) for a, b, s in timeline],
                  "replays": {k: v for k, v in []}}, indent=None))
