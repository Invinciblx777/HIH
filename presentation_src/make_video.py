"""Render the 120-second pitch video, voice-over script, SRT captions and timestamped storyboard from narration.json.

    python make_video.py narration.json slides_dir terminal_hires.png voice.onnx out_dir

slides_dir holds slide-1.png .. slide-8.png rendered from the final PDF at 3840 x 2160. The speech is synthesised locally with Piper
(one file per sentence, so every sentence has a measured duration); captions are split inside each sentence in proportion to character
count. Output: Tech_Mavericks_AegisLab_Pitch_120s.mp4 (1920x1080, 30 fps, H.264 + AAC 48 kHz stereo, exactly 120.000 s), Captions.srt,
Voiceover_Script.txt, Storyboard_Timestamped.txt, timeline.json.
"""
import json
import math
import subprocess
import sys
import textwrap
import wave
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw, ImageFont

FPS, DUR, W, H, CAP = 30, 120.0, 1920, 1080, 120
VH = H - CAP
PPI = 192  # pixels per inch of the 3840 x 2160 slide renders
FONTS = Path(__file__).resolve().parent.parent / "aegislab" / "web" / "fonts"
BG = (14, 22, 36)
GAP_SENT = 0.28


def synth(spec, voice_path, out):
    from piper import PiperVoice
    v = PiperVoice.load(str(voice_path))
    out.mkdir(parents=True, exist_ok=True)
    for seg in spec["segments"]:
        for i, s in enumerate(seg["sentences"]):
            p = out / ("%s_%d.wav" % (seg["id"], i))
            with wave.open(str(p), "wb") as w:
                v.synthesize_wav(s["tts"], w)
            with wave.open(str(p)) as w:
                s["dur"] = w.getnframes() / w.getframerate()
                s["sr"] = w.getframerate()
            s["wav"] = str(p)


def layout(spec):
    """Absolute start of every sentence; checks every segment fits its window."""
    problems = []
    for seg in spec["segments"]:
        t = seg["start"]
        for s in seg["sentences"]:
            s["t0"], s["t1"] = t, t + s["dur"]
            t = s["t1"] + GAP_SENT
        seg["speech_end"] = seg["sentences"][-1]["t1"]
        if seg["speech_end"] > seg["end"]:
            problems.append("%s speech ends %.2f s, window ends %.2f s" % (seg["id"], seg["speech_end"], seg["end"]))
    return problems


def cues(spec, max_chars=62):
    out = []
    for seg in spec["segments"]:
        for s in seg["sentences"]:
            words = s["text"].split()
            chunks, cur = [], []
            for w_ in words:
                if cur and len(" ".join(cur + [w_])) > max_chars:
                    chunks.append(cur)
                    cur = []
                cur.append(w_)
            chunks.append(cur)
            # balance a short trailing chunk
            if len(chunks) > 1 and len(" ".join(chunks[-1])) < 14:
                last = chunks.pop()
                chunks[-1] += last
            total = sum(len(" ".join(c)) for c in chunks)
            t = s["t0"]
            for c in chunks:
                d = s["dur"] * len(" ".join(c)) / total
                out.append((t, t + d, " ".join(c)))
                t += d
    return out


def srt_time(t):
    ms = int(round(t * 1000))
    return "%02d:%02d:%02d,%03d" % (ms // 3600000, ms // 60000 % 60, ms // 1000 % 60, ms % 1000)


def mm(t):
    return "%02d:%02d" % (int(t) // 60, int(t) % 60)


def write_texts(spec, cs, out):
    (out / "Captions.srt").write_text("\n".join("%d\n%s --> %s\n%s\n" % (i + 1, srt_time(a), srt_time(b), t) for i, (a, b, t) in enumerate(cs)))
    lines = ["AegisLab · 120-second pitch · voice-over script", "Same words as Captions.srt. Voice: %s (local speech synthesis). Spoken pace is not altered to fit." % spec["voice"], ""]
    for seg in spec["segments"]:
        lines.append("[%s-%s] %s" % (mm(seg["start"]), mm(seg["end"]), seg["section"].upper()))
        lines.append(" ".join(s["text"] for s in seg["sentences"]))
        lines.append("")
    words = sum(len(s["text"].split()) for seg in spec["segments"] for s in seg["sentences"])
    lines.append("Spoken words: %d" % words)
    (out / "Voiceover_Script.txt").write_text("\n".join(lines) + "\n")
    sb = ["AegisLab · 120-second pitch · timestamped storyboard", "1920x1080, 30 fps, H.264 + AAC 48 kHz stereo, 120.000 s. Times are start-end seconds of the rendered file.", ""]
    for seg in spec["segments"]:
        sb.append("%s-%s  %s  (slide %d)" % (mm(seg["start"]), mm(seg["end"]), seg["section"], seg["slide"]))
        sb.append("  Visual: " + seg["visual"])
        if seg.get("tag"):
            sb.append("  On-screen tag: " + seg["tag"])
        if seg.get("terminal_from"):
            sb.append("  From %.1f s: the recorded terminal output of scripts/judge_demo.sh step 3, full screen. Text is the real transcript; nothing is typed or replayed faster." % seg["terminal_from"])
        sb.append("  Speech: %.1f-%.1f s" % (seg["sentences"][0]["t0"], seg["speech_end"]))
        for s in seg["sentences"]:
            sb.append("    - " + s["text"])
        sb.append("")
    sb.append("Media notes: the slides are renders of the submitted PDF. Results shown for the real model are precomputed from saved runs (Qwen2.5-0.5B Q4_K_M, CPU llama.cpp, loopback); the demo footage uses the deterministic stub model. No playback speed change anywhere.")
    (out / "Storyboard_Timestamped.txt").write_text("\n".join(sb) + "\n")


def build_audio(spec, out):
    sr = 48000
    track = np.zeros(int(DUR * sr), dtype=np.float32)
    for seg in spec["segments"]:
        for s in seg["sentences"]:
            with wave.open(s["wav"]) as w:
                x = np.frombuffer(w.readframes(w.getnframes()), dtype=np.int16).astype(np.float32) / 32768.0
                srcsr = w.getframerate()
            n = int(len(x) * sr / srcsr)
            y = np.interp(np.linspace(0, len(x) - 1, n), np.arange(len(x)), x).astype(np.float32)
            f = int(0.01 * sr)
            y[:f] *= np.linspace(0, 1, f)
            y[-f:] *= np.linspace(1, 0, f)
            i0 = int(s["t0"] * sr)
            track[i0:i0 + n] += y * 0.9
    peak = float(np.abs(track).max())
    if peak > 0.97:
        track *= 0.97 / peak
    pcm = (np.stack([track, track], 1) * 32767).astype(np.int16)
    p = out / "voice_48k.wav"
    with wave.open(str(p), "wb") as w:
        w.setnchannels(2)
        w.setsampwidth(2)
        w.setframerate(sr)
        w.writeframes(pcm.tobytes())
    return p, peak


# ------------------------------------------------------------------ frames
def ease(u):
    return u * u * (3 - 2 * u)


class Renderer:
    def __init__(self, spec, slides_dir, term_png):
        self.spec = spec
        self.slides = {i: Image.open(Path(slides_dir) / ("slide-%d.png" % i)).convert("RGB") for i in range(1, 9)}
        self.term = self._terminal(term_png)
        self.f_cap = ImageFont.truetype(str(FONTS / "IBMPlexSans-var.ttf"), 40)
        self.f_tag = ImageFont.truetype(str(FONTS / "IBMPlexSans-var.ttf"), 22)
        try:
            self.f_tag.set_variation_by_name("SemiBold")
            self.f_cap.set_variation_by_name("Medium")
        except Exception:  # noqa: BLE001
            pass
        self.cues = None
        self.tag_cache = {}

    def _terminal(self, p):
        t = Image.open(p).convert("RGB")
        s = min((W - 160) / t.size[0], (VH - 150) / t.size[1])
        t = t.resize((int(t.size[0] * s), int(t.size[1] * s)), Image.LANCZOS)
        im = Image.new("RGB", (W, VH), (7, 12, 22))
        im.paste(t, ((W - t.size[0]) // 2, 40))
        d = ImageDraw.Draw(im)
        f = ImageFont.truetype(str(FONTS / "IBMPlexMono-SemiBold.ttf"), 26)
        d.text((W // 2, VH - 48), "RECORDED OUTPUT · judge_demo.sh step 3 · stub model · text unedited", font=f, fill=(255, 191, 96), anchor="mm")
        return im

    def view(self, seg, t):
        u = min(max((t - seg["start"]) / (seg["end"] - seg["start"]), 0.0), 1.0)
        kf = seg["view"]
        for a, b in zip(kf, kf[1:]):
            if u <= b[0]:
                k = ease((u - a[0]) / (b[0] - a[0])) if b[0] > a[0] else 1.0
                return [a[i] + (b[i] - a[i]) * k for i in (1, 2, 3)]
        return kf[-1][1:]

    def content(self, seg, t):
        if seg.get("terminal_from") and t >= seg["terminal_from"]:
            return self.term
        x, y, w = self.view(seg, t)
        h = w * VH / W
        x = min(max(x, 0), 20 - w)
        y = min(max(y, 0), 11.25 - h)
        return self.slides[seg["slide"]].resize((W, VH), Image.BICUBIC, box=(x * PPI, y * PPI, (x + w) * PPI, (y + h) * PPI))

    def tag(self, text):
        if text not in self.tag_cache:
            w = int(self.f_tag.getlength(text)) + 36
            im = Image.new("RGBA", (w, 38), (0, 0, 0, 0))
            d = ImageDraw.Draw(im)
            col = (232, 119, 46, 255) if text.startswith("REAL") else (47, 109, 181, 255)
            d.rounded_rectangle([0, 0, w - 1, 37], radius=19, fill=col)
            d.text((18, 19), text, font=self.f_tag, fill=(255, 255, 255), anchor="lm")
            self.tag_cache[text] = im
        return self.tag_cache[text]

    def seg_at(self, t):
        segs = self.spec["segments"]
        cur = segs[0]
        for s in segs:
            if t >= s["start"] - 0.4:
                cur = s
        return cur

    def frame(self, t):
        segs = self.spec["segments"]
        i = max(k for k, s in enumerate(segs) if t >= s["start"] - 0.4) if t >= segs[0]["start"] - 0.4 else 0
        seg = segs[i]
        img = self.content(seg, t)
        # crossfade into the next segment over the last 0.4 s before its start
        if i + 1 < len(segs):
            nxt = segs[i + 1]
            if t >= nxt["start"] - 0.4:
                a = (t - (nxt["start"] - 0.4)) / 0.4
                img = Image.blend(self.content(seg, t), self.content(nxt, nxt["start"]), min(max(a, 0), 1))
                seg = nxt if a >= 0.5 else seg
        img = img.copy()
        out = Image.new("RGB", (W, H), BG)
        out.paste(img, (0, 0))
        if seg.get("tag"):
            tg = self.tag(seg["tag"])
            out.paste(tg, (28, VH + 10), tg)
        d = ImageDraw.Draw(out)
        cap = next((c for (a, b, c) in self.cues if a <= t < b), "")
        if cap:
            d.text((W // 2, VH + 82), cap, font=self.f_cap, fill=(255, 255, 255), anchor="mm")
        return out


def render(spec, cs, slides_dir, term_png, audio, out_mp4, ffmpeg, stills=None):
    r = Renderer(spec, slides_dir, term_png)
    r.cues = cs
    if stills:
        for t in stills:
            r.frame(t).save(Path(out_mp4).parent / ("still_%06.2f.png" % t))
        return
    cmd = [ffmpeg, "-y", "-loglevel", "error", "-f", "rawvideo", "-pix_fmt", "rgb24", "-s", "%dx%d" % (W, H), "-r", str(FPS), "-i", "-", "-i", str(audio),
           "-map", "0:v", "-map", "1:a", "-c:v", "libx264", "-preset", "medium", "-crf", "18", "-pix_fmt", "yuv420p", "-r", str(FPS), "-c:a", "aac",
           "-b:a", "192k", "-ar", "48000", "-t", "%.3f" % DUR, "-movflags", "+faststart", str(out_mp4)]
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE)
    for n in range(int(FPS * DUR)):
        p.stdin.write(r.frame(n / FPS).tobytes())
        if n % 300 == 0:
            print("frame", n, flush=True)
    p.stdin.close()
    p.wait()
    return p.returncode


if __name__ == "__main__":
    import imageio_ffmpeg
    args = sys.argv[1:]
    stills = None
    if "--stills" in args:
        i = args.index("--stills")
        stills = [float(x) for x in args[i + 1].split(",")]
        args = args[:i] + args[i + 2:]
    nar, slides, term, voice, out = args
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    spec = json.loads(Path(nar).read_text())
    wavs = out / "wav"
    if not (wavs / "S1_0.wav").exists():
        synth(spec, voice, wavs)
    else:  # reuse the synthesis from a previous run (durations are re-read from the files)
        for seg in spec["segments"]:
            for i, s in enumerate(seg["sentences"]):
                p = wavs / ("%s_%d.wav" % (seg["id"], i))
                with wave.open(str(p)) as w:
                    s["dur"], s["sr"], s["wav"] = w.getnframes() / w.getframerate(), w.getframerate(), str(p)
    probs = layout(spec)
    for p in probs:
        print("OVERRUN", p)
    cs = cues(spec)
    write_texts(spec, cs, out)
    audio, peak = build_audio(spec, out)
    (out / "timeline.json").write_text(json.dumps({"segments": [{k: v for k, v in s.items() if k not in ("sentences", "view")} | {"sentences": [{k: v for k, v in x.items() if k not in ("wav",)} for x in s["sentences"]]} for s in spec["segments"]],
                                                   "cues": cs, "audio_peak_before_limit": peak}, indent=1))
    if probs:
        sys.exit(2)
    sys.exit(render(spec, cs, slides, term, audio, out / "Tech_Mavericks_AegisLab_Pitch_120s.mp4", imageio_ffmpeg.get_ffmpeg_exe(), stills) or 0)
