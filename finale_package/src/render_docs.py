"""Render the finale text assets from templates; every figure comes from claims_used_for_finale.json.

    python render_docs.py CLAIMS.json TEMPLATE OUT        render one template
    python render_docs.py CLAIMS.json --all               render every repository template (see TARGETS)

Placeholders:  {{key.form}}  the claim's display form      {{key.form+}}  the form followed by "(LABEL)"
               {{key.label}} LIVE / RE-MEASURED <date> / RECORDED <date>      {{key.ev}}  its first evidence path
               {{key.ev*}}   every evidence path, comma-separated
An unknown key or form is an error. For narration templates (*.json.tmpl) each segment's "say" is derived from its
"caption" by say() below, so the spoken words and the captions carry the same figures.
"""
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PKG = HERE.parent
REPO = PKG.parent
TARGETS = [("FINALE_SCRIPT.md.tmpl", PKG / "FINALE_SCRIPT.md"), ("FINALE_JUDGE_QA.md.tmpl", PKG / "FINALE_JUDGE_QA.md"),
           ("HANDOUT.md.tmpl", PKG / "HANDOUT.md"), ("narration_judge.json.tmpl", PKG / "src" / "narration_judge.json"),
           ("narration_walkthrough.json.tmpl", PKG / "src" / "narration_walkthrough.json"),
           ("RC4_PACKAGE_HISTORICAL.md.tmpl", REPO / "RC4_PACKAGE_HISTORICAL.md")]


def render(text, C):
    def rep(m):
        key, form = m.group(1), m.group(2)
        if key not in C:
            raise SystemExit("unknown claim key: " + key)
        c = C[key]
        if form == "label":
            return c["label"]
        if form == "ev":
            return c["evidence"][0]
        if form == "ev*":
            return ", ".join(c["evidence"])
        plus = form.endswith("+")
        f = form.rstrip("+")
        if f not in c["forms"]:
            raise SystemExit("unknown form %s.%s" % (key, f))
        return c["forms"][f] + (" (%s)" % c["label"] if plus else "")
    out = re.sub(r"\{\{(\w+)\.([\w*]+\+?)\}\}", rep, text)
    if "{{" in out:
        raise SystemExit("unrendered placeholder: " + out[out.index("{{"):][:60])
    return out


MONTH = {"Oct": "October", "Nov": "November"}
ORD = {10: "tenth", 11: "eleventh", 12: "twelfth", 22: "twenty-second", 23: "twenty-third"}


def say(caption):
    """Spoken form of a caption for Piper: labels, units, slashes and names read out. Figures are not changed."""
    s = caption
    s = re.sub(r"\((RE-MEASURED|RECORDED) (\d+) (Oct|Nov) 2026\)",
               lambda m: ", %s on the %s of %s," % ("re-measured" if m.group(1) == "RE-MEASURED" else "recorded", ORD[int(m.group(2))], MONTH[m.group(3)]), s)
    s = re.sub(r"\((RE-MEASURED|RECORDED) (\d+) (Oct|Nov)\)",
               lambda m: ", %s on the %s of %s," % ("re-measured" if m.group(1) == "RE-MEASURED" else "recorded", ORD[int(m.group(2))], MONTH[m.group(3)]), s)
    s = re.sub(r"\(LIVE\)", ", live,", s)
    s = s.replace("AegisLab", "Aegis Lab").replace("Qwen2.5-0.5B", "Kwen two point five, half a billion parameters").replace("Qwen2.5-1.5B", "Kwen two point five, one point five billion parameters")
    s = s.replace("t0 + ", "t zero plus ").replace("llama.cpp", "llama C P P").replace("AUC", "A U C").replace("UID", "U I D").replace("CPU", "C P U").replace("GPU", "G P U")
    s = s.replace("p = ", "p equals ").replace(" ms", " milliseconds").replace("%", " percent").replace("errno", "error number")
    s = s.replace("0.05/9 = ", "0.05 divided by 9, which is ")
    s = re.sub(r"(\d\.\d+)/(\d\.\d+)/(\d\.\d+)", r"\1, \2 and \3", s)
    s = re.sub(r"(\d\.\d+)/(\d\.\d+)", r"\1 and \2", s)
    s = re.sub(r"(?<![\d.])(\d+)/(\d+)(?![\d.])", r"\1 of \2", s)
    s = re.sub(r"\+(\d+)", r"plus \1", s)
    s = s.replace("–", " to ").replace(" · ", ", ").replace("F4", "F four").replace("E1", "E one").replace("E2", "E two")
    s = re.sub(r"\s+,", ",", re.sub(r",\s*,", ",", s))
    s = re.sub(r",\s*([.:;])", r"\1", s)
    seen = set()   # a label is spoken once per segment; the caption keeps every label

    def once(m):
        k = m.group(1)
        if k in seen:
            return ","
        seen.add(k)
        return m.group(0)
    s = re.sub(r", ((?:re-measured|recorded) on the \w+(?:-\w+)? of \w+|live),?", once, s)
    s = re.sub(r",\s*([.:;])", r"\1", re.sub(r"\s+([,.:;])", r"\1", s))
    return re.sub(r"\s{2,}", " ", s).strip()


def render_file(C, tmpl, out):
    t = render((HERE / "templates" / tmpl).read_text(), C)
    if tmpl.endswith(".json.tmpl"):
        d = json.loads(t)
        for seg in d["segments"]:
            seg["say"] = say(seg["caption"])
        t = json.dumps(d, indent=1, ensure_ascii=False) + "\n"
    Path(out).write_text(t)
    print("wrote", out)


def readme_block(C):
    """Replace (or insert after the title) the block between the finale markers in the root README.md."""
    block = render((HERE / "templates" / "README_block.md.tmpl").read_text(), C).strip("\n")
    p = REPO / "README.md"
    t = p.read_text()
    a, b = "<!-- finale:start -->", "<!-- finale:end -->"
    if a in t:
        t = t.split(a, 1)[0] + block + t.split(b, 1)[1]
    else:
        lines = t.split("\n")
        i = next(k for k, ln in enumerate(lines) if ln.startswith("# ")) + 1
        t = "\n".join(lines[:i] + ["", block] + lines[i:])
    p.write_text(t)
    print("wrote", p, "(finale block)")


def main():
    C = json.loads(Path(sys.argv[1]).read_text())["claims"]
    if sys.argv[2] == "--all":
        for tmpl, out in TARGETS:
            render_file(C, tmpl, out)
        readme_block(C)
        return
    render_file(C, sys.argv[2], sys.argv[3])


if __name__ == "__main__":
    main()
