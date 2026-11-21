"""Finale P18: input hardening for blue's checks. OFF unless the run's frozen defence config has "guard_harden": true
(the playground's "Hardening" toggle, or AEGIS_GUARD_HARDEN=1 for the console's default). Without it nothing here runs and every
committed figure is the P16/P17 one.

Two parts, both general (built from the TUNE half of the team's red-team set only; see evaluation/harden_eval.py):

  normalise(text) -> (normalised text, [technique, ...])
      a second view of the input with common obfuscations undone: Unicode compatibility forms (NFKC), zero-width and other
      invisible characters removed, combining marks stripped, Cyrillic/Greek look-alike letters mapped to Latin, case folded,
      leetspeak digits/symbols inside words mapped to letters, letters split by spaces or punctuation ("i g n o r e",
      "i.g.n.o.r.e") joined, and base64 / hex / URL-percent encoded runs decoded and appended.
  rules(): the extra input rules in guard/harden_rules.json (one regex per technique, matched case-insensitively against both the
      original and the normalised text). They add to the defence config's own input_patterns; they never replace them.

The guard (Qwen3Guard) judges the original text AND the normalised view when they differ; either one blocking blocks.
Controversial still blocks. The length rule (guard_max_chars, fail closed) is unchanged.

This file has no dependencies outside the standard library: guard/guard_runner.py loads it inside the defence runner's container
(aegis/guard.py mounts a read-only copy next to it).
"""
import base64
import binascii
import json
import re
import unicodedata
import urllib.parse
from pathlib import Path

RULES_FILE = Path(__file__).resolve().parent.parent / "guard" / "harden_rules.json"
MAX_DECODED = 4000

INVISIBLE = re.compile("[­͏؜ᅟᅠ឴឵᠎​-‏‪-‮⁠-⁤⁦-⁯ㅤ︀-️﻿ﾠ]")
CONFUSABLE = str.maketrans({
    # Cyrillic
    "а": "a", "в": "b", "е": "e", "ё": "e", "к": "k", "м": "m", "н": "h", "о": "o", "р": "p", "с": "c", "т": "t", "у": "y",
    "х": "x", "і": "i", "ї": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ԛ": "q", "ԝ": "w", "ɡ": "g",
    # Greek
    "α": "a", "β": "b", "ε": "e", "η": "n", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "χ": "x",
    "ω": "w", "ϲ": "c",
    # Latin look-alikes
    "ı": "i", "ȷ": "j", "ł": "l", "ø": "o", "đ": "d", "ß": "ss",
})
LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a", "$": "s", "!": "i", "|": "l"})
LEET_WORD = re.compile(r"(?<![\w])(?=[\w@$!|]*[a-z])(?=[\w@$!|]*[0-9@$!|])[\w@$!|]{3,}(?![\w])")
SPLIT_LETTERS = re.compile(r"(?<![a-z])(?:[a-z][\s.\-_*·•,/|+]{1,3}){3,}[a-z](?![a-z])")
B64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")
B64URL = re.compile(r"(?<![A-Za-z0-9_\-=])[A-Za-z0-9_\-]{16,}={0,2}(?![A-Za-z0-9_\-=])")
HEX = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}[\s:]?){8,}(?![0-9a-fA-F])")
PCT = re.compile(r"(?:%[0-9a-fA-F]{2}){3,}")


def _printable(s):
    if not s:
        return False
    ok = sum(1 for ch in s if ch.isprintable() or ch in "\n\t")
    letters = sum(1 for ch in s if ch.isalpha())
    return ok / len(s) > 0.95 and letters / len(s) > 0.5


def _try_b64(run):
    for dec in (base64.b64decode, base64.urlsafe_b64decode):
        if dec is base64.urlsafe_b64decode and ("/" in run or "+" in run):
            continue
        try:
            raw = dec(run + "=" * (-len(run) % 4))
            s = raw.decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if _printable(s):
            return s
    return None


def decode_runs(text):
    """Decoded base64 / hex / URL-percent runs found in the text, each as (technique, decoded text)."""
    out = []
    for m in B64.finditer(text):
        run = m.group(0)
        if not (re.search(r"[A-Z]", run) and re.search(r"[a-z]", run)) and not re.search(r"\d", run):
            continue  # a plain word or identifier, not an encoding
        s = _try_b64(run)
        if s:
            out.append(("base64", s))
    for m in B64URL.finditer(text):
        run = m.group(0)
        if ("-" in run or "_" in run) and re.search(r"[A-Z]", run) and re.search(r"[a-z]", run):
            s = _try_b64(run)
            if s and ("base64", s) not in out:
                out.append(("base64url", s))
    for m in HEX.finditer(text):
        h = re.sub(r"[\s:]", "", m.group(0))
        if len(h) % 2:
            h = h[:-1]
        try:
            s = bytes.fromhex(h).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if _printable(s):
            out.append(("hex", s))
    for m in PCT.finditer(text):
        s = urllib.parse.unquote(m.group(0))
        if s != m.group(0) and _printable(s):
            out.append(("url_percent", s))
    return out


def normalise(text):
    """(normalised view, sorted technique names that changed something)."""
    t = str(text or "")
    used = set()
    decoded = decode_runs(t)
    for k, _ in decoded:
        used.add(k)
    s = unicodedata.normalize("NFKC", t)
    if s != t:
        used.add("unicode_compat")
    s2 = INVISIBLE.sub("", s)
    if s2 != s:
        used.add("invisible_chars")
    s = s2
    d = unicodedata.normalize("NFKD", s)
    s2 = "".join(ch for ch in d if not unicodedata.combining(ch))
    if any(unicodedata.combining(ch) for ch in d):
        used.add("combining_marks")
    s = unicodedata.normalize("NFC", s2).casefold()
    s2 = s.translate(CONFUSABLE)
    if s2 != s:
        used.add("homoglyphs")
    s = s2
    s2 = LEET_WORD.sub(lambda m: m.group(0).translate(LEET), s)
    if s2 != s:
        used.add("leetspeak")
    s = s2
    s2 = SPLIT_LETTERS.sub(lambda m: re.sub(r"[^a-z]", "", m.group(0)), s)
    if s2 != s:
        used.add("split_letters")
    s = re.sub(r"[ \t\r\f\v]+", " ", s2)
    s = re.sub(r"\n\s*\n+", "\n", s).strip()
    if decoded:
        s += "\n" + "\n".join(x[:MAX_DECODED].casefold() for _, x in decoded)
    return s, sorted(used)


def load_rules(path=None):
    """[{"id", "technique", "pattern": compiled}] from guard/harden_rules.json; a missing or broken file gives no extra rules."""
    p = Path(path) if path else RULES_FILE
    try:
        doc = json.loads(p.read_text())
    except (OSError, ValueError):
        return []
    out = []
    for r in doc.get("rules", []):
        try:
            out.append({"id": str(r["id"]), "technique": str(r.get("technique", "")), "pattern": re.compile(r["pattern"], re.I | re.S)})
        except (KeyError, re.error, TypeError):
            continue
    return out


def match(text, norm, base_patterns, rules):
    """First matching rule on the original or the normalised text: {"verdict", "rule", "view"}; base patterns first."""
    for view, s in (("original", text), ("normalised", norm)):
        for p in base_patterns:
            if p.search(s):
                return {"verdict": "block", "rule": "base:" + p.pattern[:60], "view": view}
        for r in rules:
            if r["pattern"].search(s):
                return {"verdict": "block", "rule": r["id"], "view": view}
    return {"verdict": "allow", "rule": None, "view": None}
