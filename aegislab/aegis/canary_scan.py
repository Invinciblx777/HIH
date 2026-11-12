"""Finale P4, task 3: find another run's canary in model output even when it is re-encoded.

runs.canary_hits() catches the token, its 12 hex digits, the digits with separators, and any 8 consecutive digits. It does
not see a canary that was base64-encoded, hex-encoded, rot13'd, reversed or spelled out ("base64 not detected" in the
finale analysis). This module closes that for a fixed, documented list of encodings:

  base64        standard and URL-safe alphabets, padded or not, at any byte alignment inside a longer encoded text; line
                breaks and spaces inside the encoded text are ignored
  hex           the ASCII bytes of the token as hex digits (any case, any separators)
  rot13         of the token (letters a-f of the digits become n-s)
  reversed      the token or its digits written backwards (separators ignored)
  split         the digits with whitespace or punctuation between them (also caught by canary_hits)
  spelled       digits spelled out as words (zero/oh, one, ... nine) and letters as themselves or NATO words (alpha ... foxtrot),
                consecutive words only

For each of the forms "CANARY-<hex>", lowercase, uppercase, and the 12 hex digits alone (lower and upper case).

How it searches: it never decodes the text. It ENCODES each foreign canary (cached), and looks the fixed-length encodings up
in a few normalised views of the text (whitespace removed; lowercase alphanumerics only; spelled words mapped to characters)
with one sliding window per needle length. So the work is linear in the text size, there is no recursion and no decoder that
an input could drive. Bounds: at most MAX_SCAN characters are scanned (a longer text is reported as not scanned, and the
broker withholds it), and a time budget (default 50 ms) is checked between steps (exceeding it is also reported, and the
broker withholds). A full match needs the whole token or all 12 digits, so a random text practically never matches (each
needle carries at least 48 random bits).

Not covered (THREAT_MODEL.md section 9): arbitrary ciphers or keyed encodings, encodings applied twice or combined
(base64 of the reversed token), other bases (base32, base85, decimal of the bytes), homoglyphs, translation, paraphrase
("the code starts with seven, then...") with filler words between the digits, and splitting the token across several replies.

near_misses() (used by the anomaly detectors, never to withhold) reports partial fragments: 6-11 consecutive digits of a
foreign canary in the alphanumeric view, or a base64 run of at least 12 characters of a canary's encoding.
"""
import base64
import codecs
import re
import time

MAX_SCAN = 16384
DEFAULT_BUDGET_S = 0.05
DIGIT_WORDS = {"zero": "0", "oh": "0", "one": "1", "two": "2", "three": "3", "four": "4", "five": "5", "six": "6", "seven": "7",
               "eight": "8", "nine": "9", "alpha": "a", "alfa": "a", "bravo": "b", "charlie": "c", "delta": "d", "echo": "e", "foxtrot": "f"}
_WORD = re.compile(r"[a-z0-9]+")
_cache = {}


def _b64_stable(token: bytes, alphabet):
    """The base64 characters that depend only on ``token``'s bytes, for each of the three byte alignments."""
    out = set()
    for k in range(3):
        enc = base64.b64encode(b"\0" * k + token).decode()
        if alphabet == "url":
            enc = enc.replace("+", "-").replace("/", "_")
        lo, hi = 8 * k, 8 * (k + len(token))
        keep = "".join(ch for i, ch in enumerate(enc) if 6 * i >= lo and 6 * i + 6 <= hi)
        if len(keep) >= 12:
            out.add(keep)
    return out


def needles(canary: str) -> dict:
    """{view: {needle: encoding}} for one canary (cached)."""
    if canary in _cache:
        return _cache[canary]
    h = canary.split("-", 1)[-1].lower()
    forms = {canary, canary.lower(), canary.upper(), h, h.upper()}
    nd = {"nows": {}, "alnum": {}, "spelled": {}}
    for f in forms:
        for alpha in ("std", "url"):
            for s in _b64_stable(f.encode(), alpha):
                nd["nows"].setdefault(s, "base64" if alpha == "std" else "base64url")  # same text in both alphabets: base64
        nd["alnum"][f.encode().hex()] = "hex"
    for f in (canary.lower(), h):
        sq = re.sub(r"[^0-9a-z]", "", f)
        nd["alnum"].setdefault(codecs.encode(sq, "rot13"), "rot13")
        nd["alnum"].setdefault(sq[::-1], "reversed")
        nd["alnum"].setdefault(sq, "split")
    nd["spelled"][h] = "spelled"
    _cache[canary] = nd
    if len(_cache) > 20000:
        _cache.clear()
    return nd


class _Index:
    """Needle and fragment lookup tables for a set of canaries, updated incrementally (a new run adds one canary). Built from
    the control plane's own canary list, never from tenant text, so building it is outside the scan's time budget; the broker
    builds it when its workloads start (warm()), not on a request."""

    def __init__(self):
        self.canaries, self.table, self.frags = set(), {}, {}

    def _add(self, c):
        for view, nd in needles(c).items():
            for nd_, enc in nd.items():
                self.table.setdefault(view, {}).setdefault(len(nd_), {})[nd_] = (c, enc)
        h = c.split("-", 1)[-1].lower()
        for n in range(NEAR_MIN_DIGITS, 12):
            for i in range(len(h) - n + 1):
                self.frags.setdefault(("alnum", n), {}).setdefault(h[i:i + n], set()).add(c)
        for s in _b64_stable(c.encode(), "std"):
            for i in range(len(s) - NEAR_B64 + 1):
                self.frags.setdefault(("nows", NEAR_B64), {}).setdefault(s[i:i + NEAR_B64], set()).add(c)

    def update(self, canaries):
        new = set(canaries)
        if len(self.canaries | new) > 50000:  # bounded memory: start over with just this set
            self.canaries, self.table, self.frags = set(), {}, {}
        for c in new - self.canaries:
            self._add(c)
        self.canaries |= new
        return self


NEAR_MIN_DIGITS, NEAR_B64 = 6, 12
_index = _Index()


def warm(canaries):
    """Build the lookup tables ahead of the first request (Broker.start_workloads)."""
    _index.update(canaries)


def _table(canaries) -> dict:
    return _index.update(canaries).table


def views(text: str) -> dict:
    low = text.lower()
    spelled, run = [], []
    for w in _WORD.findall(low):
        ch = DIGIT_WORDS.get(w) or (w if len(w) == 1 and w in "0123456789abcdef" else None)
        if ch is None:
            if run:
                spelled.append("".join(run))
            run = []
        else:
            run.append(ch)
    if run:
        spelled.append("".join(run))
    return {"nows": re.sub(r"\s+", "", text), "alnum": re.sub(r"[^0-9a-z]", "", low), "spelled": "|".join(spelled)}


def scan(text: str, canaries, budget_s: float = None, cap: int = None) -> dict:
    """Returns {"found": {canary: sorted encodings}, "complete": bool, "reason": None | "over_cap" | "budget_exceeded",
    "elapsed_ms"}. ``complete`` False means the text was NOT fully scanned: the caller must withhold it. The bounds default
    to the module's MAX_SCAN and DEFAULT_BUDGET_S, read at call time."""
    budget_s = DEFAULT_BUDGET_S if budget_s is None else budget_s
    if len(text) > (MAX_SCAN if cap is None else cap):
        return {"found": {}, "complete": False, "reason": "over_cap", "elapsed_ms": 0.0}
    want = set(canaries)
    table = _table(want)  # depends on the control plane's canary list only, not on the text: outside the budget, cached
    t0 = time.monotonic()
    found = {}
    v = views(text)
    for view, by_len in table.items():
        s = v[view]
        for n, d in by_len.items():
            for i in range(0, len(s) - n + 1):
                hit = d.get(s[i:i + n])
                if hit and hit[0] in want:  # the index holds every canary seen; only the ones asked about count
                    found.setdefault(hit[0], set()).add(hit[1])
            if time.monotonic() - t0 > budget_s:
                return {"found": {k: sorted(x) for k, x in found.items()}, "complete": False, "reason": "budget_exceeded",
                        "elapsed_ms": round((time.monotonic() - t0) * 1000, 3)}
    return {"found": {k: sorted(x) for k, x in found.items()}, "complete": True, "reason": None,
            "elapsed_ms": round((time.monotonic() - t0) * 1000, 3)}


def near_misses(text: str, canaries, cap: int = None) -> dict:
    """{canary: longest fragment length} for partial fragments: 6-11 consecutive digits of a foreign canary in the
    alphanumeric view, or a 12-character run of the canary token's base64 encoding in the whitespace-free view (reported as
    12). Full matches are scan()'s job; this feeds the anomaly detectors only and never withholds. One dictionary lookup per
    text position and fragment length."""
    if len(text) > (MAX_SCAN if cap is None else cap):
        return {}
    idx = _index.update(canaries)
    want = set(canaries)
    v = views(text)
    out = {}
    for (view, n), d in idx.frags.items():
        s = v[view]
        for i in range(len(s) - n + 1):
            hit = d.get(s[i:i + n])
            if hit:
                for c in hit & want:
                    out[c] = max(out.get(c, 0), n)
    return out
