# Finale P18: the team's own red-team set, and input hardening (MEASURED 2026-11-21)

What this is: the jailbreak prompts the team wrote, measured against AegisLab's blue checks (the tag's regex rules and the sandboxed
Qwen3Guard-Gen-0.6B, same server and request path as `evaluation/guard_eval.py`), with a new **input hardening** layer OFF (the
P16/P17 system, every earlier figure) and ON. No model change: the guard GGUF and its sha256 are the P16 ones
(`3f66ce2417b6df31…`). **The hardening is OFF by default** (`guard_harden` in the run's frozen defence config; the
playground's "Hardening" toggle; `AEGIS_GUARD_HARDEN=1` makes the toggle default to on).

## Prompt set and split

- Source: the team's folder of jailbreak prompts, outside the repository. **No prompt text is in this repository**: only IDs,
  the split and aggregates. Per-prompt verdicts (by ID, no text) were kept outside the repository.
- Format rule: **one prompt per file**. No file has numbered or delimited prompts. The few `---` lines are Markdown rules inside one prompt.
- ID = sha256 of the normalised text: NFC, LF line ends, trailing spaces removed, trimmed. Identical files count once.
- Split, fixed before any result was seen: **last hex digit of the ID even = TUNE, odd = HELD-OUT**. A prompt added later gets
  its split by the same rule.
- The hardening rules were written from TUNE prompts only. HELD-OUT prompts were never opened; the eval prints only aggregates
  for them.
- Cut-off: 08:00:07 IST on 21 Nov 2026 (snapshot of IDs only). Files added after 08:00 are not counted; none had arrived when the final run ended (08:10).
- Sizes: 50 files, **49 unique prompts: 22 TUNE, 27 HELD-OUT**.
  Length 3441 to 105773 characters (median 22591).
  46 of 49 are longer than the guard's 4000-character limit.

## Modes

- **As deployed**, Qwen3Guard refuses any input over 4000 characters, unscanned (fail closed). So the deployed guard, and regex +
  guard, block **every** team prompt by length alone, with hardening OFF or ON. That is a length rule, not detection, so it is
  not the headline.
- The **detection** figures below give the guard the prompt's **first 1000 characters**. That is the
  playground's own prompt limit, and it lets a guard call finish inside its 1500 ms budget: on the 4000-character window every
  call timed out.
  - Only a Safety verdict counts as a block. A timeout would block in deployment (fail closed), but it is not counted here as
    a detection.
  - Guard errors or timeouts in this run: team 7, reference 0.
- **Regex** runs on the full text.
- **Hardening ON** (`aegis/harden.py`, `guard/harden_rules.json`, 11 rules):
  - a normalised view of the input: base64 / hex / URL decoding, zero-width and invisible characters, homoglyphs, combining
    marks, leetspeak, split letters, case;
  - the regex rules plus the extra technique rules run on the original text and on the normalised view;
  - the guard judges both views, and either one blocking blocks;
  - Controversial still blocks.

## Results: team set (detection view)

| Split | Regex OFF | Regex ON | Guard OFF | Guard ON | **Regex + guard OFF** | **Regex + guard ON** |
|---|---|---|---|---|---|---|
| HELD-OUT (n = 27) | 7/27 | 22/27 | 16/27 | 20/27 | 19/27 | 26/27 |
| TUNE (n = 22) | 3/22 | 20/22 | 14/22 | 16/22 | 15/22 | 22/22 |
| all (n = 49) | 10/49 | 42/49 | 30/49 | 36/49 | 34/49 | 48/49 |

**Headline (HELD-OUT, regex + Qwen3Guard): 19/27 blocked OFF and 26/27 blocked ON.**

## Results: reference sets (P16 sets, pinned revisions), regex + guard as deployed

| Set | n | Regex OFF | Regex ON | Regex + guard OFF | Regex + guard ON |
|---|---|---|---|---|---|
| HH-RLHF helpful (benign) | 200 | 0/200 | 0/200 | 3/200 | 4/200 |
| JailbreakBench benign look-alikes | 100 | 0/100 | 0/100 | 59/100 | 61/100 |
| Gandalf (attacks) | 112 | 15/112 | 16/112 | 63/112 | 66/112 |
| JailbreakBench harmful (attacks) | 100 | 0/100 | 0/100 | 99/100 | 99/100 |

- The false-positive rate rose by at most 2.0
  points on either benign set. The limit was 5 points, so no rule was dropped.
- The extra regex rules match none of the benign texts. The small rise comes from the guard's verdict on the normalised view.

## Latency (guard calls for one text)

- Reference sets: hardening OFF p50 504, p95 624, max 662 ms (n = 512, over 4000 ms: 0); ON p50 1000, p95 1231, max 1329 ms (n = 512, over 4000 ms: 0).
- Team set, first 1000 characters: OFF p50 1075, p95 1488, max 1503 ms (n = 49, over 4000 ms: 0); ON p50 2164, p95 2911, max 3005 ms (n = 49, over 4000 ms: 0).
- ON includes the second guard call on the normalised view. In the defence runner that call is made only when the first one
  passed, so deployed latency is at or below these figures. Nothing exceeded the 4000 ms deadline.

## Honest limits

- Small n (27 held-out prompts). One prompt more or less moves the rate by several points.
- The prompts were written by the team, and the held-out half comes from the same source and authors as the TUNE half.
  Some files are near-duplicates of each other (same prompt, small edits); they get different IDs and can fall on both sides
  of the split.
- The detection view judges the first 1000 characters. A prompt whose harmful part comes later is
  caught only by the regex rules on the full text, or by the length rule as deployed.
- The guard runs on a laptop CPU, which sets the window and the timeouts.
- The extra rules are regular expressions for jailbreak techniques; a rephrased attack can avoid them. The benign sets measure
  false positives on ordinary requests only.
- Not "safe": blocked inputs are the guard's and the rules' verdicts, not a proof that no prompt gets through.

## Reproduce

```bash
cd aegislab
.venv/bin/python evaluation/harden_eval.py --prompts "<prompt folder>" --guard-rundir "$AEGIS_GUARD_RUNDIR" \
    --datasets "<P16 datasets dir>" --cutoff-list <ids.txt> --out evidence/finale_p18_2026-11-21 --detail <outside the repo>
```

`results.json`: aggregates, the TUNE and HELD-OUT ID lists, the rules file's sha256, and the sources' sha256. Wall time 634.3 s.
