# AegisLab pitch: talk tracks (finale P17, 21 Nov 2026)

Deck: `docs/pitch/AegisLab_Pitch.pptx` and `docs/pitch/AegisLab_Pitch.pdf`. Every number below is a claim from `finale_package/claims_used_for_finale.json`
with its label, or comes from a P17 evidence file named next to it. Say the label when you say a number ("measured on 20 November").

## How the deck maps to the judging criteria

The slides follow the judging criteria in order, 1 to 4 (weights as given by the organisers); each slide carries a chip naming its criterion, and the cover shows the map.

| Criterion | Weight | Where |
|---|---|---|
| 1. Problem Understanding & Innovation | 25 | slides 2–4 |
| 2. Technical Execution & Functionality | 30 | slides 5–10 and the live demo (Lab playground, Aegis Chat) |
| 3. Real-World Impact & Scalability | 25 | slides 11–13 |
| 4. Presentation & Team Understanding | 20 | slide 14 and the whole talk; every team member should be able to explain the broker, the guard and the evidence chain |

## 3-minute track

**[0:00, slide 1] Hook.** "Your red team is the easiest way to steal your model's secrets. The red-team range holds the attack pack,
the defence rules, the model and the results. If it leaks, an attacker learns which jailbreaks work and which layer stopped the
rest. AegisLab is the secure range for AI red-teaming."

**[0:20, slides 2–3] Problem and insight.** "Track 04 asks us to secure the testing infrastructure itself. Four leaks break an
evaluation: the pack, which layer refused, results before review, and logs that can be rewritten. Guards protect the model; attack
tools test the model. We protect the test, and we work with both."

**[0:45, slide 5] Product.** "Red, blue and the model each run in a rootless sandbox with no network. Only the broker passes
messages. Every reply leaves at one fixed deadline with one refusal text. Every run is sealed, released by a reviewer, and verifiable
offline."

**[1:05, slides 6–7, LIVE] Jailbreak.** Console → Lab → Try a jailbreak → Prompt B → Run real test. "Same prompt, two real runs. Without
the guard, the model answers. With Qwen3Guard, it is blocked before the model, Non-violent Illegal Acts, in about six hundred
milliseconds. And red? Red gets the same refusal at the same four-second deadline either way." Point at the pipeline tiles and the
evidence strip: verify exit 0, tampered copy exit 1.

**[optional, after slide 7, LIVE] Aegis Chat.** Console → Chat → New chat. Ask "What is the capital of France?" (green "Aegis Guard:
allowed"), then Prompt B (red "Aegis Guard: blocked · Non-violent Illegal Acts", the uniform refusal). "This is a normal chat, but
every message is a real broker run: Aegis Guard checks it before the model, the model answers only if allowed, output and canary
checks run, and the broker releases one answer at the fixed four-second deadline." Point at the open Operator view (reviewer only:
deciding layer, guard, model and output times, padding, signed audit). If asked: Aegis Guard is our regex rules plus input hardening
plus Qwen's Qwen3Guard-Gen-0.6B (Apache-2.0) in its own sandbox.

**[1:50, slide 8] Proof.** "Measured on 20 November: the guard blocks 99 of 100 JailbreakBench harmful goals; regex blocks none.
On Gandalf injections it gets 61 of 112, so it is a layer, not a wall. It costs false positives: 59 of 100 benign look-alikes.
Without the deadline, a classifier reads the refusal with accuracy 1.000; with it, 0.395 against a 0.800 baseline, p 0.846: no leak
detected."

**[2:20, slide 10] TinyFish Outside-In.** "We pointed the sponsor's web agents at pages with hidden instructions, imported what they
brought back as an untrusted pack, and ran it through the same range. We also let their agents pentest our public demo."
"Recorded on 21 November: of the agents that actually read a poisoned page, none of 18 obeyed it. In the range, regex plus
Qwen3Guard stopped 9 of 20 imported entries before the model, and no model answer carried the injected link. Their audit of our
demo found no keys, no API docs and no way to write."

**[2:45, slides 9, 14] Evidence and ask.** "Every run's terminal checkpoint can be anchored on Base: one transaction, a fraction of a
cent, and the check fails on a tampered copy. We are looking for two design partners who run red-team evaluations. The read-only
demo is live, and the code is MIT."

## 5-minute track

Follow the slide notes in order (they are written as this track); timings:

| Time | Slide | Beat |
|---|---|---|
| 0:00–0:20 | 1 | Hook |
| 0:20–0:45 | 2 | Four leaks of a red-team range (Track 04) |
| 0:45–1:05 | 3 | Insight: secure the range; complementary to guards and generators (sources: docs/pitch/SOURCES.md) |
| 1:05–1:20 | 4 | Comparison: documented / not documented; we did not benchmark these products |
| 1:20–1:40 | 5 | Product: isolation, hidden refusals, provable evidence |
| 1:40–2:20 | 6–7 | LIVE: Prompt B without and with the guard; pipeline tiles; banner; red waits for the deadline |
| 2:20–2:50 | 8 | Proof with the weak numbers (MEASURED 20 Nov 2026) |
| 2:50–3:10 | 9 | Evidence: hash chain, Ed25519, 40/40 tampered copies rejected (RE-MEASURED 11 Nov 2026), Base anchor tx |
| 3:10–3:45 | 10 | TinyFish Outside-In: (a) web injections imported and run, (b) agents pentest our demo, (c) signed n8n incidents |
| 3:45–4:00 | 11 | Integrations loop |
| 4:00–4:15 | 12 | Market (one sourced estimate) and buyers; plans illustrative |
| 4:15–4:40 | 13 | Roadmap (commit-reveal anchoring, transparency log) and residual risk |
| 4:40–5:00 | 14 | The ask |

Outside-In lines for slide 10 (from the evidence): 

- (a) 30 TinyFish runs on 10 synthetic pages; 18 answers show the page was read; 0 of 18 followed the hidden instruction; 0 warned
  the user. Say it plainly: the first mirror put a click-through page in front of ours and about half the agents never got past it.
- Import: regex + Qwen3Guard stopped 9 of 20 entries before the model (regex alone 8 of 20). The base64 page was stopped only by a
  guard timeout (fail-closed). The agents' answers were clean, so they reached the model, which is correct. No model answer carried
  the injected link. Sealed OIN-002-G: verify exit 0, tampered copy exit 1.
- (b) "We let the sponsor's agents pentest us": no API docs, keys, tokens or write path. One agent said it saw an "Unsafe"
  verdict; we checked every page and response, and it was a misreading. One goal was refused by TinyFish's usage policy and reworded.
- (c) 34 of 34 HMAC-signed incidents delivered to n8n.
- All RECORDED 21 Nov 2026; small samples; details in docs/integrations/TINYFISH.md.

## If the live demo fails

Do not debug on stage. Say "here is the same run, recorded" and use slide 7 (screenshot of a live run on 21 Nov 2026), then the
read-only demo at https://aegislab-demo.onrender.com (verify a bundle, tamper with a copy). The free Render instance can take about
half a minute to wake: open it before the talk.
