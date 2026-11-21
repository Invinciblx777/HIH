# P17 product research: how AI-security products pitch, and where AegisLab sits

Accessed 21 Nov 2026. Sources are numbered S1–S13 in [SOURCES.md](SOURCES.md). We did not benchmark any product named here.

## 1. What the category sells

| Group | Products (sources) | What they protect or test |
|---|---|---|
| Runtime guards | Lakera Guard (S1), NeMo Guardrails (S7), Llama Guard / Prompt Guard (S8), the open guard model inside AegisGuard | The model's inputs and outputs in production |
| Red-team / attack generators | PyRIT (S3), garak (S4), promptfoo (S5), Cisco AI Defense validation (S6), HiddenLayer automated red teaming (S2), Protect AI Recon (S9) | The model or the LLM application, by sending attacks |
| Model supply chain | HiddenLayer model scanner (S2), Protect AI Guardian (S9) | Model files and artefacts before deployment |

All three groups secure or test **the model**. None of the public pages we read describe how the **testing infrastructure itself** is protected:
who can see the attack pack, whether the red team can learn which defence layer refused (or how long it took), whether results can be
read before they are released, and whether the evidence can be rewritten afterwards.

## 2. Landing-page patterns worth copying (Wiz, Snyk, Vanta, Datadog style)

1. **Hero claim in one line** plus one primary CTA ("Launch live lab").
2. **Proof numbers** directly under the hero, each with a small label (we add MEASURED + date + n, which the big vendors usually do not).
3. **How it works in 3 steps** with one icon each.
4. **Architecture diagram** (one picture, not a wall of boxes).
5. **Comparison grid**: we use "documented / not documented" with sources, never "missing".
6. **Integrations strip** with partner names.
7. **Compliance mapping** (OWASP LLM Top 10, MITRE ATLAS, NIST AI RMF, EU AI Act): only what the code does.
8. **Who it is for**, **plans** (ours clearly marked illustrative), footer with repo and team.

## 3. Positioning statement

> For AI labs, red-team vendors, AI safety institutes and regulated enterprises that run adversarial tests on their models,
> **AegisLab is the secure range for AI red-teaming**: red, blue and the model run in sandboxes that cannot reach each other, a
> broker hides which layer refused and when, and every result is sealed, released only by a reviewer, and provable afterwards
> (Ed25519-signed hash chain, optionally anchored on Base). Unlike runtime guards and attack generators, which secure or test the
> **model**, AegisLab secures the **testing infrastructure** itself, exactly the gap in Track 04.

AegisLab is complementary: it can run any guard (we run AegisGuard) as the blue team and any generator (PyRIT, garak, promptfoo, or
TinyFish web agents) as the red team, inside the range.

## 4. Feature grid (public documentation only)

D = documented in the sources read; ND = not documented in the sources read. AegisLab column: implemented and tested in this repo.

| Capability | AegisLab | Lakera Guard (S1) | PyRIT (S3) | garak (S4) | promptfoo (S5) | Cisco AI Defense (S6) | HiddenLayer (S2) | NeMo Guardrails (S7) |
|---|---|---|---|---|---|---|---|---|
| Screens model input/output at runtime | Yes (AegisGuard) | D | ND | ND | ND | D | D | D |
| Generates or automates attacks | Yes (attack packs, TinyFish agents) | ND | D | D | D | D | D | ND |
| Red, blue and model in separate network-less sandboxes | Yes | ND | ND | ND | ND | ND | ND | ND |
| Broker hides which layer refused, fixed-deadline replies | Yes | ND | ND | ND | ND | ND | ND | ND |
| Results sealed until a reviewer releases them | Yes | ND | ND | ND | ND | ND | ND | ND |
| Ed25519-signed hash-chained evidence, offline verifier | Yes | ND | ND | ND | ND | ND | ND | ND |
| Public timestamped anchor of the evidence (Base) | Yes (optional) | ND | ND | ND | ND | ND | ND | ND |
| OWASP LLM Top 10 report mapping | Partial (manual mapping) | ND | ND | ND | D | D | ND | ND |

Reading of the grid: AegisLab does not replace a guard or an attack generator. It is the range they run inside.

## 5. Market (one sourced number)

AI trust, risk and security management (AI TRiSM) is a recognised category (Gartner Market Guide, Feb 2025, S11). One third-party
estimate: USD 7.44 billion by 2030 (Grand View Research press release, S10). Estimates vary widely by scope; we quote this one as
an estimate, not a fact about our segment.
