# R4 submission checklist

Team Tech Mavericks · Hack in Hills '26 · Track 04 (Bayora). Prepared 26 October 2026 (IST) in Phase R4. Claude prepared
this list; it submitted nothing, posted nothing and filled no form. **Status: NOT SUBMITTED.** Only a genuine organizer
confirmation may change that.

## Deadline and channel

| Item | Value | Status |
|---|---|---|
| Deadline | 28 October 2026, India Standard Time (team statement for Phase R4). The Unstop listing read on 26 Oct showed 28 Oct 2026, 11:59 PM IST for the "Prototype Development, Social Pitch & Outreach" stage | HUMAN_CONFIRMATION_REQUIRED: the exact time comes from the organizer's own instructions |
| Channel | **Not Unstop** (team statement). The organizer's separate submission instructions were not available to Claude: no organizer message, form or rules file exists in the project workspace. The Unstop page read on 26 Oct named a Google Form shared in the official Hack in Hills '26 WhatsApp group | HUMAN_CONFIRMATION_REQUIRED: open the organizer's instructions and follow them, not this file |
| Required items | Per the Unstop page read on 26 Oct: GitHub link, demo video link, LinkedIn post link, Instagram Reel link (posts tagging Eren, Builder Base, Nexido, Web3 India). Video length, file naming and format were not stated anywhere Claude could read | HUMAN_CONFIRMATION_REQUIRED against the organizer instructions |

Do not confuse the optional TinyFish Builder Challenge form with the Round 2 form.

## Ready for the team (engineering done)

| # | Item | Value | Verified by Claude | Human action |
|---|---|---|---|---|
| 1 | Public repository | https://github.com/Invinciblx777/HIH, public, MIT, default branch `main` | anonymous GitHub API and page HTTP 200 on 26 Oct (R4) | open logged out; record in `docs/round2/SUBMISSION_LINKS.md` (workspace) |
| 2 | Verified prototype revision | `main` = `743415223e916d31c43c48f648d31524c8ba1d88` (merge of PR #5) | clean clone: all container-free and Podman gates pass, live browser walkthrough, strict verify, tamper rejection (`PHASE_R4_FINAL_REPORT.md`) | none, unless the R4 branch is merged (then re-check the new SHA) |
| 3 | Hosted CI on that revision | run 40370478665, success | yes (`gh run view`) | none |
| 4 | Recommended demo video | workspace `round2/final_prototype/video/AegisLab_R4_Interactive_Prototype.mp4` (138.4 s, 1080p, captions burned in, `.srt` beside it) | decodes fully, audio OK, captions cover all speech, 0 secret hits in the recording check | **watch and listen first** (`round2/final_prototype/DEMO_CHECKLIST.md` part A), then upload; test the link logged out |
| 5 | Fallback video | workspace `round2/submission_ready/video/AegisLab_Judge_Cut.mp4` (R0.6, 89.2 s, terminal recording from an older build) | unchanged, `SHA256SUMS` OK | use only if item 4 fails sign-off |
| 6 | Quickstart | `git clone https://github.com/Invinciblx777/HIH && cd HIH/aegislab && bash scripts/start_prototype.sh` | yes, from a clean clone | none |
| 7 | Judge walkthrough | `docs/release/R4_JUDGE_DEMO_GUIDE.md` (this branch); on `main`: `docs/prototype/JUDGE_INTERACTIVE_WALKTHROUGH.md` | from a real run | rehearse once |
| 8 | Technical description | below | — | adapt to the form's length limit |
| 9 | Integrity summary | `docs/release/R4_RELEASE_INTEGRITY.md` | yes | none |
| 10 | Known limitations | `docs/release/R4_JUDGE_DEMO_GUIDE.md`, experience 6; `aegislab/THREAT_MODEL.md` | — | say them in the video description too |
| 11 | LinkedIn post, Instagram Reel | drafts in workspace `round2/submission_ready/text/`; Reel `round2/submission_ready/reel/` | not posted by Claude | verify tag handles, post, record URLs |

## Technical project description (draft, 120 words)

AegisLab is an isolation and evidence layer for adversarial AI evaluation. A red-team attack agent, a blue-team defence and
the model under test each run in their own rootless Podman container with no network. A trusted broker is the only path
between them: it enforces policy, seals results until an authorised reviewer releases them, and records every decision in
a hash-chained audit log signed with Ed25519. Anyone can check an exported bundle with an independent verifier; a single
edited event is rejected. The interactive console runs the whole lifecycle live with a deterministic stub model and shows
saved Qwen2.5-0.5B experiments, labelled as precomputed. Limits: the broker and its key are trusted, one local operator,
shared host kernel, side channels and GPU caches untested.

## Order of human actions

1. Read the organizer's submission instructions; confirm deadline, channel, required links and video rules.
2. Watch and listen to the R4 video; sign `round2/final_prototype/DEMO_CHECKLIST.md` part A, or choose the fallback.
3. Upload the chosen video; open the link in a private window.
4. Decide whether to merge the R4 branch (CSS fixes, tests, docs) before submitting. If merged, re-run the checks in
   `PHASE_R4_FINAL_REPORT.md` section 9 on the new `main` SHA. Submitting `7434152` is also valid: it is what the video shows.
5. Post the LinkedIn post and the Reel if the instructions require them; verify the tag handles first.
6. Submit through the organizer's channel; save the confirmation privately; record date, time (IST) and who submitted in
   `docs/round2/SUBMISSION_LINKS.md`.
