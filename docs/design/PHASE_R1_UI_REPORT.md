# Phase R1-UI report: interface redesign

AegisLab, team Tech Mavericks, Hack in Hills '26, Track 04. 26 October 2026.

Scope: a complete redesign of the local prototype console (`aegislab/web/console/`) in a visual language adapted
from https://thestoryarchive.net/. UI only. The control plane, broker, evidence, experiments and tests are unchanged.

## 1. Reference analysis

Full audit: `docs/design/REFERENCE_DESIGN_AUDIT.md`. Values were read from computed styles and the page's own CSS
custom properties in a rendered browser (about 25 page loads, no crawling, no asset downloads). Summary:

- One typeface for everything (DM Mono 400, 400 italic, 500), 15 px body, 24 px tabs and search.
- Ink `#111` on `#f5f5f5`, 2 px ink rules, earth and jewel tones only for categories.
- Text tabs separated by commas, active tab marked by a hand-drawn graphite ring that draws itself in.
- One large search field, a Filters panel of facet chips with counts and Match All / Any.
- White cards with an 8 px colour bar, 2 px inset outline, 19 px coloured titles, italic meta lines, tag pills.
- A detail sheet from the right with a 2 px rule; the selection is in the URL.
- A Connections view with three perspectives (Clusters, Tree, Time), kind chips with counts, zoom controls and a
  footnote stating coverage.

Reference screenshots: `docs/design/screenshots/reference/` (17 files, 1440, 1024 and 390 px).

## 2. Original UI (R1, commit ea2f8ea)

A dark dashboard: left sidebar navigation, system-font text, blue accents, panels on a near-black background. Seven
routes (`#/overview`, `#/topology`, `#/lab`, `#/events`, `#/evidence`, `#/experiments`, `#/limits`). Functionally
complete, but dense and generic; no search or filters, URL state only for the selected lab scenario, a static topology diagram.
Screenshots: `docs/design/screenshots/before/` (9 files).

## 3. Design system

Documented in `docs/design/AEGISLAB_DESIGN_SYSTEM.md`. Key points:

- Tokens on `:root` for surfaces, palette, security states (`--s-pass/deny/allow/warn/fail/none`), evidence labels
  (`--l-live/rec/pre/stub`), graph edges (`--e-allow/deny/audit/trust`), type scale, spacing, shape and motion.
- DM Mono self-hosted (SIL OFL 1.1, licence file shipped and linked in the footer); Lucide icons (ISC) inlined.
- Components: header and tabs, ring, search band and facet panel, cards, sheet, ledger, lifecycle, labels, status
  text, stamps, verdicts, tables, graph, toasts, confirm dialog, empty, loading and error states.
- Own hand-drawn ring generator (seeded ellipse, Catmull-Rom to cubic Bézier); the reference's path is not used.
- Ochre darkened to `#8c6210` so every text colour reaches 4.5:1.

## 4. Screens

Routes are now `#/overview`, `#/lab`, `#/connections`, `#/audit`, `#/evidence`, `#/experiments`,
`#/threat-model`. The old routes (`topology`, `events`, `limits`, `lab?s=`) redirect.

| Screen | What it does | Data source |
|---|---|---|
| Overview | Statement of the isolation problem, runtime status ledger, latest run lifecycle, evidence integrity, five demonstration cards coloured by the journal, recent denials, labels, limitations | `/api/lab/status`, `/api/runs`, `/api/lab/timeline`, `/api/lab/journal` |
| Security Lab | Search, facets (type, boundary, actor, outcome); evaluation run box; 10 scenario cards (6 live, 3 precomputed real-model, 1 stub); sheet with what is tested, attacker objective, trust boundary, expected and actual result, action, step-by-step result, evidence reference, limitations; manual request probe; recorded execution when not live | `/api/lab/scenarios`, `/api/lab/runs`, `/api/lab/scenarios/{id}/run`, `/api/lab/experiments` |
| Connections | Topology (12 components, 18 paths), Hierarchy (6 actors, 10 operations, 8 resources, 30 relations from `aegis/api.py`), Timeline (real events of one run); kind chips with counts; side panel; text view | static description of the code; `/api/lab/status` hardening flags; `/api/lab/timeline?run_id=` |
| Audit Archive | Search, facets (run, actor, event type, decision, signature), sort, live update every 2 s, event sheet with the redacted monitoring record | `/api/lab/timeline` |
| Evidence Verification | Bundle cards (genuine, tampered, legacy, lab), sheet with the independent verifier result per check, disposable-copy tamper test, in-memory tamper suite, download | `/api/lab/bundles`, `/verify`, `/tamper`, `/api/runs/{id}/tamper-test` |
| Experiments | Label legend, real-model E1–E5 cards with recomputation (48/48), timing dot strips with chance line (29/29), system tests, detector limits | `/api/lab/experiments` |
| Threat Model | Tested vs not proven, trusted components, attack assumptions, tested attack classes with links, unverified environments, deployment constraints | restated from `THREAT_MODEL.md` and the phase reports |

Every result carries one of the four labels. A scenario never run in this session says "Not run in this session";
the console never shows a fabricated live number.

## 5. Visual comparison

Side-by-side images (reference, before, after): `docs/design/screenshots/compare/`

- `compare_cards_1440.jpg`: card grid and header
- `compare_detail_1440.jpg`: detail sheet
- `compare_connections_1440.jpg`: graph view
- `compare_mobile_390.jpg`: mobile graph view

After screenshots: `docs/design/screenshots/after/` (31 files): all seven views and the three graph perspectives
at 1440; Overview, Lab, Connections, Evidence at 1024 and 768; Overview, Lab, Connections, Audit at 390 and 360;
the Lab sheet at 1440, 390 and 360; filters open; a verified bundle; an audit event sheet.

Deliberate differences from the reference: no card bookmark icons or lineage links (not meaningful here); the
graph is an explicit SVG layout, not a force simulation, because trust boundaries must sit in fixed zones; the
status pill and evidence labels are AegisLab additions.

## 6. Responsive behaviour

Checked with headless Chromium at 1440 × 900, 1024 × 900, 768 × 900, 390 × 844 and 360 × 844 (mobile emulation
with touch below 600).

- Page-level horizontal overflow measured at 390 and 360 on all seven routes: 0 px.
- Cards: 4 → 3 → 2 → 1 columns; the Overview demonstrations use 5 → 3 → 2 → 1.
- The tab row scrolls horizontally and keeps the active tab in view; the brand subtitle and long status text hide.
- The graph side panel moves below the graph under 1100 px; on narrow frames the graph opens zoomed on the
  selected node; tables scroll inside their own wrapper.
- The sheet is full width under 700 px.

## 7. Accessibility

- Keyboard: every control is a native button, link, input or select. The graph has a roving tab stop, arrow-key
  movement between nodes, Enter/Space selection and `+` `-` `0` zoom. Verified in Playwright: from the broker,
  ArrowRight then Enter selected the sealed store and wrote `?node=sealed` to the URL.
- Sheet: dialog semantics, background `inert`, focus moves to Close, Esc closes, focus returns to the card
  (verified: focus back on `prohibited-access`).
- Release requires a native modal confirmation.
- Text view gives a table alternative to every graph perspective (32 rows for the Topology view).
- Contrast: all text colours ≥ 4.5:1 on both surfaces (table in the design system document). Status is never colour
  alone.
- `prefers-reduced-motion` turns off every animation and transition; `forced-colors` keeps outlines and rings.
- Not done: no screen-reader session (NVDA/VoiceOver) and no automated axe audit; see section 10.

## 8. Regression results

| Check | Result |
|---|---|
| `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q` | **386 passed**, 2 warnings (Starlette deprecation), 67 s |
| `sha256sum -c MANIFEST.sha256` (442 files, evidence and pinned code) | all OK |
| Browser console errors across all screenshot and interaction runs | none |
| Live flows in the browser | lab sheet open/close, facet filter (10 → 6 cards), deep link `#/evidence?open=VAL-001`, verifier run (accepted as expected), audit event sheet survives reload, graph keyboard selection, text view |

No backend file changed. `aegis/console.py`, `aegis/api.py` and every pinned or manifest-listed file are
untouched. The R1 console tests (`tests/test_r1_console.py`, 41 tests) pass unchanged.

Security properties kept:

- Authentication: role actions still go through the control plane with the role's token; observers send none.
- Tokens: held in memory only, sent only in `X-Aegis-Token`, never logged, stored or put into a URL.
- Protected data: the UI shows only what the control plane returns for the calling role; graph and detail views
  describe permissions and do not fetch restricted data.
- Errors show the server's `detail` text only.
- No command execution: the browser can choose only fixed server-side scenario, bundle and tamper-mode IDs.
- Evidence is immutable: tamper tests use disposable copies; originals are hashed before and after.

## 9. Changed files

| File | Change |
|---|---|
| `aegislab/web/console/index.html` | rewritten page shell |
| `aegislab/web/console/console.css` | rewritten design system |
| `aegislab/web/console/console.js` | rewritten router, components, seven views, graph engine |
| `aegislab/web/console/fonts/` | new: DM Mono 400, 400 italic, 500 (Latin, woff2, 45 KB) and `OFL.txt` |
| `docs/design/REFERENCE_DESIGN_AUDIT.md` | new |
| `docs/design/AEGISLAB_DESIGN_SYSTEM.md` | new |
| `docs/design/PHASE_R1_UI_REPORT.md` | new (this file) |
| `docs/design/screenshots/before/`, `after/` | new, 9 and 31 JPEGs (1.1 MB and 3.3 MB) |
| `docs/design/screenshots/reference/`, `compare/` | kept locally, not committed (see section 10) |

## 10. Known issues

1. **Third-party screenshots.** The reference captures and the comparison images that contain them are screenshots
   of another site. They are kept in the working tree but excluded from git (`docs/design/screenshots/.gitignore`)
   because the repository is public. Committing them is the team's decision.
2. No screen-reader or axe audit has been run.
3. Scenario titles come from the server and are clamped to two lines on cards; the full title is in the sheet.
4. The Topology and Hierarchy graphs are static descriptions of the code at this commit; if `aegis/api.py` changes,
   `TOPO` and `HIER` in `console.js` must be updated by hand. The Lab runs the same rules live.
5. The graph uses fixed coordinates; at 360 px it opens zoomed on the selected node, and the full picture needs
   zoom out or the text view.
6. Dark mode is not provided (the reference has none either).

## 11. Branch and commit

- Branch: `design/story-archive-ui`, from `7b75297` on `r1/functional-prototype`.
- Commit: the single commit that adds this report (see `git log -1 design/story-archive-ui`).
- Not pushed, not merged, not deployed. Phase R2 not started.
