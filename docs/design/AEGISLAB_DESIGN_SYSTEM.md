# AegisLab design system

Phase R1-UI, 26 October 2026. Implemented in `aegislab/web/console/console.css` (tokens and components),
`console.js` (component markup and behaviour) and `index.html` (page shell). The visual language is an adaptation of
the measurements in `REFERENCE_DESIGN_AUDIT.md`. No code, logo, copy, icon or drawing from the reference is used.

## 1. Principles

1. **An archive, not a dashboard.** Ink on light grey, 2 px rules, one typeface. Colour only carries meaning.
2. **Every colour is a security state or an evidence label.** No decorative hue.
3. **Every number comes from the API.** Descriptive text (scenario catalogue, trust graph, threat model) restates
   the repository's code and documents and names its source.
4. **The label says how a result was produced:** LIVE SYSTEM TEST, RECORDED EXECUTION, PRECOMPUTED REAL-MODEL,
   STUB MODEL.
5. **Motion is quiet** and is turned off under `prefers-reduced-motion`.

## 2. Typography

DM Mono (Colophon Foundry, SIL OFL 1.1), self-hosted from `@fontsource/dm-mono` 5.2.6:
`web/console/fonts/dm-mono-latin-{400-normal,400-italic,500-normal}.woff2`, with the licence in
`web/console/fonts/OFL.txt` and a link in the page footer. Only the Latin subset ships (about 45 KB in total).

| Token | Value | Use |
|---|---|---|
| `--font` | `"DM Mono", ui-monospace, …, monospace` | everything |
| `--fs-tab` / `--lh-tab` | 24 / 36 px (21 below 1280, 18 below 700) | primary tabs, perspective tabs |
| `--fs-field` | 24 px (16 below 1024) | header search |
| `--fs-title` | 19 px, weight 500 | card titles |
| `--fs-body` | 15 px / 1.5 | body |
| `--fs-read` | 14 px / 1.6 | sheet body, ledgers |
| `--fs-tag` | 13 px | tags, labels, table cells |
| `--fs-ctl` / `--fs-ctl-sm` | 13 / 12 px | buttons, chips |
| `--fs-label` | 11 px, weight 600, uppercase, +0.6 px | section labels (`.lbl`) |

Meta lines are italic. Sentence case everywhere except `.lbl` labels and the four evidence labels.

## 3. Colour

Surfaces and ink: `--bg #f5f5f5`, `--panel #fff`, `--panel2 #e8e8e8`, `--soft #ebebeb`, `--ink #111`,
`--ink2 #595959`, `--line #d4d4d4`, `--faint #c4c4c4`.

Palette and contrast (WCAG 2.x ratio on `--bg` / on white). All text colours pass AA (4.5:1).

| Token | Value | On bg | On white | Semantic use |
|---|---|---|---|---|
| `--crimson` | `#b3263e` | 5.90 | 6.43 | `--s-deny` refused by policy; `--e-deny` prohibited path |
| `--cobalt` | `#2f6fb3` | 4.76 | 5.19 | `--s-allow` permitted; `--e-allow` authorised path |
| `--moss` | `#2f7a4a` | 4.81 | 5.25 | `--s-pass` verified, PASS, accepted |
| `--ochre` | `#8c6210` | 4.98 | 5.43 | `--s-warn` limitation; `--e-audit` audited path; `--l-rec` |
| `--danger` | `#9b2c2c` | 6.90 | 7.53 | `--s-fail` FAIL, ERROR, rejected unexpectedly |
| `--teal` | `#1f7a7a` | 4.67 | 5.09 | `--l-live` LIVE SYSTEM TEST |
| `--violet` | `#5d44a8` | 6.74 | 7.35 | `--l-pre` PRECOMPUTED REAL-MODEL; `--e-trust` trusted dependency |
| `--rust` | `#b4532a` | 4.57 | 4.99 | `--l-stub` STUB MODEL |
| `--ink2` | `#595959` | 6.42 | 7.00 | secondary text, `--s-none` not run |
| `--ink3` | `#8a8a8a` | 3.17 | 3.45 | inactive chip text only, never sole carrier of meaning |

The reference's ochre `#9a6b12` measures about 4.3:1 on `#f5f5f5`, so AegisLab darkens it to `#8c6210`.

A denial is a correct security decision, so `--s-deny` (crimson) is distinct from `--s-fail` (dark red, a broken
expectation). Status text always carries a word ("denied", "PASS", "Not run in this session") as well as a colour.

## 4. Space and shape

| Token | Value |
|---|---|
| `--gutter` | 32 px (24 below 700) |
| `--rule` | 2 px, every structural line |
| `--tab-h` | 52 px (46 below 700) |
| `--ctl-h` / `-sm` / `-lg` | 30 / 24 / 40 px |
| `--ctl-r`, `--pill`, `--radius` | 6 px, 999 px, 12 px |
| `--ico` / `-sm` / `-lg` | 21 / 16 / 30 px |
| `--sheet-w` | `clamp(420px, 40vw, 580px)`; 480 px below 1024; 100 vw below 700 |
| `--lift` | `cubic-bezier(.4, 0, .2, 1)` |

## 5. Components

| Component | Classes | Notes |
|---|---|---|
| Header | `.site-head .hrow1 .brand .tools .sys .iconbtn` | status pill: `live`, `degraded`, `offline`; long text hides below 1024 |
| Tabs | `.subnav a > span`, `.ringed`, `svg.ring` | commas between items; active item `aria-current="page"` with a hand-drawn ring |
| Hand-drawn ring | `ring(el)` in JS | own generator: seeded ellipse, 1.07 turns, wobble, Catmull-Rom to cubic, two strokes; `.ring.still` on redraw |
| Search band | `.band .search .bandbtn .count` | one large field; Filters and Sort show only when the page supports them |
| Facet panel | `.fpanel .frow .facets .facet .chips .chip` | Match All / Any; chips are `aria-pressed` toggles with live counts; Clear filters |
| Card | `.card .top .badge .meta .mark .body .tagline .tag` | 8 px colour bar, 2 px inset outline, title ruled below; colour class `c-live c-pre c-stub c-rec c-pass c-deny c-warn c-fail c-grey` |
| Detail sheet | `.scrim .sheet .sheet-head .sheet-meta .sheet-body .xbtn` | from the right, 2 px left rule, transparent scrim; URL `?open=key` |
| Ledger | `ul.ledger li .k .v` | two-column key/value list |
| Lifecycle | `ol.life` | CREATED → RELEASED, current state ringed, FAILED shown separately |
| Labels | `.label.live/.rec/.pre/.stub` | outlined, uppercase, 11 px |
| Status text | `.st.pass/.deny/.allow/.warn/.fail/.none` | word plus colour |
| Stamps | `.stamp.denied/.allowed/.error/.attempted` | per request in scenario results |
| Verdict | `.verdict.pass/.fail/.error` | PASS / FAIL / ERROR, ERROR is never a security result |
| Tables | `.table-wrap table`, `tr.click`, `tr.sel` | horizontal scroll inside the wrapper, never the page |
| Graph | `.persp .kinds .gwrap .gframe svg.g .gtools .zoom .roundbtn .gside .gtext .gfoot` | see section 6 |
| Feedback | `.toast`, `dialog.confirm`, `.loading`, `.empty`, `.errorbox`, `.note` | |

Icons: Lucide (ISC licence), inlined as SVG paths in `console.js` (`ICONS`), stroke `currentColor`, width 2.

## 6. Graph view

- Three perspectives on real data: **Topology** (12 components, 18 paths), **Hierarchy** (actors → operations →
  resources from the role checks in `aegis/api.py`), **Timeline** (events of one run from `/api/lab/timeline`).
- Edge kinds and chips: Authorised (cobalt, solid arrow), Prohibited (crimson, dashed, × mark, no arrow), Audited
  (ochre), Trusted dependency (violet, dotted). Hierarchy adds After release (ochre) and Acts on (grey).
- Selecting a node highlights its edges and neighbours and fades the rest; the side panel lists role, trust
  assumption, permitted, denied, controls, live hardening flags (Topology), connections and supporting evidence.
- Zoom 0.5×–5× with buttons, `+` `-` `0`, Ctrl/Cmd + wheel and pinch; drag pans after 5 px of movement.
- Keyboard: Tab into the graph, arrow keys move to the nearest node in that direction, Enter or Space selects.
- Text view: tables of nodes and paths (or events) with the same selection.
- Footnote states the single-host limit: no separate machines, no hardware isolation.

## 7. Motion

| Motion | Duration | Reduced motion |
|---|---|---|
| Ring draw-in | 0.38 s, second stroke +0.04 s | drawn complete |
| Card entrance | fade + 14 px rise, 35 ms stagger (max 12) | none |
| Card hover lift | −6 px, 0.24 s | none |
| Sheet slide | 0.2 s | instant |
| Page fade | 0.2 s | none |
| Loading dots | 1 s pulse | static |
| Toast | 0.18 s fade, 16 px rise | instant |

## 8. Responsive

Breakpoints: 1279 (3 card columns, smaller tabs), 1099 (graph panel under the graph), 1023 (2 columns, 16 px
fields, compact status), 899 (single-column sections), 699 (1 column, 24 px gutter, full-width sheet, icon-only band
buttons), 359 (smaller tabs), `max-height: 500px` (landscape phones). The tab row scrolls horizontally on narrow
screens and keeps the active tab in view. No page-level horizontal scroll at 360–1440 px (measured).

## 9. Accessibility

- Skip link, `main` focus on route change, `aria-current` on tabs and perspectives.
- Sheet: `role="dialog"`, `aria-modal`, background `inert`, Esc and scrim close, focus returns to the opener.
- Confirm dialog: native `<dialog>` with `showModal()` for the irreversible release.
- Live regions: status pill, toasts, scenario and verification output, audit counter.
- Chips are `aria-pressed` buttons; filter panel `aria-expanded`/`aria-controls`.
- `forced-colors: active` rules keep rings, outlines and state borders visible.

## 10. Security rules for UI code

- The browser never sends commands, paths, container options or network targets; actions are fixed server lists.
- Demo tokens stay in memory (`S.tokens`), go only in the `X-Aegis-Token` header, are never logged, stored or put
  in a URL.
- Role-restricted data is only shown when the control plane returns it for that role; the UI does not infer or
  cache protected values. Error messages show the server's `detail` text only.
- All dynamic text is escaped (`esc()`); no `eval`, no inline event handlers (CSP `script-src 'self'`).
