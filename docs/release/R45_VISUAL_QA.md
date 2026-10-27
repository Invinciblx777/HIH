# R4.5 visual QA: the phone viewport shift

Team Tech Mavericks · Hack in Hills '26 · Track 04 (Bayora) · 27 October 2026 (IST).
Branch `r45/final-freeze` from public `main` `c46df2b`. Fix commit `431b18c`.

## 1. The observation (open since R4)

The phone screenshot `m06_graph.png` written by the live browser test (390x844, mobile emulation) showed the Connections
page shifted left: the header's session controls at the right edge, the main column cut off on the left. R4 could not
reproduce it by direct navigation and recorded it as an open observation (it was present on `7434152` too).

## 2. Root cause (demonstrated with real Chromium and DOM measurements)

A diagnostic probe (Playwright 1.64.1, real console in degraded mode, operator session) measured, at each width and after
each step: `documentElement.scrollWidth`, `clientWidth`, `innerWidth`, `visualViewport.pageLeft`/`scale`, the header
row's own `scrollWidth`, and every element extending past the screen.

| Width (mobile emulation) | Session | Header row needed / available | Document width | `innerWidth` | `pageLeft` after the evidence sheet |
|---|---|---|---|---|---|
| 320 | read-only | 339 / 288 | 347 | 347 | 27 |
| 320 | operator | 512 / 288 | 520 | 520 | 200 |
| 360 | operator | 512 / 312 | 537 | 537 | 177 |
| 390 | read-only | 342 / 342 | 390 | 390 | 0 |
| 390 | operator | 512 / 342 | 536 | 536 | 146 |
| 768, 1024, 1440 | both | fits | = width | = width | 0 |

1. **Overflow.** The first header row (brand, *Operator session*, *End session*, *Live*, info icon) is a single
   `flex` line of `white-space: nowrap` items. During an operator session it needs about 512 px. On phones it ran 146 to
   200 px past the screen (27 px read-only at 320 and 360). It was already visible in `m01_overview.png` (*End session*
   cut, *Live* and the info icon off screen).
2. **Why the tests passed.** In a mobile context (`is_mobile=True`, meta viewport) Chromium widens the layout viewport
   to the content, so `window.innerWidth` grew with the overflow (536 at a 390 px screen). The shared `no_overflow` helper
   compared `scrollWidth` with `innerWidth` and could therefore never fail on a phone. `clientWidth` stayed 390.
3. **Why the page stayed shifted.** Opening the evidence sheet (a fixed panel 100vw wide, of the widened layout viewport,
   that moves focus to its close button) panned the visual viewport right by exactly the overflow (146 px at 390). Hash
   navigation keeps the visual viewport position, so the next pages (Connections in the test) were shown panned.

Ruled out: graph transforms (the graph's own pan/zoom is an SVG `transform` inside an `overflow: hidden` frame; probe
after zoom ×3, drag pan and zoom out: no change), modal scroll locking (no lock is used; the confirm dialog is a native
`<dialog>`), scrollbar width (overlay scrollbars; `clientWidth` = `innerWidth` on desktop), browser emulation artefact
(the overflow exists on a non-mobile 390 px context too: `scrollWidth` 536 > 390; mobile emulation only hides it and adds
the pan).

## 3. Fix (CSS only, `aegislab/web/console/console.css`, inside the existing `max-width: 699px` block)

Below 700 px the header row wraps into two lines: brand, status and info first; *Operator session* and *End session*
below. `.tools` becomes `display: contents`, a zero-height `::after` with `flex-basis: 100%` forces the break, and `order`
places the items. No markup, script, label, colour or font changed; nothing is clipped or hidden; no `overflow-x: hidden`
was added anywhere. 700 px and wider are unchanged.

## 4. Regression coverage

- `tests/browser/conftest.py::no_overflow` now compares `scrollWidth` with `clientWidth` and also requires
  `visualViewport.pageLeft == 0`. This strengthens every existing phone and desktop overflow check; none was relaxed.
- New `test_phone_header_fits_and_the_page_does_not_shift[320|360|390]` (container-free, mobile emulation): every header
  control inside the screen, no overflow and no sideways pan after the evidence sheet, Connections and Audit, main column
  not shifted.

| Run | Container-free browser module |
|---|---|
| Fixed tests on the **old** CSS (`c46df2b`) | 5 failed, 10 passed: the 3 new cases, plus `test_main_pages_have_no_horizontal_overflow[phone]` (`[536, 390, 0]`) and `test_evidence_actions_fit_a_phone_screen[320]` (`[347, 320, 27]`) now that the helper sees the overflow |
| Same tests on the **fixed** CSS (`431b18c`) | 15 passed |
| Full browser suite incl. live containers, fixed CSS | PASS 18, FAIL 0, SKIPPED 0, BLOCKED 0 |

## 5. Responsive sweep after the fix

Probe 1 (layout): widths 320, 340, 360, 375, 390, 414, 430, 600, 699, 700, 720, 744, 768, 800, 900, 1024, 1280, 1440;
mobile emulation and desktop up to 1024; read-only and operator session; Overview, Lab, Evidence sheet, Connections graph,
Audit, in that order. **340 measurements: 0 overflow, 0 sideways pan.**

Probe 2 (interactions): 360, 390, 768 (mobile) and 1024, 1440 (desktop), operator session: graph load, zoom in ×3, drag
pan, zoom out ×3, text view on/off (2 steps), evidence sheet, independent verification output, tamper output, sheet closed with
Escape, a 44-character run ID in the audit URL, history back, history forward, reload after scrolling, Lab.
**75 steps (15 per width): 0 failures, 0 page errors.**

Live suite (real containers) on the fix: the regenerated phone set (`docs/prototype/screenshots/r45/m01`–`m06`) shows the
two-line header and the Connections page unshifted after the evidence sheet. The r3 screenshot set stays as recorded.

## 6. R4 fixes re-checked

| R4 item | Still fixed? | How |
|---|---|---|
| R4-UI-1 graph caption over the drawing | yes | `test_graph_caption_does_not_cover_the_drawing` at 1280x720, 1366x768, 1440x900, 390x844 passes; final video stills show the caption below the drawing |
| R4-UI-2 lifecycle row touching the Run ID row | yes | gap assertion in `test_judge_flow_desktop` passes (live) |
| R4-UI-3 verify button off a phone screen | yes | `test_evidence_actions_fit_a_phone_screen[320|390]` passes with the stricter helper |

## 7. Not changed, by design

- On phones the graph opens zoomed in; pan and zoom are the intended navigation.
- The section tabs scroll horizontally inside their own row on narrow screens.
- The final video is recorded at 1280x720, above the 700 px breakpoint, so the R4.5 CSS does not alter any frame of it.
