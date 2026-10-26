# Reference design audit: The Story Archive

Phase R1-UI, 26 October 2026. Reference: https://thestoryarchive.net/ (and its static index at `/works/`).

## How the reference was inspected

- Rendered in a real browser, not a text extract: the Claude desktop browser pane (Chromium, 1024 px wide) for live
  inspection, and headless Chromium 156 (Playwright-core 1.56, `~/.cache/ms-playwright/chromium-1248`) for
  screenshots at 1440 × 900, 1024 × 768 and 390 × 844 (mobile emulation with touch).
- Values below come from `getComputedStyle`, `getBoundingClientRect` and the page's own CSS custom properties read
  from `document.styleSheets` at run time. Where a value is an estimate from a screenshot it says so.
- About 25 page loads in total, spread over the session. No crawling, no asset downloads from the reference.
- Nothing of the reference's code, logo, copy, icons or hand-drawn ring path was copied into AegisLab.

Screenshots (JPEG, quality 78) are in `docs/design/screenshots/reference/`:

| State | 1440 | 1024 | 390 |
|---|---|---|---|
| Cards (home) | `ref_desktop_1440_cards.jpg` | `ref_tablet_1024_cards.jpg` | `ref_mobile_390_cards.jpg` |
| Filters open | `ref_desktop_1440_filters.jpg` | `ref_tablet_1024_filters.jpg` | `ref_mobile_390_filters.jpg` |
| Work detail sheet | `ref_desktop_1440_detail.jpg` | `ref_tablet_1024_detail.jpg` | `ref_mobile_390_detail.jpg` |
| Connections, Clusters | `ref_desktop_1440_connections.jpg` | `ref_tablet_1024_connections.jpg` | `ref_mobile_390_connections.jpg` |
| Connections, Tree | `ref_desktop_1440_conn_tree.jpg` | | |
| Connections, Time | `ref_desktop_1440_conn_time.jpg` | | |
| Index page (`/works/`) | `ref_desktop_1440_index.jpg` | `ref_tablet_1024_index.jpg` | `ref_mobile_390_index.jpg` |

These are screenshots of a third-party site, kept only as design references for this phase. They are excluded from git
(`docs/design/screenshots/.gitignore`) because the repository is public; they exist only in the local working tree.

## 1. Typography

| Item | Measured |
|---|---|
| Family | `"DM Mono", ui-monospace, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace` for everything (`--font-sans` and `--font-mono` are both DM Mono) |
| Loaded faces | DM Mono 400, 400 italic, 500 (from `document.fonts`) |
| Base | 15 px / 22.5 px (1.5), weight 400, colour `#111111` |
| Site title (h1) | 24 px / 36 px, weight 400, letter-spacing −0.24 px (−0.01em) |
| Primary navigation tabs | 24 px (`--tab-fs`), line box 52 px (`--tab-h`), weight 400, −0.01em; items separated by a comma in `--ink2` drawn with `::after` |
| Search input | 24 px, 52 px high, no border, 34 px left padding for the icon, placeholder in full ink |
| Sub-view tabs (Clusters, Tree, Time) | 24 px, same treatment as the main tabs |
| Card title (h3) | 19 px / 1.2, weight 500, coloured with the card's category colour, clamped to 2 lines |
| Card meta line | 14 px / 21 px, *italic*, `--ink2` or category colour |
| Lineage line | 13 px, weight 500, with a 13 px icon |
| Tags and badges | 13 px / 1.5, padding 2 px 9 px, fully rounded |
| Filter chips | 12 px, 24 px high (`--ctl-h-sm`), padding 0 10 px |
| Controls | 13 px (`--ctl-fs`), 30 px high (`--ctl-h`), padding 0 12 px; large: 15 px / 40 px |
| Sheet title (h2) | 24 px / 28.8 px, letter-spacing +0.2 px |
| Sheet body | 14 px / 22.4 px (1.6) |
| Section labels in sheets | 11 px / 16.5 px, weight 600 (synthesised from 500), uppercase, letter-spacing 0.6 px |
| Graph footnote | 13 px italic, `--ink2` |
| Graph labels | about 11–12 px DM Mono (estimate from screenshots; drawn on canvas) |
| Below 1024 px | form fields go to 16 px (`--field-fs`) to avoid iOS zoom |
| Below 360 px | tab font size drops to 16 px |
| Numbers | DM Mono is monospaced, so numbers are tabular by construction; counts are set in the same size as their label |
| Casing | sentence case everywhere except the 11 px section labels |

The reference credits DM Mono (Colophon Foundry, SIL Open Font License 1.1). AegisLab uses the same family from the
`@fontsource/dm-mono` 5.2.6 package (Google Fonts build, OFL 1.1), self-hosted because the console's Content
Security Policy is `font-src 'self'`.

## 2. Colour

All values are the page's own custom properties, confirmed against computed styles.

| Token | Value | Use |
|---|---|---|
| `--bg` / `--canvas` | `#f5f5f5` | page background, sheet background |
| `--panel` | `#ffffff` | cards |
| `--panel2` | `#e8e8e8` | neutral badge background |
| `--ink` | `#111111` | text, 2 px rules, outlines, active fills |
| `--ink2` | `#595959` | secondary text, comma separators (6.4:1 on `#f5f5f5`, 7.0:1 on white) |
| `--line` | `#d4d4d4` | light dividers |
| `--accent` | `#111111` | the accent is ink; no brand hue |
| `--accent-soft` / `--g-band` | `#ebebeb` | soft fills, graph bands |
| `--accent-hover` | `#3a3a3a` | hover on filled ink controls |
| `--g-faint` | `#c4c4c4` | unconnected nodes and edges in the graph, grey dots in Time |
| `--kchip-off-line` / `--kchip-off-fg` | `#d9d9d9` / `#8a8a8a` | inactive kind chips |
| `--danger` | `#9b2c2c` | destructive actions |
| `--pop-shadow` | `0 8px 24px rgba(0,0,0,.14), 0 1px 3px rgba(0,0,0,.1)` | the only shadow (pop-overs) |
| Connection kinds | adaptation `#b3263e`, influence `#2f6fb3`, sequel `#8c6210`, parallel `#5d44a8`, resemblance `#2f7a4a` | kind chips and edges |
| Collection palette | crimson `#b3263e`, rust `#b4532a`, ochre `#9a6b12`, moss `#4f7a2e`, teal `#1f7a7a`, cobalt `#2f6fb3`, violet `#5d44a8`, plum `#8a3f7a` | user colours |
| Category (card) colours | e.g. poem `rgb(57,124,79)`; tag families `--t-theme #8a5a2b`, `--t-arch #2f6b6b`, `--t-struct #5b4a8a` … | card bar, outline, title, badge |
| Graph edges | grey `#c4c4c4` at rest; the selected work's edges take the kind colour | |
| Scrim | `rgba(0,0,0,0)`: the detail sheet does not darken the page | |
| Focus | `outline: 2px solid var(--accent)` (ink); custom selects underline on focus with a 7 px offset | |

There is no dark theme in the reference (no `prefers-color-scheme` rule). The palette is restrained: ink on light
grey, with mid-saturation earth and jewel tones used only to carry category meaning.

## 3. Layout and spacing

| Item | Measured |
|---|---|
| Gutter | 32 px (`--gutter`); header padding `35px 32px 0` |
| Content width | full width minus gutters (no max-width on the cards page; 1376 px at 1440) |
| Header rows | title row (36 px text, icons 30 px, `--ico-lg`); tab row with a 2 px ink rule above, 3 px band padding (`--hband`), 52 px tabs; search row ruled 2 px above and below |
| Header height | about 212 px at 1024 (title 43–79, tabs 90–150, search 150–212) |
| Main | padding `48px 32px 32px` |
| Card grid | 4 columns at 1440 (card 326 px), 2 at 1024 (462 px), 1 at 390; gap about 17 px; card height 228 px (`--card-h`) |
| Card | radius 12 px (`--radius`), padding `18px 18px 18px 26px`, 8 px colour bar on the left (`::before`), 2 px inset outline in the category colour, title row ruled 2 px below in the same colour |
| Rule weight | 2 px (`--rule`) for every structural line |
| Control radius | 6 px (`--ctl-r`); pills 999 px; tags 5 px in places (`--tag-r`) |
| Filter panel | opens under the search row; "Match All / Any" row ruled 2 px below; facet columns separated by 2 px vertical rules; facet title 15 px with the count right-aligned |
| Detail sheet | slides in from the right over the page; about 570 px wide at 1440 and 480 px at 1024, full width on mobile; 2 px ink rule on its left edge; header row ruled 2 px below; 24 px side padding |
| Sheet sub-blocks | connection rows boxed with a 2 px ink border and 8 px radius; primary action is a full-width ink pill, 40 px |
| Graph frame | 2 px ink border, radius 12 px, fills the remaining viewport; zoom − / + as a joined outlined pill, reset as a circular button, both top right |
| Breakpoints | 1279/1280, 1023/1024, 899/900, 699/700, 599/600, 359/360 px, `max-height: 500px`, print, `forced-colors: active` |
| Scroll | the page scrolls; header rows are not sticky; the sheet scrolls on its own |

## 4. Interaction

- **Navigation:** text tabs with commas. The active tab gets a hand-drawn graphite oval drawn in with a stroke-dash
  animation (0.38 s; a second fainter stroke 0.04 s later). Disabled under `prefers-reduced-motion`.
- **Search:** one large field in the header; results filter as you type. An animated placeholder types example titles.
- **Filters:** a "Filters ⌄" toggle opens a facet panel with chip groups and live counts; chips toggle on (filled in
  the facet colour, white text) and off (1 px ink outline); "Show all N" chips are dashed and italic; "Clear filters ×"
  is an outlined pill. Match All / Any is a radio pair.
- **Sorting:** a sort icon opens a custom list-box (2 px ink border, 12 px radius).
- **Selection / detail:** clicking a card opens the right-hand sheet and writes the selection to the URL hash
  (`#work=The+Epic+of+Gilgamesh`), so refresh and back restore it. Close is an × in the sheet header.
- **Cards:** hover lifts 6 px (`transform .24s cubic-bezier(.4,0,.2,1)`); cards enter with a staggered fade and
  14 px rise.
- **Connections:** three perspectives on one data set: **Clusters** (force layout of connected works, labels in
  place), **Tree** (choose one work, see its roots and fruits; empty state with suggestions), **Time** (one dot per
  work on a year axis, ink = has connections, grey = none). Kind chips (All, Adaptations 251, Influence 795, …)
  filter edges and show counts; "Connections: 1,454" total at the right; a one-line explanation under the
  perspective tabs; zoom − / + / reset; a footnote states coverage ("1,507 of 3,567 works have a recorded link").
- **Motion vocabulary:** one easing (`--lift: cubic-bezier(.4,0,.2,1)`), 0.12–0.3 s durations, opacity and
  transform only; reduced-motion rules turn the entrance and ring animations off.
- **Mobile:** the tab row scrolls horizontally behind a library icon; the search row keeps the icon and sort
  button; a round floating filter button appears bottom right; the sheet becomes full-screen.

## 5. Uncertainties and limits of this audit

- The graph is drawn on `<canvas>`, so edge widths, node radii and label sizes are estimates from screenshots.
- Keyboard behaviour inside the canvas graph was not exercised; the reference's tabs and cards are native buttons and
  links, so they are reachable by Tab.
- The "Index" tab links to a separate static page (`/works/`) whose style differs (bold 48 px heading, white header
  bar); it was treated as a secondary page, not as the main language.
- Account features ("My Collections", save) were not inspected; they need sign-in.
- The tablet-width (768 px) state was not captured for the reference; 1024 and 390 were.
- Exact hover colours were read from CSS, not from captured hover screenshots.
