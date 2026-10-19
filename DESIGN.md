---
name: BrandWatch
description: A night watch floor for brand impersonation — dark, instrument-grade, and every number opens to its arithmetic.
colors:
  operations-black: "#080B14"
  panel: "#0E1420"
  panel-raised: "#121A2B"
  field: "#0b1220"
  console-black: "#060910"
  border: "#1E2A3D"
  instrument-cyan: "#35C7F2"
  readout-cyan: "#5FE3FF"
  critical: "#FF4D4D"
  high: "#FF9F1C"
  medium: "#F5C518"
  low: "#2ECC71"
  text: "#E6EDF5"
  text-secondary: "#C3CDD9"
  muted: "#8A97A8"
  dim: "#7C8A9E"
  on-lit: "#06121D"
  op-5: "#B388FF"
  op-6: "#FF6FA8"
  op-7: "#4DD0C4"
  op-8: "#9AA5B1"
  daylight-paper: "#ffffff"
  daylight-ground: "#e9eef3"
  daylight-soft: "#f4f7fa"
  daylight-line: "#dfe5ec"
  daylight-ink: "#16202e"
  daylight-muted: "#5d6b7e"
  daylight-accent: "#0b6fbd"
typography:
  display:
    fontFamily: "Rajdhani, JetBrains Mono, ui-monospace, Consolas, monospace"
    fontSize: "26px"
    fontWeight: 700
    lineHeight: 1.2
    letterSpacing: "0.04em"
  readout:
    fontFamily: "Rajdhani, JetBrains Mono, ui-monospace, Consolas, monospace"
    fontSize: "34px"
    fontWeight: 700
    lineHeight: 1
    letterSpacing: "0.02em"
  headline:
    fontFamily: "Rajdhani, JetBrains Mono, ui-monospace, Consolas, monospace"
    fontSize: "clamp(26px, 3vw, 38px)"
    fontWeight: 700
    lineHeight: 1.08
    letterSpacing: "0.01em"
  title:
    fontFamily: "JetBrains Mono, ui-monospace, Consolas, monospace"
    fontSize: "12px"
    fontWeight: 600
    lineHeight: 1.5
    letterSpacing: "0.12em"
  body:
    fontFamily: "Inter, system-ui, Segoe UI, Roboto, sans-serif"
    fontSize: "14px"
    fontWeight: 400
    lineHeight: 1.45
    letterSpacing: "normal"
  label:
    fontFamily: "JetBrains Mono, ui-monospace, Consolas, monospace"
    fontSize: "12px"
    fontWeight: 400
    lineHeight: 1.4
    letterSpacing: "0.06em"
  column-head:
    fontFamily: "JetBrains Mono, ui-monospace, Consolas, monospace"
    fontSize: "11px"
    fontWeight: 500
    lineHeight: 1.4
    letterSpacing: "0.08em"
rounded:
  hairline: "4px"
  control: "6px"
  surface: "8px"
  panel: "10px"
  card: "12px"
  feature: "14px"
  pill: "999px"
spacing:
  hair: "4px"
  tight: "6px"
  snug: "8px"
  control: "12px"
  panel: "14px"
  room: "20px"
components:
  panel:
    backgroundColor: "linear-gradient(180deg, rgba(18,26,43,.92), rgba(14,20,32,.92))"
    textColor: "{colors.text}"
    rounded: "{rounded.panel}"
    padding: "14px 16px"
  kpi:
    backgroundColor: "linear-gradient(180deg, rgba(18,26,43,.95), rgba(14,20,32,.95))"
    textColor: "{colors.text}"
    typography: "{typography.readout}"
    rounded: "{rounded.panel}"
    padding: "12px 14px"
  button:
    backgroundColor: "{colors.panel-raised}"
    textColor: "{colors.text}"
    rounded: "{rounded.control}"
    padding: "7px 12px"
  button-primary:
    backgroundColor: "rgba(53,199,242,.16)"
    textColor: "{colors.readout-cyan}"
    rounded: "{rounded.control}"
    padding: "7px 12px"
  button-danger:
    backgroundColor: "{colors.panel-raised}"
    textColor: "{colors.critical}"
    rounded: "{rounded.control}"
    padding: "7px 12px"
  button-small:
    backgroundColor: "{colors.panel-raised}"
    textColor: "{colors.text}"
    rounded: "{rounded.control}"
    padding: "4px 9px"
  input:
    backgroundColor: "{colors.field}"
    textColor: "{colors.text}"
    rounded: "{rounded.control}"
    padding: "7px 9px"
  badge-critical:
    backgroundColor: "rgba(255,77,77,.15)"
    textColor: "{colors.critical}"
    typography: "{typography.column-head}"
    rounded: "{rounded.pill}"
    padding: "2px 8px"
  badge-high:
    backgroundColor: "rgba(255,159,28,.15)"
    textColor: "{colors.high}"
    typography: "{typography.column-head}"
    rounded: "{rounded.pill}"
    padding: "2px 8px"
  badge-medium:
    backgroundColor: "rgba(245,197,24,.15)"
    textColor: "{colors.medium}"
    typography: "{typography.column-head}"
    rounded: "{rounded.pill}"
    padding: "2px 8px"
  badge-low:
    backgroundColor: "rgba(46,204,113,.15)"
    textColor: "{colors.low}"
    typography: "{typography.column-head}"
    rounded: "{rounded.pill}"
    padding: "2px 8px"
  pill:
    backgroundColor: "{colors.panel-raised}"
    textColor: "{colors.text}"
    typography: "{typography.column-head}"
    rounded: "{rounded.control}"
    padding: "1px 6px"
  chip:
    backgroundColor: "{colors.panel-raised}"
    textColor: "{colors.muted}"
    typography: "{typography.column-head}"
    rounded: "{rounded.pill}"
    padding: "4px 10px"
  chip-on:
    backgroundColor: "{colors.panel-raised}"
    textColor: "{colors.text}"
    typography: "{typography.column-head}"
    rounded: "{rounded.pill}"
    padding: "4px 10px"
  nav-item:
    backgroundColor: "transparent"
    textColor: "{colors.muted}"
    rounded: "{rounded.surface}"
    padding: "8px 10px"
  nav-item-active:
    backgroundColor: "rgba(53,199,242,.10)"
    textColor: "{colors.text}"
    rounded: "{rounded.surface}"
    padding: "8px 10px"
  card:
    backgroundColor: "{colors.panel-raised}"
    textColor: "{colors.text}"
    rounded: "{rounded.card}"
    padding: "14px"
  chip-static:
    backgroundColor: "{colors.panel-raised}"
    textColor: "{colors.muted}"
    typography: "{typography.column-head}"
    rounded: "{rounded.pill}"
    padding: "4px 10px"
  console:
    backgroundColor: "{colors.console-black}"
    textColor: "{colors.text}"
    typography: "{typography.label}"
    rounded: "{rounded.surface}"
    padding: "12px"
    height: "420px"
---

# Design System: BrandWatch

## Overview

**Creative North Star: "The Night Watch Floor"**

BrandWatch looks like a room that never closes. The ground is near-black, the air carries a faint
CRT scanline and a slow cyan sweep, the logo dot beats like a heartbeat monitor, and a radar spins
whenever the system is actually doing something. Nothing in that room is decoration for its own
sake: the sweep says the floor is live, the pulse says a scan is running, the glow says *this is
where your attention goes*. It is calm rather than alarmed — an operator sits here for eight hours,
and a UI that shouts all day stops being heard by the second hour.

The personality is **instrument-grade and quiet**. Controls are small, hairline-bordered and
monospace-labelled; they recede so the data leads. The one place the system raises its voice is a
number that matters — a KPI set in 34px Rajdhani, a severity badge, a critical row with a red spine
down its left edge. Density is deliberate: tables are compact, panels are tight, and the screen is
allowed to be full, because the analyst's job is comparison and comparison needs things next to
each other. Legibility for a first-time visitor is bought with structure and labelling, never by
emptying the screen.

The system runs in **two worlds**. *Night* is the console — everything at `/ui`, where work is done.
*Daylight* is the operation report: white paper, navy masthead, print type, a per-operation accent
drawn from an eight-color cycle. Daylight is what **leaves** the app and goes to a registrar, an
executive or a case file. The division is doctrine, not drift: dark is for working, light is for
handing over.

The tokens live in two places that cannot disagree: the `:root` block in `base.html` for everything
CSS and the browser draw, and `api/palette.py` for everything the server draws itself — the SVG it
writes into a page, and the daylight report. `tests/test_palette.py` fails if the two lists drift, if
a page redeclares a token the system already owns, or if a page uses one nobody declares.

**Key Characteristics:**

- Near-black ground (`#080B14`) with a single cyan light source. Only two other things may carry
  colour: severity, and an operation's place in the series.
- Three typographic voices with fixed jobs: Rajdhani counts, JetBrains Mono labels, Inter explains.
- Flat at rest. Surfaces lift on hover; glow appears only as state.
- Color is information: the severity ramp means severity and nothing else.
- Compact by default — 14px body, 8px cell padding, 14px grid gutter, 1440px ceiling.
- Motion is arrival and progress, staggered by index, and killed entirely under
  `prefers-reduced-motion`.
- Every surface carries its own explanation affordance (the `?` help dot, the `intro` line, the
  breadcrumb rail) because nothing here is allowed to be an unexplained number.

## Colors

A single cyan light source in a near-black room, with a four-step severity ramp that is the only
other color allowed to mean anything.

### Primary

- **Instrument Cyan** (`#35C7F2`): the one accent. Active navigation, focus rings, links, the
  running state, bar fills, the logo dot, the radar, every glow in the system. It is light, not
  paint — it marks what is interactive or alive, never what is merely important.
- **Readout Cyan** (`#5FE3FF`): the lit edge of the accent. Hovered links, the gradient terminal of
  an `h1`, primary-button text, breadcrumb links, `details` summaries. Used for text where Instrument
  Cyan would be too dim against the panel.

### Secondary

The severity ramp. These four are **not** a palette; they are an enumeration.

- **Critical Red** (`#FF4D4D`): critical severity, confirmed/flagged state, destructive buttons, the
  alert pulse, the left spine of a critical row.
- **High Orange** (`#FF9F1C`): high severity, a changed observation on a timeline, warning console
  lines, the undo affordance.
- **Medium Amber** (`#F5C518`): medium severity only.
- **Low Green** (`#2ECC71`): low severity, a completed step, a successful flash message, the "ok"
  button variant.

### Tertiary

**The operation series** (`--op1` … `--op8`): the eight colours one operation is drawn in, by its
index, so a graph of eight operations has eight colours nobody can confuse. The first four are the
system's own hues — Instrument Cyan, Medium Amber, High Orange, Low Green — and only the last four
are new: **Series Violet** (`#B388FF`), **Series Pink** (`#FF6FA8`), **Series Teal** (`#4DD0C4`),
**Series Grey** (`#9AA5B1`).

A series colour identifies *which* operation, never *how bad* it is; the legend says which is which.
It appears on the all-operations map, the infrastructure graph, the connections views, each operation
card's rail and its confidence ring, and `--op5` is also the one place a redirect host is coloured.
The daylight report runs the same eight positions in print-safe ink (`#0b6fbd`, `#b88a00`, `#e07b00`,
`#2e7d32`, `#7b4fd1`, `#d6336c`, `#00897b`, `#5d6b7e`), because the night series washes out on paper.

### Neutral

- **Operations Black** (`#080B14`): the page ground, and the only true background. The scanline and
  radial wash sit on top of it.
- **Panel** (`#0E1420`): the recessed surface — the ring's inner disc, the sidebar's lower gradient
  stop, mono blocks and intel cards.
- **Panel Raised** (`#121A2B`): the raised surface — chips, pills, state badges, default buttons,
  card interiors, phone row-cards.
- **Field** (`#0b1220`): inputs, selects, textareas, tooltips. Darker than the panel they sit on, so
  a field reads as a hole rather than a tile.
- **Console Black** (`#060910`): the live scan console only. The deepest value in the system,
  reserved for the one surface that is a terminal.
- **Border** (`#1E2A3D`): every hairline — panel edges, table rules, control strokes, the empty
  track behind bars, rings and stacks.
- **Text** (`#E6EDF5`): body copy and primary values.
- **Text Secondary** (`#C3CDD9`): prose that explains rather than states — chapter copy on *How it
  works*, a diagram's labels, a sub-line under a value, an advisory note. Brighter than Muted,
  because it is meant to be read rather than scanned past.
- **Muted** (`#8A97A8`): secondary copy, labels, column heads, legends, axis ticks.
- **Dim** (`#7C8A9E`): the quietest legible step — a sidebar group heading, a column's name inside a
  phone row-card, an unplaced node. It is the floor, and it is a floor on purpose: it clears 4.5:1 on
  every ground in the system (4.95:1 on Panel Raised, 5.60:1 on the page). Nothing is quieter.
- **On Lit** (`#06121D`): ink on a lit surface — the solid cyan "go" cap, a filled severity tick, a
  heat-map cell. One value for all of them, 7.1:1 or better on every hue it can land on.

### Named Rules

**The Severity-Only Rule.** Red, orange, amber and green mean severity and nothing else. Cyan means
interactive-or-live and nothing else. Every other number, label, chart series and legend swatch is
plain `Text` or `Muted`. There is no decorative color in this system — if a color appears, a reader
is entitled to ask what it means, and there must be an answer.

**The One Light Source Rule.** Cyan is the only hue that glows *on its own account*. A severity may
also glow, because a severity is a state: the status pulse expands in red or green, a completed
step's dot carries a green halo, an error panel sits in a red one. Nothing else glows — not a brand,
not a category, not an operation's series colour, and never a surface at rest.

**The Plain Number Rule.** A KPI's value is `Text` unless the number *is* a severity count
(`.kpi.crit`, `.kpi.hi`, `.kpi.med`). Coloring a number for emphasis is forbidden; emphasis comes
from size and position.

**The Series-Is-Identity Rule.** A series colour answers "which operation?" and nothing else. It is
never severity, never a brand, never a tier, never an accent. An ordered scale — scan depth, tier,
confidence — is one hue getting brighter (a `color-mix` of the accent toward Muted, then the accent,
then Readout Cyan), never three unrelated hues.

**The Drawing's Own Materials Rule.** An illustration may mix grounds of its own: the globe's land
and coastline, the flow diagram's four node fills, a graph box's radial floor. It may **not** invent
a colour that carries meaning. Anything standing for severity, state, identity or an operation comes
from the tokens — `var()` in CSS, `BW.ink()` in the browser, `api/palette.py` on the server.

## Typography

**Display Font:** Rajdhani (500/600/700), falling back to JetBrains Mono, then system mono.
**Body Font:** Inter (400/500/600), falling back to system-ui, Segoe UI, Roboto.
**Label/Mono Font:** JetBrains Mono (400/600), falling back to ui-monospace, Consolas.

**Character:** Rajdhani is a condensed, squared display face — it makes a number look like a readout
on a panel rather than a figure in a document. JetBrains Mono, uppercased and letter-spaced, turns
every label into equipment labelling. Inter carries anything written in sentences. The three never
trade jobs, and the contrast between them is what makes a dense screen parse.

### Hierarchy

- **Display / `h1`** (Rajdhani 700, 26px, `0.04em`, line-height 1.2): one per page. Filled with a
  left-to-right gradient from `Text` to `Readout Cyan` via background-clip, so the page title is the
  only text in the system that is lit. Drops to 22px at 900px and 20px at 700px. Any `.muted` or
  `.small` span inside it reverts to Inter 13px and breaks onto its own line on a phone.
- **Readout** (Rajdhani 700, 34px, line-height 1): KPI values, ring centers, operation-card
  statistics, the counter in *How it works*. The single loudest element on any screen. 28px at
  900px, 19px at 700px.
- **Headline** (Rajdhani 700, `clamp(26px, 3vw, 38px)`, line-height 1.08): the chapter headings on
  the *How it works* narrative surface — the only place a second display-scale step is justified.
- **Title / `h2`** (JetBrains Mono 600, 12px, uppercase, `0.12em`, `Muted`): every section heading,
  preceded by a 6px solid cyan square set 2px above the baseline. The square is the section marker
  for the whole system; a section heading without it is not a section heading.
- **Body** (Inter 400, 14px, line-height 1.45): all prose. The page `intro` line is 13px/1.55 in
  `Muted`, capped at 980px, and clamps to two lines with a tap-to-expand on phones.
- **Label** (JetBrains Mono 400, 12px, uppercase, `0.06em`, `Muted`): form labels, breadcrumbs,
  state badges, pills.
- **Column Head** (JetBrains Mono 500, 11px, uppercase, `0.08em`, `Muted`): table `th`, KPI captions,
  legend values, chart ticks. On a phone, the same role drops to 9.5px/600 in `Dim` as the
  per-cell label inside a row-card.

### Named Rules

**The Three-Voice Rule.** Rajdhani counts, JetBrains Mono labels, Inter explains. A number in Inter
looks like a sentence; a sentence in Rajdhani looks like a slogan. Never swap them.

**The Uppercase-Is-Metadata Rule.** Uppercase plus letter-spacing marks something *about* content —
a column name, a state, a field label, a group heading. Content itself is never uppercased. A
headline shouting in caps would claim to be a label.

**The Lit Title Rule.** The `h1` gradient is the system's one typographic flourish and belongs to
the page title alone. Gradient-filled text anywhere else cheapens it.

## Layout

A fixed left rail and a single centered column. The sidebar is 232px, folds to a 64px icon rail
(persisted in `localStorage` as `bw-side`), and below 900px becomes an off-canvas drawer behind a
sticky top bar with a scrim at `rgba(3,6,12,.6)`. Content lives in `main` at 20px padding and a
1440px ceiling, dropping to 14px 12px 28px on a phone.

Spacing is a short, repeated scale: 4 / 6 / 8 / 12 / 14 / 20px. Grid gutters are 14px; panel padding
is 14px 16px; table cells are 8px, tightening to 7px 6px below 900px. KPI strips are
`auto-fit, minmax(150px, 1fr)`; intel card grids are `auto-fit, minmax(260px, 1fr)`.

Breakpoints, in the order the system actually uses them: **1100px** (four-up becomes two-up),
**900px** (every grid collapses to one column, the sidebar becomes a drawer, type steps down),
**800px** (operation cards go single-column), **700px** (wide tables become row-cards; the page head
compacts; filters fold into a `details.mfold`), **640/600px** (CTA and tooltip reflow), **520px**
(donuts shrink, action rows wrap at 140px), **420px** (operation-card statistics go three-up).

Every grid and column child carries `min-width: 0`, and any table too wide to collapse scrolls
inside its own `.tw` box with `overscroll-behavior-x: contain`. The page body never scrolls
sideways.

### Named Rules

**The Row-Becomes-A-Card Rule.** Below 700px a `table.rwd` stops being a table: each row becomes a
bordered card, the identity cell (host, domain, site) jumps to the top full-width, signals and
actions span the card, every remaining cell is prefixed with its column name, and empty cells
disappear entirely. A horizontally-scrolling data table on a phone is a failure, not a fallback.

**The Min-Zero Rule.** Any grid or flex child that can contain a table, a domain or a hash gets
`min-width: 0`. Long attacker-supplied strings must wrap or scroll inside their box — never widen
the page.

## Elevation & Depth

Flat at rest. Depth comes from **tonal layering** — Operations Black under a Panel/Panel-Raised
gradient under a hairline border — not from shadows. Surfaces sit on the page; they do not float
above it.

Two things change that, and only two: **hover** lifts a surface (a translate of 2–3px plus a black
ambient shadow), and **state** lights it (a cyan ring or glow). Black shadow is physics; cyan glow
is information.

### Shadow Vocabulary

- **Panel hover** (`0 0 0 1px rgba(53,199,242,.08), 0 8px 30px rgba(0,0,0,.35)`): a panel under the
  cursor.
- **Tile lift** (`0 6px 24px rgba(0,0,0,.35)` with `translateY(-2px)`): KPI tiles.
- **Card lift** (`0 0 0 1px var(--accent), 0 14px 40px rgba(0,0,0,.45)` with `translateY(-3px)`):
  operation cards, the one place hover both lifts *and* lights, because the whole card is a link.
- **Focus ring** (`0 0 0 3px rgba(53,199,242,.15)` on fields, `.25` on links and buttons, plus a 2px
  `Readout Cyan` outline at 2px offset): keyboard focus only, via `:focus-visible`.
- **Active marker** (`0 0 8px var(--accent)` on a 3px rail): the current nav item and timeline dots.
- **Dialog** (`0 20px 60px rgba(0,0,0,.6)`): the confirm dialog, on a 1px cyan hairline.
- **Drawer** (`12px 0 40px rgba(0,0,0,.55)`): the phone sidebar over the page.
- **Tooltip** (`0 10px 30px rgba(0,0,0,.5)`): the help bubble and the 2.6× thumbnail zoom.

### Named Rules

**The Glow-Is-Signal Rule.** Cyan glow means state — focused, active, running, selected, critical.
It never means "important" and never means "pretty". Ambient cyan exists only in the page
background and chrome: the body scanline, the radial wash, the 9-second sweep and the logo pulse.
Element-level glow is reserved for state. Nothing in between.

**The Flat-At-Rest Rule.** A surface with a resting shadow is a bug. Lift is a response to the
pointer; light is a response to the system.

## Shapes

A graduated radius scale where the number says what kind of object you are looking at: **4px**
hairline (thumbnails, focus outline), **6px** control (buttons, inputs, pills, bar tracks), **8px**
surface (sidebar items, console, tooltips, screenshots), **10px** panel, **12px** card (intel cards,
phone row-cards, operation cards), **14px** feature (IP cards, the report page), **999px** pill.

Borders are hairlines at 1px `Border`, and they are the system's primary edge — almost every object
is defined by its stroke rather than by a fill difference. Severity, where it applies to a whole
row, is carried as a 3px inset left spine (`box-shadow: inset 3px 0 0`) rather than a tint, so a
critical row stays readable.

The recurring geometry is circular measurement: the conic-gradient score ring (96px, with a 76px
Panel disc punched out of it, animating via an `@property --p` transition), the 38px small ring in
tables, the 14px radar with its spinning conic sweep, the 8px status pulse, and the donut. When
BrandWatch shows a proportion, it shows a circle.

### Named Rules

**The Pill-Is-A-State Rule.** A 999px radius means a value you read, never one you type into — a
severity badge, a state chip, a filter toggle, a count. Anything you can edit or press has a 6px
corner. Radius is a part of speech.

**The Hairline Rule.** One border width (1px) and one border color (`#1E2A3D`) at rest. Emphasis
changes the border's *color* to cyan or a severity hue; it never changes its thickness.

## Components

### Buttons

- **Shape:** 6px corners (`rounded.control`), 1px `Border` stroke, inheriting the 14px Inter body
  face.
- **Default:** `Panel Raised` ground, `Text` label, 7px 12px padding.
- **Primary:** a cyan wash (`rgba(53,199,242,.16)`), `Instrument Cyan` border, `Readout Cyan` label
  at weight 600. The primary is a lit outline, not a solid fill — the only solid cyan button in the
  system is the "go" cap inside the all-map CTA, where the dark label (`#04121c`) on full cyan is
  the point.
- **Hover:** border goes to `Instrument Cyan` with a `0 0 12px rgba(53,199,242,.2)` glow, over 0.2s.
- **Danger / OK:** the default ground with a `Critical Red` / `Low Green` border and matching label.
  Destructive intent is shown in the stroke, never by filling a button red.
- **Ghost:** transparent ground, everything else unchanged.
- **Small:** 4px 9px, 12px, `white-space: nowrap`.
- **Disabled:** 0.55 opacity, default cursor, no glow.
- **Busy:** a guarded form disables its submitter and swaps the label to "Working…" for up to 30s,
  so a double-press can never queue two scans.

### Chips

- **Style:** pill (999px), `Panel Raised` ground, 1px `Border`, JetBrains Mono 11px, `Muted` label,
  4px 10px, `user-select: none`.
- **State:** `.on` promotes the label to `Text`, the border to `Instrument Cyan`, and adds a
  `0 0 10px rgba(53,199,242,.18)` glow. A selected filter is lit; an unselected one is dim. There is
  no third state.
- **Read-only (`.chip.static`):** the same pill with `cursor: default` and no `.on` state, for a
  value you read rather than press — a brand keyword, an approved query, a shared pivot. Use the
  modifier; do not redefine `.chip`, which restyles every filter on the page as a side effect.
- **Hint (`.chip.static.hint`):** a dashed border. On the connections views the hue says what kind
  of evidence a tie is, and the dash says it is a hint rather than proof. Strength is never carried
  by a dimmer shade of the hue.

### Cards / Containers

- **Panel** — corner 10px, a `180deg` gradient from `rgba(18,26,43,.92)` to `rgba(14,20,32,.92)`,
  1px `Border`, 14px 16px padding (12px below 900px). Arrives with `fadeUp` staggered by `--i`.
  Hover borders at `rgba(53,199,242,.35)` with the panel-hover shadow. A `h2` as its first child
  loses its top margin.
- **Intel card** — corner 12px, flat `Panel Raised`, 14px padding, with a mono uppercase `h3`.
- **KPI tile** — corner 10px, near-opaque gradient, 12px 14px, a 86px radial cyan bloom bleeding off
  the top-right corner at 7% opacity, a Rajdhani 34px value and an 11px uppercase caption. As a
  link it keeps `color: inherit`; when it is the active filter it takes an inset cyan ring.
- **Operation card** — corner 12px, a `160deg` gradient, a 220×150 canvas preview on the left with
  its own radial ground, a Rajdhani 21px title, and a five-up statistics strip of inset tiles.
  Single-column below 800px with the canvas at a 440:300 aspect; three-up statistics below 420px.

### Inputs / Fields

- **Style:** `Field` (`#0b1220`) ground — darker than its container — 1px `Border`, 6px corners,
  7px 9px, full width, inheriting the body face.
- **Focus:** border to `Instrument Cyan` plus a `0 0 0 3px rgba(53,199,242,.15)` ring, over 0.2s.
- **Label:** a block-level JetBrains Mono 12px uppercase `Muted` label above the field, 8px above
  and 4px below. Fields are always labelled; placeholders never substitute for labels.
- **RTL-safe text:** any block that can carry a brand name, an ad or an attacker's words
  (`.lead`, `.summary`, `.story`, `.say`, `.reason`) uses `unicode-bidi: plaintext` so Hebrew and
  Arabic take direction from their own first character.

### Navigation

- **Sidebar:** a `180deg` `#0d1422 → #0a101b` gradient, 232px, hairline right border, grouped under
  JetBrains Mono 11px uppercase headings in `Dim` (Work / Manage / Help). Items are 13.5px,
  8px 10px, 8px corners, `Muted` at rest, with a 17px 1.7-weight stroked SVG icon.
- **Hover:** `Text` label over a `rgba(53,199,242,.06)` wash.
- **Active:** `Text` label, `rgba(53,199,242,.10)` wash, cyan-tinted border, a `Readout Cyan` icon,
  and a 3px glowing cyan rail bleeding off the left edge.
- **Counts:** a pill badge right-aligned in the item — cyan for work waiting, `.warn` red for
  takedowns not sent. Folded to the icon rail it becomes a 16px corner dot.
- **Logo:** JetBrains Mono 700 uppercase at `0.14em` in `Instrument Cyan`, preceded by a 9px cyan
  dot that beats on a 2.2s ease-in-out loop.
- **Mobile:** a sticky top bar with a hamburger, the wordmark, and the same counts as pills; the
  sidebar slides in at `min(280px, 86vw)` over a scrim.
- **Search:** one input in the rail, focused by pressing `/` from anywhere (falling back to the
  search page when the rail is folded or on a phone).

### Signature Components

**The live scan console.** `Console Black` (`#060910`), 1px `Border`, 8px corners, JetBrains Mono
12px, `white-space: pre-wrap`, 420px tall (320px on a phone), fed by SSE. Lines are colored by the
severity vocabulary — cyan running, green done, red error, orange warning — and each arrives with a
0.3s `rowIn`. It is the one place in the product where the machine narrates itself in real time, and
it looks like a terminal because it *is* one.

**The score ring.** A 96px conic gradient driven by a registered `@property --p`, so the fill
animates from 0 over 1.4s on the system's standard easing, with a `Panel` disc punched out and the
value set in Rajdhani 28px. A 38px variant drops to JetBrains Mono 11px inside tables, and a 64px
variant sits in the IP card header.

**The help dot.** A 15px bordered circle carrying `data-tip`, rendering a `Field`-ground,
cyan-bordered 320px-max tooltip above itself on hover *and* `:focus-visible` (flipping to
right-aligned below 600px). It is how the system keeps a promise: no term, score or column stands
unexplained.

**The evidence thumbnail.** 64×40, desaturated to `saturate(.2) brightness(.8)` at rest, scaling to
2.6× with full saturation and a cyan border on hover. Evidence is dimmed until you look at it, so a
wall of screenshots never competes with the data around it. The zoom is disabled below 900px.

**The daylight operation report.** The second world, and the only light surface in the system:
`#e9eef3` ground, a 1020px white page at 14px corners under a `0 10px 40px rgba(20,35,55,.15)`
shadow, a `135deg #0d1b2e → #14304f` navy masthead with an `0.18em` eyebrow and a 5px bottom border
in the operation's own accent. Type is system-UI at 14px/1.55; the accent cycles through eight
print-safe hues (`#0b6fbd`, `#b88a00`, `#e07b00`, `#2e7d32`, `#7b4fd1`, `#d6336c`, `#00897b`,
`#5d6b7e`) by operation index; severity becomes a solid white-on-color pill because paper has no
glow to spend. Tables zebra at `#fbfcfd`.

### Named Rules

**The Stroke-Not-Fill Rule.** State, severity and intent are expressed by changing a border color.
Solid color fills are reserved for severity badges (at 15% alpha), bar fills, and the daylight
report. A button filled with `Critical Red` would be louder than an actual critical finding.

**The Explain-Affordance Rule.** Any component that displays a derived value — a score, a
confidence, a count, a verdict, a grouping — ships with the route to its explanation: a help dot, a
link to *Explain Finding*, or a breadcrumb side-link. A derived number with no way in is incomplete,
not minimal.

## Do's and Don'ts

### Do:

- **Do** reach for the existing tokens: `var(--…)` in CSS, `BW.ink('name')` / `BW.sev` / `BW.op` /
  `BW.kind` in the browser, and `INK` / `OPS` / `kind_color()` / `op_color()` / `op_print_color()`
  from `api/palette.py` in a template. A new hex is a fork of the design system.
- **Do** put a colour that must exist in more than one renderer in `api/palette.py` and mirror it on
  `:root`. `tests/test_palette.py` is what keeps the two honest.
- **Do** color a number only when it *is* a severity (`.kpi.crit`, `.kpi.hi`, `.kpi.med`). Every
  other value is `Text`.
- **Do** mark a new section with an `h2` — JetBrains Mono 12px uppercase at `0.12em` with its 6px
  cyan square.
- **Do** give any new wide table `class="rwd"` and real `<th>` text, so the 700px row-card
  transformation can label its cells.
- **Do** stagger arriving collections with `--i` (70ms per panel, 55ms per tile) or `--r` (28ms per
  row) and let `fadeUp` / `rowIn` do the work.
- **Do** state severity on a whole row with the 3px inset left spine (`.sevrow.critical`), not a
  background tint.
- **Do** label every input with a block mono uppercase `<label>`, and give any block that can hold a
  brand name or attacker text `unicode-bidi: plaintext`.
- **Do** keep every animation inside the blanket `prefers-reduced-motion` kill switch at the end of
  `base.html` — new keyframes outside a stylesheet it covers must opt in explicitly.
- **Do** use the daylight world for anything that leaves the app as a document, and the night world
  for everything that stays in it.

### Don't:

- **Don't** introduce a second accent hue. `--violet` and `--magenta` used to exist and are now
  deleted; `tests/test_demo_story.py::test_palette_is_calm` fails if either comes back. The series
  tokens are not a substitute — see The Series-Is-Identity Rule.
- **Don't** write a colour into SVG with `var()`. A presentation attribute (`fill="…"`,
  `stroke="…"`, `stop-color="…"`) does not accept it: either move the colour into CSS
  (`style="fill:var(--accent)"`, or a class) or render the concrete value from `api/palette.py`.
- **Don't** redefine a global component (`.chip`, `.panel`, `.badge`, `.card`) inside a page to get
  a variant. Add a modifier; a redefinition silently restyles every other use on that page.
- **Don't** put a resting shadow on anything. Flat at rest; lift on hover; light on state.
- **Don't** glow an element to say it matters. Glow says focused, active, running or selected.
- **Don't** uppercase content. Uppercase is reserved for metadata.
- **Don't** set prose in Rajdhani or numbers in Inter.
- **Don't** fill a button with a severity color, or give a destructive action more visual weight
  than a critical finding has.
- **Don't** let a table scroll the page sideways — wrap it in `.tw` or convert it to a row-card.
- **Don't** emphasise by thickening a border. Change its color instead.
- **Don't** ship a derived number without the path to its arithmetic.
- **Don't** take a colour below the Dim floor (`#7C8A9E`). If a label needs to be quieter than that,
  it needs less weight, less size or less prominence — not less contrast.
- **Don't** reach for the light palette inside `/ui`. There is exactly one light surface, and it is
  the thing you hand to someone else.
