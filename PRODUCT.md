# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

**Primary: the evaluator.** A technical reviewer — hiring manager, engineer, or interviewer — who
opens BrandWatch cold, with no onboarding, no credentials of their own, and a few minutes of
attention. They are not protecting a brand; they are deciding whether the person who built this
ships whole products. Confirmed verdict to earn: *"this person ships whole products"* — end-to-end
scope (schema, API, UI, tests, CI, docs), not detection depth alone.

They arrive from three places, in no fixed order, and any one of them may be the only one they see:

1. **the live static demo** — they click through pages, and the app must teach and impress unguided;
2. **the GitHub README** — they skim screenshots and tables and may never click further;
3. **the YouTube case study** — a real-brand scan; they reach the repo or demo already convinced.

**Secondary: the analyst persona the app must convincingly serve.** BrandWatch models a real
brand-protection workflow for three roles — `admin`, `analyst`, `viewer` (RBAC enforced on API and
UI, multi-tenant workspaces). No analyst is a confirmed live user today, but every screen must hold
up as if one worked in it all day: the evaluator's verdict depends on the workflow being credible,
not on it being decorated. Density, correctness and the real usage scene outrank expression.

**Operator/author:** Itay Azulay, who also runs scans in live mode.

## Product Purpose

BrandWatch finds the fake sites impersonating a brand, proves it with tamper-proof evidence, maps
the attackers behind them, and gets them taken down. Its pipeline is **detect → analyze → report**,
human-in-the-loop, never blind auto-action.

Success for the product-in-use: an analyst goes from "a look-alike domain exists" to "here is the
proof, here are the eight other sites run by the same operator, and here is the drafted takedown
with the registrar's abuse contact" without leaving the app or trusting a number they cannot audit.

Success for the product-as-artifact: an evaluator who spends two minutes in the demo concludes it is
a real system — coherent data, explainable scores, nothing faked.

## Positioning

Three mechanisms a neighboring brand-protection tool could not truthfully claim:

- **Every score opens down to its arithmetic.** 50 signals in 7 capped groups (Identity 20, Visual
  30, Behavior 30, Infrastructure 20, Reputation 15, Freshness 10, Evasion 25 → raw 0–150), decisive
  bonuses, false-positive penalties, combination rules that floor severity, and a separate
  confidence axis. Each score stores its `scoring_version` with a snapshot of the weights, so an old
  finding stays interpretable after the weights change. *Explain Finding* shows the whole path.
- **It checks what the AI assistants tell customers.** It learns a brand's real contacts from the
  brand's own site, asks ChatGPT, Gemini and Google AI Mode what a customer would ask, compares
  every phone / short code / e-mail / login address in the answers, demands the cited proof, and
  then opens the cited pages itself — raising made-up or scam-published contacts as findings.
- **It names the operation, not just the site.** Pivoting on servers, certificates, registrants,
  analytics and affiliate IDs, redirect hosts and data sinks groups sites into *operations*: who is
  behind them, how they work, and the shortest way to stop each one.

AI and the hand-written logistic-regression classifier sit **next to** the score as second opinions
and never change it.

## Operating Context

- **Demo (the evaluator's path):** `python scripts/seed_demo.py --reset` (≈90 s) builds a clean,
  self-consistent story on fictional brands (ShopNova, CoinPilot, VaultPay, NordBank). Runs at $0,
  no API keys. Local demo on port **8765**; live mode on **8766**. The suggested walkthrough begins
  at **How it works** — the whole product in one picture and six short steps.
- **A static read-only build** of the app lives in `site/` and is what the public demo link serves.
- **Screens:** Dashboard · Brands & Scans · Findings → Explain Finding · Watchlist · Attack
  infrastructure (graph, operations, connections) · Takedowns · Activity (append-only audit trail) ·
  How it works · Settings.
- **A live scan is a narrated event:** an SSE console narrates each step while it runs, with a
  *replay highlights* pass afterwards; provider outages surface in an alert panel and the scan
  carries on with the remaining feeds.
- **Facts shown inside the product are computed from the code** (`src/brandwatch/about.py`, surfaced
  on *How it works*, Settings and `GET /health` → `facts`), never typed by hand, so they cannot
  drift from the code the way a README does.
- **Deployment of record:** FastAPI + Jinja server-rendered, SQLite locally / PostgreSQL in Docker,
  an optional Arq/Redis worker and an optional sandboxed Playwright browser worker.

## Capabilities and Constraints

**Confirmed capabilities** (six delivered phases): discovery across dnstwist look-alikes, newly
registered domains, certificate transparency, search, urlscan and Meta pages/ads; sandboxed
Playwright evidence with cloaking multi-probe and gated residential/mobile proxy probes;
pHash/dHash/palette and rendered-DOM comparison; risk + confidence scoring with a live scoring
editor, versioned weights and re-score history; analyst verdicts one-by-one or in bulk; budgeted BFS
pivoting with co-hosted triage; campaign/operation graph and IOC export as CSV/JSON/STIX 2.1;
registrar/host/CDN abuse channels, 26 report portals, evidence packages (HTML + JSON, SHA-256 per
row) and an audited takedown lifecycle; RBAC, personal access tokens, encrypted provider keys,
workspace budgets, multi-tenancy, classifier training.

**Product facts the interface must never contradict:**

- **Human-in-the-loop, always** *(the user's binding constraint)*. Nothing is sent, reported or
  accused automatically. Takedowns are drafts a person reviews and sends. No screen may imply
  otherwise, and no affordance may make an outbound action feel already taken.
- Evidence is append-only at the database level (triggers), with SHA-256 and provenance per row.
- The demo uses fictional brands only; they are never dressed as real customers or testimonials.
- Only brands the operator is authorized to protect are monitored; identify and report, never
  retaliate.

**Technical constraints that bind design:**

- Server-rendered Jinja2 templates in `src/brandwatch/api/templates`; **no front-end framework**.
  The graphs, the globe and the console are plain SVG/JS. A direction that needs React is out of
  bounds.
- `base.html` carries a single inline `<style>` block as the de-facto design system; fonts come from
  Google Fonts (Rajdhani, JetBrains Mono, Inter).
- The static demo must survive export to flat files — anything that requires a live server degrades.
- Phone support is real, not hypothetical: layouts are expected to hold at **390 px**.

**Terminology** (use exactly these words): candidate · finding · signal · score vs. confidence ·
verdict (confirm / dismiss) · operation (a group of sites run by one attacker) · campaign graph ·
cloaking probe · watchlist · takedown · evidence package · workspace / tenant · scoring version.

**Open, deliberately undecided:**

- A marketing/landing page is in design scope but **does not exist yet**; no audience, offer or
  pricing has been decided for it, and none may be invented.
- Whether BrandWatch is ever positioned as a product to buy. The evaluator verdict chosen was
  *"ships whole products"*, not *"I would pay for this"* — no commercial claim is authorized.

## Brand Commitments

- **Name:** BrandWatch. **Mission line:** "Finds the fake sites impersonating your brand, proves it,
  maps the attackers behind them, and gets them taken down."
- **Voice (as practiced in the shipped artifact):** plain, concrete, declarative. Specific numbers
  instead of adjectives. No marketing superlatives, no exclamation, no hype. A finding explains
  itself in two sentences. Labels and headings are unornamented.
- **Never link the repository from the app, the demo or any built surface.** The static build's
  `--github` flag stays empty. The repository is private; the code is "published for viewing only".
- **License:** © 2026 Itay Azulay, all rights reserved — carried in the README and `LICENSE`.
- An incumbent visual system exists and is coherent (dark console, cyan accent, sidebar shell).
  It is design authority for refinement, and it is **not yet documented** — a `DESIGN.md` gap, not a
  greenfield.

## Evidence on Hand

Real, and usable without fabrication:

- `docs/images/` — dashboard, graph, map, finding, findings, connections and takedowns screenshots;
  `site/og-how-it-works.png`.
- A recorded case study on a real crypto-trading brand: eight typo domains proven to be one
  operation, forwarding to the real site with the same affiliate id.
- A 65-scenario golden dataset; last measured phishing precision 1.00, recall 1.00, FP rate 0.00
  against a 0.90 / 0.90 / 0.05 gate (`tests/test_golden.py`, `src/brandwatch/about.py`).
- ~35k lines of Python and a passing suite in the high hundreds of tests; CI runs lint plus the suite
  on SQLite-with-Chromium and on PostgreSQL 16 with an Alembic up/down cycle, with no live API keys.
  **These counts move** — read them from `GET /health` → `facts`, never hard-code them into a
  surface.
- `docs/SPEC.md` and the phase tables in `README.md`.

**Absences future work must not fill in:** no customers, no users besides the author, no
testimonials, no press, no pricing, no uptime or scale numbers, no named brands as clients. The
fictional demo brands are fictional.

## Product Principles

1. **Nothing is asserted that cannot be opened.** Every number, verdict and grouping has a path to
   its evidence, and the interface's job is to make that path one click away rather than to
   reassure.
2. **The human presses the button.** Automation gathers and explains; it never accuses, sends or
   decides. Design must keep the boundary between *found* and *acted on* unmistakable.
3. **The artifact is the argument.** The product earns belief by being coherent and complete under
   inspection — real data, real pipeline, working tests — not by describing itself well.
4. **Credible to an analyst, legible to a stranger.** Density is not reduced for the visitor; the
   way in is made obvious instead.
5. **Facts come from the code.** Anything a surface claims about the system is computed, so the
   product cannot drift from its own description.

## Accessibility & Inclusion

No standard has been set as a requirement. The shipped artifact already practices `aria-live` on the
scan console and flash messages, a skip link, `prefers-reduced-motion` handling for the animated
background and globe, and phone layouts down to 390 px. **Open:** whether WCAG 2.2 AA is binding —
until that is decided, existing behavior is preserved and not regressed.
