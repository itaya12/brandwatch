<div align="center">

# BrandWatch

**Finds the fake sites impersonating your brand, proves it, maps the attackers behind them, and gets them taken down.**

[![CI](https://github.com/itaya12/brandwatch/actions/workflows/ci.yml/badge.svg)](https://github.com/itaya12/brandwatch/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.12-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white)
![Playwright](https://img.shields.io/badge/Playwright-sandboxed-2EAD33?logo=playwright&logoColor=white)
![Tests](https://img.shields.io/badge/tests-701%20passing-brightgreen)
![Demo](https://img.shields.io/badge/demo-%240%2C%20no%20API%20keys-35C7F2)

### [▶ Open the live demo](https://nbse3h.s.gy/M37Izw)
<sub>A read-only copy of the app with fictional brands: click through every page, the attacker map and the findings. Nothing is sent anywhere. Start at <b>How it works</b> — the whole product in one picture and six short steps.</sub>

### [🎬 Watch a real case study](https://nbse3h.s.gy/sSLDpR)
<sub>A live scan of a real crypto-trading brand: BrandWatch finds its look-alike domains, investigates them, and the map shows that eight typo domains are one operation, forwarding visitors to the real site with the same affiliate id.</sub>

<a href="https://nbse3h.s.gy/sSLDpR"><img src="https://img.youtube.com/vi/17dMOIzThgk/maxresdefault.jpg" alt="Video: a real BrandWatch case study" width="70%"></a>

<a href="https://nbse3h.s.gy/M37Izw"><img src="docs/images/dashboard.png" alt="BrandWatch dashboard: the five-step pipeline and a live map of where the phishing kits are hosted" width="100%"></a>

</div>

## What it does

| | |
|---|---|
| 🔎 **Find** | Look-alike domains (typos and look-alike letters on 1,000+ domain endings, checked in DNS), newly registered domains from yesterday's registrations, brand-new HTTPS certificates, Google results, urlscan, and fake Facebook / Instagram pages and ads that use the brand's name — scam shops for a brand that shops resell, phishing ads for a bank or a payment app (the site behind such an ad often has no brand name in its domain). |
| 🤖 **Ask the AI assistants** | Asks ChatGPT, Gemini and Google AI Mode what a customer would ask ("what is the support phone of …?"), checks every phone, short code, e-mail and login address in the answers against the brand's own website, asks for the proof when one does not match, opens the cited pages itself, and raises made-up or scam-published contacts as findings. |
| 🧪 **Prove** | Visits every suspect in a sandboxed browser like a real victim would — a real Chrome (User-Agent, Accept-Language, client hints, language and time zone) through a residential or mobile 4G / 5G proxy, as a desktop or a phone — and like a scanner would, to catch cloaking; compares it with the real site (favicon, screenshot, login form, DOM), and scores 50 signals in 7 capped groups. Every point is explained. |
| ⚖️ **Decide** | An analyst confirms or dismisses, one by one or in bulk. AI and an ML classifier give a second opinion, but never change the score. Nothing is sent automatically. |
| 🕸️ **Map the attackers** | Pivots on servers, certificates, registrants, analytics IDs, affiliate IDs, redirect hosts and where the stolen data goes, then groups the sites into **operations**: who is behind them, how they operate, and the shortest way to stop each one. |
| 🧾 **Take down** | Registrar, host and CDN abuse contacts, 26 report portals, evidence packages (HTML + JSON, SHA-256 per row), and an audited takedown lifecycle. |

### 🤖 AI answers: what ChatGPT and Gemini tell your customers

People no longer only search Google — they ask an assistant *"what is the support phone of my bank?"* and call the number
it gives. When the assistant makes a number up (a hallucination) or repeats one a scam page published, the caller reaches
a stranger; a made-up number is one a scammer can claim tomorrow. BrandWatch checks it, per brand, with a switch:

1. **Learns the real contacts** — reads the brand's own website (contact, support and service pages first) and keeps every
   phone, short code (`*2407`), e-mail and WhatsApp number with the page it is on.
2. **Asks like a customer** — approved questions in the brand's languages (support phone, every way to get in touch,
   where to log in, how to report fraud) to **ChatGPT** (with web search), **Gemini** and **Google AI Mode**.
3. **Compares** — every contact and web address in the answers against the official ones.
4. **Asks for the proof** — *"show me the official page where it appears, I suspect it is a fraud"* — and then **opens every
   cited page itself**: the assistant's word is never taken. A Google search of the number shows who else publishes it.
5. **Raises a finding** — *made up* (no page publishes it, or the assistant took it back), *published off the brand's site*
   (Critical when a look-alike or a known phishing site carries it), or *sends users to a site that is not the brand's* —
   with the full transcripts as evidence and a ready text for reporting the answer. Pages that publish the wrong number
   are checked as suspects in the same scan.

<table>
<tr>
<td width="50%"><img src="docs/images/graph.png" alt="The map of all confirmed sites: each operation in its own coloured area"><br><sub><b>One map of all sites</b>: each operation (a group of sites run by one attacker) in its own area.</sub></td>
<td width="50%"><img src="docs/images/map.png" alt="Operation cards: what ties the sites together and how to stop them"><br><sub><b>Operations</b>: why these sites belong together, with a confidence level and the first step to stop them.</sub></td>
</tr>
<tr>
<td><img src="docs/images/finding.png" alt="A finding: a cloaked phishing kit explained in two sentences"><br><sub><b>A finding explains itself</b>: a cloaked kit, its score, its evidence and the next step.</sub></td>
<td><img src="docs/images/connections.png" alt="Connections view: what is shared on the left, the sites on the right"><br><sub><b>Connections</b>: what the sites share (server, certificate, registrant…) and who shares it.</sub></td>
</tr>
<tr>
<td><img src="docs/images/findings.png" alt="The findings list with statistics, brand chips and bulk verdicts"><br><sub><b>Findings</b>: ranked by severity, filtered by brand, with a verdict on many at once.</sub></td>
<td><img src="docs/images/takedowns.png" alt="Takedowns: every confirmed site and how far its takedown got"><br><sub><b>Takedowns</b>: every confirmed site and how far its takedown got.</sub></td>
</tr>
</table>

**Built end to end:** ~35k lines of Python, 678 automated tests, and a 65-scenario golden dataset
(phishing precision 1.00, recall 1.00; every scam shop flagged and no genuine shop). The demo
runs at $0 with no API keys, on fictional brands (ShopNova, CoinPilot, VaultPay, NordBank).
Exact numbers are computed from the code: open **How it works** in the app or `GET /health` → `facts`.

**Stack:** Python 3.12 · FastAPI · SQLAlchemy 2 + Alembic (SQLite or PostgreSQL) · Jinja2 · Playwright · dnspython ·
dnstwist · Pydantic · numpy (a logistic-regression classifier written by hand) · Arq/Redis (optional) ·
plain SVG/JS for the graphs and the globe, no front-end framework.

## A ten-minute demo

1. `python scripts/seed_demo.py --reset` (≈ 90 s) — a clean, self-consistent ShopNova story.
2. Sign in → **Dashboard**: the mission line and *How BrandWatch works · 5 steps*.
3. **Brands & Scans → ShopNova**: tick *include fingerprinting*, press **START SCAN**; the live
   console narrates every step, then *▶ replay highlights*.
4. **Findings → shopnova-giftcard.com**: a cloaked kit that explains itself in two sentences; the
   scanner-view / victim-view / official screenshots; *Explain Finding* down to the arithmetic.
5. **Confirm phishing** → the attack infrastructure is mapped automatically; open
   **Investigate site and its network** for the VirusTotal-style intel page.
6. **Attack infrastructure**: drag the graph, read the triage reasons, export STIX 2.1.
7. **Takedowns**: registrar / host / CDN channels, 26 report portals, the audited lifecycle.
8. **Activity**: the append-only audit trail. **How it works** answers the "how" questions.

Set `DEMO_FLAKY_PROVIDER=virustotal` to make VirusTotal fail once: the console's alert panel
explains the outage and the scan carries on with the other reputation feeds.

Guiding principle: **detect → analyze → report**, human-in-the-loop, never blind auto-action.

## Quick start (Windows PowerShell shown; bash is the same minus `.venv\Scripts`)

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
copy .env.example .env
alembic upgrade head
uvicorn brandwatch.api.main:app --port 8765
```

Open `http://127.0.0.1:8765/ui` and sign in with the bootstrap admin from `.env`
(`admin` / `admin` locally — set `BOOTSTRAP_ADMIN_EMAIL` / `BOOTSTRAP_ADMIN_PASSWORD` in `.env` before any shared deployment). To fill the demo with a realistic picture (multi-stream scan,
cloaked kits, verdicts, a mapped campaign, a trained classifier):

```powershell
python scripts/seed_demo.py --base http://127.0.0.1:8765
```

Optional real browser worker for live mode: `pip install -e ".[browser]"` then
`python -m playwright install chromium`. JSON API and interactive docs at `/docs`.

> PyPI blocked? Use a mirror with binary wheels:
> `pip install -i https://pypi.tuna.tsinghua.edu.cn/simple --only-binary=:all: -e ".[dev]"`.

## What the analyst sees

| Screen | What it answers |
|---|---|
| **Dashboard** (`/ui/dashboard`) | Live brand monitor: rotating 3D globe with arcs to where the kits are hosted, KPIs, threat level, score distribution, 14-day activity, which discovery stream actually finds phishing, pipeline stage stats, analyst metrics (precision, FP rate, MTTD, MTTC), budget meter, live event feed. |
| **Findings → Explain Finding** | Fired signals with plain-language evidence, group caps, bonuses/penalties, combination rules, confidence breakdown, cloaking probe comparison, suspect-vs-official screenshots, observation timeline, immutable evidence table, AI second opinion and classifier probability (both advisory). |
| **Attack infrastructure** | Interactive infrastructure graph, co-hosted triage (included/excluded + reason + AI verdict), actor profile (servers, certs, tracking ids, registrant, other brands hit), IOC export as CSV / JSON / STIX 2.1. |
| **Watchlist** | Every watched domain by state, with its finding, an evidence timeline, forced rescans and one-click *known legit* dismissal. |
| **Takedowns** | Every confirmed site and its takedown state; registrar / hosting / CDN contacts with pre-filled mail, 26 report portals, evidence packages (HTML + JSON). Nothing is ever sent automatically. |
| **How it works** | The pipeline with links into real data, an 8-stop demo walkthrough, facts computed from the code, under-the-hood engineering, glossary. |
| **Brands** | Attack-surface baseline, scans, scoring editor with live re-score preview, whitelist. |
| **Settings** | Workspace budget, users & roles, encrypted provider keys, personal API tokens, tenants, classifier training. |

## Architecture by phase

| Phase | Delivered | Key modules |
|---|---|---|
| 0 Foundation | 44-table schema with DB-enforced invariants (immutable evidence triggers, one current score, dedup uniques, `ON DELETE RESTRICT`), SSRF-safe fetcher, provider abstraction with resilience + fallback + $0 mocks, jobs/events, auth | `db/`, `security/`, `providers/`, `jobs/`, `events/` |
| 1 Detection MVP | dnstwist discovery → normalize/dedup/pre-filter → evidence → signals → risk + confidence → Finding → Explain Finding → verdicts; golden dataset | `detection/{discovery,normalize,enrichment,analysis,scoring,finding,baseline,runner}.py` |
| 2 Evidence | Sandboxed Playwright worker (route-gated public-only egress, fresh browser per fetch), rendered-DOM login similarity, pHash + dHash + palette, evidence packages, takedown drafts, candidate timeline | `providers/impl/playwright_fetcher.py`, `detection/{dom,reports}.py` |
| 3 Continuous intelligence | CT / NRD / search / urlscan streams, watchlist scheduler (long-watch + expiry), trigger engine, Slack / Telegram / e-mail / digest notifications, real provider clients, Arq/Redis queue, SSE console | `detection/{sources,triggers,scheduler}.py`, `notifications.py`, `providers/impl/clients.py`, `jobs/arq_worker.py` |
| 4 Investigation | Budgeted BFS pivoting (reverse IP, certificates, favicon hash, tracking ids, registrant) with co-hosted triage and shared-hosting stop, campaign graph, Infrastructure signals for later scans, IOC normalisation + STIX 2.1 | `detection/investigation.py`, `api/campaigns.py` |
| 5 Advanced detection | Cloaking multi-probe (crawler UA, `?email=` parameter, search referer, a phone) as a real Chrome with matching headers + gated, budgeted Tier-4 probe through a residential and / or mobile proxy that adopts the victim's view; AI second opinion and AI co-hosted triage (strict JSON schema, untrusted-text framing, advisory only); logistic-regression classifier trained on analyst labels with k-fold validation | `detection/{cloaking,ai,ml}.py`, `api/ml.py` |
| 6 Productization | RBAC admin / analyst / viewer on API and UI, personal access tokens (hashed, read/write scope, expiry, revocation), provider keys in the DB with AES-256-GCM envelope encryption bound to workspace + provider, workspace budget inherited by brands, multi-tenant isolation, scoring editor with content-addressed scoring versions + live preview + re-score with history, FP whitelist, settings UI | `api/{admin,tokens}.py`, `keys.py`, `tenancy.py`, `detection/rescore.py`, `api/ui_settings.py` |

### Scoring in one paragraph

Signals carry points inside seven capped groups (Identity 20, Visual 30, Behavior 30,
Infrastructure 20, Reputation 15, Freshness 10, Evasion 25 → raw 0–150). Decisive clusters add a
bonus, false-positive indicators subtract, the raw value is normalised to 0–100 → Low / Medium /
High / Critical, and combination rules floor the severity (for example
`favicon_exact + screenshot_similarity_ge_90 + credential_form → ≥ Critical`). **Confidence** is a
separate axis (breadth, hard confirmers, completeness, provider agreement, minus unavailable
evidence). Every score stores its `scoring_version`; weights/thresholds/rules per version are
snapshotted, so an old finding stays interpretable after the weights change. AI and the
classifier are shown next to the score and never change it.

### Security & safety highlights

- Every attacker-supplied URL goes through the SSRF guard: resolve-then-validate, connection pinned
  to the validated IP (Host + SNI), redirects re-validated, size / time / content-type caps. The
  browser worker applies the same policy to every request the page makes.
- Evidence is append-only at the database level (triggers), with SHA-256 and provenance per row.
- Provider keys are envelope-encrypted, decrypted in memory only, shown as `…last4` only.
- Access tokens are stored as SHA-256 only; read tokens cap the holder at viewer rights.
- Page text sent to an LLM is truncated and framed as untrusted data; answers must match a strict schema.
- Residential proxies are used to *look* (evidence), never to interact with a target; Tier 4 is gated and budgeted.

## Running against PostgreSQL / Redis

```bash
docker compose up -d
```
```bash
set TEST_DATABASE_URL=postgresql+psycopg://brandwatch:brandwatch@localhost:5432/brandwatch && pytest -q
```

Set `QUEUE_BACKEND=arq` and `REDIS_URL=redis://localhost:6379/0`, then run the worker with
`arq brandwatch.jobs.arq_worker.WorkerSettings`. CI (`.github/workflows/ci.yml`) runs lint, the
suite on SQLite with Chromium, and the suite plus `alembic upgrade head` / `downgrade base` on
PostgreSQL 16 — with no live API keys.

Production checklist: set a real `SECRET_KEY` (≥ 32 bytes) and `LOCAL_KEK_B64` (or a KMS-held KEK),
`DEMO_MODE=false`, the provider keys you want (Settings → Provider API keys), a residential budget
if you want Tier 4, and run the browser worker in its own container with restricted egress.

## Definition of Done

All phase checklists from the spec are green:

- **0** migration with constraints · constraint, SSRF and provider-factory tests · `/health` + login · $0 CI
- **1** candidate → normalized/deduplicated → DNS/HTTP evidence → screenshot → risk + confidence → Finding → Explain Finding → evidence page → golden suite
- **2** sandboxed screenshots · rendered-DOM snapshots · visual similarity · reports · evidence timeline
- **3** CT + NRD + search + urlscan · watchlist scheduler · trigger engine · provider enrichment · notifications · Arq · SSE
- **4** VirusTotal / urlscan / Shodan / crt.sh clients · budgeted pivoting · campaign graph · IOC + STIX export
- **5** cloaking multi-probe · residential probe · AI triage / second opinion · ML classifier
- **6** full RBAC · multi-tenant · budget management · public API with tokens · case management

## Ethical & legal guardrails

Only monitor brands you are authorized to protect (your own, your employer's, or a fictional demo
brand — the demo uses the fictional ShopNova and NordBank). Discovery uses public data and respects
provider policies and rate limits. Takedowns are **drafts reviewed by a human** — never automatic
accusations. Phishing-kit handling is static-only, sandboxed and manual. Identify and report;
never retaliate or "hack back".

## License

Copyright © 2026 Itay Azulay. All rights reserved. The code is published for viewing only; no permission is
granted to use, copy, modify or distribute it without written consent. See [LICENSE](LICENSE).
