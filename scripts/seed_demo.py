"""Populate a running BrandWatch (demo mode) with a clean, self-consistent demo story.

    python scripts/seed_demo.py --reset          # wipe every brand, then seed the story (~90 s)
    python scripts/seed_demo.py                  # seed on top of what is there (idempotent-ish)

The story, in the order an interviewer will see it:

1. ShopNova (shopnova.com) is onboarded on the Deep track; a partner domain is whitelisted; the
   AI's Google queries are approved (Google search runs only with an approved list).
2. A brand scan fingerprints the real site and discovers look-alikes on every stream; the recorded
   golden URLs (incl. three cloaked kits) are scanned too.
3. An analyst confirms three phishing sites (shopn0va.com, shopnova-login.com, shopnova-refund.net)
   and dismisses an other-brand kit; **shopnova-giftcard.com is left open** so the live demo can
   confirm it on stage (which maps its infrastructure automatically).
4. shopn0va.com's attacker infrastructure is mapped; its takedown goes draft → review → approved →
   sent with the hosting provider notified and three report portals ticked.
5. Site & network intel is pre-fetched for the findings the demo opens; the advisory classifier is
   trained on the golden labels; a read-only API token "SIEM export (read)" exists.
6. ShopNova is a brand whose products other shops resell: its profile (Israel + US, ad keyword
   "shopnova runner", official prices, an authorised retailer) makes the brand scan search Meta ads,
   which leads to three scam shops — "Suspicious shop" findings — and one genuine retailer.
7. Social media: the brand scan also finds Facebook pages / Instagram profiles under the ShopNova name —
   a fake "ShopNova Support" page and a fake "ShopNova Israel | Official" giveaway profile become
   "fake social account" findings; the fan club is watched, a bakery that only shares half the name
   and ShopNova's own verified accounts are skipped.

Only talks to the local API; never contacts real providers (the server must run with DEMO_MODE=true).
"""

from __future__ import annotations

import argparse
import sys
import time

import httpx

GOLDEN_URLS = [
    "https://shopn0va.com/", "https://shopnova-login.com/", "https://secure-shopnova.com/account",
    "https://shopnova-verify.com/", "https://shopnowa.com/", "https://shoqnova.com/login",
    "https://shopnova-account.net/", "https://shopnova-support-center.com/", "https://shopnova.co/",
    "https://xn--shopnov-8fg.com/", "https://shopnova-giftcard.com/", "https://shopnova-refund.net/",
    "https://shopnova-verification.com/", "https://shopnova-partners.com/", "https://shopnova-blog.net/",
    "https://shopnovafans.com/", "https://shopnova-reviews.com/", "https://shopnova-careers.com/",
    "https://shopnova-status.com/", "https://shopnova-support.com/", "https://shopnova-coupons.com/",
    "https://shopnova-outlet-store.com/", "https://shopnovaa.com/", "https://shop-nova.com/",
    "https://weatherly-forecasts.org/", "https://trailrunners-club.org/", "https://nordbank-verify.com/",
]  # fmt: skip
CONFIRM = ("shopn0va.com", "shopnova-login.com", "shopnova-refund.net")
LEAVE_OPEN = "shopnova-giftcard.com"  # confirmed live during the demo
INTEL_FOR = ("shopnova-giftcard.com", "shopn0va.com", "shopnova-refund.net")  # incl. WHOIS history
PORTALS = ("google_safebrowsing", "netcraft", "apwg")


def wait(c: httpx.Client, job_id: str, timeout: float = 300) -> dict:
    t0 = time.time()
    while time.time() - t0 < timeout:
        j = c.get(f"/api/jobs/{job_id}").json()
        if j["state"] in ("done", "failed", "cancelled"):
            return j
        time.sleep(1)
    raise TimeoutError(job_id)


def step(msg: str) -> None:
    print(f"· {msg}", flush=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8765")
    ap.add_argument("--email", default="admin")
    ap.add_argument("--password", default="admin")
    ap.add_argument("--reset", action="store_true", help="delete every brand first (demo servers only)")
    args = ap.parse_args()
    c = httpx.Client(base_url=args.base, timeout=120)
    health = c.get("/health").json()
    if not health.get("demo_mode"):
        print("refusing to seed: the server is not in DEMO_MODE", file=sys.stderr)
        return 2
    token = c.post("/api/auth/login", json={"email": args.email, "password": args.password}).json()
    c.headers["Authorization"] = "Bearer " + token["access_token"]

    # --- 0. a clean slate --------------------------------------------------------------------
    for b in c.get("/api/brands").json():
        dup = "shopnova.com" in b["domains"] and b["name"] != "ShopNova"
        if args.reset or dup:
            r = c.delete(f"/api/brands/{b['id']}")
            step(f"deleted brand {b['name']} ({r.status_code})")

    # --- 1. onboard ------------------------------------------------------------------------------
    brands = [b for b in c.get("/api/brands").json() if b["name"] == "ShopNova"]
    brand = brands[0] if brands else c.post(
        "/api/brands",
        json={"name": "ShopNova", "vertical": "ecommerce", "domains": ["shopnova.com", "www.shopnova.com"],
              "preset": "enterprise", "kind": "retail"},
    ).json()  # fmt: skip
    bid = brand["id"]
    step(f"brand ShopNova {bid}")
    # seed the story by hand: no automatic infrastructure mapping until the end
    c.patch(f"/api/brands/{bid}/config", json={"detection": {
        "streams": ["dnstwist", "ct", "search", "urlscan"], "max_candidates": 120, "auto_map_on_confirm": False,
    }})  # fmt: skip
    c.post(f"/api/brands/{bid}/whitelist", json={"domain": "shopnova-partners.com", "kind": "partner"})
    # products other shops resell: Meta ads in Israel and the US, official prices per country
    c.put(f"/api/brands/{bid}/profile", json={
        "kind": "retail", "countries": ["IL", "US"], "ad_keywords": ["shopnova runner"],
        "official_social": ["https://www.facebook.com/shopnova", "https://www.instagram.com/shopnova/"],
        "products": [{"name": "ShopNova Runner", "price": 799, "currency": "ILS", "country": "IL", "source": "analyst"},
                     {"name": "ShopNova Trail", "price": 949, "currency": "ILS", "country": "IL", "source": "analyst"},
                     {"name": "ShopNova Runner", "price": 150, "currency": "USD", "country": "US", "source": "analyst"}],
    })  # fmt: skip
    step("brand profile: retail · IL, US · official prices")
    # Google is searched only with queries an analyst approved: take the AI's proposal as it is
    sugg = c.post(f"/api/brands/{bid}/search-queries/suggest").json()
    c.put(f"/api/brands/{bid}/search-queries", json={"queries": sugg.get("queries") or ["shopnova login", "shopnova"]})
    step(f"Google queries approved: {len(sugg.get('queries') or [])}")

    # --- 2. discover -----------------------------------------------------------------------------
    j = c.post(f"/api/brands/{bid}/scan", json={"max_candidates": 120}).json()["job_id"]
    step(f"brand scan {wait(c, j)['state']}")
    j = c.post(f"/api/brands/{bid}/scan-urls", json={"urls": GOLDEN_URLS}).json()["job_id"]
    step(f"golden URL scan {wait(c, j)['state']}")

    # --- 3. verdicts -----------------------------------------------------------------------------
    findings = {f["hostname"]: f for f in c.get("/api/findings", params={"brand_id": bid, "state": "open", "limit": 500}).json()}
    for host in CONFIRM:
        f = findings.get(host)
        if f:
            c.post(f"/api/findings/{f['id']}/confirm", json={"reason": "cloned ShopNova login page, verified by analyst"})
            step(f"confirmed {host}")
    nb = findings.get("nordbank-verify.com")
    if nb:
        c.post(f"/api/findings/{nb['id']}/dismiss",
               json={"reason": "phishing for another brand (NordBank), not ShopNova", "verdict": "legitimate"})
        step("dismissed nordbank-verify.com (other brand)")

    # --- 4. map the attacker + takedown ------------------------------------------------------------
    seed = findings.get("shopn0va.com")
    if seed:
        r = c.post(f"/api/findings/{seed['id']}/investigate")
        if r.status_code == 202:
            step(f"attack infrastructure mapped: {wait(c, r.json()['job_id'])['state']}")
        c.post(f"/api/findings/{seed['id']}/report")
        td = c.post(f"/api/findings/{seed['id']}/takedown").json()
        tid = td["id"]
        c.patch(f"/api/takedowns/{tid}", json={"abuse_contact": td.get("abuse_contact") or "abuse@mock-registrar.example"})
        for to in ("review", "approved", "sent"):
            c.post(f"/api/takedowns/{tid}/transition", json={"to": to, "reason": f"demo story: {to}"})
        t = c.get(f"/api/takedowns/{tid}").json()
        hosting = (t.get("channels") or {}).get("resolved", {}).get("hosting") or []
        if hosting:
            c.post(f"/api/takedowns/{tid}/channels", json={"channel": f"hosting:{hosting[0]['ip']}",
                                                          "contact": hosting[0].get("email") or "abuse@bulletproof-host.example", "sent": True})  # fmt: skip
        for portal in PORTALS:
            c.post(f"/api/takedowns/{tid}/reports/{portal}")
        step(f"takedown {t['reference']} → sent · {len(PORTALS)} portals reported")

    # --- 5. intel, classifier, API token ------------------------------------------------------------
    for host in INTEL_FOR:
        f = findings.get(host)
        if f:
            r = c.post(f"/api/findings/{f['id']}/intel")
            if r.status_code == 202:
                step(f"site & network intel for {host}: {wait(c, r.json()['job_id'])['state']}")
    r = c.post("/api/ml/train", json={"source": "golden"})
    step(f"classifier {r.json().get('version')} {r.json().get('metrics')}")
    if not any(t["name"] == "SIEM export (read)" for t in c.get("/api/tokens").json()):
        c.post("/api/tokens", json={"name": "SIEM export (read)", "scope": "read"})
        step("API token 'SIEM export (read)' created")

    # the live demo: confirming the open site maps its infrastructure automatically
    c.patch(f"/api/brands/{bid}/config", json={"detection": {"auto_map_on_confirm": True}})

    d = c.get("/api/dashboard", params={"brand_id": bid}).json()["kpis"]
    print("\nready:", {k: d[k] for k in ("candidates_total", "findings_open", "findings_confirmed", "critical_open",
                                         "campaigns", "iocs", "confirmed_no_takedown")})  # fmt: skip
    left = findings.get(LEAVE_OPEN)
    if left:
        print(f"demo: open {args.base}/ui/findings/{left['id']} and press Confirm phishing")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
