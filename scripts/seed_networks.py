"""Add the "one attack group, two brands" story to a running BrandWatch demo (DEMO_MODE=true).

    python scripts/seed_networks.py            # add CoinPilot and VaultPay, confirm their look-alikes, map and investigate them
    python scripts/seed_networks.py --reset    # remove those two brands first (the ShopNova story is not touched)

The story, as seen on /ui/campaigns/all:

* CoinPilot (crypto trading bots) has seven typo domains. Each forwards the visitor to the real site with the same affiliate id
  (``?atid=51803``) through the same redirect host (go-linkz.click): not phishing, but abuse: a stranger collects the commission and a
  third-party host can send the visitors anywhere tomorrow.
* VaultPay (payments) has four pixel clones of its sign-in page that post the password to a collection host.
* They are the same group: the VaultPay kits and four of the CoinPilot typos sit on one server (192.0.2.77), share one TLS certificate,
  one registrant e-mail, and the registrar bought them in the same weeks. The page shows ONE operation with two brands.

The recorded answers live in ``src/brandwatch/demo/networks/coinpilot_vaultpay.jsonl``; they are not part of the golden dataset.
Only talks to the local API; never contacts real providers.
"""

from __future__ import annotations

import argparse
import sys
import time

import httpx

BRANDS = {
    "CoinPilot": {
        "domains": ["coinpilot.io", "www.coinpilot.io"], "vertical": "fintech",
        "urls": [f"https://{h}/" for h in ("coinpilott.io", "coinpllot.io", "coinplot.io", "koinpilot.io", "cooinpilot.io", "coin-pilot.io", "coinpilot-bot.io")],
    },
    "VaultPay": {
        "domains": ["vaultpay.com", "www.vaultpay.com"], "vertical": "payments",
        "urls": [f"https://{h}/" for h in ("vaultpay-login.com", "vaultpay-secure.net", "vault-pay.co", "vaultpay-verify.com")],
    },
}


def wait(c: httpx.Client, job_id: str, timeout: float = 300) -> str:
    t0 = time.time()
    while time.time() - t0 < timeout:
        j = c.get(f"/api/jobs/{job_id}").json()
        if j["state"] in ("done", "failed", "cancelled"):
            return j["state"]
        time.sleep(1)
    raise TimeoutError(job_id)


def step(msg: str) -> None:
    print(f"· {msg}", flush=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8765")
    ap.add_argument("--email", default="admin")
    ap.add_argument("--password", default="admin")
    ap.add_argument("--reset", action="store_true", help="remove CoinPilot and VaultPay first")
    args = ap.parse_args()
    c = httpx.Client(base_url=args.base, timeout=120)
    if not c.get("/health").json().get("demo_mode"):
        print("refusing to seed: the server is not in DEMO_MODE", file=sys.stderr)
        return 2
    c.headers["Authorization"] = "Bearer " + c.post("/api/auth/login", json={"email": args.email, "password": args.password}).json()["access_token"]

    if args.reset:
        for b in c.get("/api/brands").json():
            if b["name"] in BRANDS:
                step(f"removed {b['name']} ({c.delete(f'/api/brands/{b['id']}').status_code})")

    ids: dict[str, str] = {}
    for name, spec in BRANDS.items():
        have = next((b for b in c.get("/api/brands").json() if b["name"] == name), None)
        brand = have or c.post("/api/brands", json={"name": name, "vertical": spec["vertical"], "domains": spec["domains"], "preset": "standard"}).json()
        ids[name] = brand["id"]
        # the story is told by hand: nothing maps or investigates by itself until the buttons are pressed
        c.patch(f"/api/brands/{brand['id']}/config", json={"detection": {"auto_map_on_confirm": False, "auto_investigate_on_confirm": False}})
        step(f"brand {name} {'(already there)' if have else 'created'}")
        j = c.post(f"/api/brands/{brand['id']}/scan-urls", json={"urls": spec["urls"]}).json()["job_id"]
        step(f"  scan of {len(spec['urls'])} look-alikes: {wait(c, j)}")
        n = 0
        for f in c.get("/api/findings", params={"brand_id": brand["id"], "state": "open", "limit": 200}).json():
            r = c.post(f"/api/findings/{f['id']}/confirm", json={"reason": "look-alike of the brand run by the same group (demo story)"})
            n += r.status_code < 300
        step(f"  confirmed {n}")

    # MAP ALL and INVESTIGATE ALL, the two buttons of the Attack infrastructure page, for both brands
    for name, bid in ids.items():
        r = c.post("/api/campaigns/map-all", json={"brand_id": bid}).json()
        if r.get("job_id"):
            step(f"{name}: MAP ALL {r['count']} sites: {wait(c, r['job_id'], 600)}")
        r = c.post("/api/campaigns/investigate-all", json={"brand_id": bid}).json()
        states = [wait(c, j, 600) for j in r.get("job_ids", [])]
        step(f"{name}: INVESTIGATE ALL {r.get('count', 0)} sites: {sorted(set(states)) or 'nothing to do'}")

    data = c.get("/api/campaigns/all-map").json()
    ops = [g for g in data["operations"] if len(g.get("brands") or []) > 1]
    print("\nready:", {k: data["stats"][k] for k in ("sites", "operations", "brands", "cross_brand_groups")})
    for g in ops:
        print(f"  {g['name']}  ·  {g['size']} sites  ·  brands: {', '.join(b['name'] + ' ×' + str(b['count']) for b in g['brands'])}  ·  {g['level']} {round(g['confidence'] * 100)}%")
    print(f"open {args.base}/ui/campaigns/all")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
