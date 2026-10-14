"""How sure are we that a suspicious shop sells fakes? Three conclusions, and words that match them.

A low price, a Gmail address or a missing returns page justify a closer look; they do not prove
that the goods are counterfeit. So a shop finding carries a *conclusion*, and everything BrandWatch
writes in the brand's name — the takedown letter, the text for Meta's report forms — claims only
what that conclusion supports:

    suspicious_retailer    signs that justify an investigation; nothing claimed about the goods
    likely_counterfeit     independent evidence about the goods (price far below the official one,
                           reviews that mention fakes) *and* about the seller (not in the registry,
                           anonymous, a one-brand store posing as the brand, fraud reports)
    confirmed_counterfeit  direct proof only a person can supply: a test purchase, the brand's own
                           inspection of the product, a platform's or an authority's confirmation

BrandWatch proposes the first two from the shop checks (``system_level``); only an analyst can
confirm the third, with the proof written down (``validate``). The AI's opinion is advisory and
never moves the level.
"""

from __future__ import annotations

from typing import Any

LEVELS: dict[str, dict[str, str]] = {
    "suspicious_retailer": {
        "label": "Suspicious shop",
        "short": "suspicious",
        "help": "signs that justify a closer look — not proof that the goods are fake",
    },
    "likely_counterfeit": {
        "label": "Likely counterfeit seller",
        "short": "likely fake",
        "help": "independent evidence about the goods and about the seller point to counterfeits",
    },
    "confirmed_counterfeit": {
        "label": "Confirmed counterfeit",
        "short": "counterfeit",
        "help": "direct proof: a test purchase, the brand's inspection of the product, or a platform's confirmation",
    },
}
ORDER = list(LEVELS)
PROOFS: dict[str, str] = {
    "test_purchase": "a test purchase — the product received is not genuine",
    "brand_inspection": "the brand inspected the product photos / listing and confirmed they are fake",
    "platform_confirmation": "a platform, payment provider or authority confirmed the counterfeit sale",
    "customer_evidence": "a customer sent the fake product (photos / the item) to the brand",
}
MIN_PROOF_NOTE = 10  # characters: "how was it confirmed" must say something

# words in a search result that are about the goods (fakes), not just about a bad seller
COUNTERFEIT_WORDS = ("fake", "replica", "counterfeit", "knock-off", "knockoff", "זיוף", "מזויף", "מזויפות",
                     "מזויפים", "רפליקה", "חיקוי", "falso", "falsific", "réplica", "faux", "contrefaçon",
                     "fälschung", "gefälscht", "contraffa", "подделк", "реплик", "مزيف", "sahte", "podróbk")  # fmt: skip

# the evidence families: about the goods, and about the seller
GOODS = {"price": "the price is half the official price or less", "fake_reviews": "reviews say the goods are fake",
         "bundle": "one bundle price across many premium brands"}
SELLER = {
    "registry": "the company is not in the registry, is dissolved, or is another business",
    "anonymous": "the seller is anonymous — no company details, or nothing about it on Google",
    "brand_use": "a one-brand store or an ad page that uses the brand's name",
    "fraud_reviews": "reviews report a scam or orders that never arrived",
}


def _review_text(rec: dict[str, Any]) -> str:
    web = rec.get("web") or {}
    return " ".join(f"{w.get('title') or ''} {w.get('snippet') or ''}" for w in web.get("warnings") or []).lower()


def families(fired: dict[str, Any] | list[str], rec: dict[str, Any]) -> dict[str, list[str]]:
    """Which evidence families the fired shop signals belong to."""
    keys = set(fired)
    goods: list[str] = []
    seller: list[str] = []
    if "shop_price_far_below_official" in keys:
        goods.append("price")
    if "shop_multibrand_bundle" in keys:
        goods.append("bundle")
    reviews = _review_text(rec)
    if "shop_reviews_warn" in keys:
        if any(w in reviews for w in COUNTERFEIT_WORDS):
            goods.append("fake_reviews")
        seller.append("fraud_reviews")
    if keys & {"shop_company_not_in_registry", "shop_company_dissolved", "shop_company_name_mismatch"}:
        seller.append("registry")
    if keys & {"shop_no_company_details", "shop_no_web_presence"}:
        seller.append("anonymous")
    if keys & {"shop_brand_catalog", "shop_ad_page_uses_brand"}:
        seller.append("brand_use")
    return {"goods": goods, "seller": seller}


def system_level(fired: dict[str, Any], rec: dict[str, Any], severity: str) -> dict[str, Any]:
    """BrandWatch's own reading of the evidence: ``likely_counterfeit`` needs a High shop score,
    evidence about the goods and evidence about the seller; anything less is ``suspicious_retailer``.
    Also says what evidence would move it up a level."""
    fam = families(fired, rec)
    high = severity in ("high", "critical")
    likely = high and bool(fam["goods"]) and bool(fam["seller"])
    level = "likely_counterfeit" if likely else "suspicious_retailer"
    because = [GOODS[g] for g in fam["goods"]] + [SELLER[s] for s in fam["seller"]]
    nxt: list[str] = []
    if level == "suspicious_retailer":
        if not (rec.get("price") or {}).get("reference"):
            nxt.append("add the official price of the brand's products for this country in the brand profile — "
                       "a price at half or less is the main evidence of fake goods")  # fmt: skip
        elif not fam["goods"]:
            nxt.append("evidence about the goods: a price at half the official one or less, or reviews that say the goods are fake")
        if not fam["seller"]:
            nxt.append("evidence about the seller: the registry check, the company on Google, reviews")
        if not high and fam["goods"] and fam["seller"]:
            nxt.append("a High shop score — more of the checks have to fail")
        if not rec.get("external"):
            nxt.append("the registry, Google and AI checks did not run for this shop (only the first 15 shops of a scan get them)")
    nxt.append("for “Confirmed counterfeit”: a test purchase, the brand's inspection of the product, or a platform's confirmation")
    return {"level": level, "families": fam, "because": because, "next": nxt}


def effective_level(conclusion: dict[str, Any] | None, rec: dict[str, Any] | None) -> str:
    """The analyst's conclusion when there is one, else BrandWatch's proposal, else the safest."""
    if conclusion and conclusion.get("level") in LEVELS:
        return str(conclusion["level"])
    lvl = ((rec or {}).get("level") or {}).get("level") if isinstance((rec or {}).get("level"), dict) else None
    return lvl if lvl in LEVELS else "suspicious_retailer"


def validate(level: str, proof: str | None, note: str, system: str | None) -> None:
    """An analyst's conclusion: confirming counterfeits needs the proof written down; claiming more
    than BrandWatch's own reading needs a reason."""
    if level not in LEVELS:
        raise ValueError(f"unknown conclusion {level!r}")
    if level == "confirmed_counterfeit":
        if proof not in PROOFS:
            raise ValueError("“Confirmed counterfeit” needs the kind of proof (test purchase, the brand's inspection, …)")
        if len((note or "").strip()) < MIN_PROOF_NOTE:
            raise ValueError("“Confirmed counterfeit” needs a short description of the proof in the reason")
    elif system in LEVELS and ORDER.index(level) > ORDER.index(system) and not (note or "").strip():
        raise ValueError(f"the evidence supports “{LEVELS[system]['label']}”; say why you conclude “{LEVELS[level]['label']}”")


def record(level: str, proof: str | None, note: str, system: str | None, by: str, at: str) -> dict[str, Any]:
    return {"level": level, "proof": proof if level == "confirmed_counterfeit" else None, "note": (note or "").strip()[:500],
            "system_level": system, "by": by, "at": at}  # fmt: skip


# ------------------------------------------------------------------------------------ the words
def wording(level: str, brand: str, conclusion: dict[str, Any] | None = None) -> dict[str, str]:
    """What BrandWatch writes about the shop, per conclusion: the subject line, the claim, the request,
    and the sentence for Meta's report forms. Only ``confirmed_counterfeit`` says “counterfeit” as a fact."""
    if level == "confirmed_counterfeit":
        proof = PROOFS.get(str((conclusion or {}).get("proof")), "direct evidence")
        note = str((conclusion or {}).get("note") or "").strip()
        return {
            "subject": f"Shop selling counterfeit {brand} products — takedown request",
            "claim": (f"sells counterfeit {brand} products. This was confirmed by {proof}"
                      + (f" ({note})" if note else "") + "."),  # fmt: skip
            "ask": "We respectfully request that you suspend the domain / hosting for the content above and confirm when done.",
            "meta": f"a shop selling counterfeit {brand} products (confirmed by {proof})",
            "meta_reason": "Intellectual property → Counterfeit",
        }
    if level == "likely_counterfeit":
        return {
            "subject": f"Shop likely selling counterfeit {brand} products — request for review and takedown",
            "claim": (f"advertises {brand} products and, based on the evidence below, is likely selling counterfeit goods. "
                      "We have not yet made a test purchase."),  # fmt: skip
            "ask": "We request that you review the site against your acceptable-use policy and suspend the domain / hosting if it violates it.",
            "meta": f"a shop that is likely selling counterfeit {brand} products",
            "meta_reason": "Scam or fraud (or Intellectual property → Counterfeit, if you hold the trademark)",
        }
    return {
        "subject": f"Suspected fraudulent shop advertising {brand} products — request for review",
        "claim": (f"advertises {brand} products and shows the warning signs of a fraudulent shop listed below. "
                  "We have not established that its goods are counterfeit."),  # fmt: skip
        "ask": "We ask you to review the site against your acceptable-use policy and act as you see fit; the full evidence package is available on request.",
        "meta": f"a shop advertising {brand} products that shows the warning signs of a scam",
        "meta_reason": "Scam or fraud",
    }
