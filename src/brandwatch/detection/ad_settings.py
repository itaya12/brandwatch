"""How far the Facebook / Instagram ad hunt of a retail brand goes — three numbers per brand, kept in
``brands.profile`` (a detection track never overwrites them):

    ads_per_search      ads read per search (one keyword × one country). Meta's Ad Library answers
                        about 30 ads a page; more ads = more pages, each one SearchApi request.
    ad_searches_max     searches per scan (keywords × countries); the rest are not searched.
    shops_checked_max   shops that get the paid checks (company registry, two Google searches, the
                        AI's opinion); shops beyond it get the free page checks only.

The cost shown next to them is an upper bound from the per-call prices: SearchApi ~$0.004 a request,
SerpApi ~$0.01 a search, the AI a fraction of a cent.
"""

from __future__ import annotations

import math
from typing import Any

AD_PAGE_SIZE = 30  # ads per Ad Library page (SearchApi answers ~30)
ADS_PER_SEARCH_OPTIONS = (30, 60, 100, 200)
ADS_PER_SEARCH_DEFAULT = 30
AD_SEARCHES_DEFAULT, AD_SEARCHES_MAX = 6, 20
SHOPS_CHECKED_DEFAULT, SHOPS_CHECKED_MAX = 15, 60
SEARCHAPI_USD, SERPAPI_USD, SHOP_AI_USD = 0.004, 0.01, 0.001


def _int(v: Any, default: int, lo: int, hi: int) -> int:
    try:
        return max(lo, min(hi, int(v)))
    except (TypeError, ValueError):
        return default


def settings(profile: dict[str, Any] | None) -> dict[str, int]:
    """The brand's three numbers, defaults filled in and clamped."""
    p = profile or {}
    return {
        "ads_per_search": _int(p.get("ads_per_search"), ADS_PER_SEARCH_DEFAULT, 10, 300),
        "ad_searches_max": _int(p.get("ad_searches_max"), AD_SEARCHES_DEFAULT, 1, AD_SEARCHES_MAX),
        "shops_checked_max": _int(p.get("shops_checked_max"), SHOPS_CHECKED_DEFAULT, 0, SHOPS_CHECKED_MAX),
    }


def pages_per_search(ads_per_search: int) -> int:
    return max(1, math.ceil(ads_per_search / AD_PAGE_SIZE))


def cost(profile: dict[str, Any] | None, *, keywords: int, countries: int) -> dict[str, Any]:
    """An upper bound per scan: the ad searches (pages × requests) and the paid shop checks."""
    s = settings(profile)
    searches = min(max(1, keywords) * max(1, countries), s["ad_searches_max"])
    requests = searches * pages_per_search(s["ads_per_search"])
    ads_usd = requests * SEARCHAPI_USD
    shops_usd = s["shops_checked_max"] * (2 * SERPAPI_USD + SHOP_AI_USD)
    return {**s, "searches": searches, "requests": requests, "ads_max": searches * s["ads_per_search"],
            "ads_usd": round(ads_usd, 3), "shops_usd": round(shops_usd, 3), "usd": round(ads_usd + shops_usd, 2)}  # fmt: skip
