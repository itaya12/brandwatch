"""What the search-market picker needs: the countries and languages to choose from, and a brand's markets as the page shows them."""

from __future__ import annotations

from typing import Any

from brandwatch.detection import markets as m
from brandwatch.ui.flags import COUNTRY_NAMES

# countries a brand can be searched in beyond the ones the flags table names
EXTRA = {
    "AL": "Albania", "AM": "Armenia", "AZ": "Azerbaijan", "BA": "Bosnia and Herzegovina", "BH": "Bahrain", "BO": "Bolivia", "CR": "Costa Rica",
    "DO": "Dominican Republic", "DZ": "Algeria", "EC": "Ecuador", "GE": "Georgia", "GH": "Ghana", "GT": "Guatemala", "IQ": "Iraq", "JM": "Jamaica",
    "JO": "Jordan", "KH": "Cambodia", "KW": "Kuwait", "LB": "Lebanon", "LK": "Sri Lanka", "MA": "Morocco", "MK": "North Macedonia", "MT": "Malta",
    "NP": "Nepal", "OM": "Oman", "PE": "Peru", "PR": "Puerto Rico", "PY": "Paraguay", "QA": "Qatar", "TN": "Tunisia", "TZ": "Tanzania", "UG": "Uganda",
    "UY": "Uruguay", "UZ": "Uzbekistan", "VE": "Venezuela",
}  # fmt: skip


def market_data() -> dict[str, Any]:
    names = {**EXTRA, **COUNTRY_NAMES}
    return {
        "countries": [{"code": c.lower(), "name": n} for c, n in sorted(names.items(), key=lambda kv: kv[1])],
        "languages": [{"code": c, "name": n} for c, n in m.LANGUAGES],
        "defaults": dict(m.DEFAULT_LANG),
    }


def _get(detection: Any, key: str, default: Any = None) -> Any:
    return detection.get(key, default) if isinstance(detection, dict) else getattr(detection, key, default)


def markets_of(detection: Any) -> list[dict[str, Any]]:
    """The markets of a detection config (the older two fields mean one language for every country)."""
    mk = m.normalize(_get(detection, "search_markets") or [])
    return mk or m.from_legacy(_get(detection, "search_geo"), _get(detection, "search_lang"))


def pairs_of(detection: Any) -> list[tuple[str, str]]:
    return m.pairs(_get(detection, "search_geo"), _get(detection, "search_lang"), _get(detection, "search_markets"))
