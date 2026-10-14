"""Which registry checks a company number printed on a shop — by the number's kind and country.

    VAT number (DE123…)      → EU VIES
    Israel (ח.פ. / 9 digits)  → Israeli Registrar of Companies (data.gov.il)
    United Kingdom           → Companies House (free key)
    anything                 → OpenCorporates, when a key was added
    a company name           → GLEIF (LEI holders; only a *found* answer counts)

Registries are asked one by one; one that does not cover the number answers NOT_APPLICABLE and the
next is tried. When none can answer, the result is ``not_checked`` — never "valid". (The Google
search for the company in ``merchant.check_web`` covers every other country.)
"""

from __future__ import annotations

from typing import Any

from brandwatch.db.enums import ProviderStatus


def registries_for(kind: str, country: str) -> list[str]:
    cc = (country or "").upper()
    if kind == "vat":
        names = ["vies"]
    elif kind == "il" or cc == "IL":
        names = ["il_companies"]
    elif cc in ("GB", "UK"):
        names = ["companies_house"]
    else:
        names = []
    return [*names, "opencorporates"]


async def lookup_number(
    providers: Any, cid: dict[str, str], country: str, company_name: str | None
) -> dict[str, Any]:
    number = cid.get("number") or ""
    cc = (cid.get("country") or country or "").upper()
    tried: list[str] = []
    for name in registries_for(cid.get("kind", ""), cc):
        p = providers.single("registry", name)
        if p is None:  # live mode without the provider's key
            continue
        res = await p.lookup(number, cc, company_name)
        tried.append(name)
        if res.status is ProviderStatus.ERROR:
            continue
        if res.status in (ProviderStatus.POSITIVE, ProviderStatus.NEGATIVE):
            d = dict(res.data or {})
            status = (
                "not_found"
                if res.status is ProviderStatus.NEGATIVE
                else ("dissolved" if d.get("status") == "dissolved" else "found")
            )
            return {
                **d,
                "status": status,
                "number": d.get("number") or number,
                "provider": name,
                "label": cid.get("label"),
            }
    if company_name:
        p = providers.single("registry", "gleif")
        if p is not None:
            res = await p.lookup(number, cc, company_name)
            tried.append("gleif")
            if res.status is ProviderStatus.POSITIVE:
                d = dict(res.data or {})
                return {
                    **d,
                    "status": "dissolved" if d.get("status") == "dissolved" else "found",
                    "provider": "gleif",
                    "label": cid.get("label"),
                }
    why = (
        f"no registry BrandWatch can query for {cc or 'this country'}"
        if not tried
        else f"not covered by {', '.join(tried)}"
    )
    return {"status": "not_checked", "number": number, "why": why, "label": cid.get("label")}
