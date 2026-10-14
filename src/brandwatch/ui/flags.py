"""Country code → flag image + name. Windows renders no emoji flags, so flags are small PNGs from
flagcdn.com (public CDN, no key); the ISO code is the text fallback when the image cannot load."""

from __future__ import annotations

from markupsafe import Markup, escape

COUNTRY_NAMES: dict[str, str] = {
    "AE": "United Arab Emirates", "AR": "Argentina", "AT": "Austria", "AU": "Australia", "BD": "Bangladesh",
    "BE": "Belgium", "BG": "Bulgaria", "BR": "Brazil", "BY": "Belarus", "CA": "Canada", "CH": "Switzerland",
    "CL": "Chile", "CN": "China", "CO": "Colombia", "CY": "Cyprus", "CZ": "Czechia", "DE": "Germany",
    "DK": "Denmark", "EE": "Estonia", "EG": "Egypt", "ES": "Spain", "FI": "Finland", "FR": "France",
    "GB": "United Kingdom", "GR": "Greece", "HK": "Hong Kong", "HR": "Croatia", "HU": "Hungary",
    "ID": "Indonesia", "IE": "Ireland", "IL": "Israel", "IN": "India", "IR": "Iran", "IS": "Iceland",
    "IT": "Italy", "JP": "Japan", "KE": "Kenya", "KR": "South Korea", "KZ": "Kazakhstan", "LT": "Lithuania",
    "LU": "Luxembourg", "LV": "Latvia", "MD": "Moldova", "MX": "Mexico", "MY": "Malaysia", "NG": "Nigeria",
    "NL": "Netherlands", "NO": "Norway", "NZ": "New Zealand", "PA": "Panama", "PH": "Philippines",
    "PK": "Pakistan", "PL": "Poland", "PT": "Portugal", "RO": "Romania", "RS": "Serbia", "RU": "Russia",
    "SA": "Saudi Arabia", "SC": "Seychelles", "SE": "Sweden", "SG": "Singapore", "SI": "Slovenia",
    "SK": "Slovakia", "TH": "Thailand", "TR": "Türkiye", "TW": "Taiwan", "UA": "Ukraine", "US": "United States",
    "VN": "Vietnam", "ZA": "South Africa",
}  # fmt: skip


def country_name(cc: str | None) -> str:
    code = (cc or "").strip().upper()
    return COUNTRY_NAMES.get(code, code) if code else "unknown"


def flag_img(cc: str | None, size: int = 20) -> Markup:
    """``<img>`` of the flag (width ``size`` px, 4:3) with the code as alt/fallback text."""
    code = (cc or "").strip().lower()
    if len(code) != 2 or not code.isalpha():
        return Markup('<span class="flag flag-none" title="country unknown">🌐</span>')
    h = round(size * 3 / 4)
    return Markup(
        f'<img class="flag" src="https://flagcdn.com/w{40 if size > 20 else 20}/{code}.png" '
        f'width="{size}" height="{h}" alt="{escape(code.upper())}" title="{escape(country_name(code))}" '
        f'loading="lazy" onerror="this.replaceWith(document.createTextNode(this.alt))">'
    )
