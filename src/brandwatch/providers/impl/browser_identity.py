"""What the sandboxed browser looks like to a site: a real person's Chrome, not a headless crawler.

Phishing kits and the bot checks in front of them look past the User-Agent: at Accept-Language, at the client hints
(``sec-ch-ua`` — headless Chromium sends "HeadlessChrome" there), at ``navigator.languages``, ``navigator.userAgentData``
and the time zone. A visit that pretends to be a person has to agree with itself on all of them, and with the address it
comes from: through a residential or mobile proxy in Israel the browser speaks Hebrew and lives in Asia/Jerusalem.

The crawler probe (profile ``bot``) stays an honest crawler: it is the control that tells a site which hides from
scanners apart from one that does not.
"""

from __future__ import annotations

from dataclasses import dataclass, field

CHROME_MAJOR = "124"
CHROME_FULL = "124.0.6367.207"
DESKTOP_UA = (f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
              f"Chrome/{CHROME_MAJOR}.0.0.0 Safari/537.36")  # fmt: skip
MOBILE_UA = (f"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) "
             f"Chrome/{CHROME_MAJOR}.0.0.0 Mobile Safari/537.36")  # fmt: skip

# the proxy's country → the language and time zone a person there has (the default: a US English browser)
COUNTRY_LOCALE: dict[str, tuple[str, str]] = {
    "us": ("en-US", "America/New_York"), "gb": ("en-GB", "Europe/London"), "uk": ("en-GB", "Europe/London"),
    "ie": ("en-IE", "Europe/Dublin"), "ca": ("en-CA", "America/Toronto"), "au": ("en-AU", "Australia/Sydney"),
    "nz": ("en-NZ", "Pacific/Auckland"), "in": ("en-IN", "Asia/Kolkata"), "sg": ("en-SG", "Asia/Singapore"),
    "za": ("en-ZA", "Africa/Johannesburg"), "il": ("he-IL", "Asia/Jerusalem"), "de": ("de-DE", "Europe/Berlin"),
    "at": ("de-AT", "Europe/Vienna"), "ch": ("de-CH", "Europe/Zurich"), "fr": ("fr-FR", "Europe/Paris"),
    "be": ("fr-BE", "Europe/Brussels"), "es": ("es-ES", "Europe/Madrid"), "mx": ("es-MX", "America/Mexico_City"),
    "ar": ("es-AR", "America/Argentina/Buenos_Aires"), "co": ("es-CO", "America/Bogota"), "it": ("it-IT", "Europe/Rome"),
    "nl": ("nl-NL", "Europe/Amsterdam"), "pt": ("pt-PT", "Europe/Lisbon"), "br": ("pt-BR", "America/Sao_Paulo"),
    "pl": ("pl-PL", "Europe/Warsaw"), "se": ("sv-SE", "Europe/Stockholm"), "no": ("nb-NO", "Europe/Oslo"),
    "dk": ("da-DK", "Europe/Copenhagen"), "fi": ("fi-FI", "Europe/Helsinki"), "ru": ("ru-RU", "Europe/Moscow"),
    "ua": ("uk-UA", "Europe/Kyiv"), "tr": ("tr-TR", "Europe/Istanbul"), "ae": ("ar-AE", "Asia/Dubai"),
    "sa": ("ar-SA", "Asia/Riyadh"), "eg": ("ar-EG", "Africa/Cairo"), "jp": ("ja-JP", "Asia/Tokyo"),
    "kr": ("ko-KR", "Asia/Seoul"), "cn": ("zh-CN", "Asia/Shanghai"), "hk": ("zh-HK", "Asia/Hong_Kong"),
    "tw": ("zh-TW", "Asia/Taipei"), "th": ("th-TH", "Asia/Bangkok"), "vn": ("vi-VN", "Asia/Ho_Chi_Minh"),
    "id": ("id-ID", "Asia/Jakarta"), "ph": ("en-PH", "Asia/Manila"), "my": ("ms-MY", "Asia/Kuala_Lumpur"),
}  # fmt: skip


def accept_language(locale: str) -> str:
    """What Chrome sends for one UI language: the locale, its language, then English as a fallback."""
    lang = locale.split("-")[0]
    if lang == "en":
        return f"{locale},en;q=0.9"
    return f"{locale},{lang};q=0.9,en-US;q=0.8,en;q=0.7"


def languages(locale: str) -> list[str]:
    """``navigator.languages`` for the same browser, in the same order as Accept-Language."""
    return [part.split(";")[0] for part in accept_language(locale).split(",")]


@dataclass(frozen=True)
class Identity:
    user_agent: str
    locale: str
    timezone: str
    mobile: bool
    accept_language: str
    platform: str  # navigator.platform
    ch_platform: str  # sec-ch-ua-platform
    ch_platform_version: str
    model: str
    languages: list[str] = field(default_factory=list)

    def brands(self, full: bool = False) -> list[dict[str, str]]:
        v = CHROME_FULL if full else CHROME_MAJOR
        return [{"brand": "Chromium", "version": v}, {"brand": "Google Chrome", "version": v},
                {"brand": "Not-A.Brand", "version": "99.0.0.0" if full else "99"}]  # fmt: skip

    def headers(self) -> dict[str, str]:
        """The request headers Chrome adds on its own (the browser fills in the sec-fetch-* ones per request)."""
        sec_ch_ua = ", ".join(f'"{b["brand"]}";v="{b["version"]}"' for b in self.brands())
        return {"Accept-Language": self.accept_language, "sec-ch-ua": sec_ch_ua,
                "sec-ch-ua-mobile": "?1" if self.mobile else "?0", "sec-ch-ua-platform": f'"{self.ch_platform}"'}  # fmt: skip

    def ua_override(self) -> dict:
        """``Network.setUserAgentOverride``: the same story in navigator.userAgentData and every sub-request."""
        return {
            # the plain list: Chrome adds the q-values itself ("he-IL,he" → "he-IL,he;q=0.9")
            "userAgent": self.user_agent, "acceptLanguage": ",".join(self.languages), "platform": self.platform,
            "userAgentMetadata": {
                "brands": self.brands(), "fullVersionList": self.brands(full=True), "fullVersion": CHROME_FULL,
                "platform": self.ch_platform, "platformVersion": self.ch_platform_version,
                "architecture": "" if self.mobile else "x86", "bitness": "" if self.mobile else "64",
                "model": self.model, "mobile": self.mobile, "wow64": False,
            },
        }  # fmt: skip

    def init_script(self) -> str:
        """Small things a page can read that headless Chromium gets wrong."""
        langs = ", ".join(f"'{x}'" for x in self.languages)
        return ("Object.defineProperty(navigator, 'webdriver', {get: () => undefined});"
                f"Object.defineProperty(navigator, 'languages', {{get: () => [{langs}]}});"
                f"Object.defineProperty(navigator, 'language', {{get: () => '{self.languages[0]}'}});"
                "if (!window.chrome) { window.chrome = {runtime: {}}; }")  # fmt: skip


def identity(country: str | None = None, *, mobile: bool = False) -> Identity:
    """A person's Chrome in ``country`` (an ISO code; unknown → US), on a Windows desktop or an Android phone."""
    locale, tz = COUNTRY_LOCALE.get((country or "us").lower(), COUNTRY_LOCALE["us"])
    return Identity(
        user_agent=MOBILE_UA if mobile else DESKTOP_UA, locale=locale, timezone=tz, mobile=mobile,
        accept_language=accept_language(locale), languages=languages(locale),
        platform="Linux armv8l" if mobile else "Win32", ch_platform="Android" if mobile else "Windows",
        ch_platform_version="14.0.0" if mobile else "15.0.0", model="Pixel 8" if mobile else "",
    )  # fmt: skip
