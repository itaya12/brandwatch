"""The baseline follows the official site's Login / Sign-up links; suspicious pages are compared
with the official login page too; /login-style paths on candidates are a (small) signal."""

import uuid

from brandwatch.config.brand_config import ScoringConfig
from brandwatch.detection.analysis import analyze
from brandwatch.detection.baseline import BrandBaseline
from brandwatch.detection.enrichment import CollectedEvidence
from brandwatch.detection.html import auth_links

HOME = """<html><body>
<nav><a href="/features">Features</a><a href="/pricing">Pricing</a>
<a href="https://www.cryptohopper.com/login">Login</a>
<a class="btn" href="https://www.cryptohopper.com/signup?ref=nav">Sign up</a>
<a href="https://twitter.com/cryptohopper">Twitter</a>
<a href="https://app.cryptohopper.com/account">My account</a></nav></body></html>"""


def test_auth_links_are_found_by_text_or_path_and_stay_on_the_official_domain():
    links = auth_links(HOME, "https://www.cryptohopper.com/", {"cryptohopper.com"})
    kinds = [x["kind"] for x in links]
    assert kinds == ["login", "signup", "account"]
    assert links[0]["url"] == "https://www.cryptohopper.com/login"
    assert links[1]["url"].startswith("https://www.cryptohopper.com/signup")
    assert links[2]["url"] == "https://app.cryptohopper.com/account"  # subdomain of the brand
    # a path alone is enough, link text is not required
    only_path = auth_links(
        '<a href="/auth/sign-in"><img src="x.png"></a>', "https://x.example/", {"x.example"}
    )
    assert only_path and only_path[0]["kind"] == "login"


def _baseline(**kw) -> BrandBaseline:
    return BrandBaseline(
        brand_id=uuid.uuid4(), brand_key="cryptohopper", official_domains=("cryptohopper.com",),
        favicon_mmh3=None, favicon_phash=None, screenshot_phash="00ff00ff00ff00ff",
        screenshot_dhash=None, **kw,
    )  # fmt: skip


def _evidence(url: str, phash: str | None = None) -> CollectedEvidence:
    host = url.split("/")[2]
    ev = CollectedEvidence(
        candidate_id=uuid.uuid4(), url=url, host=host, registrable="cryptohoper.com"
    )
    ev.final_url = url
    ev.screenshot_phash = phash
    return ev


def test_candidate_screenshot_is_compared_with_the_login_page_too():
    login_phash = "ffffffff00000000"
    base = _baseline(login_screenshot_phash=login_phash)
    an = analyze(_evidence("https://cryptohoper.com/", phash=login_phash), base, ScoringConfig())
    assert "screenshot_similarity_ge_90" in an.signals
    det = an.details.get("signals", an.details)
    assert "login page" in det["screenshot_similarity"]
    an2 = analyze(
        _evidence("https://cryptohoper.com/", phash=login_phash), _baseline(), ScoringConfig()
    )
    assert "screenshot_similarity_ge_90" not in an2.signals  # homepage only: no match


def test_login_like_path_is_a_signal():
    an = analyze(_evidence("https://cryptohoper.com/account/sign-in"), _baseline(), ScoringConfig())
    assert "auth_path_in_url" in an.signals
    assert (
        "auth_path_in_url"
        not in analyze(
            _evidence("https://cryptohoper.com/blog"), _baseline(), ScoringConfig()
        ).signals
    )


def test_bot_challenge_pages_are_recognised():
    from brandwatch.detection.html import is_bot_challenge

    assert is_bot_challenge("Just a moment...", "<html><body>Checking your browser</body></html>")
    assert is_bot_challenge(
        None, '<div id="cf-chl-widget">Enable JavaScript and cookies to continue</div>'
    )
    assert not is_bot_challenge("CryptoHopper - Login", "<form><input type='password'></form>")
