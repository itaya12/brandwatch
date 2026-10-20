"""One vocabulary for every screen.

Internal identifiers (``age_lt_30d``, ``long_watch``, ``serpapi``) never reach a page as-is: every
template renders them through the Jinja filters registered here, so the same concept has the same
name everywhere and every term carries a one-line explanation (``?`` tooltips, page intros and the
glossary on the How-it-works page all come from this module).
"""

from __future__ import annotations

from typing import Any

from markupsafe import Markup, escape

from brandwatch.config.brand_config import SIGNAL_GROUPS

N_SIGNALS = len(SIGNAL_GROUPS)  # the real number, never typed by hand

# signal id → (short label shown on pills, one sentence of evidence)
SIGNAL_LABELS: dict[str, tuple[str, str]] = {
    "brand_exact_in_domain": ("brand name in the domain", "the exact brand name is part of the domain name"),
    "brand_tld_swap": ("brand on another TLD", "the brand's own name registered on a different top-level domain"),
    "title_claims_brand": ("page title claims the brand", "the page <title> says it is the brand"),
    "brand_in_subdomain": ("brand in a subdomain", "the brand name hides in a subdomain of someone else's domain"),
    "brand_in_path": ("brand in the URL path", "the brand name appears in the URL path"),
    "app_listing_brand_title": ("fake app listing (title)", "an app-store / APK listing uses the brand's name"),
    "app_listing_brand_description": ("fake app listing (text)", "an app listing describes itself as the brand"),
    "homoglyph_idn": ("look-alike characters", "Unicode characters that look like Latin letters (homoglyphs)"),
    "combosquat": ("brand + extra word", "the brand combined with a word such as login, secure or support"),
    "levenshtein_le_2": ("1–2 typos away", "the domain is one or two keystrokes from the real one"),
    "favicon_exact": ("identical favicon", "the site icon is byte-for-byte the brand's icon (mmh3 hash)"),
    "favicon_phash_near": ("near-identical favicon", "the icon looks the same to the eye (perceptual hash)"),
    "logo_detected": ("brand logo on the page", "the brand's logo was found in the page"),
    "looks_like_brand_ge_85": ("looks 85%+ like the real site", "the screenshot is at least 85% similar to the real site's homepage (the \u201cLooks like\u201d percentage on the finding page): a copy that good is rated very high (Critical) whatever else is known"),
    "screenshot_similarity_ge_90": ("looks like the real site", "the screenshot is ≥ 90% similar to the official site"),
    "login_dom_similarity": ("cloned login form", "the login form's structure matches the official one"),
    "palette_match": ("same colours", "the page uses the brand's colour palette"),
    "credential_form": ("asks for a password", "a form collects a username / password"),
    "payment_form": ("asks for card details", "a form collects payment-card data"),
    "seed_phrase_field": ("asks for a wallet seed", "a form collects a crypto wallet recovery phrase"),
    "brand_keywords_in_content": ("brand words in the text", "the page text uses the brand's own keywords"),
    "auth_path_in_url": ("login-style URL", "the URL path looks like a login / verify page"),
    "lure_language": ("urgent lure wording", "'verify within 24 hours', 'account suspended' …"),
    "external_form_action": ("sends data elsewhere", "the form posts to another domain (data exfiltration)"),
    "password_prefill": ("pre-filled victim e-mail", "the victim's e-mail is pre-filled from the link"),
    "bad_reputation_asn": ("bad-reputation network", "hosted on a network known for abuse"),
    "cohosted_with_known_phish": ("shares a server with phishing", "same IP as a known phishing site"),
    "cert_shared_with_phish": ("shares a certificate with phishing", "same TLS certificate as a known phishing site"),
    "tracking_id_shared": ("same tracking ID as phishing", "same analytics / pixel ID as a known phishing site"),
    "linked_to_known_campaign": ("linked to a mapped attacker", "part of an attack infrastructure already mapped"),
    "affiliate_redirect": ("forwards with an affiliate id", "the visit ends on the brand's own site after a link that carries an affiliate id: not phishing, but the commission on everything the visitor buys goes to a stranger, and the brand pays it on its own traffic"),
    "redirect_via_third_party": ("forwards through another host", "the visit ends on the brand's own site, but through a third-party redirect host (a short link, a traffic broker): it can send the visitor to a phishing page tomorrow without the look-alike changing"),
    "redirect_from_suspect": ("a flagged site redirects here", "a look-alike BrandWatch already rated High sends its visitors to this address: same operator, same verdict"),
    "vt_flagged": ("flagged on VirusTotal", "security vendors on VirusTotal flag this domain"),
    "urlhaus_listed": ("listed on URLhaus", "the abuse.ch malware-URL feed lists it"),
    "phishtank_listed": ("listed on PhishTank", "the PhishTank community feed lists it"),
    "safe_browsing": ("Google Safe Browsing warns", "Google Safe Browsing flags it"),
    "age_lt_7d": ("registered < 7 days ago", "brand-new domain: phishing domains are usually days old"),
    "age_lt_30d": ("registered < 30 days ago", "young domain"),
    "cert_age_lt_7d": ("certificate < 7 days old", "TLS certificate issued in the last week"),
    "woke_up_in_watch": ("woke up while watched", "was parked / empty and suddenly started serving a page"),
    "cloaking_ip_based": ("hides from datacenter IPs", "shows the phishing page only to home (residential) or mobile-network IPs"),
    "cloaking_ua_based": ("hides from scanners", "shows a decoy to crawler / bot user-agents"),
    "parameter_gating": ("needs a victim link", "the kit only opens with a parameter from the phishing e-mail"),
    "device_gating": ("only a phone sees it", "the login form is shown to a mobile browser only: a desktop scanner sees a harmless page"),
    "referer_gating": ("needs a search referer", "the kit only opens when arriving from a search result"),
    "clickfix_lure": ("makes the visitor run a command", "a fake human-verification (often a copy of Cloudflare's) tells the visitor to press Win+R, paste and press Enter, which runs malware (the ClickFix lure), and may lock the browser full screen. BrandWatch only reads it; it never follows the steps"),
    "known_phishing": ("already flagged as phishing", "a security service (Cloudflare, an antivirus, a DNS filter, Google Safe Browsing, PhishTank, several VirusTotal engines) has already judged this site phishing — rated High without needing a deeper look"),
    "cloudflare_phishing_warning": ("Cloudflare blocks it as phishing", "Cloudflare, which serves the site, shows its own “Suspected Phishing” warning instead of it — a trust-and-safety verdict"),
    "bot_blocking": ("blocks bots", "the site showed BrandWatch a bot check / CAPTCHA, or refused it outright (the finding shows the screenshot, who was challenged and why)"),
    # suspicious shops (detection/merchant.py — a separate score, never part of the phishing one)
    "shop_company_not_in_registry": ("company number not in the registry", "the company number printed on the shop does not exist in its country's registry"),
    "shop_company_dissolved": ("company dissolved", "the company printed on the shop is dissolved or in liquidation"),
    "shop_price_far_below_official": ("half the official price or less", "the price per item is at most half the brand's official price — the classic replica bait"),
    "shop_reviews_warn": ("reviews say scam / replica", "a search result about the shop mentions a scam, fake goods or orders that never arrived"),
    "shop_no_policy_pages": ("no privacy / terms / returns", "a real shop links its privacy policy, terms and returns policy"),
    "shop_free_email_only": ("Gmail-type contact only", "the only contact e-mail is a free mailbox, not one on the shop's own domain"),
    "shop_new_domain": ("new domain", "the shop's domain was registered less than 90 days ago"),
    "shop_no_web_presence": ("no footprint on Google", "Google finds nothing about the company or the shop outside the shop itself"),
    "shop_no_company_details": ("no company details", "no company name or registration number anywhere on the page"),
    "shop_tld_language_mismatch": ("local language, generic domain", "a .com-style domain with a page in the country's language — a local shop without the local domain ending"),
    "shop_chat_or_phone_only": ("WhatsApp / phone only", "contact is WhatsApp or a phone number, with no e-mail on the shop's own domain"),
    "shop_multibuy_bait": ("multi-buy offer", "“2 pairs for …” style offers, typical of replica shops"),
    "shop_ad_page_uses_brand": ("ad page uses the brand's name", "the Facebook / Instagram page running the ads is named after the brand but is not the brand's page"),
    "shop_brand_catalog": ("one-brand catalogue", "the shop lists several of the brand's product lines without being an authorised retailer"),
    "shop_deep_discounts": ("invented discounts", "several items marked down by half or more from a “regular price”"),
    "shop_young_domain": ("young domain", "the shop's domain is less than a year old"),
    "shop_multibrand_bundle": ("one price, many premium brands", "a single “2 pairs for …” price on a shop that sells a dozen premium brands — a replica catalogue"),
    "shop_company_name_mismatch": ("borrowed company number", "the company number on the shop belongs to another business in the registry"),
    # fake social accounts (detection/social.py — a separate score)
    "social_ai_impersonation": ("AI: impersonation", "the AI read the account's content and says it poses as the brand (advisory, at most 20 points)"),
    "social_claims_official": ("claims to be the brand", "the name or bio calls the account the brand's official / support / help account"),
    "social_logo_match": ("uses the brand's logo", "the profile picture matches the brand's logo"),
    "social_links_off_brand": ("links off the brand", "the bio or page links to a site that is not one of the brand's"),
    "social_scam_lures": ("scam lures", "refunds, giveaways, “DM us your order / card”, crypto, pay-only-shipping"),
    "social_new_account": ("new page", "the page was created less than six months ago"),
    "social_renamed": ("renamed page", "the page changed its name (Meta's page history) — scammers rename old pages"),
    "social_exact_brand_name": ("exactly the brand's name", "uses the brand's exact name without Meta's verified badge"),
    "social_admins_abroad": ("run from abroad", "the page's admins are in countries the brand does not operate in"),
    "social_small_audience": ("tiny audience", "under 1,000 followers / likes for an account under the brand's name"),
    "social_verified": ("verified by Meta", "carries Meta's blue verified badge"),
    "social_says_unofficial": ("says it is unofficial", "calls itself a fan page / unofficial / not affiliated"),
    # AI answers (detection/ai_answers.py — a separate score)
    "ai_contact_not_on_site": ("not on the brand's site", "an AI assistant gives this phone / e-mail / short code, and no page of the brand's website carries it"),
    "ai_url_not_official": ("sends users elsewhere", "an AI assistant sends people who ask about the brand to a site that is not one of its domains"),
    "ai_known_suspect": ("a known phishing site", "the page that publishes it (or the address given) is a phishing site BrandWatch already found"),
    "ai_offsite_lookalike": ("published by a look-alike", "the only page that carries it has the brand's name in a domain the brand does not own"),
    "ai_offsite_page": ("published off the brand's site", "the contact appears only on pages that are not the brand's"),
    "ai_retracted": ("the AI took it back", "asked for the official page, the assistant said it was a mistake"),
    "ai_cited_page_missing": ("the cited page does not say it", "BrandWatch opened the pages the assistant cited: none of them carries the contact"),
    "ai_several_engines": ("several assistants say it", "two or more assistants give the same wrong contact"),
    "ai_no_source": ("no source given", "asked for the proof, the assistant cited no page"),
}  # fmt: skip

GROUP_LABELS: dict[str, tuple[str, str]] = {
    "identity": ("Identity", "does the name pretend to be the brand?"),
    "visual": ("Visual", "does it look like the real site?"),
    "behavior": ("Behaviour", "what does the page try to make a victim do?"),
    "infrastructure": ("Infrastructure", "is it hosted alongside known phishing?"),
    "reputation": ("Reputation", "do public blocklists already know it?"),
    "freshness": ("Freshness", "how new is it?"),
    "evasion": ("Evasion", "does it hide from scanners (cloaking)?"),
    "merchant": ("Shop", "does it behave like a real, registered shop?"),
    # suspicious shops (shop-v2): related signals share a group and a cap, so one cause counts once
    "seller": ("Seller", "who is behind the shop — registry, company details, a footprint on Google"),
    "offer": ("Offer", "what it sells and for how much — price vs the official one, invented discounts, multi-buy"),
    "brand": ("Brand use", "a one-brand store or an ad page named after the brand"),
    "contact": ("Contact & policies", "free-mail or WhatsApp only, no privacy / terms / returns pages"),
    "ai": ("AI reading", "what the AI concluded from the account's content (advisory, capped)"),
    "evidence": ("Proof", "what the pages the assistant cited really say, and whether it took the answer back"),
    "breadth": ("Breadth", "how many assistants give the same answer"),
}

RULE_LABELS: dict[str, str] = {
    "pixel_clone_login": "pixel-perfect clone with a login form (favicon + screenshot + password form)",
    "cloaked_clone": "a clone that hides from scanners",
    "fresh_lookalike_login": "a days-old look-alike asking for a password",
    "crypto_seed_harvest": "harvests crypto wallet seed phrases",
    "exact_brand_impersonation": "the exact brand name on another TLD, calling itself the brand",
    "exact_brand_login": "the exact brand name plus a login page",
    "brand_title_login": "titled as the brand and asking for a password",
    "campaign_linked_login": "a login page tied to an already-mapped attacker",
    "cloudflare_flagged_lookalike": "the brand's name in the address, and Cloudflare already blocks it as phishing",
    "cloudflare_flagged_typo": "a typo of the brand's domain that Cloudflare already blocks as phishing",
}

FP_LABELS: dict[str, str] = {
    "age_gt_2y": "domain older than 2 years (phishing domains are usually young)",
    "redirects_to_official": "redirects to the official site",
    "ev_cert_matches_brand": "an extended-validation certificate issued to the brand",
    "hosted_on_brand_asn_or_cdn": "hosted on the brand's own network / CDN",
    "whois_registrant_is_brand": "registered by the brand itself",
    "shop_company_registered": "an active company in its country's registry, with the shop's name",
    "shop_established_domain": "the shop's domain is more than three years old",
    "shop_established_company": "registered company and an old domain (shop-v1)",
}

STREAM_LABELS: dict[str, str] = {
    "dnstwist": "Look-alike names",
    "ct": "Certificate logs",
    "crtsh": "Certificate logs",
    "certspotter": "Certificate logs",
    "nrd": "New-domain feed",
    "search": "Google search",
    "serpapi": "Google search",
    "serper": "Google search",
    "scraperapi": "Google search",
    "urlscan": "urlscan archive",
    "manual": "Analyst URL scan",
    "pivot": "Infrastructure pivot",
    "meta_ads": "Facebook / Instagram ads",
    "social": "Facebook pages / Instagram profiles",
    "redirect": "Redirect from a flagged site",
    "ai_answer": "AI answer (ChatGPT / Gemini / Google AI Mode)",
}

STATE_LABELS: dict[str, str] = {
    # candidates
    "new": "new",
    "watching": "watching",
    "analyzing": "analysing",
    "flagged": "flagged (finding)",
    "long_watch": "long watch",
    "dismissed": "dismissed",
    # findings
    "open": "awaiting verdict",
    "confirmed": "confirmed phishing",
    "confirmed_social": "confirmed fake account",
    "confirmed_shop": "confirmed scam shop",
    # takedowns
    "none": "no takedown yet",
    "draft": "draft",
    "review": "in review",
    "approved": "approved",
    "sent": "sent",
    "acknowledged": "acknowledged",
    "in_progress": "in progress",
    "resolved": "taken down",
    "rejected": "rejected",
    "reopened": "reopened",
    # jobs
    "queued": "queued",
    "running": "running",
    "done": "done",
    "failed": "failed",
    "cancelled": "stopped",
}

STATE_HELP: dict[str, str] = {
    "new": "just discovered, not visited yet",
    "watching": "visited, below the finding threshold: re-checked on a schedule",
    "flagged": "scored Medium or higher: there is a finding for it",
    "long_watch": "quiet for the whole watch window: checked less often, then expires",
    "dismissed": "dead, legitimate, whitelisted or dismissed by an analyst",
    "open": "a finding no analyst has judged yet",
    "confirmed": "an analyst confirmed it as phishing",
    "review": "four-eyes check before anything is sent",
    "approved": "ready to send from the analyst's own mailbox",
    "sent": "recorded by the analyst after mailing it from their own mailbox",
    "resolved": "the site is down",
}

SURFACE_LABELS: dict[str, str] = {"name": "domain name", "subdomain": "subdomain", "path": "URL path",
                                  "app": "app listing", "social": "social profile"}  # fmt: skip

JOB_LABELS: dict[str, str] = {"brand_scan": "brand scan", "url_scan": "URL scan",
                              "investigate": "infrastructure map", "intel": "site intel", "map_all": "map all"}  # fmt: skip

# which part of BrandWatch each key feeds (the tags on Settings → API keys, and the "Start here" checklist)
KEY_USED_BY: dict[str, list[str]] = {
    "virustotal": ["every track", "the site investigation"], "urlhaus": ["every track"], "safebrowsing": ["every track"],
    "abuseipdb": ["the site investigation"], "serpapi": ["Google search"], "scraperapi": ["Google search (fallback)"],
    "urlscan": ["Standard · Deep", "the site investigation"], "shodan": ["the infrastructure map"],
    "whoisxml": ["WHOIS history", "WHOIS by service"], "searchapi": ["social media", "ads", "AI answers"],
    "companies_house": ["scam-shop checks (UK)"], "opencorporates": ["scam-shop checks"],
    "openai": ["AI second opinion", "Suggest with AI", "ad relevance"],
}
# the "Start here" checklist: free keys first, then the budget, then a key per feature
START_HERE: list[dict[str, Any]] = [
    {"keys": ["virustotal", "urlscan", "safebrowsing"], "title": "Free reputation keys", "why": "VirusTotal, urlscan.io and Google Safe Browsing: free keys that every scan uses to see whether a site is already known as bad."},
    {"budget": True, "title": "A daily spend cap", "why": "Every paid call is checked against it; a scan stops spending instead of overspending."},
    {"keys": ["serpapi", "scraperapi"], "any": True, "title": "Google search", "why": "SerpApi (or ScraperAPI as a fallback) for the Google search stream — sites that rank for the brand's name."},
    {"keys": ["searchapi"], "title": "Social media, ads and AI answers", "why": "One SearchApi.io key: fake Facebook / Instagram accounts, the Meta Ad Library, and what ChatGPT / Gemini tell users."},
    {"keys": ["openai"], "title": "AI", "why": "OpenAI: the advisory second opinion, \"Suggest with AI\" for queries and prices, and the ad-relevance check."},
]

# the analyst's reason for dismissing, in words (the enum values are what the API takes)
VERDICT_LABELS: dict[str, str] = {"legitimate": "a legitimate site", "suspicious": "suspicious, but not phishing",
                                  "unknown": "cannot tell"}  # fmt: skip
# the kinds of message a page shows after a form was saved (?saved=<key>)
SAVED_TEXT: dict[str, str] = {"config": "Detection track and search rules saved.", "allowlist": "Allowlist updated.",
                              "baseline": "Baseline rebuilt from the official site.", "brand": "Brand updated.",
                              "map_deleted": "The infrastructure map was deleted.", "notify": "Notification settings saved.",
                              "note": "Note added — it is kept with the finding and in Activity.",
                              "snoozed": "Snoozed — it is out of the queue until the date below, then it comes back by itself.",
                              "woken": "Back in the queue."}  # fmt: skip

STAGE_LABELS: dict[str, tuple[str, str]] = {
    "baseline": ("Learn the real site", "favicon, screenshot, login form, keywords"),
    "discovery": ("Find look-alikes", "typos, new certificates, new domains, Google, Facebook / Instagram ads"),
    "deduplicate": ("Clean the list", "merge, drop official & known platforms"),
    "enrichment": ("Visit in a sandbox", "DNS, WHOIS, screenshot, HTML"),
    "cloaking": ("Catch cloaking", "fetch as a bot, a victim and a home IP"),
    "analysis": ("Compare with the brand", f"{N_SIGNALS} signals in 7 groups"),
    "scoring": ("Score & explain", "risk 0–100 + confidence"),
    "finding": ("Raise a finding", "Medium and above go to an analyst"),
    "summary": ("Report", "what this scan did, step by step"),
    "social": ("Check social media", "Facebook pages, Instagram profiles, AI reading"),
    "ai_answers": ("Ask AI assistants", "ChatGPT, Gemini, Google AI Mode — every contact they give vs the brand's site"),
    "contacts": ("Read the real contacts", "phones, short codes, e-mails and WhatsApp on the official site"),
    "investigation": ("Map the attacker", "shared servers, certificates, favicons"),
    "intel": ("Look it up", "VirusTotal, RDAP, DNS, urlscan"),
}

PAGE_INTROS: dict[str, str] = {
    "dashboard": "BrandWatch finds impostors of your brand on the web and on social media — look-alike websites, fake Facebook pages and Instagram profiles that use the brand's name (an AI reads what they post), and ads that sell fakes of its products. It visits each site in a sandbox, scores and explains everything, maps the attacker's infrastructure and drafts the takedown, including the report to Meta. Nothing is sent automatically: an analyst decides every step.",
    "brands": "The brands you protect. Each one has official domains (never treated as suspects), a fingerprint of the real site, and a detection track that sets how deep the scan goes.",
    "findings": "A finding is a look-alike that scored Medium or higher and waits for an analyst's verdict. Everything below the threshold stays on the Watchlist and is re-checked on a schedule.",
    "candidates": "Every domain ever discovered for your brands — parked, empty or legitimate-looking — re-checked on a schedule. One that suddenly grows a login form jumps to the front.",
    "campaigns": "One confirmed phishing site → the servers, certificates and sister domains it shares. That is the attacker's infrastructure: take down all of it, not one site.",
    "takedowns": "Every confirmed phishing site and how far its takedown got. BrandWatch drafts the request and tracks it; an analyst sends it from their own mailbox.",
    "activity": "The append-only audit trail: who did what, when, old → new, and why. The database itself refuses to edit or delete it.",
    "baseline": "The fingerprint of the real site that every suspect is compared against.",
}

# --- Settings → API keys: what each key powers (keys follow config.settings.PROVIDER_KEY_FIELDS) ---
PROVIDER_GROUPS: list[tuple[str, str, str]] = [
    ("reputation", "Threat reputation", "is this site already known as bad?"),
    ("discovery", "Discovery & search", "where look-alikes are found"),
    ("infrastructure", "Domains & servers", "who registered it and where it runs"),
    (
        "shops",
        "Suspicious shops",
        "ads selling the brand's products, and whether the seller exists",
    ),
    ("ai", "AI", "advisory only, never part of the score"),
]
PROVIDER_INFO: dict[str, dict[str, Any]] = {
    "virustotal": {"group": "reputation", "name": "VirusTotal", "recommended": True, "plan": "free public key · 4 requests/min",
                   "does": "Verdicts from 70+ anti-virus and blocklist engines for every visited site. Also powers passive DNS on the infrastructure map and most of a finding's site & network investigation.",
                   "url": "https://www.virustotal.com"},
    "urlhaus": {"group": "reputation", "name": "URLhaus · abuse.ch", "plan": "free key",
                "does": "Checks each URL against abuse.ch's feed of malware and phishing URLs (second in the reputation chain).",
                "url": "https://urlhaus.abuse.ch"},
    "safebrowsing": {"group": "reputation", "name": "Google Safe Browsing", "recommended": True, "plan": "free for non-commercial use · Google Cloud key",
                     "does": "The list Chrome, Firefox and Safari use to warn users. Checked for every visited site: shows whether Google already warns about it, so you can tell when BrandWatch found a kit first.",
                     "url": "https://developers.google.com/safe-browsing/v4/get-started"},
    "abuseipdb": {"group": "reputation", "name": "AbuseIPDB", "plan": "free daily quota",
                  "does": "Community abuse reports for every server in a finding's investigation: a 0–100 abuse score, how many reports, from how many reporters, and when last.",
                  "url": "https://www.abuseipdb.com/account/api"},
    "serpapi": {"group": "discovery", "name": "SerpApi", "recommended": True, "plan": "free tier",
                "does": "Google results for the brand's search queries: the 'Google search' discovery stream, run per country.",
                "url": "https://serpapi.com"},
    "scraperapi": {"group": "discovery", "name": "ScraperAPI", "plan": "paid · free trial credits",
                   "does": "The fallback of SerpApi for the 'Google search' discovery stream: when SerpApi has no key, no quota left or is down, the same searches go to ScraperAPI (about 25 credits a search).",
                   "url": "https://www.scraperapi.com"},
    "urlscan": {"group": "discovery", "name": "urlscan.io", "recommended": True, "plan": "free key",
                "does": "Searches the urlscan.io archive for pages that mention the brand (a discovery stream), and submits fresh scans from a finding's investigation.",
                "url": "https://urlscan.io"},
    "shodan": {"group": "infrastructure", "name": "Shodan", "plan": "paid membership for search",
               "does": "Infrastructure map: what runs on each hosting server, and other servers that serve the same favicon.",
               "url": "https://www.shodan.io"},
    "whoisxml": {"group": "infrastructure", "name": "WhoisXML API", "plan": "paid · WHOIS History is its own product on the same key",
                 "does": "WHOIS history on the finding page: every past owner, registrar and privacy change, and owner details hidden after registration. Also WHOIS records when Lookups → WHOIS is 'Service' (the default RDAP method needs no key).",
                 "url": "https://whoisxmlapi.com"},
    "searchapi": {"group": "shops", "name": "SearchApi.io · Meta Ad Library, social accounts, AI answers", "recommended": True, "plan": "100 free requests · then $40/month for 10k",
                  "does": "Finds Facebook and Instagram ads that sell the brand's products in each chosen country, and the shops they link to (brands whose products other shops resell); fake Facebook pages and Instagram profiles; and what ChatGPT, Gemini and Google AI Mode tell users about the brand's phone, e-mail and login. Meta's own Ad Library API only covers ads that ran in the EU/UK.",
                  "url": "https://www.searchapi.io/meta-ad-library-api"},
    "companies_house": {"group": "shops", "name": "UK Companies House", "plan": "free key",
                        "does": "Checks that a UK company number printed on a shop exists and is not dissolved.",
                        "url": "https://developer.company-information.service.gov.uk/get-started"},
    "opencorporates": {"group": "shops", "name": "OpenCorporates", "plan": "paid · optional",
                       "does": "Company numbers in 140+ countries — only needed for countries without a free official registry (otherwise BrandWatch searches Google for the company).",
                       "url": "https://opencorporates.com/api_accounts/new"},
    "openai": {"group": "ai", "name": "OpenAI", "recommended": True, "plan": "paid per token",
               "does": "Writes the Google queries a phisher would target, gives the advisory second opinion on findings, and triages co-hosted pages on the infrastructure map.",
               "url": "https://platform.openai.com/api-keys"},
}  # fmt: skip
# sources that never need a key (always on in live mode)
KEYLESS_SOURCES: list[tuple[str, str]] = [
    ("crt.sh · CertSpotter", "certificate transparency logs"),
    ("RDAP · port-43 WHOIS", "registration date, registrar, abuse contact"),
    ("DNS", "BrandWatch's own resolver walk, or public resolvers"),
    ("Chromium (Playwright)", "the sandboxed browser that visits every site"),
    ("ip-api", "where a server is (country, city, network)"),
    ("whoisds", "yesterday's newly registered domains"),
    ("Israel Registrar of Companies (data.gov.il)", "company numbers printed on Israeli shops"),
    ("EU VIES", "VAT numbers printed on EU shops"),
    ("GLEIF", "registered companies worldwide, by name (LEI holders)"),
]


GLOSSARY: list[tuple[str, str, str]] = [
    ("baseline", "Baseline", "The fingerprint of the brand's real site — favicon hash, screenshot hash, colours, login pages, keywords. Every suspect is compared against it."),
    ("candidate", "Candidate / watched domain", "Any domain discovered for a brand. It lives on the Watchlist until it scores high enough to become a finding, expires, or is dismissed."),
    ("finding", "Finding", "A candidate that scored Medium or higher. An analyst confirms it as phishing or dismisses it; nothing happens automatically."),
    ("signal", "Signal", f"One piece of evidence (e.g. 'identical favicon'). {N_SIGNALS} signals in 7 groups; each adds points."),
    ("group-cap", "Group cap", "Each group can add at most its cap, so ten weak visual hints never outweigh one strong behaviour signal."),
    ("risk", "Risk score", "How dangerous the site is, 0–100. Medium ≥ 25, High ≥ 50, Critical ≥ 75. Combination rules can raise the severity."),
    ("confidence", "Confidence", "How complete and consistent the evidence is (breadth, completeness, provider agreement) — separate from risk."),
    ("cloaking", "Cloaking", "A kit that shows a harmless decoy to scanners and the phishing page to victims. BrandWatch fetches as a bot, as a victim link, from a search referer and from a home IP."),
    ("tracks", "Detection track", "Light, Standard or Deep: which discovery streams run, how many sites are visited, how often the watchlist is re-checked."),
    ("attack-infrastructure", "Attack infrastructure", "The map built from one confirmed site: every server, certificate and sister domain it shares, triaged so reverse-IP noise is excluded. The pivot is budgeted (at most 2 hops, 100 nodes, a fixed number of API calls) and those limits are frozen in code."),
    ("advisory", "Advisory opinions", "An AI model and a trained classifier each give a second opinion on Medium+ findings. The page text is passed as untrusted input and the answer must match a strict JSON schema. Shown for context only: the deterministic score never depends on them."),
    ("ioc", "IOC", "Indicator of compromise: a domain, IP, certificate hash or tracking ID a firewall / SIEM can block. Exported as CSV, JSON or STIX 2.1."),
    ("takedown", "Takedown", "The request to remove a site. Draft → review → approved → sent → taken down; sent to the registrar, the hosting provider and the CDN, and reported to blocklists."),
    ("evidence", "Evidence", "Every screenshot, HTML page, DNS / WHOIS answer and reputation lookup, stored append-only with its SHA-256 — the database rejects edits and deletes."),
    ("stream", "Discovery stream", "One way of finding look-alikes: look-alike names (dnstwist), new certificates (CT), newly registered domains (NRD), Google search, the urlscan.io archive, social media, ads. A track decides which streams run."),
    ("dnstwist", "dnstwist", "Generates the names a phisher would register — typos, swapped letters, other TLDs, look-alike Unicode — and checks in DNS which of them exist."),
    ("ct", "Certificate transparency (CT)", "Every HTTPS certificate is published in public logs within minutes; a new certificate carrying the brand's name is often the first sign of a kit."),
    ("nrd", "Newly registered domains (NRD)", "Yesterday's list of every newly registered domain (about 70,000 a day), searched for the brand's name."),
    ("urlscan", "urlscan.io", "A public archive of scanned web pages: past scans that mention the brand, and a screenshot of a site that blocks BrandWatch."),
    ("residential", "Home / mobile IP probe", "A visit through a home (residential) or 4G/5G address, for kits that show the real page only to people, never to a datacentre. Needs a proxy and a GB budget."),
    ("stix", "STIX 2.1", "The standard file format security tools exchange threat indicators in; the infrastructure map's indicators can be exported as STIX for a SIEM or a firewall."),
    ("golden", "Golden dataset", "Recorded, hand-labelled scenarios (phishing, cloaked kits, scam shops, legitimate sites) the real pipeline is run on in every build; precision and recall are measured on them."),
    ("tld-set", "TLD set", "Which top-level domains dnstwist tries: common (.com .net …), popular (about 100) or all (about 1,280)."),
    ("vertical", "Vertical", "The kind of business (\"footwear and apparel\", \"crypto exchange\") — read by the AI from the official site, used to pick the right Google queries."),
    ("kind", "Who sells it", "Only the brand (a service, an app, a bank) or other shops too: then scam shops advertising its products are hunted as well."),
    ("demo", "Demo mode", "Recorded scenarios replace every external service: the full pipeline runs deterministically, offline, at $0."),
]  # fmt: skip


# ------------------------------------------------------------------------------- Jinja filters
def signal_label(sig: str) -> str:
    return SIGNAL_LABELS.get(sig, (sig.replace("_", " "), ""))[0]


def signal_help(sig: str) -> str:
    return SIGNAL_LABELS.get(sig, ("", ""))[1]


def group_label(g: str) -> str:
    return GROUP_LABELS.get(g, (g.replace("_", " ").title(), ""))[0]


def ts(value: Any) -> Markup:
    """A timestamp as the browser's local time: <time datetime=…> that base.html rewrites, the UTC text as a fallback."""
    if not value:
        return Markup("—")
    raw = value.isoformat() if hasattr(value, "isoformat") else str(value)
    shown = raw[:16].replace("T", " ")
    return Markup(f'<time datetime="{escape(raw)}" data-local title="{escape(raw)} UTC">{escape(shown)}</time>')


def state_label(s: Any) -> str:
    v = getattr(s, "value", s) or ""
    return STATE_LABELS.get(str(v), str(v).replace("_", " "))


def stream_label(s: Any) -> str:
    v = str(getattr(s, "value", s) or "")
    return STREAM_LABELS.get(v, v.replace("_", " "))


# Where a domain was found, as one small mark per kind of source: the analyst reads "Google", "ChatGPT", "Facebook" at a
# glance instead of a sentence. Several streams are one source to a reader (four certificate logs, four Google APIs).
STREAM_GROUP: dict[str, str] = {
    "dnstwist": "lookalike", "ct": "cert", "crtsh": "cert", "certspotter": "cert", "nrd": "nrd",
    "search": "google", "serpapi": "google", "serper": "google", "scraperapi": "google", "urlscan": "urlscan",
    "manual": "analyst", "pivot": "pivot", "meta_ads": "meta_ads", "social": "social", "redirect": "redirect", "ai_answer": "ai",
}  # fmt: skip
SOURCE_SHORT: dict[str, str] = {
    "lookalike": "Look-alike name", "cert": "Certificate logs", "nrd": "New domains", "google": "Google", "urlscan": "urlscan",
    "analyst": "Analyst scan", "pivot": "Infrastructure map", "meta_ads": "FB / IG ads", "social": "FB / IG pages",
    "redirect": "Redirect", "ai": "ChatGPT / Gemini",
}  # fmt: skip
_SVG = '<svg viewBox="0 0 16 16" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">'
SOURCE_GLYPH: dict[str, Markup] = {k: Markup(v) for k, v in {
    "google": "G", "social": "f", "meta_ads": "f",
    "ai": _SVG + '<path d="M8 1.8l1.5 4.2 4.3 1.5-4.3 1.5L8 13.2 6.5 9 2.2 7.5 6.5 6z" fill="currentColor" stroke="none"/></svg>',
    "cert": _SVG + '<rect x="3.2" y="7.2" width="9.6" height="6.6" rx="1.5"/><path d="M5.5 7.2V5.3a2.5 2.5 0 015 0v1.9"/></svg>',
    "lookalike": "Aa",
    "urlscan": _SVG + '<circle cx="7" cy="7" r="4.2"/><path d="M10.2 10.2l3.6 3.6"/></svg>',
    "analyst": _SVG + '<path d="M3.5 2.5l9 4.8-4 1.3-1.6 3.9z" fill="currentColor"/></svg>',
    "nrd": _SVG + '<path d="M8 2.5v11M2.5 8h11"/></svg>',
    "pivot": _SVG + '<circle cx="4" cy="4.5" r="1.9"/><circle cx="12" cy="4.5" r="1.9"/><circle cx="8" cy="12" r="1.9"/><path d="M5.6 5.6l1.6 4.6M10.4 5.6l-1.6 4.6M5.9 4.5h4.2"/></svg>',
    "redirect": _SVG + '<path d="M3 4.5h6.5a3.2 3.2 0 010 6.4H5"/><path d="M7 8.7l-2.2 2.2L7 13.1"/></svg>',
}.items()}  # fmt: skip


def source_badges(sources: Any, limit: int = 3) -> list[dict[str, Any]]:
    """One mark per kind of source, in the order found: [{g, label, title, glyph}]. Takes stream names or {stream, pattern}."""
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for src in sources or []:
        stream = str(src.get("stream") if isinstance(src, dict) else getattr(src, "value", src) or "")
        pattern = str((src.get("pattern") if isinstance(src, dict) else "") or "")
        g = "pivot" if stream == "manual" and pattern.startswith("pivot") else STREAM_GROUP.get(stream, "analyst")
        if g in seen:
            continue
        seen.add(g)
        out.append({"g": g, "label": SOURCE_SHORT.get(g, stream), "title": STREAM_LABELS.get(stream, stream), "glyph": SOURCE_GLYPH.get(g, "")})
    return out[:limit]


def rule_label(r: str) -> str:
    return RULE_LABELS.get(r, r.replace("_", " "))


def fp_label(f: str) -> str:
    return FP_LABELS.get(f, f.replace("_", " "))


def job_label(k: str) -> str:
    return JOB_LABELS.get(k, (k or "").replace("_", " "))


def help_tip(text: str, anchor: str | None = None) -> Markup:
    """A small focusable '?' with a tooltip; opens the glossary entry when an anchor is given.

    Always a <span> (base.html navigates on click / Enter): it sits inside clickable cards and
    table links, and an <a> inside an <a> makes the browser close the outer link early."""
    href = f' role="link" data-href="/ui/how-it-works#g-{escape(anchor)}"' if anchor else ""
    return Markup(
        f'<span class="help" tabindex="0"{href} data-tip="{escape(text)}" title="{escape(text)}" '
        f'aria-label="What is this? {escape(text)}">?</span>'
    )


def term(key: str) -> Markup:
    """'?' for a glossary term, by key."""
    entry = next((g for g in GLOSSARY if g[0] == key), None)
    return help_tip(entry[2], key) if entry else Markup("")


def register(templates: Any) -> None:
    env = templates.env
    env.filters.update({
        "signal_label": signal_label, "signal_help": signal_help, "group_label": group_label,
        "state_label": state_label, "stream_label": stream_label, "rule_label": rule_label,
        "fp_label": fp_label, "job_label": job_label, "ts": ts, "source_badges": source_badges,
    })  # fmt: skip
    from brandwatch.detection.takedown_channels import REPORT_PORTALS

    env.globals.update({
        "REPORT_PORTAL_COUNT": len(REPORT_PORTALS),
        "help_tip": help_tip, "term": term, "PAGE_INTROS": PAGE_INTROS, "GLOSSARY": GLOSSARY,
        "GROUP_LABELS": GROUP_LABELS, "STAGE_LABELS": STAGE_LABELS, "STATE_HELP": STATE_HELP,
        "SIGNAL_LABELS_JSON": {k: v[0] for k, v in SIGNAL_LABELS.items()},
        "STREAM_LABELS": STREAM_LABELS, "SURFACE_LABELS": SURFACE_LABELS,
        "PROVIDER_GROUPS": PROVIDER_GROUPS, "PROVIDER_INFO": PROVIDER_INFO, "KEYLESS_SOURCES": KEYLESS_SOURCES,
        "VERDICT_LABELS": VERDICT_LABELS, "SAVED_TEXT": SAVED_TEXT, "SIGNAL_COUNT": N_SIGNALS,
        "KEY_USED_BY": KEY_USED_BY, "START_HERE": START_HERE,
    })  # fmt: skip
