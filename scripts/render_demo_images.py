"""Render the demo's website screenshots and favicons (run once; the PNGs are committed).

    python scripts/render_demo_images.py          # → src/brandwatch/demo/assets/{shots,icons}/

The demo never visits a real site, so every page the mock browser "sees" needs a picture. Each
golden scenario gets one that looks like the site it pretends to be:

* ``_brand.png``          the official ShopNova shop — the reference every suspect is compared to
* ``_brand_similar.png``  the same page with a phishing banner: a near-identical clone
* ``<host>.png``          every other site, styled from its own recorded HTML (shops, blogs, a dentist …)
* ``<host>__decoy.png``   what a cloaked kit shows a security scanner
* ``icons/_brand.png``    ShopNova's favicon (a cloned favicon is byte-identical → same mmh3)
* ``icons/<host>.png``    everyone else's favicon

The pHash relationships the scoring relies on are preserved: brand-class clones are the brand picture,
"similar" stays above the 90 % threshold, every other site stays well below it (checked at the end).
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import sys
from pathlib import Path

from bs4 import BeautifulSoup
from PIL import Image
from playwright.async_api import async_playwright

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from brandwatch.detection import images  # noqa: E402
from brandwatch.providers.mock.fixtures import default_store  # noqa: E402

ASSETS = ROOT / "src" / "brandwatch" / "demo" / "assets"
SHOTS, ICONS = ASSETS / "shots", ASSETS / "icons"
VIEW = (1280, 800)
OUT_SIZE = (960, 600)

# ------------------------------------------------------------------------------ illustrations
SNEAKER = """<svg viewBox="0 0 320 170" xmlns="http://www.w3.org/2000/svg"><defs>
<linearGradient id="up" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="{a}"/><stop offset="1" stop-color="{b}"/></linearGradient></defs>
<ellipse cx="162" cy="160" rx="140" ry="7" fill="rgba(0,0,0,.13)"/>
<path d="M20 118 C 24 104 44 97 72 93 C 104 88 128 74 152 63 C 172 54 194 54 212 60 C 226 50 250 42 272 46 C 292 50 302 70 304 96 L 306 118 Z" fill="url(#up)"/>
<path d="M210 62 C 226 52 248 47 268 51 C 252 56 234 63 218 70 Z" fill="{sole}" opacity=".85"/>
<path d="M284 50 C 296 54 302 66 304 80 L 296 82 C 294 70 290 60 282 56 Z" fill="{stripe}"/>
<path d="M118 82 L 136 96 M134 74 L 152 88 M150 67 L 168 81 M166 62 L 182 75" stroke="{sole}" stroke-width="4" stroke-linecap="round" opacity=".7"/>
<path d="M64 108 C 118 100 178 92 252 98" stroke="{stripe}" stroke-width="8" fill="none" stroke-linecap="round"/>
<path d="M14 118 L 308 118 L 306 133 C 305 139 300 141 292 141 L 30 141 C 20 141 14 135 14 127 Z" fill="#ffffff" stroke="rgba(0,0,0,.12)" stroke-width="1.5"/>
<g fill="{sole}"><rect x="26" y="138" width="34" height="13" rx="6"/><rect x="66" y="139" width="34" height="13" rx="6"/><rect x="106" y="139" width="34" height="13" rx="6"/>
<rect x="146" y="139" width="34" height="13" rx="6"/><rect x="186" y="139" width="34" height="13" rx="6"/><rect x="226" y="139" width="34" height="13" rx="6"/><rect x="266" y="138" width="34" height="13" rx="6"/></g>
</svg>"""
HEADPHONES = """<svg viewBox="0 0 160 140"><path d="M30 92 C 30 40 130 40 130 92" stroke="#1f1b4d" stroke-width="10" fill="none" stroke-linecap="round"/>
<rect x="18" y="82" width="28" height="44" rx="12" fill="#5b4bff"/><rect x="114" y="82" width="28" height="44" rx="12" fill="#5b4bff"/>
<rect x="24" y="90" width="16" height="28" rx="7" fill="#8f84ff"/><rect x="120" y="90" width="16" height="28" rx="7" fill="#8f84ff"/></svg>"""
WATCH = """<svg viewBox="0 0 160 140"><rect x="62" y="6" width="36" height="128" rx="12" fill="#ff6b4a"/>
<rect x="44" y="34" width="72" height="72" rx="20" fill="#1f1b4d"/><rect x="52" y="42" width="56" height="56" rx="14" fill="#2c2f7a"/>
<path d="M80 54 L 80 70 L 92 78" stroke="#9ff0ff" stroke-width="5" fill="none" stroke-linecap="round"/></svg>"""
LAPTOP = """<svg viewBox="0 0 160 140"><rect x="26" y="24" width="108" height="72" rx="8" fill="#1f1b4d"/>
<rect x="33" y="31" width="94" height="58" rx="4" fill="#7b6dff"/><path d="M40 78 L 70 52 L 88 68 L 104 56 L 120 78 Z" fill="#c9c2ff"/>
<path d="M12 100 L 148 100 L 140 114 L 20 114 Z" fill="#cfd3e6"/></svg>"""
STAR = """<svg viewBox="0 0 64 64"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#5b4bff"/>
<stop offset="1" stop-color="#3016b8"/></linearGradient></defs><rect width="64" height="64" rx="14" fill="url(#g)"/>
<path d="M32 9 C 34 25 39 30 55 32 C 39 34 34 39 32 55 C 30 39 25 34 9 32 C 25 30 30 25 32 9 Z" fill="#fff"/>
<circle cx="47" cy="17" r="5" fill="#ff6b4a"/></svg>"""

# ------------------------------------------------------------------------------ ShopNova (official)
BRAND_CSS = """
*{box-sizing:border-box;margin:0}body{font-family:'Segoe UI',Inter,Arial,sans-serif;background:#f6f5fb;color:#1c1a33;width:1280px;height:800px;overflow:hidden}
.promo{background:#1c1a33;color:#e6e3ff;font-size:13px;text-align:center;padding:8px}
.promo.alert{background:#d92d20;color:#fff;font-weight:600}
header{display:flex;align-items:center;gap:28px;padding:16px 48px;background:#fff;border-bottom:1px solid #eceaf5}
.logo{display:flex;align-items:center;gap:10px;font-weight:800;font-size:24px;letter-spacing:-.5px;color:#1c1a33}.logo svg{width:36px;height:36px}
nav{display:flex;gap:22px;font-size:15px;color:#4b4870}nav b{color:#5b4bff}
.search{flex:1;max-width:380px;margin-left:auto;background:#f1f0f8;border-radius:999px;padding:11px 18px;color:#8b88a8;font-size:14px}
.icons{display:flex;gap:16px;align-items:center}.icons span{width:38px;height:38px;border-radius:50%;background:#f1f0f8;display:grid;place-items:center;font-size:16px;color:#4b4870;position:relative}
.icons .badge{position:absolute;top:-4px;right:-4px;width:18px;height:18px;border-radius:50%;background:#ff6b4a;color:#fff;font-size:11px;display:grid;place-items:center}
main{display:grid;grid-template-columns:1.55fr 1fr;gap:28px;padding:28px 48px 0}
.hero{position:relative;border-radius:22px;padding:42px 44px;color:#fff;background:linear-gradient(130deg,#5b4bff 0%,#3016b8 70%);overflow:hidden;height:372px}
.hero:after{content:"";position:absolute;right:-80px;top:-90px;width:360px;height:360px;border-radius:50%;background:rgba(255,255,255,.08)}
.hero small{font-size:13px;letter-spacing:.14em;text-transform:uppercase;opacity:.8}
.hero h1{font-size:44px;line-height:1.05;margin:12px 0 12px;max-width:420px}
.hero p{font-size:16px;opacity:.88;max-width:360px;line-height:1.5}
.hero .cta{display:inline-block;margin-top:24px;background:#ff6b4a;color:#fff;padding:13px 26px;border-radius:999px;font-weight:700;font-size:15px}
.hero svg{position:absolute;right:18px;bottom:30px;width:380px}
.card{background:#fff;border-radius:22px;padding:30px 32px;box-shadow:0 12px 40px rgba(40,30,120,.08);height:372px}
.card h2{font-size:23px}.card .sub{font-size:14px;color:#6b6890;margin:6px 0 20px}
.field{border:1.5px solid #e0def0;border-radius:12px;padding:13px 14px;font-size:14px;color:#9a97b5;margin-bottom:12px}
.btn{background:#1c1a33;color:#fff;text-align:center;border-radius:12px;padding:14px;font-weight:700;font-size:15px;margin-top:6px}
.links{display:flex;justify-content:space-between;font-size:13px;color:#5b4bff;margin-top:16px}
.row{display:grid;grid-template-columns:repeat(4,1fr);gap:20px;padding:24px 48px}
.p{background:#fff;border-radius:18px;padding:14px;box-shadow:0 6px 24px rgba(40,30,120,.06)}
.p .img{height:118px;border-radius:12px;background:#f1effc;display:grid;place-items:center}.p .img svg{height:100px}
.p b{display:block;font-size:14px;margin-top:10px}.p span{font-size:14px;color:#5b4bff;font-weight:700}
"""


def brand_page(*, similar: bool = False) -> str:
    sneaker = SNEAKER.format(a="#ffffff", b="#dcd8ff", sole="#1c1a33", stripe="#ff6b4a")
    promo = (
        '<div class="promo alert">⚠ Your account has been limited — verify your details within 24 hours</div>'
        if similar
        else '<div class="promo">Free delivery on orders over $50 · 30-day returns · ShopNova Plus members save 10%</div>'
    )
    card_title = "Verify your account" if similar else "Sign in to ShopNova"
    card_sub = (
        "Confirm your details to restore access."
        if similar
        else "Track orders, save favourites and check out faster."
    )
    small = SNEAKER.format(a="#ffffff", b="#ffd9cf", sole="#1c1a33", stripe="#5b4bff")
    return f"""<!doctype html><html><head><meta charset="utf-8"><style>{BRAND_CSS}</style></head><body>
{promo}
<header><div class="logo">{STAR}ShopNova</div><nav><b>Electronics</b><span>Home</span><span>Running</span><span>Deals</span><span>Gift cards</span></nav>
<div class="search">Search products, brands and more…</div><div class="icons"><span>♡</span><span>👤</span><span>🛒<i class="badge">2</i></span></div></header>
<main><section class="hero"><small>New season</small><h1>Shop smarter. Run lighter.</h1>
<p>The new ShopNova Runner — cloud-soft cushioning, built for every day.</p><span class="cta">Shop the Runner</span>{sneaker}</section>
<section class="card"><h2>{card_title}</h2><div class="sub">{card_sub}</div><div class="field">Email address</div><div class="field">Password</div>
<div class="btn">Sign in</div><div class="links"><span>Forgot password?</span><span>Create an account</span></div></section></main>
<section class="row"><div class="p"><div class="img">{HEADPHONES}</div><b>Nova Sound Pro</b><span>$149</span></div>
<div class="p"><div class="img">{WATCH}</div><b>Nova Watch 3</b><span>$229</span></div>
<div class="p"><div class="img">{LAPTOP}</div><b>NovaBook Air 14"</b><span>$899</span></div>
<div class="p"><div class="img">{small}</div><b>ShopNova Runner</b><span>$150</span></div></section>
</body></html>"""


# ------------------------------------------------------------------------------ every other site
THEMES = [  # (background, surface, primary, ink, accent, font)
    ("#f4f8f7", "#ffffff", "#0f766e", "#12312e", "#f59e0b", "Georgia, 'Times New Roman', serif"),
    ("#fbf7f2", "#ffffff", "#b45309", "#3b2a1a", "#0e7490", "'Segoe UI', Arial, sans-serif"),
    ("#f3f6fb", "#ffffff", "#1d4ed8", "#0f1b33", "#16a34a", "'Segoe UI', Arial, sans-serif"),
    ("#f6f6f6", "#ffffff", "#111827", "#111827", "#ef4444", "Arial, sans-serif"),
    ("#f2fbf5", "#ffffff", "#15803d", "#14301f", "#a16207", "Verdana, sans-serif"),
    ("#fdf4f8", "#ffffff", "#be185d", "#3a1428", "#0d9488", "'Segoe UI', Arial, sans-serif"),
    ("#eef6fb", "#ffffff", "#0369a1", "#0b2536", "#f97316", "Tahoma, sans-serif"),
    ("#f7f5ef", "#fffdf8", "#57534e", "#1c1917", "#ca8a04", "Georgia, serif"),
]
OTHER_CSS = """
*{box-sizing:border-box;margin:0}body{font-family:var(--font);background:var(--bg);color:var(--ink);width:1280px;height:800px;overflow:hidden}
.top{display:flex;align-items:center;gap:26px;padding:18px 56px;background:var(--surface);border-bottom:1px solid rgba(0,0,0,.06)}
.brand{display:flex;align-items:center;gap:12px;font-weight:700;font-size:21px}.mark{width:38px;height:38px;border-radius:10px;background:var(--primary);color:#fff;display:grid;place-items:center;font-size:19px}
.top nav{display:flex;gap:22px;margin-inline-start:auto;font-size:15px;opacity:.75}
.top .cta{background:var(--primary);color:#fff;padding:10px 18px;border-radius:8px;font-size:14px;font-weight:600}
.wrap{display:grid;grid-template-columns:1.25fr 1fr;gap:48px;padding:56px 56px 0;align-items:start}
.content h1{font-size:46px;line-height:1.08;letter-spacing:-.5px;margin-bottom:16px}
.content h2{font-size:22px;font-weight:500;opacity:.8;margin-bottom:14px}
.content p{font-size:18px;line-height:1.6;opacity:.85;margin-bottom:14px;max-width:560px}
.content form{display:grid;gap:12px;max-width:440px;margin-top:22px;background:var(--surface);padding:24px;border-radius:14px;box-shadow:0 10px 30px rgba(0,0,0,.06)}
.content input,.content textarea{font:inherit;font-size:15px;padding:12px 14px;border:1.5px solid rgba(0,0,0,.12);border-radius:9px;background:#fff;width:100%}
.content textarea{height:70px}
.content button,.content .btn{font:inherit;font-weight:700;font-size:15px;background:var(--primary);color:#fff;border:0;border-radius:9px;padding:13px 18px;cursor:pointer}
.content footer{margin-top:26px;font-size:14px;opacity:.7}
.content a{color:var(--primary)}
.art{height:420px;border-radius:24px;background:var(--surface);box-shadow:0 18px 50px rgba(0,0,0,.08);overflow:hidden;position:relative}
.art svg{position:absolute;inset:0;width:100%;height:100%}
.foot{position:absolute;bottom:0;left:0;right:0;padding:16px 56px;font-size:13px;opacity:.6;border-top:1px solid rgba(0,0,0,.06);background:var(--surface)}
/* shops */
.shop .wrap{grid-template-columns:1fr 1fr}
.product{display:grid;grid-template-columns:auto 1fr;gap:6px 18px;align-items:center;background:var(--surface);border-radius:16px;padding:18px;box-shadow:0 10px 30px rgba(0,0,0,.07);margin-top:18px;max-width:560px}
.product .pic{grid-row:span 3;width:190px;height:120px;border-radius:12px;background:#f3f1ee;display:grid;place-items:center}.product .pic svg{width:180px}
.product .price{font-size:26px;font-weight:800;color:var(--accent)}
.product button,.product a{justify-self:start}
"""


def _art(primary: str, accent: str, seed: int) -> str:
    """An abstract hero illustration in the site's colours (circles and waves, varied by host)."""
    r = seed % 7
    return f"""<svg viewBox="0 0 480 420" preserveAspectRatio="xMidYMid slice" xmlns="http://www.w3.org/2000/svg">
<rect width="480" height="420" fill="{primary}" opacity=".10"/>
<circle cx="{330 - r * 18}" cy="{120 + r * 12}" r="{120 - r * 6}" fill="{primary}" opacity=".85"/>
<circle cx="{150 + r * 10}" cy="{290 - r * 8}" r="{80 + r * 4}" fill="{accent}" opacity=".75"/>
<path d="M0 {330 - r * 6} C 120 {280 + r * 4} 240 {390 - r * 5} 480 {310 + r * 3} L 480 420 L 0 420 Z" fill="{primary}" opacity=".55"/>
<rect x="{60 + r * 8}" y="70" width="140" height="20" rx="10" fill="#fff" opacity=".8"/><rect x="{60 + r * 8}" y="100" width="90" height="14" rx="7" fill="#fff" opacity=".6"/></svg>"""


def other_page(host: str, html: str, *, rtl: bool) -> str:
    soup = BeautifulSoup(html, "html.parser")
    title = (soup.title.get_text(strip=True) if soup.title else "") or host
    name = title.split(" — ")[0].split(" | ")[0].strip() or host
    seed = int(hashlib.sha256(host.encode()).hexdigest()[:6], 16)
    bg, surface, primary, ink, accent, font = THEMES[seed % len(THEMES)]
    if soup.title:
        soup.title.decompose()
    for link in soup.find_all("link"):
        link.decompose()
    for s in soup.find_all("script"):
        s.decompose()
    body = soup.body or soup
    is_shop = (
        bool(soup.select(".product"))
        or "add-to-cart" in html
        or "הוספה לסל" in html
        or "add to cart" in html.lower()
    )
    for prod in soup.select(".product"):  # a product card with a picture
        pic = soup.new_tag("div", attrs={"class": "pic"})
        pic.append(
            BeautifulSoup(
                SNEAKER.format(a="#ffffff", b="#ffe0d6", sole="#262626", stripe=accent),
                "html.parser",
            )
        )
        prod.insert(0, pic)
        for sp in prod.select(".price"):
            sp["class"] = "price"
    inner = "".join(str(c) for c in body.children)
    nav = (
        ("בית", "מבצעים", "צור קשר")
        if rtl
        else (("Shop", "New in", "Sale") if is_shop else ("Home", "About", "Contact"))
    )
    cta = ("🛒 סל" if rtl else "🛒 Cart") if is_shop else ("כניסה" if rtl else "Get in touch")
    art = (
        SNEAKER.format(a="#ffffff", b="#ffd9cf", sole="#262626", stripe=accent)
        if is_shop and not soup.select(".product")
        else _art(primary, accent, seed)
    )
    art_html = (
        f'<aside class="art" style="display:grid;place-items:center;background:linear-gradient(140deg,{primary}22,{accent}33)">'
        f'<div style="width:86%">{art}</div></aside>'
        if is_shop and not soup.select(".product")
        else f'<aside class="art">{art}</aside>'
    )
    if is_shop and soup.select(".product"):
        art_html = (
            f'<aside class="art" style="display:grid;place-items:center;background:linear-gradient(140deg,{primary}26,{accent}30)">'
            f'<div style="width:88%">{SNEAKER.format(a="#ffffff", b="#ffe0d6", sole="#262626", stripe=accent)}</div></aside>'
        )
    return f"""<!doctype html><html dir="{"rtl" if rtl else "ltr"}"><head><meta charset="utf-8"><style>
:root{{--bg:{bg};--surface:{surface};--primary:{primary};--ink:{ink};--accent:{accent};--font:{font}}}{OTHER_CSS}</style></head>
<body class="{"shop" if is_shop else ""}"><header class="top"><div class="brand"><span class="mark">{name[:1].upper()}</span>{name}</div>
<nav>{"".join(f"<span>{n}</span>" for n in nav)}</nav><span class="cta">{cta}</span></header>
<main class="wrap"><section class="content">{inner}</section>{art_html}</main>
<div class="foot">© 2026 {name} · {host}</div></body></html>"""


DECOY_CSS = """*{box-sizing:border-box;margin:0}body{font-family:Arial,sans-serif;background:#fafafa;color:#333;width:1280px;height:800px;display:grid;place-items:center}
.box{text-align:center}.gear{font-size:64px;color:#bbb}h1{font-size:30px;font-weight:600;margin:14px 0 8px}p{color:#777;font-size:16px}"""


def decoy_page(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    h1 = soup.h1.get_text(strip=True) if soup.h1 else "Site under maintenance"
    p = soup.p.get_text(strip=True) if soup.p else "Please check back later."
    return f'<!doctype html><html><head><meta charset="utf-8"><style>{DECOY_CSS}</style></head><body><div class="box"><div class="gear">⚙</div><h1>{h1}</h1><p>{p}</p></div></body></html>'


def icon_page(svg_or_letter: str, color: str | None = None) -> str:
    inner = (
        svg_or_letter
        if svg_or_letter.startswith("<svg")
        else (
            f'<div style="width:64px;height:64px;border-radius:14px;background:{color};color:#fff;display:grid;place-items:center;'
            f'font:700 38px Arial,sans-serif">{svg_or_letter}</div>'
        )
    )
    return f"<!doctype html><html><head><style>*{{margin:0}}body{{width:64px;height:64px;background:transparent}}svg{{width:64px;height:64px;display:block}}</style></head><body>{inner}</body></html>"


def _shrink(png: bytes, size: tuple[int, int]) -> bytes:
    im = Image.open(io.BytesIO(png)).convert("RGB").resize(size, Image.LANCZOS)
    im = im.quantize(colors=256, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE).convert(
        "RGB"
    )
    buf = io.BytesIO()
    im.save(buf, format="PNG", optimize=True)
    return buf.getvalue()


async def main() -> None:
    SHOTS.mkdir(parents=True, exist_ok=True)
    ICONS.mkdir(parents=True, exist_ok=True)
    store = default_store()
    async with async_playwright() as p:
        b = await p.chromium.launch()
        page = await b.new_page(viewport={"width": VIEW[0], "height": VIEW[1]})

        async def shot(html: str, out: Path) -> bytes:
            await page.set_content(html, wait_until="load")
            data = _shrink(await page.screenshot(), OUT_SIZE)
            out.write_bytes(data)
            return data

        ipage = await b.new_page(viewport={"width": 64, "height": 64})

        async def icon(html: str, out: Path) -> None:
            await ipage.set_content(html, wait_until="load")
            png = await ipage.screenshot(omit_background=True)
            im = Image.open(io.BytesIO(png)).convert("RGBA").resize((32, 32), Image.LANCZOS)
            buf = io.BytesIO()
            im.save(buf, format="PNG", optimize=True)
            out.write_bytes(buf.getvalue())

        brand = await shot(brand_page(), SHOTS / "_brand.png")
        similar = await shot(brand_page(similar=True), SHOTS / "_brand_similar.png")
        await icon(icon_page(STAR), ICONS / "_brand.png")
        report = [
            (
                "_brand_similar",
                images.similarity(images.phash_hex(brand), images.phash_hex(similar)),
            )
        ]
        for sc in store.all():
            html = (sc.http or {}).get("html", "")
            rtl = 'lang="he"' in html or any("֐" <= ch <= "׿" for ch in html[:4000])
            if sc.screenshot == "other" and html:
                data = await shot(other_page(sc.host, html, rtl=rtl), SHOTS / f"{sc.host}.png")
                report.append(
                    (sc.host, images.similarity(images.phash_hex(brand), images.phash_hex(data)))
                )
            if sc.cloak:
                await shot(
                    decoy_page(sc.cloak.get("benign_html") or ""), SHOTS / f"{sc.host}__decoy.png"
                )
            if sc.favicon == "other":
                seed = int(hashlib.sha256(sc.host.encode()).hexdigest()[:6], 16)
                color = THEMES[seed % len(THEMES)][2]
                await icon(icon_page(sc.host[:1].upper(), color), ICONS / f"{sc.host}.png")
        await b.close()
    worst_other = max((s for h, s in report if h != "_brand_similar"), default=0)
    print(
        f"similar vs brand: {report[0][1]:.2f} (must be ≥ 0.90) · most similar other site: {worst_other:.2f} (must be < 0.90)"
    )
    total = sum(f.stat().st_size for f in ASSETS.rglob("*.png"))
    print(
        f"{len(list(SHOTS.glob('*.png')))} screenshots · {len(list(ICONS.glob('*.png')))} favicons · {total / 1024:.0f} KB"
    )


if __name__ == "__main__":
    asyncio.run(main())
