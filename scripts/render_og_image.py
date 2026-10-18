"""Render the link-preview picture for How it works (1200×630) from the flow diagram.

A chat app or LinkedIn shows this next to a link to the page (``og:image``). It is rendered once from a
running demo server and committed as ``src/brandwatch/api/assets/og-how-it-works.png``; the app serves it
at ``/ui/assets/og-how-it-works.png``.

    python scripts/render_og_image.py --base http://127.0.0.1:8765
"""

from __future__ import annotations

import argparse
from pathlib import Path

from playwright.sync_api import sync_playwright

OUT = Path(__file__).resolve().parents[1] / "src" / "brandwatch" / "api" / "assets" / "og-how-it-works.png"
# the diagram alone, on the page's own background, with a title above it
PAGE = """<!doctype html><html><head><meta charset="utf-8">
<link href="https://fonts.googleapis.com/css2?family=Rajdhani:wght@700&family=Inter:wght@400;600&display=swap" rel="stylesheet">
<style>
  :root{--line:#1E2A3D;--muted:#8A97A8;--accent:#35C7F2;--accent2:#5FE3FF;--mono:"JetBrains Mono",Consolas,monospace;--sans:Inter,system-ui,sans-serif;--display:Rajdhani,sans-serif}
  html,body{margin:0;background:#080B14;color:#E6EDF5;font-family:var(--sans)}
  .og{width:1200px;height:630px;padding:34px 40px 0;box-sizing:border-box;overflow:hidden;background:radial-gradient(ellipse at 50% 0,rgba(53,199,242,.14),transparent 55%),#080B14}
  .t{font:700 44px/1.05 var(--display);letter-spacing:.01em;margin:0 0 6px}
  .t em{font-style:normal;color:#5FE3FF}
  .s{font-size:17px;color:#c3cdd9;margin:0 0 14px}
  .sx-flow{border-radius:16px}
  .sx-flow .hint{display:none}
</style></head><body><div class="og">
<p class="t">Someone fakes a brand's site. <em>BrandWatch finds it, proves it, takes it down.</em></p>
<p class="s">Look-alike domains · new registrations · Facebook &amp; Instagram · ChatGPT &amp; Gemini → evidence → the attacker's footprint → takedown</p>
%s</div></body></html>"""


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--base", default="http://127.0.0.1:8765")
    ap.add_argument("--user", default="admin")
    ap.add_argument("--password", default="admin")
    ap.add_argument("--out", default=str(OUT))
    args = ap.parse_args()
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        page = browser.new_page(viewport={"width": 1440, "height": 900})
        page.goto(args.base + "/ui/login")
        page.fill("input[name=email]", args.user)
        page.fill("input[name=password]", args.password)
        page.click("button[type=submit]")
        page.wait_for_load_state("networkidle")
        page.goto(args.base + "/ui/how-it-works")
        page.wait_for_load_state("networkidle")
        # the wide drawing with its styles, moving dots removed (a still picture)
        diagram = page.evaluate(
            "() => { const d = document.querySelector('.sx-flow-h').cloneNode(true);"
            " d.querySelectorAll('animateMotion, set').forEach(a => a.parentNode.remove());"
            " const css = [...document.querySelectorAll('style')].map(s => s.textContent).filter(t => t.includes('.sx-flow')).join('\\n');"
            " return '<style>' + css + '</style>' + d.outerHTML; }"
        )
        shot = browser.new_page(viewport={"width": 1200, "height": 630}, device_scale_factor=1)
        shot.set_content(PAGE.replace("%s", diagram), wait_until="networkidle")
        shot.wait_for_timeout(800)
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        shot.screenshot(path=args.out, clip={"x": 0, "y": 0, "width": 1200, "height": 630})
        browser.close()
    print(f"wrote {args.out} ({Path(args.out).stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()
