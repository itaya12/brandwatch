"""Build a static, read-only copy of the demo for a static host (Cloudflare Pages).

A browser signs in to a running demo server, opens every page it can reach (up to a cap per kind of
page), and keeps the page and everything it loaded: images, the dashboard's JSON, the world map.
The links are rewritten to the saved copies. A small script in every page answers the requests the
page makes while it runs (``fetch``, the live console's ``EventSource``) from the saved copies, and
turns everything that would change data (a form that posts, a scan, a verdict) into a short
"static demo" notice. Nothing in the copy talks to a server.

Never copied: the raw HTML that a phishing kit served (stored as evidence) — only screenshots — so
the static site carries no login form of a fake site.

    python scripts/build_static_demo.py --base http://127.0.0.1:8765 --out site
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
import shutil
import sys
import time
from collections import Counter, deque
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit

from playwright.sync_api import sync_playwright

# how many pages of one kind are worth keeping: the rest of a kind turns into the "static demo" notice
CAPS = [
    (re.compile(r"^/ui/candidates/[0-9a-f-]{36}$"), 60),
    (re.compile(r"^/ui/jobs/[0-9a-f-]{36}$"), 12),
    (re.compile(r"^/ui/brands/[0-9a-f-]{36}/setup$"), 2),
]
QUERY_VARIANTS_PER_PATH = 40
SKIP = re.compile(r"^/ui/(login|logout)$|/export|/download|\.(csv|json|stix)$")
EXT = {"image/png": ".png", "image/jpeg": ".jpg", "image/gif": ".gif", "image/webp": ".webp", "image/svg+xml": ".svg",
       "image/x-icon": ".ico", "image/vnd.microsoft.icon": ".ico", "application/json": ".json", "text/csv": ".csv",
       "text/plain": ".txt", "text/css": ".css", "application/javascript": ".js", "text/javascript": ".js"}  # fmt: skip
ATTR = re.compile(r'(\b(?:href|src|action|data-src|data-href|poster)=")(/[^"]*)(")')
CSS_URL = re.compile(r"(url\(['\"]?)(/[^)'\"]+)(['\"]?\))")


def key(url: str) -> str:
    """One name for one resource: the path without a trailing slash, the non-empty query parameters sorted."""
    parts = urlsplit(url)
    path = parts.path.rstrip("/") or "/"
    pairs = sorted((k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if v != "")
    return path + ("?" + urlencode(pairs) if pairs else "")


def doc_target(k: str) -> str:
    path, _, query = k.partition("?")
    base = path.strip("/")
    if query:
        base += "/_" + hashlib.sha1(query.encode()).hexdigest()[:10]
    return "/" + base + "/" if base else "/"


def res_target(k: str, ctype: str) -> str:
    return "/_r/" + hashlib.sha1(k.encode()).hexdigest()[:14] + EXT.get(ctype, ".bin")


def capped(path: str, seen: Counter) -> bool:
    for rx, cap in CAPS:
        if rx.match(path):
            seen[rx.pattern] += 1
            return seen[rx.pattern] > cap
    return False


def crawl(base: str, user: str, password: str, max_pages: int) -> tuple[dict, dict]:
    docs: dict[str, tuple[str, str]] = {}  # key -> (html, final key)
    res: dict[str, tuple[bytes, str]] = {}  # key -> (body, content type)
    queue = deque(["/ui/dashboard", "/ui/how-it-works", "/ui/findings", "/ui/campaigns", "/ui/campaigns/all",
                   "/ui/takedowns", "/ui/candidates", "/ui/brands", "/ui/activity", "/ui/settings"])  # fmt: skip
    queued = {key(u) for u in queue}
    kinds: Counter = Counter()
    variants: Counter = Counter()
    origin = urlsplit(base)._replace(path="", query="", fragment="").geturl()
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        page = browser.new_page(viewport={"width": 1440, "height": 900})
        page.goto(base + "/ui/login")
        page.fill("input[name=email]", user)
        page.fill("input[name=password]", password)
        page.click("button[type=submit]")
        page.wait_for_load_state("networkidle")
        while queue and len(docs) < max_pages:
            path = queue.popleft()
            k = key(path)
            responses = []
            def handler(r, _keep=responses):  # a plain function: Playwright cannot wrap a built-in method
                _keep.append(r)

            page.on("response", handler)
            try:
                nav = page.goto(base + path, wait_until="domcontentloaded", timeout=30000)
                try:
                    page.wait_for_load_state("networkidle", timeout=8000)
                except Exception:  # noqa: BLE001 - a page that keeps polling never goes idle; what it loaded so far is enough
                    pass
                page.wait_for_timeout(400)
            except Exception as exc:  # noqa: BLE001
                print(f"  ! {path}: {exc}", file=sys.stderr)
                page.remove_listener("response", handler)
                continue
            page.remove_listener("response", handler)
            if nav is None or nav.status >= 400:
                continue
            final = key(page.url[len(origin):] if page.url.startswith(origin) else path)
            ctype = (nav.headers.get("content-type") or "").split(";")[0]
            if ctype == "text/html":
                docs[k] = (nav.text(), final)
                if final != k and final not in docs:
                    docs[final] = docs[k]
            else:
                res[k] = (nav.body(), ctype)
            for r in responses:
                if r.request.method != "GET" or not r.url.startswith(origin) or r.status != 200 or r == nav:
                    continue
                if r.request.resource_type in ("document", "eventsource"):
                    continue
                rct = (r.headers.get("content-type") or "").split(";")[0]
                if rct == "text/html":
                    continue  # a captured kit page (evidence) is never copied
                rk = key(r.url[len(origin):])
                if rk not in res:
                    try:
                        res[rk] = (r.body(), rct)
                    except Exception:  # noqa: BLE001 - a stream or a body the browser already dropped
                        pass
            # pictures the page shows only on demand (the screenshots view, the lightbox) were never loaded: fetch them
            wanted = page.evaluate("""() => [...document.querySelectorAll('[src], [data-src]')]
                .flatMap(e => [e.getAttribute('src'), e.getAttribute('data-src')])
                .filter(u => u && u.startsWith('/') && !u.startsWith('//'))""")
            for u in wanted:
                uk = key(u)
                if uk in res:
                    continue
                try:
                    got = page.request.get(base + u)
                except Exception:  # noqa: BLE001
                    continue
                gct = (got.headers.get("content-type") or "").split(";")[0]
                if got.status == 200 and gct.startswith("image/"):
                    res[uk] = (got.body(), gct)
            links = page.evaluate("""() => [...document.querySelectorAll('a[href], [data-href]')]
                .map(a => a.getAttribute('href') || a.getAttribute('data-href'))""")
            for href in links:
                if not href or not href.startswith("/ui/"):
                    continue
                href = href.split("#")[0]
                lk = key(href)
                p = lk.split("?")[0]
                if lk in queued or SKIP.search(p):
                    continue
                if "?" in lk:
                    variants[p] += 1
                    if variants[p] > QUERY_VARIANTS_PER_PATH:
                        continue
                if capped(p, kinds):
                    continue
                queued.add(lk)
                queue.append(href)
            print(f"  {len(docs):4d} pages · {len(res):4d} files · {path}")
        browser.close()
    return docs, res


SHIM = r"""(function () {
  var MAP = window.__BW_MAP || {}, GH = window.__BW_GITHUB || '';
  var STATIC = {}; Object.keys(MAP).forEach(function (k) { STATIC[MAP[k]] = 1; });
  function key(u) {
    var url; try { url = new URL(u, location.href); } catch (e) { return null; }
    if (url.origin !== location.origin) return null;
    var p = []; url.searchParams.forEach(function (v, k) { if (v !== '') p.push([k, v]); });
    p.sort(function (a, b) { return a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0; });
    var q = p.map(function (x) { return encodeURIComponent(x[0]).replace(/%20/g, '+') + '=' + encodeURIComponent(x[1]).replace(/%20/g, '+'); }).join('&');
    return (url.pathname.replace(/\/+$/, '') || '/') + (q ? '?' + q : '');
  }
  function target(u) { var k = key(u); if (k === null) return null; if (MAP[k]) return MAP[k]; var path = new URL(u, location.href).pathname; return STATIC[path] ? path : ''; }
  var toastEl = null, toastT = null;
  function notice(what) {
    if (!document.body) return;
    if (!toastEl) {
      toastEl = document.createElement('div');
      toastEl.style.cssText = 'position:fixed;left:50%;bottom:64px;transform:translateX(-50%);z-index:99999;max-width:min(560px,92vw);padding:12px 18px;border-radius:10px;background:#0b1622;border:1px solid #35C7F2;color:#e6f6ff;font:14px/1.45 system-ui,sans-serif;box-shadow:0 10px 30px rgba(0,0,0,.5);text-align:center';
      document.body.appendChild(toastEl);
    }
    toastEl.innerHTML = '<b>Static demo</b> — ' + (what || 'this action changes data, so it is switched off here.') +
      (GH ? ' <a href="' + GH + '" target="_blank" rel="noopener" style="color:#35C7F2">Run the full app from GitHub ↗</a>' : '');
    toastEl.style.display = 'block'; clearTimeout(toastT); toastT = setTimeout(function () { toastEl.style.display = 'none'; }, 4200);
  }
  window.__bwStaticNotice = notice;
  var ofetch = window.fetch ? window.fetch.bind(window) : null;
  window.fetch = function (input, init) {
    var url = typeof input === 'string' ? input : (input && input.url) || String(input);
    var method = ((init && init.method) || (input && input.method) || 'GET').toUpperCase();
    var t = target(url);
    if (t === null) return ofetch(input, init);
    if (method === 'GET' && t) return ofetch(t);
    var path = new URL(url, location.href).pathname;
    if (method === 'GET' && /\/events$/.test(path)) return Promise.resolve(new Response(JSON.stringify({events: [], state: 'done'}), {status: 200, headers: {'Content-Type': 'application/json'}}));
    if (method !== 'GET') notice();
    return Promise.resolve(new Response(JSON.stringify({detail: 'static demo: not available here'}), {status: method === 'GET' ? 404 : 403, headers: {'Content-Type': 'application/json'}}));
  };
  window.EventSource = function () { var self = this; this.readyState = 2; this.close = function () {}; this.addEventListener = function (t, f) { if (t === 'error') setTimeout(function () { f({}); }, 0); };
    setTimeout(function () { if (self.onerror) self.onerror({}); }, 0); };
  function go(url, hash, blank) { var t = target(url); if (!t) { notice('this page is not part of the static demo.'); return; } if (blank) window.open(t + (hash || ''), '_blank'); else location.href = t + (hash || ''); }
  document.addEventListener('click', function (e) {
    var a = e.target.closest && e.target.closest('a[href]');
    if (!a || e.defaultPrevented) return;
    var href = a.getAttribute('href') || '';
    if (!href || href.charAt(0) === '#' || /^(mailto:|tel:|javascript:)/.test(href)) return;
    var url = new URL(href, location.href);
    if (url.origin !== location.origin) return;
    var t = target(url.href);
    if (t && t === url.pathname && !url.search) return;  // already a saved page
    e.preventDefault(); e.stopImmediatePropagation();
    if (t) go(url.href, url.hash, a.target === '_blank'); else notice('this page is not part of the static demo.');
  }, true);
  function submitted(form, btn) {
    var method = (form.getAttribute('method') || 'get').toLowerCase();
    if (method !== 'get') { notice(); return; }
    var url = new URL(form.getAttribute('action') || location.pathname, location.href);
    var fd = new FormData(form); if (btn && btn.name) fd.append(btn.name, btn.value);
    url.search = ''; fd.forEach(function (v, k) { if (typeof v === 'string') url.searchParams.append(k, v); });
    go(url.href, '', false);
  }
  document.addEventListener('submit', function (e) { e.preventDefault(); e.stopImmediatePropagation(); submitted(e.target, e.submitter); }, true);
  HTMLFormElement.prototype.submit = function () { submitted(this, null); };
  HTMLFormElement.prototype.requestSubmit = function (btn) { submitted(this, btn || null); };
  document.addEventListener('DOMContentLoaded', function () {
    var pill = document.createElement('a');
    pill.href = GH || '#'; pill.target = '_blank'; pill.rel = 'noopener';
    pill.innerHTML = '<b style="color:#35C7F2">STATIC DEMO</b> · fictional brands · read-only' + (GH ? ' · GitHub ↗' : '');
    pill.style.cssText = 'position:fixed;left:14px;bottom:14px;z-index:99998;padding:7px 13px;border-radius:999px;background:rgba(8,16,26,.92);border:1px solid rgba(53,199,242,.55);color:#cfe9f5;font:12px/1.2 system-ui,sans-serif;text-decoration:none;letter-spacing:.02em;box-shadow:0 6px 18px rgba(0,0,0,.4)';
    document.body.appendChild(pill);
  });
})();
"""

INDEX = """<!doctype html><html lang="en"><head><meta charset="utf-8"><title>BrandWatch · static demo</title>
<meta http-equiv="refresh" content="0; url=/ui/dashboard/"><link rel="canonical" href="/ui/dashboard/"></head>
<body style="background:#060b12;color:#cfe9f5;font-family:system-ui"><p><a href="/ui/dashboard/" style="color:#35C7F2">Open the BrandWatch demo →</a></p></body></html>
"""
NOT_FOUND = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Not in the static demo · BrandWatch</title></head>
<body style="background:#060b12;color:#cfe9f5;font:16px/1.5 system-ui,sans-serif;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0">
<div style="max-width:520px;padding:24px;text-align:center"><h1 style="font-size:22px;color:#35C7F2">Not part of the static demo</h1>
<p>This copy holds the main pages of BrandWatch with fictional brands. The full app runs locally in a few minutes.</p>
<p><a href="/ui/dashboard/" style="color:#35C7F2">← Back to the dashboard</a>{github}</p></div></body></html>
"""


def write_site(docs: dict, res: dict, out: Path, github: str) -> None:
    if out.exists():
        shutil.rmtree(out)
    (out / "_r").mkdir(parents=True)
    (out / "_demo").mkdir()
    mapping: dict[str, str] = {}
    for k, (body, ctype) in res.items():
        t = res_target(k, ctype)
        (out / t.lstrip("/")).write_bytes(body)
        mapping[k] = t
    for k in docs:
        mapping[k] = doc_target(k)

    def swap(m: re.Match) -> str:
        raw = html.unescape(m.group(2))
        path, hashpart = (raw.split("#", 1) + [""])[:2]
        t = mapping.get(key(path))
        if not t:
            return m.group(0)
        return m.group(1) + html.escape(t + ("#" + hashpart if hashpart else "")) + m.group(3)

    head = ('<script>window.__BW_GITHUB=' + json.dumps(github) + '</script>'
            '<script src="/_demo/map.js"></script><script src="/_demo/shim.js"></script>')  # fmt: skip
    for k, (text, _final) in docs.items():
        page = ATTR.sub(swap, text)
        page = CSS_URL.sub(swap, page)
        page = re.sub(r"<head([^>]*)>", lambda m: "<head" + m.group(1) + ">" + head, page, count=1)
        dest = out / doc_target(k).strip("/") / "index.html" if doc_target(k) != "/" else out / "index.html"
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(page, encoding="utf-8")
    (out / "_demo" / "map.js").write_text("window.__BW_MAP=" + json.dumps(mapping, separators=(",", ":")) + ";", encoding="utf-8")
    (out / "_demo" / "shim.js").write_text(SHIM, encoding="utf-8")
    if "/" not in docs:
        (out / "index.html").write_text(INDEX, encoding="utf-8")
    gh = f' · <a href="{html.escape(github)}" style="color:#35C7F2">GitHub ↗</a>' if github else ""
    (out / "404.html").write_text(NOT_FOUND.replace("{github}", gh), encoding="utf-8")
    # a demo of a phishing-detection tool: keep it out of search engines
    (out / "_headers").write_text("/*\n  X-Robots-Tag: noindex\n  Referrer-Policy: no-referrer\n", encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--base", default="http://127.0.0.1:8765")
    ap.add_argument("--out", default="site")
    ap.add_argument("--user", default="admin")
    ap.add_argument("--password", default="admin")
    ap.add_argument("--max-pages", type=int, default=450)
    ap.add_argument("--github", default="https://github.com/itaya12/brandwatch")
    args = ap.parse_args()
    t0 = time.time()
    docs, res = crawl(args.base.rstrip("/"), args.user, args.password, args.max_pages)
    write_site(docs, res, Path(args.out), args.github)
    size = sum(p.stat().st_size for p in Path(args.out).rglob("*") if p.is_file())
    print(f"done: {len(docs)} pages, {len(res)} files, {size / 1e6:.1f} MB in {time.time() - t0:.0f}s → {args.out}/")


if __name__ == "__main__":
    main()
