"""Image helpers: perceptual hashes, Shodan-style favicon hash, and deterministic synthetic
artifacts for demo mode.

* ``phash_hex`` / ``similarity`` — 64-bit pHash (32×32 grey → DCT-II → top-left 8×8 vs median),
  implemented with numpy only (imagehash pulls in scipy, which this environment cannot load)
* ``favicon_mmh3`` — MurmurHash3 of the base64 favicon, the convention Shodan/Censys index on
* ``synth_screenshot`` / ``synth_favicon`` — deterministic PNGs derived from a key, so mocks can
  serve "the brand's favicon", "a near-identical screenshot" or "something unrelated" at $0
"""

from __future__ import annotations

import base64
import hashlib
import io
import random
from functools import lru_cache

import mmh3
import numpy as np
from PIL import Image, ImageDraw

_HASH_SIZE = 8
_HIGHFREQ_FACTOR = 4


@lru_cache(maxsize=1)
def _dct_matrix(n: int) -> np.ndarray:
    """Orthonormal DCT-II matrix (n×n)."""
    k = np.arange(n).reshape(-1, 1)
    i = np.arange(n).reshape(1, -1)
    m = np.cos(np.pi * (2 * i + 1) * k / (2 * n)) * np.sqrt(2.0 / n)
    m[0, :] /= np.sqrt(2.0)
    return m


def phash_bits(data: bytes) -> np.ndarray:
    size = _HASH_SIZE * _HIGHFREQ_FACTOR
    with Image.open(io.BytesIO(data)) as im:
        grey = im.convert("L").resize((size, size), Image.Resampling.LANCZOS)
    pixels = np.asarray(grey, dtype=np.float64)
    d = _dct_matrix(size)
    dct = d @ pixels @ d.T
    low = dct[:_HASH_SIZE, :_HASH_SIZE]
    return (low > np.median(low)).flatten()


def phash_hex(data: bytes) -> str:
    bits = phash_bits(data)
    value = 0
    for b in bits:
        value = (value << 1) | int(b)
    return f"{value:016x}"


def dhash_hex(data: bytes) -> str:
    """64-bit difference hash (9x8 grey, horizontal gradients) - complements pHash."""
    with Image.open(io.BytesIO(data)) as im:
        grey = im.convert("L").resize((9, 8), Image.Resampling.LANCZOS)
    px = np.asarray(grey, dtype=np.int16)
    bits = (px[:, 1:] > px[:, :-1]).flatten()
    value = 0
    for b in bits:
        value = (value << 1) | int(b)
    return f"{value:016x}"


def hamming(a_hex: str, b_hex: str) -> int:
    return bin(int(a_hex, 16) ^ int(b_hex, 16)).count("1")


def similarity(a_hex: str, b_hex: str) -> float:
    """1.0 identical … 0.0 maximally different (64-bit pHash)."""
    return max(0.0, 1.0 - hamming(a_hex, b_hex) / 64.0)


def is_svg(data: bytes | None) -> bool:
    head = (data or b"")[:400].lstrip().lower()
    return head.startswith(b"<svg") or (head.startswith((b"<?xml", b"<!doctype svg")) and b"<svg" in (data or b"")[:2000].lower())


async def rasterize_svg(svg: bytes, size: int = 64) -> bytes | None:
    """A PNG of an SVG favicon (Pillow cannot read SVG, and many brands now serve only ``favicon.svg``), drawn by
    the sandboxed Chromium that is already part of BrandWatch. The SVG is shown as an <img> from a data: URL, so
    nothing in it runs and nothing is fetched. None when no browser is available."""
    try:
        from playwright.async_api import async_playwright
    except Exception:  # noqa: BLE001
        return None
    page_html = (f'<html><body style="margin:0;background:transparent"><img id="i" width="{size}" height="{size}" '
                 f'src="data:image/svg+xml;base64,{base64.b64encode(svg).decode()}"></body></html>')  # fmt: skip
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch()
            try:
                page = await browser.new_page(viewport={"width": size, "height": size})
                await page.set_content(page_html)
                return await page.locator("#i").screenshot(omit_background=True)
            finally:
                await browser.close()
    except Exception:  # noqa: BLE001 - a favicon is never worth failing onboarding for
        return None


def favicon_mmh3(data: bytes) -> int:
    """Shodan convention: mmh3 over the *base64-encoded* bytes (with newlines, as encodebytes)."""
    return mmh3.hash(base64.encodebytes(data))


def image_size(data: bytes) -> tuple[int, int]:
    with Image.open(io.BytesIO(data)) as im:
        return im.size


def is_blank(data: bytes | None, *, share: float = 0.997) -> bool:
    """A picture of nothing: one flat colour (a white page of a gate that has not forwarded yet, a failed render). At
    least ``share`` of the pixels sit within a few grey levels of the same value. A page with a small logo on white is
    not blank; a picture that cannot be read is not called blank either."""
    if not data:
        return False
    try:
        with Image.open(io.BytesIO(data)) as im:
            grey = im.convert("L")
            grey.thumbnail((200, 200))
            hist = grey.histogram()
    except Exception:  # noqa: BLE001 - an unreadable picture is not evidence of a blank page
        return False
    total = sum(hist)
    if not total:
        return False
    peak = max(sum(hist[max(0, i - 4): i + 5]) for i in range(256))
    return peak / total >= share


def _rng(key: str) -> random.Random:
    return random.Random(int(hashlib.sha256(key.encode()).hexdigest()[:16], 16))


def synth_screenshot(key: str, *, size: tuple[int, int] = (320, 200), shift: int = 0) -> bytes:
    """A deterministic 'page' (coloured block grid + header bar) derived from ``key``.
    ``shift`` nudges every colour slightly: pHash distance stays tiny (a 'near-identical' page)."""
    rng = _rng(key)
    w, h = size
    im = Image.new("RGB", size, (255, 255, 255))
    d = ImageDraw.Draw(im)
    cols, rows = 8, 5
    bw, bh = w // cols, h // rows
    for r in range(rows):
        for c in range(cols):
            colour = tuple(min(255, rng.randrange(30, 220) + shift) for _ in range(3))
            d.rectangle([c * bw, r * bh, (c + 1) * bw - 1, (r + 1) * bh - 1], fill=colour)
    header = tuple(min(255, rng.randrange(0, 90) + shift) for _ in range(3))
    d.rectangle([0, 0, w, bh // 2], fill=header)
    buf = io.BytesIO()
    im.save(buf, format="PNG")
    return buf.getvalue()


def synth_favicon(key: str, *, size: int = 16) -> bytes:
    rng = _rng(f"favicon:{key}")
    im = Image.new("RGB", (size, size), tuple(rng.randrange(0, 256) for _ in range(3)))
    d = ImageDraw.Draw(im)
    for _ in range(6):
        x0, y0 = rng.randrange(size), rng.randrange(size)
        x1, y1 = rng.randrange(x0, size), rng.randrange(y0, size)
        d.rectangle([x0, y0, x1, y1], fill=tuple(rng.randrange(0, 256) for _ in range(3)))
    buf = io.BytesIO()
    im.save(buf, format="PNG")
    return buf.getvalue()
