"""DOM structure similarity (spec §5 ``login_dom_similarity``) and screenshot palette comparison
(``palette_match``), Phase 2.

* ``dom_signature``   — an ordered token list describing the page skeleton: landmark tags, every
  form with its inputs (type / name hints / buttons). Kits copy the brand's login markup, so the
  skeleton survives even when text and styling are tweaked.
* ``dom_similarity``  — difflib ratio on two signatures (0–1).
* ``palette``         — the dominant colours of a screenshot (quantised, ordered by weight).
* ``palette_similarity`` — fraction of the suspect's dominant *brand* colours (white / grey / black
  ignored) that are close to one of the brand's.
"""

from __future__ import annotations

import io
from difflib import SequenceMatcher

from bs4 import BeautifulSoup
from PIL import Image

_LANDMARKS = ("header", "nav", "main", "footer", "aside", "h1", "h2", "img", "a", "button")
_INPUT_HINTS = ("email", "user", "login", "phone", "pass", "card", "cvv", "otp", "code", "seed")


def _input_token(tag) -> str:
    kind = (tag.get("type") or tag.name or "text").lower()
    if kind == "password":
        return "input:password"  # stable token the analysis stage keys on
    blob = " ".join(
        str(tag.get(a, "")) for a in ("name", "id", "autocomplete", "placeholder")
    ).lower()
    hint = next((h for h in _INPUT_HINTS if h in blob), "")
    return f"input:{kind}{':' + hint if hint else ''}"


def dom_signature(html: str, *, max_tokens: int = 400) -> list[str]:
    soup = BeautifulSoup(html or "", "html.parser")
    for t in soup(["script", "style", "noscript", "svg"]):
        t.decompose()
    tokens: list[str] = []
    for el in soup.find_all(True):
        name = el.name.lower()
        if name == "form":
            tokens.append("form:open")
            for inp in el.find_all(["input", "textarea", "select", "button"]):
                tokens.append(
                    "button"
                    if inp.name == "button" or inp.get("type") in ("submit", "button")
                    else _input_token(inp)
                )
            tokens.append("form:close")
        elif name in _LANDMARKS and not el.find_parent("form"):
            tokens.append(name)
        if len(tokens) >= max_tokens:
            break
    return tokens


def dom_similarity(a: list[str], b: list[str]) -> float:
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a, b, autojunk=False).ratio()


def login_form_signature(html: str) -> list[str]:
    """Only the forms (what a credential-harvesting kit must reproduce)."""
    sig = dom_signature(html)
    out: list[str] = []
    inside = False
    for tok in sig:
        if tok == "form:open":
            inside = True
        if inside:
            out.append(tok)
        if tok == "form:close":
            inside = False
    return out


def palette(png: bytes, *, colors: int = 6) -> list[tuple[int, int, int]]:
    with Image.open(io.BytesIO(png)) as im:
        small = im.convert("RGB").resize((64, 40))
        quant = small.quantize(colors=colors, method=Image.Quantize.MEDIANCUT)
        pal = quant.getpalette()[: colors * 3]
        counts = sorted(quant.getcolors() or [], reverse=True)
    out: list[tuple[int, int, int]] = []
    for _n, idx in counts:
        r, g, b = pal[idx * 3 : idx * 3 + 3]
        out.append((r, g, b))
    return out


def _close(c1: tuple[int, int, int], c2: tuple[int, int, int], tol: int = 18) -> bool:
    return sum(abs(a - b) for a, b in zip(c1, c2, strict=True)) <= tol * 3


def _neutral(c: tuple[int, int, int], spread: int = 30, saturation: float = 0.25) -> bool:
    """White, grey, black and washed-out tints: every site has them, so they say nothing about a
    brand. Neutral = a small channel spread, or a low HSV saturation (spread / brightest channel)."""
    hi, lo = max(c), min(c)
    return hi - lo < spread or (hi - lo) / max(hi, 1) < saturation


def palette_similarity(a: list[tuple[int, int, int]], b: list[tuple[int, int, int]]) -> float:
    """Share of the suspect's *brand* colours that are close to one of the brand's. Neutral colours
    are ignored on both sides — otherwise any mostly-white site would "match" a mostly-white brand."""
    a, b = [c for c in a if not _neutral(c)], [c for c in b if not _neutral(c)]
    if not a or not b:
        return 0.0
    hits = sum(1 for c in a if any(_close(c, d) for d in b))
    return hits / len(a)


def palette_to_hex(p: list[tuple[int, int, int]]) -> list[str]:
    return [f"#{r:02x}{g:02x}{b:02x}" for r, g, b in p]


def palette_from_hex(hexes: list[str]) -> list[tuple[int, int, int]]:
    out: list[tuple[int, int, int]] = []
    for h in hexes:
        h = h.lstrip("#")
        if len(h) == 6:
            out.append((int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)))
    return out
