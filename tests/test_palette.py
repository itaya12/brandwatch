"""The palette has one source, and these tests fail the moment it has two.

``api/palette.py`` is read by everything the server draws itself; the ``:root`` block in
``base.html`` is read by the stylesheet and, through ``BW.ink``, by every graph in the browser. The
two lists carry the same values, so the only thing that can go wrong is somebody changing one of
them. That is what this file is for.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from brandwatch.api import palette

TEMPLATES = Path(palette.__file__).parent / "templates"
BASE = TEMPLATES / "base.html"


def _root_tokens() -> dict[str, str]:
    """Every custom property declared on ``:root`` in base.html, with ``var()`` resolved."""
    css = BASE.read_text(encoding="utf-8")
    tokens: dict[str, str] = {}
    for block in re.findall(r":root\{(.*?)\}", css, re.S):
        for name, value in re.findall(r"--([a-z0-9-]+)\s*:\s*([^;}]+)", block):
            tokens[name] = value.strip()
    for _ in range(4):  # a token may be declared as another token
        for name, value in list(tokens.items()):
            ref = re.fullmatch(r"var\(--([a-z0-9-]+)\)", value)
            if ref and ref.group(1) in tokens:
                tokens[name] = tokens[ref.group(1)]
    return tokens


@pytest.mark.parametrize("name", sorted(palette.INK))
def test_every_ink_token_matches_the_stylesheet(name: str) -> None:
    root = _root_tokens()
    assert name in root, f"palette.INK['{name}'] has no --{name} on :root in base.html"
    assert root[name].lower() == palette.INK[name].lower(), (
        f"--{name} is {root[name]} in base.html but {palette.INK[name]} in palette.py"
    )


def test_the_operation_series_matches_the_stylesheet() -> None:
    root = _root_tokens()
    series = [root.get(f"op{i}", "").lower() for i in range(1, len(palette.OPS) + 1)]
    assert series == [c.lower() for c in palette.OPS]


def test_every_kind_colour_is_a_palette_colour() -> None:
    """A pivot kind is drawn in a colour the system owns — never in one invented for it."""
    allowed = {c.lower() for c in palette.INK.values()} | {c.lower() for c in palette.OPS}
    for kind, colour in palette.KIND.items():
        assert colour.lower() in allowed, f"{kind} is drawn in {colour}, which is not in the palette"


def test_the_print_series_is_as_long_as_the_night_one() -> None:
    """The report cycles through operations the same way the map does, in ink that survives paper."""
    assert len(palette.OPS_PRINT) == len(palette.OPS)
    assert palette.op_print(1) == palette.OPS_PRINT[0]
    assert palette.op_print(len(palette.OPS_PRINT) + 1) == palette.OPS_PRINT[0]
    assert palette.op_print(None) == palette.INK["muted"]


def test_an_unknown_name_stays_muted_instead_of_being_invented() -> None:
    assert palette.kind("something_nobody_coloured") == palette.INK["muted"]
    assert palette.sev(None) == palette.INK["muted"]
    assert palette.sev("critical") == palette.INK["crit"]
    assert palette.op(None) == palette.INK["muted"]
    assert palette.op(1) == palette.INK["accent"]


def test_no_template_declares_a_token_the_system_already_has() -> None:
    """A page may name a value of its own; it may not shadow one the system declares.

    The How-it-works page used to alias ``--ink``, ``--line`` and ``--card`` to tokens that already
    existed, so the same colour had two names and one of them could drift.
    """
    owned = set(_root_tokens())
    offenders: list[str] = []
    for path in sorted(TEMPLATES.glob("*.html")):
        if path.name in ("base.html", "operation_report.html"):
            continue  # base declares them; the report is a separate, daylight document
        for name in re.findall(r"--([a-z0-9-]+)\s*:", path.read_text(encoding="utf-8")):
            if name in owned and name not in ("side-w", "p", "c"):
                offenders.append(f"{path.name} redeclares --{name}")
    assert not offenders, "; ".join(offenders)


def test_no_template_uses_a_token_nobody_declares() -> None:
    """``var(--cyan, #35c7f2)`` sat in four places; ``--cyan`` was never declared anywhere.

    A token set on an element — ``style="--i:3"``, or from a script — counts as declared: the
    stagger and ring properties are written per element and read from the stylesheet.
    """
    declared = set(_root_tokens())
    for path in TEMPLATES.glob("*.html"):
        text = path.read_text(encoding="utf-8")
        declared |= set(re.findall(r"--([a-z0-9-]+)\s*:", text))
        declared |= set(re.findall(r"setProperty\(\s*['\"]--([a-z0-9-]+)", text))
    unknown: dict[str, set[str]] = {}
    for path in sorted(TEMPLATES.glob("*.html")):
        for name in re.findall(r"var\(--([a-z0-9-]+)", path.read_text(encoding="utf-8")):
            if name not in declared:
                unknown.setdefault(path.name, set()).add(name)
    assert not unknown, f"undeclared tokens in use: {unknown}"
