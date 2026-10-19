"""One palette for every screen.

Severity hues, the eight colours an operation is drawn in and the colour of a pivot kind are read
by three different renderers: the CSS in ``base.html``, the SVG the server writes straight into a
page, and the JavaScript that draws the graphs. Each of them used to carry its own copy, and they
had already drifted apart — a past IP was one cyan in the connections view and a different one in
the all-operations map, and the eight-colour series was written out three times.

The values here are the ones ``base.html`` declares on ``:root``; ``tests/test_palette.py`` fails if
the two ever disagree. So CSS reads the custom properties, JavaScript reads them back through
``BW.ink`` (defined in ``base.html``), and a template asks this module.
"""

from __future__ import annotations

from typing import Any

# The semantic tokens, mirroring ``:root`` in base.html. A name here is the same name there.
INK: dict[str, str] = {
    "bg": "#080B14",  # the page ground — the room the whole product sits in
    "panel": "#0E1420",  # a recessed surface
    "panel2": "#121A2B",  # a raised surface: chips, pills, default buttons
    "field": "#0b1220",  # an input: darker than the panel it sits on, so it reads as a hole
    "console": "#060910",  # the live scan console only — the deepest value in the system
    "border": "#1E2A3D",  # every hairline, and the empty track behind every bar and ring
    "accent": "#35C7F2",  # the one accent: interactive, or alive
    "accent2": "#5FE3FF",  # its lit edge, for text that would be too dim in the accent itself
    "crit": "#FF4D4D",
    "high": "#FF9F1C",
    "med": "#F5C518",
    "low": "#2ECC71",
    "text": "#E6EDF5",
    "text2": "#C3CDD9",  # prose that explains rather than states: intros, chapter copy, captions
    "muted": "#8A97A8",  # labels, column heads, legends
    "dim": "#7C8A9E",  # the quietest legible step: group headings, a cell label on a phone
    "on-lit": "#06121D",  # ink on a lit surface — a solid accent button, a filled chip
}

# severity → its hue. The four are an enumeration, not a palette.
SEV: dict[str, str] = {
    "critical": INK["crit"],
    "high": INK["high"],
    "medium": INK["med"],
    "low": INK["low"],
}

# The eight series colours an operation is drawn in, by its index. The first four are the system's
# own hues; the last four exist only because a graph of eight operations needs eight colours no
# reader can confuse. Series colour never means severity — the legend says which operation is which.
OPS: list[str] = [
    INK["accent"],
    INK["med"],
    INK["high"],
    INK["low"],
    "#B388FF",
    "#FF6FA8",
    "#4DD0C4",
    "#9AA5B1",
]

# The same eight for the operation report, which is ink on paper: print-safe, and dark enough that a
# label sits on white. The night series would wash out.
OPS_PRINT: list[str] = [
    "#0b6fbd",
    "#b88a00",
    "#e07b00",
    "#2e7d32",
    "#7b4fd1",
    "#d6336c",
    "#00897b",
    "#5d6b7e",
]

# What a pivot kind is drawn in. The hue says what kind of evidence ties two sites together; how
# strong that tie is comes from the dashed outline, never from a dimmer shade of the same hue.
KIND: dict[str, str] = {
    # the server it runs on, now or before
    "ip": INK["accent"],
    "shared_ip": INK["accent"],
    "past_ip": INK["accent"],
    # what the page is made of: its certificate and the kit's own code
    "certificate": INK["med"],
    "kit": INK["med"],
    "kit_look": INK["med"],
    # what the operator plugged in, and where the stolen data goes
    "tracking_id": INK["high"],
    "data_sink": INK["high"],
    # who it belongs to — the strongest ties there are
    "registrant": INK["crit"],
    "dns_token": INK["crit"],
    "affiliate_id": INK["crit"],
    # where the traffic is sent on to
    "tds_campaign": INK["low"],
    "shared_tds": INK["low"],
    "favicon": INK["low"],
    "redirector": OPS[4],
    # bookkeeping ties: a registrar, a nameserver, one registration batch
    "cf_ns_pair": INK["muted"],
    "batch": INK["muted"],
    "registrar": INK["muted"],
    "nameserver": INK["muted"],
}


def op(index: int | None) -> str:
    """The series colour of operation ``index`` (1-based). Unplaced sites stay muted."""
    return OPS[(int(index) - 1) % len(OPS)] if index else INK["muted"]


def op_print(index: int | None) -> str:
    """The same, on paper."""
    return OPS_PRINT[(int(index) - 1) % len(OPS_PRINT)] if index else INK["muted"]


def sev(severity: str | None) -> str:
    """The hue of a severity; anything unscored is muted."""
    return SEV.get(str(severity or "").lower(), INK["muted"])


def kind(name: str | None) -> str:
    """The hue of a pivot kind; a kind nobody has coloured yet is muted, not invented."""
    return KIND.get(str(name or ""), INK["muted"])


def register(templates: Any) -> None:
    env = templates.env
    env.globals.update({
        "INK": INK, "SEV": SEV, "OPS": OPS, "OPS_PRINT": OPS_PRINT, "KIND": KIND,
        "op_color": op, "op_print_color": op_print, "sev_color": sev, "kind_color": kind,
    })  # fmt: skip
