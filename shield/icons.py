"""Kleine Status-Badges (gruener Haken / rotes Kreuz) als PNG-Bytes.

Programmatisch mit Pillow gezeichnet - keine externen Bilddateien noetig.
Wird inline per CID in Bestaetigungs-/Ablehnungs-Mails eingebettet.
"""
from __future__ import annotations

import io

from PIL import Image, ImageDraw

_GREEN = (46, 125, 50, 255)    # #2e7d32
_RED = (198, 40, 40, 255)      # #c62828
_WHITE = (255, 255, 255, 255)


def _badge(bg, symbol, size: int = 96) -> bytes:
    """Kreis in Farbe bg, darauf das per `symbol` gezeichnete weisse Zeichen.
    Wird in 4x gezeichnet und heruntergerechnet (Kantenglaettung)."""
    scale = 4
    s = size * scale
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.ellipse([0, 0, s - 1, s - 1], fill=bg)
    symbol(d, s, scale)
    img = img.resize((size, size), Image.LANCZOS)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def check_png(size: int = 96) -> bytes:
    """Gruener Kreis mit weissem Haken."""
    def sym(d, s, sc):
        w = 7 * sc
        pts = [(0.28 * s, 0.52 * s), (0.44 * s, 0.68 * s), (0.74 * s, 0.34 * s)]
        try:
            d.line(pts, fill=_WHITE, width=w, joint="curve")
        except TypeError:  # aeltere Pillow ohne joint
            d.line(pts, fill=_WHITE, width=w)
    return _badge(_GREEN, sym, size)


def cross_png(size: int = 96) -> bytes:
    """Roter Kreis mit weissem Kreuz."""
    def sym(d, s, sc):
        w = 7 * sc
        m = 0.33
        d.line([(m * s, m * s), ((1 - m) * s, (1 - m) * s)], fill=_WHITE, width=w)
        d.line([(m * s, (1 - m) * s), ((1 - m) * s, m * s)], fill=_WHITE, width=w)
    return _badge(_RED, sym, size)
