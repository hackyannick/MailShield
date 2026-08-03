"""Verrauschtes Bild-CAPTCHA (PNG-Bytes) auf Basis von Pillow."""
from __future__ import annotations

import io
import os
import random
import string

from PIL import Image, ImageDraw, ImageFilter, ImageFont

# Mehrdeutige Zeichen weglassen (0/O, 1/I/l).
_AMBIGUOUS = set("0O1Il")
ALPHABET = "".join(
    c for c in (string.ascii_uppercase + string.digits) if c not in _AMBIGUOUS
)

_FONT_CANDIDATES = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
    "/usr/share/fonts/liberation/LiberationSans-Bold.ttf",
    "/Library/Fonts/Arial.ttf",
]


def random_code(length: int = 6) -> str:
    return "".join(random.choice(ALPHABET) for _ in range(length))


def _load_font(size: int) -> ImageFont.FreeTypeFont:
    for path in _FONT_CANDIDATES:
        if os.path.exists(path):
            try:
                return ImageFont.truetype(path, size)
            except Exception:
                pass
    try:  # Pillow >= 10.1 kann load_default skalieren
        return ImageFont.load_default(size=size)
    except TypeError:  # pragma: no cover
        return ImageFont.load_default()


def render(code: str, width: int = 280, height: int = 90) -> bytes:
    img = Image.new("RGB", (width, height), (245, 245, 245))
    draw = ImageDraw.Draw(img)

    # Hintergrundrauschen (Punkte)
    for _ in range(int(width * height * 0.04)):
        g = random.randint(160, 225)
        draw.point((random.randint(0, width - 1), random.randint(0, height - 1)),
                   fill=(g, g, g))

    # Stoerlinien im Hintergrund
    for _ in range(6):
        g = random.randint(120, 190)
        draw.line(
            [(random.randint(0, width), random.randint(0, height)),
             (random.randint(0, width), random.randint(0, height))],
            fill=(g, g, g), width=1,
        )

    font = _load_font(48)
    n = len(code)
    slot = width / (n + 1)
    for i, ch in enumerate(code):
        cell = Image.new("RGBA", (60, 72), (0, 0, 0, 0))
        cd = ImageDraw.Draw(cell)
        color = (random.randint(0, 90), random.randint(0, 90), random.randint(0, 90))
        cd.text((8, 6), ch, font=font, fill=color)
        cell = cell.rotate(random.uniform(-28, 28), expand=1, resample=Image.BICUBIC)
        x = int(slot * (i + 1) - cell.width / 2 + random.randint(-4, 4))
        y = int((height - cell.height) / 2 + random.randint(-6, 6))
        img.paste(cell, (x, y), cell)

    # Stoerboegen im Vordergrund
    for _ in range(3):
        g = random.randint(60, 140)
        bbox = [
            random.randint(0, width // 2), random.randint(0, height // 2),
            random.randint(width // 2, width), random.randint(height // 2, height),
        ]
        draw.arc(bbox, random.randint(0, 180), random.randint(180, 360),
                 fill=(g, g, g))

    img = img.filter(ImageFilter.GaussianBlur(0.6))

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()
