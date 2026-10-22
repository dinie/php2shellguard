#!/usr/bin/env python3
"""Generate placeholder shield icons for the extension (no dependencies).

Draws a shield badge as two layered polygons and writes icon16/48/128.png
next to this script. Re-run any time with: python3 generate_icons.py
"""

from __future__ import annotations

import struct
import zlib
from pathlib import Path

OUT_DIR = Path(__file__).resolve().parent
SIZES = (16, 48, 128)

SHIELD = [
    (0.50, 0.03),
    (0.93, 0.15),
    (0.93, 0.52),
    (0.50, 0.97),
    (0.07, 0.52),
    (0.07, 0.15),
]

OUTER = (49, 46, 129, 255)  # indigo-800
INNER = (224, 231, 255, 255)  # indigo-100


def scale_polygon(points, factor, cx=0.5, cy=0.5):
    return [
        (cx + (x - cx) * factor, cy + (y - cy) * factor) for x, y in points
    ]


def point_in_polygon(x, y, polygon):
    inside = False
    j = len(polygon) - 1
    for i in range(len(polygon)):
        xi, yi = polygon[i]
        xj, yj = polygon[j]
        if (yi > y) != (yj > y) and x < (xj - xi) * (y - yi) / (yj - yi) + xi:
            inside = not inside
        j = i
    return inside


def write_png(path, size, pixels):
    raw = b"".join(
        b"\x00" + b"".join(struct.pack("4B", *pixel) for pixel in row)
        for row in pixels
    )

    def chunk(tag, data):
        return (
            struct.pack(">I", len(data))
            + tag
            + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        )

    png = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw))
        + chunk(b"IEND", b"")
    )
    path.write_bytes(png)


def render(size):
    outer = SHIELD
    inner = scale_polygon(SHIELD, 0.68)
    pixels = []
    for py in range(size):
        row = []
        y = (py + 0.5) / size
        for px in range(size):
            x = (px + 0.5) / size
            if point_in_polygon(x, y, inner):
                row.append(INNER)
            elif point_in_polygon(x, y, outer):
                row.append(OUTER)
            else:
                row.append((0, 0, 0, 0))
        pixels.append(row)
    return pixels


def main():
    for size in SIZES:
        write_png(OUT_DIR / f"icon{size}.png", size, render(size))
        print(f"wrote icon{size}.png")


if __name__ == "__main__":
    main()
