"""Generate the Valkyrie app icon (electron/build/icon.ico) + a 512px PNG.

Pure-Pillow render of the shield/wing mark on a matte-black rounded tile with a
soft blue rim — the same visual language as the in-app splash logo. Run once;
the .ico is what electron-builder embeds into Valkyrie.exe and ValkyrieSetup.exe.
"""
from __future__ import annotations
import math
from pathlib import Path
from PIL import Image, ImageDraw

HERE = Path(__file__).resolve().parent
OUT_DIR = HERE.parent / "electron" / "build"
OUT_DIR.mkdir(parents=True, exist_ok=True)

# Supersample for crisp edges, then downscale to each icon size.
SS = 1024


def lerp(a, b, t):
    return tuple(round(a[i] + (b[i] - a[i]) * t) for i in range(len(a)))


def render(size: int) -> Image.Image:
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    # Rounded matte tile with a subtle top-down graphite gradient.
    radius = int(size * 0.22)
    top, bot = (22, 24, 30), (8, 8, 11)
    grad = Image.new("RGBA", (1, size))
    for y in range(size):
        grad.putpixel((0, y), lerp(top, bot, y / size) + (255,))
    grad = grad.resize((size, size))
    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, size - 1, size - 1], radius, fill=255)
    img.paste(grad, (0, 0), mask)

    # Soft inner rim.
    d.rounded_rectangle(
        [size * 0.02, size * 0.02, size * 0.98, size * 0.98],
        radius=int(radius * 0.92), outline=(120, 150, 255, 60), width=max(2, size // 200),
    )

    # Shield outline.
    cx = size / 2
    w = size * 0.30
    top_y = size * 0.20
    shoulder_y = size * 0.30
    mid_y = size * 0.52
    tip_y = size * 0.80
    pts = [
        (cx, top_y),
        (cx + w, shoulder_y),
        (cx + w, mid_y),
        (cx, tip_y),
        (cx - w, mid_y),
        (cx - w, shoulder_y),
    ]
    blue = (91, 140, 255, 255)
    lw = max(3, size // 90)
    d.polygon(pts, fill=(91, 140, 255, 26))
    d.line(pts + [pts[0]], fill=blue, width=lw, joint="curve")

    # Central wing/rune: a vertical spine with two pairs of upward strokes.
    spine_top = size * 0.30
    spine_bot = size * 0.68
    d.line([(cx, spine_top), (cx, spine_bot)], fill=blue, width=lw)
    for fy in (0.40, 0.52):
        y = size * fy
        span = size * 0.13
        d.line([(cx, y), (cx + span, y - span * 0.55)], fill=blue, width=lw)
        d.line([(cx, y), (cx - span, y - span * 0.55)], fill=blue, width=lw)

    return img


def main():
    base = render(SS)
    png = OUT_DIR / "icon.png"
    base.resize((512, 512), Image.LANCZOS).save(png)

    sizes = [16, 24, 32, 48, 64, 128, 256]
    frames = [base.resize((s, s), Image.LANCZOS) for s in sizes]
    ico = OUT_DIR / "icon.ico"
    frames[-1].save(ico, format="ICO", sizes=[(s, s) for s in sizes])
    print(f"[OK] wrote {ico}")
    print(f"[OK] wrote {png}")


if __name__ == "__main__":
    main()
