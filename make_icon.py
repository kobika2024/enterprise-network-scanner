"""
make_icon.py — Generate static/icon.ico for the NetworkScanner EXE.

Run:  python make_icon.py
Requires: Pillow  (pip install Pillow)

Pillow's ICO plugin: draw once at 256×256, then pass a sizes= list so it
auto-downsamples to every required size inside the .ico file.
"""

import os
import sys


def make_icon(out_path: str = 'static/icon.ico') -> None:
    try:
        from PIL import Image, ImageDraw
    except ImportError:
        print('[ERROR] Pillow is not installed. Run: pip install Pillow')
        sys.exit(1)

    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)

    # Draw master image at 256×256 — Pillow downsamples to smaller sizes
    S  = 256
    cx = cy = S // 2

    img  = Image.new('RGBA', (S, S), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # ── Dark circular background ──────────────────────────────────────────────
    margin = 6
    draw.ellipse([margin, margin, S - margin, S - margin],
                 fill=(13, 17, 23, 255))

    # ── Blue outer ring ───────────────────────────────────────────────────────
    draw.ellipse([margin, margin, S - margin, S - margin],
                 outline=(88, 166, 255, 255), width=10)

    # ── Inner dashed ring (concentric) ────────────────────────────────────────
    r_mid = S // 3
    draw.arc([cx - r_mid, cy - r_mid, cx + r_mid, cy + r_mid],
             start=0, end=360, fill=(88, 166, 255, 60), width=4)

    # ── Radar cross-hairs ─────────────────────────────────────────────────────
    arm = S // 3
    draw.line([cx, cy - arm, cx, cy + arm], fill=(88, 166, 255, 140), width=4)
    draw.line([cx - arm, cy, cx + arm, cy], fill=(88, 166, 255, 140), width=4)

    # ── Sweep arc ─────────────────────────────────────────────────────────────
    r_sweep = S // 4
    draw.arc([cx - r_sweep, cy - r_sweep, cx + r_sweep, cy + r_sweep],
             start=200, end=340, fill=(88, 166, 255, 120), width=6)

    # ── Centre dot ────────────────────────────────────────────────────────────
    r = 20
    draw.ellipse([cx - r, cy - r, cx + r, cy + r],
                 fill=(88, 166, 255, 255))

    # ── Green satellite nodes ─────────────────────────────────────────────────
    nr = 14
    for dx, dy in [(-arm // 2, -arm // 2), (arm // 2, arm // 2)]:
        draw.ellipse(
            [cx + dx - nr, cy + dy - nr, cx + dx + nr, cy + dy + nr],
            fill=(63, 185, 80, 255),
        )

    # ── Save multi-size ICO ───────────────────────────────────────────────────
    sizes = [(16, 16), (24, 24), (32, 32), (48, 48),
             (64, 64), (128, 128), (256, 256)]

    img.save(out_path, format='ICO', sizes=sizes)

    file_kb = os.path.getsize(out_path) // 1024
    print(f'[OK] Icon saved: {out_path}  '
          f'({len(sizes)} sizes, {file_kb} KB)')


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else 'static/icon.ico'
    make_icon(out)
