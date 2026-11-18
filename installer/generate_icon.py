"""
Genera el icono oficial de NetTrap-IPS (escudo CyberDefender verde esmeralda)
en formato multi-resolución .ico para el ejecutable y el instalador de Windows.
"""

from pathlib import Path
from PIL import Image, ImageDraw


def draw_shield_icon(size: int = 256) -> Image.Image:
    """Dibuja un escudo vectorial de alta nitidez sobre un fondo oscuro redondeado."""
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    pad = int(size * 0.06)
    radius = int(size * 0.22)
    # Fondo oscuro SOC (#0B0D13) con borde esmeralda
    draw.rounded_rectangle(
        [pad, pad, size - pad, size - pad],
        radius=radius,
        fill=(11, 13, 19, 255),
        outline=(16, 185, 129, 220),
        width=max(2, size // 32),
    )

    # Polígono de escudo exterior
    cx = size / 2.0
    top_y = size * 0.19
    mid_y = size * 0.54
    bot_y = size * 0.83
    half_w = size * 0.26

    shield_pts = [
        (cx, top_y),
        (cx + half_w, top_y + size * 0.08),
        (cx + half_w * 0.92, mid_y),
        (cx, bot_y),
        (cx - half_w * 0.92, mid_y),
        (cx - half_w, top_y + size * 0.08),
    ]
    draw.polygon(shield_pts, fill=(16, 185, 129, 45), outline=(0, 229, 153, 255))

    # Borde grueso del escudo
    line_w = max(2, int(size * 0.045))
    draw.line(shield_pts + [shield_pts[0]], fill=(0, 229, 153, 255), width=line_w, joint="curve")

    # Anillo radar central + núcleo activo
    r1 = size * 0.11
    draw.ellipse(
        [cx - r1, size * 0.49 - r1, cx + r1, size * 0.49 + r1],
        outline=(0, 229, 153, 220),
        width=max(1, int(size * 0.025)),
    )
    r2 = size * 0.045
    draw.ellipse(
        [cx - r2, size * 0.49 - r2, cx + r2, size * 0.49 + r2],
        fill=(0, 229, 153, 255),
    )

    return img


def main() -> None:
    out_dir = Path(__file__).resolve().parent
    ico_path = out_dir / "nettrap.ico"
    png_path = out_dir / "nettrap_256.png"

    base = draw_shield_icon(256)
    base.save(png_path, format="PNG")
    base.save(
        ico_path,
        format="ICO",
        sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
    )
    print(f"Icono generado: {ico_path}")


if __name__ == "__main__":
    main()
