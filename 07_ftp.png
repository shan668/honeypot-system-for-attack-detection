"""Render raw terminal capture .txt files into Kali-styled PNG screenshots."""
from __future__ import annotations
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

RAW = Path(__file__).parent / "terminals" / "raw"
OUT = Path(__file__).parent / "terminals"
OUT.mkdir(parents=True, exist_ok=True)

BG = (48, 10, 36)          # #300a24
FG = (240, 240, 240)
PROMPT = (138, 226, 52)    # green
USER = (114, 159, 207)     # blue for path
TITLE_BG = (60, 60, 60)
TITLE_FG = (230, 230, 230)
WIDTH = 1200
PAD_X = 30
PAD_Y = 22
TITLE_H = 34

FONT_PATH = r"C:\Windows\Fonts\consola.ttf"
FONT_BOLD = r"C:\Windows\Fonts\consolab.ttf"
FONT_SIZE = 15
font = ImageFont.truetype(FONT_PATH, FONT_SIZE)
font_bold = ImageFont.truetype(FONT_BOLD, FONT_SIZE)
title_font = ImageFont.truetype(FONT_BOLD, 14)

# measure char width
CHAR_W = font.getlength("M")
LINE_H = FONT_SIZE + 6
MAX_COLS = int((WIDTH - 2 * PAD_X) // CHAR_W)


def wrap(text: str) -> list[str]:
    out = []
    for line in text.splitlines() or [""]:
        if not line:
            out.append("")
            continue
        while len(line) > MAX_COLS:
            out.append(line[:MAX_COLS])
            line = line[MAX_COLS:]
        out.append(line)
    return out


def render(txt_path: Path, png_path: Path) -> None:
    raw = txt_path.read_text(encoding="utf-8", errors="replace")
    lines = wrap(raw)
    height = TITLE_H + 2 * PAD_Y + LINE_H * max(len(lines), 4)
    img = Image.new("RGB", (WIDTH, height), BG)
    d = ImageDraw.Draw(img)
    # Title bar
    d.rectangle([0, 0, WIDTH, TITLE_H], fill=TITLE_BG)
    d.text((PAD_X, 8), "kali@kali: ~", font=title_font, fill=TITLE_FG)
    # window buttons (right side)
    for i, color in enumerate([(255, 90, 82), (255, 189, 46), (39, 201, 63)][::-1]):
        cx = WIDTH - 20 - i * 22
        d.ellipse([cx - 7, 10, cx + 7, 24], fill=color)
    # body
    y = TITLE_H + PAD_Y
    for line in lines:
        x = PAD_X
        if line.startswith("kali@kali:~$"):
            # colored prompt
            d.text((x, y), "kali@kali", font=font_bold, fill=PROMPT)
            x += font_bold.getlength("kali@kali")
            d.text((x, y), ":", font=font, fill=FG)
            x += font.getlength(":")
            d.text((x, y), "~", font=font_bold, fill=USER)
            x += font_bold.getlength("~")
            rest = line[len("kali@kali:~"):]
            d.text((x, y), rest, font=font, fill=FG)
        else:
            d.text((x, y), line, font=font, fill=FG)
        y += LINE_H
    img.save(png_path)


def main() -> None:
    for txt in sorted(RAW.glob("*.txt")):
        png = OUT / (txt.stem + ".png")
        render(txt, png)
        print(f"rendered {txt.name} -> {png.name} ({png.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
