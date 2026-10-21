#!/usr/bin/env python3
"""Builds the desktop launcher's fonts and icons in crates/client/assets from upstream files.

    python3 packaging/make_ui_assets.py <downloads>

<downloads> must hold, from github.com/google/fonts (ofl/inter, ofl/jetbrainsmono):
  Inter[opsz,wght].ttf, JetBrainsMono[wght].ttf, and their OFL.txt as OFL-Inter.txt /
  OFL-JetBrainsMono.txt; and from github.com/lucide-icons/lucide at tag 0.460.0: icons/<name>.svg
  for each name in ICONS, plus LICENSE as LICENSE-lucide.txt.

Needs fonttools and cairosvg (pip install fonttools cairosvg). Fonts are pinned to static
weights and subset to Latin so the binary stays small.
"""
import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
ASSETS = ROOT / "crates/client/assets"
LATIN = "U+0020-007E,U+00A0-00FF,U+0100-017F,U+2010-2027,U+2030-203A,U+20AC,U+2190-2193,U+2212"
FONTS = [
    # (source, output, axis values)
    ("Inter[opsz,wght].ttf", "Inter-Regular.ttf", ["wght=400", "opsz=14"]),
    ("Inter[opsz,wght].ttf", "Inter-Medium.ttf", ["wght=500", "opsz=14"]),
    ("Inter[opsz,wght].ttf", "Inter-SemiBold.ttf", ["wght=600", "opsz=14"]),
    # Display cut for headings.
    ("Inter[opsz,wght].ttf", "Inter-Bold.ttf", ["wght=700", "opsz=32"]),
    ("JetBrainsMono[wght].ttf", "JetBrainsMono-Regular.ttf", ["wght=400"]),
]
ICONS = ["log-in", "monitor", "settings", "info", "plus"]
ICON_PX = 36


def main(src: pathlib.Path):
    fonts = ASSETS / "fonts"
    shutil.rmtree(fonts, ignore_errors=True)
    fonts.mkdir(parents=True)
    tmp = fonts / "tmp.ttf"
    for source, out, axes in FONTS:
        subprocess.run([sys.executable, "-m", "fontTools.varLib.instancer", "-q", str(src / source), *axes, "-o", str(tmp)], check=True)
        subprocess.run([sys.executable, "-m", "fontTools.subset", str(tmp), f"--unicodes={LATIN}", "--layout-features=*", f"--output-file={fonts / out}"], check=True)
    tmp.unlink()
    for lic in ["OFL-Inter.txt", "OFL-JetBrainsMono.txt"]:
        shutil.copy(src / lic, fonts / lic)

    import cairosvg

    icons = ASSETS / "icons"
    shutil.rmtree(icons, ignore_errors=True)
    icons.mkdir(parents=True)
    for name in ICONS:
        # White strokes on transparency, tinted when drawn.
        svg = (src / f"{name}.svg").read_text().replace("currentColor", "#FFFFFF")
        cairosvg.svg2png(bytestring=svg.encode(), write_to=str(icons / f"{name}.png"), output_width=ICON_PX, output_height=ICON_PX)
    shutil.copy(src / "LICENSE-lucide.txt", icons / "LICENSE-lucide.txt")


if __name__ == "__main__":
    main(pathlib.Path(sys.argv[1]))
