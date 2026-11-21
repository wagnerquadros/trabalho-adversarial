"""Arena design tokens and packaged stylesheet."""

from __future__ import annotations

from importlib.resources import files

COLOR_ATTACKER_TEXT = "#9A3C06"
COLOR_DEFENDER_TEXT = "#1546B8"
COLOR_DETECTOR_TEXT = "#334155"
COLOR_PAGE = "#F4F5F7"
COLOR_TEXT = "#1B2330"


def load_css() -> str:
    """Read the stylesheet and expose the palette as CSS variables."""
    palette = (
        f"--attacker:{COLOR_ATTACKER_TEXT};--defender:{COLOR_DEFENDER_TEXT};"
        f"--detector:{COLOR_DETECTOR_TEXT};--page:{COLOR_PAGE};--ink:{COLOR_TEXT}"
    )
    stylesheet = files("jev_ids.ui").joinpath("static", "theme.css").read_text(encoding="utf-8")
    return stylesheet.replace("/* palette */", palette)
