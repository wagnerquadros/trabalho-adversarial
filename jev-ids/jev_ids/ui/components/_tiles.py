"""Shared numeric tiles."""

from __future__ import annotations

from html import escape

from ..models import Metric


def render_tiles(metrics: tuple[Metric, ...]) -> str:
    """Render metric values and their optional deltas."""
    tiles = []
    for metric in metrics:
        delta = f'<span class="m">{escape(metric.delta)}</span>' if metric.delta else ""
        tiles.append(f'<div class="q"><span class="m">{escape(metric.label)}</span><b>{escape(metric.value)}</b>{delta}</div>')
    return "".join(tiles)
