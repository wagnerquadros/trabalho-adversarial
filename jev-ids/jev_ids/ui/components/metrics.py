"""Development metrics and accessible vector chart."""

from __future__ import annotations

from ..models import RoundSnapshot
from ._tiles import render_tiles

_METRICS = """<div class="c" style="flex:1 1 460px;min-width:0">
<h2 class="h">Métricas por rodada · desenvolvimento</h2>
<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:8px">
{tiles}
</div>
<div class="t m" style="margin:12px 0 4px;gap:16px;flex-wrap:wrap">
<span>
<b style="color:#9A3C06">━</b> Evasão (%)</span>
<span>
<b style="color:#1546B8">╌</b> Falsos alarmes (%)</span>
</div>
<svg viewBox="0 0 580 150" style="width:100%;height:auto" role="img" aria-label="Evasão e falsos alarmes por rodada, de R1 a R{last}">
<line x1="30" y1="120" x2="570" y2="120" stroke="#C5CBD4"></line><line x1="30" y1="60" x2="570" y2="60" stroke="#E1E5EB"></line>
<text x="4" y="124" font-size="10" fill="#566174">0</text><text x="2" y="64" font-size="10" fill="#566174">{tick}</text>
<line x1="{current_x}" y1="10" x2="{current_x}" y2="120" stroke="#1B2330" stroke-dasharray="2 3"></line>
<polyline points="{evasions}" fill="none" stroke="#9A3C06" stroke-width="2.5"></polyline>
<polyline points="{alarms}" fill="none" stroke="#1546B8" stroke-width="2.5" stroke-dasharray="6 4"></polyline>
<g fill="#fff" stroke="#9A3C06" stroke-width="2">{dots}</g>
<g font-size="10" fill="#566174" text-anchor="middle">{labels}</g>
</svg>
</div>"""


def render_metrics(snapshot: RoundSnapshot) -> str:
    """Plot the series using the reference coordinate system."""
    step = 504 / max(snapshot.total_rounds - 1, 1)
    positions = [40 + i * step for i in range(snapshot.total_rounds)]
    scale = 1 if snapshot.is_live else 2
    evasion = [(x, 120 - scale * value) for x, value in zip(positions, snapshot.evasion_rates, strict=False) if value is not None]
    alarms = [(x, 120 - scale * value) for x, value in zip(positions, snapshot.false_alarm_rates, strict=False) if value is not None]
    return _METRICS.format(
        tiles=render_tiles(snapshot.metrics),
        tick=60 if snapshot.is_live else 30,
        last=snapshot.round_index,
        current_x=positions[max(snapshot.round_index - 1, 0)],
        evasions=" ".join(f"{x:g},{y:g}" for x, y in evasion),
        alarms=" ".join(f"{x:g},{y:g}" for x, y in alarms),
        dots="".join(f'<circle cx="{x:g}" cy="{y:g}" r="4"></circle>' for x, y in evasion),
        labels="".join(f'<text x="{x:g}" y="138">R{i}</text>' for i, x in enumerate(positions, 1)),
    )
