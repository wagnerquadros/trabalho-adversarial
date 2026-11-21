"""Round history."""

from __future__ import annotations

from html import escape

from ..models import RoundSnapshot

_TIMELINE = """<section class="c" aria-label="Linha do tempo">
<h2 class="h">Linha do tempo · ação do atacante / ação do defensor</h2>
<ol style="list-style:none;margin:0;padding:0;display:grid;grid-template-columns:repeat(auto-fit,minmax(78px,1fr));gap:8px">
{tiles}
</ol>
<div class="m" style="margin-top:10px">{caption}</div>
</section>"""


def render_timeline(snapshot: RoundSnapshot) -> str:
    """Render completed, current and pending rounds."""
    tiles: list[str] = []
    for index in range(1, snapshot.total_rounds + 1):
        style = "r p"
        actions = "—"
        if index <= len(snapshot.cells):
            cell = snapshot.cells[index - 1]
            actions = f"{escape(cell.attacker_action)}/{escape(cell.defender_action)}"
            style = "r n" if index == snapshot.round_index else "r"
        tiles.append(f'<li class="{style}"><b>R{index}</b><span class="k">{actions}</span></li>')
    return _TIMELINE.format(tiles="".join(tiles), caption=escape(snapshot.timeline_caption))
