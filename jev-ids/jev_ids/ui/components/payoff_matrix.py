"""Ordinal payoffs and visit counts."""

from __future__ import annotations

from ..models import RoundSnapshot

_MATRIX = """<div class="c" style="flex:0 0 340px">
<h2 class="h">Matriz 2×2 ao vivo · visitas e payoff</h2>
<table style="width:100%;border-collapse:separate;border-spacing:6px;text-align:center">
<thead><tr><td></td><th class="m" scope="col">B · básicas</th><th class="m" scope="col">R · reforçadas</th></tr></thead>
<tbody>
<tr><th class="m" scope="row" style="text-align:left">N · com nota</th>{NB}{NR}</tr>
<tr><th class="m" scope="row" style="text-align:left">S · sem nota</th>{SB}{SR}</tr>
</tbody>
</table>
<div class="m">Payoffs ordinais (atacante, defensor), hipóteses a medir. Contorno escuro: célula da rodada atual.</div>
</div>"""


def render_payoff_matrix(snapshot: RoundSnapshot) -> str:
    """Render the two-by-two matrix with the current action pair outlined."""
    cells = {}
    for payoff in snapshot.payoffs:
        style = "x cur" if payoff.cell == snapshot.current_cell else "x"
        key = payoff.cell.attacker_action + payoff.cell.defender_action
        cells[key] = f'<td class="{style}"><b>×{payoff.visits}</b><span class="k">{payoff.utilities}</span></td>'
    return _MATRIX.format_map(cells)
