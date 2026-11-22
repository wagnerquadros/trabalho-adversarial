"""Page title and round summary."""

from __future__ import annotations

from html import escape

from ..models import RoundSnapshot

TITLE = "Arena Adversarial"
STEP = "Passo"
RUN_ALL = "Executar tudo"
_HEADER = """<header class="arena-heading t">
<div><h1>{title}</h1><div class="m">{subtitle}</div></div>
<div class="t"><span class="chip m">{mode}</span>
<span class="chip">Rodada {index} de {total}</span></div></header>"""


def render_header(snapshot: RoundSnapshot) -> str:
    """Render the title and round chips."""
    return _HEADER.format(
        title=escape(TITLE),
        index=snapshot.round_index,
        total=snapshot.total_rounds,
        mode="Execução real" if snapshot.is_live else "Valores ilustrativos, não medidos",
        subtitle="Teste controlado · detector LLM sobre registros NSL-KDD · roteiro fixo"
        if snapshot.is_live
        else "Atacante × Defensor · detector LLM sobre registros NSL-KDD · simulação, sem rede real",
    )
