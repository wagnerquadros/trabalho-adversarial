"""Message history and context changes."""

from __future__ import annotations

from html import escape

from ..models import RoundSnapshot

TAB_LABELS = ("Mensagens trocadas", "Matriz de resultados", "Mudança de contexto", "Log por rodada (C9)")
_ANALYSIS = """<div style="display:flex;flex-wrap:wrap;gap:24px">
<div style="flex:1 1 520px;min-width:0">
{messages}
</div>
<div class="blk" style="flex:1 1 280px;align-self:flex-start">
<h3 class="h">O que mudou desde a R1</h3>
<div style="display:flex;flex-direction:column;gap:10px">
{changes}
</div>
</div>
</div>"""


def render_analysis_tabs(snapshot: RoundSnapshot) -> str:
    """Return the contents of the messages tab."""
    messages: list[str] = []
    for message in snapshot.messages:
        actor = escape(message.actor)
        messages.append(
            f'<div class="msg"><span class="who {message.actor.name.lower()}">R{message.round_index} · {actor}</span>'
            f"<span>{escape(message.text)}</span></div>"
        )
    changes = "".join(f'<div><div class="m">{escape(label)}</div>{escape(value)}</div>' for label, value in snapshot.context_changes)
    return _ANALYSIS.format(messages="".join(messages), changes=changes)
