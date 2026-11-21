"""Attacker, detector and defender panels."""

from __future__ import annotations

from html import escape

from ..models import RoundSnapshot, Verdict
from ._tiles import render_tiles

_ARENA = """<section aria-label="Arena" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(min(280px,100%),1fr));gap:16px">

<article class="c" style="display:flex;flex-direction:column;gap:12px">
<div class="band" style="background:#FDF1E7;color:#9A3C06"><span>ATACANTE · C7</span><span class="chip">Ação {attacker}</span></div>
<div>
<div class="m">Nota anexada ao campo service</div>
<div class="blk k" style="margin-top:4px">service = “{base_service}<mark style="background:#F8D4B4;color:#1B2330">{suffix}</mark>”</div>
</div>
<div>
<div class="m">Intenção declarada</div>
<div>{intention}</div>
</div>
<div>
<div class="m" style="margin-bottom:6px">Vereditos das próprias tentativas</div>
<div class="t" style="flex-wrap:wrap;gap:6px">
{dots}
</div>
<div class="m" style="margin-top:4px">● sem alerta · ○ alerta · tracejado: ainda não jogada</div>
</div>
<div>
<div class="t m" style="justify-content:space-between"><span>Orçamento de tentativas</span><span>{left} de {total}</span></div>
<div style="height:8px;border-radius:4px;background:#EEF1F5;margin-top:4px">
<div style="width:{budget_percent}%;height:8px;border-radius:4px;background:#9A3C06">
</div>
</div>
</div>
<div class="lock">
<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
<rect x="5" y="11" width="14" height="9" rx="2">
</rect>
<path d="M8 11V8a4 4 0 0 1 8 0v3">
</path>
</svg>Não vê: p_attack, instruções, exemplos, gabarito, F1</div>
</article>

<article class="c" style="display:flex;flex-direction:column;gap:12px">
<div class="band" style="background:#EEF1F5;color:#334155"><span>DETECTOR · C3</span><span class="chip">{detector}</span></div>
<div>
<div class="m">Registro avaliado ({attribute_count} atributos)</div>
<div class="blk k" style="margin-top:4px;display:grid;grid-template-columns:auto 1fr;gap:2px 14px">
{fields}
<span class="m">…</span><span class="m">+{remaining} atributos fixos</span>
</div>
</div>
<div class="t" style="justify-content:space-between;flex-wrap:wrap">
<span class="m">Validador C6 · {mode}</span>
<span class="chip" style="color:#334155">{status}</span>
</div>
<div class="m" style="margin-top:-6px">{validator_note}</div>
<div>
<div class="t m" style="justify-content:space-between"><span>p_attack</span><span class="k">{probability} · limiar {threshold}</span></div>
<div style="position:relative;height:12px;border-radius:6px;background:#EEF1F5;margin-top:6px">
<div style="width:{probability_percent}%;height:12px;border-radius:6px;background:#334155"></div>
<div style="position:absolute;left:{threshold_percent}%;top:-4px;width:2px;height:20px;background:#1B2330"></div>
</div>
</div>
<div class="verdict {verdict_class}">{verdict}</div>
<div class="t" style="justify-content:center">
<span class="chip" style="color:#9A3C06">{outcome}</span>
<span class="m">gabarito: {truth}</span>
</div>
<div class="lock">Gabarito e p_attack só chegam ao avaliador (C4)</div>
</article>

<article class="c" style="display:flex;flex-direction:column;gap:12px">
<div class="band" style="background:#E8EFFD;color:#1546B8"><span>DEFENSOR · C8</span><span class="chip">Ação {defender}</span></div>
<div>
<div class="m">Instruções vigentes</div>
{instructions}
</div>
<div>
<div class="m" style="margin-bottom:6px">Agregados do conjunto de desenvolvimento</div>
<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:8px">
{aggregates}
</div>
<div class="m" style="margin-top:4px">Custo de R em tokens por registro.</div>
</div>
<div>
<div class="m">Gatilho de adaptação</div>
<div>{adaptation}</div>
</div>
<div class="lock">
<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
<rect x="5" y="11" width="14" height="9" rx="2">
</rect>
<path d="M8 11V8a4 4 0 0 1 8 0v3">
</path>
</svg>Não vê: conjunto final reservado, log completo</div>
</article>
</section>"""
_DOT_CLASS = {None: "pending", Verdict.ALERT: "", Verdict.QUIET: "quiet"}


def _fields(snapshot: RoundSnapshot) -> str:
    fields = []
    for name, value in snapshot.record_fields:
        tag = "mark" if name == "service" else "span"
        fields.append(f"<span>{escape(name)}</span><{tag}>{escape(value)}</{tag}>")
    return "".join(fields)


def _instructions(snapshot: RoundSnapshot) -> str:
    blocks = []
    for version in snapshot.instructions:
        quote = f'<div class="k">{escape(version.quotation)}</div>' if version.quotation else ""
        blocks.append(
            f'<div class="blk revision"><b>{escape(version.title)}</b> <span class="m">{escape(version.status)}</span>{quote}</div>'
        )
    return "".join(blocks)


def render_arena(snapshot: RoundSnapshot) -> str:
    """Render the three participants from the same observed round."""
    service = dict(snapshot.record_fields).get("service", "")
    return _ARENA.format(
        attacker=escape(snapshot.current_cell.attacker_action),
        defender=escape(snapshot.current_cell.defender_action),
        detector=escape(snapshot.detector),
        base_service=escape(service.removesuffix(snapshot.note_suffix)),
        suffix=escape(snapshot.note_suffix),
        intention=escape(snapshot.intention),
        dots="".join(f'<span class="dot {_DOT_CLASS[item]}"></span>' for item in snapshot.attempts),
        left=snapshot.budget_left,
        total=snapshot.budget_total,
        budget_percent=round(100 * snapshot.budget_left / snapshot.budget_total) if snapshot.budget_total else 0,
        attribute_count=snapshot.attribute_count,
        fields=_fields(snapshot),
        remaining=snapshot.attribute_count - len(snapshot.record_fields),
        mode=escape(snapshot.validator_mode),
        status=escape(snapshot.validator_status),
        validator_note=escape(snapshot.validator_note),
        probability=format(snapshot.p_attack, "g").replace(".", ","),
        threshold=format(snapshot.threshold, "g").replace(".", ","),
        probability_percent=snapshot.p_attack * 100,
        threshold_percent=snapshot.threshold * 100,
        verdict_class="alert" if snapshot.verdict is Verdict.ALERT else "",
        verdict=escape(snapshot.verdict),
        outcome=escape(snapshot.outcome),
        truth=escape(snapshot.ground_truth),
        instructions=_instructions(snapshot),
        aggregates=render_tiles(snapshot.aggregates),
        adaptation=escape(snapshot.adaptation),
    )
