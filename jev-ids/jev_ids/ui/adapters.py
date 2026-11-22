"""Project recorded pilot classifications onto the arena components."""

from __future__ import annotations

from statistics import mean

from jev_ids.adversarial.classification import ArenaConfig, Classification
from jev_ids.adversarial.evaluation.metrics import Outcome, measure
from jev_ids.adversarial.round_log import round_event
from jev_ids.records import VERDICT_THRESHOLD
from jev_ids.ui.models import Actor, InstructionVersion, Message, Metric, Payoff, RoundCell, RoundSnapshot, Verdict

__all__ = ["build_live_snapshot", "round_events"]

_PAYOFFS = {RoundCell("N", "B"): (3, 0), RoundCell("N", "R"): (0, 2), RoundCell("S", "B"): (1, 3), RoundCell("S", "R"): (1, 1)}
_VERDICTS = {Outcome.ALERT: Verdict.ALERT, Outcome.QUIET: Verdict.QUIET, Outcome.FAILURE: Verdict.FAILURE, Outcome.BLOCKED: Verdict.BLOCKED}


def _number(value: float | None, *, percent: bool = False) -> str:
    if value is None:
        return "—"
    return (f"{100 * value:.1f}%" if percent else f"{value:.2f}").replace(".", ",")


def _cell(row: Classification) -> RoundCell:
    return RoundCell("N" if row.note else "S", "R" if row.reinforced else "B")


def _evaluation(row: Classification) -> str:
    if row.sample.outcome == Outcome.ALERT:
        return "Ataque detectado" if row.sample.is_attack else "Falso alarme"
    if row.sample.outcome == Outcome.QUIET:
        return "Evasão" if row.sample.is_attack else "Legítimo"
    return "Sem classificação"


def round_events(rows: tuple[Classification, ...], settings: ArenaConfig) -> list[dict[str, object]]:
    """Export raw numeric values and the exact tested context for each round."""
    return [round_event(i, row, settings) for i, row in enumerate(rows, 1)]


def _paired_cost(rows: tuple[Classification, ...]) -> str:
    basic = {(r.row_id, r.note): r.tokens for r in rows if not r.reinforced and r.tokens is not None}
    deltas = [r.tokens - basic[r.row_id, r.note] for r in rows if r.reinforced and r.tokens is not None and (r.row_id, r.note) in basic]
    return f"{mean(deltas):+.1f}".replace(".", ",") if deltas else "—"


def _metrics(rows: tuple[Classification, ...]) -> tuple[Metric, ...]:
    totals = measure(r.sample for r in rows)
    tokens = [r.tokens for r in rows if r.tokens is not None]
    times = [r.latency_ms for r in rows if r.latency_ms is not None]
    return (
        Metric("Taxa de evasão", _number(totals["miss_rate"], percent=True), "acumulada"),
        Metric("Recall", _number(totals["recall"]), "acumulado"),
        Metric("Falsos alarmes", _number(totals["false_alarm_rate"], percent=True), "acumulados"),
        Metric("F1", _number(totals["f1"]), "acumulado"),
        Metric("Falhas", str(totals["failures"])),
        Metric("Inválidos", str(totals["invalid"])),
        Metric("Tokens", str(round(mean(tokens))) if tokens else "—", "por resposta"),
        Metric("Latência", f"{mean(times):.0f} ms" if times else "—", "média"),
    )


def _series(rows: tuple[Classification, ...], key: str, size: int) -> tuple[float | None, ...]:
    values = (measure(row.sample for row in rows[i : i + size])[key] for i in range(0, len(rows), size))
    return tuple(100 * v if v is not None else None for v in values)


def build_live_snapshot(rows: tuple[Classification, ...], settings: ArenaConfig) -> RoundSnapshot:
    """Build a complete view, including pending, blocked and failed rounds."""
    n = len(rows)
    latest = rows[-1] if rows else None
    size = settings.records_per_round
    cells = tuple(_cell(r) for r in rows[::size])
    fields = dict(latest.fields) if latest else {}
    totals = measure(r.sample for r in rows)
    note = latest.note if latest else ""
    verdicts = tuple(_VERDICTS[r.sample.outcome] for r in rows)
    messages = tuple(
        Message(
            settings.round_number(i),
            Actor.ORCHESTRATOR,
            f"Registro {r.row_id} · {_cell(r).attacker_action}/{_cell(r).defender_action} · "
            f"{_VERDICTS[r.sample.outcome]} · {_evaluation(r)}.",
        )
        for i, r in enumerate(rows, 1)
    )
    version = "v2 · reforçadas (R)" if latest and latest.reinforced else "v1 · básicas"
    return RoundSnapshot(
        round_index=len(cells),
        total_rounds=settings.rounds,
        cells=cells,
        attempts=(verdicts + (None,) * (settings.rounds - n))
        if size == 1
        else verdicts[-((n - 1) % size + 1) :] + (None,) * ((-n) % size)
        if n
        else (None,) * size,
        budget_left=settings.budget - n,
        budget_total=settings.budget,
        detector="Qwen3:8b" if settings.detector == "qwen3" else "Laya multilingual",
        record_fields=tuple((key, fields[key]) for key in ("protocol_type", "service", "flag", "src_bytes") if key in fields),
        attribute_count=len(fields),
        note_suffix=note,
        intention="Anotação fixa de procedência para o teste." if note else "Registro original, sem nota.",
        validator_mode="Observar" if settings.mode == "observe" else "Bloquear",
        validator_status=("inválido" if latest.sample.is_invalid else "válido") if latest else "—",
        validator_note=", ".join(latest.invalid_fields) if latest else "",
        p_attack=latest.probability if latest else None,
        threshold=VERDICT_THRESHOLD,
        verdict=verdicts[-1] if rows else Verdict.WAITING,
        ground_truth=latest.truth if latest else "—",
        outcome=_evaluation(latest) if latest else "—",
        instructions=(InstructionVersion(version, f"ativa na R{len(cells)}"),) if rows else (),
        aggregates=tuple(
            Metric(label, str(totals[key]))
            for label, key in (("Evasões", "misses"), ("Falsos alarmes", "false_alarms"), ("Falhas", "failures"), ("Inválidos", "invalid"))
        )
        + (Metric("Notas testadas", str(len({r.note for r in rows if r.note}))), Metric("Custo de R", _paired_cost(rows))),
        adaptation="As instruções seguem o roteiro pareado, definido antes do teste.",
        payoffs=tuple(Payoff(cell, cells.count(cell), pay) for cell, pay in _PAYOFFS.items()),
        metrics=_metrics(rows),
        evasion_rates=_series(rows, "miss_rate", size),
        false_alarm_rates=_series(rows, "false_alarm_rate", size),
        messages=messages,
        context_changes=(
            ("Nota do atacante", note or "Sem nota"),
            ("Instruções do defensor", version if rows else "—"),
            ("Orçamento do atacante", f"{settings.budget} → {settings.budget - n} tentativas"),
        ),
        timeline_caption=(
            "N com anotação fixa · S sem nota · B instruções básicas · R instruções reforçadas. "
            f"{size} registro(s) por rodada. Cada bloco de quatro rodadas usa o mesmo lote. Gráfico por rodada; indicadores acumulados."
        ),
        is_live=True,
    )
