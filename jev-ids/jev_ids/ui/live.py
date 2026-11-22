"""Bind the arena components to measured local detector runs."""

from __future__ import annotations

import json
from typing import Literal

import streamlit as st

from jev_ids import ROOT
from jev_ids.adversarial.analysis.paired import compare_contexts
from jev_ids.adversarial.analysis.protocol import protocol_report
from jev_ids.adversarial.classification import ArenaConfig, Classification, arena_records
from jev_ids.adversarial.evaluation.metrics import measure
from jev_ids.adversarial.round_log import new_run_id, read_run, record_run
from jev_ids.ui.adapters import build_live_snapshot, round_events
from jev_ids.ui.components.analysis_tabs import TAB_LABELS, render_analysis_tabs
from jev_ids.ui.components.arena import render_arena
from jev_ids.ui.components.header import RUN_ALL, render_header
from jev_ids.ui.components.metrics import render_metrics
from jev_ids.ui.components.payoff_matrix import render_payoff_matrix
from jev_ids.ui.components.sidebar import render_sidebar
from jev_ids.ui.components.timeline import render_timeline
from jev_ids.ui.controller import Batch, Progress
from jev_ids.ui.models import RoundSnapshot

__all__ = ["show_live"]


def _show(markup: str) -> None:
    content = " ".join(markup.splitlines())
    st.markdown(f'<div class="arena-html">{content}</div>', unsafe_allow_html=True)


def _comparisons(rows: tuple[Classification, ...]) -> None:
    st.caption("Comparações do mesmo fluxo e semente. S → N adiciona a nota. B → R reforça as instruções. Δ é depois menos antes.")
    table = [
        {
            "Contexto": f"{c['before']} → {c['after']}",
            "Pares": c["matched"],
            "Pares com dois vereditos": c["valid"],
            "Passou a alertar": c["gained_alert"],
            "Deixou de alertar": c["lost_alert"],
            "Mudou categoria": c["changed_category"],
            "Mudou p_attack": c["changed_score"],
            "Δ médio de p_attack": c["mean_score_delta"],
            "Pares com tokens": c["token_pairs"],
            "Δ tokens por fluxo": c["mean_token_delta"],
            "Pares com latência": c["latency_pairs"],
            "Δ latência (ms)": c["mean_latency_delta_ms"],
        }
        for c in compare_contexts(rows)
    ]
    st.dataframe(table, hide_index=True)  # pyright: ignore[reportUnknownMemberType]


def _protocol(rows: tuple[Classification, ...], settings: ArenaConfig) -> None:
    report = protocol_report(rows, settings)
    if not rows:
        return
    st.subheader("Resultados por condição e semente")
    st.caption(
        "F1 da classe ataque. A Arena usa os vereditos válidos. No fail-open, uma chamada com falha conta como sem alerta. "
        "Bloqueios do validador são contabilizados à parte nas duas leituras."
    )
    st.dataframe(  # pyright: ignore[reportUnknownMemberType]
        report["by_seed"],
        hide_index=True,
        column_config={
            "cell": "Condição",
            "seed": "Semente",
            "records": "Registros",
            "valid": "Vereditos válidos",
            "failures": "Falhas",
            "blocked": "Bloqueios",
            "arena_f1": "F1 Arena",
            "fail_open_f1": "F1 fail-open",
            "tokens_mean": "Tokens médios",
            "token_measurements": "Respostas com tokens",
            "latency_mean_ms": "Latência média (ms)",
            "latency_measurements": "Chamadas com latência",
            "arena_recall": "Recall Arena",
            "fail_open_recall": "Recall fail-open",
            "arena_novel_recall": "Recall de ataques inéditos (Arena)",
            "fail_open_novel_recall": "Recall de ataques inéditos (fail-open)",
            "false_alarms": "Falsos alarmes",
            "false_alarm_rate": "Taxa de falsos alarmes",
        },
    )
    if settings.split == "paper":
        st.subheader("F1 nas três sementes")
        if report["across_seeds"]:
            st.dataframe(  # pyright: ignore[reportUnknownMemberType]
                [
                    {
                        "Condição": item["cell"],
                        "Política": "Arena" if item["policy"] == "arena_f1" else "Fail-open",
                        "Sementes com F1 definido": item["defined_seeds"],
                        "F1 médio": item["f1_mean"],
                        "DP amostral": item["f1_sd"],
                    }
                    for item in report["across_seeds"]
                ],
                hide_index=True,
            )
        else:
            st.caption("O resumo de cada condição aparece quando seus 2.000 fluxos estão avaliados nas três sementes.")


def _analysis(rows: tuple[Classification, ...], snapshot: RoundSnapshot, settings: ArenaConfig) -> None:
    events = round_events(rows, settings)
    with st.container(key="analysis"):
        messages, matrix, changes, log = st.tabs(TAB_LABELS)
        with messages:
            _show(render_analysis_tabs(snapshot))
        with matrix:
            _protocol(rows, settings)
            values: list[dict[str, object]] = []
            size = settings.records_per_round
            for start in range(0, len(rows), size):
                cohort = rows[start : start + size]
                totals = measure(r.sample for r in cohort)
                values.append(
                    {
                        "Rodada": settings.round_number(start + 1),
                        "Célula": events[start]["cell"],
                        "Registros": len(cohort),
                        "Previstos": size,
                        "Vereditos válidos": totals["valid_verdicts"],
                        "Evasão": totals["miss_rate"],
                        "Recall": totals["recall"],
                        "Taxa de falsos alarmes": totals["false_alarm_rate"],
                        "F1": totals["f1"],
                        "Falhas": totals["failures"],
                        "Inválidos": totals["invalid"],
                        "Bloqueados": totals["invalid_blocked"],
                    }
                )
            if values:
                st.dataframe(values, hide_index=True)  # pyright: ignore[reportUnknownMemberType]
            else:
                st.caption("Aguardando a primeira rodada.")
        with changes:
            if events:
                _comparisons(rows)
                st.dataframe(  # pyright: ignore[reportUnknownMemberType]
                    [
                        {
                            "Rodada": e["round"],
                            "Tentativa": e["attempt"],
                            "Registro": e["row_id"],
                            "Nota": e["note"] or "Sem nota",
                            "Instruções": "v2 · reforçadas" if row.reinforced else "v1 · básicas",
                            "Hash das instruções": row.prompt_hash,
                            "Tentativas restantes": e["budget_left"],
                        }
                        for e, row in zip(events, rows, strict=True)
                    ],
                    hide_index=True,
                )
            else:
                st.caption("Aguardando a primeira rodada.")
        with log:
            if events:
                st.json(events, expanded=False)
                st.download_button(
                    "Baixar log JSONL",
                    "".join(json.dumps(e, ensure_ascii=False) + "\n" for e in events),
                    "arena-rodadas.jsonl",
                    "application/x-ndjson",
                    on_click="ignore",
                )
            else:
                st.caption("Aguardando a primeira rodada.")


def _results(progress: Progress, settings: ArenaConfig, run_id: str | None = None) -> None:
    if progress.error:
        st.error("A execução parou. Verifique o servidor do detector e os arquivos NSL-KDD.")
        st.text(progress.error)
    elif progress.busy and settings.split == "pilot":
        st.caption("Aguardando o detector local…")
    elif len(progress.rows) == settings.budget < settings.rounds * settings.records_per_round:
        st.caption("Orçamento esgotado. O log inclui todas as tentativas, inclusive de uma rodada parcial.")
    if settings.split == "paper":
        n = len(progress.rows)
        st.progress(n / settings.attempts, text=f"{n:,} / {settings.attempts:,} classificações".replace(",", "."))
        st.caption(
            f"{n // settings.records_per_round} de {settings.rounds} rodadas concluídas · "
            "N com nota · S sem nota · B instruções básicas · R reforçadas"
        )
        if progress.rows:
            last = progress.rows[-1]
            st.caption(f"Última tentativa · semente {last.seed} · fluxo {last.row_id} · {last.sample.outcome.value}")
        _protocol(progress.rows, settings)
        if progress.rows:
            st.subheader("Efeito da nota e do reforço")
            _comparisons(progress.rows)
        if progress.rows and not progress.busy and run_id and (path := ROOT / "runs" / run_id / "rounds.jsonl").is_file():
            st.download_button("Baixar log da execução", path.read_bytes, "arena-paper.jsonl", "application/x-ndjson", on_click="ignore")
        return
    snapshot = build_live_snapshot(progress.rows, settings)
    st.caption(
        f"{len(progress.rows)} de {settings.attempts} tentativas · {len({r.row_id for r in progress.rows})} registros distintos · "
        f"{len(progress.rows) // settings.records_per_round} rodadas completas"
    )
    _show(render_timeline(snapshot))
    _show(render_arena(snapshot))
    _show(f'<section class="summary">{render_payoff_matrix(snapshot)}{render_metrics(snapshot)}</section>')
    _analysis(progress.rows, snapshot, settings)


def _sidebar(busy: bool) -> ArenaConfig:
    st.html('<h2 class="h">Configuração</h2>')
    split = st.selectbox("Avaliação", ("Piloto", "Final · paper"), disabled=busy)
    model = st.selectbox("Detector (um por execução)", ("Qwen3:8b · Ollama", "Laya multilingual"), disabled=busy)
    detector: Literal["qwen3", "laya"] = "qwen3" if model.startswith("Qwen") else "laya"
    validation = st.selectbox("Validador de campos (C6)", ("Observar", "Bloquear (comparação)"), disabled=busy)
    mode: Literal["observe", "block"] = "observe" if validation == "Observar" else "block"
    if split != "Piloto":
        size = st.selectbox("Fluxos por rodada", (10, 50, 100, 500, 2000), index=2, disabled=busy)
        settings = ArenaConfig.paper(detector, mode, size)
        st.caption(f"2.000 fluxos fixos × 3 sementes de exemplos (0, 1, 2) × 4 condições. {settings.rounds} rodadas · 24.000 tentativas.")
        return settings
    seed = st.selectbox("Semente", (0, 1, 2), disabled=busy)
    rounds = st.slider(f"Rodadas: {st.session_state.get('rounds', 8)}", 3, 20, 8, key="rounds", disabled=busy)
    size = st.slider("Registros por rodada", 2, 16, 8, step=2, disabled=busy)
    budget = st.number_input("Orçamento de tentativas", min_value=1, max_value=320, value=rounds * size, step=1, disabled=busy)
    st.caption(f"Plano completo: {rounds} rodadas × {size} registros = {rounds * size} tentativas.")
    return ArenaConfig(seed, rounds, budget, mode, detector, size)


def _replay(run_id: str) -> None:
    try:
        settings, rows, error = read_run(run_id)
    except (ValueError, OSError, KeyError, TypeError) as exc:
        st.error("Execução indisponível. Confira o identificador e se o teste terminou.")
        st.text(str(exc))
        return
    with st.sidebar:
        st.html('<h2 class="h">Reprodução do teste</h2>')
        last = settings.round_number(len(rows))
        selected = st.slider("Rodada exibida", 0, last, last) if rows else 0
        n = min(selected * settings.records_per_round, len(rows))
        st.caption(f"Split {settings.split} · orçamento {settings.budget}")
        st.markdown("[Iniciar outro teste](?modo=real)")
    with st.container(key="page_header"):
        _header(rows[:n], settings)
    with st.container(key="page_content"):
        _results(Progress(rows[:n], settings.attempts, False, error if n == len(rows) else None), settings, run_id)


def _header(rows: tuple[Classification, ...], settings: ArenaConfig) -> None:
    if settings.split == "paper":
        st.title("Arena · avaliação final NSL-KDD")
        st.caption(f"Split paper · {settings.rounds} rodadas de {settings.records_per_round} fluxos")
    else:
        _show(render_header(build_live_snapshot(rows, settings)))


def _start(selection: ArenaConfig, execution: str) -> None:
    if st.session_state.get("confirmed_plan") != (selection, execution):
        return
    run_id = new_run_id()
    new = Batch(record_run(run_id, arena_records(selection), selection), selection.attempts, selection.records_per_round)
    st.session_state.run_id = run_id
    st.session_state.qwen_batch = new
    st.session_state.qwen_settings = selection
    st.session_state.confirmed_plan = None
    new.advance(all_remaining=execution == RUN_ALL)


def show_live() -> None:
    """Keep the sidebar and header stable while the measured arena updates."""
    if run_id := st.query_params.get("run"):
        _replay(run_id)
        return
    batch: Batch | None = st.session_state.get("qwen_batch")
    current = batch.snapshot() if batch else None
    busy = bool(current and current.busy)
    underway = bool(current and (busy or current.can_continue))
    with st.sidebar:
        selection = _sidebar(underway)
        execution = st.radio("Modo de execução", ("Rodada por rodada", RUN_ALL), disabled=underway)
        st.html(render_sidebar(build_live_snapshot((), selection)))
        if current and not current.can_continue and not current.busy and "run_id" in st.session_state:
            st.markdown(f"[Rever este teste](?run={st.session_state.run_id})")
        st.markdown("[Ver demonstração ilustrativa](?modo=demo)")
        plan = (selection, execution)
        if st.session_state.get("confirmed_plan") != plan:
            st.session_state.confirmed_plan = None
        if st.button("Concluir configuração", type="primary", width="stretch", disabled=underway):
            st.session_state.confirmed_plan = plan
    ready = st.session_state.get("confirmed_plan") == plan and not underway
    if ready:
        batch = current = None

    active: ArenaConfig = st.session_state.qwen_settings if batch else selection
    progress = current or Progress((), active.attempts, False, None)
    with st.container(key="page_header"):
        title, action = st.columns([5, 2])
        with title:
            _header(progress.rows, active)
        if underway and batch:
            action.button("Próxima rodada", type="primary", disabled=busy, on_click=batch.advance)
            action.button(RUN_ALL, disabled=busy, on_click=batch.advance, kwargs={"all_remaining": True})
        else:
            action.button("Executar simulação", type="primary", disabled=not ready, on_click=_start, args=plan)
    with st.container(key="page_content"):

        @st.fragment(run_every=1 if busy else None)
        def refresh() -> None:
            latest = batch.snapshot() if batch else progress
            stride = active.records_per_round if active.split == "paper" else 1
            if busy and (not latest.busy or len(latest.rows) // stride != len(progress.rows) // stride):
                st.rerun()
            if busy and active.split == "paper":
                position = len(latest.rows) % stride
                st.caption(f"Rodada em execução · {position} de {stride} tentativas registradas")

        refresh()
        _results(progress, active, st.session_state.get("run_id"))
