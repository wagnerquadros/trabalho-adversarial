"""Exercise the dashboard through Streamlit's widget API."""

from __future__ import annotations

import os
import time
from collections.abc import Iterator
from typing import TYPE_CHECKING

import pytest

from jev_ids import ROOT
from jev_ids.adversarial.classification import ArenaConfig, Classification
from jev_ids.adversarial.evaluation.metrics import Outcome, Sample
from jev_ids.ui.controller import Batch

if TYPE_CHECKING:
    from streamlit.testing.v1 import AppTest


def _app() -> AppTest:
    pytest.importorskip("streamlit")
    from streamlit.testing.v1 import AppTest  # noqa: PLC0415 -- optional dependency

    return AppTest.from_file(str(ROOT / "jev_ids/ui/app.py"), default_timeout=30).run()


def _click(app: AppTest, label: str) -> None:
    button = next(button for button in app.button if button.label == label)
    assert not button.disabled
    button.click().run()
    assert not app.exception


def _wait(app: AppTest) -> None:
    batch: Batch = app.session_state["qwen_batch"]
    deadline = time.monotonic() + 180
    while batch.snapshot().busy and time.monotonic() < deadline:
        time.sleep(0.1)
    assert not batch.snapshot().busy
    app.run()
    assert not app.exception


def _flow(settings: ArenaConfig) -> Iterator[Classification]:
    assert settings.seed == 0 and settings.mode == "observe"
    for index in range(settings.attempts):
        yield Classification(index, (("service", "<script>"),), "normal", Sample(Outcome.QUIET, False), 0.1, "normal", 10, 50, None)


def _skip_archive(run_id: str, rows: Iterator[Classification], settings: ArenaConfig) -> Iterator[Classification]:
    return rows


def test_widgets_resume_the_same_batch_and_escape_record_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    app = _app()
    monkeypatch.setattr("jev_ids.ui.live.arena_records", _flow)
    monkeypatch.setattr("jev_ids.ui.live.record_run", _skip_archive)
    app.slider[0].set_value(3).run()
    assert next(b for b in app.button if b.label == "Executar simulação").disabled
    _click(app, "Concluir configuração")
    assert "qwen_batch" not in app.session_state
    for expected, label in enumerate(("Executar simulação", "Próxima rodada", "Executar tudo"), start=1):
        _click(app, label)
        _wait(app)
        assert len(app.session_state["qwen_batch"].snapshot().rows) == expected * 8
    assert any("&lt;script&gt;" in mark.value for mark in app.markdown)
    assert next(button for button in app.button if button.label == "Executar simulação").disabled
    app.selectbox[0].set_value("Final · paper").run()
    _click(app, "Concluir configuração")
    assert any("avaliação final" in title.value for title in app.title)


def test_changed_plan_requires_confirmation_and_automatic_runs_to_completion(monkeypatch: pytest.MonkeyPatch) -> None:
    app = _app()
    monkeypatch.setattr("jev_ids.ui.live.arena_records", _flow)
    monkeypatch.setattr("jev_ids.ui.live.record_run", _skip_archive)
    _click(app, "Concluir configuração")
    app.selectbox[0].set_value("Final · paper").run()
    assert next(b for b in app.button if b.label == "Executar simulação").disabled
    app.radio[0].set_value("Executar tudo").run()
    _click(app, "Concluir configuração")
    _click(app, "Executar simulação")
    _wait(app)
    assert len(app.session_state["qwen_batch"].snapshot().rows) == 24000


@pytest.mark.live
@pytest.mark.skipif(os.getenv("JEV_LIVE") != "1", reason="Requires local Ollama and the NSL-KDD files")
def test_live_qwen_dashboard() -> None:
    app = _app()
    _click(app, "Concluir configuração")
    for label in ("Executar simulação", "Próxima rodada", "Executar tudo"):
        _click(app, label)
        _wait(app)
        assert not app.error
    batch: Batch = app.session_state["qwen_batch"]
    rows = batch.snapshot().rows
    assert len(rows) == 64
    assert len({row.row_id for row in rows}) == 16
    assert len({(bool(row.note), row.reinforced) for row in rows}) == 4
    for start in range(0, 64, 32):
        ids = [r.row_id for r in rows[start : start + 8]]
        for i in range(start, start + 32, 8):
            cohort = rows[i : i + 8]
            assert [r.row_id for r in cohort] == ids
            assert sum(r.sample.is_attack for r in cohort) == 4
            assert len({(bool(r.note), r.prompt_hash) for r in cohort}) == 1
    assert [tab.label for tab in app.tabs] == ["Mensagens trocadas", "Matriz de resultados", "Mudança de contexto", "Log por rodada (C9)"]
    for row in rows:
        assert row.category and row.probability is not None and 0 <= row.probability <= 1
        assert row.latency_ms is not None and row.latency_ms > 0
        print(row.row_id, row.sample.outcome, row.probability, row.category, row.truth, row.tokens, round(row.latency_ms))
