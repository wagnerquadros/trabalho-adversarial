"""Rendering checks that do not require Streamlit."""

from __future__ import annotations

from dataclasses import replace
from xml.etree import ElementTree

from jev_ids.ui import build_sample_snapshot
from jev_ids.ui.components.analysis_tabs import render_analysis_tabs
from jev_ids.ui.components.arena import render_arena
from jev_ids.ui.components.header import render_header
from jev_ids.ui.components.metrics import render_metrics
from jev_ids.ui.components.payoff_matrix import render_payoff_matrix
from jev_ids.ui.components.sidebar import render_sidebar
from jev_ids.ui.components.timeline import render_timeline
from jev_ids.ui.models import Verdict
from jev_ids.ui.theme import load_css


def test_reference_round() -> None:
    snapshot = build_sample_snapshot()
    assert "Rodada 5 de 10" in render_header(snapshot)
    assert "Limiar de alerta 0,5" in render_sidebar(snapshot)
    timeline = render_timeline(snapshot)
    assert timeline.count("<li ") == 10
    assert '<li class="r n"><b>R5' in timeline
    assert "SEM ALERTA" in render_arena(snapshot)
    assert "7 de 12" in render_arena(snapshot)
    assert "Notas testadas" in render_arena(snapshot)
    assert "(3, 0)" in render_payoff_matrix(snapshot)
    assert 'class="x cur"><b>×2' in render_payoff_matrix(snapshot)
    assert render_analysis_tabs(snapshot).count('class="msg"') == 5
    assert "--ink:#1B2330" in load_css()


def test_chart_coordinates_and_accessibility() -> None:
    chart = ElementTree.fromstring(render_metrics(build_sample_snapshot())).find("svg")  # noqa: S314 -- trusted local fixture
    assert chart is not None
    assert chart.get("role") == "img"
    assert chart.get("aria-label") == "Evasão e falsos alarmes por rodada, de R1 a R5"
    assert [line.get("points") for line in chart.findall("polyline")] == [
        "40,24 96,84 152,72 208,68 264,26",
        "40,110 96,102 152,100 208,108 264,110",
    ]


def test_snapshot_changes_and_untrusted_text() -> None:
    snapshot = build_sample_snapshot()
    changed = replace(
        snapshot,
        detector="<example>",
        verdict=Verdict.ALERT,
        note_suffix="<suffix>",
        messages=(replace(snapshot.messages[0], text="<script>"),),
    )
    arena = render_arena(changed)
    assert "&lt;example&gt;" in arena and "&lt;suffix&gt;" in arena
    assert '<div class="verdict alert">ALERTA</div>' in arena
    assert "&lt;script&gt;" in render_analysis_tabs(changed)
