"""Native configuration controls and fixed study settings."""

from __future__ import annotations

from dataclasses import replace

from ..models import RoundSnapshot

_DETECTORS = ("Qwen3:8b · Ollama", "Laya multilingual")
_VALIDATORS = ("Observar", "Bloquear (comparação)")
_HEADING = '<h2 class="h" style="margin:0">Configuração</h2>'
_FIXED = """<div class="blk m"><b style="color:#1B2330">Fixos no recorte</b><br>Limiar de alerta {threshold}<br>
Exemplos rotulados (k = 1)<br>Demais atributos do registro</div>"""
_DETECTOR_LABEL = "Detector (um por execução)"
_SEED_LABEL = "Semente"
_ROUNDS_LABEL = "Rodadas: {}"
_BUDGET_LABEL = "Orçamento de tentativas do atacante: {}"
_VALIDATOR_LABEL = "Validador de campos (C6)"
_START = "Iniciar simulação"


def render_sidebar(snapshot: RoundSnapshot) -> str:
    """Render the fixed settings below the native controls."""
    return _FIXED.format(threshold=format(snapshot.threshold, "g").replace(".", ","))


def show_sidebar(snapshot: RoundSnapshot) -> RoundSnapshot:
    """Display the controls and bind the selected detector to its label."""
    import streamlit as st  # noqa: PLC0415 -- optional UI dependency

    with st.sidebar:
        st.html(_HEADING)
        detector = st.selectbox(_DETECTOR_LABEL, _DETECTORS)
        st.selectbox(_SEED_LABEL, (0, 1, 2))
        st.slider(_ROUNDS_LABEL.format(st.session_state.get("rounds", snapshot.total_rounds)), 3, 20, snapshot.total_rounds, key="rounds")
        st.slider(_BUDGET_LABEL.format(st.session_state.get("budget", snapshot.budget_total)), 4, 30, snapshot.budget_total, key="budget")
        st.selectbox(_VALIDATOR_LABEL, _VALIDATORS)
        st.html(render_sidebar(snapshot))
        st.button(_START, type="primary", width="stretch")
    return replace(snapshot, detector=detector.split(" · ")[0])
