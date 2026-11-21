"""Compose the illustrative arena with native Streamlit controls."""

from __future__ import annotations

import streamlit as st

from jev_ids.ui.components.analysis_tabs import TAB_LABELS, render_analysis_tabs
from jev_ids.ui.components.arena import render_arena
from jev_ids.ui.components.header import RUN_ALL, STEP, TITLE, render_header
from jev_ids.ui.components.metrics import render_metrics
from jev_ids.ui.components.payoff_matrix import render_payoff_matrix
from jev_ids.ui.components.sidebar import show_sidebar
from jev_ids.ui.components.timeline import render_timeline
from jev_ids.ui.sample_data import build_sample_snapshot
from jev_ids.ui.theme import load_css


def _show(markup: str) -> None:
    # Keep one HTML block in Markdown so the inline SVG survives rendering.
    content = " ".join(markup.splitlines())
    st.markdown(f'<div class="arena-html">{content}</div>', unsafe_allow_html=True)


def main() -> None:
    """Show the reference round without running a simulation."""
    st.set_page_config(page_title=TITLE, layout="wide", initial_sidebar_state="expanded")
    st.markdown(f"<style>{load_css()}</style>", unsafe_allow_html=True)
    snapshot = show_sidebar(build_sample_snapshot())
    with st.container(key="page_header"):
        title, step, run_all = st.columns([8, 1, 1])
        with title:
            _show(render_header(snapshot))
        step.button(STEP)
        run_all.button(RUN_ALL, type="primary")
    with st.container(key="page_content"):
        _show(render_timeline(snapshot))
        _show(render_arena(snapshot))
        _show(f'<section class="summary">{render_payoff_matrix(snapshot)}{render_metrics(snapshot)}</section>')
        with st.container(key="analysis"):
            messages, *placeholders = st.tabs(TAB_LABELS)
            with messages:
                _show(render_analysis_tabs(snapshot))
            for tab in placeholders:
                with tab:
                    _show('<div class="c"></div>')


if __name__ == "__main__":
    main()
