"""Consistency checks for the illustrative fifth round."""

from __future__ import annotations

from collections import Counter

from jev_ids.ui import RoundCell, build_sample_snapshot
from jev_ids.ui.models import Verdict


def test_round_history_matches_matrix_and_chart() -> None:
    snapshot = build_sample_snapshot()
    visits = Counter(snapshot.cells)
    assert snapshot.current_cell == RoundCell("N", "B")
    assert visits == {payoff.cell: payoff.visits for payoff in snapshot.payoffs}
    assert len(snapshot.cells) == snapshot.round_index == 5
    assert snapshot.total_rounds == 10
    assert snapshot.evasion_rates == (48, 18, 24, 26, 47)
    assert snapshot.false_alarm_rates == (5, 9, 10, 6, 5)
    assert snapshot.attempts.count(None) == 5
    assert snapshot.attempts.count(Verdict.ALERT) == 1
    assert (snapshot.budget_left, snapshot.budget_total) == (7, 12)
    assert (snapshot.p_attack, snapshot.threshold) == (0.38, 0.5)
    assert len(snapshot.metrics) == 8
