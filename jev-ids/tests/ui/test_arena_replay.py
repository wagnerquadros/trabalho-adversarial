"""Round-trip real arena events through the archive and presentation model."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from jev_ids.adversarial.classification import ArenaConfig, Classification
from jev_ids.adversarial.evaluation.metrics import Outcome, Sample
from jev_ids.adversarial.round_log import new_run_id, read_run, record_run
from jev_ids.ui.adapters import build_live_snapshot
from jev_ids.ui.components.arena import render_arena
from jev_ids.ui.models import Verdict


def test_replay_preserves_missing_measurements_and_exact_fields(tmp_path: Path) -> None:
    settings = ArenaConfig(rounds=2, budget=2, records_per_round=1)
    blocked = Classification(
        7,
        (("service", "http [NSL-KDD]"),),
        "normal",
        Sample(Outcome.BLOCKED, False, is_invalid=True),
        None,
        None,
        None,
        None,
        None,
        " [NSL-KDD]",
        False,
        "abc",
        ("service",),
    )
    failed = replace(blocked, sample=Sample(Outcome.FAILURE, False), error="offline", invalid_fields=(), reinforced=True)
    run_id = new_run_id()
    assert tuple(record_run(run_id, iter((blocked, failed)), settings, tmp_path)) == (blocked, failed)
    assert read_run(run_id, tmp_path) == (settings, (blocked, failed), None)
    empty = build_live_snapshot((), settings)
    assert empty.verdict == Verdict.WAITING and empty.round_index == 0
    snapshot = build_live_snapshot((blocked, failed), settings)
    assert snapshot.p_attack is None and snapshot.budget_left == 0
    assert snapshot.attempts == (Verdict.BLOCKED, Verdict.FAILURE)
    assert "FALHA" in render_arena(snapshot)
    assert sum(p.visits for p in snapshot.payoffs) == 2
    with pytest.raises(ValueError):
        read_run("../other", tmp_path)
