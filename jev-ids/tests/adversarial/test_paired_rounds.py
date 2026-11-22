"""Cover matched contrasts, partial cohorts and the single-record archive format."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

from jev_ids.adversarial.analysis.paired import compare_contexts
from jev_ids.adversarial.classification import ArenaConfig, Classification
from jev_ids.adversarial.evaluation.metrics import Outcome, Sample
from jev_ids.adversarial.round_log import new_run_id, read_run, record_run
from jev_ids.ui.adapters import build_live_snapshot


def _original(index: int) -> Classification:
    return Classification(index, (("service", "http"),), "dos", Sample(Outcome.QUIET, True), 0.1, "normal", 5, 20, None)


def test_comparison_joins_by_record_and_excludes_missing_predictions() -> None:
    first, second = _original(10), _original(20)
    alert = replace(first, note=" tag", sample=Sample(Outcome.ALERT, True), probability=0.8, category="dos")
    blocked = replace(second, note=" tag", sample=Sample(Outcome.BLOCKED, True, is_invalid=True), probability=None, category=None)
    result = compare_contexts((first, second, _original(30), blocked, alert))[0]
    assert (result["matched"], result["valid"]) == (2, 1)
    assert result["gained_alert"] == result["changed_score"] == result["changed_category"] == 1
    assert result["lost_alert"] == 0
    assert result["mean_score_delta"] == 0.8 - 0.1


def test_partial_final_round_is_counted_and_replayable(tmp_path: Path) -> None:
    config = ArenaConfig(rounds=4, budget=6, records_per_round=4)
    cohort = tuple(replace(_original(i), note=" tag") for i in range(4))
    rows = cohort + tuple(replace(row, reinforced=True) for row in cohort[:2])
    run_id = new_run_id()
    assert tuple(record_run(run_id, iter(rows), config, tmp_path)) == rows
    assert read_run(run_id, tmp_path) == (config, rows, None)
    folder = tmp_path / run_id
    events = [json.loads(line) for line in (folder / "rounds.jsonl").read_text().splitlines()]
    assert [(e["round"], e["position_in_round"]) for e in events] == [(1, 1), (1, 2), (1, 3), (1, 4), (2, 1), (2, 2)]
    summary = json.loads((folder / "summary.json").read_text())
    assert (summary["rounds_started"], summary["rounds_completed"], summary["unique_records"]) == (2, 1, 4)
    snapshot = build_live_snapshot(rows, config)
    assert snapshot.round_index == 2 and snapshot.budget_left == 0
    assert sum(cell.visits for cell in snapshot.payoffs) == 2
    assert len(snapshot.evasion_rates) == 2


def test_old_manifest_defaults_to_one_record_per_round(tmp_path: Path) -> None:
    config = ArenaConfig(rounds=2, budget=2, records_per_round=1)
    run_id = new_run_id()
    rows = tuple(record_run(run_id, iter((_original(3), _original(4))), config, tmp_path))
    path = tmp_path / run_id / "manifest.json"
    manifest = json.loads(path.read_text())
    del manifest["settings"]["records_per_round"]
    path.write_text(json.dumps(manifest))
    assert read_run(run_id, tmp_path) == (config, rows, None)
