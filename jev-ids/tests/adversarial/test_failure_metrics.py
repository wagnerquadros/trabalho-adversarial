"""Cross-check evaluation against stored baseline predictions."""

from __future__ import annotations

import csv
import json
from statistics import mean

import pytest

from jev_ids import ROOT
from jev_ids.adversarial.evaluation.metrics import Outcome, Sample, classify, measure


@pytest.mark.parametrize("score", [None, False, "0", float("nan"), float("inf"), -0.01, 1.01])
def test_invalid_probability_has_no_decision(score: object) -> None:
    outcome, reason = classify(score)
    assert outcome == Outcome.FAILURE and reason
    assert classify(0.0, "timeout") == (Outcome.FAILURE, "timeout")
    assert classify(0.5) == (Outcome.ALERT, None)


def test_failures_and_blocks_are_separate_from_misses() -> None:
    counts = measure([Sample(Outcome.FAILURE, True), Sample(Outcome.BLOCKED, True), Sample(Outcome.QUIET, True, is_invalid=True)])
    assert (counts["failures"], counts["invalid_blocked"], counts["invalid"], counts["misses"]) == (1, 1, 2, 1)
    assert counts["miss_rate"] == 1
    assert measure([])["miss_rate"] is None


def test_published_jev_anchor() -> None:
    directory = ROOT / "results/paper"
    (path,) = directory.glob("*-jev-paper/predictions.jsonl")
    seeds: dict[int, list[Sample]] = {0: [], 1: [], 2: []}
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            row = json.loads(line)
            if row["k"] == 1:
                outcome, _ = classify(row["p_attack"], row.get("error"))
                seeds[row["seed"]].append(Sample(outcome, bool(row["is_attack"]), row["novel_attack"]))
    metrics = [measure(rows) for rows in seeds.values()]
    assert [item["false_alarms"] for item in metrics] == [57, 36, 37]
    with (directory / "summary.csv").open(encoding="utf-8", newline="") as source:
        summary = next(row for row in csv.DictReader(source) if row["detector"] == "jev" and row["k"] == "1")
    for key, column in (("f1", "f1_mean"), ("zero_day_recall", "recall_novel_mean")):
        values = [item[key] for item in metrics]
        present = [value for value in values if value is not None]
        assert len(present) == 3
        assert mean(present) == pytest.approx(float(summary[column]))
