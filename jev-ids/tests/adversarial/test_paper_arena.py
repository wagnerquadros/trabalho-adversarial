"""Exercise the committed paper split and the two interpretations of call errors."""

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from statistics import stdev

import pytest

from jev_ids import ROOT
from jev_ids.adversarial.analysis.paired import compare_contexts
from jev_ids.adversarial.analysis.protocol import protocol_report
from jev_ids.adversarial.classification import ArenaConfig, Classification, arena_records
from jev_ids.adversarial.evaluation.metrics import Outcome, Sample
from jev_ids.dataset import Config, Flow, load_config, load_split


def test_each_seed_and_condition_visits_the_same_ordered_paper_split(monkeypatch: pytest.MonkeyPatch) -> None:
    config = load_config(ROOT / "data/nsl-kdd/dataset.json")
    settings = ArenaConfig.paper("qwen3", "observe", 50)
    pool = [Flow(i * 5 + j, "0," * 40 + "0", c, c != "normal") for i in range(10) for j, c in enumerate(config["categories"])]

    def splits(path: Path, card: Config) -> list[Flow]:
        return pool if path.name == "pool.csv" else load_split(path, card)

    class Detector:
        first = True

        def predict(self, flow: Flow, examples: Sequence[Flow]) -> dict[str, object]:
            if self.first:
                self.first = False
                raise TimeoutError("timeout")
            assert len({ref.category for ref in examples}) == 5
            return {"p_attack": 0, "category_pred": "normal", "usage": {"total_tokens": 20}, "latency_ms": 10}

    monkeypatch.setattr("jev_ids.adversarial.classification.load_split", splits)
    monkeypatch.setattr("jev_ids.adversarial.classification.build_detector", lambda *_args, **_kwargs: Detector())
    cells: dict[tuple[int, bool, bool], list[int]] = defaultdict(list)
    examples_by_seed: dict[int, set[tuple[int, ...]]] = defaultdict(set)
    failures = 0
    for row in arena_records(settings):
        cells[row.seed, bool(row.note), row.reinforced].append(row.row_id)
        examples_by_seed[row.seed].add(row.example_ids)
        failures += row.sample.outcome == Outcome.FAILURE
    assert failures == 2  # One transient error from each prompt's detector.
    assert all(len(examples) == 1 for examples in examples_by_seed.values())
    assert len(set.union(*examples_by_seed.values())) == 3
    expected = [flow.row_id for flow in load_split(config["dir"] / "splits/paper.csv", config)]
    assert len(set(expected)) == 2000 and len(cells) == 12
    assert all(ids == expected for ids in cells.values())


def test_complete_seed_statistics_and_paired_cost_do_not_mix_seeds() -> None:
    config = ArenaConfig.paper("qwen3", "observe", 100)
    hit = Classification(0, (), "dos", Sample(Outcome.ALERT, True), 0.8, "dos", 12, 50, None)
    rows = [replace(hit, seed=seed, row_id=i) for seed in range(3) for i in range(2000)]
    for index in (2000, 4000, 4001):
        rows[index] = replace(rows[index], sample=Sample(Outcome.FAILURE, True), probability=None, category=None, error="timeout")
    assert not protocol_report(rows[:-1], config)["across_seeds"]
    report = protocol_report(rows, config)
    arena, paper = report["across_seeds"]
    expected = [1, 3998 / 3999, 3996 / 3998]
    assert (arena["f1_mean"], arena["f1_sd"]) == (1, 0)
    assert paper["f1_mean"] == pytest.approx(sum(expected) / 3)
    assert paper["f1_sd"] == pytest.approx(stdev(expected))
    b0, b1 = hit, replace(hit, seed=1, tokens=500)
    r0, r2 = replace(hit, reinforced=True, tokens=73, latency_ms=8), replace(hit, seed=2, reinforced=True, tokens=700)
    contrast = compare_contexts((b0, b1, r0, r2))[2]
    assert (contrast["matched"], contrast["mean_token_delta"], contrast["mean_latency_delta_ms"]) == (1, 23, -4)
