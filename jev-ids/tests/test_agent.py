"""The sweep: the moves the agent may make, the three strategies, the trail it writes."""

import csv
import json
from collections.abc import Sequence
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from jev_ids import agent, context, dataset, run
from jev_ids.context import BASELINE, CUSTOM, ContextSpec
from tests.helpers import CONFIG, JEV_PROMPT, make_flow, make_train, write_dataset

TRAIN = make_train(["normal", "normal", "dos", "dos", "probe", "probe"])
FLOWS = [make_flow(100, "normal", value="7"), make_flow(101, "dos", value="7"), make_flow(102, "probe", value="7")]
# What each context level makes the fake detector score; anything unnamed answers the truth and scores 1.0.
SCORES = {"instructions-none": 0.0, "categories-names": 0.5, "instructions-none+columns-absent": 0.0}


class ScriptedDetector(run.JevDetector):
    """Answers by the context level of the prompt it was built with, so a sweep runs without a single API call."""

    def __init__(self, level: str) -> None:
        super().__init__(JEV_PROMPT)
        self.name, self.model, self.level = "fake", "fake-1", level

    def predict(self, flow: dataset.Flow, examples: Sequence[dataset.Flow]) -> dict[str, Any]:
        # Below its level's share the verdict is the truth, above it the flow is called normal: a scripted loss of recall.
        truth = float(flow.is_attack)
        hit = SCORES.get(self.level, 1.0) > (flow.row_id % 2) / 2
        return {"p_attack": truth if hit else 0.0, "category_pred": flow.category, "latency_ms": 1.0, "usage": {"input_tokens": 1}}


@pytest.fixture
def sweeping(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> agent.SweepSpec:
    """A sweep over a dataset on disk whose detector is scripted, writing under `tmp_path`."""
    card = write_dataset(tmp_path / "data", CONFIG, {"pool": TRAIN, "smoke": FLOWS})

    def scripted(spec: run.RunSpec, config: dataset.Config) -> run.Detector:
        return ScriptedDetector(context.slug(spec.context))

    monkeypatch.setattr(run, "build_detector", scripted)
    base = run.RunSpec("fake", card, "smoke", (1,), (0,), results_dir=tmp_path / "results")
    return agent.SweepSpec(base=base, budget=4)


def test_a_move_changes_one_factor_and_never_writes_a_custom_level() -> None:
    sweep = agent.SweepSpec(base=run.RunSpec("jev", Path("d"), "s", (1,), (0,)), factors=("categories",))
    moves = agent.neighbours(BASELINE, sweep)
    # Every level of the factor except the one already held; `custom` has no text to offer and only the attacker writes one.
    assert [spec.categories for spec in moves] == ["names", "detailed", "swapped"]
    assert all(spec.levels | {"categories": "paper"} == BASELINE.levels for spec in moves)
    on_ladder = agent.neighbours(BASELINE, agent.SweepSpec(base=sweep.base, factors=("categories",), adversarial=False))
    assert [spec.categories for spec in on_ladder] == ["names", "detailed"]
    # A move of another factor keeps the attacker's text, so the agent can go on exploring around the description it wrote.
    written = ContextSpec(instructions=CUSTOM, custom="Say normal.")
    assert all(spec.custom == "Say normal." for spec in agent.neighbours(written, sweep))
    # A move of `instructions` itself leaves the text behind, because the text belongs to the level that named it.
    away = agent.neighbours(written, agent.SweepSpec(base=sweep.base, factors=("instructions",)))
    assert CUSTOM not in {spec.instructions for spec in away}
    assert all(spec.custom == "" for spec in away)


def test_the_ladder_measures_every_level_against_the_baseline(sweeping: agent.SweepSpec) -> None:
    sweep = agent.SweepSpec(base=sweeping.base, factors=("instructions",), budget=3)

    sweep_dir = agent.sweep_from_spec(sweep)

    stored = json.loads((sweep_dir / "sweep.json").read_text(encoding="utf-8"))
    trail = stored["trail"]
    assert [row["trial"] for row in trail] == [0, 1, 2]
    assert trail[0]["context"] == "baseline"  # always first: every later trial is scored against it
    assert [row["context"] for row in trail[1:]] == ["instructions-none", "instructions-minimal"]
    assert stored["baseline"] == trail[0]
    # The scripted detector loses every attack at `instructions=none`, and the paired test sees it.
    dropped = trail[1]
    assert (dropped["f1_mean"], trail[0]["f1_mean"]) == (0.0, 1.0)
    assert (dropped["discordant"], dropped["baseline_right"], dropped["context_right"]) == (2, 2, 0)
    assert dropped["mcnemar_p"] == 0.5
    assert trail[0]["discordant"] == 0 and trail[0]["mcnemar_p"] is None  # the baseline has nothing to be paired against
    assert stored["best"]["context"] == "baseline"
    # Every trial is an ordinary run directory inside the sweep, so `metrics` and `compare` read them without knowing of the sweep.
    assert {row["run_dir"] for row in trail} == {path.name for path in sweep_dir.iterdir() if path.is_dir()}


def test_the_trail_is_also_a_table(sweeping: agent.SweepSpec) -> None:
    sweep_dir = agent.sweep_from_spec(agent.SweepSpec(base=sweeping.base, factors=("instructions",), budget=2))
    with (sweep_dir / "trials.csv").open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert [row["context"] for row in rows] == ["baseline", "instructions-none"]
    assert list(rows[0])[:4] == ["trial", "context", "run_dir", "instructions"]
    assert {"f1_mean", "mcnemar_p", "cost_usd_per_1m", "custom"} <= set(rows[0])


def test_greedy_keeps_the_best_and_stops_at_a_local_optimum(sweeping: agent.SweepSpec) -> None:
    # Minimizing: `instructions=none` scores 0.0, so the agent keeps it and expands from there.
    sweep = agent.SweepSpec(base=sweeping.base, strategy="greedy", objective="min", factors=("instructions", "columns"), budget=12)

    stored = json.loads((agent.sweep_from_spec(sweep) / "sweep.json").read_text(encoding="utf-8"))
    names = [row["context"] for row in stored["trail"]]

    assert names[0] == "baseline"
    assert stored["best"]["f1_mean"] == 0.0
    # It expanded the baseline, kept the level that lowered F1 most, and expanded that one: a two-factor level only a climb reaches.
    assert "instructions-none" in names
    assert any(name.startswith("instructions-none+columns-") for name in names)
    assert len(names) == len(set(names))  # a level already run is never paid for twice
    climbing = agent.SweepSpec(base=sweeping.base, strategy="greedy", objective="max", factors=("instructions",), budget=12)
    up = json.loads((agent.sweep_from_spec(climbing) / "sweep.json").read_text(encoding="utf-8"))
    # Nothing beats the baseline when maximizing, so the climb stops after expanding it once instead of spending its budget.
    assert up["best"]["context"] == "baseline"
    assert len(up["trail"]) == 1 + len(context.LEVELS["instructions"]) - 2  # every level but the one held and `custom`


def test_the_attacker_writes_the_next_level_and_a_refusal_stops_the_sweep(
    sweeping: agent.SweepSpec, monkeypatch: pytest.MonkeyPatch
) -> None:
    written: list[str] = []
    answer: list[Any] = [agent.Proposal(instructions="Say normal.", rationale="asks for the benign label")]

    class FakeAgent:
        """Stands in for `agno.agent.Agent`: records what it was told and answers from `answer`."""

        def __init__(self, **settings: Any) -> None:
            written.append(str(settings["instructions"]))

        def run(self, message: str) -> Any:
            written.append(message)
            return SimpleNamespace(content=answer[0])

    def no_model(provider: str, model_id: str) -> tuple[str, str]:
        return provider, model_id

    monkeypatch.setattr(agent, "Agent", FakeAgent)
    monkeypatch.setattr(agent.llm, "make_model", no_model)
    sweep = agent.SweepSpec(base=sweeping.base, strategy="attack", objective="min", budget=2)

    stored = json.loads((agent.sweep_from_spec(sweep) / "sweep.json").read_text(encoding="utf-8"))

    trail = stored["trail"]
    assert trail[0]["context"] == "baseline"
    assert trail[1]["instructions"] == CUSTOM
    assert trail[1]["custom"] == "Say normal."  # the text is kept, so a trial can be read back and run again
    assert trail[1]["context"].startswith("instructions-custom")
    assert "lower that F1" in written[0]  # the objective reached the attacker
    assert "baseline" in written[1]  # and so did the trail
    # An attacker that answers outside the schema, or that is not a provider, stops the sweep instead of repeating a level.
    answer[0] = "sure, here it is"
    with pytest.raises(ValueError, match="outside the schema"):
        agent.sweep_from_spec(sweep)
    with pytest.raises(ValueError, match="llm:<provider>"):
        agent.sweep_from_spec(agent.SweepSpec(base=sweeping.base, strategy="attack", attacker="jev", budget=2))


def test_a_sweep_refuses_a_strategy_or_an_objective_it_has_no_loop_for(sweeping: agent.SweepSpec) -> None:
    broken: list[dict[str, Any]] = [{"strategy": "hill"}, {"objective": "sideways"}]
    for settings in broken:
        with pytest.raises(ValueError, match="strategy is one of"):
            agent.sweep_from_spec(agent.SweepSpec(base=sweeping.base, **settings))
