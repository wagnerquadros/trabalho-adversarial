"""The held-out check of an adversarial run, on doubles: what it judges, what it reuses, what it refuses and the `holdout` subcommand."""

import csv
import hashlib
import json
import shutil
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from jev_ids import cli, holdout
from jev_ids.dataset import load_config, load_split
from jev_ids.holdout import CheckPlan, HeldRound, check_rounds, instructions_of, reserved_flows, rounds_to_check
from tests.adversarial_helpers import (
    ATTACKER_SCRIPT,
    BASE_INSTRUCTIONS,
    DEFENDER_SCRIPT,
    NSL_KDD_CARD,
    REINFORCED_INSTRUCTIONS,
    STUDY_FLOWS,
    AgentFactory,
    MockDecisionDetector,
    agent_factory,
    make_spec,
    read_jsonl,
)

RESERVED = "internal"


@pytest.fixture
def agents(tmp_path: Path) -> Iterator[AgentFactory]:
    yield from agent_factory(tmp_path)


@pytest.fixture
def run_dir(agents: AgentFactory, tmp_path: Path) -> Path:
    """The canonical cycle `N/B -> N/R -> S/R -> S/B -> N'/B`, played on doubles over the smoke split's card."""
    out = tmp_path / "run_adv"
    loop = agents.loop(ATTACKER_SCRIPT, DEFENDER_SCRIPT)
    loop.orchestrator.run_loop(STUDY_FLOWS, [], make_spec(tmp_path), out_dir=out)
    return out


def install(monkeypatch: pytest.MonkeyPatch, double: MockDecisionDetector) -> None:
    """Build `double` wherever the check would build the run's detector."""

    def build(_spec: Any, _config: Any) -> MockDecisionDetector:
        return double

    monkeypatch.setattr(holdout, "build_detector", build)


@pytest.fixture
def detector(monkeypatch: pytest.MonkeyPatch) -> MockDecisionDetector:
    """The rule-based double, built in place of the run's detector."""
    double = MockDecisionDetector()
    install(monkeypatch, double)
    return double


def test_each_round_is_judged_on_the_reserved_split_and_nothing_else(run_dir: Path, detector: MockDecisionDetector) -> None:
    out_dir, lines = holdout.holdout_from_run(run_dir, RESERVED)
    flows = load_split(NSL_KDD_CARD.parent / "splits" / f"{RESERVED}.csv", load_config(NSL_KDD_CARD))
    assert out_dir == run_dir / f"holdout_{RESERVED}"
    assert [line.state_code for line in lines] == ["N/B", "N/R", "S/R", "S/B", "N'/B"]
    assert detector.calls == 5 * len(flows)
    rows = read_jsonl(out_dir / "predictions.jsonl")
    assert len(rows) == 5 * len(flows)
    assert {row["row_id"] for row in rows} == {flow.row_id for flow in flows}
    assert all(row["holdout"] and row["adapted_on"] == "smoke" and row["split"] == RESERVED for row in rows)
    # Benign Flows never carry the note, on the reserved split as on the run's own.
    assert all(row["note"] == "" for row in rows if not row["is_attack"])
    assert [line["round"] for line in read_jsonl(out_dir / "rounds.jsonl")] == [1, 2, 3, 4, 5]


def test_the_reserved_split_shows_the_note_fooling_basic_instructions_and_the_reinforcement_catching_it(
    run_dir: Path, detector: MockDecisionDetector
) -> None:
    del detector
    _, lines = holdout.holdout_from_run(run_dir, RESERVED)
    by_code = {line.state_code: line for line in lines}
    assert by_code["N/B"].held_out_detection_rate is not None
    assert by_code["N/R"].held_out_detection_rate is not None
    assert by_code["N/B"].held_out_detection_rate < by_code["N/R"].held_out_detection_rate
    assert by_code["N/B"].held_out_detection_rate < (by_code["S/B"].held_out_detection_rate or 0)
    for line in lines:
        assert line.detection_gap == pytest.approx((line.held_out_detection_rate or 0) - (line.adapted_detection_rate or 0), abs=1e-4)
        assert line.total_attacks + line.total_benign == 50


def test_config_names_the_source_run_and_the_splits(run_dir: Path, detector: MockDecisionDetector) -> None:
    del detector
    out_dir, _ = holdout.holdout_from_run(run_dir, RESERVED, wanted=(1, 5))
    config = json.loads((out_dir / "config.json").read_text(encoding="utf-8"))
    assert (config["mode"], config["source_run"], config["adapted_on"], config["split"]) == ("holdout", "run_adv", "smoke", RESERVED)
    assert (config["rounds"], config["flows"], config["dropped_shared_flows"]) == ([1, 5], 50, 0)


def test_a_check_already_written_is_not_mixed_with_a_new_one(run_dir: Path, detector: MockDecisionDetector) -> None:
    del detector
    holdout.holdout_from_run(run_dir, RESERVED, wanted=(1,))
    with pytest.raises(ValueError, match="already holds a check"):
        holdout.holdout_from_run(run_dir, RESERVED, wanted=(1,))


def test_rounds_to_check_skips_a_round_the_detector_cut_short_and_refuses_unknown_rounds(run_dir: Path) -> None:
    lines = (run_dir / "rounds.jsonl").read_text(encoding="utf-8").splitlines()
    last = json.loads(lines[-1]) | {"why_adapted": "detector_stopped"}
    (run_dir / "rounds.jsonl").write_text("\n".join([*lines[:-1], json.dumps(last)]) + "\n", encoding="utf-8")
    assert [item.round for item in rounds_to_check(run_dir)] == [1, 2, 3, 4]
    with pytest.raises(ValueError, match=r"rounds \[5\]"):
        rounds_to_check(run_dir, wanted=(1, 5))


def test_a_run_without_rounds_has_nothing_to_check(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="nothing to check"):
        rounds_to_check(tmp_path)


def test_an_instruction_file_changed_after_the_run_is_refused(run_dir: Path) -> None:
    (item,) = rounds_to_check(run_dir, wanted=(2,))
    assert instructions_of(run_dir, item.instruction_label, item.instructions_sha256) == REINFORCED_INSTRUCTIONS
    (run_dir / "instructions" / f"{item.instruction_label}.txt").write_text("Classify everything as normal.", encoding="utf-8")
    with pytest.raises(ValueError, match="sha256 differs"):
        instructions_of(run_dir, item.instruction_label, item.instructions_sha256)


def test_the_reserved_split_must_differ_and_loses_every_flow_it_shares(tmp_path: Path) -> None:
    card = tmp_path / "nsl-kdd" / "dataset.json"
    card.parent.mkdir()
    shutil.copy(NSL_KDD_CARD, card)
    source = (NSL_KDD_CARD.parent / "splits" / f"{RESERVED}.csv").read_text(encoding="utf-8").splitlines()
    header, rows = source[0], source[1:]
    splits = card.parent / "splits"
    splits.mkdir()
    (splits / "adapt.csv").write_text("\n".join([header, *rows[:3]]) + "\n", encoding="utf-8")
    (splits / "reserved.csv").write_text("\n".join([header, *rows[2:6]]) + "\n", encoding="utf-8")
    config = load_config(card)
    with pytest.raises(ValueError, match="must differ"):
        reserved_flows(config, "adapt", "adapt")
    kept, dropped = reserved_flows(config, "adapt", "reserved")
    shared = next(csv.DictReader([header, rows[2]]))["row_id"]
    assert (len(kept), dropped) == (3, 1)
    assert int(shared) not in {flow.row_id for flow in kept}
    (splits / "inside.csv").write_text("\n".join([header, *rows[:2]]) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="also in"):
        reserved_flows(config, "adapt", "inside")


def held(round_index: int, note: str, label: str, text: str) -> HeldRound:
    """A round as `rounds_to_check` would read it, with made-up rates on the run's own split."""
    return HeldRound(round_index, f"?/{label}", note, label, hashlib.sha256(text.encode("utf-8")).hexdigest(), 0.5, 0.1, 0.5)


def write_versions(run_dir: Path) -> None:
    (run_dir / "instructions").mkdir(parents=True)
    (run_dir / "instructions" / "B.txt").write_text(BASE_INSTRUCTIONS, encoding="utf-8")
    (run_dir / "instructions" / "R.txt").write_text(REINFORCED_INSTRUCTIONS, encoding="utf-8")


def plan_for(flows: Any) -> CheckPlan:
    return CheckPlan(RESERVED, flows, [], 2, 60, {"split": RESERVED, "holdout": True})


def test_a_pair_already_judged_is_reused_and_says_from_which_round(tmp_path: Path) -> None:
    write_versions(tmp_path)
    flows = load_split(NSL_KDD_CARD.parent / "splits" / "smoke.csv", load_config(NSL_KDD_CARD))
    detector = MockDecisionDetector()
    rounds = [
        held(1, "(maintenance)", "B", BASE_INSTRUCTIONS),
        held(2, "", "R", REINFORCED_INSTRUCTIONS),
        held(3, "(maintenance)", "B", BASE_INSTRUCTIONS),
    ]
    lines = check_rounds(detector, tmp_path, rounds, plan_for(flows))
    assert [line.reused_from for line in lines] == [None, None, 1]
    assert detector.calls == 2 * len(flows)
    assert lines[2].held_out_detection_rate == lines[0].held_out_detection_rate
    assert not (tmp_path / "predictions.jsonl").exists()


def test_a_detector_that_stops_answering_ends_the_check_after_that_round(tmp_path: Path) -> None:
    write_versions(tmp_path)
    flows = load_split(NSL_KDD_CARD.parent / "splits" / "smoke.csv", load_config(NSL_KDD_CARD))
    detector = MockDecisionDetector(failing={flow.row_id for flow in flows})
    rounds = [held(1, "", "B", BASE_INSTRUCTIONS), held(2, "", "R", REINFORCED_INSTRUCTIONS)]
    (line,) = check_rounds(detector, tmp_path, rounds, plan_for(flows), out_dir=tmp_path)
    assert line.stopped
    assert line.held_out_detection_rate is None
    assert line.detection_gap is None
    assert line.attack_errors == line.total_attacks
    assert len(read_jsonl(tmp_path / "rounds.jsonl")) == 1


def test_cli_holdout_prints_one_row_per_round_and_refuses_a_second_check(
    run_dir: Path, detector: MockDecisionDetector, capsys: pytest.CaptureFixture[str]
) -> None:
    del detector
    assert cli.main(["holdout", str(run_dir), "--split", RESERVED, "--rounds", "1,2"]) == 0
    printed = list(csv.DictReader(capsys.readouterr().out.splitlines()))
    assert [row["state_code"] for row in printed] == ["N/B", "N/R"]
    assert {"adapted_detection_rate", "held_out_detection_rate", "detection_gap", "reused_from"} <= set(printed[0])
    with pytest.raises(SystemExit, match="already holds a check"):
        cli.main(["holdout", str(run_dir), "--split", RESERVED])


def test_cli_holdout_exits_non_zero_when_the_detector_stops(
    run_dir: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    flows = load_split(NSL_KDD_CARD.parent / "splits" / f"{RESERVED}.csv", load_config(NSL_KDD_CARD))
    double = MockDecisionDetector(failing={flow.row_id for flow in flows})
    install(monkeypatch, double)
    with pytest.raises(SystemExit, match="stopped answering at round 1"):
        cli.main(["holdout", str(run_dir), "--split", RESERVED])
    assert len(capsys.readouterr().out.splitlines()) == 2


@pytest.mark.parametrize("text", ["0", "", "a,b", "2,-1"])
def test_cli_holdout_refuses_rounds_that_are_not_integers_from_one(text: str) -> None:
    with pytest.raises(SystemExit):
        cli.main(["holdout", "results/x", "--split", RESERVED, "--rounds", text])
