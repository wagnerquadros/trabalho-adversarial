"""The held-out check of an adversarial run: does what each round settled on still hold on Flows no agent ever saw?

Every round of `adversarial.py` judges and adapts on the same split, so a defense that works there may only fit those 50 Flows, and a note
that passes there may only fool the detector on them. This module takes a finished run and judges a second split, kept apart, under the
note and the instructions each round had in force. Nothing it measures goes back to the agents: it never opens their memories and runs
after the loop, so the reserved split cannot shape any decision (interface I7 of the Trabalho 1, "dados do conjunto final reservado").

In reading order:

- `HeldRound` and `rounds_to_check`: the rounds of a run that judged every Flow, with their note and their instructions.
- `instructions_of`: the text of one instruction version, checked against the sha256 the rows carry.
- `reserved_flows`: the held-out split without any Flow the run adapted on.
- `HoldoutRecord` and `check_rounds`: one judgement of the reserved split per distinct (note, instructions) pair, one line per round.
- `holdout_from_run`: the CLI entry that strings the above together into `<run_dir>/holdout_<split>/`.

Two rounds with the same note and the same instructions ask the detector the same question, so the reserved split is judged once for the
pair and the later round says which round it reuses (`reused_from`). A call that fails is counted apart, as in `evaluator.py`, and the rates
read the answered Flows only.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Collection, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from typing import Any, cast

from jev_ids import records
from jev_ids.adversarial import DETECTOR_STOPPED, read_rounds, spec_of
from jev_ids.dataset import Config, Flow, load_config, load_split
from jev_ids.detectors import DecisionDetector
from jev_ids.evaluator import RoundCounts, RoundEvaluation, RoundPlan, evaluate_round, service_feature_index
from jev_ids.run import RunSpec, build_detector, sample_examples


@dataclass(frozen=True)
class HeldRound:
    """One round of the run, as the held-out check reads it from `rounds.jsonl`.

    Attributes:
        round: the round, from 1.
        state_code: the compact code of the round (`N/B`, `S/R`, ...).
        note: the attacker's note in force, empty for none.
        instruction_label: the label of the instructions in force.
        instructions_sha256: the sha256 of their text.
        detection_rate: detected attacks over answered attacks on the split the run adapted on.
        false_alarm_rate: the false-alarm rate on that split.
        f1: the F1 on that split.
    """

    round: int
    state_code: str
    note: str
    instruction_label: str
    instructions_sha256: str
    detection_rate: float | None
    false_alarm_rate: float
    f1: float


def detection_rate(detected: int, total: int, errors: int) -> float | None:
    """Detected attacks over the answered ones; None when no attack was answered."""
    answered = total - errors
    return None if answered <= 0 else round(detected / answered, 4)


def rounds_to_check(run_dir: Path, wanted: Collection[int] | None = None) -> list[HeldRound]:
    """The rounds of the run that judged every Flow, or only those in `wanted`.

    A round the detector cut short (`detector_stopped`) is left out: its instructions and note were never measured on the whole split.

    Raises:
        ValueError: when the run recorded no round, or a round in `wanted` is not among those it can check.
    """
    held: list[HeldRound] = []
    for record in read_rounds(run_dir):
        if record.why_adapted == DETECTOR_STOPPED:
            continue
        rate = detection_rate(record.attacks_detected, record.total_attacks, record.attack_errors)
        held.append(
            HeldRound(
                record.round,
                record.state_code,
                record.note,
                record.instruction_label,
                record.instructions_sha256,
                rate,
                record.false_alarm_rate,
                record.f1,
            )
        )
    if not held:
        raise ValueError(f"{run_dir}: no round judged every Flow, so there is nothing to check")
    if wanted is None:
        return held
    missing = sorted(set(wanted) - {item.round for item in held})
    if missing:
        raise ValueError(f"{run_dir}: rounds {missing} are not among the rounds that judged every Flow")
    return [item for item in held if item.round in wanted]


def instructions_of(run_dir: Path, label: str, sha256: str) -> str:
    """The text of one instruction version, from `instructions/<label>.txt`, refused when its bytes no longer hash to `sha256`."""
    path = run_dir / "instructions" / f"{label}.txt"
    payload = path.read_bytes()
    if hashlib.sha256(payload).hexdigest() != sha256:
        raise ValueError(f"{path}: its sha256 differs from the one the rounds recorded; the file changed after the run")
    return payload.decode("utf-8")


def reserved_flows(config: Config, adapted_on: str, held_out: str) -> tuple[list[Flow], int]:
    """The held-out split without any Flow of the split the run adapted on, and how many were dropped.

    Raises:
        ValueError: when the two splits are the same, or nothing is left once the shared Flows are dropped.
    """
    if adapted_on == held_out:
        raise ValueError(f"the held-out split must differ from the split the run adapted on ({adapted_on!r})")
    splits = config["dir"] / "splits"
    seen = {flow.row_id for flow in load_split(splits / f"{adapted_on}.csv", config)}
    candidates = load_split(splits / f"{held_out}.csv", config)
    kept = [flow for flow in candidates if flow.row_id not in seen]
    if not kept:
        raise ValueError(f"every Flow of {held_out!r} is also in {adapted_on!r}")
    return kept, len(candidates) - len(kept)


@dataclass(frozen=True)
class HoldoutRecord:
    """One line of `holdout_<split>/rounds.jsonl`: a round of the run, measured on the split it adapted on and on the reserved one.

    Attributes:
        round: the round of the run.
        state_code: its compact code.
        note: the note in force.
        instruction_label: the label of the instructions in force.
        split: the reserved split.
        adapted_detection_rate: the detection rate the run measured on its own split.
        held_out_detection_rate: the detection rate on the reserved split.
        adapted_false_alarm_rate: the false-alarm rate on the run's own split.
        held_out_false_alarm_rate: the false-alarm rate on the reserved split.
        adapted_f1: the F1 on the run's own split.
        held_out_f1: the F1 on the reserved split.
        detection_gap: held-out detection minus adapted detection; negative when the round did worse on unseen Flows.
        reused_from: the earlier round whose judgement this one reuses, None when this round was judged itself.
        stopped: whether the detector stopped answering on the reserved split.
    """

    round: int
    state_code: str
    note: str
    instruction_label: str
    split: str
    adapted_detection_rate: float | None
    held_out_detection_rate: float | None
    adapted_false_alarm_rate: float
    held_out_false_alarm_rate: float
    adapted_f1: float
    held_out_f1: float
    detection_gap: float | None
    attacks_detected: int
    attacks_passed: int
    attack_errors: int
    false_alarms: int
    benign_errors: int
    total_attacks: int
    total_benign: int
    reused_from: int | None
    stopped: bool


def _record(item: HeldRound, split: str, evaluation: RoundEvaluation, reused_from: int | None) -> HoldoutRecord:
    """The line of one round, from what the run measured and what the reserved split gave."""
    counts: RoundCounts = evaluation.counts
    held_rate = detection_rate(counts.attacks_detected, counts.total_attacks, counts.attack_errors)
    gap = None if held_rate is None or item.detection_rate is None else round(held_rate - item.detection_rate, 4)
    return HoldoutRecord(
        round=item.round,
        state_code=item.state_code,
        note=item.note,
        instruction_label=item.instruction_label,
        split=split,
        adapted_detection_rate=item.detection_rate,
        held_out_detection_rate=held_rate,
        adapted_false_alarm_rate=item.false_alarm_rate,
        held_out_false_alarm_rate=evaluation.false_alarm_rate,
        adapted_f1=item.f1,
        held_out_f1=round(evaluation.f1, 4),
        detection_gap=gap,
        reused_from=reused_from,
        stopped=evaluation.stopped,
        **asdict(counts),
    )


def _append(out_dir: Path | None, name: str, line: dict[str, Any]) -> None:
    """Append one JSON line to `out_dir/name`; no folder writes nothing."""
    if out_dir is None:
        return
    with (out_dir / name).open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(line, ensure_ascii=False) + "\n")


@dataclass(frozen=True)
class CheckPlan:
    """What every judgement of the reserved split shares.

    Attributes:
        split: the reserved split, by name.
        flows: its Flows, without those of the split the run adapted on.
        examples: the labeled Examples of the run, the same in every judgement.
        service_index: where `service` sits among the card's features.
        max_note_length: the run's longest note, in characters.
        fields: the fields every row shares.
    """

    split: str
    flows: Sequence[Flow]
    examples: Sequence[Flow]
    service_index: int
    max_note_length: int
    fields: dict[str, Any]


def check_rounds(
    detector: DecisionDetector,
    run_dir: Path,
    rounds: Sequence[HeldRound],
    plan: CheckPlan,
    out_dir: Path | None = None,
) -> list[HoldoutRecord]:
    """Judge the reserved split under each round's note and instructions, once per distinct pair, and write one line per round.

    The rows go to `out_dir/predictions.jsonl` right after each call and the lines to `out_dir/rounds.jsonl`, so a check that fails
    later loses nothing already paid for. A detector that stops answering ends the check after that round's line.
    """
    judged: dict[tuple[str, str], tuple[int, RoundEvaluation]] = {}
    lines: list[HoldoutRecord] = []
    for item in rounds:
        key = (item.note, item.instructions_sha256)
        if key in judged:
            first, evaluation = judged[key]
            lines.append(_record(item, plan.split, evaluation, first))
        else:
            detector.set_instructions(instructions_of(run_dir, item.instruction_label, item.instructions_sha256))
            fields = {
                **plan.fields,
                "round": item.round,
                "instruction_label": item.instruction_label,
                "instructions_sha256": item.instructions_sha256,
            }
            round_plan = RoundPlan(item.note, plan.service_index, plan.max_note_length, fields)
            sink = partial(_append, out_dir, "predictions.jsonl")
            evaluation = evaluate_round(detector, plan.flows, plan.examples, round_plan, sink)
            judged[key] = (item.round, evaluation)
            lines.append(_record(item, plan.split, evaluation, None))
        _append(out_dir, "rounds.jsonl", asdict(lines[-1]))
        if lines[-1].stopped:
            break
    return lines


def holdout_from_run(run_dir: Path, split: str, wanted: Collection[int] | None = None) -> tuple[Path, list[HoldoutRecord]]:
    """Check a finished adversarial run on a reserved split, into `<run_dir>/holdout_<split>/`.

    The detector, its model, the record format, k and the seed are the run's own (`adversarial.spec_of`); the agents are never built.

    Args:
        run_dir: the `results/adv_*` folder of the run.
        split: the reserved split, a file under `data/<name>/splits/`.
        wanted: the rounds to check; None checks every round that judged every Flow.

    Returns:
        The folder written and one line per round checked.

    Raises:
        ValueError: when the folder already holds a check of that split, or the splits or rounds cannot be checked.
    """
    spec = spec_of(run_dir)
    config = load_config(spec.dataset)
    rounds = rounds_to_check(run_dir, wanted)
    flows, dropped = reserved_flows(config, spec.split, split)
    out_dir = run_dir / f"holdout_{split}"
    if (out_dir / "rounds.jsonl").exists():
        raise ValueError(f"{out_dir} already holds a check; remove the folder to judge it again")
    examples: list[Flow] = []
    if spec.k > 0:
        examples = sample_examples(load_split(config["dir"] / "pool.csv", config), spec.k, spec.seed, config["categories"])
    run_spec = RunSpec(
        detector=spec.detector,
        dataset=spec.dataset,
        split=split,
        k_values=(spec.k,),
        seeds=(spec.seed,),
        model_id=spec.detector_model,
        record=spec.record,
    )
    detector = cast(DecisionDetector, build_detector(run_spec, config))
    fields: dict[str, Any] = {
        "dataset": config["name"],
        "detector": detector.name,
        "model": detector.model,
        "split": split,
        "adapted_on": spec.split,
        "prompt_hash": detector.prompt_hash,
        "record": spec.record,
        "k": spec.k,
        "seed": spec.seed,
        "holdout": True,
    }
    records.write_config(
        out_dir,
        {
            "mode": "holdout",
            "source_run": run_dir.name,
            "adapted_on": spec.split,
            "split": split,
            "flows": len(flows),
            "attacks": sum(1 for flow in flows if flow.is_attack),
            "dropped_shared_flows": dropped,
            "rounds": [item.round for item in rounds],
            "detector": detector.name,
            "detector_model": detector.model,
            "record": spec.record,
            "k": spec.k,
            "seed": spec.seed,
            "started_at": datetime.now(UTC).isoformat(timespec="seconds"),
        },
    )
    plan = CheckPlan(split, flows, examples, service_feature_index(config), spec.max_note_length, fields)
    return out_dir, check_rounds(detector, run_dir, rounds, plan, out_dir)
