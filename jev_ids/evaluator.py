"""The evaluator of the adversarial loop: the note in the `service` field, one round of detector calls and what the round measured.

In reading order:

- `sanitize_note`, `normalize_wording`, `apply_note` and `service_feature_index`: the one thing the attacker may change, a note appended
  to the `service` value of the attack Flows, kept to a single CSV-safe line. Benign Flows never carry it.
- `RoundPlan`: what one round fixes for every call.
- `RoundCounts` and `RoundEvaluation`: what one round measured.
- `evaluate_round`: one call and one row per Flow, each row handed over right after its call.
- `answered` and `summarize_rows`: the counts read off the rows.

A call that fails ends as a row without a Verdict (`records.complete_prediction`). Such a row is neither an alert nor a pass, so it is
counted apart (`attack_errors`, `benign_errors`), and the passes, the false alarms, the rates, F1 and the turn rule read the answered rows
only.
"""

from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from typing import Any

from jev_ids import metrics, records
from jev_ids.dataset import Config, Flow
from jev_ids.detectors import DecisionDetector
from jev_ids.records import Prediction

# Stopping a round after this many failed calls in a row, because a detector that stopped answering only burns the calls left.
DETECTOR_FAILURE_LIMIT = 10

# Typing what receives each row right after its call; the orchestrator appends it to predictions.jsonl.
Sink = Callable[[Prediction], None]


def sanitize_note(note: str, max_note_length: int) -> str:
    """Keep a single-line CSV-safe note capped at `max_note_length` characters."""
    clean = note.replace(",", ";").replace("\r", " ").replace("\n", " ").strip()
    return clean[:max_note_length].strip()


def normalize_wording(note: str) -> str:
    """A note as two wordings are compared: casefolded, with every run of whitespace collapsed to one space."""
    return " ".join(note.casefold().split())


def apply_note(
    flow: Flow,
    note: str,
    service_index: int = 2,
    max_note_length: int = 120,
) -> Flow:
    """Attach `note` to the `service` attribute of an attack Flow; leave benign Flows untouched."""
    if not flow.is_attack or not note.strip():
        return flow
    clean = sanitize_note(note, max_note_length)
    if not clean:
        return flow
    attrs = flow.attributes_csv.split(",")
    if not (0 <= service_index < len(attrs)):
        raise ValueError(f"service_index {service_index} out of bounds for flow with {len(attrs)} fields")
    attrs[service_index] = f"{attrs[service_index]} {clean}"
    return replace(flow, attributes_csv=",".join(attrs))


def service_feature_index(config: Config) -> int:
    """Locate the `service` feature index in `config['features']` (2 in NSL-KDD)."""
    features = config["features"]
    if "service" not in features:
        raise ValueError(f"dataset {config['name']!r} has no 'service' feature")
    return features.index("service")


@dataclass(frozen=True)
class RoundPlan:
    """What one round fixes for every call of the detector.

    Attributes:
        note: the attacker's note in force, already sanitized; empty for none.
        service_index: where `service` sits among the card's features.
        max_note_length: the longest note allowed, in characters.
        fields: the fields every row of the round shares (the dataset, the split, k, the seed, the round, the instruction version).
    """

    note: str
    service_index: int
    max_note_length: int
    fields: dict[str, Any]


@dataclass(frozen=True)
class RoundCounts:
    """The Flows of one round by what their call gave; a failed call is neither an alert nor a pass and is counted apart.

    Attributes:
        attacks_detected: answered attack Flows that raised an alert.
        attacks_passed: answered attack Flows that raised none.
        attack_errors: attack Flows whose call failed, which left a row without a Verdict.
        false_alarms: answered benign Flows that raised an alert.
        benign_errors: benign Flows whose call failed.
        total_attacks: attack Flows judged, answered or not.
        total_benign: benign Flows judged, answered or not.
    """

    attacks_detected: int
    attacks_passed: int
    attack_errors: int
    false_alarms: int
    benign_errors: int
    total_attacks: int
    total_benign: int


@dataclass(frozen=True)
class RoundEvaluation:
    """What one round measured.

    Attributes:
        counts: the Flows of the round by what their call gave.
        f1: attack-class F1 over the answered rows, 0.0 when it is undefined.
        false_alarm_rate: the false alarms over the answered benign Flows.
        notes_tested: the notes the attack Flows carried, at most one per round.
        attack_verdicts: whether each answered attack Flow raised an alert, keyed by the Flow's position in the split.
        stopped: whether the round was cut short because the detector stopped answering.
    """

    counts: RoundCounts
    f1: float
    false_alarm_rate: float
    notes_tested: list[str]
    attack_verdicts: dict[int, bool]
    stopped: bool = False


def evaluate_round(
    detector: DecisionDetector,
    flows: Sequence[Flow],
    examples: Sequence[Flow],
    plan: RoundPlan,
    sink: Sink,
) -> RoundEvaluation:
    """Judge every Flow under the note in force, one call and one row each, and count what came back.

    Each row goes to `sink` right after its call, as `run.judge` appends it, so whatever fails later loses no call already paid for.
    The round is cut short when the detector fails DETECTOR_FAILURE_LIMIT calls in a row, or every call of a split shorter than that.

    Args:
        detector: the detector, with the instructions of the round already set.
        flows: the Flows of the split, judged in order.
        examples: the labeled Examples, the same in every round.
        plan: the note in force, where it goes and the fields every row shares.
        sink: what receives each complete row.

    Returns:
        The counts of the round, over the rows judged before any stop.
    """
    rows: list[Prediction] = []
    failures = 0
    limit = min(DETECTOR_FAILURE_LIMIT, len(flows))
    for flow in flows:
        judged = apply_note(flow, plan.note, plan.service_index, plan.max_note_length)
        cell = {**plan.fields, "note": plan.note if flow.is_attack else ""}
        row = records.complete_prediction(detector.predict(judged, examples), judged, cell)
        sink(row)
        rows.append(row)
        failures = 0 if answered(row) else failures + 1
        if failures >= limit:
            return summarize_rows(rows, plan.note, stopped=True)
    return summarize_rows(rows, plan.note)


def answered(row: Prediction) -> bool:
    """Whether the call gave a Verdict; a failed call leaves `classification_verdict` at None."""
    return row.get("classification_verdict") is not None


def _alerts_and_errors(rows: Sequence[Prediction]) -> tuple[int, int]:
    """The answered rows that raised an alert, and the rows whose call failed."""
    alerts = sum(1 for row in rows if row.get("classification_verdict"))
    return alerts, sum(1 for row in rows if not answered(row))


def _f1(rows: Sequence[Prediction]) -> float:
    """Attack-class F1 over the answered rows, as `metrics.scores` defines it; 0.0 when it is undefined."""
    return float(metrics.scores([row for row in rows if answered(row)])["f1"] or 0.0)


def _attack_verdicts(rows: Sequence[Prediction]) -> dict[int, bool]:
    """Whether each answered attack Flow raised an alert, keyed by its position, which is the same in every round."""
    return {position: bool(row["classification_verdict"]) for position, row in enumerate(rows) if row["is_attack"] and answered(row)}


def summarize_rows(rows: Sequence[Prediction], note: str, stopped: bool = False) -> RoundEvaluation:
    """The counts of one round read off its rows, with F1 and the false-alarm rate over the answered rows only."""
    attacks = [row for row in rows if row["is_attack"]]
    benign = [row for row in rows if not row["is_attack"]]
    hits, attack_errors = _alerts_and_errors(attacks)
    false_alarms, benign_errors = _alerts_and_errors(benign)
    counts = RoundCounts(
        attacks_detected=hits,
        attacks_passed=len(attacks) - hits - attack_errors,
        attack_errors=attack_errors,
        false_alarms=false_alarms,
        benign_errors=benign_errors,
        total_attacks=len(attacks),
        total_benign=len(benign),
    )
    return RoundEvaluation(
        counts=counts,
        f1=_f1(rows),
        false_alarm_rate=round(false_alarms / max(len(benign) - benign_errors, 1), 4),
        notes_tested=[note] if note and attacks else [],
        attack_verdicts=_attack_verdicts(rows),
        stopped=stopped,
    )
