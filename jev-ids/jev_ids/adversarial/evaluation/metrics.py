"""Binary classification metrics with explicit failure and validation counts."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

from jev_ids.records import VERDICT_THRESHOLD

__all__ = ["Outcome", "Sample", "classify", "measure"]


class Outcome(StrEnum):
    """Result of a detector call or a validation block."""

    ALERT = "alert"
    QUIET = "no_alert"
    FAILURE = "failure"
    BLOCKED = "invalid_blocked"


@dataclass(frozen=True, slots=True)
class Sample:
    """Evaluator-only join of the decision, validation flag and ground truth."""

    outcome: Outcome
    is_attack: bool
    is_novel: bool = False
    is_invalid: bool = False


def classify(score: object, error: str | None = None) -> tuple[Outcome, str | None]:
    """Apply the shared threshold only to finite probabilities."""
    if error:
        return Outcome.FAILURE, error
    if isinstance(score, bool) or not isinstance(score, (int, float)) or not 0 <= score <= 1:
        return Outcome.FAILURE, "Probabilidade ausente ou inválida."
    return (Outcome.ALERT if score >= VERDICT_THRESHOLD else Outcome.QUIET), None


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def measure(samples: Iterable[Sample]) -> dict[str, float | int | None]:
    """Compute rates and expose denominator counts for auditing partial coverage."""
    rows = tuple(samples)
    valid = [row for row in rows if row.outcome in (Outcome.ALERT, Outcome.QUIET)]
    tp = sum(row.is_attack and row.outcome == Outcome.ALERT for row in valid)
    fn = sum(row.is_attack and row.outcome == Outcome.QUIET for row in valid)
    fp = sum(not row.is_attack and row.outcome == Outcome.ALERT for row in valid)
    legitimate = sum(not row.is_attack for row in rows)
    novel = [row for row in valid if row.is_attack and row.is_novel]
    return {
        "records": len(rows),
        "valid_verdicts": len(valid),
        "legitimate": legitimate,
        "true_positives": tp,
        "misses": fn,
        "false_alarms": fp,
        "failures": sum(row.outcome == Outcome.FAILURE for row in rows),
        "invalid": sum(row.is_invalid or row.outcome == Outcome.BLOCKED for row in rows),
        "invalid_blocked": sum(row.outcome == Outcome.BLOCKED for row in rows),
        "f1": _ratio(2 * tp, 2 * tp + fp + fn),
        "recall": _ratio(tp, tp + fn),
        "miss_rate": _ratio(fn, tp + fn),
        "false_alarm_rate": _ratio(fp, legitimate),
        "zero_day_recall": _ratio(sum(row.outcome == Outcome.ALERT for row in novel), len(novel)),
    }
