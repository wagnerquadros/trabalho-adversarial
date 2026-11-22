"""Descriptive within-record contrasts for the four fixed arena contexts."""

from __future__ import annotations

from collections.abc import Sequence
from statistics import mean
from typing import TypedDict

from jev_ids.adversarial.classification import Classification
from jev_ids.adversarial.evaluation.metrics import Outcome

__all__ = ["Contrast", "compare_contexts"]


class Contrast(TypedDict):
    """Paired detector measurements for one controlled context change."""

    before: str
    after: str
    matched: int
    valid: int
    gained_alert: int
    lost_alert: int
    changed_category: int
    changed_score: int
    mean_score_delta: float | None
    token_pairs: int
    mean_token_delta: float | None
    latency_pairs: int
    mean_latency_delta_ms: float | None


def compare_contexts(rows: Sequence[Classification]) -> list[Contrast]:
    """Pair within each example seed and flow, holding one factor constant."""
    arms: dict[str, dict[tuple[int, int], Classification]] = {k: {} for k in ("N/B", "S/B", "N/R", "S/R")}
    for row in rows:
        key = ("N" if row.note else "S") + ("/R" if row.reinforced else "/B")
        arms[key][row.seed, row.row_id] = row
    contrasts: list[Contrast] = []
    for before, after in (("S/B", "N/B"), ("S/R", "N/R"), ("S/B", "S/R"), ("N/B", "N/R")):
        ids = arms[before].keys() & arms[after].keys()
        pairs = [(arms[before][i], arms[after][i]) for i in sorted(ids)]
        valid = [(a, b) for a, b in pairs if a.probability is not None and b.probability is not None]
        deltas = [b.probability - a.probability for a, b in valid if a.probability is not None and b.probability is not None]
        tokens = [b.tokens - a.tokens for a, b in pairs if a.tokens is not None and b.tokens is not None]
        times = [b.latency_ms - a.latency_ms for a, b in pairs if a.latency_ms is not None and b.latency_ms is not None]
        contrasts.append(
            Contrast(
                before=before,
                after=after,
                matched=len(ids),
                valid=len(valid),
                gained_alert=sum(a.sample.outcome == Outcome.QUIET and b.sample.outcome == Outcome.ALERT for a, b in valid),
                lost_alert=sum(a.sample.outcome == Outcome.ALERT and b.sample.outcome == Outcome.QUIET for a, b in valid),
                changed_category=sum(a.category != b.category for a, b in valid),
                changed_score=sum(d != 0 for d in deltas),
                mean_score_delta=mean(deltas) if deltas else None,
                token_pairs=len(tokens),
                mean_token_delta=mean(tokens) if tokens else None,
                latency_pairs=len(times),
                mean_latency_delta_ms=mean(times) if times else None,
            )
        )
    return contrasts
