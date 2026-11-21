"""Immutable presentation data for one observed round."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Literal


class Verdict(StrEnum):
    """Visible outcome of a detector decision."""

    QUIET = "SEM ALERTA"
    ALERT = "ALERTA"


class Actor(StrEnum):
    """Participant credited in the message log."""

    ATTACKER = "Atacante"
    DEFENDER = "Defensor"
    DETECTOR = "Detector"
    ORCHESTRATOR = "Orquestrador"


@dataclass(frozen=True, slots=True)
class RoundCell:
    """Actions played in a round."""

    attacker_action: Literal["N", "S"]
    defender_action: Literal["B", "R"]


@dataclass(frozen=True, slots=True)
class Metric:
    """Display value and optional comparison for a metric tile."""

    label: str
    value: str
    delta: str = ""


@dataclass(frozen=True, slots=True)
class InstructionVersion:
    """One instruction revision shown to the defender."""

    title: str
    status: str
    quotation: str = ""


@dataclass(frozen=True, slots=True)
class Message:
    """One attributed observation in the log."""

    round_index: int
    actor: Actor
    text: str


@dataclass(frozen=True, slots=True)
class Payoff:
    """Visit count and ordinal utilities for an action pair."""

    cell: RoundCell
    visits: int
    utilities: tuple[int, int]


@dataclass(frozen=True, slots=True)
class RoundSnapshot:
    """Everything the interface can display, independent of its data source."""

    round_index: int
    total_rounds: int
    cells: tuple[RoundCell, ...]
    attempts: tuple[Verdict | None, ...]
    budget_left: int
    budget_total: int
    detector: str
    record_fields: tuple[tuple[str, str], ...]
    attribute_count: int
    note_suffix: str
    intention: str
    validator_mode: str
    validator_status: str
    validator_note: str
    p_attack: float
    threshold: float
    verdict: Verdict
    ground_truth: str
    outcome: str
    instructions: tuple[InstructionVersion, ...]
    aggregates: tuple[Metric, ...]
    adaptation: str
    payoffs: tuple[Payoff, ...]
    metrics: tuple[Metric, ...]
    evasion_rates: tuple[int, ...]
    false_alarm_rates: tuple[int, ...]
    messages: tuple[Message, ...]
    context_changes: tuple[tuple[str, str], ...]
    timeline_caption: str

    @property
    def current_cell(self) -> RoundCell:
        """Return the action pair highlighted in the timeline and matrix."""
        return self.cells[self.round_index - 1]
