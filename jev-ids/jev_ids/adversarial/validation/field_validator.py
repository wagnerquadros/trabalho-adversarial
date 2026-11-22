"""Apply exact vocabulary checks before a detector call."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

from jev_ids.dataset import Config, Flow, load_split
from jev_ids.detectors.random_forest import vocabulary

from ..evaluation.metrics import Outcome, classify

__all__ = ["FieldValidator", "ValidatedResult"]

_FIELDS = ("protocol_type", "service", "flag")


@dataclass(frozen=True, slots=True)
class ValidatedResult:
    """Validation issues, detector outcome and measured response."""

    invalid_fields: tuple[str, ...]
    outcome: Outcome
    reason: str | None
    response: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class FieldValidator:
    """Immutable membership information derived from the training pool."""

    fields: tuple[tuple[int, str, tuple[str, ...]], ...]
    width: int

    @classmethod
    def from_training_pool(cls, config: Config, pool: Sequence[Flow] | None = None) -> FieldValidator:
        """Read only pool.csv, deriving the exact sets using the baseline encoder."""
        if config["name"] != "nsl-kdd":
            raise ValueError("Este validador requer o cartão NSL-KDD.")
        if pool is None:
            pool = load_split(config["dir"] / "pool.csv", config)
        known = vocabulary(pool, config)
        fields = tuple((config["features"].index(name), name) for name in _FIELDS)
        return cls(tuple((index, name, known[index]) for index, name in fields), len(config["features"]))

    def manifest(self) -> dict[str, Any]:
        """Return the exact membership lists and the digest of their canonical JSON."""
        labels = {name: values for _, name, values in self.fields}
        encoded = json.dumps(labels, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        return {"vocabulary": labels, "sha256": hashlib.sha256(encoded).hexdigest()}

    def evaluate(
        self, flow: Flow, predict: Callable[[Flow], Mapping[str, Any]], mode: Literal["observe", "block"] = "observe"
    ) -> ValidatedResult:
        """Observe invalid records or block before calling the supplied detector."""
        if mode not in ("observe", "block"):
            raise ValueError("Modo de validação desconhecido.")
        values = flow.attribute_values
        invalid = tuple(name for index, name, allowed in self.fields if index >= len(values) or values[index] not in allowed)
        if len(values) != self.width:
            invalid += ("attribute_count",)
        if invalid and mode == "block":
            return ValidatedResult(invalid, Outcome.BLOCKED, None, {})
        response = predict(flow)
        outcome, reason = classify(response.get("p_attack"), response.get("error"))
        return ValidatedResult(invalid, outcome, reason, response)
