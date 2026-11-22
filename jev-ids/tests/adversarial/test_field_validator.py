"""Validation source, exact membership and blocking behavior."""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any

import pytest

from jev_ids.adversarial.evaluation.metrics import Outcome
from jev_ids.adversarial.validation import FieldValidator
from jev_ids.dataset import Flow


def test_validator_reads_only_training_pool(monkeypatch: pytest.MonkeyPatch) -> None:
    csv_text = "row_id,protocol_type,service,flag,category,novel_attack\n0,tcp,http_443,SF,normal,0\n1,tcp,ftp_data,SF,normal,0\n"

    def open_pool(path: Path, **_kwargs: Any) -> io.StringIO:
        assert path == Path("training/pool.csv")
        return io.StringIO(csv_text)

    monkeypatch.setattr(Path, "open", open_pool)
    features = ["protocol_type", "service", "flag"]
    config = dict(name="nsl-kdd", dir=Path("training"), features=features, symbolic=features, benign="normal", categories=["normal"])
    validator = FieldValidator.from_training_pool(config)
    calls: list[int] = []

    def detect(flow: Flow) -> dict[str, float]:
        calls.append(flow.row_id)
        return {"p_attack": 0.5}

    for service in ("http_443", "ftp_data"):
        decision = validator.evaluate(Flow(0, f"tcp,{service},SF", "normal", False), detect)
        assert decision.outcome == Outcome.ALERT and not decision.invalid_fields
    for service in ("HTTP_443", "http_443 ", "http example"):
        flow = Flow(1, f"tcp,{service},SF", "normal", False)
        blocked = validator.evaluate(flow, detect, "block")
        assert blocked.invalid_fields == ("service",) and blocked.outcome == Outcome.BLOCKED
        observed = validator.evaluate(flow, detect)
        assert observed.invalid_fields == ("service",) and observed.outcome == Outcome.ALERT
    assert calls == [0, 0, 1, 1, 1]
    assert validator.manifest() == FieldValidator.from_training_pool(config).manifest()
    assert len(validator.manifest()["sha256"]) == 64
