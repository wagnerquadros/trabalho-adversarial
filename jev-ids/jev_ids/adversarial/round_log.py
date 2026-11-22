"""Save and replay local arena tests without calling the detector again."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jev_ids import ROOT
from jev_ids.adversarial.analysis.paired import compare_contexts
from jev_ids.adversarial.analysis.protocol import protocol_report
from jev_ids.adversarial.classification import PAPER_SEEDS, PAPER_SHA256, ArenaConfig, Classification
from jev_ids.adversarial.evaluation.metrics import Outcome, Sample, measure

__all__ = ["new_run_id", "read_run", "record_run", "round_event"]


def new_run_id() -> str:
    """Name one test using its UTC starting time."""
    return datetime.now(UTC).strftime("arena-%Y%m%dT%H%M%S.%fZ")


def _directory(run_id: str, root: Path) -> Path:
    if not re.fullmatch(r"arena-[0-9]{8}T[0-9]{6}\.[0-9]{6}Z", run_id):
        raise ValueError("Identificador de execução inválido.")
    return root / run_id


def round_event(index: int, row: Classification, settings: ArenaConfig) -> dict[str, Any]:
    """Record the exact classification and its experimental context."""
    a, d = ("N" if row.note else "S"), ("R" if row.reinforced else "B")
    return {
        "round": settings.round_number(index),
        "attempt": index,
        "position_in_round": (index - 1) % settings.records_per_round + 1,
        "row_id": row.row_id,
        "model": "qwen3:8b" if settings.detector == "qwen3" else "Laya multilingual",
        "seed": row.seed,
        "example_ids": row.example_ids,
        "split": settings.split,
        "validator": settings.mode,
        "cell": f"{a}/{d}",
        "note": row.note,
        "instruction_sha256": row.prompt_hash,
        "budget_left": settings.budget - index,
        "outcome": row.sample.outcome.value,
        "p_attack": row.probability,
        "prediction": row.category,
        "ground_truth": row.truth,
        "sample": asdict(row.sample),
        "invalid_fields": row.invalid_fields,
        "tokens": row.tokens,
        "latency_ms": row.latency_ms,
        "error": row.error,
        "fields": dict(row.fields),
    }


def _write(path: Path, data: object) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def record_run(run_id: str, rows: Iterator[Classification], settings: ArenaConfig, root: Path = ROOT / "runs") -> Iterator[Classification]:
    """Flush a round before publishing it and save the final evaluation."""
    directory = _directory(run_id, root)
    directory.mkdir(parents=True)
    _write(
        directory / "manifest.json",
        {
            "dataset": "NSL-KDD",
            "split": settings.split,
            "seeds": PAPER_SEEDS if settings.split == "paper" else [settings.seed],
            **({"split_sha256": PAPER_SHA256} if settings.split == "paper" else {}),
            "k": 1,
            "threshold": 0.5,
            "settings": asdict(settings),
            "design": "paired-cohorts-v2",
        },
    )
    recorded: list[Classification] = []

    def finish(error: str | None) -> None:
        _write(
            directory / "summary.json",
            {
                **measure(r.sample for r in recorded),
                "unique_records": len({r.row_id for r in recorded}),
                "rounds_started": settings.round_number(len(recorded)),
                "rounds_completed": len(recorded) // settings.records_per_round,
                "context_comparisons": compare_contexts(recorded),
                "protocol": protocol_report(recorded, settings),
                "error": error,
            },
        )

    log = directory / "rounds.jsonl"
    log.touch(exist_ok=False)
    try:
        for i, row in enumerate(rows, 1):
            with log.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(round_event(i, row, settings), ensure_ascii=False) + "\n")
            recorded.append(row)
            if i == settings.attempts:
                finish(None)
            yield row
    except Exception as exc:
        finish(str(exc))
        raise


def read_run(run_id: str, root: Path = ROOT / "runs") -> tuple[ArenaConfig, tuple[Classification, ...], str | None]:
    """Read a finalized arena log strictly inside the local runs directory."""
    directory = _directory(run_id, root)
    saved = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))["settings"]
    saved.setdefault("records_per_round", 1)  # Original arena logs contain one record per round.
    settings = ArenaConfig(**saved)
    summary = json.loads((directory / "summary.json").read_text(encoding="utf-8"))
    rows: list[Classification] = []
    with (directory / "rounds.jsonl").open(encoding="utf-8") as handle:
        for line in handle:
            e = json.loads(line)
            sample = e["sample"]
            rows.append(
                Classification(
                    e["row_id"],
                    tuple(e["fields"].items()),
                    e["ground_truth"],
                    Sample(Outcome(e["outcome"]), sample["is_attack"], sample["is_novel"], sample["is_invalid"]),
                    e["p_attack"],
                    e["prediction"],
                    e["latency_ms"],
                    e["tokens"],
                    e["error"],
                    e["note"],
                    e["cell"].endswith("/R"),
                    e["instruction_sha256"],
                    tuple(e["invalid_fields"]),
                    e.get("seed", settings.seed),
                    tuple(e.get("example_ids", ())),
                )
            )
    if len(rows) != summary["records"]:
        raise ValueError("O log e o resumo têm contagens diferentes.")
    return settings, tuple(rows), summary["error"]
