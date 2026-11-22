"""Per-seed attack-class F1 and sample deviation for the Arena protocol."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import replace
from statistics import fmean, stdev
from typing import Any

from jev_ids.adversarial.classification import PAPER_FLOWS, PAPER_SEEDS, ArenaConfig, Classification
from jev_ids.adversarial.evaluation.metrics import Outcome, measure


def protocol_report(rows: Sequence[Classification], settings: ArenaConfig) -> dict[str, list[dict[str, Any]]]:
    """Keep the denominators, measurement coverage and policies visible in the archive and UI."""
    groups: dict[tuple[str, int], list[Classification]] = defaultdict(list)
    for row in rows:
        cell = ("N" if row.note else "S") + ("/R" if row.reinforced else "/B")
        groups[cell, row.seed].append(row)
    details: list[dict[str, Any]] = []
    final: list[dict[str, Any]] = []
    for (cell, seed), group in sorted(groups.items()):
        samples = [r.sample for r in group]
        arena = measure(samples)
        paper = measure(replace(s, outcome=Outcome.QUIET) if s.outcome == Outcome.FAILURE else s for s in samples)
        tokens = [r.tokens for r in group if r.tokens is not None]
        times = [r.latency_ms for r in group if r.latency_ms is not None]
        details.append(
            {
                "cell": cell,
                "seed": seed,
                "records": len(group),
                "valid": arena["valid_verdicts"],
                "failures": arena["failures"],
                "blocked": arena["invalid_blocked"],
                "arena_f1": arena["f1"],
                "fail_open_f1": paper["f1"],
                "arena_recall": arena["recall"],
                "fail_open_recall": paper["recall"],
                "arena_novel_recall": arena["zero_day_recall"],
                "fail_open_novel_recall": paper["zero_day_recall"],
                "false_alarms": arena["false_alarms"],
                "false_alarm_rate": arena["false_alarm_rate"],
                "tokens_mean": fmean(tokens) if tokens else None,
                "token_measurements": len(tokens),
                "latency_mean_ms": fmean(times) if times else None,
                "latency_measurements": len(times),
            }
        )
    if settings.split == "paper":
        for cell in sorted({d["cell"] for d in details}):
            complete = [d for d in details if d["cell"] == cell and d["records"] == PAPER_FLOWS]
            if {d["seed"] for d in complete} == set(PAPER_SEEDS):
                for policy in ("arena_f1", "fail_open_f1"):
                    scores = [d[policy] for d in complete if d[policy] is not None]
                    final.append(
                        {
                            "cell": cell,
                            "policy": policy,
                            "defined_seeds": len(scores),
                            "f1_mean": fmean(scores) if scores else None,
                            "f1_sd": stdev(scores) if len(scores) > 1 else None,
                        }
                    )
    return {"by_seed": details, "across_seeds": final}
