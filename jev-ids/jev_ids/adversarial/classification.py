"""Evaluate fixed Arena contexts on pilot or paper NSL-KDD records."""

from __future__ import annotations

import hashlib
import random
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, replace
from typing import Any, Literal

from dotenv import load_dotenv

from jev_ids import ROOT
from jev_ids.adversarial.analysis.hypotheses import reinforced_prompt
from jev_ids.adversarial.cli import Detector, build_detector
from jev_ids.adversarial.evaluation.metrics import Outcome, Sample
from jev_ids.adversarial.validation import FieldValidator
from jev_ids.dataset import Config, Flow, load_config, load_split
from jev_ids.run import load_prompt, sample_examples

__all__ = ["ArenaConfig", "Classification", "arena_records", "classify_records"]

_NOTE = " [NSL-KDD]"
_ARMS = ((True, False), (True, True), (False, True), (False, False))
PAPER_SEEDS = (0, 1, 2)
PAPER_FLOWS = 2000
PAPER_ATTEMPTS = PAPER_FLOWS * len(PAPER_SEEDS) * len(_ARMS)
# Recorded in results/paper/*/config.json.
PAPER_SHA256 = "b035cb330df3e0dd5f732699e27e9ddb250c8f3f36b6c5f168528e05d41bf2e7"


@dataclass(frozen=True, slots=True)
class ArenaConfig:
    """Settings held constant for one local Arena experiment."""

    seed: int = 0
    rounds: int = 8
    budget: int = 64
    mode: Literal["observe", "block"] = "observe"
    detector: Literal["qwen3", "laya"] = "qwen3"

    records_per_round: int = 8
    split: Literal["pilot", "paper"] = "pilot"

    @classmethod
    def paper(cls, detector: Literal["qwen3", "laya"], mode: Literal["observe", "block"], size: int) -> ArenaConfig:
        """Divide each fixed seed and context into equal manual steps."""
        if size < 1 or PAPER_FLOWS % size:
            raise ValueError("O tamanho da rodada deve dividir os 2.000 fluxos.")
        return cls(0, PAPER_ATTEMPTS // size, PAPER_ATTEMPTS, mode, detector, size, "paper")

    @property
    def attempts(self) -> int:
        """Return the number of submissions permitted by the plan and budget."""
        return min(self.rounds * self.records_per_round, self.budget)

    def round_number(self, attempts: int) -> int:
        """Map the count of submitted records to a one-based round (zero when idle)."""
        return (attempts + self.records_per_round - 1) // self.records_per_round

    def __post_init__(self) -> None:
        """Reject unsupported experiment settings."""
        if (
            min(self.rounds, self.budget, self.records_per_round) < 1
            or self.mode not in ("observe", "block")
            or self.detector not in ("qwen3", "laya")
            or self.split not in ("paper", "pilot")
        ):
            raise ValueError("Configuração da Arena inválida.")
        if self.split == "paper" and (
            self.seed != 0
            or PAPER_FLOWS % self.records_per_round
            or self.budget != PAPER_ATTEMPTS
            or self.rounds * self.records_per_round != PAPER_ATTEMPTS
        ):
            raise ValueError("A avaliação final requer o plano paper completo.")


@dataclass(frozen=True, slots=True)
class Classification:
    """One measured record, joined to its label for display after inference."""

    row_id: int
    fields: tuple[tuple[str, str], ...]
    truth: str
    sample: Sample
    probability: float | None
    category: str | None
    latency_ms: float | None
    tokens: int | None
    error: str | None
    note: str = ""
    reinforced: bool = False
    prompt_hash: str = ""
    invalid_fields: tuple[str, ...] = ()
    seed: int = 0
    example_ids: tuple[int, ...] = ()


def classify_records(seed: int, count: int, mode: Literal["observe", "block"]) -> Iterator[Classification]:
    """Reuse one detector, prompt, validator and fixed examples throughout a batch."""
    yield from _records(ArenaConfig(seed, count, count, mode, records_per_round=1), paired=False)


def arena_records(settings: ArenaConfig) -> Iterator[Classification]:
    """Apply the four predefined conditions to matched flows within each seed."""
    yield from _records(settings, paired=True)


def _cohorts(pilot: list[Flow], settings: ArenaConfig, group: int) -> list[list[Flow]]:
    size = settings.records_per_round
    blocks = (settings.round_number(settings.attempts) + group - 1) // group
    rng = random.Random(settings.seed)  # noqa: S311 -- reproducible experiment
    if size == 1:
        return [[flow] for flow in rng.sample(pilot, blocks)]
    attacks = iter(rng.sample([r for r in pilot if r.is_attack], blocks * (size // 2)))
    normal = iter(rng.sample([r for r in pilot if not r.is_attack], blocks * (size - size // 2)))
    batches: list[list[Flow]] = []
    for _ in range(blocks):
        batch = [next(attacks) for _ in range(size // 2)] + [next(normal) for _ in range(size - size // 2)]
        rng.shuffle(batch)
        batches.append(batch)
    return batches


def _schedule(config: Config, settings: ArenaConfig, paired: bool) -> Iterator[tuple[int, Flow, bool, bool]]:
    pilot = load_split(config["dir"] / "splits/pilot.csv", config)
    if settings.split == "paper":
        path = config["dir"] / "splits/paper.csv"
        if hashlib.sha256(path.read_bytes()).hexdigest() != PAPER_SHA256:
            raise ValueError("O SHA-256 de paper.csv difere do split do artigo.")
        flows = load_split(path, config)
        ids = {flow.row_id for flow in flows}
        if len(flows) != PAPER_FLOWS or len(ids) != PAPER_FLOWS or ids.intersection(r.row_id for r in pilot):
            raise ValueError("O split paper deve ter 2.000 fluxos distintos e separados do piloto.")
        for seed in PAPER_SEEDS:
            for start in range(0, len(flows), settings.records_per_round):
                for noted, reinforced in _ARMS:
                    for flow in flows[start : start + settings.records_per_round]:
                        yield seed, flow, noted, reinforced
        return
    arms = _ARMS if paired else ((False, False),)
    cohorts = _cohorts(pilot, settings, len(arms))
    for index in range(settings.attempts):
        round_offset, position = divmod(index, settings.records_per_round)
        noted, reinforced = arms[round_offset % len(arms)]
        yield settings.seed, cohorts[round_offset // len(arms)][position], noted, reinforced


def _predict(detector: Detector, flow: Flow, examples: Sequence[Flow]) -> dict[str, Any]:
    try:
        return detector.predict(flow, examples)
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}


def _records(settings: ArenaConfig, *, paired: bool) -> Iterator[Classification]:
    load_dotenv(ROOT / ".env")
    config = load_config(ROOT / "data/nsl-kdd/dataset.json")
    categories = config["categories"]
    pool = load_split(config["dir"] / "pool.csv", config)
    seeds = PAPER_SEEDS if settings.split == "paper" else (settings.seed,)
    examples = {seed: sample_examples(pool, 1, seed, categories) for seed in seeds}
    example_ids = {seed: tuple(flow.row_id for flow in refs) for seed, refs in examples.items()}
    validator = FieldValidator.from_training_pool(config, pool)
    del pool
    filename = "jev.json" if settings.detector == "laya" else "llm.md"
    basic = load_prompt(ROOT / "prompts/nsl-kdd" / filename)
    prompts = {False: basic, True: reinforced_prompt(basic, settings.detector)} if paired else {False: basic}
    detectors = {key: build_detector(settings.detector, categories, prompt=value) for key, value in prompts.items()}
    for seed, original, noted, reinforced in _schedule(config, settings, paired):
        flow = original
        note = _NOTE if noted else ""
        if note:
            fields = list(flow.attribute_values)
            fields[config["features"].index("service")] += note
            flow = replace(flow, attributes_csv=",".join(fields))
        detector = detectors[reinforced]
        result = validator.evaluate(flow, lambda item, model=detector, refs=examples[seed]: _predict(model, item, refs), settings.mode)
        response = result.response
        outcome, error = result.outcome, result.reason
        category = response.get("category_pred")
        if outcome in (Outcome.ALERT, Outcome.QUIET) and category not in categories:
            outcome, error = Outcome.FAILURE, "Categoria ausente ou inválida."
        valid = outcome in (Outcome.ALERT, Outcome.QUIET)
        usage: dict[str, Any] = response.get("usage") or {}
        yield Classification(
            flow.row_id,
            tuple(zip(config["features"], flow.attribute_values, strict=True)),
            flow.category,
            Sample(outcome, flow.is_attack, flow.novel_attack, bool(result.invalid_fields)),
            response.get("p_attack") if valid else None,
            category if valid else None,
            response.get("latency_ms"),
            usage.get("total_tokens"),
            error,
            note,
            reinforced,
            prompts[reinforced]["sha256"],
            result.invalid_fields,
            seed,
            example_ids[seed],
        )
