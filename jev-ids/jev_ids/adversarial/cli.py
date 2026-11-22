"""Probe one detector on unmodified development records."""

from __future__ import annotations

import argparse
import json
import random
import time
from collections.abc import Sequence
from typing import Any, Protocol

import httpx
from dotenv import load_dotenv
from ollama import Client

from jev_ids import ROOT
from jev_ids.adversarial.evaluation.metrics import Outcome
from jev_ids.adversarial.validation import FieldValidator
from jev_ids.dataset import Flow, load_config, load_split
from jev_ids.detectors.laya import LayaDetector
from jev_ids.detectors.llm import LLMDetector
from jev_ids.run import load_prompt, sample_examples

__all__ = ["Detector", "build_detector", "probe", "verify_request", "verify_response"]


class Detector(Protocol):
    """Detector port shared by the two local adapters."""

    def predict(self, flow: Flow, examples: Sequence[Flow]) -> dict[str, Any]:
        """Measure one record."""
        ...


def verify_request(request: httpx.Request) -> None:
    """Require explicit thinking control in the serialized request."""
    if json.loads(request.content).get("think") is not False:
        raise ValueError("Ollama não recebeu think=false.")


def verify_response(response: httpx.Response) -> None:
    """Reject reasoning returned by the server."""
    if response.is_success:
        response.read()
        message = response.json()["message"]
        if message.get("thinking") or "<think>" in (message.get("content") or ""):
            raise ValueError("Ollama retornou conteúdo de raciocínio.")


def build_detector(name: str, categories: Sequence[str], *, prompt: dict[str, Any] | None = None) -> Detector:
    """Build one local evaluation adapter with the selected prompt."""
    directory = ROOT / "prompts/nsl-kdd"
    if name == "laya":
        return LayaDetector(prompt or load_prompt(directory / "jev.json"))
    if name != "qwen3":
        raise ValueError(f"Detector desconhecido: {name}")
    detector = LLMDetector(prompt or load_prompt(directory / "llm.md"), "ollama", "qwen3:8b", categories=categories)
    model = detector.agno_model
    model.request_params = {"think": False}
    model.client = Client(host=model.host, timeout=model.timeout, event_hooks={"request": [verify_request], "response": [verify_response]})
    return detector


def probe() -> int:
    """Report one measured result per original class of traffic."""
    parser = argparse.ArgumentParser(description="Verificar o detector no NSL-KDD")
    parser.add_argument("--detector", choices=("qwen3", "laya"), required=True)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--validator", choices=("observe", "block"), default="observe")
    args = parser.parse_args()
    load_dotenv(ROOT / ".env")
    config = load_config(ROOT / "data/nsl-kdd/dataset.json")
    examples = sample_examples(load_split(config["dir"] / "pool.csv", config), 1, args.seed, config["categories"])
    pilot = load_split(config["dir"] / "splits/pilot.csv", config)
    detector = build_detector(args.detector, config["categories"])
    validator = FieldValidator.from_training_pool(config)
    print(json.dumps({"seed": args.seed, "mode": args.validator, **validator.manifest()}), flush=True)

    def predict(flow: Flow) -> dict[str, Any]:
        return detector.predict(flow, examples)

    rng = random.Random(args.seed)  # noqa: S311 -- reproducible sampling
    failures = 0
    for is_attack in (False, True):
        flow = rng.choice([item for item in pilot if item.is_attack == is_attack])
        started = time.perf_counter()
        decision = validator.evaluate(flow, predict, args.validator)
        result = decision.response
        score = result.get("p_attack")
        error = decision.reason
        if decision.outcome != Outcome.BLOCKED and result.get("category_pred") not in config["categories"]:
            error = error or "Resposta sem probabilidade ou categoria válida."
        failures += int(bool(error))
        print(
            json.dumps(
                {
                    "detector": args.detector,
                    "row_id": flow.row_id,
                    "p_attack": score,
                    "category": result.get("category_pred"),
                    "usage": result.get("usage"),
                    "outcome": Outcome.FAILURE if error else decision.outcome,
                    "invalid_fields": decision.invalid_fields,
                    "error": error,
                    "latency_ms": round((time.perf_counter() - started) * 1000, 2),
                    "thinking_disabled_verified": True if args.detector == "qwen3" and result and not error else None,
                },
                ensure_ascii=False,
            ),
            flush=True,
        )
    print(f"Registros: 2. Falhas: {failures}.")
    if failures:
        print("Confira o servidor local, o modelo instalado e o formato da resposta.")
    return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(probe())
