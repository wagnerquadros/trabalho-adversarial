"""Offline doubles shared by the adversarial tests: a scripted Agno model, a rule-based detector, their Flows and a loop builder."""

import json
from collections.abc import AsyncIterator, Collection, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agno.models.base import Model
from agno.models.response import ModelResponse

from jev_ids import ROOT
from jev_ids.adversarial import AdversarialSpec, Orchestrator, reinforce_instructions
from jev_ids.agents import AttackerAgent, AttackerDecision, DefenderAgent, DefenderDecision
from jev_ids.dataset import Config, Flow

BASE_INSTRUCTIONS = "Classify NSL-KDD traffic."
REINFORCED_INSTRUCTIONS = reinforce_instructions(BASE_INSTRUCTIONS)
NSL_KDD_CARD = ROOT / "data" / "nsl-kdd" / "dataset.json"

ADV_CONFIG: Config = {
    "name": "nsl-kdd",
    "features": ["duration", "protocol_type", "service", "flag"],
    "symbolic": ["protocol_type", "service", "flag"],
    "categories": ["normal", "dos", "r2l"],
    "benign": "normal",
}
# Naming the services of the three attack Flows by how the detector double treats them.
LOUD = "ftp_data"
SILENT = "imap4"
QUIET = "telnet"
RARE_BENIGN = "uucp_path"


def study_flow(row_id: int, service: str, *, attack: bool) -> Flow:
    """A four-feature Flow of ADV_CONFIG with the given `service`."""
    return Flow(row_id=row_id, attributes_csv=f"0,tcp,{service},SF", category="r2l" if attack else "normal", is_attack=attack)


# Two benign Flows, one of them on a rare service, then a loud attack, one that always passes and a quiet one.
STUDY_FLOWS: tuple[Flow, ...] = (
    study_flow(1, "http", attack=False),
    study_flow(2, RARE_BENIGN, attack=False),
    study_flow(3, LOUD, attack=True),
    study_flow(4, SILENT, attack=True),
    study_flow(5, QUIET, attack=True),
)


class ScriptedAgnoModel(Model):
    """Offline Agno `Model` answering from a script, in order; an `Exception` in the script is raised as a provider would raise it."""

    responses: list[str | Exception]
    seen_prompts: list[str]
    tools_offered: list[int]

    def __init__(self, model_id: str, responses: Sequence[str | Exception]) -> None:
        super().__init__(id=model_id, provider="scripted")
        self.responses = list(responses)
        self.seen_prompts = []
        self.tools_offered = []

    def invoke(self, *args: Any, **kwargs: Any) -> ModelResponse:
        raw_messages: Sequence[Any] = kwargs.get("messages") or (args[0] if args else ())
        self.seen_prompts.append("\n".join(str(getattr(msg, "content", "")) for msg in raw_messages))
        self.tools_offered.append(len(kwargs.get("tools") or ()))
        answer = self.responses.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return ModelResponse(content=answer)

    async def ainvoke(self, *args: Any, **kwargs: Any) -> ModelResponse:
        return self.invoke(*args, **kwargs)

    def invoke_stream(self, *args: Any, **kwargs: Any) -> Iterator[ModelResponse]:
        yield self.invoke(*args, **kwargs)

    async def ainvoke_stream(self, *args: Any, **kwargs: Any) -> AsyncIterator[ModelResponse]:
        yield self.invoke(*args, **kwargs)

    def _parse_provider_response(self, response: Any, **kwargs: Any) -> ModelResponse:
        del kwargs
        return ModelResponse(content=str(response))

    def _parse_provider_response_delta(self, response: Any) -> ModelResponse:
        return ModelResponse(content=str(response))


class MockDecisionDetector:
    """Rule-based `DecisionDetector` standing in for a real one.

    Under the base instructions any note fools it on the loud attack and it misses the quiet one. Under the reinforced instructions it
    catches both and raises a false alarm on the rare benign service. The silent attack always passes. A call for a Flow listed in
    `failing` fails, as a provider outage would make it.
    """

    name = "mock_decision"
    model = "mock-1"
    prompt_hash: str | None = "mockhash"

    def __init__(self, base_instructions: str = BASE_INSTRUCTIONS, failing: Collection[int] = ()) -> None:
        self._instructions = base_instructions
        self.record = "full"
        self.failing = set(failing)
        self.calls = 0

    @property
    def instructions(self) -> str:
        return self._instructions

    def set_instructions(self, instructions: str) -> None:
        self._instructions = instructions

    def predict(self, flow: Flow, examples: Sequence[Flow]) -> dict[str, Any]:
        del examples
        self.calls += 1
        if flow.row_id in self.failing:
            return {"error": "HTTP 503: unavailable", "retries": 4}
        p_attack = self._attack_p(flow) if flow.is_attack else self._benign_p(flow)
        return {"p_attack": p_attack, "category_pred": "r2l" if p_attack >= 0.5 else "normal", "confidence": 0.9}

    @property
    def _reinforced(self) -> bool:
        return "untrusted network data" in self._instructions

    def _benign_p(self, flow: Flow) -> float:
        rare = flow.attributes_csv.split(",")[2] == RARE_BENIGN
        return 0.72 if rare and self._reinforced else 0.05

    def _attack_p(self, flow: Flow) -> float:
        service = flow.attributes_csv.split(",")[2]
        kind = service.split(" ")[0]
        if kind == SILENT:
            return 0.10
        if kind == QUIET:
            return 0.80 if self._reinforced else 0.30
        fooled_by_note = service != kind and not self._reinforced
        return 0.15 if fooled_by_note else 0.88


def attacker_says(action: str, note: str = "", rationale: str = "scripted") -> str:
    """The JSON a model would answer for an attacker decision."""
    return AttackerDecision.model_validate({"action": action, "note": note, "rationale": rationale}).model_dump_json()


def defender_says(action: str, instructions: str = "", label: str = "?", rationale: str = "scripted") -> str:
    """The JSON a model would answer for a defender decision; `label` is whatever the model chose to call it."""
    fields = {"action": action, "instruction_label": label, "instructions": instructions, "rationale": rationale}
    return DefenderDecision.model_validate(fields).model_dump_json()


# Scripting the canonical cycle: the defender reinforces and later relaxes, the attacker removes its note and later rewrites it.
# The labels the defender's model writes are wrong on purpose, because the loop must not read them.
ATTACKER_SCRIPT = [attacker_says("remove"), attacker_says("reformulate", "ticket-4821")]
DEFENDER_SCRIPT = [defender_says("reinforce", label="V9"), defender_says("relax", label="R")]
# Scripting a cycle in which both sides hold twice: in round 2, after the attacker removed its note, and in round 4, after the
# defender reinforced in round 3. A run stops at round 2; resumed past it (`past_stable`), it plays round 3 and stops at round 4.
HOLDING_ATTACKER = [attacker_says("remove"), attacker_says("keep"), attacker_says("keep")]
HOLDING_DEFENDER = [defender_says("keep"), defender_says("keep"), defender_says("reinforce"), defender_says("keep")]


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    """The lines of a JSONL file as dicts; an absent file has none."""
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def make_spec(results_dir: Path, **overrides: Any) -> AdversarialSpec:
    """A spec for the loop tests: five rounds on the mock detector, three attempts, notes of at most 60 characters."""
    fields: dict[str, Any] = {
        "detector": "mock_decision",
        "dataset": NSL_KDD_CARD,
        "split": "smoke",
        "max_rounds": 5,
        "max_attempts": 3,
        "max_note_length": 60,
        "results_dir": results_dir,
    }
    return AdversarialSpec(**(fields | overrides))


@dataclass
class Loop:
    """An orchestrator on doubles, with the two scripted models whose prompts a test may read."""

    orchestrator: Orchestrator
    detector: MockDecisionDetector
    attacker_model: ScriptedAgnoModel
    defender_model: ScriptedAgnoModel

    @property
    def attacker(self) -> AttackerAgent:
        return self.orchestrator.attacker

    @property
    def defender(self) -> DefenderAgent:
        return self.orchestrator.defender


class AgentFactory:
    """Builds agents and loops on scripted models under one folder, and releases their SQLite files when the test ends."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.memory_dir = root / "memory"
        self._opened: list[AttackerAgent | DefenderAgent] = []

    def attacker(self, script: Sequence[str | Exception], memory_dir: Path | None = None, reopen: bool = False) -> AttackerAgent:
        agent = AttackerAgent(ScriptedAgnoModel("scripted-attacker", script), memory_dir or self.memory_dir, reopen=reopen)
        self._opened.append(agent)
        return agent

    def defender(self, script: Sequence[str | Exception], memory_dir: Path | None = None, reopen: bool = False) -> DefenderAgent:
        model = ScriptedAgnoModel("scripted-defender", script)
        agent = DefenderAgent(model, memory_dir or self.memory_dir, BASE_INSTRUCTIONS, REINFORCED_INSTRUCTIONS, reopen=reopen)
        self._opened.append(agent)
        return agent

    def loop(
        self,
        attacker_script: Sequence[str | Exception],
        defender_script: Sequence[str | Exception],
        detector: MockDecisionDetector | None = None,
        reopen: bool = False,
    ) -> Loop:
        attacker, defender = self.attacker(attacker_script, reopen=reopen), self.defender(defender_script, reopen=reopen)
        judge = detector or MockDecisionDetector()
        return Loop(Orchestrator(judge, attacker, defender, ADV_CONFIG), judge, attacker.model, defender.model)

    def restart(self) -> None:
        """Close every agent opened so far, as a process that stopped would, so the next ones open the files afresh."""
        self.close()
        self._opened.clear()

    def close(self) -> None:
        for agent in self._opened:
            agent.memory.close()


def agent_factory(root: Path) -> Iterator[AgentFactory]:
    """The body of a fixture: an `AgentFactory` under `root`, closed when the test ends.

    The fixture itself lives in the test modules that use it and not in a `conftest.py`, which would make every test run of the
    repository import Agno.
    """
    factory = AgentFactory(root)
    yield factory
    factory.close()
