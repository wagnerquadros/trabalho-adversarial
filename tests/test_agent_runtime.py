"""The Agno runtime of a participant: the model of a provider, the question before round 1, failures and the SQLite memory."""

import json
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import httpx2
import pytest
from agno.models.anthropic import Claude
from agno.models.openai.like import OpenAILike
from agno.run.base import RunStatus

from jev_ids import agent_runtime
from jev_ids.agent_runtime import (
    AGENT_TIMEOUT,
    HYDROGEN_KEY_VARS,
    OPENAI_LIKE_PROVIDERS,
    QWEN_DEFAULT_BASE_URL,
    AgentBundle,
    AgentMemory,
    AgentUnavailableError,
    check_agent_model,
    make_agent_model,
)
from jev_ids.agents import AttackerDecision, RetiredNote
from jev_ids.rate_limit import PATIENT_WAITS
from tests.adversarial_helpers import ScriptedAgnoModel, attacker_says
from tests.helpers import FakeClock, fake_spaced_transport, sse


def open_memory(memory_dir: Path, model: ScriptedAgnoModel) -> AgentMemory:
    """A participant's memory on `memory_dir`, as the attacker opens it."""
    return AgentMemory(AgentBundle("attacker", model, "Answer in JSON.", AttackerDecision, {}, memory_dir))


class StubAgent:
    """An Agno agent reduced to `run`: it answers with a fixed content, or raises as code outside the model call would."""

    def __init__(self, outcome: Any) -> None:
        self.outcome = outcome

    def run(self, _prompt: str, **_options: Any) -> Any:
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return SimpleNamespace(status=RunStatus.completed, content=self.outcome)


def test_claude_is_built_without_sampling_parameters(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    model = make_agent_model("claude")
    request_params: dict[str, Any] = model.get_request_params()
    assert isinstance(model, Claude)
    assert model.id == "claude-sonnet-5-5"
    # The Messages API version the SDK sends rejects `temperature`, so it must not reach the request at all.
    assert model.temperature is None
    assert {"temperature", "top_p", "top_k"}.isdisjoint(request_params)
    assert make_agent_model("anthropic", "claude-other").id == "claude-other"


def test_hydrogen_takes_its_key_from_the_environment_in_order(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in HYDROGEN_KEY_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("GEMINI_API_KEY", "test-g-key")
    assert make_agent_model("hydrogen").api_key == "test-g-key"
    monkeypatch.setenv("HYDROGEN_API_KEY", "test-h-key")
    model = make_agent_model("hydrogen")
    assert isinstance(model, OpenAILike)
    assert (model.id, model.api_key) == ("gemini-4-hydrogen", "test-h-key")


def test_each_openai_like_provider_has_its_own_key_and_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    # Every provider reached through the OpenAI chat API answers to its own variables, so one of them never borrows another's key.
    for endpoint in OPENAI_LIKE_PROVIDERS.values():
        for name in (*endpoint.key_vars, endpoint.base_url_var):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("QWEN_API_KEY", "test-q-key")
    model = make_agent_model("qwen")
    assert isinstance(model, OpenAILike)
    assert (model.id, model.api_key, model.base_url) == ("Qwen3.8-27B", "test-q-key", QWEN_DEFAULT_BASE_URL)
    assert make_agent_model("qwen", "Other-7B").id == "Other-7B"
    monkeypatch.setenv("QWEN_BASE_URL", "https://elsewhere.example/v1")
    assert make_agent_model("qwen").base_url == "https://elsewhere.example/v1"
    # The hydrogen agent has no key of its own now, and says so instead of taking the one next to it.
    with pytest.raises(RuntimeError, match="the hydrogen agent needs an API key"):
        make_agent_model("hydrogen")


def test_hydrogen_without_a_key_names_the_variables_instead_of_sending_a_placeholder(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in HYDROGEN_KEY_VARS:
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(RuntimeError, match="HYDROGEN_API_KEY, GEMINI_API_KEY, GOOGLE_API_KEY"):
        make_agent_model("hydrogen")
    with pytest.raises(ValueError, match="unsupported agent provider"):
        make_agent_model("unknown_vendor")


def test_check_agent_model_asks_one_question_and_reports_a_failing_model() -> None:
    healthy = ScriptedAgnoModel("scripted", ["OK", "not a decision", "unused"])
    check_agent_model(healthy, "attacker")
    # Asked with the schema, only a failed call counts: an answer that is no decision still passes.
    check_agent_model(healthy, "attacker", AttackerDecision)
    assert healthy.responses == ["unused"]
    broken = ScriptedAgnoModel("scripted", [RuntimeError("401 invalid x-api-key")])
    with pytest.raises(AgentUnavailableError, match="defender: .*401 invalid x-api-key") as failure:
        check_agent_model(broken, "defender")
    assert failure.value.role == "defender"


def test_check_agent_model_sends_claude_the_request_a_decision_sends(monkeypatch: pytest.MonkeyPatch) -> None:
    # Running the real Anthropic client over a mock transport, so what is read is the request body it would send.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    bodies: list[dict[str, Any]] = []

    def answer(request: httpx2.Request) -> httpx2.Response:
        bodies.append(json.loads(request.content))
        message = {
            "id": "msg_1",
            "type": "message",
            "role": "assistant",
            "model": "claude-sonnet-5-5",
            "content": [{"type": "text", "text": attacker_says("keep")}],
            "stop_reason": "end_turn",
            "stop_sequence": None,
            "usage": {"input_tokens": 1, "output_tokens": 1},
        }
        return httpx2.Response(200, json=message, request=request)

    model = make_agent_model("claude")
    model.http_client = httpx2.Client(transport=httpx2.MockTransport(answer))
    check_agent_model(model, "attacker", AttackerDecision)
    (body,) = bodies
    assert body["model"] == "claude-sonnet-5-5"
    assert body["output_config"]["format"]["schema"]["title"] == "AttackerDecision"
    assert {"temperature", "top_p", "top_k"}.isdisjoint(body)


def test_ask_turns_a_provider_error_and_an_answer_outside_the_schema_into_agent_unavailable(tmp_path: Path) -> None:
    model = ScriptedAgnoModel("scripted", [attacker_says("remove"), RuntimeError("503 overloaded"), "no JSON here"])
    memory = open_memory(tmp_path, model)
    assert memory.ask("first", AttackerDecision).action == "remove"
    with pytest.raises(AgentUnavailableError, match="503 overloaded"):
        memory.ask("second", AttackerDecision)
    with pytest.raises(AgentUnavailableError, match="outside the AttackerDecision schema") as failure:
        memory.ask("third", AttackerDecision)
    assert failure.value.role == "attacker"
    memory.close()


def test_memory_is_shown_to_the_model_but_no_memory_tool_is_offered(tmp_path: Path) -> None:
    model = ScriptedAgnoModel("scripted", [attacker_says("keep")])
    memory = open_memory(tmp_path, model)
    memory.remember("Round 1: two of three records alerted")
    memory.log("tested_note:'x'", "what was tried", outcome="2/3 alerted")
    memory.ask("first", AttackerDecision)
    # Agno would hand the tools of an AGENTIC store to the model, and a tool call is a model call the loop never asked for.
    assert model.tools_offered == [0]
    assert "Round 1: two of three records alerted" in model.seen_prompts[0]
    assert "tested_note:'x'" in model.seen_prompts[0]
    assert "update_user_memory" not in model.seen_prompts[0]
    memory.close()


def test_ask_reads_a_dict_and_reports_whatever_escapes_agno(tmp_path: Path) -> None:
    memory = open_memory(tmp_path, ScriptedAgnoModel("scripted", []))
    memory.agent = StubAgent({"action": "keep", "note": "", "rationale": "as a dict"})
    assert memory.ask("first", AttackerDecision).rationale == "as a dict"
    memory.agent = StubAgent(ConnectionError("socket closed"))
    with pytest.raises(AgentUnavailableError, match="attacker: ConnectionError: socket closed"):
        memory.ask("second", AttackerDecision)
    memory.agent = StubAgent(42)
    with pytest.raises(AgentUnavailableError, match="outside the AttackerDecision schema: 42"):
        memory.ask("third", AttackerDecision)
    memory.close()


def test_ledger_records_outlive_the_process_only_through_the_memory_folder(tmp_path: Path) -> None:
    first = open_memory(tmp_path / "kept", ScriptedAgnoModel("scripted", []))
    first.save_record("retired_note", RetiredNote(wording="ticket-1", note="Ticket-1"))
    first.close()
    again = open_memory(tmp_path / "kept", ScriptedAgnoModel("scripted", []))
    elsewhere = open_memory(tmp_path / "other", ScriptedAgnoModel("scripted", []))
    assert again.load_records("retired_note", RetiredNote) == [RetiredNote(wording="ticket-1", note="Ticket-1")]
    assert elsewhere.load_records("retired_note", RetiredNote) == []
    assert again.load_records("instruction_cost", RetiredNote) == []
    assert (tmp_path / "kept" / "attacker.db").is_file()
    again.close()
    elsewhere.close()


def chat_gateway(*statuses: int) -> Callable[[httpx.Request], httpx.Response]:
    """An OpenAI-compatible gateway giving each request the next status; a 200 streams a completion in which the attacker keeps."""
    queue = list(statuses)

    def answer(request: httpx.Request) -> httpx.Response:
        status = queue.pop(0)
        if status != 200:
            return httpx.Response(status, json={"error": {"message": "The model service is temporarily unavailable."}}, request=request)
        # The transport sends the SDK's plain request as a stream, so that is what reaches the gateway.
        assert json.loads(request.content)["stream"] is True
        head = {"id": "chatcmpl-1", "object": "chat.completion.chunk", "created": 0, "model": "Qwen3.8-27B"}
        delta = {"role": "assistant", "content": attacker_says("keep")}
        chunks: list[dict[str, Any]] = [
            {**head, "choices": [{"index": 0, "delta": delta, "finish_reason": "stop"}]},
            {**head, "choices": [], "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}},
        ]
        return httpx.Response(200, content=sse(chunks), headers={"content-type": "text/event-stream"}, request=request)

    return answer


def test_the_qwen_agent_rides_out_a_refusal_through_the_spaced_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    # Running the real OpenAI client over the transport `make_agent_model` asks for, so the spacing and the patience tested are
    # the ones a run gets; the SDK never sees the 503 the transport waited out.
    monkeypatch.setenv("QWEN_API_KEY", "test-q-key")
    monkeypatch.delenv("QWEN_BASE_URL", raising=False)
    clock = FakeClock()
    built = fake_spaced_transport(monkeypatch, agent_runtime, chat_gateway(503, 200, 200), clock)
    model = make_agent_model("qwen")
    assert isinstance(model.http_client, httpx.Client)
    assert model.http_client.timeout == AGENT_TIMEOUT
    # The transport is the one retry policy, so the SDK's own quick retries are off.
    assert model.max_retries == 0
    check_agent_model(model, "attacker", AttackerDecision)
    check_agent_model(model, "attacker", AttackerDecision)
    assert built == [(QWEN_DEFAULT_BASE_URL, PATIENT_WAITS)]
    # 15 s waited out the 503; the second question then waits the rest of its 3 s interval.
    assert clock.slept == [15.0, 3.0]
    # The hydrogen agent's gateway sets no such ceiling, so its requests go through the SDK's own client, unspaced.
    monkeypatch.setenv("HYDROGEN_API_KEY", "test-h-key")
    hydrogen = make_agent_model("hydrogen")
    assert (hydrogen.http_client, hydrogen.max_retries) == (None, None)
