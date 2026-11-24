"""The Agno runtime of a participant of the adversarial loop: its model, its private memory and the one way its failures surface.

In reading order:

- `AgentUnavailableError`: what any failure of a participant's model becomes, so the loop records it and stops instead of crashing.
- `OPENAI_LIKE_PROVIDERS`, `api_key_of` and `make_agent_model`: the Agno model of a participant, by provider; the requests of a
  spaced provider wait for the spacer its host shares with every other client of it, and a passing refusal is waited out
  (`rate_limit.py`).
- `check_agent_model`: the one trivial question that finds a bad key before a round of detector calls is paid for.
- `AgentBundle` and `AgentMemory`: one participant's Agno `Agent`, `LearningMachine` and `SqliteDb`.

Each participant has one SQLite file, `<memory_dir>/<role>.db`, that the other never opens. It holds what Agno keeps (the session, the
user memory, the decision log) and the ledger records `agents.py` enforces its rules with, so both outlive the process when the folder does.
"""

from __future__ import annotations

import os
import uuid
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
from agno.agent import Agent
from agno.db.base import SessionType
from agno.db.sqlite import SqliteDb
from agno.learn import DecisionLogConfig, LearningMachine, LearningMode, UserMemoryConfig
from agno.learn.schemas import DecisionLog
from agno.models.anthropic import Claude
from agno.models.openai.like import OpenAILike
from agno.run.base import RunStatus
from pydantic import BaseModel

from jev_ids.detectors import llm
from jev_ids.rate_limit import spaced_transport

HYDROGEN_DEFAULT_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/openai/"
QWEN_DEFAULT_BASE_URL = "https://api.tokenlab.amd.com/v1"
# Naming the variables the hydrogen agent takes its key from, in order of preference.
HYDROGEN_KEY_VARS = ("HYDROGEN_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY")
QWEN_KEY_VARS = ("QWEN_API_KEY",)
AGENT_DEFAULT_MODELS: dict[str, str] = {
    "claude": "claude-sonnet-5-5",
    "anthropic": "claude-sonnet-5-5",
    "hydrogen": "gemini-4-hydrogen",
    "qwen": "Qwen3.8-27B",
    **llm.DEFAULT_MODEL,
}


@dataclass(frozen=True)
class OpenAIEndpoint:
    """A provider an agent reaches through the OpenAI chat API.

    Attributes:
        key_vars: the environment variables its key may come from, in order of preference.
        base_url_var: the variable that overrides its endpoint.
        default_base_url: the endpoint used when that variable is unset.
        spaced: whether its gateway caps the calls a minute and refuses calls under load, so that every request waits for the
            spacer of its host and a passing refusal is sent again after patient waits.
    """

    key_vars: tuple[str, ...]
    base_url_var: str
    default_base_url: str
    spaced: bool = False


OPENAI_LIKE_PROVIDERS: dict[str, OpenAIEndpoint] = {
    "hydrogen": OpenAIEndpoint(HYDROGEN_KEY_VARS, "HYDROGEN_BASE_URL", HYDROGEN_DEFAULT_BASE_URL),
    "qwen": OpenAIEndpoint(QWEN_KEY_VARS, "QWEN_BASE_URL", QWEN_DEFAULT_BASE_URL, spaced=True),
}
PROBE_QUESTION = "Connectivity check before the study starts: no data is under review yet. Answer with the action `keep`."
# Cutting an error text to this length before it reaches a record, a log line or the terminal.
DETAIL_LENGTH = 300
# The OpenAI SDK's own defaults, ten minutes for an answer and five seconds to connect, set on a spaced client explicitly,
# because the SDK keeps the timeout of a client it is handed unless that timeout equals httpx's default.
AGENT_TIMEOUT = httpx.Timeout(600.0, connect=5.0)


class AgentUnavailableError(RuntimeError):
    """A participant's model failed: the call raised, the run ended in error, or the answer did not fit the schema.

    Attributes:
        role: `attacker` or `defender`.
        detail: the error text, cut to DETAIL_LENGTH characters.
    """

    def __init__(self, role: str, detail: str) -> None:
        """Keep the role and the cut error text, and say both in the message."""
        self.role = role
        self.detail = detail[:DETAIL_LENGTH]
        super().__init__(f"{role}: {self.detail}")


def api_key_of(provider: str) -> str:
    """The key of an OpenAI-compatible provider, from the first of its variables that is set.

    Args:
        provider: a key of OPENAI_LIKE_PROVIDERS.

    Returns:
        The key, never a placeholder.

    Raises:
        RuntimeError: when none of the provider's variables is set, naming them all.
    """
    key_vars = OPENAI_LIKE_PROVIDERS[provider].key_vars
    for name in key_vars:
        value = os.environ.get(name)
        if value:
            return value
    raise RuntimeError(f"the {provider} agent needs an API key: set one of {', '.join(key_vars)}")


def make_agent_model(provider: str, model_id: str | None = None) -> Any:
    """Build an Agno model instance for one benchmark participant."""
    normalized = provider.strip().lower()
    if normalized not in AGENT_DEFAULT_MODELS:
        supported = ", ".join(sorted(AGENT_DEFAULT_MODELS))
        raise ValueError(f"unsupported agent provider {provider!r}; choose one of: {supported}")
    resolved = model_id or AGENT_DEFAULT_MODELS[normalized]
    if normalized in ("claude", "anthropic"):
        # Leaving `temperature` out, because the Messages API version the SDK sends (2026-10-21) rejects it
        # and Claude Sonnet 5.5 accepts the default sampling values only.
        return Claude(id=resolved)
    endpoint = OPENAI_LIKE_PROVIDERS.get(normalized)
    if endpoint is not None:
        return _openai_like_model(normalized, endpoint, resolved)
    return llm.make_model(normalized, resolved)


def _openai_like_model(provider: str, endpoint: OpenAIEndpoint, model_id: str) -> OpenAILike:
    """The Agno model of a provider reached through the OpenAI chat API.

    A spaced provider gets its own httpx client, whose transport sends every request only when the spacer its host shares with
    every other client gives it a turn, and sends a passing refusal again after patient waits (`rate_limit.py`). The SDK's own
    quick retries are switched off, so the transport's patience is the whole patience instead of starting over on each of them,
    and the SDK sees one answer, so the agent's session never holds a failed attempt.
    """
    base_url = os.environ.get(endpoint.base_url_var) or endpoint.default_base_url
    if not endpoint.spaced:
        return OpenAILike(id=model_id, api_key=api_key_of(provider), base_url=base_url, temperature=0.0)
    http_client = httpx.Client(transport=spaced_transport(base_url), timeout=AGENT_TIMEOUT)
    return OpenAILike(id=model_id, api_key=api_key_of(provider), base_url=base_url, temperature=0.0, http_client=http_client, max_retries=0)


def _run_checked(agent: Any, role: str, prompt: str, **run_options: Any) -> Any:
    """One Agno run, with every way a provider can fail turned into `AgentUnavailableError`.

    Agno catches a provider error itself and returns a run whose status is `RunStatus.error` and whose content is the error text,
    so an exception escapes only from outside the model call. Both end the same way here.

    Args:
        agent: the Agno agent to run.
        role: `attacker` or `defender`, named in the error.
        prompt: the user message of the run.
        **run_options: what else `Agent.run` takes, such as the session state of the run.

    Returns:
        Agno's output of a run that did not fail.
    """
    try:
        run_output = agent.run(prompt, **run_options)
    # Catching whatever a provider SDK or Agno raises, because each provider has its own family of errors.
    except Exception as exc:
        raise AgentUnavailableError(role, f"{type(exc).__name__}: {exc}") from exc
    if run_output.status == RunStatus.error:
        raise AgentUnavailableError(role, str(run_output.content))
    return run_output


def check_agent_model(model: Any, role: str, output_schema: type[BaseModel] | None = None) -> None:
    """Ask the model one trivial question, so a bad key or model id shows before a round of detector calls is paid for.

    The question goes through a bare Agno agent on the same model object, without the participant's memory, so it leaves no trace there.
    With `output_schema`, it is asked as a decision is, with the provider's structured output switched on, so a provider that refuses
    that request shows here too. Only a failed call counts: what the model answers is not read.

    Args:
        model: the Agno model of the participant.
        role: `attacker` or `defender`, named in the error.
        output_schema: the schema of the participant's decisions; None asks without structured output.

    Raises:
        AgentUnavailableError: when the call raises or the run ends in error.
    """
    probe: Any = Agent(model=model, output_schema=output_schema, markdown=False, retries=0, telemetry=False)
    _run_checked(probe, role, PROBE_QUESTION)


@dataclass(frozen=True)
class AgentBundle:
    """Runtime settings used to wire an Agno agent and its private memory.

    Attributes:
        reopen: go on with the session the role last ran in on its file, as a resumed run does, instead of opening a new one.
    """

    role: str
    model: Any
    instructions: str
    output_schema: type[BaseModel]
    initial_state: dict[str, Any]
    memory_dir: Path
    reopen: bool = False


def _parse_schema_output[T: BaseModel](content: Any, schema: type[T]) -> T:
    """Convert Agno `RunOutput.content` (instance, dict, or JSON string) into `schema`."""
    if isinstance(content, schema):
        return content
    if isinstance(content, dict):
        return schema.model_validate(content)
    if isinstance(content, str):
        return schema.model_validate_json(content.strip())
    raise TypeError(f"unexpected Agno output for {schema.__name__}: {type(content).__name__}")


class AgentMemory:
    """One participant's Agno agent and its private memory, a SQLite file that no other participant opens.

    The file holds what Agno keeps (the session, and the user memory and decision log of the `LearningMachine`) and the ledger records
    this module enforces rules with (`save_record`, `load_records`), so both outlive the process for as long as the folder does.
    """

    def __init__(self, bundle: AgentBundle) -> None:
        """Open `<memory_dir>/<role>.db` and build the `LearningMachine` and the Agno `Agent` on it."""
        self.role = bundle.role
        # Keeping the session state here and handing a copy to every run, because Agno copies an agent's default state into
        # the session once, at the first run, and a change made to it afterwards would never reach the model.
        self.state = bundle.initial_state
        self.db = SqliteDb(db_file=str(bundle.memory_dir / f"{bundle.role}.db"))
        # Going on, in a resumed run, with the session the role last ran in, so the model reads the history it read before the stop;
        # Agno leaves a run that ended in error out of that history.
        reopened = self._latest_session_id() if bundle.reopen else None
        self.session_id = reopened or f"{bundle.role}-{uuid.uuid4().hex[:8]}"
        # Switching each memory tool off by its own flag, because in AGENTIC mode Agno hands them to the model whatever
        # `enable_agent_tools` says. The memory is written by this module alone: a tool call would be a model call the loop
        # never asked for, and `update_user_memory` could rewrite or delete the feedback recorded here.
        self.learning = LearningMachine(
            db=self.db,
            user_memory=UserMemoryConfig(mode=LearningMode.AGENTIC, enable_agent_tools=False, agent_can_update_memories=False),
            decision_log=DecisionLogConfig(
                mode=LearningMode.AGENTIC,
                enable_agent_tools=False,
                agent_can_save=False,
                agent_can_search=False,
            ),
            namespace=bundle.role,
        )
        # Typing the agent as `Any`, because Agno's `run` overloads are partially untyped for pyright.
        self.agent: Any = Agent(
            id=bundle.role,
            model=bundle.model,
            db=self.db,
            user_id=bundle.role,
            session_id=self.session_id,
            session_state=bundle.initial_state,
            add_session_state_to_context=True,
            add_history_to_context=True,
            num_history_runs=10,
            learning=self.learning,
            add_learnings_to_context=True,
            instructions=bundle.instructions,
            output_schema=bundle.output_schema,
            markdown=False,
            retries=0,
            telemetry=False,
        )

    def _latest_session_id(self) -> str | None:
        """The session this role last ran in on its file, or None when it never ran there."""
        sessions: Any = self.db.get_sessions(
            session_type=SessionType.AGENT, component_id=self.role, sort_by="created_at", sort_order="desc", limit=1, include_runs=False
        )
        return sessions[0].session_id if sessions else None

    def remember(self, summary: str) -> None:
        """Add one line of feedback to the user memory, which Agno shows the model on every later run."""
        store: Any = self.learning.user_memory_store
        if store is not None:
            store.add_memory(user_id=self.role, memory=summary, agent_id=self.role)

    def log(self, decision: str, context: str, outcome: str = "pending") -> None:
        """Add one structured entry to the participant's decision log."""
        store: Any = self.learning.decision_log_store
        if store is not None:
            store.save(
                DecisionLog(
                    id=f"{self.role}-{uuid.uuid4().hex[:8]}",
                    decision=decision,
                    reasoning=context,
                    context=context,
                    outcome=outcome,
                    user_id=self.role,
                    agent_id=self.role,
                )
            )

    def ask[T: BaseModel](self, prompt: str, schema: type[T]) -> T:
        """One run of the agent parsed into `schema`; a failed run or an answer outside the schema is `AgentUnavailableError`."""
        run_output = _run_checked(self.agent, self.role, prompt, session_state=deepcopy(self.state))
        try:
            return _parse_schema_output(run_output.content, schema)
        # Catching pydantic's `ValidationError`, a `ValueError`, and the `TypeError` of a content of an unexpected type.
        except (ValueError, TypeError) as exc:
            raise AgentUnavailableError(self.role, f"answer outside the {schema.__name__} schema: {run_output.content!r}") from exc

    def save_record(self, kind: str, record: BaseModel) -> None:
        """Store one ledger record in the learnings table of the participant's own file."""
        self.db.upsert_learning(
            id=f"{self.role}-{kind}-{uuid.uuid4().hex}",
            learning_type=kind,
            content=record.model_dump(),
            agent_id=self.role,
            namespace=self.role,
        )

    def load_records[T: BaseModel](self, kind: str, schema: type[T]) -> list[T]:
        """The ledger records of one kind that this or an earlier run stored in the file, in no particular order."""
        rows = self.db.get_learnings(learning_type=kind, agent_id=self.role)
        return [schema.model_validate(row["content"]) for row in rows]

    def close(self) -> None:
        """Release the SQLite file, which Windows keeps locked while a connection is open."""
        self.db.close()
