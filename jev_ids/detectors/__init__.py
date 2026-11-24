"""Detectors: Jev, Gemini Decision, the LLM baselines, Random Forest, Isolation Forest, and KNN.

Each detector is a class with `name`, `model`, `prompt_hash` and `predict(flow, examples) -> dict` returning what it measured for that
one Flow (`p_attack`, `category_pred`, `latency_ms`, ...) or an `error`. Decision detectors also expose `instructions` and
`set_instructions(...)` behind the `DecisionDetector` protocol so the adversarial orchestrator can swap defenders' instructions
without coupling to a specific backend.
"""

import json
import time
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Protocol, cast, runtime_checkable

from jev_ids.dataset import Flow, record_text

# Shared retry policy for HTTP decision APIs (Jev / Gemini Decisions).
MAX_ATTEMPTS = 5
BACKOFF_SECONDS = 1.0
TIMEOUT_SECONDS = 60
RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504, 529})


@runtime_checkable
class DecisionDetector(Protocol):
    """Common interface for IDS detectors that evaluate flows under configurable instructions."""

    name: str
    model: str
    prompt_hash: str | None

    @property
    def instructions(self) -> str:
        """Current defense instructions applied to each judged Flow."""
        ...

    def set_instructions(self, instructions: str) -> None:
        """Update the detector instructions for subsequent `predict` calls."""
        ...

    def predict(self, flow: Flow, examples: Sequence[Flow]) -> dict[str, Any]:
        """Predict attack probability and category for a single Flow."""
        ...


def template_instructions(template: str) -> str:
    """Return `state.instructions` from a JSON decision prompt template."""
    body: dict[str, Any] = json.loads(template)
    return str(body["state"]["instructions"])


def with_template_instructions(template: str, new_instructions: str) -> str:
    """Return a copy of a JSON decision template with `state.instructions` updated."""
    body: dict[str, Any] = json.loads(template)
    body["state"]["instructions"] = new_instructions
    return json.dumps(body)


class DecisionTemplate:
    """A Jev-style decision template and the dynamic-instructions interface shared by the HTTP decision detectors.

    Holds the template (`state` + `questions`), the model id, the prompt hash, the record format and a lazy client; a subclass
    adds its `name`, builds its client in `_ensure_client`, and judges one Flow in `predict`. The defender rewrites
    `state.instructions` between rounds through `set_instructions`.
    """

    name: str
    model: str
    default_model: str = ""

    def __init__(self, prompt: dict[str, Any], model_id: str | None = None, record: str = "compact") -> None:
        """Keep the template and settings; the model falls back to the subclass default, and the client is lazy."""
        self.template: str = prompt["text"]
        self.record = record
        self.prompt_hash: str = prompt["sha256"]
        self.model = model_id or self.default_model
        self.client: Any = None

    @property
    def instructions(self) -> str:
        """Current `state.instructions` sent inside each request."""
        return template_instructions(self.template)

    def set_instructions(self, instructions: str) -> None:
        """Update `state.instructions` in the decision template."""
        self.template = with_template_instructions(self.template, instructions)


def build_decision_body(template: str, flow: Flow, examples: Sequence[Flow], record: str = "compact") -> dict[str, Any]:
    """Fill a decision template with the Flow under test, optional Examples, and Category criteria."""
    body: dict[str, Any] = json.loads(template)
    body["state"]["flows"] = {"under_test": record_text(flow, record)}
    if examples:
        body["state"]["examples"] = [
            {
                "record": record_text(example, record),
                "category": example.category,
            }
            for example in examples
        ]
    body["questions"]["category"]["criteria"] = body["state"]["categories"]
    return body


def retry_request(
    call: Callable[[], dict[str, Any]],
    max_attempts: int = MAX_ATTEMPTS,
    backoff_seconds: float = BACKOFF_SECONDS,
) -> dict[str, Any]:
    """Execute `call` up to `max_attempts` times with exponential backoff on retryable errors."""
    result = call()
    retries = 0
    while result.get("retryable") and retries < max_attempts - 1:
        time.sleep(backoff_seconds * 2**retries)
        result = call()
        retries += 1
    result.pop("retryable", None)
    return {
        **result,
        "retries": retries,
    }


def _field(obj: Any, key: str, default: Any = None) -> Any:
    """A value by key from a mapping, or an attribute from an object; `default` when absent."""
    if obj is None:
        return default
    if isinstance(obj, Mapping):
        mapping = cast(Mapping[str, Any], obj)
        return mapping.get(key, default)
    return getattr(obj, key, default)


# Each normalized usage field, with the source names it may arrive under: Google's `total_*` names and the OpenAI-style names.
_USAGE_SOURCES: dict[str, tuple[str, ...]] = {
    "input_tokens": ("total_input_tokens", "input_tokens", "prompt_tokens"),
    "output_tokens": ("total_output_tokens", "output_tokens", "completion_tokens"),
    "cache_read_tokens": ("total_cached_tokens", "cache_read_tokens", "cached_tokens"),
    "reasoning_tokens": ("total_thought_tokens", "reasoning_tokens"),
    "total_tokens": ("total_tokens",),
}


def normalize_decision_usage(usage: Any) -> dict[str, int]:
    """Token counts of a decision response under one set of names, whichever names the backend used."""
    if usage is None:
        return {}
    normalized: dict[str, int] = {}
    for dst, sources in _USAGE_SOURCES.items():
        for src in sources:
            value = _field(usage, src)
            if isinstance(value, int):
                normalized[dst] = value
                break
    return normalized


def serialize_raw(response: Any) -> dict[str, Any]:
    """The raw response as a dict: itself when it is one, its `model_dump(mode="json")` when it offers one, else empty."""
    if isinstance(response, dict):
        return cast(dict[str, Any], response)
    model_dump = getattr(response, "model_dump", None)
    if callable(model_dump):
        dumped: Any = model_dump(mode="json")
        if isinstance(dumped, dict):
            return cast(dict[str, Any], dumped)
    return {}


def unanswered_reason(response: Any) -> str:
    """Why a decision response carries no `is_attack` answer: the block reason of its `prompt_feedback`, when present."""
    feedback = _field(response, "prompt_feedback")
    reason = _field(feedback, "block_reason")
    if reason is None:
        return "no is_attack answer"
    message = _field(feedback, "block_reason_message") or ""
    return f"no is_attack answer: input blocked ({reason}) {message}".strip()[:200]


def decision_measurements(response: Any, latency_ms: float, model: str) -> dict[str, Any]:
    """Normalize a System One / Decisions response (`answers`, `usage`) into the standard prediction row.

    A response without an `is_attack` answer, such as one a content filter blocked, is a failed call: the row carries an `error`
    beside what the call still measured, so it never passes for an answered Flow with no alert.

    Args:
        response: the decision response, a mapping or an object exposing `answers` and `usage`.
        latency_ms: the wall-clock time of the call, in milliseconds.
        model: the model the request named.

    Returns:
        `model`, `p_attack`, `category_pred`, `confidence`, `latency_ms`, `usage`, `raw`, and `error` when no answer came back.
    """
    answers: dict[str, Any] = _field(response, "answers") or {}
    is_attack = _field(answers, "is_attack")
    category = _field(answers, "category")
    row: dict[str, Any] = {
        "model": model,
        "p_attack": _field(is_attack, "noul"),
        "category_pred": _field(category, "choice"),
        "confidence": _field(category, "confidence"),
        "latency_ms": latency_ms,
        "usage": normalize_decision_usage(_field(response, "usage")),
        "raw": serialize_raw(response),
    }
    if row["p_attack"] is None:
        row["error"] = unanswered_reason(response)
    return row
