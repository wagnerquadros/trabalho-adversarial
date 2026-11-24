"""System One detector tests: request mapping, response parsing, retries, errors and dynamic instructions.

The calls run the real `httpx.Client` over an `httpx.MockTransport`, so what the detector sends to `/systemone` and what it makes
of the answer is exercised with no network and no key.
"""

import json
import time
from typing import Any

import httpx
import pytest

from jev_ids import ROOT
from jev_ids.dataset import load_config
from jev_ids.detectors import DecisionDetector, normalize_decision_usage, systemone
from jev_ids.detectors.systemone import (
    DEFAULT_MODEL,
    ENDPOINT,
    PATIENCE,
    SystemOneDetector,
    attempt,
    request_body,
)
from jev_ids.run import RunSpec, build_detector, sample_examples
from tests.helpers import CATEGORIES, CONFIG, FLOW, JEV_PROMPT, TOKENLAB, TRAIN, FakeClock, fake_spaced_transport, no_sleep

Reply = tuple[int, dict[str, Any]] | Exception


def answered(p_attack: float = 0.82, category: str = "dos") -> Reply:
    """A 200 answer of the System One API: both questions answered, with an OpenAI-style usage report."""
    return 200, {
        "model": DEFAULT_MODEL,
        "answers": {
            "is_attack": {"type": "noul", "noul": p_attack},
            "category": {"type": "choice", "choice": category, "confidence": 0.88, "probabilities": {category: 0.9, "normal": 0.1}},
        },
        "usage": {"input_tokens": 716, "output_tokens": 0},
    }


def errored(status: int) -> Reply:
    """A non-200 answer with a short body, as the gateway returns one."""
    return status, {"error": {"message": f"status {status}"}}


# A 200 answer whose `answers` carry no `is_attack`, as a filtered or partial response would.
WITHOUT_ANSWER: Reply = (200, {"model": DEFAULT_MODEL, "answers": {"category": {"choice": "dos"}}, "usage": {"input_tokens": 12}})


class FakeGateway:
    """A scripted System One endpoint behind the real httpx client: each request gets the next reply, and is kept."""

    def __init__(self, replies: list[Reply]) -> None:
        self.replies = replies
        self.requests: list[httpx.Request] = []

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return httpx.Response(reply[0], json=reply[1], request=request)

    def detector(self) -> SystemOneDetector:
        built = SystemOneDetector(JEV_PROMPT)
        built.client = httpx.Client(
            base_url="https://gateway.test/v1",
            headers={"Authorization": "Bearer test-key", "Content-Type": "application/json"},
            transport=httpx.MockTransport(self.handle),
        )
        return built


def test_request_body_carries_the_state_and_the_two_questions() -> None:
    examples = sample_examples(TRAIN, 1, 0, CONFIG["categories"])
    body = request_body(JEV_PROMPT["text"], FLOW, examples)
    assert sorted(body) == ["questions", "state"]
    assert body["state"]["flows"]["under_test"] == "2,2,2"
    assert len(body["state"]["examples"]) == len(CONFIG["categories"])
    assert body["questions"]["is_attack"]["type"] == "noul"
    assert body["questions"]["category"]["criteria"] == CATEGORIES


def test_predict_reads_the_answer_and_posts_the_body_to_the_endpoint() -> None:
    gateway = FakeGateway([answered(0.76, "probe")])
    out = gateway.detector().predict(FLOW, [])
    assert (out["p_attack"], out["category_pred"], out["confidence"], out["retries"]) == (0.76, "probe", 0.88, 0)
    assert out["usage"] == {"input_tokens": 716, "output_tokens": 0}
    assert out["model"] == DEFAULT_MODEL
    (request,) = gateway.requests
    assert str(request.url).endswith(ENDPOINT)
    sent = json.loads(request.content)
    assert sent["model"] == DEFAULT_MODEL
    assert sorted(sent) == ["model", "questions", "state"]


def test_retries_a_rate_limit_a_network_failure_and_an_overload_then_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(time, "sleep", no_sleep)
    gateway = FakeGateway([errored(429), httpx.ConnectError("connection refused"), errored(503), answered(0.76)])
    out = gateway.detector().predict(FLOW, [])
    assert (out["retries"], out["p_attack"]) == (3, 0.76)
    assert "error" not in out
    assert len(gateway.requests) == 4


@pytest.mark.parametrize("status", [400, 401, 403, 404])
def test_a_non_retryable_status_fails_at_once(monkeypatch: pytest.MonkeyPatch, status: int) -> None:
    monkeypatch.setattr(time, "sleep", no_sleep)
    gateway = FakeGateway([errored(status), answered()])
    out = gateway.detector().predict(FLOW, [])
    assert out["retries"] == 0
    assert out["error"].startswith(f"HTTP {status}: ")
    assert "p_attack" not in out
    assert len(gateway.requests) == 1


def test_a_status_that_keeps_coming_ends_as_an_error_row(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(time, "sleep", no_sleep)
    gateway = FakeGateway([errored(429)] * 5)
    out = gateway.detector().predict(FLOW, [])
    assert (out["retries"], len(gateway.requests)) == (4, 5)
    assert out["error"].startswith("HTTP 429: ")


def test_a_response_without_an_is_attack_answer_is_an_error_row() -> None:
    gateway = FakeGateway([WITHOUT_ANSWER])
    out = gateway.detector().predict(FLOW, [])
    assert out["error"] == "no is_attack answer"
    assert (out["p_attack"], out["retries"], out["usage"]) == (None, 0, {"input_tokens": 12})


def test_usage_is_read_under_either_the_google_or_the_openai_names() -> None:
    assert normalize_decision_usage({"input_tokens": 5, "output_tokens": 0}) == {"input_tokens": 5, "output_tokens": 0}
    assert normalize_decision_usage({"total_input_tokens": 5, "total_tokens": 9}) == {"input_tokens": 5, "total_tokens": 9}
    assert normalize_decision_usage(None) == {}


def test_attempt_turns_a_connection_failure_into_a_retryable_error() -> None:
    class Boom:
        def post(self, *_args: Any, **_kwargs: Any) -> httpx.Response:
            raise httpx.ConnectError("down")

    assert attempt(Boom(), DEFAULT_MODEL, {"state": {}, "questions": {}}) == {"error": "ConnectError: down", "retryable": True}


def test_set_instructions_updates_state_instructions() -> None:
    detector = SystemOneDetector(JEV_PROMPT)
    assert isinstance(detector, DecisionDetector)
    detector.set_instructions("Updated strict policy")
    assert detector.instructions == "Updated strict policy"
    assert request_body(detector.template, FLOW, [])["state"]["instructions"] == "Updated strict policy"


def test_missing_api_key_raises_runtime_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("QWEN_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="QWEN_API_KEY"):
        SystemOneDetector(JEV_PROMPT).predict(FLOW, [])


def test_build_detector_selects_system_one() -> None:
    config = load_config(ROOT / "data" / "nsl-kdd" / "dataset.json")
    spec = RunSpec(detector="systemone", dataset=ROOT / "data" / "nsl-kdd" / "dataset.json", split="smoke", k_values=(0,), seeds=(0,))
    detector = build_detector(spec, config)
    assert isinstance(detector, SystemOneDetector)
    assert isinstance(detector, DecisionDetector)
    assert detector.model == DEFAULT_MODEL


def test_the_detector_rides_out_a_refusal_through_the_spaced_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QWEN_API_KEY", "test-key")
    monkeypatch.delenv("QWEN_BASE_URL", raising=False)
    clock = FakeClock()
    gateway = FakeGateway([errored(503), answered(0.7)])
    built = fake_spaced_transport(monkeypatch, systemone, gateway.handle, clock)
    out = SystemOneDetector(JEV_PROMPT).predict(FLOW, [])
    # The transport waited out the 503, so `post` saw one answer and counts no retry of its own.
    assert (out["p_attack"], out["retries"]) == (0.7, 0)
    assert built == [(TOKENLAB, PATIENCE)]
    assert clock.slept == [15.0]
    assert len(gateway.requests) == 2
