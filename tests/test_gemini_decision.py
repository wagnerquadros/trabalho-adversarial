"""Gemini Decision detector tests: request mapping, usage normalization, the SDK's own errors, retries, and dynamic instructions.

The error tests run the real `google-genai` client over an `httpx.MockTransport`, so what the detector catches is what the SDK raises
for an HTTP status, a network failure or a timeout, with no network and no key.
"""

import json
import time
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from google import genai
from google.genai import errors, types
from google.genai._interactions import APIConnectionError, APIStatusError, APITimeoutError, GeminiNextGenAPIClientError

from jev_ids import ROOT
from jev_ids.dataset import load_config
from jev_ids.detectors import DecisionDetector, gemini_decision
from jev_ids.detectors.gemini_decision import (
    DEFAULT_MODEL,
    GeminiDecisionDetector,
    attempt,
    decision_request,
    measurements,
)
from jev_ids.run import RunSpec, build_detector, sample_examples
from tests.helpers import CATEGORIES, CONFIG, FLOW, JEV_PROMPT, TRAIN, no_sleep

# Keeping the SDK's client class, because one test replaces `genai.Client` to read what the detector builds it with.
SDK_CLIENT = genai.Client
# Listing what the scripted transport answers with: a status and a JSON body, or an exception httpx would raise.
Outcome = tuple[int, dict[str, Any]] | Exception
BLOCKED: Outcome = (
    200,
    {"prompt_feedback": {"block_reason": "safety", "block_reason_message": "input blocked"}, "usage": {"total_input_tokens": 12}},
)


def answered(p_attack: float = 0.82, category: str = "dos") -> Outcome:
    """A 200 answer of the Decisions API with both questions answered and a usage report."""
    answers = {
        "is_attack": {"type": "noul", "noul": p_attack, "confidence": 0.9},
        "category": {"type": "choice", "choice": category, "confidence": 0.88, "probabilities": {category: 0.88, "normal": 0.12}},
    }
    return 200, {"answers": answers, "usage": {"total_input_tokens": 450, "total_output_tokens": 18, "total_tokens": 468}}


def failed(status: int) -> Outcome:
    """An HTTP error answer, in the shape Google's APIs give one."""
    return status, {"error": {"code": status, "message": f"status {status}"}}


class ScriptedTransport:
    """What the real client talks to instead of the network: scripted answers, with every request kept."""

    def __init__(self, outcomes: list[Outcome]) -> None:
        self.outcomes = outcomes
        self.requests: list[httpx.Request] = []

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return httpx.Response(outcome[0], json=outcome[1], request=request)

    def client(self) -> genai.Client:
        """A real client of the Gemini API over this transport, with the SDK's own retries off as the detector sets them."""
        options = types.HttpOptions(
            api_version="v1beta",
            retry_options=types.HttpRetryOptions(attempts=1),
            httpx_client=httpx.Client(transport=httpx.MockTransport(self.handle)),
        )
        return SDK_CLIENT(api_key="test-key", vertexai=False, http_options=options)


def detector_over(outcomes: list[Outcome]) -> tuple[GeminiDecisionDetector, ScriptedTransport]:
    """A detector whose client is the real SDK over a scripted transport."""
    transport = ScriptedTransport(outcomes)
    detector = GeminiDecisionDetector(JEV_PROMPT)
    detector.client = transport.client()
    return detector, transport


def raised_for(outcome: Outcome) -> Exception:
    """What the SDK raises from `decisions.create` for one scripted answer."""
    detector, _ = detector_over([outcome])
    payload = decision_request(JEV_PROMPT["text"], FLOW, [])
    with pytest.raises(GeminiNextGenAPIClientError) as raised:
        detector.client.decisions.create(model=DEFAULT_MODEL, input=payload["input"], questions=payload["questions"])
    return raised.value


def test_decision_request_matches_jev_questions() -> None:
    examples = sample_examples(TRAIN, 1, 0, CONFIG["categories"])
    payload = decision_request(JEV_PROMPT["text"], FLOW, examples)
    parsed_input = json.loads(payload["input"])
    assert parsed_input["instructions"] == json.loads(JEV_PROMPT["text"])["state"]["instructions"]
    assert parsed_input["flows"]["under_test"] == "2,2,2"
    assert len(parsed_input["examples"]) == len(CONFIG["categories"])
    assert payload["questions"]["is_attack"]["type"] == "noul"
    assert payload["questions"]["category"]["type"] == "choice"
    assert payload["questions"]["category"]["criteria"] == CATEGORIES


def test_measurements_extracts_noul_choice_and_usage() -> None:
    usage = SimpleNamespace(
        total_input_tokens=450, total_output_tokens=18, total_cached_tokens=120, total_thought_tokens=6, total_tokens=474
    )
    answers = {
        "is_attack": SimpleNamespace(type="noul", noul=0.91, confidence=0.9),
        "category": SimpleNamespace(type="choice", choice="probe", confidence=0.88),
    }
    row = measurements(SimpleNamespace(answers=answers, usage=usage), 42.5, DEFAULT_MODEL)
    assert (row["model"], row["p_attack"], row["category_pred"], row["confidence"]) == (DEFAULT_MODEL, 0.91, "probe", 0.88)
    assert row["latency_ms"] == 42.5
    assert row["usage"] == {
        "input_tokens": 450,
        "output_tokens": 18,
        "cache_read_tokens": 120,
        "reasoning_tokens": 6,
        "total_tokens": 474,
    }
    assert "error" not in row


def test_predict_reads_the_answer_of_the_real_client() -> None:
    detector, transport = detector_over([answered(0.76, "probe")])
    out = detector.predict(FLOW, [])
    assert (out["p_attack"], out["category_pred"], out["confidence"], out["retries"]) == (0.76, "probe", 0.88, 0)
    assert out["usage"] == {"input_tokens": 450, "output_tokens": 18, "total_tokens": 468}
    assert out["raw"]["answers"]["is_attack"]["noul"] == 0.76
    (request,) = transport.requests
    assert str(request.url) == "https://generativelanguage.googleapis.com/v1beta/decisions"
    assert json.loads(request.content)["model"] == DEFAULT_MODEL


def test_the_sdk_raises_its_own_family_which_the_old_classes_do_not_match() -> None:
    rate_limited = raised_for(failed(429))
    assert isinstance(rate_limited, APIStatusError)
    assert rate_limited.status_code == 429
    assert isinstance(raised_for(httpx.ConnectError("connection refused")), APIConnectionError)
    assert isinstance(raised_for(httpx.ReadTimeout("timed out")), APITimeoutError)
    # Neither class the detector used to catch is in that family.
    assert not isinstance(rate_limited, (errors.APIError, httpx.HTTPError))


def test_retries_rate_limit_network_failure_and_timeout_then_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(time, "sleep", no_sleep)
    script = [failed(429), httpx.ConnectError("connection refused"), httpx.ReadTimeout("timed out"), failed(503), answered(0.76)]
    detector, transport = detector_over(script)
    out = detector.predict(FLOW, [])
    assert (out["retries"], out["p_attack"]) == (4, 0.76)
    assert "error" not in out
    assert len(transport.requests) == 5


@pytest.mark.parametrize("status", [400, 401, 403, 404])
def test_non_retryable_status_fails_immediately(monkeypatch: pytest.MonkeyPatch, status: int) -> None:
    monkeypatch.setattr(time, "sleep", no_sleep)
    detector, transport = detector_over([failed(status), answered()])
    out = detector.predict(FLOW, [])
    assert out["retries"] == 0
    assert out["error"].startswith(f"HTTP {status}: ")
    assert "p_attack" not in out
    assert len(transport.requests) == 1


def test_a_status_that_keeps_coming_ends_as_an_error_row(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(time, "sleep", no_sleep)
    detector, transport = detector_over([failed(429)] * 5)
    out = detector.predict(FLOW, [])
    assert (out["retries"], len(transport.requests)) == (4, 5)
    assert out["error"].startswith("HTTP 429: ")


def test_other_errors_of_the_sdk_family_are_not_retried() -> None:
    def create(**_kwargs: Any) -> Any:
        raise GeminiNextGenAPIClientError("answer outside the schema")

    out = attempt(SimpleNamespace(decisions=SimpleNamespace(create=create)), DEFAULT_MODEL, {"input": "{}", "questions": {}})
    assert out == {"error": "GeminiNextGenAPIClientError: answer outside the schema", "retryable": False}


def test_a_response_without_an_is_attack_answer_is_an_error_row() -> None:
    detector, transport = detector_over([BLOCKED, answered()])
    out = detector.predict(FLOW, [])
    assert out["error"] == "no is_attack answer: input blocked (safety) input blocked"
    assert (out["p_attack"], out["retries"]) == (None, 0)
    assert out["usage"] == {"input_tokens": 12}
    assert len(transport.requests) == 1
    assert measurements({"answers": {"category": {"choice": "dos"}}}, 1.0, DEFAULT_MODEL)["error"] == "no is_attack answer"


def test_client_names_the_gemini_api_whatever_the_environment_says(monkeypatch: pytest.MonkeyPatch) -> None:
    # Setting what the `llm:gemini` setup of this repository puts in the environment, which would route a default client to Vertex AI.
    monkeypatch.setenv("GOOGLE_GENAI_USE_VERTEXAI", "true")
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    transport = ScriptedTransport([answered()])
    built: list[dict[str, Any]] = []

    def record_client(**kwargs: Any) -> genai.Client:
        built.append(kwargs)
        return transport.client()

    monkeypatch.setattr(gemini_decision.genai, "Client", record_client)
    assert GeminiDecisionDetector(JEV_PROMPT).predict(FLOW, [])["p_attack"] == 0.82
    assert built[0]["vertexai"] is False
    assert transport.requests[0].url.host == "generativelanguage.googleapis.com"
    assert transport.requests[0].headers["x-goog-api-key"] == "test-key"


def test_missing_api_key_raises_runtime_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    detector = GeminiDecisionDetector(JEV_PROMPT)
    with pytest.raises(RuntimeError, match="GEMINI_API_KEY"):
        detector.predict(FLOW, [])


def test_set_instructions_updates_state_instructions() -> None:
    detector = GeminiDecisionDetector(JEV_PROMPT)
    assert isinstance(detector, DecisionDetector)
    detector.set_instructions("Updated strict policy")
    assert detector.instructions == "Updated strict policy"
    payload = decision_request(detector.template, FLOW, [])
    assert json.loads(payload["input"])["instructions"] == "Updated strict policy"


def test_build_detector_selects_gemini_decision() -> None:
    config = load_config(ROOT / "data" / "nsl-kdd" / "dataset.json")
    spec = RunSpec(
        detector="gemini_decision",
        dataset=ROOT / "data" / "nsl-kdd" / "dataset.json",
        split="smoke",
        k_values=(0,),
        seeds=(0,),
    )
    detector = build_detector(spec, config)
    assert isinstance(detector, GeminiDecisionDetector)
    assert isinstance(detector, DecisionDetector)
    assert detector.model == DEFAULT_MODEL
