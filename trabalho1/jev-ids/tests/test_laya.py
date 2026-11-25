"""Laya detector: where the server is, the request body it shares with Jev, the answer and the retry policy."""

import json
from typing import Any

import pytest
import requests

from jev_ids.detectors import jev, laya
from jev_ids.run import sample_examples
from tests.helpers import CONFIG, JEV_PROMPT, make_flow, make_train, no_sleep

# The answer shape of the laya-serve README (read on 2026-09-29), with the numbers of a flow this size.
BODY: dict[str, Any] = {
    "answers": {
        "is_attack": {"noul": 0.78, "confidence": 0.81, "probabilities": [0.22, 0.78]},
        "category": {"choice": "r2l", "confidence": 0.8, "probabilities": {"r2l": 0.84, "probe": 0.02, "normal": 0.14}},
    },
    "usage": {"input_tokens": 1606, "output_tokens": 0},
    "routing": {"model": "multilingual", "reason": "pinned"},
}
FLOW = make_flow(9, "r2l", value="1")
TRAIN = make_train(["normal", "dos", "probe"])


class FakeResponse:
    """What `Session.post` returns, reduced to what the detector reads."""

    def __init__(self, status_code: int, body: Any) -> None:
        """Keep the status and the body; `ok` follows the 4xx boundary."""
        self.status_code = status_code
        self.ok = status_code < 400
        self.text = json.dumps(body) if not isinstance(body, str) else body
        self._body = body

    def json(self) -> Any:
        """The parsed body; a string body was never JSON and raises as one."""
        if isinstance(self._body, str):
            raise ValueError("not JSON")
        return self._body


@pytest.fixture
def detector(monkeypatch: pytest.MonkeyPatch) -> laya.LayaDetector:
    """A detector whose backoff does not wait; each test plugs the answers into its session."""
    monkeypatch.setattr(jev.time, "sleep", no_sleep)
    monkeypatch.delenv(laya.BASE_URL_VAR, raising=False)
    monkeypatch.delenv(laya.API_KEY_VAR, raising=False)
    return laya.LayaDetector(JEV_PROMPT)


def serving(detector: laya.LayaDetector, *answers: FakeResponse | Exception, sent: list[dict[str, Any]] | None = None) -> None:
    """Answer the detector's requests from a queue, in order, and record what was sent."""
    queue = list(answers)

    def post(url: str, *, json: dict[str, Any], timeout: int) -> FakeResponse:
        if sent is not None:
            sent.append({"url": url, "body": json, "timeout": timeout})
        item = queue.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    detector.session.post = post  # pyright: ignore[reportAttributeAccessIssue]  a stand-in for the one method used


def test_the_server_is_the_one_the_environment_names(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(laya.BASE_URL_VAR, raising=False)
    monkeypatch.delenv(laya.API_KEY_VAR, raising=False)
    assert laya.endpoint() == "http://127.0.0.1:8000/v1/systemone"
    assert laya.headers() == {}
    # Laya runs on another machine as easily as on this one: only the two variables move.
    monkeypatch.setenv(laya.BASE_URL_VAR, "http://192.168.0.7:9000/")
    monkeypatch.setenv(laya.API_KEY_VAR, "k")
    assert laya.endpoint() == "http://192.168.0.7:9000/v1/systemone"
    assert laya.headers() == {"Authorization": "Bearer k"}
    assert laya.LayaDetector(JEV_PROMPT).session.headers["Authorization"] == "Bearer k"


def test_the_request_is_jevs_own_body_with_the_checkpoint_and_the_budget(detector: laya.LayaDetector) -> None:
    sent: list[dict[str, Any]] = []
    serving(detector, FakeResponse(200, BODY), sent=sent)
    examples = sample_examples(TRAIN, 1, 0, CONFIG["categories"])

    detector.predict(FLOW, examples)

    assert sent[0]["url"] == "http://127.0.0.1:8000/v1/systemone"
    body = sent[0]["body"]
    # The same state and the same two questions Jev is asked, so a verdict of one is comparable with a verdict of the other; only the
    # model asked and the token budget of the checkpoint are Laya's own.
    shared = jev.request_body(detector.template, FLOW, examples)
    assert (body["state"], body["questions"]) == (shared["state"], shared["questions"])
    assert (body["model"], body["max_len"]) == ("multilingual", laya.MAX_LEN)
    assert (detector.name, detector.model, detector.prompt_hash) == ("laya", "multilingual", "h")
    assert laya.LayaDetector(JEV_PROMPT, "english").model == "english"


def test_the_answer_gives_p_attack_the_category_and_both_confidences(detector: laya.LayaDetector) -> None:
    serving(detector, FakeResponse(200, BODY))
    prediction = detector.predict(FLOW, [])
    assert prediction["p_attack"] == 0.78
    assert prediction["category_pred"] == "r2l"
    assert prediction["confidence"] == 0.8
    # Laya's noul answer carries a confidence where Jev's carries none, so the row keeps it under its own name.
    assert prediction["attack_confidence"] == 0.81
    assert prediction["usage"] == {"input_tokens": 1606, "output_tokens": 0}
    assert prediction["latency_ms"] > 0
    assert prediction["retries"] == 0
    assert prediction["raw"] == BODY
    assert "error" not in prediction


def test_an_overloaded_or_unreachable_server_is_retried_then_given_up_on(detector: laya.LayaDetector) -> None:
    serving(detector, FakeResponse(503, {"detail": "loading"}), FakeResponse(200, BODY))
    assert detector.predict(FLOW, [])["retries"] == 1
    serving(detector, *[requests.ConnectionError("refused") for _ in range(jev.MAX_ATTEMPTS)])
    prediction = detector.predict(FLOW, [])
    # A server that is not up yet, or is on a machine that is not reachable, ends as a row that `redo-errors` repairs.
    assert prediction["error"].startswith("ConnectionError")
    assert prediction["retries"] == jev.MAX_ATTEMPTS - 1
    assert "p_attack" not in prediction


def test_a_refused_request_or_an_answer_of_another_shape_is_an_error_row(detector: laya.LayaDetector) -> None:
    serving(detector, FakeResponse(422, {"detail": "max_len"}))
    refused = detector.predict(FLOW, [])
    assert refused["error"].startswith("HTTP 422")
    assert refused["retries"] == 0  # a request the server refuses is not worth sending again
    serving(detector, FakeResponse(200, "<html>proxy</html>"))
    assert detector.predict(FLOW, [])["error"].startswith("parse: ValueError")
    serving(detector, FakeResponse(200, {"answers": {"is_attack": {"noul": 0.5}}}))
    assert detector.predict(FLOW, [])["error"].startswith("parse: KeyError")
