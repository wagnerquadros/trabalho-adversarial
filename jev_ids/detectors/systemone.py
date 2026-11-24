"""TypeSafe System One decision models served over an HTTP endpoint (e.g. AMD TokenLab, `/v1/systemone`).

The System One protocol is the same one the Jev detector speaks (`jev.py`): one request carries a `state` (instructions, the
column header, the Category descriptions, the Flow under test) and two `questions` (`is_attack`, a `noul` probability, and
`category`, a labeled `choice`), and the answer is a probability, a category and a confidence. Jev reaches it through TypeSafe's
SDK; this detector reaches any System One model an OpenAI-style gateway hosts by a plain POST to `<base>/systemone` with a bearer
key, so the adversarial defender can rewrite `state.instructions` between rounds exactly as it does for Jev and Gemini Decision.

The request body (`state`, `questions`) and the answer shape (`answers`, `usage`) are the decision protocol shared with
`gemini_decision`, so `build_decision_body` and `decision_measurements` of the package build and read them here too.

TokenLab admits at most 20 calls a minute on a key, and this detector shares its key with the `qwen` agent: every request,
a retry included, goes out through the transport of `rate_limit.py`, which waits for the spacer of the gateway's host, so the
two add up under one ceiling, and sends a passing refusal again after short patient waits, before `post` retries on its own.
"""

import os
import time
from collections.abc import Sequence
from typing import Any

import httpx

from jev_ids.dataset import Flow
from jev_ids.detectors import (
    BACKOFF_SECONDS,
    MAX_ATTEMPTS,
    RETRYABLE_STATUS,
    TIMEOUT_SECONDS,
    DecisionTemplate,
    build_decision_body,
    decision_measurements,
    retry_request,
)
from jev_ids.rate_limit import spaced_transport

API_KEY_VAR = "QWEN_API_KEY"
BASE_URL_VAR = "QWEN_BASE_URL"
DEFAULT_BASE_URL = "https://api.tokenlab.amd.com/v1"
DEFAULT_MODEL = "Clef"
ENDPOINT = "/systemone"
HTTP_OK = 200
# Waiting out a passing refusal for up to almost four minutes before `post` retries, shorter than an agent's patience because
# `post` tries five times: a record gives up only after some 19 minutes of outage, so an outage costs a round one unanswered
# record at most instead of the 10 failed calls in a row that stop it.
PATIENCE: tuple[float, ...] = (15.0, 30.0, 60.0, 120.0)


class SystemOneDetector(DecisionTemplate):
    """Judges one Flow per request to a System One model on an HTTP gateway (`noul` + `choice`)."""

    name = "systemone"
    default_model = DEFAULT_MODEL

    def _ensure_client(self) -> Any:
        if self.client is not None:
            return self.client
        api_key = os.environ.get(API_KEY_VAR)
        if not api_key:
            raise RuntimeError(f"{API_KEY_VAR} environment variable is not set")
        base_url = (os.environ.get(BASE_URL_VAR) or DEFAULT_BASE_URL).rstrip("/")
        self.client = httpx.Client(
            base_url=base_url,
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            timeout=TIMEOUT_SECONDS,
            transport=spaced_transport(base_url, PATIENCE),
        )
        return self.client

    def predict(self, flow: Flow, examples: Sequence[Flow]) -> dict[str, Any]:
        """One `/systemone` request for one Flow, or `error` and `retries`."""
        client = self._ensure_client()
        return post(client, self.model, request_body(self.template, flow, examples, self.record))


def request_body(template: str, flow: Flow, examples: Sequence[Flow], record: str = "compact") -> dict[str, Any]:
    """The `state` and `questions` of one Flow, from a Jev JSON template; the model is added per request."""
    body = build_decision_body(template, flow, examples, record)
    return {"state": body["state"], "questions": body["questions"]}


def attempt(client: Any, model: str, body: dict[str, Any]) -> dict[str, Any]:
    """Execute one POST to the System One endpoint, returning measurements or a retry flag."""
    started = time.perf_counter()
    try:
        response = client.post(ENDPOINT, json={"model": model, **body})
    # Catching a request that got no answer, a network failure or a timeout, which another attempt may repair.
    except httpx.HTTPError as exc:
        return {"error": f"{type(exc).__name__}: {exc}"[:200], "retryable": True}
    if response.status_code != HTTP_OK:
        return {
            "error": f"HTTP {response.status_code}: {response.text[:200]}",
            "retryable": response.status_code in RETRYABLE_STATUS,
        }
    return decision_measurements(response.json(), (time.perf_counter() - started) * 1000, model)


def post(client: Any, model: str, body: dict[str, Any]) -> dict[str, Any]:
    """Retry `attempt` up to `MAX_ATTEMPTS` times on transient or rate-limit errors."""
    return retry_request(
        lambda: attempt(client, model, body),
        max_attempts=MAX_ATTEMPTS,
        backoff_seconds=BACKOFF_SECONDS,
    )
