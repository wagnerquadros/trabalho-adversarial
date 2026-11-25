"""Laya, Convai Innovations' open-source System 1 decision engine, through its HTTP server `laya-serve`.

In reading order:

- `endpoint` and `headers`: where the server is and how to reach it, both read from the environment so that Laya can run on another
  machine: LAYA_BASE_URL (default `http://127.0.0.1:8000`) and LAYA_API_KEY, sent as a bearer token when set.
- `LayaDetector`: holds the request template of `prompts/<dataset>/jev.json`, the very file Jev reads; `predict` judges one Flow per
  request.
- `attempt`: one POST to `/v1/systemone`, retried by Jev's `post` under Jev's policy.
- `measurements`: what one successful answer measured.

Laya answers the same typed questions as Jev (`noul`, `choice`) over the same `state`, so switching between the two changes the Detector and
never the request: `jev.request_body` builds it, and only `model` (a Laya checkpoint instead of `jev-1.13.0`) and `max_len` differ. The
checkpoint matters here. The English `laya` checkpoint reads 512 tokens, while the NSL-KDD request is about 1,000 tokens at k = 0 and 7,000
at k = 8, so the default is `multilingual` with `max_len` 8,192, the one checkpoint whose budget holds every k; with any other the server
cuts the context without a word, and a study of context would measure the cut. Laya runs on your own hardware and bills nothing, so
prices.json has no entry for it.
"""

import functools
import os
import time
from collections.abc import Sequence
from typing import Any

import requests

from jev_ids.dataset import Flow
from jev_ids.detectors import jev

BASE_URL_VAR = "LAYA_BASE_URL"
API_KEY_VAR = "LAYA_API_KEY"
DEFAULT_BASE_URL = "http://127.0.0.1:8000"
SYSTEM_ONE_PATH = "/v1/systemone"
DEFAULT_MODEL = "multilingual"
MAX_LEN = 8192
TIMEOUT_SECONDS = 60


def endpoint() -> str:
    """The URL of `POST /v1/systemone` on the server that LAYA_BASE_URL names."""
    return os.environ.get(BASE_URL_VAR, DEFAULT_BASE_URL).rstrip("/") + SYSTEM_ONE_PATH


def headers() -> dict[str, str]:
    """A bearer token when LAYA_API_KEY is set, which `laya-serve` then requires; nothing otherwise."""
    key = os.environ.get(API_KEY_VAR)
    return {"Authorization": f"Bearer {key}"} if key else {}


class LayaDetector:
    """Judges one Flow per request to a `laya-serve` server, retrying while it is unreachable or overloaded."""

    name = "laya"

    def __init__(self, prompt: dict[str, Any], model_id: str | None = None) -> None:
        """Keep the template and open an HTTP session to the server of LAYA_BASE_URL.

        Args:
            prompt: `run.load_prompt` of `prompts/<dataset>/jev.json`, the request body without the Flow and the Examples.
            model_id: the Laya checkpoint (`english`, `multilingual`, ...); None means `multilingual`.
        """
        self.template: str = prompt["text"]
        self.prompt_hash: str = prompt["sha256"]
        self.model = model_id or DEFAULT_MODEL
        # Read once, after the CLI loaded `.env`; every call of this Detector goes to the same server.
        self.url = endpoint()
        self.session = requests.Session()
        self.session.headers.update(headers())

    def predict(self, flow: Flow, examples: Sequence[Flow]) -> dict[str, Any]:
        """One request for one Flow: what it measured, or `error` and `retries`."""
        body = jev.request_body(self.template, flow, examples)
        body["model"] = self.model
        body["max_len"] = MAX_LEN
        return jev.post(functools.partial(attempt, self.session, self.url, body))


def attempt(session: requests.Session, url: str, body: dict[str, Any]) -> dict[str, Any]:
    """One request: the measurements on success, else `error` and `retryable`.

    A refused connection, a timeout and the statuses Jev retries on earn another attempt; any other status fails at once, with the first
    200 characters of the server's message. An answer without the two questions is an error row too, never a crash.
    """
    started = time.perf_counter()
    try:
        response = session.post(url, json=body, timeout=TIMEOUT_SECONDS)
    except requests.RequestException as exc:  # connection refused, timeout, reset
        return {"error": f"{type(exc).__name__}: {exc}"[:500], "retryable": True}
    latency_ms = (time.perf_counter() - started) * 1000
    if not response.ok:
        return {"error": f"HTTP {response.status_code}: {response.text[:200]}", "retryable": response.status_code in jev.RETRYABLE_STATUS}
    try:
        return measurements(response.json(), latency_ms)
    except (ValueError, KeyError, TypeError, AttributeError) as exc:  # not JSON, or not the shape of an answer
        return {"error": f"parse: {type(exc).__name__}: {exc}"[:300], "retryable": False}


def measurements(body: dict[str, Any], latency_ms: float) -> dict[str, Any]:
    """What one answer measured, plus the whole body as `raw` for responses.jsonl.

    As for Jev, p_attack is the `noul` answer, and the Category and its confidence come from the `choice` answer. Laya's `noul` answer also
    carries a confidence, which Jev's lacks, kept as `attack_confidence`. `usage` is the server's own token report.
    """
    answers: dict[str, Any] = body["answers"]
    return {
        "p_attack": answers["is_attack"].get("noul"),
        "attack_confidence": answers["is_attack"].get("confidence"),
        "category_pred": answers["category"].get("choice"),
        "confidence": answers["category"].get("confidence"),
        "latency_ms": latency_ms,
        "usage": body.get("usage", {}),
        "raw": body,
    }
