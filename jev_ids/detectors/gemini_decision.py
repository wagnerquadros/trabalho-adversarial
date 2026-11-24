"""Google Gemini Decisions API detector (`gemini-decision-1`) through the official `google-genai` SDK.

In reading order:

- `GeminiDecisionDetector`: holds the JSON decision template (`prompts/<dataset>/jev.json`), supports dynamic
  instructions via `instructions` / `set_instructions`, and builds `google.genai.Client` on first call.
- `decision_request`: extracts `input` (the serialized Jev `state`) and `questions` (`noul` + `choice`) from the template.
- `attempt` and `post`: execute one `client.decisions.create(...)` call with exponential backoff on retryable failures.
- `measurements`: normalize `CreateDecisionResponse` (`answers`, `usage`) into the standard prediction row shape.

`client.decisions.create` raises a family of its own, rooted at `GeminiNextGenAPIClientError`, and neither `google.genai.errors.APIError`
(the family of `client.models`) nor `httpx.HTTPError`: the SDK wraps every transport failure into `APIConnectionError` before it leaves.
The classes are defined in `google/genai/_gaos/lib/compat_errors.py` and published as `google.genai._interactions`, the only module that
exports them (the public `google.genai.interactions` holds the types alone), so they are imported from there.
"""

import json
import os
import time
from collections.abc import Sequence
from typing import Any

from google import genai
from google.genai import types
from google.genai._interactions import APIConnectionError, APIStatusError, GeminiNextGenAPIClientError

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

API_KEY_VAR = "GEMINI_API_KEY"
DEFAULT_MODEL = "gemini-decision-1"


class GeminiDecisionDetector(DecisionTemplate):
    """Judges one Flow per request via Google's `decisions.create` API (`noul` + `choice`)."""

    name = "gemini_decision"
    default_model = DEFAULT_MODEL

    def _ensure_client(self) -> Any:
        if self.client is not None:
            return self.client
        api_key = os.environ.get(API_KEY_VAR)
        if not api_key:
            raise RuntimeError(f"{API_KEY_VAR} environment variable is not set")
        # Naming the Gemini API explicitly, because the client otherwise follows `GOOGLE_GENAI_USE_VERTEXAI`, which the `llm:gemini`
        # setup of this repository puts in the environment, and would send this key's requests to Vertex AI.
        self.client = genai.Client(
            api_key=api_key,
            vertexai=False,
            http_options=types.HttpOptions(
                api_version="v1beta",
                timeout=TIMEOUT_SECONDS * 1000,
                retry_options=types.HttpRetryOptions(attempts=1),
            ),
        )
        return self.client

    def predict(self, flow: Flow, examples: Sequence[Flow]) -> dict[str, Any]:
        """One `decisions.create` request for one Flow, or `error` and `retries`."""
        client = self._ensure_client()
        payload = decision_request(self.template, flow, examples, self.record)
        return post(client, self.model, payload)


def decision_request(template: str, flow: Flow, examples: Sequence[Flow], record: str = "compact") -> dict[str, Any]:
    """Convert a Jev JSON template and Flow into `input` (serialized state) and `questions`."""
    body = build_decision_body(template, flow, examples, record)
    return {
        "input": json.dumps(body["state"], ensure_ascii=False),
        "questions": body["questions"],
    }


def attempt(client: Any, model: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Execute one `client.decisions.create` call, returning measurements or a retry flag."""
    started = time.perf_counter()
    try:
        response = client.decisions.create(
            model=model,
            input=payload["input"],
            questions=payload["questions"],
        )
    # Catching a request that got no answer, a network failure or a timeout, which another attempt may repair.
    except APIConnectionError as exc:
        return {"error": f"{type(exc).__name__}: {exc}"[:200], "retryable": True}
    # Catching an HTTP status the API answered with.
    except APIStatusError as exc:
        return {
            "error": f"HTTP {exc.status_code}: {str(exc)[:200]}",
            "retryable": exc.status_code in RETRYABLE_STATUS,
        }
    # Catching the rest of the SDK's own family, such as an answer outside its schema, which no retry repairs.
    except GeminiNextGenAPIClientError as exc:
        return {"error": f"{type(exc).__name__}: {exc}"[:200], "retryable": False}
    return measurements(response, (time.perf_counter() - started) * 1000, model)


def post(client: Any, model: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Retry `attempt` up to `MAX_ATTEMPTS` times on transient or rate-limit errors."""
    return retry_request(
        lambda: attempt(client, model, payload),
        max_attempts=MAX_ATTEMPTS,
        backoff_seconds=BACKOFF_SECONDS,
    )


# The response shape of System One / Decisions is shared; the parser lives in the package.
measurements = decision_measurements
