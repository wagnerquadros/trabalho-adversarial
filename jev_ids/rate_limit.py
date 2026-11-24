"""Keep the calls to TokenLab under its ceiling and through its outages, for the key the `qwen` agent and the Clef detector share.

TokenLab admits at most 20 calls a minute on a key, whatever the model, and under load it answers that the model service is
temporarily unavailable. The transport here deals with both before a response reaches the OpenAI SDK or the detector:

- every request it sends, a retry included, waits until a fixed interval has passed since the previous request to the same host
  started, and every client of the host shares one spacer, so the attacker's calls and the detector's calls add up under one
  ceiling. The interval is set for `QWEN_CALLS_PER_MINUTE` calls a minute, 18 unless the variable says otherwise, which leaves a
  margin under the 20 for the jitter between the moment a request leaves and the moment the gateway counts it;
- a request the gateway refuses for a passing reason (a status in `RETRYABLE_STATUS`) or that fails in transit is sent again after
  each of the caller's patient waits, longer when the gateway asks for it in `Retry-After`. When the waits run out, the last
  response is given back, or the last failure raised, for the caller's own policy to read: a gateway that stays down still ends
  the run with its error, and a permanent refusal is given back at once.

A chat request also travels as a stream (`streamed_chat.py`), because the gateway cuts a plain one that waits in its queue for about a
minute, which made every patient retry of a busy hour fail the same way.

The spacer lives in one process: two runs on the same key must go one after the other, never side by side.

In reading order:

- `CallSpacer`: the interval of one host and the moment its next request may start.
- `calls_per_minute`: the rate to space for, from the environment, refused above the ceiling.
- `spacer_for`: the one spacer of a host, created on first use.
- `SpacedTransport` and `spaced_transport`: the httpx transport that spaces every attempt and waits out a passing refusal.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections.abc import Callable, Sequence
from urllib.parse import urlsplit

import httpx

from jev_ids.detectors import RETRYABLE_STATUS
from jev_ids.streamed_chat import StreamedChatTransport

CEILING_PER_MINUTE = 20.0
DEFAULT_CALLS_PER_MINUTE = 18.0
# Sharing the QWEN_ prefix of the key and the endpoint the spaced clients read.
CALLS_PER_MINUTE_VAR = "QWEN_CALLS_PER_MINUTE"
SECONDS_PER_MINUTE = 60.0
# Waiting close to an hour in all before a refused request is given back: doubling from 15 s to 4 min, then every 5 min. TokenLab's
# Qwen was down for about 15 and 25 minutes in two outages on 2026-11-17, and a long run must outlive both kinds; the attempts
# made while waiting are a dozen or so, far under the ceiling.
PATIENT_WAITS: tuple[float, ...] = (15.0, 30.0, 60.0, 120.0, 240.0, *([300.0] * 10))

logger = logging.getLogger(__name__)


class CallSpacer:
    """Spaces the starts of requests so that no more than `calls_per_minute` start in any minute.

    Attributes:
        interval: the seconds between the starts of two consecutive requests.
    """

    def __init__(
        self,
        calls_per_minute: float,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        """Set the interval for `calls_per_minute`, on a clock and a sleep that a test can replace."""
        if calls_per_minute <= 0:
            raise ValueError(f"calls per minute must be positive, got {calls_per_minute}")
        self.interval = SECONDS_PER_MINUTE / calls_per_minute
        self._clock = clock
        self._sleep = sleep
        self._next_start = float("-inf")
        self._lock = threading.Lock()

    def wait(self) -> float:
        """Block until the next request may start, and book the slot that follows it.

        Returns:
            The seconds waited: 0 when the interval had already passed.
        """
        with self._lock:
            now = self._clock()
            start = max(now, self._next_start)
            self._next_start = start + self.interval
        delay = start - now
        if delay > 0:
            self._sleep(delay)
        return delay


_SPACERS: dict[str, CallSpacer] = {}
_SPACERS_LOCK = threading.Lock()


def calls_per_minute() -> float:
    """The rate to space for: `QWEN_CALLS_PER_MINUTE`, or 18 when it is unset.

    Raises:
        ValueError: when the variable is not a number above 0 and at most 20, the most the gateway admits.
    """
    raw = os.environ.get(CALLS_PER_MINUTE_VAR)
    if not raw:
        return DEFAULT_CALLS_PER_MINUTE
    try:
        rate = float(raw)
    except ValueError as exc:
        raise ValueError(f"{CALLS_PER_MINUTE_VAR} must be a number, got {raw!r}") from exc
    if not 0 < rate <= CEILING_PER_MINUTE:
        raise ValueError(f"{CALLS_PER_MINUTE_VAR} must be above 0 and at most {CEILING_PER_MINUTE:g}, got {raw}")
    return rate


def spacer_for(base_url: str) -> CallSpacer:
    """The one spacer of the host of `base_url`, created on first use, so every client of that host shares it."""
    host = urlsplit(base_url).netloc.lower()
    with _SPACERS_LOCK:
        spacer = _SPACERS.get(host)
        if spacer is None:
            spacer = CallSpacer(calls_per_minute())
            _SPACERS[host] = spacer
        return spacer


def retry_after(response: httpx.Response) -> float:
    """The seconds the gateway asks a client to wait in `Retry-After`; 0 when it asks for none or not in seconds."""
    try:
        return max(0.0, float(response.headers.get("Retry-After", "")))
    except ValueError:
        return 0.0


class SpacedTransport(httpx.BaseTransport):
    """Sends a request only when its host's spacer gives it a turn, and sends a passing refusal again after patient waits."""

    def __init__(
        self,
        spacer: CallSpacer,
        waits: Sequence[float] = PATIENT_WAITS,
        inner: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        """Keep the host's spacer, the waits before each new attempt and the transport that sends; a test replaces the last two."""
        self.spacer = spacer
        self.waits = tuple(waits)
        self.inner = inner if inner is not None else httpx.HTTPTransport()
        self._sleep = sleep

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        """Send `request` in its turn; a passing refusal or a failure in transit is sent again after each wait, then given back."""
        for wait in self.waits:
            try:
                response = self._send(request)
            except httpx.TransportError as exc:
                self._pause(request, type(exc).__name__, wait)
                continue
            if response.status_code not in RETRYABLE_STATUS:
                return response
            response.close()
            self._pause(request, f"HTTP {response.status_code}", max(wait, retry_after(response)))
        return self._send(request)

    def close(self) -> None:
        """Close the transport that sends."""
        self.inner.close()

    def _send(self, request: httpx.Request) -> httpx.Response:
        self.spacer.wait()
        return self.inner.handle_request(request)

    def _pause(self, request: httpx.Request, reason: str, seconds: float) -> None:
        logger.warning("%s answered %s; sending again in %.0f s", request.url.host, reason, seconds)
        self._sleep(seconds)


def spaced_transport(base_url: str, waits: Sequence[float] = PATIENT_WAITS) -> SpacedTransport:
    """A transport on the shared spacer of the host of `base_url`, with the caller's patient waits.

    Each attempt goes out through `StreamedChatTransport`, so a chat request travels as a stream, which TokenLab's gateway keeps in its
    queue instead of cutting it after a minute; any other request goes out as it is.
    """
    return SpacedTransport(spacer_for(base_url), waits, inner=StreamedChatTransport(httpx.HTTPTransport()))
