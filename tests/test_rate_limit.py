"""The transport that keeps TokenLab's calls under its ceiling and through its outages: spacer, rate, one spacer per host, patience."""

import logging

import httpx
import pytest

from jev_ids import rate_limit
from jev_ids.rate_limit import CallSpacer, calls_per_minute, retry_after, spaced_transport, spacer_for
from tests.helpers import TOKENLAB, FakeClock, fake_transport

Reply = int | Exception


class Gateway:
    """A scripted TokenLab behind the transport: each request gets the next status, or raises the next failure, and is counted."""

    def __init__(self, *replies: Reply, headers: dict[str, str] | None = None) -> None:
        self.replies = list(replies)
        self.headers = headers or {}
        self.calls = 0

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return httpx.Response(reply, headers=self.headers, json={}, request=request)

    def post(self, clock: FakeClock, waits: tuple[float, ...] = ()) -> httpx.Response:
        """One request through a fresh transport over this gateway, spaced on `clock`."""
        with httpx.Client(transport=fake_transport(self.handle, clock, waits)) as client:
            return client.post(f"{TOKENLAB}/systemone", json={})


def test_the_first_call_goes_at_once_and_the_next_waits_out_the_interval() -> None:
    clock = FakeClock()
    spacer = CallSpacer(20, clock=clock.time, sleep=clock.sleep)
    assert spacer.interval == 3.0
    assert spacer.wait() == 0
    assert spacer.wait() == 3.0
    clock.now = 10.0
    # The interval has passed since the last booked start, so nothing is waited.
    assert spacer.wait() == 0
    assert clock.slept == [3.0]


def test_no_minute_holds_more_calls_than_the_rate() -> None:
    clock = FakeClock()
    spacer = CallSpacer(20, clock=clock.time, sleep=clock.sleep)
    starts: list[float] = []
    for _ in range(100):
        spacer.wait()
        starts.append(clock.now)
    # Counting the starts of every minute that opens on a start: the busiest of them all.
    busiest = max(sum(1 for other in starts if start <= other < start + 60) for start in starts)
    assert busiest == 20


def test_the_rate_comes_from_the_environment_and_never_passes_the_ceiling(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(rate_limit.CALLS_PER_MINUTE_VAR, raising=False)
    assert calls_per_minute() == 18.0
    monkeypatch.setenv(rate_limit.CALLS_PER_MINUTE_VAR, "12")
    assert calls_per_minute() == 12.0
    for refused in ("21", "0", "-3", "many"):
        monkeypatch.setenv(rate_limit.CALLS_PER_MINUTE_VAR, refused)
        with pytest.raises(ValueError, match=rate_limit.CALLS_PER_MINUTE_VAR):
            calls_per_minute()
    with pytest.raises(ValueError, match="positive"):
        CallSpacer(0)


def test_every_client_of_a_host_shares_its_spacer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(rate_limit, "_SPACERS", {})
    monkeypatch.delenv(rate_limit.CALLS_PER_MINUTE_VAR, raising=False)
    agent_side = spacer_for(TOKENLAB)
    assert spacer_for("https://API.tokenlab.amd.com/v1/systemone") is agent_side
    assert spaced_transport(TOKENLAB, (15.0,)).spacer is agent_side
    assert spacer_for("https://generativelanguage.googleapis.com/v1beta/openai/") is not agent_side
    assert agent_side.interval == pytest.approx(60 / 18)


def test_every_attempt_waits_its_turn() -> None:
    clock = FakeClock()
    gateway = Gateway(200, 200, 200)
    with httpx.Client(transport=fake_transport(gateway.handle, clock)) as client:
        codes = [client.post(f"{TOKENLAB}/systemone", json={}).status_code for _ in range(3)]
    assert codes == [200, 200, 200]
    assert clock.slept == [3.0, 3.0]


def test_a_passing_refusal_is_sent_again_after_each_wait(caplog: pytest.LogCaptureFixture) -> None:
    clock = FakeClock()
    gateway = Gateway(503, 503, 200)
    with caplog.at_level(logging.WARNING, logger=rate_limit.__name__):
        response = gateway.post(clock, (15.0, 30.0))
    assert (response.status_code, gateway.calls) == (200, 3)
    # The waits run on the spacer's clock, so by the time each retry leaves its interval has long passed.
    assert clock.slept == [15.0, 30.0]
    assert "api.tokenlab.amd.com answered HTTP 503; sending again in 15 s" in caplog.text


def test_the_last_refusal_is_given_back_when_the_waits_run_out() -> None:
    gateway = Gateway(503, 503)
    assert gateway.post(FakeClock(), (15.0,)).status_code == 503
    assert gateway.calls == 2


def test_a_permanent_refusal_is_given_back_at_once() -> None:
    clock = FakeClock()
    gateway = Gateway(400, 200)
    assert gateway.post(clock, (15.0, 30.0)).status_code == 400
    assert (gateway.calls, clock.slept) == (1, [])


def test_the_gateway_may_ask_for_a_longer_wait() -> None:
    clock = FakeClock()
    assert Gateway(429, 200, headers={"Retry-After": "40"}).post(clock, (15.0,)).status_code == 200
    assert clock.slept == [40.0]
    # A date instead of seconds is not read, and the caller's own wait applies.
    assert retry_after(httpx.Response(429, headers={"Retry-After": "Tue, 17 Nov 2026 13:30:00 GMT"})) == 0.0


def test_a_failure_in_transit_is_sent_again_then_raised() -> None:
    assert Gateway(httpx.ConnectError("down"), 200).post(FakeClock(), (15.0,)).status_code == 200
    with pytest.raises(httpx.ConnectError, match="still down"):
        Gateway(httpx.ConnectError("down"), httpx.ConnectError("still down")).post(FakeClock(), (15.0,))
