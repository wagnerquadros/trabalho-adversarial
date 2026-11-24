"""The transport that sends TokenLab's chat requests as streams and gives back the one chat completion each stream adds up to."""

import json
from typing import Any

import httpx

from jev_ids.streamed_chat import BROKEN_STREAM, StreamedChatTransport
from tests.helpers import TOKENLAB, sse

HEAD = {"id": "chatcmpl-7", "object": "chat.completion.chunk", "created": 1794931120, "model": "Qwen3.8-27B"}
ANSWER = '{"action": "remove", "note": "", "rationale": "caught"}'
USAGE = {"prompt_tokens": 1600, "completion_tokens": 640, "total_tokens": 2240}
# A stream as a reasoning model sends one: its thinking, then its answer in two pieces, then the usage on a chunk of its own.
CHUNKS: list[dict[str, Any]] = [
    {
        **HEAD,
        "choices": [{"index": 0, "delta": {"role": "assistant", "reasoning_content": "The note was caught, "}, "finish_reason": None}],
    },
    {**HEAD, "choices": [{"index": 0, "delta": {"reasoning_content": "so remove it."}, "finish_reason": None}]},
    {**HEAD, "choices": [{"index": 0, "delta": {"content": ANSWER[:20]}, "finish_reason": None}]},
    {**HEAD, "choices": [{"index": 0, "delta": {"content": ANSWER[20:]}, "finish_reason": "stop"}]},
    {**HEAD, "choices": [], "usage": USAGE},
]
CHAT_BODY = {"model": "Qwen3.8-27B", "messages": [{"role": "user", "content": "go"}], "temperature": 0.0}


class Gateway:
    """A scripted TokenLab endpoint: each request is kept and answered with the next status and body."""

    def __init__(self, *replies: tuple[int, bytes]) -> None:
        self.replies = list(replies)
        self.requests: list[httpx.Request] = []

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        status, body = self.replies.pop(0)
        return httpx.Response(status, content=body, request=request)

    def post(self, path: str, body: dict[str, Any]) -> httpx.Response:
        """One request to `path` through the streaming transport over this gateway."""
        with httpx.Client(transport=StreamedChatTransport(httpx.MockTransport(self.handle))) as client:
            return client.post(f"{TOKENLAB}{path}", json=body)

    def sent(self, index: int = 0) -> dict[str, Any]:
        """The JSON body of a request the gateway received."""
        return json.loads(self.requests[index].content)


def test_a_plain_chat_request_goes_out_as_a_stream_and_comes_back_as_one_completion() -> None:
    gateway = Gateway((200, sse(CHUNKS)))
    response = gateway.post("/chat/completions", CHAT_BODY)
    # The model reads the same request; only the transport asks for a stream, closed by its usage.
    assert gateway.sent() == {**CHAT_BODY, "stream": True, "stream_options": {"include_usage": True}}
    message = {"role": "assistant", "content": ANSWER, "reasoning_content": "The note was caught, so remove it."}
    assert response.status_code == httpx.codes.OK
    assert response.json() == {
        "id": "chatcmpl-7",
        "object": "chat.completion",
        "created": 1794931120,
        "model": "Qwen3.8-27B",
        "choices": [{"index": 0, "message": message, "finish_reason": "stop"}],
        "usage": USAGE,
    }


def test_any_other_request_goes_through_as_it_is() -> None:
    detector: dict[str, Any] = {"model": "Clef", "state": {}, "questions": {}}
    gateway = Gateway((200, b'{"answers": {}}'), (200, sse(CHUNKS)))
    assert gateway.post("/systemone", detector).json() == {"answers": {}}
    assert gateway.sent(0) == detector
    # A request that already asks for a stream is the caller's own, so it is left as it is, and so is its answer.
    streamed = gateway.post("/chat/completions", {**CHAT_BODY, "stream": True})
    assert gateway.sent(1) == {**CHAT_BODY, "stream": True}
    assert streamed.content == sse(CHUNKS)


def test_a_refusal_before_the_stream_starts_is_given_back_as_it_came() -> None:
    refusal = b'{"error": {"message": "The model service is temporarily unavailable."}}'
    response = Gateway((503, refusal)).post("/chat/completions", CHAT_BODY)
    assert (response.status_code, response.content) == (503, refusal)


def test_a_stream_that_breaks_off_or_carries_an_error_comes_back_as_a_refusal_to_send_again() -> None:
    cut = Gateway((200, sse(CHUNKS[:2], done=False))).post("/chat/completions", CHAT_BODY)
    assert cut.status_code == BROKEN_STREAM
    assert "ended before the answer did" in cut.json()["error"]["message"]
    failed = Gateway((200, sse([{"error": {"message": "overloaded"}}]))).post("/chat/completions", CHAT_BODY)
    assert failed.status_code == BROKEN_STREAM
    assert "carried an error" in failed.json()["error"]["message"]
