"""Send TokenLab's chat requests as streams, and give the caller back the one chat completion it asked for.

TokenLab queues requests while its model service is busy, and its gateway cuts a non-streaming chat request that has waited there for
about a minute, answering 503 "The model service is temporarily unavailable"; a streaming request keeps its place and is served.
Replaying the attacker's real request on 2026-11-17 showed both: sent plain, it got that 503 after 60 s; sent as a stream, its first
chunk came after 212 s and the whole answer after 302 s. So retrying a plain request only waits for the queue to empty, while a stream
gets through it.

This transport turns every non-streaming `/chat/completions` request into a streaming one, reads the stream to its end and hands back
the single chat completion the caller asked for, so neither the OpenAI SDK nor Agno sees the difference and the model reads the same
request. Every other request, the System One detector's included, goes through untouched.

In reading order:

- `StreamedChatTransport`: the transport, wrapping the one that sends.
- `assemble`: the chat completion a stream of chunks adds up to.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any, cast

import httpx

CHAT_PATH = "/chat/completions"
HTTP_OK = 200
# Answering a stream that broke off or carried an error with a status the spaced transport sends again after a patient wait.
BROKEN_STREAM = 502


class StreamedChatTransport(httpx.BaseTransport):
    """Sends each non-streaming chat request as a stream, and gives back the one chat completion the stream adds up to."""

    def __init__(self, inner: httpx.BaseTransport) -> None:
        """Wrap the transport that sends."""
        self.inner = inner

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        """Stream a plain chat request and answer it with the completion the stream adds up to; pass any other request through.

        A refusal before the stream starts is given back as it came, and a stream that breaks off or carries an error comes back as a
        502, so the transport around this one can send the request again.
        """
        body = _plain_chat_body(request)
        if body is None:
            return self.inner.handle_request(request)
        response = self.inner.handle_request(_as_stream(request, body))
        if response.status_code != HTTP_OK:
            return response
        try:
            completion = assemble(_chunks(response))
        except ValueError as exc:
            return httpx.Response(BROKEN_STREAM, json={"error": {"message": f"the stream broke off: {exc}"}}, request=request)
        finally:
            response.close()
        return httpx.Response(HTTP_OK, json=completion, request=request)

    def close(self) -> None:
        """Close the transport that sends."""
        self.inner.close()


def _plain_chat_body(request: httpx.Request) -> dict[str, Any] | None:
    """The JSON body of a non-streaming chat request; None for any other request."""
    if request.method != "POST" or not request.url.path.endswith(CHAT_PATH):
        return None
    body: Any = json.loads(request.read() or b"{}")
    if not isinstance(body, dict):
        return None
    plain = cast(dict[str, Any], body)
    return None if plain.get("stream") else dict(plain)


def _as_stream(request: httpx.Request, body: dict[str, Any]) -> httpx.Request:
    """The same request asking for a stream that ends with its usage, with the length of the new body."""
    headers = {name: value for name, value in request.headers.items() if name.lower() != "content-length"}
    streamed = {**body, "stream": True, "stream_options": {"include_usage": True}}
    return httpx.Request(request.method, request.url, headers=headers, json=streamed, extensions=request.extensions)


def _chunks(response: httpx.Response) -> Iterator[dict[str, Any]]:
    """The JSON chunks of a server-sent event stream, up to its `[DONE]`."""
    for line in response.iter_lines():
        data = line.removeprefix("data:").strip() if line.startswith("data:") else ""
        if data == "[DONE]":
            return
        if data:
            yield json.loads(data)


@dataclass
class _Answer:
    """What the chunks of a stream have said so far."""

    head: dict[str, Any] = field(default_factory=dict[str, Any])
    content: list[str] = field(default_factory=list[str])
    reasoning: list[str] = field(default_factory=list[str])
    finish_reason: str | None = None
    usage: Any = None

    def absorb(self, chunk: dict[str, Any]) -> None:
        """Add one chunk: the first gives the completion's identity, a later one may close it and carry the usage."""
        if "error" in chunk:
            raise ValueError(f"the stream carried an error: {chunk['error']}")
        self.head = self.head or chunk
        self.usage = chunk.get("usage") or self.usage
        choices: list[dict[str, Any]] = chunk.get("choices") or []
        for choice in choices:
            self._absorb_choice(choice)

    def _absorb_choice(self, choice: dict[str, Any]) -> None:
        delta: dict[str, Any] = choice.get("delta") or {}
        self.content.append(delta.get("content") or "")
        self.reasoning.append(delta.get("reasoning_content") or delta.get("reasoning") or "")
        self.finish_reason = choice.get("finish_reason") or self.finish_reason

    def completion(self) -> dict[str, Any]:
        """The one chat completion the chunks add up to, as a plain request would have got it."""
        if self.finish_reason is None:
            raise ValueError("the stream ended before the answer did")
        message: dict[str, Any] = {"role": "assistant", "content": "".join(self.content) or None}
        reasoning = "".join(self.reasoning)
        if reasoning:
            message["reasoning_content"] = reasoning
        return {
            "id": self.head.get("id"),
            "object": "chat.completion",
            "created": self.head.get("created"),
            "model": self.head.get("model"),
            "choices": [{"index": 0, "message": message, "finish_reason": self.finish_reason}],
            "usage": self.usage,
        }


def assemble(chunks: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """The chat completion a stream of chunks adds up to.

    Raises:
        ValueError: when a chunk carries an error, or the stream ends before a chunk gives the finish reason.
    """
    answer = _Answer()
    for chunk in chunks:
        answer.absorb(chunk)
    return answer.completion()
