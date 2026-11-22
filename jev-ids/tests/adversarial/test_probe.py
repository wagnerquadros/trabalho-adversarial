"""Wire-level checks for the local Qwen baseline."""

from __future__ import annotations

import httpx
import pytest

from jev_ids.adversarial.cli import verify_request, verify_response


def test_probe_requires_explicit_false_on_the_wire() -> None:
    for payload in ({}, {"think": True}):
        with pytest.raises(ValueError, match="think=false"):
            verify_request(httpx.Request("POST", "http://localhost/api/chat", json=payload))
    verify_request(httpx.Request("POST", "http://localhost/api/chat", json={"think": False}))


def test_probe_rejects_separate_or_embedded_thinking() -> None:
    for message in ({"thinking": "example"}, {"content": "<think>example</think>"}):
        with pytest.raises(ValueError, match="raciocínio"):
            verify_response(httpx.Response(200, json={"message": message}))
    verify_response(httpx.Response(200, json={"message": {"content": "{}"}}))
