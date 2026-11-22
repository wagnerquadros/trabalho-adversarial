"""Opt-in integration test for a local Qwen installation."""

from __future__ import annotations

import json
import os
import sys

import httpx
import pytest

from jev_ids.adversarial.cli import probe


@pytest.mark.live
@pytest.mark.skipif(os.getenv("JEV_LIVE") != "1", reason="local model test requires JEV_LIVE=1")
def test_local_probe(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    host = os.getenv("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
    try:
        httpx.get(f"{host}/api/version", timeout=3).raise_for_status()
    except httpx.HTTPError:
        pytest.skip("Ollama is unreachable")
    monkeypatch.setattr(sys, "argv", ["adversarial-sim-probe", "--detector", "qwen3"])
    assert probe() == 0
    manifest, *predictions, _ = capsys.readouterr().out.splitlines()
    assert len(json.loads(manifest)["sha256"]) == 64
    assert len(predictions) == 2
    assert all(json.loads(line)["thinking_disabled_verified"] for line in predictions)
