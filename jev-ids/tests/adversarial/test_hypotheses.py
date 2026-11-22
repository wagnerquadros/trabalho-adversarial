"""Paired defensive measurements on original flows."""

from __future__ import annotations

import hashlib
import json

import pytest

from jev_ids import ROOT
from jev_ids.adversarial.analysis import hypotheses
from jev_ids.dataset import Flow
from jev_ids.run import load_prompt


def test_sampling_repeats_without_changing_source() -> None:
    pilot = tuple(Flow(i, f"service-{i}", "normal" if i % 2 else "dos", not i % 2) for i in range(12))
    sample = hypotheses.paired_batch(pilot, 3, 14)
    assert sample == hypotheses.paired_batch(pilot, 3, 14)
    assert sum(row.is_attack for row in sample) == 3
    assert len({row.row_id for row in sample}) == 6
    assert all(row in pilot for row in sample)
    with pytest.raises(ValueError):
        hypotheses.paired_batch(pilot, 0, 14)


@pytest.mark.parametrize(("model", "filename"), [("qwen3", "llm.md"), ("laya", "jev.json")])
def test_only_instructions_change(model: str, filename: str) -> None:
    source = ROOT / "prompts/nsl-kdd" / filename
    basic = load_prompt(source)
    reinforced = hypotheses.reinforced_prompt(basic, model)
    assert reinforced["sha256"] == hashlib.sha256(reinforced["text"].encode()).hexdigest()
    assert reinforced["sha256"] != basic["sha256"]
    if model == "laya":
        original = json.loads(basic["text"])
        revised = json.loads(reinforced["text"])
        assert revised["state"]["instructions"].startswith(original["state"]["instructions"])
        revised["state"]["instructions"] = original["state"]["instructions"]
        assert revised == original
    else:
        assert reinforced["text"].split("# Categories")[1:] == basic["text"].split("# Categories")[1:]
    assert load_prompt(source) == basic
