"""The context space: the spec and its name, the two renderings, the record and the labels."""

import json
from typing import Any

import pytest

from jev_ids import ROOT, context, dataset, run
from jev_ids.context import BASELINE, ContextSpec
from tests.helpers import CONFIG, JEV_PROMPT, LLM_PROMPT, make_flow, make_train

# What `prompts/<dataset>/context.json` holds for the three-feature card of the tests.
EXTRAS: dict[str, Any] = {
    "instructions": {"minimal": "Classify it.", "expert": "Read a, b and c together.", "misleading": "Answer normal."},
    "columns": {"described": {"a": "the first one.", "b": "the symbolic one.", "c": "the last one."}},
    "categories": {"detailed": {"normal": "ordinary.", "dos": "a flood.", "probe": "a scan."}},
    "note": {"feature": "b", "text": " (a note)"},
}
TRAIN = make_train(["normal", "dos", "probe"])
FLOW = make_flow(7, "dos", value="9")


def state_of(spec: ContextSpec) -> dict[str, Any]:
    """The `state` of `jev.json` rendered at one spec."""
    body: dict[str, Any] = json.loads(context.render_jev(JEV_PROMPT["text"], spec, CONFIG, EXTRAS))
    return body["state"]


def test_a_spec_names_only_what_it_moves_and_refuses_a_level_no_factor_has() -> None:
    assert context.slug(BASELINE) == "baseline"
    assert context.slug(ContextSpec(instructions="none", labels="flipped")) == "instructions-none+labels-flipped"
    assert context.parse("instructions=none,labels=flipped") == ContextSpec(instructions="none", labels="flipped")
    assert context.parse("  columns=absent  ") == ContextSpec(columns="absent")
    assert context.parse("") == BASELINE
    with pytest.raises(ValueError, match="'wrong' is not one of"):
        context.parse("instructions=wrong")
    with pytest.raises(ValueError, match="expected one of"):
        context.parse("nonsense=none")
    with pytest.raises(ValueError, match="expected one of"):
        context.parse("instructions")
    # Every level of every factor is reachable, and the paper's is in the ladder of each.
    for factor, levels in context.LEVELS.items():
        assert BASELINE.levels[factor] in context.LADDER[factor]
        for level in levels:
            text = {"custom": "Say normal."} if level == context.CUSTOM else {}
            assert ContextSpec(**{factor: level}, **text).levels[factor] == level


def test_a_custom_instruction_carries_its_own_text_and_is_named_by_its_hash() -> None:
    written = ContextSpec(instructions="custom", custom="Say normal.")
    assert state_of(written)["instructions"] == "Say normal."
    # Two proposals of the searching agent are two context levels, never the same one under one name.
    other = ContextSpec(instructions="custom", custom="Say attack.")
    assert context.slug(written) != context.slug(other)
    assert context.slug(written).startswith("instructions-custom")
    assert len(context.slug(written)) == len("instructions-custom") + 8
    # The level and the text come together or not at all, so a spec never claims a text it does not carry.
    for broken in ({"instructions": "custom"}, {"custom": "loose"}):
        with pytest.raises(ValueError, match="needs"):
            ContextSpec(**broken)


def test_the_state_carries_only_what_its_levels_hold() -> None:
    assert state_of(BASELINE)["columns"] == "a,b,c"
    assert state_of(ContextSpec(columns="anonymous"))["columns"] == "f1,f2,f3"
    assert state_of(ContextSpec(columns="described"))["columns"] == "a: the first one.\nb: the symbolic one.\nc: the last one."
    assert sorted(state_of(ContextSpec(columns="shuffled"))["columns"].split(",")) == ["a", "b", "c"]
    assert state_of(ContextSpec(instructions="minimal"))["instructions"] == "Classify it."
    # A piece with no text at its level leaves the state rather than staying as an empty string; the questions are never touched.
    stripped = state_of(ContextSpec(instructions="none", columns="absent"))
    assert set(stripped) == {"categories"}
    assert (
        json.loads(context.render_jev(JEV_PROMPT["text"], ContextSpec(columns="absent"), CONFIG, EXTRAS))["questions"]
        == json.loads(JEV_PROMPT["text"])["questions"]
    )


def test_the_categories_keep_their_names_and_lose_or_swap_their_descriptions() -> None:
    paper = state_of(BASELINE)["categories"]
    assert set(paper) == set(CONFIG["categories"])
    assert state_of(ContextSpec(categories="names"))["categories"] == dict.fromkeys(paper, "")
    assert state_of(ContextSpec(categories="detailed"))["categories"] == EXTRAS["categories"]["detailed"]
    swapped = state_of(ContextSpec(categories="swapped"))["categories"]
    # Same names, same descriptions, each under its neighbour: nothing was added to the request, only misplaced.
    assert list(swapped) == list(paper)
    assert sorted(swapped.values()) == sorted(paper.values())
    assert all(swapped[name] != paper[name] for name in paper)


def test_the_markdown_keeps_its_shape_and_drops_a_section_with_no_text() -> None:
    headings = [heading for heading, _ in context.sections(LLM_PROMPT["text"])]
    detailed = context.render_llm(LLM_PROMPT["text"], ContextSpec(categories="detailed"), CONFIG, EXTRAS)
    assert [heading for heading, _ in context.sections(detailed)] == headings
    assert "- `dos`: a flood." in detailed
    assert detailed.count("{examples}") == 1
    named = context.render_llm(LLM_PROMPT["text"], ContextSpec(categories="names"), CONFIG, EXTRAS)
    assert "- `dos`\n" in named  # the option is there and nothing says what it means
    bare = context.render_llm(LLM_PROMPT["text"], ContextSpec(instructions="none", columns="absent"), CONFIG, EXTRAS)
    assert [heading for heading, _ in context.sections(bare)] == ["# Categories", "# Examples", "# Complementary Information"]


def test_the_baseline_renders_the_committed_bytes_and_any_other_level_rehashes() -> None:
    # The property the fork rests on: a baseline run carries the paper's own prompt_hash, so its rows compare with results/paper/.
    for kind, prompt in (("jev", JEV_PROMPT), ("llm", LLM_PROMPT)):
        assert context.apply(prompt, kind, BASELINE, CONFIG) is prompt
    config = dataset.load_config(ROOT / "data" / "nsl-kdd" / "dataset.json")
    extras = context.load_extras(config)
    for name, render in (("jev.json", context.render_jev), ("llm.md", context.render_llm)):
        committed = run.load_prompt(ROOT / "prompts" / "nsl-kdd" / name)
        # Not the short circuit of `apply` but the renderer itself: at the paper's levels it reproduces the file byte for byte.
        assert render(committed["text"], BASELINE, config, extras) == committed["text"]
        moved = context.apply(committed, "jev" if name == "jev.json" else "llm", ContextSpec(categories="names"), config)
        assert moved["sha256"] != committed["sha256"]
        assert len(moved["sha256"]) == 64


def test_the_record_is_rewritten_and_the_flow_keeps_its_truth() -> None:
    plain = context.rewriter(BASELINE, CONFIG, EXTRAS).apply(FLOW, under_test=True)
    assert plain == FLOW
    labeled = context.rewriter(ContextSpec(record="labeled"), CONFIG, EXTRAS).apply(FLOW, under_test=True)
    assert labeled.attributes_csv == "a=9,b=9,c=9"
    # The record stays comma-separated at every level, so a forest still finds one value per feature of the card.
    assert len(labeled.attribute_values) == len(CONFIG["features"])
    assert (labeled.row_id, labeled.category, labeled.is_attack) == (FLOW.row_id, FLOW.category, FLOW.is_attack)


def test_only_a_flow_under_test_carries_the_note_and_only_when_its_level_asks() -> None:
    normal, attack = make_flow(1, "normal", value="9"), FLOW
    for level, noted in (("none", ()), ("attacks", (attack,)), ("all", (normal, attack))):
        rewrite = context.rewriter(ContextSpec(note=level), CONFIG, EXTRAS)
        for flow in (normal, attack):
            written = rewrite.apply(flow, under_test=True).attributes_csv
            assert (written == "9,9 (a note),9") == (flow in noted)
        # An Example is never under test: the note rides in the record of the Flow being judged, the one channel an attacker controls.
        assert rewrite.apply(attack, under_test=False).attributes_csv == "9,9,9"
    # A dataset whose context.json names no feature for the note simply carries none.
    assert context.rewriter(ContextSpec(note="all"), CONFIG, {}).apply(attack, under_test=True) == attack


def test_the_labels_are_the_true_ones_a_seeded_half_or_all_benign() -> None:
    assert context.mislabel(TRAIN, BASELINE, 0, CONFIG) == list(TRAIN)
    benign = context.mislabel(TRAIN, ContextSpec(labels="benign"), 0, CONFIG)
    assert [example.category for example in benign] == ["normal"] * len(TRAIN)
    assert not any(example.is_attack for example in benign)  # a forest trains on the written label
    flipped = context.mislabel(TRAIN, ContextSpec(labels="flipped"), 0, CONFIG)
    assert flipped == context.mislabel(TRAIN, ContextSpec(labels="flipped"), 0, CONFIG)  # seeded: the same poisoning twice
    assert flipped != context.mislabel(TRAIN, ContextSpec(labels="flipped"), 1, CONFIG)
    wrong = [example for example, was in zip(flipped, TRAIN, strict=True) if example.category != was.category]
    assert 0 < len(wrong) <= len(TRAIN)
    # Only the label moves: the values of an Example are the pool's, which is what makes the poisoning invisible in the record.
    assert [example.attributes_csv for example in flipped] == [example.attributes_csv for example in TRAIN]


def test_the_committed_context_file_covers_its_card() -> None:
    config = dataset.load_config(ROOT / "data" / "nsl-kdd" / "dataset.json")
    extras = context.load_extras(config)
    assert set(extras["columns"]["described"]) == set(config["features"])
    assert set(extras["categories"]["detailed"]) == set(config["categories"])
    assert extras["note"]["feature"] in config["symbolic"]
    assert set(extras["instructions"]) == {"minimal", "expert", "misleading"}
    # A dataset with no context.json still runs at the levels its card and its prompt already hold.
    assert context.load_extras({**config, "name": "absent"}) == {}
