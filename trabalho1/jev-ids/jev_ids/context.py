"""The context space: what a Detector is told around the Flow, and the knobs that change it.

In reading order:

- `LADDER` and `ADVERSARIAL`: the levels of each factor, the first ordered from least context to most, the second outside that order.
- `ContextSpec`, `BASELINE`, `slug` and `parse`: one point of the space, the paper's point, its name and the CLI's `factor=level` list.
- `load_extras`: `prompts/<dataset>/context.json`, the text the levels above the paper's need.
- `column_names`, `columns_text`, `instructions_text`, `categories_text`: one piece of the state at the level the spec asks for.
- `render` and `apply`: the whole prompt file at that level, rehashed; the baseline returns the committed bytes untouched.
- `Rewriter` and `rewriter`: the Flow as the Detector will read it, and the labels the Examples carry.

A Detector's accuracy is a function of the Flow *and* of everything around it: the task description, the column names, the category
descriptions, the shape of the record, the labels on the Examples. The paper held all of that fixed and moved k alone. This module makes
each of them a factor with its own levels, so a run can be placed anywhere in the space and two runs compared one factor apart.

Two rules keep the comparison honest. The questions never change: only the `state` does, so a difference between two runs is a difference
of context and not of what was asked. And the baseline is the paper's own bytes: `render` returns the file untouched at `BASELINE`, so a
baseline run of this fork carries the same `prompt_hash` as the runs of `results/paper/` and can be compared with them as equals.

The adversarial levels are the point of the fork: a context that misinforms rather than informs, measured the same way as one that informs.
What they say lives in `prompts/<dataset>/context.json`, beside the prompt they belong to, never in this file.
"""

import hashlib
import json
import random
from collections.abc import Sequence
from dataclasses import dataclass, fields, replace
from typing import Any

from jev_ids import ROOT
from jev_ids.dataset import Config, Flow

# The text a level above the paper's needs, as `prompts/<dataset>/context.json` holds it.
Extras = dict[str, Any]

# Each factor's levels in order, from the least context to the most; the paper's level is the field default of `ContextSpec`.
LADDER: dict[str, tuple[str, ...]] = {
    "instructions": ("none", "minimal", "paper", "expert"),
    "columns": ("absent", "anonymous", "named", "described"),
    "categories": ("names", "paper", "detailed"),
    "record": ("csv", "labeled"),
    "labels": ("true",),
    "note": ("none",),
}
# The levels outside the ladder: a context that misinforms. `misleading` argues for the benign label, `shuffled` names the columns in the
# wrong order, `swapped` gives each Category another's description, `flipped` and `benign` mislabel the Examples, and `attacks` and `all`
# put a note inside the record itself, the one channel an attacker controls.
ADVERSARIAL: dict[str, tuple[str, ...]] = {
    "instructions": ("misleading", "custom"),
    "columns": ("shuffled",),
    "categories": ("swapped",),
    "record": (),
    "labels": ("flipped", "benign"),
    "note": ("attacks", "all"),
}
LEVELS: dict[str, tuple[str, ...]] = {factor: LADDER[factor] + ADVERSARIAL[factor] for factor in LADDER}
FACTORS: tuple[str, ...] = tuple(LADDER)
# `instructions = custom` reads its text from the spec's own `custom` field instead of a file: the level the searching agent writes into
# (`agent.py`), where every other level is a level someone chose in advance.
CUSTOM = "custom"
# The headings of `llm.md` that hold the state; `# Examples` and `# Complementary Information` are the placeholder and the answer format,
# which no factor touches. A test asserts the committed files still carry them.
HEADINGS = {"instructions": "# Overview", "categories": "# Categories", "columns": "# Columns of a record (in order)"}
# The share of Examples that `labels = flipped` mislabels.
FLIP_SHARE = 0.5


@dataclass(frozen=True)
class ContextSpec:
    """One point of the context space; every default is the paper's level.

    Attributes:
        instructions: the task description in the state.
        columns: how the columns of a record are named, if at all.
        categories: how much each Category is described.
        record: how a Flow's values are written out.
        labels: what the Examples are labeled with.
        note: whether a note travels inside the record of the Flow under test.
        custom: the task description of `instructions = custom`; empty at every other level.
    """

    instructions: str = "paper"
    columns: str = "named"
    categories: str = "paper"
    record: str = "csv"
    labels: str = "true"
    note: str = "none"
    custom: str = ""

    def __post_init__(self) -> None:
        """Refuse a level no factor has, so a typo fails before the first call is paid for."""
        for factor, level in self.levels.items():
            if level not in LEVELS[factor]:
                raise ValueError(f"{factor}: {level!r} is not one of {LEVELS[factor]}")
        if (self.instructions == CUSTOM) != bool(self.custom):
            raise ValueError("instructions = custom needs a `custom` text, and a `custom` text needs that level")

    @property
    def levels(self) -> dict[str, str]:
        """The level of every factor, in declaration order; `custom` is text, not a factor, and is not among them."""
        return {field.name: getattr(self, field.name) for field in fields(self) if field.name in LEVELS}


BASELINE = ContextSpec()


def slug(spec: ContextSpec) -> str:
    """A filename-safe name for a spec: its levels away from the paper's, or `baseline`.

    The name goes into the run directory and into every row, so a table of runs reads as the experiment it was. A `custom` text is named
    by the first eight characters of its sha256, so two proposals of the searching agent never share a name.
    """
    written = hashlib.sha256(spec.custom.encode("utf-8")).hexdigest()[:8] if spec.custom else ""
    apart = [
        f"{factor}-{level}{written if level == CUSTOM else ''}" for factor, level in spec.levels.items() if level != BASELINE.levels[factor]
    ]
    return "+".join(apart) if apart else "baseline"


def parse(text: str) -> ContextSpec:
    """A spec from the CLI's `factor=level` list: `instructions=none,columns=absent`.

    Unnamed factors keep the paper's level, so a spec states only what it moves.
    """
    chosen: dict[str, str] = {}
    for part in filter(None, (piece.strip() for piece in text.split(","))):
        factor, separator, level = part.partition("=")
        if not separator or factor not in LEVELS:
            raise ValueError(f"{part!r}: expected one of {tuple(LEVELS)} as `factor=level`")
        chosen[factor] = level
    return ContextSpec(**chosen)


def load_extras(config: Config) -> Extras:
    """`prompts/<dataset>/context.json`: the text of every level the committed prompt does not already hold.

    A dataset without the file can still be run at the levels derived from its card and its prompt; a level that needs text the file does
    not have raises when it is rendered, not here.
    """
    path = ROOT / "prompts" / config["name"] / "context.json"
    extras: Extras = json.loads(path.read_bytes()) if path.exists() else {}
    note: str = extras.get("note", {}).get("text", "")
    if "," in note:
        raise ValueError(f"{path}: the note goes inside a comma-separated record and cannot hold a comma")
    return extras


def level_text(extras: Extras, factor: str, level: str) -> Any:
    """The entry of `context.json` for one level; its absence is an error naming the file."""
    found: Any = extras.get(factor, {}).get(level)
    if found is None:
        raise ValueError(f"prompts/<dataset>/context.json has no {factor}.{level}")
    return found


def column_names(spec: ContextSpec, config: Config) -> tuple[str, ...]:
    """The names the columns carry at this level: the card's, anonymous ones, or the card's in the wrong order.

    The shuffle is seeded by the factor's own name, so the wrong order is the same wrong order in every run.
    """
    features: list[str] = list(config["features"])
    if spec.columns == "anonymous":
        return tuple(f"f{index + 1}" for index in range(len(features)))
    if spec.columns == "shuffled":
        random.Random("shuffled").shuffle(features)  # noqa: S311  # seeded, not secret
    return tuple(features)


def columns_text(spec: ContextSpec, config: Config, extras: Extras) -> str | None:
    """The `columns` entry of the state, or None when the level holds none.

    `described` is the rung above the paper's: one line per column, the name and what it counts, in card order.
    """
    names = column_names(spec, config)
    if spec.columns == "absent":
        return None
    if spec.columns != "described":
        return ",".join(names)
    described: dict[str, str] = level_text(extras, "columns", "described")
    return "\n".join(f"{name}: {described[name]}" for name in names)


def instructions_text(paper: str, spec: ContextSpec, extras: Extras) -> str | None:
    """The `instructions` entry of the state: the paper's own text, the spec's own, one of the file's, or none at all."""
    if spec.instructions == "none":
        return None
    if spec.instructions == "paper":
        return paper
    if spec.instructions == CUSTOM:
        return spec.custom
    return level_text(extras, "instructions", spec.instructions)


def categories_text(paper: dict[str, str], spec: ContextSpec, extras: Extras) -> dict[str, str]:
    """The `categories` entry of the state, one description per Category of the card.

    `names` leaves every description empty, so the options are there and nothing says what they mean; `swapped` rotates the descriptions
    by one, so each Category is described as its neighbour, the deception that keeps the same words in the same request.
    """
    if spec.categories == "names":
        return dict.fromkeys(paper, "")
    if spec.categories == "detailed":
        detailed: dict[str, str] = level_text(extras, "categories", "detailed")
        return {name: detailed[name] for name in paper}
    if spec.categories == "swapped":
        rotated = [*list(paper)[1:], *list(paper)[:1]]
        return {name: paper[other] for name, other in zip(paper, rotated, strict=True)}
    return paper


def render_jev(template: str, spec: ContextSpec, config: Config, extras: Extras) -> str:
    """`jev.json` with its state at this spec's levels; the questions are untouched.

    A piece with no text at its level leaves the state, so the model is given nothing rather than an empty string. The questions still
    name it in backticks, and that dangling path is the condition being measured: what the Detector does without it.
    """
    body: dict[str, Any] = json.loads(template)
    state: dict[str, Any] = body["state"]
    pieces = {"instructions": instructions_text(state["instructions"], spec, extras), "columns": columns_text(spec, config, extras)}
    for name, text in pieces.items():
        if text is None:
            del state[name]
        else:
            state[name] = text
    state["categories"] = categories_text(state["categories"], spec, extras)
    return json.dumps(body, indent=2, ensure_ascii=False) + "\n"


def sections(text: str) -> list[tuple[str, str]]:
    """A Markdown file split at its top-level headings: the heading line and the body under it, stripped of its blank lines."""
    found: list[tuple[str, str]] = []
    heading: str = ""
    body: list[str] = []
    for line in text.splitlines():
        if line.startswith("# "):
            if heading:
                found.append((heading, "\n".join(body).strip("\n")))
            heading, body = line, []
        else:
            body.append(line)
    if heading:
        found.append((heading, "\n".join(body).strip("\n")))
    return found


def render_llm(template: str, spec: ContextSpec, config: Config, extras: Extras) -> str:
    """`llm.md` with the three state sections at this spec's levels; a section with no text at its level is dropped whole.

    The categories keep the file's bullet shape, and `{examples}` and the answer format travel untouched, so the only difference between
    two renderings is the context.
    """
    parts = sections(template)
    paper = dict(parts)
    described = categories_text(bullets(paper[HEADINGS["categories"]]), spec, extras)
    bodies: dict[str, str | None] = {
        HEADINGS["instructions"]: instructions_text(paper[HEADINGS["instructions"]], spec, extras),
        # A Category with no description at its level is a bare bullet, not a dangling colon that reads as a truncated file.
        HEADINGS["categories"]: "\n".join(f"- `{name}`: {text}" if text else f"- `{name}`" for name, text in described.items()),
        HEADINGS["columns"]: columns_text(spec, config, extras),
    }
    kept = ((heading, bodies.get(heading, body)) for heading, body in parts)
    return "\n\n".join(f"{heading}\n\n{body}" for heading, body in kept if body is not None) + "\n"


def bullets(body: str) -> dict[str, str]:
    """The bullet lines of a section, `- <name in backticks>: description`, as a mapping in file order."""
    found: dict[str, str] = {}
    for line in body.splitlines():
        name, separator, description = line.removeprefix("- `").partition("`: ")
        if separator:
            found[name] = description
    return found


def apply(prompt: dict[str, Any], kind: str, spec: ContextSpec, config: Config) -> dict[str, Any]:
    """A loaded prompt rendered at `spec`, rehashed; at the baseline it is returned as it was read.

    The hash is of the rendered bytes, so `prompt_hash` tells two context levels apart in every row, and a baseline run of this fork
    carries the hash of the paper's own file.
    """
    if spec == BASELINE:
        return prompt
    render = render_jev if kind == "jev" else render_llm
    text = render(prompt["text"], spec, config, load_extras(config))
    return {"text": text, "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()}


@dataclass(frozen=True)
class Rewriter:
    """Turns a Flow into the record a Detector reads, at one spec's levels.

    Attributes:
        names: the column names of the spec, for the labeled record.
        labeled: whether each value is written as `name=value`.
        note: `none`, `attacks` or `all`: which Flows under test carry the note.
        text: what the note says, appended to the value of one symbolic feature.
        index: the index of that feature in card order, -1 when the dataset names none.
    """

    names: tuple[str, ...]
    labeled: bool
    note: str
    text: str
    index: int

    def noted(self, flow: Flow) -> bool:
        """Whether this Flow under test carries the note: every Flow, the attacks alone, or none."""
        return self.index >= 0 and (self.note == "all" or (self.note == "attacks" and flow.is_attack))

    def apply(self, flow: Flow, *, under_test: bool) -> Flow:
        """The Flow as the Detector will read it; only a Flow under test can carry the note.

        The record stays comma-separated at every level, so the Flow a forest encodes is still the Flow the card describes.
        """
        values = list(flow.attribute_values)
        if under_test and self.noted(flow):
            values[self.index] = values[self.index] + self.text
        pairs = zip(self.names, values, strict=True)
        written = ",".join(f"{name}={value}" for name, value in pairs) if self.labeled else ",".join(values)
        return replace(flow, attributes_csv=written)


def rewriter(spec: ContextSpec, config: Config, extras: Extras) -> Rewriter:
    """The `Rewriter` of a spec; the note's feature and text come from `context.json`."""
    note: dict[str, Any] = extras.get("note", {}) if spec.note != "none" else {}
    feature: str | None = note.get("feature")
    index = config["features"].index(feature) if feature in config["features"] else -1
    return Rewriter(column_names(spec, config), spec.record == "labeled", spec.note, note.get("text", ""), index)


def mislabel(examples: Sequence[Flow], spec: ContextSpec, seed: int, config: Config) -> list[Flow]:
    """The Examples with the labels the spec asks for: the true ones, a seeded half made wrong, or every attack called benign.

    The values of an Example never change, only the Category written beside it, so what a Detector reads is a plausible record under a
    wrong label: the poisoning a Detector cannot see. `is_attack` follows the written label, because that is what a forest trains on.
    """
    if spec.labels == "true":
        return list(examples)
    benign: str = config["benign"]
    categories: list[str] = config["categories"]
    stream = random.Random(f"{seed}:{spec.labels}")  # noqa: S311  # seeded, not secret
    poisoned: list[Flow] = []
    for example in examples:
        others = [name for name in categories if name != example.category]
        wrong = benign if spec.labels == "benign" else stream.choice(others)
        keep = spec.labels == "flipped" and stream.random() >= FLIP_SHARE
        label = example.category if keep or not others else wrong
        poisoned.append(replace(example, category=label, is_attack=label != benign))
    return poisoned
