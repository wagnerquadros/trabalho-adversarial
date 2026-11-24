"""Draw the long adversarial runs side by side: what each side's move changed, how often each side moved, and the two detectors.

Run from the repository root with the run folders given to `scripts.plot_long_run`. matplotlib is not a project dependency, so
bring it in for the run only:

    uv run --with matplotlib python -m scripts.plot_long_comparison results/<gemini decision run> results/<clef run>

It writes, in `results/comparison/`:

- `laco_longo_jogadas.png`: after each round in which one side changed its action, how detection and false alarm moved in the
  next round, split by the side that moved, with a ring where the attacker removed its note. The note only goes into attack
  records, so after an attacker's move the normal records reach the detector exactly as before: a change in false alarm there
  could only be the detector's own variation.
- `laco_longo_ritmo.png`: how many times each side had changed its action by each round, with a dotted line where the run was
  resumed past a round both sides held in (`jev-ids resume --past-stable`).
- `laco_longo_modelos.png`: the two detectors compared: detection and false alarm over the rounds, every round as a point of
  detection against false alarm with an arrow from the first rounds' mean to the last rounds' mean, and each metric's mean over
  all the rounds of each run.

It prints, per run and side, the mean change after the side's moves. Each run is one non-deterministic trajectory, so a
difference between the detectors is a difference between two runs, not between two averages.
"""

import argparse
from pathlib import Path
from typing import Any

from scripts.plot_long_run import METRICS, MOVING_WINDOW, OUT_DIR, Run, load_run, moving_mean, phase_mean, phases
from scripts.plotting import WHO_COLORS, plt

# The side that changed its action after a round, and how the figures name its move.
SIDES = (("attacker", "atacante mudou\na nota"), ("defender", "defensor mudou\nas instruções"))
EFFECT_METRICS = (("detection_rate", "detecção"), ("false_alarm_rate", "falso alarme"))
# The detector of each run in the first two slots of the categorical palette checked for colour vision deficiency.
MODEL_COLORS = {"gemini_decision": "#2a78d6", "systemone": "#eb6834"}
OTHER_MODEL_COLOR = "#52514e"
INK = "#0b0b0b"
MUTED = "#52514e"
PERCENT = 100
# Spreading the points of one side sideways, by their order, so that equal changes do not hide each other.
JITTER_STEPS = 7
JITTER_WIDTH = 0.04
MEAN_HALF_WIDTH = 0.22
# Leaving room after the last round for the name and the count at the end of each line.
END_LABEL_ROOM = 12
# The kind of move by which the attacker takes its note out, drawn as a ring.
REMOVED = "remove"


def model_color(run: Run) -> str:
    """The colour of the run's detector, the same in every panel."""
    return MODEL_COLORS.get(run.detector, OTHER_MODEL_COLOR)


def save(figure: Any, path: Path) -> None:
    """Lay out, write and close `figure`."""
    figure.tight_layout()
    figure.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(figure)


def move_kind(row: dict[str, Any], side: str) -> str:
    """The kind of move `side` made after `row`, as its `next_action` records it: `reformulate`, `remove`, `custom`, `reinforce`, ..."""
    for part in str(row.get("next_action") or "").split("|"):
        action = part.strip()
        if action.startswith(f"{side}:"):
            return action.split(":", 1)[1].split("->", 1)[0]
    return ""


def move_effects(run: Run, side: str, column: str) -> list[tuple[str, float]]:
    """Each move of `side`: its kind and how `column` changed, in percentage points, from the round before it to the round after."""
    pairs = zip(run.rows, run.rows[1:], strict=False)
    return [
        (move_kind(before, side), (float(after[column]) - float(before[column])) * PERCENT)
        for before, after in pairs
        if before["who_adapts"] == side
    ]


def spread(count: int) -> list[float]:
    """A sideways offset for each of `count` points, repeating every JITTER_STEPS points, the same on every run."""
    return [((index % JITTER_STEPS) - JITTER_STEPS // 2) * JITTER_WIDTH for index in range(count)]


def draw_mean(axis: Any, position: int, changes: list[float]) -> None:
    """The mean of `changes` as a short bar across the strip at `position`, named with its value and the number of moves."""
    mean = sum(changes) / len(changes)
    axis.hlines(mean, position - MEAN_HALF_WIDTH, position + MEAN_HALF_WIDTH, color=INK, linewidth=2, zorder=3)
    label = f"média {mean:+.1f} p.p.\n{len(changes)} jogadas"
    axis.annotate(label, (position + MEAN_HALF_WIDTH, mean), xytext=(6, 0), textcoords="offset points", va="center", fontsize=8)


def draw_points(axis: Any, places: list[float], moves: list[tuple[str, float]], colour: str) -> None:
    """The moves as filled points and the notes removed as rings, so that a retreat is told apart from a new wording."""
    for hollow in (False, True):
        chosen = [(place, change) for place, (kind, change) in zip(places, moves, strict=True) if (kind == REMOVED) == hollow]
        if not chosen:
            continue
        style = {"facecolors": "none", "edgecolors": colour, "linewidths": 1.6} if hollow else {"color": colour, "alpha": 0.65}
        axis.scatter([place for place, _ in chosen], [change for _, change in chosen], s=30, **style)


def draw_effects(axis: Any, run: Run, column: str) -> None:
    """A strip of points per side, each the change in `column` after one of its moves, with the side's mean across it."""
    for position, (side, _) in enumerate(SIDES):
        moves = move_effects(run, side, column)
        draw_points(axis, [position + offset for offset in spread(len(moves))], moves, WHO_COLORS[side])
        if moves:
            draw_mean(axis, position, [change for _, change in moves])
    axis.axhline(0, color=MUTED, linewidth=0.8)
    axis.set_xticks(range(len(SIDES)))
    axis.set_xticklabels([name for _, name in SIDES], fontsize=9)
    axis.set_xlim(-0.6, len(SIDES) - 0.1)
    axis.grid(visible=True, axis="y", alpha=0.3)


def plot_move_effects(runs: list[Run], path: Path) -> None:
    """A row of strips per metric and a column per run: what each side's moves changed in the next round."""
    figure, axes = plt.subplots(len(EFFECT_METRICS), len(runs), figsize=(6.2 * len(runs), 8.4), squeeze=False, sharey="row")
    for row_axes, (column, name) in zip(axes, EFFECT_METRICS, strict=True):
        for axis, run in zip(row_axes, runs, strict=True):
            draw_effects(axis, run, column)
            axis.set_title(f"{run.label}: {name} na rodada seguinte", fontsize=10)
        row_axes[0].set_ylabel("variação (pontos percentuais)")
    ring = plt.Line2D([], [], marker="o", linestyle="none", markerfacecolor="none", markeredgecolor=WHO_COLORS["attacker"])
    figure.legend([ring], ["anel: o atacante retirou a nota"], loc="lower center", bbox_to_anchor=(0.5, -0.02), frameon=False, fontsize=9)
    figure.suptitle(
        "O que cada jogada mudou na rodada seguinte (cada ponto é uma jogada)\n"
        "na detecção, abaixo de zero favorece o atacante e acima favorece o defensor; no falso alarme, abaixo de zero favorece o defensor",
        fontsize=11,
    )
    save(figure, path)


def cumulative_moves(run: Run, side: str) -> list[int]:
    """How many times `side` had changed its action by the end of each round of `run`."""
    counts: list[int] = []
    total = 0
    for row in run.rows:
        total += 1 if row["who_adapts"] == side else 0
        counts.append(total)
    return counts


def draw_past_stable(axis: Any, run: Run) -> None:
    """A dotted line after each round both sides held in that the run was resumed past, named once in the legend."""
    for index, held in enumerate(run.past_stable):
        label = "retomada depois de um stable" if index == 0 else None
        axis.axvline(held + 0.5, color="#7f7f7f", linestyle=":", linewidth=1.6, label=label)


def draw_pace(axis: Any, run: Run) -> None:
    """Both sides' running counts of changes over the rounds of `run`, each named at its end with its total."""
    rounds = [row["round"] for row in run.rows]
    names = {"attacker": "atacante: {} mudanças", "defender": "defensor: {} mudanças"}
    styles = {"attacker": "-", "defender": "--"}
    for side, _ in SIDES:
        counts = cumulative_moves(run, side)
        axis.step(rounds, counts, where="post", color=WHO_COLORS[side], linestyle=styles[side], linewidth=2.2)
        end = (rounds[-1], counts[-1])
        axis.annotate(names[side].format(counts[-1]), end, xytext=(6, 0), textcoords="offset points", va="center", fontsize=9)
    draw_past_stable(axis, run)
    axis.set_xlim(0.5, rounds[-1] + END_LABEL_ROOM)
    axis.set_xticks([1, *range(10, rounds[-1] + 1, 10)])
    axis.set_xlabel("rodada")
    axis.grid(visible=True, alpha=0.3)
    axis.set_title(f"{run.label}: {len(rounds)} rodadas, fim por {run.rows[-1]['why_adapted']}", fontsize=10)
    if run.past_stable:
        axis.legend(loc="upper left", fontsize=8, frameon=False)


def plot_pace(runs: list[Run], path: Path) -> None:
    """A panel per run with how many times each side had changed its action by each round, on one shared scale."""
    figure, axes = plt.subplots(1, len(runs), figsize=(7.2 * len(runs), 4.8), squeeze=False, sharey=True)
    for axis, run in zip(axes[0], runs, strict=True):
        draw_pace(axis, run)
    axes[0][0].set_ylabel("mudanças acumuladas")
    figure.suptitle("O ritmo da disputa: quantas vezes cada lado mudou a própria ação", fontsize=12)
    save(figure, path)


def draw_overlay(axis: Any, runs: list[Run]) -> None:
    """Each run's moving means of detection (solid) and of false alarm (dashed) over the rounds, on one axis."""
    for run in runs:
        rounds = [row["round"] for row in run.rows]
        for column, style, name in (("detection_rate", "-", "detecção"), ("false_alarm_rate", "--", "falso alarme")):
            values = moving_mean([float(row[column]) for row in run.rows], MOVING_WINDOW)
            axis.plot(rounds, values, color=model_color(run), linestyle=style, linewidth=2.2, label=f"{run.label}: {name}")
    axis.set_ylim(0.0, 1.0)
    axis.set_xlim(0.5, max(len(run.rows) for run in runs) + 0.5)
    axis.set_xlabel("rodada")
    axis.set_ylabel(f"média de {MOVING_WINDOW} rodadas")
    axis.grid(visible=True, alpha=0.3)
    axis.legend(loc="upper center", bbox_to_anchor=(0.5, -0.16), ncol=len(runs) * 2, fontsize=9, frameon=False)
    axis.set_title("Detecção (linha cheia) e falso alarme (tracejada) ao longo das rodadas", fontsize=10)


def draw_drift(axis: Any, run: Run) -> None:
    """An arrow from the mean of the first rounds of `run` to the mean of its last rounds, in false alarm and detection."""
    size, first, last = phases(run)
    start = (phase_mean(first, "false_alarm_rate"), phase_mean(first, "detection_rate"))
    end = (phase_mean(last, "false_alarm_rate"), phase_mean(last, "detection_rate"))
    axis.annotate("", xy=end, xytext=start, arrowprops={"arrowstyle": "-|>", "color": model_color(run), "linewidth": 2})
    axis.scatter([end[0]], [end[1]], s=80, color=model_color(run), zorder=3)
    label = f"{run.label}: média das\nrodadas 1–{size} → últimas {size}"
    box = {"boxstyle": "round,pad=0.25", "facecolor": "white", "edgecolor": "none", "alpha": 0.85}
    axis.annotate(label, end, xytext=(12, 10), textcoords="offset points", fontsize=8, color=INK, bbox=box)


def draw_tradeoff(axis: Any, runs: list[Run]) -> None:
    """Every round of each run as a point of detection against false alarm, with the drift from its first to its last rounds."""
    for run in runs:
        alarms = [row["false_alarm_rate"] for row in run.rows]
        detection = [row["detection_rate"] for row in run.rows]
        axis.scatter(alarms, detection, s=20, color=model_color(run), alpha=0.35, linewidths=0, label=f"{run.label}: uma rodada")
        draw_drift(axis, run)
    axis.set_xlim(0.0, 1.0)
    axis.set_ylim(0.0, 1.02)
    axis.set_xlabel("falso alarme")
    axis.set_ylabel("detecção")
    axis.annotate("canto ideal", (0.02, 0.99), fontsize=8, color=MUTED, va="top")
    axis.grid(visible=True, alpha=0.3)
    axis.legend(loc="lower right", fontsize=8, frameon=False)
    axis.set_title("Cada rodada como um ponto: detecção × falso alarme", fontsize=10)


def draw_means(axis: Any, runs: list[Run]) -> None:
    """Each metric's mean over all the rounds of each run, as bars side by side, each named with its value."""
    positions = list(range(len(METRICS)))
    slot = 0.8 / len(runs)
    for index, run in enumerate(runs):
        values = [phase_mean(run.rows, column) for column, _ in METRICS]
        offset = (index - (len(runs) - 1) / 2) * slot
        label = f"{run.label} ({len(run.rows)} rodadas)"
        bars = axis.bar([p + offset for p in positions], values, slot * 0.92, color=model_color(run), label=label)
        axis.bar_label(bars, fmt="%.2f", fontsize=8)
    axis.set_xticks(positions)
    axis.set_xticklabels([name for _, name in METRICS], fontsize=9)
    axis.set_ylim(0.0, 1.12)
    axis.grid(visible=True, axis="y", alpha=0.3)
    axis.legend(loc="upper right", fontsize=8, frameon=False)
    axis.set_title("Média de cada métrica em todas as rodadas", fontsize=10)


def plot_models(runs: list[Run], path: Path) -> None:
    """The detectors compared: the rounds over time on top, the rounds as points and the means of the metrics underneath."""
    figure = plt.figure(figsize=(13, 10))
    grid = figure.add_gridspec(2, 2, height_ratios=[1.0, 1.15])
    draw_overlay(figure.add_subplot(grid[0, :]), runs)
    draw_tradeoff(figure.add_subplot(grid[1, 0]), runs)
    draw_means(figure.add_subplot(grid[1, 1]), runs)
    figure.suptitle(" × ".join(run.label for run in runs) + ": o mesmo laço com dois detectores", fontsize=12)
    save(figure, path)


def describe_effects(run: Run) -> str:
    """One line with the mean change of each metric after each side's moves, as the README quotes them."""
    parts: list[str] = []
    for side, _ in SIDES:
        for column, name in EFFECT_METRICS:
            changes = [change for _, change in move_effects(run, side, column)]
            mean = sum(changes) / len(changes) if changes else 0.0
            parts.append(f"{side} -> {name} {mean:+.1f} pp over {len(changes)} moves")
    return f"{run.label}: " + "; ".join(parts)


def parse_args() -> argparse.Namespace:
    """The command line: the run folders, one per detector, and the folder the figures go to."""
    parser = argparse.ArgumentParser(description="draw the long adversarial runs side by side")
    parser.add_argument("run_dirs", nargs="+", type=Path, help="results/adv_* folders, one per detector")
    parser.add_argument("--out-dir", type=Path, default=OUT_DIR, help="folder the figures are written to")
    return parser.parse_args()


def main() -> None:
    """Read every run, then draw the effects of the moves, the pace of the moves and the detectors compared."""
    args = parse_args()
    runs = [load_run(run_dir) for run_dir in args.run_dirs]
    args.out_dir.mkdir(parents=True, exist_ok=True)
    plot_move_effects(runs, args.out_dir / "laco_longo_jogadas.png")
    plot_pace(runs, args.out_dir / "laco_longo_ritmo.png")
    plot_models(runs, args.out_dir / "laco_longo_modelos.png")
    for run in runs:
        print(describe_effects(run))


if __name__ == "__main__":
    main()
