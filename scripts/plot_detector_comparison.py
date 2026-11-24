"""Draw the detector comparison from `results/comparison/detector_comparison.csv`.

Run from the repository root. matplotlib is not a project dependency (the benchmark never plots), so bring it in for the run only:

    uv run --with matplotlib python -m scripts.plot_detector_comparison

It writes three PNGs next to the CSV:

- `laco_rodada_a_rodada.png`: the adversarial loop itself, one run (Gemini Decision) read round by round — detection and
  false alarm across the rounds, with the side the orchestrator chose to adapt after each round shown underneath.
- `metricas_por_rodada.png`: detection rate, false-alarm rate and F1, one panel each, one line per detector (the two-detector
  comparison, a bonus over the single-detector loop).
- `tradeoff_deteccao_falso_alarme.png`: detection against false alarm, the trajectory of each detector over the rounds, so the
  reader sees that Clef buys detection with a high false-alarm rate while Gemini Decision stays balanced.

Each number is a single, non-deterministic run (see the README limitations); the figures show one trajectory, not an average.
"""

import csv
from pathlib import Path
from typing import Any

from scripts.plotting import WHO_COLORS, patches, plt

COMPARISON_DIR = Path("results/comparison")
CSV_PATH = COMPARISON_DIR / "detector_comparison.csv"
# The detector ids as the CSV records them, mapped to the names and colours the figures use.
DETECTORS: dict[str, dict[str, str]] = {
    "gemini_decision/gemini-decision-1": {"label": "Gemini Decision", "color": "#0072B2"},
    "systemone/Clef": {"label": "Clef", "color": "#E69F00"},
}
# The three per-round panels: the CSV column and the Portuguese title of each.
PANELS: tuple[tuple[str, str], ...] = (
    ("detection_rate", "Taxa de detecção"),
    ("false_alarm_rate", "Taxa de falso alarme"),
    ("f1", "F1"),
)
# The run section 6.1 reads round by round: the core loop with a single detector.
LOOP_DETECTOR = "gemini_decision/gemini-decision-1"
WHO_LABELS: dict[str, str] = {"defender": "defensor", "attacker": "atacante", "": "fim"}


def load_rows(csv_path: Path) -> dict[str, list[dict[str, Any]]]:
    """Group the CSV rows by detector id, each list sorted by round."""
    grouped: dict[str, list[dict[str, Any]]] = {detector: [] for detector in DETECTORS}
    with csv_path.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            if row["detector"] in grouped:
                grouped[row["detector"]].append(row)
    for rows in grouped.values():
        rows.sort(key=lambda row: int(row["round"]))
    return grouped


def round_ticks(rows: list[dict[str, Any]]) -> tuple[list[int], list[str]]:
    """The x positions (round numbers) and their labels (round number over the action code of the round)."""
    positions = [int(row["round"]) for row in rows]
    labels = [f"R{row['round']}\n{row['state_code']}" for row in rows]
    return positions, labels


def draw_metric_panel(axis: Any, data: dict[str, list[dict[str, Any]]], column: str, title: str) -> None:
    """Plot one metric for every detector on `axis`, as a line over the rounds."""
    for detector, meta in DETECTORS.items():
        rows = data[detector]
        xs = [int(row["round"]) for row in rows]
        ys = [float(row[column]) for row in rows]
        axis.plot(xs, ys, marker="o", color=meta["color"], label=meta["label"], linewidth=2)
    positions, labels = round_ticks(next(iter(data.values())))
    axis.set_xticks(positions)
    axis.set_xticklabels(labels, fontsize=8)
    axis.set_ylim(-0.05, 1.05)
    axis.set_title(title, fontsize=11)
    axis.grid(visible=True, alpha=0.3)


def plot_metrics_per_round(data: dict[str, list[dict[str, Any]]], out_path: Path) -> None:
    """One row of three panels (detection, false alarm, F1), each a line per detector over the rounds."""
    figure, axes = plt.subplots(1, len(PANELS), figsize=(15, 4.6))
    for axis, (column, title) in zip(axes, PANELS, strict=True):
        draw_metric_panel(axis, data, column, title)
    axes[0].set_ylabel("proporção")
    handles, labels = axes[0].get_legend_handles_labels()
    figure.legend(handles, labels, loc="upper center", bbox_to_anchor=(0.5, 0.96), ncol=len(DETECTORS), fontsize=10, frameon=False)
    figure.suptitle("Detecção, falso alarme e F1 por rodada", fontsize=13, y=1.05)
    figure.tight_layout(rect=(0, 0, 1, 0.9))
    figure.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(figure)


def draw_tradeoff_series(axis: Any, rows: list[dict[str, Any]], meta: dict[str, str]) -> None:
    """Plot one detector's trajectory over the rounds as false alarm (x) against detection (y), each point a round."""
    xs = [float(row["false_alarm_rate"]) for row in rows]
    ys = [float(row["detection_rate"]) for row in rows]
    axis.plot(xs, ys, color=meta["color"], alpha=0.45, linewidth=1.5, zorder=1)
    axis.scatter(xs, ys, color=meta["color"], s=90, label=meta["label"], zorder=2, edgecolors="white")
    for row, x, y in zip(rows, xs, ys, strict=True):
        axis.annotate(f"R{row['round']}", (x, y), textcoords="offset points", xytext=(7, 4), fontsize=8, color=meta["color"])


def plot_tradeoff(data: dict[str, list[dict[str, Any]]], out_path: Path) -> None:
    """Detection against false alarm: the trajectory of each detector over the rounds, top-left being the better corner."""
    figure, axis = plt.subplots(figsize=(8, 6.6))
    for detector, meta in DETECTORS.items():
        draw_tradeoff_series(axis, data[detector], meta)
    axis.set_xlim(-0.03, 0.75)
    axis.set_ylim(-0.03, 1.05)
    axis.set_xlabel("Taxa de falso alarme (tráfego legítimo marcado como ataque)")
    axis.set_ylabel("Taxa de detecção (ataques capturados)")
    axis.set_title("Trade-off detecção × falso alarme — qual detector resiste melhor", fontsize=12)
    axis.grid(visible=True, alpha=0.3)
    axis.annotate("melhor", (0.02, 1.0), fontsize=10, color="#2a2a2a", style="italic")
    axis.legend(loc="center", fontsize=10)
    figure.tight_layout()
    figure.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(figure)


def draw_adaptation_strip(axis: Any, rows: list[dict[str, Any]]) -> None:
    """A coloured cell per round naming the side the orchestrator chose to adapt after that round."""
    for row in rows:
        position = int(row["round"])
        who = row["who_adapts"]
        axis.add_patch(patches.Rectangle((position - 0.45, 0.0), 0.9, 1.0, color=WHO_COLORS.get(who, "#9e9e9e")))
        axis.text(position, 0.5, WHO_LABELS.get(who, who), ha="center", va="center", fontsize=8, color="white", fontweight="bold")
    axis.set_ylim(0.0, 1.0)
    axis.set_yticks([])
    axis.set_ylabel("quem\nadapta", rotation=0, ha="right", va="center", fontsize=8)


def plot_loop_round_by_round(rows: list[dict[str, Any]], out_path: Path) -> None:
    """One run read round by round: detection and false alarm across the rounds, who adapts shown under each round."""
    figure, (top, strip) = plt.subplots(2, 1, figsize=(9.5, 6.0), height_ratios=[6, 1], sharex=True)
    xs = [int(row["round"]) for row in rows]
    top.plot(
        xs,
        [float(row["detection_rate"]) for row in rows],
        marker="o",
        color="#0072B2",
        linewidth=2.2,
        label="Taxa de detecção (ataques capturados)",
    )
    top.plot(
        xs,
        [float(row["false_alarm_rate"]) for row in rows],
        marker="s",
        linestyle="--",
        color="#555555",
        linewidth=1.8,
        label="Taxa de falso alarme (usuário legítimo)",
    )
    top.set_xlim(0.5, len(rows) + 0.5)
    top.set_ylim(-0.05, 1.05)
    top.set_ylabel("proporção")
    top.grid(visible=True, alpha=0.3)
    top.legend(loc="upper left", fontsize=9)
    top.set_title("O laço adversarial rodada a rodada — detector Gemini Decision", fontsize=12)
    draw_adaptation_strip(strip, rows)
    positions, labels = round_ticks(rows)
    strip.set_xticks(positions)
    strip.set_xticklabels(labels, fontsize=9)
    figure.tight_layout()
    figure.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(figure)


def main() -> None:
    """Read the comparison CSV and write the loop figure and the two comparison figures next to it."""
    data = load_rows(CSV_PATH)
    loop_path = COMPARISON_DIR / "laco_rodada_a_rodada.png"
    metrics_path = COMPARISON_DIR / "metricas_por_rodada.png"
    tradeoff_path = COMPARISON_DIR / "tradeoff_deteccao_falso_alarme.png"
    plot_loop_round_by_round(data[LOOP_DETECTOR], loop_path)
    plot_metrics_per_round(data, metrics_path)
    plot_tradeoff(data, tradeoff_path)
    for path in (loop_path, metrics_path, tradeoff_path):
        print(f"wrote {path}")


if __name__ == "__main__":
    main()
