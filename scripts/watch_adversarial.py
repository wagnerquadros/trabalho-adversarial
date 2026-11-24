"""Follow the adversarial runs while they play: one line per judged round, and how far the round in play has come.

Run from the repository root, in a terminal of its own, and stop it with Ctrl+C at any time:

    uv run python -m scripts.watch_adversarial

It follows the `results/adv_*` run that started or was resumed last and, when that run ends, waits for the next one, so a
chain of runs (one detector after the other) is followed from end to end. It only reads the files a run writes (`config.json`,
`rounds.jsonl` and `predictions.jsonl`), so starting or stopping it never touches the run or its calls.
"""

import argparse
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

RESULTS_DIR = Path("results")
POLL_SECONDS = 5.0
# Reporting the round in play every this many detector calls, so the terminal shows movement without a line per call.
CALLS_PER_REPORT = 10
LABELS = {"gemini_decision": "Gemini Decision", "systemone": "Clef"}


@dataclass
class Follow:
    """What has been shown of the run being followed."""

    run_dir: Path
    rounds_shown: int = 0
    calls_reported: int = 0
    note: str | None = None
    ended: bool = False


def read_config(run_dir: Path) -> dict[str, Any]:
    """The `config.json` a run writes when it starts."""
    return json.loads((run_dir / "config.json").read_text(encoding="utf-8"))


def newest_run(results_dir: Path) -> Path | None:
    """The adversarial run that started or was resumed last, by its `config.json`; None while there is none."""
    runs = [path.parent for path in results_dir.glob("adv_*/config.json")]
    return max(runs, key=last_start, default=None)


def last_start(run_dir: Path) -> str:
    """When a run last started playing: its `started_at`, or the `at` of its latest resumption, both in UTC."""
    config = read_config(run_dir)
    return max([str(config.get("started_at", "")), *(str(entry["at"]) for entry in config.get("resumed", []))])


def read_lines(path: Path) -> list[dict[str, Any]]:
    """The JSON lines of a file the run appends to: none while it does not exist, and a line cut by a write in progress skipped."""
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def round_line(row: dict[str, Any]) -> str:
    """One judged round: its state, its detections and false alarms, and the side that adapts after it."""
    answered = row["attacks_detected"] + row["attacks_passed"]
    who = {"attacker": "atacante", "defender": "defensor"}.get(row["who_adapts"] or "", "ninguém")
    return (
        f"R{row['round']:>2}  {row['state_code']:<9} detectados {row['attacks_detected']:>2}/{answered:<2}  "
        f"falsos alarmes {row['false_alarms']:>2}/{row['total_benign']}  F1 {row['f1']:.2f}  -> {who} ({row['why_adapted']})"
    )


def print_header(run_dir: Path) -> None:
    """Name the run now followed: its folder, detector, round limit and agents."""
    config = read_config(run_dir)
    label = LABELS.get(config["detector"], config["detector"])
    agents = f"atacante {config['attacker_provider']}, defensor {config['defender_provider']}"
    print(f"\n== {run_dir.name}: detector {label}, até {config['max_rounds']} rodadas, {agents}", flush=True)


def show_new_rounds(follow: Follow) -> dict[str, Any] | None:
    """Print the rounds judged since the last look, and the note when it changes; return the last round judged, or None."""
    rows = read_lines(follow.run_dir / "rounds.jsonl")
    for row in rows[follow.rounds_shown :]:
        print(round_line(row), flush=True)
        if row["note"] != follow.note:
            print(f"      nota testada nesta rodada: {row['note'] or '(nenhuma)'}", flush=True)
            follow.note = row["note"]
        follow.calls_reported = 0
    follow.rounds_shown = len(rows)
    return rows[-1] if rows else None


def show_round_in_play(follow: Follow) -> None:
    """Print how many detector calls the round in play has made, once every CALLS_PER_REPORT calls."""
    in_play = follow.rounds_shown + 1
    calls = [row for row in read_lines(follow.run_dir / "predictions.jsonl") if row.get("round") == in_play]
    reported = len(calls) // CALLS_PER_REPORT * CALLS_PER_REPORT
    if reported > follow.calls_reported:
        unanswered = sum(1 for row in calls if row.get("error"))
        print(f"      rodada {in_play} em andamento: {len(calls)} chamadas ao detector, {unanswered} sem resposta", flush=True)
        follow.calls_reported = reported


def judging_next(follow: Follow) -> bool:
    """Whether the detector judged a Flow of the round after the last one shown, as in a run resumed past both sides holding."""
    following = follow.rounds_shown + 1
    return any(row.get("round") == following for row in read_lines(follow.run_dir / "predictions.jsonl"))


def went_on(follow: Follow) -> bool:
    """Whether a run seen ending was resumed (`jev-ids resume`): its last round got an answer, or a round came after it."""
    rows = read_lines(follow.run_dir / "rounds.jsonl")
    later = len(rows) > follow.rounds_shown or judging_next(follow)
    if not later and (not rows or rows[-1]["who_adapts"] is None):
        return False
    print(f"== retomada: a execução segue a partir da rodada {follow.rounds_shown + 1 if later else follow.rounds_shown}", flush=True)
    follow.ended = False
    return True


def look(results_dir: Path, follow: Follow | None) -> Follow | None:
    """One look at the results: follow the newest run, and print what it did since the last look."""
    newest = newest_run(results_dir)
    if newest is None:
        return follow
    if follow is None or newest != follow.run_dir:
        follow = Follow(newest)
        print_header(newest)
    if follow.ended and not went_on(follow):
        return follow
    last = show_new_rounds(follow)
    if last is not None and last["who_adapts"] is None and not judging_next(follow):
        print(f"== fim: {last['why_adapted']} na rodada {last['round']}; aguardando uma retomada ou a próxima execução", flush=True)
        follow.ended = True
    else:
        show_round_in_play(follow)
    return follow


def parse_args() -> argparse.Namespace:
    """The command line: where the runs are written, and how often to look."""
    parser = argparse.ArgumentParser(description="follow the adversarial runs while they play")
    parser.add_argument("--results-dir", type=Path, default=RESULTS_DIR, help="where the adv_* runs are written")
    parser.add_argument("--every", type=float, default=POLL_SECONDS, help="seconds between two looks")
    return parser.parse_args()


def main() -> None:
    """Look at the results every few seconds until Ctrl+C, which stops the watching and never the run."""
    args = parse_args()
    print(f"Acompanhando {args.results_dir} a cada {args.every:g} s. Ctrl+C encerra só o acompanhamento.", flush=True)
    follow: Follow | None = None
    try:
        while True:
            follow = look(args.results_dir, follow)
            time.sleep(args.every)
    except KeyboardInterrupt:
        print("\nAcompanhamento encerrado; a execução continua.", flush=True)


if __name__ == "__main__":
    main()
