"""The command line: `jev-ids run|sweep|redo-errors|metrics|compare`, also reachable as `python -m jev_ids`.

In reading order:

- `parse_k` and `parse_list`: the list arguments (`--k 0,1,all`); `levels_help` and `parse_factors`, the context arguments.
- `build_parser`: the five subcommands and their arguments.
- `run_command`, `sweep_command`, `redo_command`, `metrics_command`, `compare_command`: one handler per subcommand, each turning the
  parsed arguments into calls of `run`, `agent` or `metrics`.
- `print_csv`: a table as CSV on stdout.
- `main`: parse, dispatch, return the exit code.

Nothing here knows how a Detector or a metric works, and no dataset is named here: `run` takes the card of the dataset as `--dataset`.
`run --context` fixes one point of the context space by hand; `sweep` hands the choice to the agent of `agent.py`.
"""

import argparse
import csv
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from jev_ids import ROOT, agent, context, metrics, run
from jev_ids.records import read_predictions


def levels_help() -> str:
    """Every factor of the context space and its levels, for the `--context` help line."""
    return "; ".join(f"{factor}={'|'.join(levels)}" for factor, levels in context.LEVELS.items())


def parse_factors(text: str) -> tuple[str, ...]:
    """The comma-separated factors a sweep may move: `--factors instructions,columns`."""
    chosen = tuple(part.strip() for part in text.split(",") if part.strip())
    unknown = [factor for factor in chosen if factor not in context.FACTORS]
    if unknown:
        raise ValueError(f"{unknown}: the factors are {context.FACTORS}")
    return chosen


def parse_k(text: str) -> int | None:
    """One k: an integer, or `all` for the whole pool (Random Forest only)."""
    return None if text.strip() == "all" else int(text)


def parse_list(text: str) -> tuple[int | None, ...]:
    """A comma-separated list of integers: `--k 0,1,2,all` and `--seeds 0,1,2`.

    Both arguments are read the same way, so `all` is accepted for `--seeds` too, where it means nothing; nobody writes it and one parser is
    worth that much looseness.
    """
    return tuple(parse_k(part) for part in text.split(","))


def build_parser() -> argparse.ArgumentParser:
    """The four subcommands; each one carries the function that handles it."""
    parser = argparse.ArgumentParser(prog="jev-ids")
    commands = parser.add_subparsers(dest="command", required=True)

    runner = commands.add_parser("run", help="run one detector over one split")
    runner.add_argument("--dataset", required=True, type=Path, help="the card: data/<name>/dataset.json")
    runner.add_argument(
        "--detector",
        required=True,
        help="jev, laya, llm:deepseek, llm:openai, llm:gemini, llm:ollama, random_forest or isolation_forest",
    )
    runner.add_argument("--split", required=True, help="internal, pilot, smoke, ...")
    runner.add_argument(
        "--k",
        type=parse_list,
        default=(0, 1, 2, 4, 8),
        help="examples per category, comma separated; `all` for the forests",
    )
    runner.add_argument("--seeds", type=parse_list, default=(0, 1, 2), help="seeds of the example draws")
    runner.add_argument("--reps", type=int, default=1, help="repetitions of each (k, seed) cell")
    runner.add_argument("--model", help="provider model id, for the LLM detectors and Laya")
    runner.add_argument("--results-dir", type=Path, default=run.RESULTS_DIR, help="where the run directory is created")
    runner.add_argument(
        "--context",
        type=context.parse,
        default=context.BASELINE,
        help=f"context levels as `factor=level`, comma separated; unnamed factors keep the paper's. Factors: {levels_help()}",
    )
    runner.set_defaults(handler=run_command)

    sweeper = commands.add_parser("sweep", help="move through the context space and report what each level did to the detector")
    sweeper.add_argument("--dataset", required=True, type=Path, help="the card: data/<name>/dataset.json")
    sweeper.add_argument("--detector", required=True, help="the detector under study, as in `run`")
    sweeper.add_argument("--split", required=True, help="internal, pilot, smoke, ...")
    sweeper.add_argument("--k", type=parse_list, default=(1,), help="examples per category; one value keeps the sweep about context")
    sweeper.add_argument("--seeds", type=parse_list, default=(0,), help="seeds of the example draws")
    sweeper.add_argument("--model", help="provider model id, for the LLM detectors and Laya")
    sweeper.add_argument("--strategy", choices=agent.STRATEGIES, default="ladder", help="how the agent picks the next context level")
    sweeper.add_argument("--objective", choices=agent.OBJECTIVES, default="max", help="max raises the detector's F1, min lowers it")
    sweeper.add_argument("--factors", type=parse_factors, default=context.FACTORS, help=f"factors to move: {','.join(context.FACTORS)}")
    sweeper.add_argument("--budget", type=int, default=12, help="the most context levels to run, the baseline among them")
    sweeper.add_argument("--no-adversarial", action="store_true", help="stay on the ladder: no level that misinforms")
    sweeper.add_argument("--attacker", default="llm:deepseek", help="the llm:<provider> that writes the levels of `--strategy attack`")
    sweeper.add_argument("--attacker-model", help="that provider's model id")
    sweeper.add_argument("--results-dir", type=Path, default=run.RESULTS_DIR, help="where the sweep directory is created")
    sweeper.set_defaults(handler=sweep_command)

    redoer = commands.add_parser("redo-errors", help="complete a run in place: its error rows again, its missing flows for the first time")
    redoer.add_argument("run_dir", type=Path, help="results/<run_id> directory")
    redoer.set_defaults(handler=redo_command)

    reporter = commands.add_parser("metrics", help="summarize one or more runs")
    reporter.add_argument("run_dirs", nargs="+", type=Path, help="results/<run_id> directories")
    reporter.set_defaults(handler=metrics_command)

    comparer = commands.add_parser("compare", help="paired comparison of two detectors over the same split")
    comparer.add_argument("--a", nargs="+", required=True, type=Path, help="results/<run_id> directories of detector A")
    comparer.add_argument("--b", nargs="+", required=True, type=Path, help="results/<run_id> directories of detector B")
    comparer.add_argument(
        "--subset",
        choices=("all", "novel", "known"),
        default="all",
        help="every flow, only novel attacks or only known attacks",
    )
    comparer.add_argument("--k-a", help="cut run A to this k or `all`")
    comparer.add_argument("--k-b", help="cut run B to this k or `all`")
    comparer.set_defaults(handler=compare_command)
    return parser


def run_command(args: argparse.Namespace) -> None:
    """`run`: one detector over one split; argparse already converted the types."""
    spec = run.RunSpec(
        detector=args.detector,
        dataset=args.dataset,
        split=args.split,
        k_values=args.k,
        seeds=args.seeds,
        reps=args.reps,
        model_id=args.model,
        results_dir=args.results_dir,
        context=args.context,
    )
    run.run_from_spec(spec)


def sweep_command(args: argparse.Namespace) -> None:
    """`sweep`: the agent over the context space, every trial an ordinary run inside the sweep directory."""
    base = run.RunSpec(
        detector=args.detector,
        dataset=args.dataset,
        split=args.split,
        k_values=args.k,
        seeds=args.seeds,
        model_id=args.model,
        results_dir=args.results_dir,
    )
    sweep = agent.SweepSpec(
        base=base,
        strategy=args.strategy,
        objective=args.objective,
        factors=args.factors,
        budget=args.budget,
        adversarial=not args.no_adversarial,
        attacker=args.attacker,
        attacker_model=args.attacker_model,
    )
    agent.sweep_from_spec(sweep)


def redo_command(args: argparse.Namespace) -> None:
    """`redo-errors`: complete the run directory given, in place."""
    run.redo_errors(args.run_dir)


def metrics_command(args: argparse.Namespace) -> None:
    """`metrics`: one CSV row per group over every run given, on stdout."""
    predictions = [p for run_dir in args.run_dirs for p in read_predictions(run_dir)]
    print_csv(metrics.summarize(predictions))


def compare_command(args: argparse.Namespace) -> None:
    """`compare`: the paired comparison of two detectors, optionally across k, as CSV."""
    if (args.k_a is None) != (args.k_b is None):
        raise SystemExit("--k-a and --k-b come together")
    across_k = None if args.k_a is None else (parse_k(args.k_a), parse_k(args.k_b))
    # A detector may be spread over several run directories (one k each, run in parallel); each side is the union of its rows.
    run_a = metrics.only_subset([p for run_dir in args.a for p in read_predictions(run_dir)], args.subset)
    run_b = metrics.only_subset([p for run_dir in args.b for p in read_predictions(run_dir)], args.subset)
    print_csv(metrics.compare(run_a, run_b, across_k))


def print_csv(rows: Sequence[dict[str, Any]]) -> None:
    """The rows as CSV on stdout, header first; nothing at all when there are none.

    The header is every key any row has, in order of first appearance: the usage columns of a summary follow the Detectors present. CSV on
    stdout: the user redirects it when a file is wanted.
    """
    if not rows:
        return
    header = list(dict.fromkeys(key for row in rows for key in row))
    writer = csv.DictWriter(sys.stdout, fieldnames=header, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)


def main(argv: Sequence[str] | None = None) -> int:
    """Load the secrets of `.env`, parse the command line and call the subcommand's handler."""
    # The API keys live in `.env` and never in git (README); the console script and `python -m jev_ids` both pass through here.
    load_dotenv(ROOT / ".env")
    args = build_parser().parse_args(argv)
    args.handler(args)
    return 0
