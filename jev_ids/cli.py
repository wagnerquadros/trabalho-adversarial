"""The command line: `jev-ids run|redo-errors|metrics|compare|sign-test|threshold|adversarial|resume|holdout`, or `python -m jev_ids`.

In reading order:

- `parse_k` and `parse_list`: the list arguments (`--k 0,1,all`).
- `build_parser`: the subcommands and their arguments.
- `run_command`, `redo_command`, `metrics_command`, `compare_command`, `sign_test_command`, `threshold_command`, `adversarial_command`,
  `resume_command`, `holdout_command`: one handler per subcommand, each turning the parsed arguments into calls of `run`, `metrics`,
  `adversarial` or `holdout`.
- `read_runs`: the rows of the run directories given, cut again at a threshold when one is given.
- `print_csv`: a table as CSV on stdout.
- `main`: parse, dispatch, return the exit code.

Nothing here knows how a Detector or a metric works, and no dataset is named here: `run` takes the card of the dataset as `--dataset`.
"""

import argparse
import csv
import sys
from collections.abc import Sequence
from dataclasses import asdict
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from jev_ids import ROOT, adversarial, holdout, metrics, run
from jev_ids.agent_runtime import AgentUnavailableError
from jev_ids.controller import BETA
from jev_ids.dataset import RECORDS
from jev_ids.records import Prediction, read_predictions


def parse_k(text: str) -> int | None:
    """One k: an integer, or `all` for the whole pool (Random Forest only)."""
    return None if text.strip() == "all" else int(text)


def parse_list(text: str) -> tuple[int | None, ...]:
    """A comma-separated list of integers: `--k 0,1,2,all` and `--seeds 0,1,2`.

    Both arguments are read the same way, so `all` is accepted for `--seeds` too,
    where it means nothing. Nobody writes it, and one parser is worth that much looseness.

    Args:
        text: the argument as typed, such as `0,1,2,all`.

    Returns:
        One k per comma-separated part, None for `all`.
    """
    return tuple(parse_k(part) for part in text.split(","))


def build_parser() -> argparse.ArgumentParser:
    """The subcommands, each carrying the function that handles it."""
    parser = argparse.ArgumentParser(prog="jev-ids")
    commands = parser.add_subparsers(dest="command", required=True)

    runner = commands.add_parser("run", help="run one detector over one split")
    runner.add_argument("--dataset", required=True, type=Path, help="the card: data/<name>/dataset.json")
    runner.add_argument(
        "--detector",
        required=True,
        help="jev, gemini_decision, systemone, llm:deepseek, llm:openai, llm:gemini, random_forest, isolation_forest or knn",
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
    runner.add_argument("--model", help="provider model id, for the LLM detectors")
    runner.add_argument("--results-dir", type=Path, default=run.RESULTS_DIR, help="where the run directory is created")
    runner.add_argument("--delay", type=int, help="stream the split with this feedback delay D, in Flows (docs/jevids-design.md, D4)")
    runner.add_argument("--jobs", type=int, default=-1, help="CPU cores each forest fit may use; -1 for all, the default")
    runner.add_argument(
        "--record",
        choices=RECORDS,
        default="compact",
        help="values Jev and the LLMs read: 4 significant digits (compact, the default) or as the CSV has them (full)",
    )
    runner.add_argument(
        "--selection",
        choices=run.SELECTIONS,
        help="Examples of a stream: by score and MMR (score, the default), the same plus the nearest benign Flow (score+nearest)"
        " or at random (random, line 0)",
    )
    runner.add_argument(
        "--control",
        choices=run.CONTROLS,
        default="fixed",
        help="k per Category: the same at every step (fixed, the default) or the KController's mirrored AIMD from k = 1 (aimd)",
    )
    runner.add_argument(
        "--beta",
        type=float,
        default=BETA,
        help="the KController's factor on an error under --control aimd (2, as D5 fixed it, outside the sensitivity check)",
    )
    runner.add_argument("--neighbours", help="K of the kNN: a number, or matched:k for as many as the Selector gives Jev at k")
    runner.set_defaults(handler=run_command)

    redoer = commands.add_parser("redo-errors", help="complete a run in place: its error rows again, its missing flows for the first time")
    redoer.add_argument("run_dir", type=Path, help="results/<run_id> directory")
    redoer.set_defaults(handler=redo_command)

    reporter = commands.add_parser("metrics", help="summarize one or more runs")
    reporter.add_argument("run_dirs", nargs="+", type=Path, help="results/<run_id> directories")
    reporter.add_argument("--threshold", type=float, help="take every Verdict again at p_attack >= this cut instead of 0.5 (D9)")
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

    signer = commands.add_parser("sign-test", help="flow-level sign test of two detectors on every subset and k, Holm-adjusted")
    signer.add_argument("--a", nargs="+", required=True, type=Path, help="results/<run_id> directories of detector A")
    signer.add_argument("--b", nargs="+", required=True, type=Path, help="results/<run_id> directories of detector B")
    signer.set_defaults(handler=sign_test_command)

    # Giving both paired tests a cut per side, so the full system at its tuned cut can meet a baseline at 0.5 (D9).
    for paired in (comparer, signer):
        paired.add_argument("--threshold-a", type=float, help="take the Verdicts of A again at this cut instead of 0.5 (D9)")
        paired.add_argument("--threshold-b", type=float, help="take the Verdicts of B again at this cut instead of 0.5 (D9)")

    tuner = commands.add_parser("threshold", help="the cut on p_attack with the best mean F1 over the validation runs given (D9)")
    tuner.add_argument("run_dirs", nargs="+", type=Path, help="results/<run_id> directories of the validation stream")
    tuner.set_defaults(handler=threshold_command)

    _add_adversarial_parser(commands)
    resumer = commands.add_parser("resume", help="go on with an adversarial run that stopped before its end, from the round it stopped in")
    resumer.add_argument("run_dir", type=Path, help="results/adv_* directory of the run that stopped")
    resumer.add_argument(
        "--past-stable",
        action="store_true",
        help="go on past a last round in which both sides held, from the same note and instructions; the loop stops again at the "
        "next such round",
    )
    resumer.set_defaults(handler=resume_command)
    _add_holdout_parser(commands)
    return parser


def _add_holdout_parser(commands: Any) -> None:
    held = commands.add_parser(
        "holdout", help="judge a reserved split under each round's note and instructions of a finished adversarial run"
    )
    held.add_argument("run_dir", type=Path, help="results/adv_* directory of the run")
    held.add_argument("--split", required=True, help="the reserved split under data/<name>/splits/, other than the one the run adapted on")
    held.add_argument("--rounds", type=parse_rounds, help="rounds to check, comma separated; default: every round that judged every flow")
    held.set_defaults(handler=holdout_command)


def parse_rounds(text: str) -> tuple[int, ...]:
    """The rounds of `holdout --rounds 1,5`, each an integer from 1."""
    rounds = tuple(int(part) for part in text.split(",") if part.strip())
    if not rounds or min(rounds) < 1:
        raise argparse.ArgumentTypeError(f"{text!r}: give the rounds as integers from 1, comma separated")
    return rounds


def _add_adversarial_parser(commands: Any) -> None:
    adv = commands.add_parser("adversarial", help="closed-loop study between Agno attacker and defender agents")
    adv.add_argument("--dataset", required=True, type=Path, help="the card: data/<name>/dataset.json")
    adv.add_argument("--split", default="smoke", help="split under data/<name>/splits/")
    adv.add_argument("--detector", required=True, help="jev, gemini_decision, systemone, llm:deepseek, llm:openai or llm:gemini")
    adv.add_argument("--detector-model", help="optional detector model override")
    adv.add_argument("--attacker", default="claude", help="attacker Agno provider: qwen, claude, hydrogen, gemini, openai, deepseek")
    adv.add_argument("--attacker-model", help="optional attacker model id")
    adv.add_argument("--defender", default="hydrogen", help="defender Agno provider: hydrogen, qwen, claude, gemini, openai, deepseek")
    adv.add_argument("--defender-model", help="optional defender model id")
    adv.add_argument("--rounds", type=int, default=5, help="maximum adversarial rounds")
    adv.add_argument("--max-attempts", type=int, default=3, help="new wordings the attacker may submit; keeping or removing is free")
    adv.add_argument("--max-note-length", type=int, default=120, help="maximum characters for service field note")
    adv.add_argument(
        "--noise-margin",
        type=int,
        default=0,
        help="attack flows the net shift between two rounds must exceed before the turn rule reads it as a shift (0, the default)",
    )
    adv.add_argument("--memory-dir", type=Path, help="where the agents keep their memories across runs; default: <run_dir>/memory")
    adv.add_argument("--initial-note", default=adversarial.INITIAL_NOTE, help="initial note used in round 1")
    adv.add_argument("--k", type=int, default=0, help="labeled examples per category (0 uses none)")
    adv.add_argument("--seed", type=int, default=0, help="example sampling seed when k > 0")
    adv.add_argument("--record", choices=RECORDS, default="compact", help="compact or full record format")
    adv.add_argument("--results-dir", type=Path, default=run.RESULTS_DIR, help="where the adv_* run directory is created")
    adv.set_defaults(handler=adversarial_command)


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
        delay=args.delay,
        jobs=args.jobs,
        record=args.record,
        selection=args.selection,
        neighbours=args.neighbours,
        control=args.control,
        beta=args.beta,
    )
    run.run_from_spec(spec)


def redo_command(args: argparse.Namespace) -> None:
    """`redo-errors`: complete the run directory given, in place."""
    run.redo_errors(args.run_dir)


def metrics_command(args: argparse.Namespace) -> None:
    """`metrics`: one CSV row per group over every run given, on stdout."""
    print_csv(metrics.summarize(read_runs(args.run_dirs, args.threshold)))


def compare_command(args: argparse.Namespace) -> None:
    """`compare`: the paired comparison of two detectors, optionally across k, as CSV."""
    if (args.k_a is None) != (args.k_b is None):
        raise SystemExit("--k-a and --k-b come together")
    across_k = None if args.k_a is None else (parse_k(args.k_a), parse_k(args.k_b))
    # Pooling the rows of each side, because a detector may be spread over several run directories (one k each, run in parallel).
    run_a = metrics.only_subset(read_runs(args.a, args.threshold_a), args.subset)
    run_b = metrics.only_subset(read_runs(args.b, args.threshold_b), args.subset)
    print_csv(metrics.compare(run_a, run_b, across_k))


def sign_test_command(args: argparse.Namespace) -> None:
    """`sign-test`: the flow-level sign test on all flows, known and novel attacks, with Holm's adjustment across every row, as CSV."""
    run_a, run_b = read_runs(args.a, args.threshold_a), read_runs(args.b, args.threshold_b)
    table = [
        {
            "subset": subset,
            **row,
        }
        for subset in ("all", "known", "novel")
        for row in metrics.sign_test(metrics.only_subset(run_a, subset), metrics.only_subset(run_b, subset))
    ]
    # Adjusting the family of every subset and k together, the 15 comparisons of the paper's Table 4.
    for row, adjusted in zip(table, metrics.holm([float(row["sign_p"]) for row in table]), strict=True):
        row["holm_p"] = adjusted
    print_csv(table)


def threshold_command(args: argparse.Namespace) -> None:
    """`threshold`: the cut of D9 over the validation runs given, as one CSV row."""
    print_csv([metrics.best_threshold(read_runs(args.run_dirs))])


def adversarial_command(args: argparse.Namespace) -> None:
    """`adversarial`: run the closed-loop Agno study and print one CSV row per round.

    The command exits non-zero when an agent's model fails its question before the first round, and, after the rounds are printed,
    when the loop ended because the detector stopped answering or an agent's model failed.
    """
    spec = adversarial.AdversarialSpec(
        detector=args.detector,
        dataset=args.dataset,
        split=args.split,
        attacker_provider=args.attacker,
        attacker_model=args.attacker_model,
        defender_provider=args.defender,
        defender_model=args.defender_model,
        detector_model=args.detector_model,
        max_rounds=args.rounds,
        max_attempts=args.max_attempts,
        max_note_length=args.max_note_length,
        initial_note=args.initial_note,
        k=args.k,
        seed=args.seed,
        record=args.record,
        results_dir=args.results_dir,
        noise_margin=args.noise_margin,
        memory_dir=args.memory_dir,
    )
    try:
        run_dir, history = adversarial.run_adversarial(spec)
    except AgentUnavailableError as exc:
        raise SystemExit(f"agent model unavailable before the first round, no detector call was made ({exc})") from exc
    report_rounds(run_dir, history)


def resume_command(args: argparse.Namespace) -> None:
    """`resume`: go on with an adversarial run that stopped before its end, and print every round of it as `adversarial` does.

    With `--past-stable`, a run that ended with both sides holding goes on too, past that round. The command exits non-zero when the
    run ended in order, when an agent's model fails its question before going on, and, after the rounds are printed, when the loop
    stopped again.
    """
    try:
        run_dir, history = adversarial.resume_adversarial(args.run_dir, args.past_stable)
    except AgentUnavailableError as exc:
        raise SystemExit(f"agent model unavailable before going on, no detector call was made ({exc})") from exc
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    report_rounds(run_dir, history)


def holdout_command(args: argparse.Namespace) -> None:
    """`holdout`: judge a reserved split under each round of a finished run and print one CSV row per round.

    The command exits non-zero when the run or the splits cannot be checked, and, after the rows are printed, when the detector stopped
    answering on the reserved split.
    """
    try:
        out_dir, lines = holdout.holdout_from_run(args.run_dir, args.split, args.rounds)
    except (ValueError, FileNotFoundError) as exc:
        raise SystemExit(str(exc)) from exc
    print_csv([asdict(line) for line in lines])
    if lines and lines[-1].stopped:
        raise SystemExit(
            f"stopped: the detector stopped answering at round {lines[-1].round} of {out_dir}; the rows judged so far are kept"
        )


def report_rounds(run_dir: Path, history: Sequence[adversarial.RoundRecord]) -> None:
    """Print one CSV row per round, then exit non-zero, naming the way to go on, when the loop stopped on a failure."""
    print_csv([asdict(rec) for rec in history])
    failure = adversarial.failure_of(history)
    if failure is not None:
        raise SystemExit(
            f"stopped: {failure} at round {history[-1].round} of {run_dir}; the rows judged so far are kept, "
            f"and `jev-ids resume {run_dir}` goes on from that round"
        )


def read_runs(run_dirs: Sequence[Path], threshold: float | None = None) -> list[Prediction]:
    """Every row of the run directories given, with each Verdict taken again at `threshold` when one is given (D9)."""
    predictions = [prediction for run_dir in run_dirs for prediction in read_predictions(run_dir)]
    return predictions if threshold is None else metrics.at_threshold(predictions, threshold)


def print_csv(rows: Sequence[dict[str, Any]]) -> None:
    """The rows as CSV on stdout, header first; nothing at all when there are none.

    The header is every key any row has, in order of first appearance, so the usage columns of a summary
    follow the Detectors present. The CSV goes to stdout, and the user redirects it when a file is wanted.

    Args:
        rows: the table, one dict per row.
    """
    if not rows:
        return
    header = list(dict.fromkeys(key for row in rows for key in row))
    writer = csv.DictWriter(sys.stdout, fieldnames=header, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)


def use_utf8_stdout() -> None:
    """Write stdout in UTF-8 where it defaults to a narrower code page, as a redirected stdout does on Windows (cp1252).

    The notes and rationales the agents write may hold any character, such as an arrow, and a CSV row that the code page cannot
    encode would stop the command after the run ended, with every round already saved.
    """
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if reconfigure is not None and sys.stdout.encoding.lower().replace("-", "") != "utf8":
        reconfigure(encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    """Load the secrets of `.env`, parse the command line and call the subcommand's handler."""
    use_utf8_stdout()
    # Loading the API keys from `.env`, which stays out of git (README),
    # here because both the console script and `python -m jev_ids` pass through.
    load_dotenv(ROOT / ".env")
    args = build_parser().parse_args(argv)
    args.handler(args)
    return 0
