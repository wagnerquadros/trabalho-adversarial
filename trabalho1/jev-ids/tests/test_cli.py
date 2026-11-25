"""CLI wiring for the run, redo-errors, metrics and compare subcommands."""

from pathlib import Path

import pytest

from jev_ids import agent, cli, context, records, run
from jev_ids.context import ContextSpec
from tests.helpers import make_prediction


def test_missing_arguments_and_removed_commands_are_rejected() -> None:
    with pytest.raises(SystemExit):
        cli.main(["metrics"])
    with pytest.raises(SystemExit):  # --dataset is required
        cli.main(["run", "--detector", "jev", "--split", "pilot"])
    for removed in ("download", "split"):
        with pytest.raises(SystemExit):
            cli.main([removed])


def test_run_builds_a_spec_from_the_arguments(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[run.RunSpec] = []

    def fake_run(spec: run.RunSpec) -> Path:
        seen.append(spec)
        return Path("x")

    monkeypatch.setattr(run, "run_from_spec", fake_run)
    card = "data/x/dataset.json"
    argv = ["run", "--dataset", card, "--detector", "random_forest", "--split", "smoke"]
    argv += ["--k", "1,all", "--seeds", "1", "--reps", "3", "--model", "m", "--results-dir", "results/paper"]
    argv += ["--context", "instructions=none,labels=flipped"]
    assert cli.main(argv) == 0
    poisoned = ContextSpec(instructions="none", labels="flipped")
    expected = run.RunSpec(
        "random_forest", Path(card), "smoke", (1, None), (1,), reps=3, model_id="m", results_dir=Path("results/paper"), context=poisoned
    )
    assert seen == [expected]
    argv = ["run", "--dataset", card, "--detector", "jev", "--split", "pilot"]
    assert cli.main(argv) == 0
    assert seen[1].k_values == (0, 1, 2, 4, 8)
    assert seen[1].seeds == (0, 1, 2)
    assert seen[1].model_id is None
    assert seen[1].results_dir == run.RESULTS_DIR
    assert seen[1].context == context.BASELINE  # every factor at the paper's level unless `--context` moves it
    with pytest.raises(SystemExit):  # a level no factor has never reaches an API call
        cli.main(["run", "--dataset", card, "--detector", "jev", "--split", "pilot", "--context", "instructions=wrong"])
    redone: list[Path] = []
    monkeypatch.setattr(run, "redo_errors", redone.append)
    assert cli.main(["redo-errors", "results/paper/x"]) == 0
    assert redone == [Path("results/paper/x")]


def test_sweep_builds_a_sweep_spec_around_a_run_spec(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[agent.SweepSpec] = []

    def fake_sweep(sweep: agent.SweepSpec) -> Path:
        seen.append(sweep)
        return Path("x")

    monkeypatch.setattr(agent, "sweep_from_spec", fake_sweep)
    card = "data/x/dataset.json"
    argv = ["sweep", "--dataset", card, "--detector", "jev", "--split", "pilot"]
    assert cli.main(argv) == 0
    # The defaults keep a sweep about context: one k, one seed, the whole ladder and the levels that misinform.
    assert seen[0] == agent.SweepSpec(base=run.RunSpec("jev", Path(card), "pilot", (1,), (0,)))
    assert (seen[0].strategy, seen[0].objective, seen[0].adversarial) == ("ladder", "max", True)
    argv += ["--strategy", "greedy", "--objective", "min", "--factors", "instructions,note", "--budget", "6", "--no-adversarial"]
    argv += ["--k", "2", "--seeds", "0,1", "--model", "m", "--attacker", "llm:ollama", "--attacker-model", "q", "--results-dir", "r"]
    assert cli.main(argv) == 0
    base = run.RunSpec("jev", Path(card), "pilot", (2,), (0, 1), model_id="m", results_dir=Path("r"))
    expected = agent.SweepSpec(base, "greedy", "min", ("instructions", "note"), 6, False, "llm:ollama", "q")
    assert seen[1] == expected
    for broken in ("nonsense", "instructions,nonsense"):
        with pytest.raises(SystemExit):  # a factor the space has no levels for never reaches a run
            cli.main(["sweep", "--dataset", card, "--detector", "jev", "--split", "pilot", "--factors", broken])


def test_metrics_prints_one_csv_over_every_run_given(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    records.append_prediction(tmp_path / "a", make_prediction(1, 1, 0.9))
    # The second run reports one usage field the first lacks: the header is the union of the rows' keys, in order of first appearance.
    other = make_prediction(2, 0, 0.1, detector="random_forest", usage={"duration": 2.0})
    records.append_prediction(tmp_path / "b", other)
    assert cli.main(["metrics", str(tmp_path / "a"), str(tmp_path / "b")]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[0].startswith("dataset,detector,model,split,context,k,cells,flows,predictions,f1_mean,")
    assert lines[0].endswith(",cost_usd_per_1m,latency_ms_mean,duration_mean")
    assert len(lines) == 3
    # After recall_known come recall_dos and recall_novel_dos (the first run's only attack is a known dos), then the two areas, which a
    # single-class cell leaves empty, then the error rate; the second run has no attack, so its category columns stay empty.
    assert lines[1] == "test,jev,m,internal,baseline,1,1,1,1,1.0,1.0,1.0,,1.0,1.0,,,,0.0,,100.0,10.0,,500.0,"
    assert lines[2] == "test,random_forest,m,internal,baseline,1,1,1,1,,,,,,,,,,0.0,,,,,500.0,2.0"
    assert cli.main(["metrics", str(tmp_path / "empty")]) == 0
    assert capsys.readouterr().out == ""


def test_compare_selects_the_subset_cuts_to_ks_and_prints_csv(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    a = [make_prediction(0, 1, 1.0, novel_attack=True), make_prediction(1, 1, 0.0)]
    b = [
        make_prediction(0, 1, 0.0, novel_attack=True, k=None),
        make_prediction(1, 1, 1.0, k=None),
    ]
    for prediction in [*a, *b]:
        records.append_prediction(tmp_path / prediction["detector"], prediction)
    # Side B is two directories: one per k, as parallel runs write them.
    records.append_prediction(tmp_path / "jev-k0", make_prediction(0, 1, 0.0, novel_attack=True, k=0))
    argv = ["compare", "--a", str(tmp_path / "jev"), "--b", str(tmp_path / "jev"), str(tmp_path / "jev-k0")]
    argv += ["--subset", "novel", "--k-a", "1", "--k-b", "all"]
    assert cli.main(argv) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == "k_a,k_b,repetition,pairs,discordant,a_correct,b_correct,mcnemar_p,f1_a,f1_b"
    assert lines[1] == "1,,0,1,1,1,0,1.0,1.0,0.0"
    with pytest.raises(SystemExit, match="come together"):
        cli.main(["compare", "--a", "a", "--b", "b", "--k-a", "0"])
