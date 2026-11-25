# The context study

The paper moved k, the number of labeled examples per category, and held everything else fixed: the task description, the column names, the
category descriptions, the shape of the record, the truth of the labels. That was the right thing to hold fixed to measure k. It also means
every number in [`docs/results.md`](results.md) is the number of **one** context, and says nothing about how much of the detector's accuracy
came from that context rather than from the flow.

This fork asks the other question. It holds k fixed and moves the context, one factor at a time, and reports what each move did to the
verdict. Two readings of the same measurement:

- **How much context helps.** Going from no task description to an expert one, or from bare column names to described columns, costs tokens
  and latency. The ladder says what each rung buys, and whether the top rung buys anything at all.
- **How much a wrong context hurts.** A detector whose accuracy moves a long way when the wording around the flow changes is a detector
  whose context is part of its attack surface. The levels that misinform measure that distance.

The second reading is why this is a fork and not a branch of the protocol. It is a measurement of a detector the authors own, on a public
dataset, reported like any other number here. Nothing in it is a recommendation.

## The space

Six factors, each with its own levels, each level reachable on its own. `jev_ids/context.py` holds the space and
`prompts/<dataset>/context.json` the text the levels above the paper's need.

| Factor         | Ladder, least context first                        | Levels that misinform  | What moves                                                  |
| -------------- | -------------------------------------------------- | ---------------------- | ----------------------------------------------------------- |
| `instructions` | `none` → `minimal` → **`paper`** → `expert`        | `misleading`, `custom` | the task description in the state                           |
| `columns`      | `absent` → `anonymous` → **`named`** → `described` | `shuffled`             | the column names, and what each one counts                  |
| `categories`   | `names` → **`paper`** → `detailed`                 | `swapped`              | how much each category is described                         |
| `record`       | **`csv`** → `labeled`                              | —                      | `0,tcp,http,...` against `duration=0,protocol_type=tcp,...` |
| `labels`       | **`true`**                                         | `flipped`, `benign`    | the category written beside each example, never its values  |
| `note`         | **`none`**                                         | `attacks`, `all`       | a note inside the record of the flow under test             |

The bold level is the paper's. A run at all six of them is the **baseline**, and it is the paper's run: `render` returns the committed
prompt file byte for byte, so a baseline run of this fork carries the same `prompt_hash` as the runs in `results/paper/` and its rows can be
compared with them as equals. Every other level rehashes, so no two context levels are ever mistaken for one another in the records.

Two rules keep a comparison honest:

- **The questions never change.** Only the `state` moves. `is_attack` and `category` are asked in the same words at every level, so a
  difference between two runs is a difference of context and not of what was asked. When a level removes a piece of the state, the questions
  go on naming it in backticks: a dangling path is the condition being measured, not a bug to paper over.
- **The truth never moves.** `labels` changes the category written beside an example; `note` changes one value of the record under test. A
  row's `is_attack`, `category_true` and `novel_attack` are always the dataset's, whatever the detector was shown, so a poisoned run is
  scored against the same truth as a clean one.

Two levels are worth spelling out. `labels = flipped` mislabels a seeded half of the examples and leaves their values alone, so the
poisoning is invisible in the record and the Random Forest trains on it exactly as the prompt detectors read it. `note` appends a short
text to the value of one symbolic feature of the flow under test — `service` in NSL-KDD — never to an example: the record is the one channel
an attacker on the network actually controls, and the level measures whether a detector that reads it as data can be made to read it as
instructions.

`record = labeled` is refused for the two forests, which read the record as numbers in card order.

## Running one level

```bash
uv run jev-ids run --dataset data/nsl-kdd/dataset.json --detector jev --split pilot --k 1 --seeds 0 \
  --context instructions=none,columns=absent
```

`--context` names only the factors it moves; the rest stay at the paper's level. The run directory gains the level's name
(`...-jev-pilot-instructions-none+columns-absent`), every row carries it as `context`, and `metrics` groups by it:

```bash
uv run jev-ids metrics results/<baseline_run> results/<other_run> > results/context.csv
uv run jev-ids compare --a results/<baseline_run> --b results/<other_run>
```

`compare` is the one that settles it: two context levels are told apart only by the flows they disagree on, and McNemar's exact test says
whether that split is chance.

## Running a sweep

`sweep` hands the choice of the next level to the agent of [`jev_ids/agent.py`](../jev_ids/agent.py). Every trial is an ordinary run inside
the sweep directory, so nothing downstream needs to know a sweep happened.

```bash
# Which factor matters, and how much: every level of the three text factors against the baseline.
uv run jev-ids sweep --dataset data/nsl-kdd/dataset.json --detector jev --split pilot \
  --k 1 --seeds 0 --strategy ladder --factors instructions,columns,categories --budget 12

# Which context hurts most, allowed to combine factors.
uv run jev-ids sweep --dataset data/nsl-kdd/dataset.json --detector jev --split pilot \
  --k 1 --seeds 0 --strategy greedy --objective min --budget 10

# The task description written during the search instead of chosen in advance.
uv run jev-ids sweep --dataset data/nsl-kdd/dataset.json --detector jev --split pilot \
  --k 1 --seeds 0 --strategy attack --objective min --budget 8 --attacker llm:deepseek
```

| Strategy | What it does                                                                         | Cost                                   |
| -------- | ------------------------------------------------------------------------------------ | -------------------------------------- |
| `ladder` | the baseline, then every level of every chosen factor, one factor at a time          | one run per level, known in advance    |
| `greedy` | keeps the best level found so far and expands from it; stops at a local optimum      | up to the budget; reaches combinations |
| `attack` | an LLM reads the trail and writes the next task description, which is run as a level | up to the budget, plus one call each   |

`--objective max` asks which context makes the detector better, `--objective min` which makes it worse. `--no-adversarial` keeps the sweep on
the ladder. `--budget` is the number of runs, which is what a sweep costs: at `--split pilot --k 1 --seeds 0` a trial is 300 calls, so a
budget of 12 is 3,600 calls, about $0.27 of Jev at list price and about $6 of Gemini.

The sweep directory holds one run directory per trial, `sweep.json` (the spec, the baseline, the best and the whole trail) and `trials.csv`,
one row per trial: the move, what the run measured, and the paired test against the baseline.

| Column                                              | What it holds                                                         |
| --------------------------------------------------- | --------------------------------------------------------------------- |
| `trial`, `context`, `run_dir`                       | the order, the level's name, the run it wrote                         |
| `instructions` … `note`, `custom`                   | the level of each factor, and the text when the attacker wrote one    |
| `f1_mean`, `precision_mean`, `recall_novel_mean`, … | what `metrics` measured over that run                                 |
| `discordant`, `baseline_right`, `context_right`     | the flows this level and the baseline disagreed on, and who was right |
| `mcnemar_p`                                         | the exact two-sided test on that split                                |

## Detectors

The study runs against any detector the repository has. Two were added for it, both so that the same context can be put to a model that
runs on your own hardware:

- **Laya** (`--detector laya`), Convai Innovations' open-source System 1 engine, answers the same typed `noul` and `choice` questions as Jev
  over the same state, so it reads Jev's own `prompts/<dataset>/jev.json` and a verdict of one is comparable with a verdict of the other.
  Start `laya-serve` and point `LAYA_BASE_URL` at it; `LAYA_API_KEY` is sent as a bearer token when the server asks for one. The default
  checkpoint is `multilingual` with a budget of 8,192 tokens, the one whose context window holds the request at every k — the `english`
  checkpoint reads 512 and would cut the context without a word, and a study of context would then be measuring the cut.
- **Ollama** (`--detector llm:ollama --model <tag>`), any model the server has pulled, through the same Agno agent and the same `llm.md` as
  the other LLM baselines. `OLLAMA_HOST` points at the server; the context window is fixed at 16,384 tokens for the same reason.

Both read their server's address from the environment, so the model can sit on another machine than the one running the sweep.

```bash
# .env
LAYA_BASE_URL=http://192.168.0.7:8000
OLLAMA_HOST=http://192.168.0.7:11434
DEEPSEEK_API_KEY=...
```

## What the study does not fix

- **One split, one dataset.** Everything here is NSL-KDD's, as in the paper.
- **A level is one wording.** `expert` and `misleading` are one text each, written once and committed. A different text at the same level
  would give different numbers; the level names a kind of context, not a bound on it.
- **The attacker is not a bound either.** `attack` reports what one LLM found within its budget. A longer search, or another attacker, may
  find more. A trial that fails to move the detector is evidence about that search, not about the detector.
- **Latency and cost move with the context.** A described-columns level sends more tokens than an absent-columns one, so the cost column of
  a sweep is part of the result: a context that helps may not be worth its tokens.
