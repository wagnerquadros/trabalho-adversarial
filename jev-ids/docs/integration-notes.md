# NSL-KDD detector evaluation

## Audit

The NSL-KDD card fixes the order of 41 features. In C1, `dataset.load_split` builds frozen `Flow` objects. Each holds the serialized features **and** evaluation metadata (`category`, `is_attack`, `novel_attack`). Treat the entire object as privileged. The detector's record text uses only its features. C1 input parsing lives in `dataset.py`. C4 joins the truth with measurements in `records.complete_prediction`.

The stored `pilot.csv` has 300 records and `paper.csv` has 2,000. The split manifest records the draw seed 20260920 and the disjoint paper draw. A probe seed selects records within pilot and examples within the training pool. It does not redraw the published splits. The base sampler at k = 1 draws one labeled example per available category and then shuffles their order. Both calls within a probe use the same examples.

In C2, `context.Rewriter` holds the static note text, field index and inclusion rule derived from the context card. Its `apply` method returns the rendered record for a particular context. The probe uses the original records and the dataset's baseline prompt. The base F1 search in `agent.py` has privileged feedback and stays outside this measurement.

In C3, Qwen uses Agno's structured output. The lockfile pins Agno 3.0.10 and ollama 0.6.3. The existing Qwen detector enables thinking. The probe configures only its own model instance and verifies the outgoing HTTP request and returned message. The base adapter returns an error for connection and parsing failures. Laya uses the same request builder as Jev, sends the multilingual checkpoint to the local systemone endpoint and reads the probability and category from separate answers. Laya can return an error with a retry count or an answer with a missing probability. Its latency on a successful attempt can exclude earlier retries. The probe measures the whole call.

The historical C4 evaluator counts a missing verdict as normal in its classification metrics. The separate evaluator here counts failures, out-of-vocabulary records and blocked records explicitly. False-alarm rate uses all legitimate records as specified. Recall, F1 and miss rate use actual detector decisions. Undefined rates are missing. For the published Jev comparison, use the model-specific predictions file in the timestamped subdirectory of `results/paper`, select k = 1, and average per-seed rates. Its tested anchors are 57, 36 and 37 false alarms, mean F1 approximately 0.856 and mean zero-day recall approximately 0.747.

## Available measurements and UI gaps

The probe can supply the model, row ID, probability, category, latency, reported tokens, validation status, training vocabulary digest and error reason. The evaluator can derive outcome counts from labeled rows. The demo snapshot requires a selected round and an indexed action cell. It requires a numeric probability and one of two verdicts, which cannot represent startup, blocked decisions or failures. A pending attempt is represented by the same absence of a verdict that a failed call would produce.

The probe does not supply round transitions, attempt history, budget use, notes, intentions, revisions, adaptation triggers, messages, context diffs, cell visits, historical metric deltas or chart series. The payoff values in the UI are ordinal hypotheses. Detector results alone cannot populate these fields. The demo and its controls continue to display the illustrative snapshot.

## Measurement assumptions

- Seed 0 is the baseline. One original benign and one original malicious pilot record form a connectivity and schema check. Two records cannot establish detector accuracy.
- The comparison uses a 0.5 threshold, identical sampled examples and one detector per invocation.
- Validation defaults to observation. A record may be invalid and still have a genuine decision. Blocking suppresses the call and records a distinct outcome. A failed call yields a reason and no classification. Missing usage stays missing.
- The validator reads only the training pool. Its digest covers sorted JSON field names and the sorted vocabulary for each field. The probe emits both in its first output line.
- No adaptive rounds were measured. Agent budgets, per-round probes, note and instruction limits and an operational development-set size are unspecified in this baseline. The illustrative UI values do not supply these measurements.

## Reproduction

Run from `jev-ids/` in Git Bash. The probe requires `data/nsl-kdd/pool.csv`. For this checkout the project's converter generated it from a local copy of `KDDTrain+.txt` verified against the SHA-256 in `splits/SOURCE.json` (125,973 training rows). Set `OLLAMA_HOST` or `LAYA_BASE_URL` when the service uses a different local address. Model IDs are fixed by the selected probe. See `.env.example` for service defaults.

```bash
uv run --no-sync python -m jev_ids.adversarial.cli --detector qwen3 --seed 0
uv run --no-sync python -m jev_ids.adversarial.cli --detector laya --seed 0
uv run --no-sync pytest -q
JEV_LIVE=1 uv run --no-sync pytest tests/adversarial/test_live_probe.py -q --no-cov
uv run --no-sync adversarial-sim-ui
```

Installing the project also exposes `adversarial-sim-probe`. The module command works in existing editable environments whose console scripts have not been refreshed. The UI command launches demo mode.

| Model | Pilot row | Probability | Predicted category | Input / output tokens | Wall time |
|---|---:|---:|---|---:|---:|
| Qwen3:8b | 14373 | 0.05 | normal | 1262 / 29 | 14.571 s |
| Qwen3:8b | 547 | 0.05 | normal | 1257 / 29 | 0.414 s |
| Laya multilingual | 14373 | — | — | — | 25.137 s including retries |
| Laya multilingual | 547 | — | — | — | 25.163 s including retries |

Ollama reported 13.532 s of model loading on the first call. For illustration, 100 comparable serial detector calls at the one warm observation would take roughly 41 s plus loading. This is a detector-only extrapolation from one warm observation. It excludes agents, setup and any changes in prompt length. Laya returned connection refused at `127.0.0.1:8000/v1/systemone`. Start the local multilingual service or configure its address before repeating. Its two elapsed times measure failed requests. Thinking control applies to Ollama.

## Paired instruction comparison on original records

Run the static H4 measurement from `jev-ids/`:

```bash
uv run --no-sync python -m jev_ids.adversarial.analysis.hypotheses --detector qwen3 --seed 0 --per-class 4
uv run --no-sync python -m jev_ids.adversarial.analysis.hypotheses --detector laya --seed 0 --per-class 4
```

The installed console entry point is `adversarial-sim-hypotheses`. Each invocation writes its manifest, measured rows for each attempted condition and summary under `runs/<timestamp>-h4-<detector>-<seed>/`. A failure stops the comparison with a nonzero exit code. Read the failure reason from the last attempted condition. The model digest is available from Ollama; the Laya adapter has no digest field.

**Design assumptions.** The smoke batch has four benign and four malicious original pilot records sampled without replacement. The same ordered batch, labeled training examples, threshold, validator mode and model apply to B and R. B uses the original template. R adds a single instruction declaring field contents untrusted. The evaluator runs B first, then R. This fixed order leaves timing sensitive to model loading and cache effects. The balanced sample changes class prevalence relative to the full pilot.

| Qwen3:8b, seed 0 | False alarms / legitimate | True positives / malicious | Recall | Mean total tokens | Mean wall time |
|---|---:|---:|---:|---:|---:|
| B | 0/4 | 0/4 | 0 | 1287.75 | 410.47 ms |
| R | 0/4 | 0/4 | 0 | 1311.00 | 370.74 ms |

Evidence directory: `20261121T151732.756453Z-h4-qwen3-0`. Both conditions had eight usable decisions and zero invalid records. The reinforcement cost 23.25 more tokens per record on average. All four malicious records were missed under each condition. The experiment did not establish a general cost in false alarms or latency. An earlier run with a cold start took 2122.27 ms per record under B.

Laya refused the first connection at the configured local endpoint during the comparison. The command recorded the failure and stopped before R. Evidence directory: `20261121T151546.130844Z-h4-laya-0`. H1–H3, adaptive round latency and held-out performance remain unmeasured.

### Local Qwen dashboard

From `jev-ids/`, run `uv run --no-sync adversarial-sim-ui --server.address=127.0.0.1 --server.port=8501`. Open `http://127.0.0.1:8501/` for live classification, or append `?modo=demo` to open the illustrative arena. The live view requires the prepared NSL-KDD pool and pilot split, the UI extra, and a running Ollama service with `qwen3:8b` installed. The adapter honors `OLLAMA_HOST` and verifies thinking is disabled on the chat request and response.

Choose **Piloto** for a configurable development sample or **Final · paper** for the held-out evaluation. Select the detector, validator, round size and execution mode, then press **Concluir configuração** and **Executar simulação**. In **Rodada por rodada**, the first round runs and the session waits for **Próxima rodada**. **Executar tudo** also works from a paused round and consumes the remaining budget. Each attempt consumes one unit, including a validation block. Qwen is the local default. Laya requires its own running local endpoint.

In paper mode the Arena verifies the published split digest, the 2,000 distinct test IDs and their disjointness from the pilot. Each of seeds 0, 1 and 2 draws one training example per category. All four contexts see the same ordered test IDs and examples for that seed. Changing the round size changes the manual step boundaries. Each full run has 24,000 attempts. The log stores the seed and example IDs for each attempt. Individual prediction failures are recorded and subsequent attempts continue.

The dashboard and saved summary give per-context F1 for both policies. Arena excludes failures from F1. Fail-open assigns failed calls a quiet decision. Validator blocks are counted separately under both policies. Once a condition covers all three full seeds, its summary gives the mean and sample standard deviation over defined F1 values. Token and latency means use available measurements. Reinforcement deltas compare B and R within each seed, record and note condition.

The live arena uses a fixed test fixture. By default the arena runs 8 rounds of 8 records with a budget of 64 submissions. In each group of four rounds, the same ordered cohort of pilot records passes through N/B, N/R, S/R and S/B in that order. The seeded sampler draws equal numbers of malicious and benign records without replacement for each even-sized cohort. Each new four-round block draws a disjoint cohort. The last round can end early if the attempt budget runs out. N appends the provenance label ` [NSL-KDD]` to service. S uses the original value. R uses the existing defensive instruction reinforcement. Both roles follow the declared schedule. Detector feedback never generates or selects a note. The cards and message tab display measured results and attributed coordinator events. The matrix counts attempted conditions, including blocks. The ordinal utilities remain hypotheses. The headline metrics accumulate attempts. The chart and results table describe individual rounds, and missing denominators are shown as a dash. Cost of R is the mean paired token difference on completed responses for the same row and note. The context tab compares each factor with the other held fixed. It joins on original record ID, counts eligible pairs and reports changes in alert, score and predicted category. Scores and threshold crossings use only pairs with two valid responses. The paired results are descriptive for this balanced pilot sample. The context and JSONL tabs expose actual notes, prompt hashes, per-attempt results and budget. Each new test is saved under `runs/arena-<UTC>/` with its manifest, rounds and summary. The sidebar replay link opens a completed test in read-only mode. Its slider scrubs back to any recorded round. The JSONL download contains the rounds currently displayed.
