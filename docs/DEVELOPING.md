# Developing foss-soc-ml

A guide for contributors. Read [ARCHITECTURE.md](ARCHITECTURE.md) for the design
and [SPEC_DIGEST.md](SPEC_DIGEST.md) for the detection specification first.

---

## Large data files — read before touching `log_samples/`

Real-traffic captures used for training and backtesting can be **very large**
(tens of gigabytes). They are **git-ignored and never committed**, and they must
be **streamed, never loaded whole**:

- Never open a multi-GB log file in an editor, `cat` it, or load it with
  `json.load()` / `f.read()` — it can exhaust memory and hang the machine.
- To inspect format, read a bounded prefix: `head -c 2000 <file>`.
- To process, stream line by line keeping only aggregates. The framework's
  `FileSource` already does this safely.
- To sample with a tool, pass a bound: `soc-ml validate --input <file>
  --limit 100000`, `soc-ml backtest --input <file> --limit 300000`.

Test fixtures under `tests/fixtures/` are small and synthetic — safe to use
directly.

---

## The nine invariants

These are not style preferences. Breaking one stops the project meeting its
goals, and several are enforced by tests.

1. **No detector reads a literal threshold from config.** Config carries policy —
   modes, budgets, cadences, toggles. Every number compared against data comes
   from the learned Environment Profile. *(enforced: `soc-ml lint-config`)*
2. **Percentiles, never raw scores.** Calibrate per use case per server before
   any comparison or gate.
3. **The raw log line is evidence, never a model input.** Same for the
   `observer.*` fields, which are namespace keys only.
4. **Two-level gating.** A single event never alerts on its own; it must also
   raise a per-entity signal, and the evidence floor must be met.
5. **Nothing unversioned may serve.** Every model artifact carries its training
   window, row count, feature-code commit hash, and evaluation scores.
6. **Never train on synthetic data.** Injected attacks are for evaluation only;
   supervised models are never primary detectors.
7. **Corpus hygiene is enforced in the trainer** — drop the most-anomalous
   windows and clip outliers before fitting, so an attacker in the training data
   cannot teach the model that they are normal.
8. **No silent failure.** Every degradation, drop, and suppression leaves a
   record. A missing optional dependency degrades to a documented fallback,
   never a crash.
9. **Zero-infra default stays zero-infra.** The `standalone` profile must never
   require Kafka, Redis, or Elasticsearch.

---

## Module map

`src/soc_ml/` — one responsibility per directory, no cross-imports except
through `core/`.

| Module | Owns |
|---|---|
| `core/` | Event contract, config, plugin registry, types |
| `ingest/` | reading events from a source (file tail, replay), checkpoints |
| `preprocess/` | validation, derived fields, sessionization |
| `baseline/` | the learned Environment Profile |
| `features/` | turning event windows into feature vectors |
| `models/` | algorithm wrappers, uniform `fit`/`score`/`save`/`load` |
| `usecases/` | one file per detection (e.g. `web_recon.py`) |
| `fusion/` | percentile calibration + the severity formula |
| `detection/` | the shared scorer, dedup, budget, and the live runtime |
| `training/` | fits model bundles with corpus hygiene |
| `registry/` | versioned model store, promotion, rollback |
| `drift/` | PSI drift detection (the retrain trigger) |
| `explain/` | alert attributions, population context, narratives |
| `alerting/` | alert schema + output sinks |
| `evaluation/` | backtest harness + synthetic attack canary |
| `cli/` | the `soc-ml` commands |

---

## Adding a use case

Detections are plugins — a new one is a file dropped in `plugins/usecases/` (or
added under `src/soc_ml/usecases/`), with **zero edits to `core/`**. Follow the
naming standard in [NAMING.md](NAMING.md): every use case has a `slug` (canonical
name everywhere), a spec ID, and a human title.

The pattern: declare which features and models you need and the alert gate; the
framework handles training, calibration, scoring, explanation, dedup, budgeting,
and delivery. See `src/soc_ml/usecases/web_recon.py` as the reference.

Every use case needs tests: one per feature (hand-computed expected value), a
gate test (proves it stays quiet below the evidence floor), and a backtest that
completes.

---

## Running the tests

```bash
.venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest tests/ -q
```

Tests that depend on large real-traffic samples skip automatically when those
files are absent (they are not part of the repository).

---

## Conventions

- **Python 3.11+.** Match the surrounding code style.
- **Apache-2.0.** No dependency requiring a commercial licence on the default path.
- **Learned artifacts are never committed** — `data/` is git-ignored.
- Record non-obvious design decisions in [JOURNAL.md](JOURNAL.md).
- Reference requirement IDs (`FR-nn` / `NFR-nn` from [REQUIREMENTS.md](REQUIREMENTS.md))
  in commits where one applies.
