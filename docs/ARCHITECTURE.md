# Architecture

How the specification in [`SPEC_DIGEST.md`](SPEC_DIGEST.md) becomes runnable
software. The spec describes an enterprise target (Kafka + Flink + Redis +
MLflow + Elasticsearch). This document explains the design decisions that make
that target **optional** rather than mandatory, so the same codebase runs on a
laptop against a log file and in a Kubernetes namespace against a Kafka firehose.

---

## 1. Design principles

These are the non-negotiables. Every later decision follows from them.

| # | Principle | Consequence |
|---|---|---|
| P1 | **The event contract is the only hard dependency.** | Anything that emits the ECS JSON in SPEC_DIGEST §3 can drive the framework. `foss-soc-engine` is the reference producer, not a requirement. |
| P2 | **Progressive infrastructure.** | Zero-infra is the *default*, not a toy mode. Kafka/Redis/MLflow are opt-in adapters behind the same interfaces. |
| P3 | **Offline before live.** | Every component must be runnable over historical data with no live stream. Backtest is the primary development loop, not an afterthought. |
| P4 | **Learned, not configured.** | If a number could be learned from the deployment's own logs, it must be. Config supplies *policy* (budgets, modes), never *thresholds*. |
| P5 | **Everything user-extensible is a plugin.** | Six extension points, uniform discovery, no core edits required to add a use case. |
| P6 | **Percentiles, never absolutes.** | Raw model scores are never compared or thresholded directly. |
| P7 | **Silent failure is the only unacceptable failure.** | Degradations emit health events; suppression leaves visible links; nothing is dropped without a record. |
| P8 | **Detection and analytics never share a runtime.** | A slow analytics job can never delay a security alert. |

---

## 2. Runtime topology

```
                     ┌───────────────────────────────────────┐
                     │  SOURCE plugin (P1/P2)                │
   parser output ───►│  file-tail │ kafka │ elasticsearch    │
   (ECS JSON)        └──────────────────┬────────────────────┘
                                        │  Event (frozen contract)
                     ┌──────────────────▼────────────────────┐
                     │  PREPROCESS                           │
                     │  validate → derive → sessionize       │
                     └──────────────────┬────────────────────┘
                                        │  Event + SessionRef
                     ┌──────────────────▼────────────────────┐
                     │  FEATURE PLATFORM                     │
                     │  feature groups × windows (1m/5m/     │
                     │  30m/24h/7d/168h), backed by STATE    │
                     └───────┬───────────────────────┬───────┘
                             │ FeatureVector         │ aggregates
        ┌────────────────────▼──────┐   ┌────────────▼─────────────┐
        │ PIPELINE 1: DETECTION     │   │ PIPELINE 2: ANALYTICS    │
        │ usecases UC-01..15        │   │ usecases AU-01..12       │
        │   └ models (scored)       │   │   └ baselines/forecasts  │
        │ fusion: calibrate →       │   │ drift monitors (PSI/KS)  │
        │   corroborate → suppress  │   │ insight generator        │
        │   → fold → budget         │   │                          │
        │ severity → explain(async) │   │                          │
        └────────────┬──────────────┘   └────────────┬─────────────┘
                     │ Alert                          │ Insight
                     └──────────────┬─────────────────┘
                     ┌──────────────▼────────────────────────┐
                     │  SINK plugin — file │ es │ kafka │ …  │
                     └───────────────────────────────────────┘

   cross-cutting:  STATE store · MODEL REGISTRY · DRIFT monitor
                   TRAINER (cadence ladder) · EVALUATION (SAIF/backtest)
```

---

## 3. Progressive infrastructure — the three profiles

The same code, three deployment shapes selected by one config key. This is how
the spec's enterprise stack becomes optional (**P2**).

| | `standalone` (default) | `cluster` | `enterprise` |
|---|---|---|---|
| **Source** | file tail of parser output | Kafka | Kafka |
| **State** | SQLite + in-process LRU | Redis | Redis (persistent) |
| **Registry** | local versioned filesystem | local FS or MLflow | MLflow |
| **Sink** | NDJSON files | Elasticsearch | Elasticsearch + Kafka |
| **Compute** | single process, threads | multi-process | Faust/Flink workers |
| **Target scale** | ≤ ~2k events/s | 2–50k events/s | 50k+ events/s |
| **Infra required** | **none** | Kafka + Redis | full stack |

`standalone` is a first-class production mode for a single site, not a demo. It
is also the mode all tests and backtests run in.

---

## 4. The three run modes (P3)

Orthogonal to the profile. Set per run; the spec's cold-start staging (§8) is
expressed by moving a use case through these.

| Mode | Reads | Trains | Scores | Emits alerts | Purpose |
|---|---|---|---|---|---|
| **`offline`** | historical files | yes | yes | to a report, not the queue | backtest, cold-start warmup, model development, CI regression |
| **`shadow`** | live stream | no (challenger may) | yes | recorded only, never delivered | the spec's *observe mode*; also champion-challenger's ≥72 h soak |
| **`live`** | live stream | on cadence | yes | delivered to sinks | production |

**A use case may be in a different mode from its neighbours.** That is exactly
how cold-start Stage 2 works: Tier-1 `live` while Tier-2 is still `shadow`.

```yaml
modes:
  default: shadow
  overrides:
    UC-01: live
    UC-14: offline
```

---

## 5. Extension points (P5)

Six interfaces. Everything a user adds is one of these. All are discovered the
same way, so there is one thing to learn.

| Interface | Contract | Ships with |
|---|---|---|
| `Source` | yields `Event` | `file`, `kafka`, `elasticsearch`, `replay` |
| `FeatureGroup` | `Event`/window → named floats | timing, volume, path, path-rarity, query, status, method, referrer, identity, geo, cross-entity |
| `UseCase` | `FeatureVector` → `Score` (+ its model + gate) | UC-01…UC-15, AU-01…AU-12 |
| `Model` | `fit` / `score` / `save` / `load` | iforest, hst, lof, gmm, hmm, ae, vae, char-lm, hdbscan, quantile-gbm |
| `StateStore` | windowed counters, HLL, tables | `memory`, `sqlite`, `redis` |
| `Sink` | `Alert`/`Insight` → somewhere | `file`, `elasticsearch`, `kafka`, `webhook`, `stdout` |

### Discovery

Two mechanisms, no registration file to edit:

1. **Directory drop-in** — anything under `plugins/<kind>/` is imported at
   startup. Zero packaging. This is the "copy a file and it works" path.
2. **Python entry points** — `soc_ml.usecases`, `soc_ml.features`, … for
   pip-installable third-party packages.

Both land in the same registry. A plugin declares its dependencies on feature
groups; the platform computes the union so **no feature is ever computed twice**,
and a use case that nobody enabled costs nothing.

### Why plugins rather than config-only rules

`foss-soc-engine` uses declarative YAML rules because parsing is pattern
matching. Detection here is *statistical*, and the spec's use cases need real
algorithms (Lomb-Scargle, BOCPD, permutation entropy). Forcing that into YAML
would produce a worse DSL than Python. So: **the ML is Python plugins; the
policy is YAML.** Use cases declare their features/model/gate declaratively and
only write code for genuinely novel maths.

---

## 6. Module map

`src/soc_ml/` — one directory per responsibility, no cross-imports except
through `core`.

| Module | Owns | Never does |
|---|---|---|
| `core/` | Event contract, config, plugin registry, types, logging, health | any ML |
| `ingest/` | `Source` adapters, offsets/checkpoints, replay | parsing raw logs (that's the parser's job) |
| `preprocess/` | validation, derived fields, **sessionization** | feature maths |
| `state/` | windowed counters, HLL, IDF/frequency tables, TTL | deciding what to store |
| `features/` | `FeatureGroup` implementations | knowing which use case wants them |
| `models/` | algorithm wrappers with a uniform fit/score API | use-case semantics |
| `usecases/` | UC-01…15 — features + model + gate | training orchestration |
| `analytics/` | AU-01…12 — insights, not alerts | emitting alerts |
| `training/` | cadence ladder, corpus hygiene, cold-start staging | choosing thresholds |
| `detection/` | the live scoring loop | fusion |
| `fusion/` | calibration, corroboration, suppression, folding, budget, **severity** | model internals |
| `explain/` | attributions, population context, evidence, narrative | blocking detection |
| `drift/` | PSI, KS, ADWIN, regime detection | retraining (it *triggers* it) |
| `registry/` | versioning, champion-challenger, promotion gates, approval | scoring |
| `alerting/` | Alert/Insight schema + `Sink` adapters | deciding severity |
| `evaluation/` | SAIF generators, backtest harness, metrics | training |
| `baseline/` | environment profile: rarity, calendars, asset weights, roles | detection |
| `cli/` | commands | logic |

---

## 7. Environment-specific learning (P4) — the differentiator

The requirement "alerts must be environment-specific, not generic" is met by an
explicit **Environment Profile**, built by `baseline/` before any detection runs
and refreshed continuously. It is the deployment's learned self-portrait:

| Learned artifact | Replaces the generic thing | Refresh |
|---|---|---|
| Path IDF / rarity table | a hardcoded "sensitive paths" list | rolling 30 d, continuous |
| UA frequency + first-seen | a static known-crawler list | rolling 30 d, continuous |
| Known-crawler clusters (UC-04) | user-agent string matching | daily |
| Activity calendar | a hardcoded "night = suspicious" | weekly |
| Per-path response-size GMMs | a fixed byte threshold | weekly |
| Endpoint roles (UC-15) | manual endpoint classification | weekly |
| **Asset weights** | a manually curated crown-jewels list | weekly |
| Calibration percentiles | fixed score cutoffs | continuous |
| Traffic baselines (AU-01/02) | fixed rate limits | hourly/daily |

Two rules make this real rather than aspirational:

- **No detector may read a literal threshold from config.** Config carries
  budgets, modes, cadences, and toggles. Any number compared against data comes
  from the profile. This is enforced by a lint in CI.
- **Every alert cites the profile values it was judged against** (`value` vs
  `population_p50`/`p99`), so an analyst sees *"47 unique 404 paths/min, this
  server's normal p99 is 3"* rather than *"exceeded threshold"*.

A new server joins on **fleet-level fallback** profiles and graduates to its own
as data accumulates (spec §8).

---

## 8. Continuous learning — never going stale

The cadence ladder (SPEC_DIGEST §8) is implemented as a scheduler over
`training/`, with drift as an **additional trigger**, never the only one:

```
continuous  ──► online models (Half-Space Trees, BOCPD, EWMA/CUSUM),
                IDF/frequency tables, calibration windows
nightly     ──► IForest/LOF, feedback re-rankers        ⟵ also on ADWIN/PSI
weekly      ──► AEs, GMMs, char LMs, clustering, forecasters
                                                        ⟵ also on PSI>0.25 (≥2 feats)
monthly     ──► VAEs, UC-10 HMM                         ⟵ also on score-KS
quarterly   ──► UC-13 chain HMM, priors, governance review
```

Promotion is never automatic for Tier-1. The registry enforces the four gates —
no SAIF regression, KS p > 0.01 on benign traffic, alert volume within ±20%, and
a **human sign-off for Tier-1** — with the challenger soaking ≥72 h in `shadow`
first. Lower tiers auto-promote once the three mechanical gates pass.

**Corpus hygiene is enforced at the trainer, not left to discipline:** drop the
top 0.1% most-anomalous windows, clip at p99.9, and permanently quarantine
confirmed-incident windows. A trainer that skips this fails CI.

---

## 9. Accuracy and alert-volume reduction

Both goals — *accurate* and *fewer alerts* — are the same mechanism: never let a
single weak signal reach a human.

1. **Two-level gating.** A per-event score never alerts; it must raise a
   per-entity burst too.
2. **Evidence floors.** UC-06 needs ≥50 content requests, UC-09 ≥10
   grammar-breaking URLs, UC-15 ≥200 calls. Small-sample anomalies are noise.
3. **Learned suppression.** UC-04's crawler clusters and human-likeness feed
   UC-02/06/15 directly.
4. **Operational rerouting.** Anything hitting >30% of entities at once is a
   deployment/outage, not an attack — it goes to Analytics (AU-11).
5. **Campaign folding.** UC-12 collapses a 500-IP storm into one campaign alert.
6. **Corroboration.** ≥2 independent use cases on one entity within 30 min
   escalates; conversely, lone weak signals stay low.
7. **Rate governance.** Per-UC daily budget (default 50); overflow becomes a
   digest. **Delivery only — every score is still recorded.**
8. **Feedback re-ranking** after ≥200 analyst verdicts, with
   `benign-true-positive` kept as a distinct verdict so correct-but-authorized
   detections don't corrupt precision.

Measured against the spec's gates: **PR-AUC ≥ 0.85**, **FP ≤ 3/day/server**,
precision ≥ 0.80 (28-day rolling), stability CV ≤ 0.2.

---

## 10. Storage layout

```
data/
├── baselines/<org>/<env>/<server>/     environment profile (versioned, replayable)
│     idf.db  ua_freq.db  calendar.json  asset_weights.json  roles.json
├── models/<usecase>/<version>/         artifact + metadata.json + calibration.json
│     └─ metadata: training window, row count, feature-code git SHA, SAIF scores
├── state/                              windowed counters, HLL, sessions (SQLite in standalone)
└── reports/                            backtest + SAIF results, drift reports
```

`data/` is gitignored — **learned artifacts are never committed**. A deployment
is reproducible from *config + event replay + registry metadata*, which is what
makes any alert auditable after the fact.

---

## 11. Language and stack

**Python 3.11+.** Chosen because the parser is Python (one language across the
SOC stack, shared operators), the entire spec's algorithm list exists there and
essentially nowhere else as a coherent set (`scikit-learn`, `river`, `hmmlearn`,
`ruptures`, `datasketch`, `statsmodels`, PyTorch), and plugin authors in a SOC
are far more likely to write Python than Rust or Go. Where throughput demands it,
the escape hatches are the same ones the parser uses — `orjson`, vectorized
NumPy, optional `confluent-kafka`, and Flink at the top profile — rather than a
rewrite.

**Dependency policy:** the `standalone` profile installs a small core
(`numpy`, `scipy`, `scikit-learn`, `river`, `pyyaml`, `orjson`). Heavy or
optional dependencies (PyTorch, hdbscan, MLflow, Kafka, Redis clients) are
**extras**, and any component whose extra is missing degrades to a documented
fallback with a health event — never a crash (the parser's GeoIP behaviour, applied
throughout).

---

## 12. Relationship to `foss-soc-engine`

Strictly one-directional: **parser → framework**. The ML framework never modifies,
imports, or requires changes to the parser. It consumes the parser's ECS output
and treats the contract in SPEC_DIGEST §3 as frozen. Any field the framework
wishes existed is a feature request against the parser's rules, not a coupling.

This keeps both projects independently deployable and independently open-sourced,
and means the framework works for anyone whose pipeline emits the contract —
Filebeat, Vector, Logstash, or a hand-rolled shipper.
