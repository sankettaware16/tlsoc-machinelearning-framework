# Requirements

Stable IDs — reference them in commits, tests, and PRs (e.g. `closes FR-12`).
Traceability: every requirement names where it is satisfied and how it is proven.

Legend: **MUST** = release-blocking · **SHOULD** = strongly expected ·
**MAY** = optional//future.

---

## 1. Functional — ingestion & contract

| ID | Requirement | Source | Verified by |
|---|---|---|---|
| FR-01 | MUST accept ECS JSON events matching the input contract (SPEC_DIGEST §3) and reject/dead-letter malformed events with a reason, never silently. | spec §5 | contract tests on `log_samples/` |
| FR-02 | MUST support file-tail ingestion of the parser's output directory with restart-safe checkpoints. | user decision | restart/replay test |
| FR-03 | SHOULD support Kafka and Elasticsearch sources behind the same `Source` interface. | spec §13.1 | adapter tests |
| FR-04 | MUST support **replay** of historical events (rewind), because cold-start warmup, backtest, and SAIF all depend on it. | spec §12.4 | replay determinism test |
| FR-05 | MUST treat `event.original` as evidence only and **never** as a model input. | spec §5 | CI lint |
| FR-06 | MUST treat `observer.*` as namespace/partitioning keys, never as features. | spec §5.3 | CI lint |
| FR-07 | MUST reconstruct entity `(server, ip, ua_hash)` and sessions with a configurable idle gap (default 30 min). | spec §5.4 | sessionization unit tests |
| FR-08 | MUST detect `@timestamp` carrying **ingest** time rather than **event** time, and surface it as a data-quality failure (`validate --strict`). Batched timestamps drive inter-arrival CV to ~0, which reads as "machine-regular" and *manufactures* false positives in UC-01/UC-04. Trust `event.timestamp_source` when present; fall back to a **sub-second** collision heuristic only — second-resolution collisions are normal CLF traffic on a busy server and MUST NOT be flagged. | D-012, D-014 | `tests/test_validate.py` |

## 2. Functional — feature platform

| ID | Requirement | Source | Verified by |
|---|---|---|---|
| FR-10 | MUST compute feature groups over sliding windows 1m/5m/30m/24h (+6h/7d/168h where a use case needs them). | spec §5.3 | window tests |
| FR-11 | MUST compute each feature **once** and share it across all subscribing use cases. | ARCH §5 | instrumentation test (no duplicate computation) |
| FR-12 | MUST maintain rolling 30-day path-IDF and UA-frequency tables as learned state. | spec §5.5 | state tests |
| FR-13 | SHOULD use HyperLogLog for unique counts to bound memory (~12 KB/entity-window). | spec §5.5 | memory benchmark |
| FR-14 | MUST let a use case declare its feature dependencies declaratively. | ARCH §5 | plugin tests |

## 3. Functional — detection

| ID | Requirement | Source | Verified by |
|---|---|---|---|
| FR-20 | MUST implement Tier-1 use cases UC-01, UC-02, UC-04, UC-06, UC-07. | spec §6 | per-UC SAIF suites |
| FR-21 | SHOULD implement Tier-2 (UC-03/05/08/09/10/12) and Tier-3 (UC-11/13/14/15). | spec §6 | per-UC SAIF suites |
| FR-22 | MUST calibrate every raw score to a percentile **per use case per server** before any comparison or gating. | spec §6.18 | calibration tests |
| FR-23 | MUST enforce per-use-case evidence floors (e.g. UC-06 ≥50 requests, UC-09 ≥10 URLs, UC-15 ≥200 calls). | spec §6 | gate tests |
| FR-24 | MUST NOT allow a single event to raise an alert without a corresponding per-entity signal (two-level gating). | spec §6 | gate tests |
| FR-25 | MAY keep a thin Sigma-style indicator layer for known-bad, kept separate from ML scoring. | spec §6.1 | — |

## 4. Functional — fusion, severity, alerting

| ID | Requirement | Source | Verified by |
|---|---|---|---|
| FR-30 | MUST apply the five fusion steps in order: calibrate → corroborate → fleet-simultaneity suppress → campaign fold → rate-govern. | spec §6.18 | fusion order tests |
| FR-31 | MUST escalate one severity band when ≥2 independent use cases fire on one entity within 30 min. | spec §6.18 | fusion tests |
| FR-32 | MUST reroute anomalies affecting >30% of entities simultaneously to Analytics, not the security queue. | spec §6.18 | suppressor tests |
| FR-33 | MUST compute severity by the single formula in SPEC_DIGEST §7, with a **learned** `asset_weight`. | spec §17.2 | severity tests |
| FR-34 | MUST apply per-use-case daily alert budgets (default 50) affecting **delivery only** — every score is still recorded. | spec §6.18 | budget tests |
| FR-35 | MUST emit ECS-aligned alerts (`event.kind=alert`) per the master schema so existing SIEM/SOAR connectors work unchanged. | spec §17.1 | schema validation |
| FR-36 | MUST make every suppression, fold, and budget decision **visible** in the alert document — never silent. | P7 | schema tests |

## 5. Functional — explainability

| ID | Requirement | Source | Verified by |
|---|---|---|---|
| FR-40 | MUST attach per-feature attributions to every alert (TreeSHAP / reconstruction-error breakdown / per-dimension distance / decoded state path / cluster contrast, per model family). | spec §16 | per-model explainer tests |
| FR-41 | MUST include population context (`value`, `population_p50`, `p99`) so the analyst sees the learned baseline. | spec §16, G1 | schema tests |
| FR-42 | MUST attach 3–10 verbatim `event.original` evidence lines. | spec §16 | schema tests |
| FR-43 | MUST run explanation **asynchronously** so it never delays detection. | spec §16 | latency test |
| FR-44 | MUST record the exact model versions that produced each score. | spec §14 | audit test |

## 6. Functional — learning lifecycle

| ID | Requirement | Source | Verified by |
|---|---|---|---|
| FR-50 | MUST implement the cadence ladder: continuous / nightly / weekly / monthly / quarterly. | spec §11.3 | scheduler tests |
| FR-51 | MUST additionally trigger retraining on drift: ADWIN/PSI (nightly), PSI>0.25 on ≥2 features (weekly), score-KS (monthly). | spec §11.3, §15 | drift trigger tests |
| FR-52 | MUST implement staged cold-start (Stage 0 observe-only → Stage 3 full) and allow **per-use-case mode overrides**. | spec §11.2 | staging tests |
| FR-53 | MUST version every artifact (model, scaler, calibration table, IDF snapshot) with training window, row count, feature-code git SHA, and SAIF scores. **Nothing unversioned may serve.** | spec §14 | registry tests |
| FR-54 | MUST keep 3 versions hot and auto-fall-back to the previous champion on load failure. | spec §14, §13.5 | failover test |
| FR-55 | MUST gate promotion on: no SAIF regression, KS p>0.01 on benign traffic, alert volume within ±20%, **and human sign-off for Tier-1**; challenger soaks ≥72 h in shadow. | spec §14 | promotion gate tests |
| FR-56 | MUST enforce corpus hygiene: exclude top 0.1% anomalous windows, clip at p99.9, permanently quarantine confirmed-incident windows. | spec §11.5 | trainer tests |
| FR-57 | SHOULD arm semi-supervised feedback re-rankers per use case after ≥200 analyst verdicts. | spec §11.1 | — |
| FR-58 | MUST NOT use supervised learning as a primary detector, and MUST NOT train on synthetic (SAIF) data. | spec §11.1, §12.1 | CI lint + review |

## 7. Functional — environment-specific learning

| ID | Requirement | Source | Verified by |
|---|---|---|---|
| FR-60 | MUST build an Environment Profile (path IDF, UA frequency, crawler clusters, activity calendar, response-size GMMs, endpoint roles, asset weights, calibration percentiles) from the deployment's own data. | ARCH §7, G1 | profile tests |
| FR-61 | MUST learn `asset_weight` rather than require a curated crown-jewels list (an explicit override MAY be supplied). | spec §17.2 | severity tests |
| FR-62 | **No detector may read a literal detection threshold from configuration.** Config carries policy (modes, budgets, cadences), never data thresholds. | G1, P4 | **CI lint** |
| FR-63 | MUST start a new server on fleet-level fallback models and graduate it to per-server models as data accumulates. | spec §11.2 | fallback tests |
| FR-64 | MUST derive seasonality handling from learned baselines (ratio features, time-of-week normalization, 72 h band widening on regime change, 12–18 mo annual series). | spec §11.4 | seasonality tests |

## 8. Functional — offline, evaluation, modes

| ID | Requirement | Source | Verified by |
|---|---|---|---|
| FR-70 | MUST support `offline`, `shadow`, and `live` run modes, selectable **per use case**. | ARCH §4, user req | mode tests |
| FR-71 | MUST be able to run a full backtest over historical logs with **no live stream and no infrastructure**. | G5, G7 | backtest on `log_samples/` |
| FR-72 | MUST run backtests through the **real engine code** via replay — never a separate notebook reimplementation. | spec §12.4 | CI |
| FR-73 | SHOULD provide SAIF: replay real traffic + inject parameterized synthetic attacks per use case with ground truth, as a release regression gate. | spec §12.1 | SAIF suite |
| FR-74 | MUST report PR-AUC (primary), recall@FP-budget, FP rate, precision, time-to-detect, and stability CV. | spec §12.2 | metrics tests |

## 9. Non-functional

| ID | Requirement | Target | Verified by |
|---|---|---|---|
| NFR-01 | **Detection quality** — Tier-1 PR-AUC | ≥ 0.85 | SAIF |
| NFR-02 | **False positives** — analyst-confirmed | ≤ 3 / day / server | live metrics |
| NFR-03 | **Precision** — 28-day rolling, Tier-1 | ≥ 0.80 | analyst verdicts |
| NFR-04 | **Stability** — recall/TTD spread over 20 replay runs | CV ≤ 0.2 | replay suite |
| NFR-05 | **Throughput** — `standalone` profile | ≥ 2k events/s single box | benchmark |
| NFR-06 | **Scalability** — `enterprise` profile | 50k+ events/s via sharding | design review |
| NFR-07 | **Zero-infra default** — `standalone` requires no Kafka/Redis/MLflow/ES | hard requirement | fresh-install test |
| NFR-08 | **Graceful degradation** — a missing optional dependency degrades to a documented fallback with a health event, never a crash | hard requirement | dependency-absent tests |
| NFR-09 | **No silent failure** — every degradation, drop, and suppression emits a record | hard requirement | fault-injection tests |
| NFR-10 | **Reproducibility** — any alert reconstructable from config + replay + registry metadata | hard requirement | audit test |
| NFR-11 | **Licence** — Apache-2.0; no dependency requiring a commercial licence on the default path | hard requirement | licence audit |
| NFR-12 | **Extensibility** — a new use case requires zero core-file edits | hard requirement | plugin drop-in test |
| NFR-13 | **Isolation** — detection and analytics never share a runtime; analytics may lag freely, Tier-3 sheds before Tier-1 | spec §13.1 | backpressure test |
| NFR-14 | **One-directional coupling** — the framework never requires changes to `foss-soc-engine` | hard requirement | review |

## 10. Open questions

Tracked here until resolved, then moved to `JOURNAL.md` as decisions.

| ID | Question | Blocks |
|---|---|---|
| OQ-01 | Confirm "minimise application traffic volume" means **reducing SOC alert volume / noise** (the reading this design assumes), not throttling actual HTTP traffic. | framing of G2 |
| OQ-02 | Is Elasticsearch/Kibana already the destination for alerts in the target deployment, or should file/webhook sinks lead? | sink priority |
| OQ-03 | How much historical parsed data is available for the initial backtest (affects how fast cold-start can be simulated)? | Phase 1 timing |
| OQ-04 | Is analyst feedback capture (verdict UI) in scope for this project, or does it come from the existing SIEM? | FR-57 |
| ~~OQ-05~~ | ~~The nginx parser rule stamps `@timestamp` at parse time~~ — **CLOSED, incorrect.** The rule has a valid `timestamp:` block; the sample file was stale output from a superseded engine version. Regenerated through the current engine (`timestamp_source: log`). See JOURNAL D-014. | — |
