# Spec Digest — the distilled source of truth

**Why this file exists:** the original specification is a very large Word
document (`ML_Cybersecurity_Detection_and_Behavioral_Analytics_Framework.docx`,
tens of thousands of words). Reading it in full is slow and rarely necessary.
This digest reproduces every load-bearing decision — use cases, feature formulas,
model choices, thresholds, cadences — so that **you should never need to open the
Word document to work on the codebase**. If you find something in it that is not
here and it matters, add it here and note it in `JOURNAL.md`.

**Status:** faithful to the .docx as of 2026-07-21. The .docx is authoritative on
conflict; this digest is authoritative for day-to-day work.

---

## 1. Core thesis

> Never write fixed-threshold rules ("alert if > 100 req/min"). Models learn what
> *normal* looks like **for this environment** and flag deviations. Every use case
> is that one idea applied to a different attack.

Two consequences that drive the whole architecture:

1. **Everything is percentile-calibrated, never absolute.** A raw model score is
   meaningless across servers; a 99.7th-percentile score is comparable everywhere.
2. **The framework is environment-independent by construction.** No org-specific
   config is *required*. Rarity, sensitivity, roles, crawler identity, and
   seasonality are all *learned* from the deployment's own logs.

Sigma-style rules are kept as a thin high-confidence layer ("free precision"):
known scanner UAs, known exploit paths, canary paths, Googlebot IP verification,
compliance hard-caps. ML owns everything behavioral. Expected outcome: cut
**60–80% of manual threshold-rule maintenance**.

---

## 2. Two independent pipelines

Both read the same input and share nothing at runtime. Separation is deliberate:
failure isolation (a slow analytics job can never delay a security alert),
different latency needs, different scaling, different release pace.

```
Apache/NGINX/app servers
   └─ log shipper (rsyslog/filebeat)
        └─ NORMALIZER  ← this is foss-soc-engine, already built
             └─ canonical ECS JSON  (topic raw.weblogs.v1 / file tail)
                  ├─► PIPELINE 1: DETECTION ENGINE   (seconds)
                  │      preprocess → features → inference → fusion+severity
                  │      → explain → alerts.web.ml.v1 → soc-web-ml-alerts-*
                  └─► PIPELINE 2: ANALYTICS ENGINE   (minutes–hours)
                         aggregation → baselines/forecast → drift monitors
                         → insights → analytics.web.insights.v1 → soc-web-analytics-*
```

**Shared services:** Model Registry (MLflow), Feature/State Store (Redis),
Drift Monitor, Champion-Challenger Trainer, Feedback Collector, Metrics/Health
(Prometheus + Grafana).

---

## 3. Data input contract (the only integration point)

This is **the single contract between any organization's logging and this
framework**. Any org that can emit this JSON runs the framework unchanged.
`foss-soc-engine` already produces exactly this.

| Field | Notes |
|---|---|
| `@timestamp` | ISO-8601 UTC |
| `event.original` | raw line — **human inspection only, NEVER a model input** |
| `event.module` | |
| `observer.org` / `.dept` / `.env` / `.server` / `.source_host` / `.source_program` | model namespace / partitioning key — **not features** |
| `source.ip` | entity key |
| `source.geo.{country_name, country_iso_code, city_name, location.{lat,lon}}` | optional; **absence == internal IP** (that is the internal/external flag) |
| `http.request.method` | |
| `http.request.referrer` | `'-'` when none |
| `http.response.status_code` | |
| `http.response.body.bytes` | |
| `url.path` | |
| `url.query` | string or null |
| `user_agent.original` | |

**Deliberately out of scope (do not design around them):** usernames, request
bodies, response contents, most headers, TLS details, **and response
time/latency** (not in the schema — service-health analytics use status-code mix
and byte sizes as a latency stand-in). Also excluded as sources: EDR, firewall,
DNS, email, auth/IdP, NetFlow, WAF verdicts, DB audit.

### Entity and session identity

Logs carry no usernames, so identity is reconstructed:

```
ENTITY KEY  = (observer.server, source.ip, sha(user_agent.original))
SESSION KEY = same triple; consecutive events form one session until an
              idle gap > 30 minutes  (configurable — a GROUPING default,
              not a detection threshold)
```

Rollups: `/24` and `/16` subnets. Sliding windows: **1m / 5m / 30m / 24h**
(plus 6h / 7d / 168h for long-window use cases).

Session features (computed at session end and every 60 s while live):
`duration_s, event_count, unique_paths, paths_per_minute,
status_class_histogram, bytes_total, mean_inter_arrival, cv_inter_arrival,
referrer_present_ratio, method_histogram, path_depth_mean, entry_path,
exit_path, path_sequence`.

**Known limitation (state it, don't hide it):** IP+UA identity fragments under
CGNAT and shared proxies. UC-11 is explicitly probabilistic for this reason.

### Entity state layout (Redis keys, or the local equivalent)

```
st:{server}:{ip}:{ua_hash}:w1m|w5m|w30m   rolling counters, HLL for uniques
st:{server}:{ip}:day:{yyyymmdd}           daily egress (UC-07)
st:{server}:path_idf                      rolling 30-day path rarity table
st:{server}:ua_freq                       rolling UA frequency table
```
Keys expire at 2× window length. HLL ≈ 12 KB per entity-window.

---

## 4. Feature platform

Built **once**, each use case subscribes to a subset. Feature groups:
Timing · Volume · Path structure · Path rarity (IDF — the heaviest state) ·
Query grammar · Status mix & sequence · Method mix · Referrer/navigation ·
Identity (UA) · Geo · Cross-entity · Cross-use-case.

### Raw field → derived features

| Raw field | Derived |
|---|---|
| `@timestamp` | hour-of-day, day-of-week, weekend flag, inter-request gaps, req/min per entity, burstiness |
| `source.ip` | entity key; unique paths per IP; unique UAs per IP; /24 rollups; internal/external flag |
| `source.geo.*` | country frequency encoding, geo-rarity score, geo mix per window |
| `http.request.method` | GET/POST/HEAD/other ratio per entity-window; rare-method frequency |
| `http.response.status_code` | 2xx/3xx/4xx/5xx shares, 404-ratio, 401/403-ratio, status sequences, error bursts |
| `http.response.body.bytes` | bytes/window (sum, mean, p95), bytes-per-request profile, total egress per IP per day |
| `url.path` | depth, token count, character entropy, digit ratio, extension class, **path rarity (IDF)**, unique paths per IP |
| `url.query` | length, special-char ratio, encoded-char ratio, entropy |
| `http.request.referrer` | referrer-present ratio, internal vs external, navigation-chain checks |
| `user_agent.original` | browser/OS/device family, UA length & entropy, UA rarity, UAs-per-IP |
| `observer.*` | **namespace key only — never a feature** |

### Technique glossary

- **IDF / path rarity** — rare URLs score high; rolling 30-day corpus.
- **Entropy** — low = human, high = scanner.
- **MinHash** — set-similarity fingerprint for campaign stitching.
- **HyperLogLog (HLL)** — approximate unique counts, ~12 KB per entity-window.
- **STL** — trend + weekly/daily seasonality + remainder; anomalies live in the remainder.

---

## 5. Detection use cases (UC-01 … UC-15)

Ranked by SOC value × practicality. **Tier = build order.**

| # | ID | Use case | Tier | Detects by |
|---|---|---|---|---|
| 1 | UC-01 | Credential stuffing & password spraying | 1 | POST-heavy, constant failed-login response size, robotic timing, cross-IP coordination |
| 2 | UC-02 | Web recon & directory enumeration | 1 | 404-mix, path rarity, entropy — **rate-independent** |
| 3 | UC-04 | Bot & abnormal crawler detection | 1 | Traffic ecology; UA-vs-behavior mismatch. **Produces the known-crawler-cluster FP suppressor used by UC-02/06/15** |
| 4 | UC-06 | Web scraping & content harvesting | 1 | Session coverage geometry, exhaustive/sequential-ID walking |
| 5 | UC-07 | Data exfiltration via HTTP responses | 1 | Egress burst, per-path size-distribution break, slow drip |
| 6 | UC-03 | Low-and-slow & distributed scanning | 2 | Long windows + campaign stitching |
| 7 | UC-08 | Beaconing / periodic automated clients | 2 | C2 metronome timing vs benign periodicity |
| 8 | UC-09 | Injection probing & rare URL/query anomalies | 2 | Structurally alien URLs vs the app's **own learned grammar** |
| 9 | UC-05 | User-agent spoofing & UA anomalies | 2 | UA string rarity, malformation, rotation, crawler impersonation |
| 10 | UC-10 | Response-code sequence anomalies | 2 | Status **transitions** (e.g. 403→200 "yield") that ratios cannot see |
| 11 | UC-12 | Distributed attack campaign clustering | 2 | Aggregates elevated entities across all UCs; collapses alert storms |
| 12 | UC-11 | Session abuse & token replay | 3 | Probabilistic continuation/hijack — **lead generator, not alarm** |
| 13 | UC-13 | Attack-chain progression (kill-chain staging) | 3 | Sub-threshold multi-day progression **in order** |
| 14 | UC-14 | Novel-behavior / zero-day ensemble | 3 | Insurance layer for unmodeled behavior |
| 15 | UC-15 | Application abuse / living-off-the-app | 3 | Learned endpoint **roles**; entities breaking a role's norm |

**Deliberately excluded:** SQLi/XSS payload matching (bodies not in schema;
probing covered behaviorally by UC-09), volumetric DDoS (network layer),
TLS-fingerprint anomalies (no TLS in schema).

### Per-use-case features and models

Format: **features** → *model(s)* → `alert gate`.

- **UC-01** `post_ratio_w5m`, `repeat_path_ratio_w5m`, `resp_size_cv_w5m` (CV of
  response bytes — failed-login pages are constant size, so bots → CV≈0),
  `fail_shape_match_ratio` (share matching a learned GMM failed-login shape over
  `(status_code, log bytes)`), `interarrival_cv`, `interarrival_median`,
  `distinct_paths_w30m` (HLL), `referrer_present_ratio`, `ua_rarity` (30-day),
  `subnet_active_entities` (/24), `campaign_fingerprint`.
  → *Half-Space Trees* (streaming, `river`, O(1)/event) for Layer A;
  *Isolation Forest* nightly on 60 s coordination summaries + *HDBSCAN* for
  Layer B coordination; *GMM* over `(status, log bytes)` per path to learn the
  failed-login shape.
  `> 99.5th pct of recent scores; lone candidates capped at 1 alert/entity/30 min`
  *Rejected: LSTM-AE (cost, slow cold start), One-Class SVM (doesn't scale past ~100k rows).*

- **UC-02** `ratio_404_w5m − population median`, `mean_path_idf_w5m` (fleet
  30-day IDF), `path_token_entropy_w5m`, `uniq_paths_per_min` (HLL),
  `nonexistent_extension_ratio` (.zip/.bak/.sql/.env on an app serving none),
  `referrer_absent_ratio`, `status_class_vector`, `ua_len`, `ua_rarity`,
  `interarrival_cv`.
  → *Isolation Forest* (nightly) + *LOF* in novelty mode (catches
  odd-in-local-neighborhood on small sites). **Fusion = max of the two after
  percentile conversion.**
  `fused pct >= 99.7; suppressed if entity is in the known-crawler cluster and still polite;
   progressive alerting — first candidate "low", upgraded as evidence accumulates over 10 min`

- **UC-03** `mean_path_idf` over 24h/7d, `uniq_rare_paths_w7d` (HLL),
  `minhash_128(rare_paths)`, `ua_set_hash`, `ua_count_w7d`,
  `timing_histogram_24bin`, /24 + /16 rollups, `jaccard_to_nearest_campaign`.
  → *Isolation Forest* on long windows; *HDBSCAN* (min cluster size 5) over
  MinHash similarity for campaign stitching (**chosen over DBSCAN because
  density varies and HDBSCAN needs no distance threshold**); *MinHash-LSH*
  (`datasketch`) to make candidate search near-linear.

- **UC-04** `interarrival_cv`, `fano_factor`, `activity_hour_entropy` (24-bin),
  `asset_fetch_ratio` (.css/.js/img — browsers fetch sub-resources, scripts
  don't), `referrer_present_ratio`, `referrer_chain_depth`, `uniq_paths`,
  `path_repeat_ratio`, `path_idf_mean`, `method_vector`, `status_vector`,
  `bytes_per_req` (p50, p95), `declared_bot`, `ua_rarity`, `ua_len`,
  `robots_txt_fetched`.
  → *HDBSCAN* over daily behavior vectors (daily); *GMM* (BIC-selected, weekly)
  giving **human-likeness** probability; *gradient-boosted classifier predicting
  the `declared_bot` flag from behavior alone* — self-supervised, the clearest
  case of free labels; isotonic-calibrated.
  `spoofing alert: browser-UA entity with P(bot|behavior) >= p99.5 sustained >= 30 min`

- **UC-05** `ua_char3gram_perplexity`, `ua_freq_30d`, `ua_first_seen_age`,
  parsed family/os/device consistency, `ua_count_per_ip_w1h`, `ua_switch_rate`,
  `claimed_crawler_family`, `mahalanobis_to_claimed_cluster`.
  → char-3-gram perplexity LM (malformation); frequency/recency encoding +
  *Isolation Forest* (rotation/rarity); *Mahalanobis* (shrinkage covariance) to
  the claimed crawler centroid (impersonation).
  `rotation >= p99.7; impersonation >= p99.5 with min volume;
   malformed UA ALONE never alerts — feature only`

- **UC-06** `coverage_density` = unique content paths ÷ estimated size of that
  content family (HLL ratio), `id_seq_score` (permutation entropy of numeric
  path tokens → sequential-ID walking), `content_class_concentration` (Gini),
  `bytes_total_session`, `bytes_rate`, `nav_interleave_ratio`,
  `referrer_validity_ratio`, `session_duration`, `req_count`, `interarrival_cv`,
  `human_likeness` (from UC-04).
  → dense **autoencoder, architecture 16-8-4-8-16**, over 24-number session
  vectors, per server; reconstruction error = score. Secondary: seasonal-quantile
  egress model.
  `smoothed score >= p99.5 AND >= 50 content requests (evidence floor)`
  *Rejected: LSTM-AE (~10× cost, planned v2), IForest.*

- **UC-07** `log_bytes` likelihood under the path-family GMM,
  `cum_bytes_per_entity` over 15m/1h/24h,
  `forecast_breach = (actual − p99.5 forecast) / IQR`,
  `egress_rhythm_vec_168h`, `uniq_paths_in_egress`, `id_seq_score`,
  `offhours_egress_share` (**against a learned activity calendar, not a
  hardcoded "night"**), `geo_novelty`.
  → per-path-family *GMM* on `log(bytes)` conditioned on status; *quantile GBM*
  forecaster (p50/p95/p99.5 per entity-class per hour-of-week); ***β-VAE (β=2)***
  on 168-h rhythm vectors for slow drip. Cross-check: Seasonal-ESD.
  *Postponed: LSTM forecaster.*

- **UC-08** `dominant_period_s`, `spectral_concentration`, `period_jitter_cv`,
  `bytes_cv`, `bytes_p50`, `path_idf`, `path_age_days`, `onset_age_days`,
  `activity_calendar_overlap`, `declared_bot`, `ua_rarity`, `status_constancy`.
  → *GMM* (BIC) over periodicity vectors; ***Lomb-Scargle periodogram — NOT FFT,
  because timestamps are unevenly spaced***; *BOCPD* per entity for onset.
  `outlierness >= p99.5 PLUS >= 2 supporting context features`

- **UC-09** `url_recon_error`, `char4gram_perplexity`, `special_char_ratio`,
  `hex_encoded_ratio`, `%25-density`, `query_len_z` (vs that path family's
  population), `param_battery_width`, `status_5xx_follow_ratio`.
  → character-level **convolutional autoencoder** (vocab ≈100 chars, max length
  512) per server; **cheap tier = char 4-gram LM giving ~80% of the value at 5%
  of the cost — both ship behind a config switch**; *LOF* over the entity vector.
  `entity LOF >= p99.7 AND >= 10 grammar-breaking URLs;
   a single URL >= p99.99 plus a 5xx may fast-path alone at "medium"`

- **UC-10** `status_class_sequence` per session over **5 symbols**
  (2xx / 3xx / 4xx-auth / 4xx-notfound / 5xx), `hmm_loglik_per_event`
  (length-normalized), transition-matrix KL vs the entity's own 30 min history,
  `success_run_length` trend on **rare** paths.
  → *HMM* (5 emission symbols, **3–8 hidden states chosen by BIC**) per server;
  online KL + BOCPD.
  `(HMM likelihood <= p99.5) OR (change-point + lengthening success runs on rare paths)`
  *Planned v2: LSTM-AE.*

- **UC-11** `entry_referrer_in_prior_session_paths`, `ua_exact_match`,
  `ua_rarity`, `gap_seconds`, `geo_km`, `implied_velocity`,
  `nav_profile_cosine`, `profile_break_recon_error`, `sensitive_path_novelty`
  (pages untouched in 90 d, rarity-weighted).
  → gradient-boosted **pair-similarity** model, self-supervised on naturally
  benign IP-hop continuations; autoencoder profile-break scorer.
  **Requires BOTH a link AND a profile break to fire** (FP control).

- **UC-12** `ua_set_simhash`, `timing_texture` (16-bin gap histogram),
  `target_minhash`, `geo_dispersion_profile`, `uc_score_vector`.
  → *HDBSCAN* on standardized fingerprints + registry matching (centroid +
  MinHash). *Considered: DenStream — postponed.*

- **UC-13** daily score-percentile vector per use case (13-dim),
  `novel_path_family_emergence`, `first_success_after_probing` (from UC-10),
  `egress_percentile` (from UC-07).
  → *HMM* over daily vectors, Gaussian emissions, **5 hidden states**, transition
  prior biased left-to-right with self-loops plus drop-back-to-Dormant. States:
  **Dormant → Survey → Target → Foothold → Harvest**.
  `P(state >= Foothold) >= 0.7  OR  ordered-traversal posterior >= 0.6`
  *Considered: transformer — postponed.*

- **UC-14** "the master vector" — union of UC-01…10 feature groups (~60 numbers),
  no new extraction.
  → ensemble of *Isolation Forest* + *β-VAE* + *LOF* (novelty), each
  percentile-calibrated per server. **Diversity of inductive biases is the point.**
  `consensus >= p99.9 from ALL THREE models -> alert (default "medium");
   disagreement -> daily hunting digest`

- **UC-15** role-discovery features (per-endpoint client diversity,
  rate-distribution quantiles, referrer-arrival ratio, 168-h temporal shape,
  method mix, bytes profile); usage features (calls/day vs role norm,
  `param_systematicity` = permutation entropy of query tokens, referrer validity,
  navigation interleave, session-style summary).
  → *k-medoids / HDBSCAN* for endpoint-role discovery (weekly); per-role dense
  *autoencoder*; *LOF* within each endpoint's peer group.
  `AE >= p99.5 AND LOF >= p99 AND (>= 200 calls OR >= 10x role p99)`

---

## 6. Analytics use cases (AU-01 … AU-12)

Produce **insight documents, not alerts.**

| # | ID | Use case | Models |
|---|---|---|---|
| 1 | AU-01 | Hourly/daily traffic baselines & forecasts | STL + quantile GBM (pinball loss) |
| 2 | AU-02 | Weekly/monthly/seasonal decomposition | MSTL + PELT change-points + regime library + Fourier (annual, needs ≥18 mo) |
| 3 | AU-11 | Operational anomaly & service-health insights | Fleet-simultaneity + residual CUSUM — **implements the fusion suppressor** |
| 4 | AU-03 | Geo-distribution evolution & drift | JS-divergence + self-calibrated EWMA + Dirichlet-multinomial smoothing |
| 5 | AU-04 | Client population evolution (UA/device ecology) | UC-04 cluster registry trends + PELT |
| 6 | AU-05 | Resource popularity drift & emerging resources | Kleinberg burst detection + rank dynamics |
| 7 | AU-06 | Capacity planning & egress forecasting | Quantile GBM + Theta ensemble |
| 8 | AU-07 | Application usage drift & endpoint role map | UC-15 role registry evolution |
| 9 | AU-08 | Client behavior segmentation & evolution | GMM segments (BIC) + tracking |
| 10 | AU-09 | Department / org-unit trends | Empirical-Bayes shrinkage + reuse AU-02/03/04 |
| 11 | AU-10 | Rare-resource & shadow-content emergence | HDBSCAN cohorts + IForest on birth-context |
| 12 | AU-12 | Executive KPI synthesis & narrative digest | Submodular coverage selection + **deterministic templates** |

> AU-12 deliberately avoids free-text generation — auditability over fluency.

**Analytics → detection feedback:** AU-03 geo-drift and AU-10 shadow-content seed
UC-12 campaigns; AU-11 annotations feed the fusion suppressor; AU-08 segment
baselines let detection score entities relative to their peer segment.

---

## 7. Scoring, fusion, severity, alerting

### Fusion layer — five ordered steps (on `ml.scores.elevated.v1`)

1. **Percentile calibration** → comparable 0–1 per UC per server.
2. **Corroboration escalation** — ≥2 independent UCs on the same entity within
   30 min → **+1 severity band**.
3. **Fleet-simultaneity suppression** — an "anomaly" hitting **>30% of all
   entities at once** is an operational event: reroute to Analytics, not the
   security queue.
4. **Campaign folding** (UC-12).
5. **Rate governance** — per-UC **daily alert budget, default 50/day**,
   configurable; overflow → digest.
   **Budgets control delivery only, never detection — every score is always recorded.**

### Severity formula (one formula for all use cases)

```
severity_score = round( 100 * fused_confidence   # calibrated 0..1
                      * asset_weight             # LEARNED endpoint sensitivity, 0.6..1.0
                      + breadth_band             # +10 if campaign >= 100, +15 if >= 1000
                      + corroboration_band       # +10 if >= 2 UCs co-fire
                      + context_band )           # +10 internal-source compromise,
                                                 # +10 transition-to-success (UC-10/13)

bands:  critical >= 90 | high 70-89 | medium 45-69 | low < 45
```

**`asset_weight` is LEARNED**, not configured — derived from response-size
profiles, client diversity, auth/export role membership, and POST share. A
deployment MAY override with an explicit asset list, but the framework never
*requires* one. This is what keeps it environment-independent.

### False-positive reduction (the accuracy story)

- **Two-level design** — a per-event score never alerts alone; it must also raise
  a per-entity burst.
- **UC-04's known-crawler cluster + human-likeness** suppress FPs in UC-02/06/15.
- **AU-11 fleet-simultaneity** reroutes operational incidents out of the queue.
- **Corroboration requirements** (UC-11 needs *both* a link and a profile break).
- **Ratio/shape features over raw counts**, so seasonal tides don't trigger.
- **`benign-true-positive` verdict class** — model correctly flagged anomalous but
  the activity was authorized; does **not** count against precision metrics.
- **Semi-supervised re-ranker** after ≥200 analyst verdicts.
- **Suppression is never silent** — every suppression leaves a visible link in the
  alert document.

### Alert schema (ECS-aligned, `event.kind=alert`)

```
alert.{id, severity, severity_score 0-100, confidence 0-1, engine, status}
rule.{id, name}        entity        target        scores        usecase
explanation.{ top_features[{feature, value, population_p50, contribution}],
              narrative, evidence_events, model_versions }
links.{ campaign_id, operational_incident, chain_state_doc, folded_alerts }
feedback.{ verdict, analyst, ts }
```

### Explainability (mandatory per alert)

Per-feature attributions (trees → TreeSHAP; AE/VAE → per-feature reconstruction
error; GMM/Mahalanobis → per-dimension distance; HMM → decoded state path;
clustering → nearest-cluster contrast), population context (value vs median/p99),
**3–10 verbatim `event.original` lines**, a deterministic narrative template, and
for UC-14 contrastive nearest-normal neighbours.
**The explainer runs asynchronously and never delays detection.**

---

## 8. Learning, cadence, lifecycle

### Learning-paradigm ladder

Unsupervised (all primary detectors) → Self-supervised (AE/VAE reconstruction,
char LMs, `declared_bot` prediction, benign IP-hop pairs) → Online/incremental
(Half-Space Trees, BOCPD, EWMA/CUSUM) → Semi-supervised (analyst-feedback
re-rankers, armed per UC after **≥200 verdicts**) →
**Supervised is NEVER a primary detector.** Synthetic labels are used for
**evaluation only, never training.**

### Retraining cadence

| Cadence | What retrains | Extra trigger beyond schedule |
|---|---|---|
| Continuous | online models, IDF/frequency tables, calibration windows | — |
| Nightly | IForest/LOF entity models, feedback re-rankers | **ADWIN / PSI drift signal** |
| **Weekly** | autoencoders, GMMs, char LMs, role/segment clustering, forecasters | **PSI > 0.25 on ≥2 features; release events** |
| Monthly | VAEs, the UC-10 HMM | **KS test on score distributions** |
| Quarterly | UC-13 chain HMM, shrinkage priors, governance review | red-team findings |

> The design diagram's "every 7 days" == the **weekly** row. There is no single
> global 7-day constant; the cadence is a ladder and "significant change" means
> the drift triggers above.

### Cold-start protocol (staged — this is how a new deployment behaves)

| Stage | Days | Behavior |
|---|---|---|
| 0 | 0–7 | ingest only; build rarity/frequency/first-seen tables; **all engines observe-only** (scores computed, nothing shown) |
| 1 | 7–14 | Tier-1 scores in observe mode; engineers review distributions; calibration percentiles established |
| 2 | 14–28 | Tier-1 **alerts go live** with conservative gates; Tier-2 observes; analytics baselines publish with widened bands |
| 3 | 28+ | full Tier-2; Tier-3 observe cycle; feedback re-rankers arm once verdicts exist |

A **new server joining an existing deployment** starts on fleet-level fallback
models and graduates to per-server models as its own data accumulates.

### Model governance

- **Registry = MLflow.** Every artifact (model, scaler, calibration table, IDF
  snapshot) is versioned with training window, data volume, git commit of the
  feature code, and SAIF scores. **"Nothing unversioned may serve."**
  **3 versions kept hot** for instant fallback.
- **Champion–challenger = the human-approval gate.** A challenger silently scores
  live traffic **≥72 h** beside the champion. Promotion requires **all** of:
  1. no SAIF regression,
  2. stable score distribution on benign traffic (**KS test p > 0.01**),
  3. alert volume within **±20%**,
  4. **human sign-off for Tier-1.**
  (Lower tiers auto-promote through the gated checks; Tier-1 always needs a human.)
- **Quarterly governance review** — learned structures that carry *meaning*
  (UC-13 chain states, UC-15 endpoint roles, UC-04 cluster labels) are audited
  and re-named by humans. **Learning is automatic; NAMING is human.**
- **Auditability** — every alert records the exact model versions that produced
  each score; any alert is reproducible from event replay + the registry.
- **Graduation path** — a UC-14 novelty, once understood, graduates into either a
  Sigma rule (fixed indicator) or a feature/use-case extension (behavioral).

### Drift management

> "For web traffic, drift is the normal operating condition, not an exception."

| Drift type | Detection | Response |
|---|---|---|
| Gradual population | **PSI per feature, weekly** | refit on the weekly cadence |
| Seasonal regime shift | AU-02 regime detection | **bands auto-widen for 72 h** |
| Abrupt app release | AU-10 cohorts + AU-11 fleet-simultaneity | corpus refresh + release annotation suppresses false alerts |
| Score/model aging | **ADWIN on score streams + weekly KS test** | early refit, spawn challenger |
| Adversarial | red-team findings + UC-14 disagreement trends | investigate |

### Poisoning resistance / corpus hygiene

- Top **0.1% most-anomalous windows excluded** from every next training corpus.
- Extreme values **clipped at the 99.9th percentile** before any fit.
- Challenger promotion requires score-distribution stability.
- **Confirmed-incident windows are permanently quarantined** from all corpora.

### Seasonality — four rules

1. Prefer **ratio/shape** features over raw counts.
2. Where counts are unavoidable, normalize by **time-of-week quantiles** from AU-01.
3. On an AU-02 regime transition, **widen all calibration bands for 72 h**.
4. Handle annual effects by keeping **12–18 months** of aggregate series.

---

## 9. Offline, shadow, and evaluation

- **Observe mode** — scores computed, nothing shown to analysts. Used in
  cold-start stages 0–1, and per-UC "first 7 days go to engineers only".
- **SAIF (Synthetic Attack Injection Framework)** — replays **real** production
  traffic into a shadow stream (`shadow.weblogs.v1`) and mixes in generated,
  parameterized attacks (one generator per UC) with perfect ground truth.
  Nightly per Tier-1 UC, weekly fleet-wide. Results stored per model version and
  used as **regression gates for every release**.
  ```
  saif inject --uc UC-02 --profile slow --rate 1/45s --duration 72h \
              --ua-spoof browser --ip-rotation 4 --target shadow.weblogs.v1
  saif evaluate --run <id> --report pr-auc,ttd,fp-rate
  ```
  **SAIF data is NEVER used to train detection models** — evaluation only.
  Generator code is versioned.
- **Backtesting** — every model release is backtested against (a) the red-team
  library, (b) all confirmed historical incidents, (c) 30 days of recent
  production traffic for alert-volume regression.
  **Backtests run the REAL engine code via replay — never a notebook
  reimplementation.**
- **Replayability is load-bearing** — cold-start warmup, state rebuilds,
  backtests and SAIF all work by rewinding the stream.

### Evaluation metrics and targets

| Metric | Target | Note |
|---|---|---|
| **PR-AUC** | **≥ 0.85** (Tier-1) | **primary** — attacks are rare, ROC-AUC misleads |
| Recall @ FP-budget | ≥ 0.90 (fast variants) | |
| FP rate | **≤ 3/day/server** (analyst-confirmed) | |
| Precision (live, 28-day rolling) | ≥ 0.80 Tier-1 | from analyst verdicts |
| Time-to-detect | per use case | |
| Detection stability | **CV ≤ 0.2** | spread of recall/TTD across 20 replay runs |
| F1 / ROC-AUC | reported, **not gated** | for literature comparability |

Analyst loop: one-click verdict — **real / false / benign-true-positive /
needs-info**. Quarterly red-team exercises become a permanent gold set.

---

## 10. Deployment reference (the spec's enterprise target)

> See `ARCHITECTURE.md` for how this project makes all of it **optional** via
> progressive infrastructure.

**Kafka topics:** `raw.weblogs.v1` (in, by `observer.server`, 7 d) ·
`shadow.weblogs.v1` (SAIF, 3 d) · `ml.features.windows.v1` (by entity hash, 2 d) ·
`ml.scores.elevated.v1` (7 d) · `alerts.web.ml.v1` (out, by severity then server,
30 d) · `analytics.web.insights.v1` (out, 30 d).
**Exactly-once is NOT required** — deterministic content-hash IDs make
reprocessing idempotent and fusion takes the max, so duplicates are harmless.
Backpressure: **shed Tier-3 first, protect Tier-1**; analytics may lag freely.

**Elasticsearch ILM:** `soc-web-ml-alerts-{yyyy.MM}` (hot 30 d → warm 180 d →
delete 400 d) · `soc-web-analytics-{yyyy.MM}` (hot 30 d → warm 365 d) ·
`soc-web-baselines-*` (rolled up after 90 d) · `soc-web-clusters-*` /
`soc-web-chain-*` (365 d, double as hunting datasets) · `soc-ml-feedback-*`
(**never deleted**). Campaign/incident parents link to children by a plain
`campaign_id` term — no joins, so Kibana drill-down is a term filter.

**Reference stack:** Python + Faust (or Flink above ~50k events/s) ·
scikit-learn · **river** · PyTorch (AEs) · hmmlearn · ruptures (PELT) ·
datasketch · statsmodels (STL) · Redis state · MLflow registry · in-process model
serving (joblib/ONNX) hot-swapped on a registry webhook · Prometheus + Grafana +
OpenTelemetry.

**Sizing:** university / mid-enterprise 2–10k events/s → 8–16 vCPU, 8–16 GB Redis,
nightly < 1 h. Large enterprise 10–50k → 32–64 vCPU, 32–64 GB, nightly 2–4 h
(optional GPU for the UC-09 conv-AE). Very large 50k+ → Flink sharded per
namespace. UC-01 alone: 2 vCPU / 4 GB per 5k events/s shard, no GPU.

**Failure doctrine:** model load fails → auto-fallback to the previous champion
(3 hot) · state lost → replay (max 30-min horizon for Tier-1) · scoring down →
events still land raw, a catch-up scorer back-fills with original timestamps and
a late-alert flag · broken JSON → dead-letter with a rate alarm · every
degradation emits a health event.
**"Silent failure is the only unacceptable failure."**

---

## 11. Stated limitations (be honest about these)

- **Telemetry ceiling** — no bodies/headers/TLS, so payload attacks are only
  reachable behaviorally.
- **Approximate identity** — IP+UA fragments under CGNAT/proxies.
- **No latency field** in the schema.
- **Unsupervised precision plateaus** without analyst feedback.
- **Cold start is 2–8 weeks.**
- **Adversarial adaptation** raises attacker cost; it does not eliminate evasion.
- **CDN-fronted estates** must capture logs at origin/LB — resolving
  `X-Forwarded-For` is the normalizer's job, upstream of this framework.

---

## 12. Roadmap (spec's own phasing, ~34 weeks)

| Phase | Weeks | Content |
|---|---|---|
| 0 Foundations | 1–3 | stream/schema/state, feature platform, ES templates, MLflow |
| 1 Baselines & observe | 3–6 | AU-01/02, rarity tables, Tier-1 observe mode, Engine Health dashboard |
| 2 Tier-1 live | 6–10 | UC-01/02/04/06/07 alerting, fusion/severity/explainer, SAIF v1 |
| 3 Analytics expansion | 10–14 | AU-03/05/11 suppressor live, AU-04/06 |
| 4 Tier-2 detection | 14–20 | UC-03/05/08/09/10/12, feedback re-rankers arm |
| 5 Tier-3 & chain | 20–28 | UC-11/13/14/15, AU-07…12, hunting digest, first governance review (exit: chain order-AUC ≥ 0.85) |
| 6 Hardening | 28–34 | red-team #1, backtest library, state-loss drills, sizing review |
