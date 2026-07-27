# Decision Journal

Append-only log of decisions and their reasoning. **Newest first.**

Write an entry when a decision is non-obvious, closes an open question, reverses
an earlier choice, or would otherwise make a future reader ask *"why on earth is
it done this way?"*. Do not log routine implementation.

Format: date · decision · why · what it rules out · where it lives.

---

## 2026-07-27 — Phase 3.0: the multi-use-case runtime

### D-020 · One runtime, N use cases — each with its own feature builder, checkpoint keyed by the set

**Decision.** The runtime scores every configured use case per window in
dependency order (`UseCase.depends_on`, topologically sorted, deterministic).
Three specifics worth defending:

1. **Each use case gets its own `WindowFeatureBuilder`,** fed the same event
   stream, rather than one shared builder feeding all scorers.
2. **The shared ingest checkpoint is keyed by the sorted use-case set**
   (`bot_detection+web_recon_checkpoint.json`); everything else on disk —
   health, shadow, digest, drift, alerts — is keyed per slug.
3. **The backtest canary became a `UseCase.canary()` classmethod** (empty =
   check skipped); canary sources must come from TEST-NET-2 so canary windows
   are recognizable regardless of which use case injected them.

**Why.**
1. Features are profile-dependent (`path_idf`, `ua_rarity`, served
   extensions), and each bundle carries the profile it was *trained* with —
   scoring UC-A's windows through UC-B's profile silently changes the
   distribution the calibrators were fitted on, which is exactly the class of
   bug percentile calibration exists to prevent (FR-22). A shared builder is
   the FR-11 ideal, but FR-11's "compute once, share" presumes a shared
   profile, which arrives only when training becomes joint. Duplicate folding
   costs counters-per-event × N use cases — noise at our event rates — and
   because every builder sees the same stream, their windows close on the
   same event, which is what makes "exporter scores before consumer within
   the same bucket" (D-019's ordering requirement) hold structurally.
2. The checkpoint is a property of *one reader position*, which belongs to
   the runtime instance, not to any single use case. Keying it per-slug would
   desync N cursors over one stream; keying it by the set means a changed set
   restarts the read (safe — shadow rescoring is cheap) and the existing
   single-`web_recon` elkcc deployment keeps its checkpoint name and resumes
   seamlessly after upgrade.
3. The canary was hardcoded to web_recon's enumeration burst; run against
   `bot_detection` it would either fail every backtest (canary "missed") or
   need a slug-keyed map — the exact pattern 3.0 removes. A per-class hook
   keeps the backtest fully generic and gives each use case an obvious place
   to ship its own known-bad burst (FR-58 still holds: scoring stream only).

**Rules out.** A single shared feature builder until profiles are trained
jointly; per-use-case ingest checkpoints; slug-keyed canary/use-case maps
anywhere in `cli`/`evaluation`/`detection` (the plugin registry is the only
resolver); a canary sourced outside 198.51.100.0/24.

**Lives in.** `detection/runtime.py` (`_UseCaseRunner`, `RuntimeConfig.set_key`),
`usecases/__init__.py` (`dependency_order`), `core/plugins.py`
(`UseCase.depends_on`, `UseCase.canary`), `evaluation/backtest.py`,
`evaluation/canary.py` (`is_canary_ip`), `tests/test_multi_usecase_runtime.py`.

---

## 2026-07-27 — UC-04 (bot_detection) design

### D-019 · bot_detection workflow — a detector whose main product is a signal for other detectors

**Context.** The first production shadow run of `web_recon` on live traffic
confirmed D-008 empirically: ~20-25% of its fires were legitimate search-engine
crawlers (Googlebot `66.249.64.x`, Bingbot `157.55.39.60`). That noise is not a
`web_recon` bug to tune away — it is exactly what `bot_detection` (UC-04) exists
to remove. This entry designs UC-04 before implementation.

**Naming (docs/NAMING.md — CI-enforced).** slug `bot_detection` · spec ID
`UC-04` · title "Bot & Abnormal Crawler Detection" · module
`src/soc_ml/usecases/bot_detection.py` · class `BotDetection` · config key
`bot_detection` (already present). Its exported per-entity signal is namespaced
`crawler.*` (see below), features `bot.*` / reused `timing.*` / `ua.*`.

**The key insight that shapes everything.** UC-04 is unusual: its *primary*
value is not its own alert stream, it is the **per-entity human-likeness /
known-crawler signal it exports for `web_recon`, `content_scraping`, and
`app_abuse` to consume** (SPEC_DIGEST §5, UC-04). So the design has two outputs,
and the export is the more important one.

**Detection logic (self-supervised — labels come free).**
1. **Label from the UA string, predict from behavior.** A `declared_bot` label
   is derived cheaply from the user-agent (contains `bot`, `crawler`, `spider`,
   `Googlebot`, `bingbot`, ...). A gradient-boosted classifier then predicts
   `declared_bot` **from behavioral features only** (never the UA). Two payoffs:
   (a) an entity whose UA says "browser" but whose *behavior* scores as a bot is
   a **spoofer** (the UC-04 alert); (b) the calibrated P(bot | behavior) is the
   **human-likeness signal** other use cases consume.
2. **Human-likeness GMM + HDBSCAN crawler clustering.** A GMM over daily
   behavior vectors yields a smooth human-likeness probability; HDBSCAN groups
   entities that cluster with known declared bots into a **known-crawler
   cluster**, catching undeclared automation by association.
3. **Verified-crawler check (the spec's "free precision" Sigma layer).**
   Search engines are confirmed by reverse-DNS / published ranges (Googlebot,
   Bingbot). Verified + polite crawlers are marked `crawler.is_verified` so
   downstream suppression is *certain*, not probabilistic. This is an
   allowlist of **identity**, not a detection threshold — FR-62 is untouched.

**Features** (reuse first, add only what's new): reused `timing.interarrival_cv`,
`ua.rarity`, `ua.len`, `web.referrer_absent_ratio`, `web.status_*`; new
`bot.asset_fetch_ratio` (browsers fetch css/js/images; scripts don't),
`bot.activity_hour_entropy` (24-bin), `timing.fano_factor`,
`bot.referrer_chain_depth`, `bot.path_repeat_ratio`, `bot.method_get_ratio`,
`bot.bytes_per_req_p50`, `bot.declared_bot`, `bot.robots_txt_fetched`.

**Gate (own alert).** A **browser-declared** entity with
`P(bot | behavior) ≥ p99.5` sustained ≥30 min → UA-spoofing alert. Declared bots
never alert here (they are the training signal, not the target); they flow to the
export instead.

**The export mechanism (new cross-use-case infrastructure).** UC-04 writes a
per-entity annotation to a shared store the scorer can read:
`crawler.human_likeness` (0-1), `crawler.is_known` (clustered with bots),
`crawler.is_verified` (reverse-DNS confirmed). `web_recon`'s gate reads it: a
**verified, polite** crawler is suppressed (and the suppression is **recorded
visibly** in the shadow/alert doc — never silent, NFR-09); a borderline entity is
only down-weighted. This is the first real instance of the spec's cross-use-case
feature sharing, and it needs the runtime to score **multiple use cases per
window in dependency order** (UC-04 before UC-02) — see the roadmap phase.

**Why not just an allowlist and skip the ML.** The verified-crawler check alone
would remove Googlebot/Bingbot, but not the long tail of undeclared scrapers,
monitoring bots, and cloud automation that also inflate `web_recon`. The ML
human-likeness signal covers that tail and generalizes to `content_scraping` /
`app_abuse`. So: ship the allowlist as the certain-suppression fast path *inside*
UC-04, and the ML signal as the general one.

**Rules out.** Building crawler handling inside `web_recon` (wrong layer,
duplicates UC-04); a config-driven "ignore these IPs" threshold (identity
allowlist is fine, data thresholds are not); silent suppression.

**Lives in.** `usecases/bot_detection.py`, a new `features/bot_features.py`, new
model wrappers (`models/gbm.py`, `models/gmm.py`, `models/hdbscan_cluster.py`),
a shared entity-annotation store, and the multi-use-case runtime. Phased in
`ROADMAP.md` Phase 3.

---

## 2026-07-27 — Phase 2: web_recon made production-deployable

### D-018 · Split train/score into a shared core; build the live runtime around it

**Decision.** Refactored so that training (`training/trainer.py`) and scoring
(`detection/scorer.py`) are standalone modules, and **both** `soc-ml backtest`
and the new live runtime (`detection/runtime.py`) call them. Added a versioned
on-disk registry (`registry/store.py`), PSI drift detection (`drift/psi.py`),
per-entity dedup (`detection/dedup.py`), daily-budget governance
(`detection/budget.py`), and the CLI verbs `train` / `run` / `promote` /
`status`.

**Why.** A vertical slice proved the detection *brain*; production needs the
*body*: a service that tails parser output continuously, survives restarts,
versions and rolls back models, notices when it goes stale, and never floods the
queue. The single most important structural choice was making backtest and live
share the exact scoring code (FR-72) — otherwise "validated by backtest" would
not mean "works in production", and every future use case would carry that risk.

**Production properties delivered (single use case, standalone profile, zero infra):**
- **Restart-safe.** Source byte-offset checkpoint persisted atomically and
  reloaded; verified a resumed run reprocesses 0 events.
- **Versioned + rollback.** Immutable version dirs, atomic `current` pointer,
  3 hot versions, candidate→promote (human gate for Tier-1, FR-55), instant
  rollback.
- **Never goes stale.** Hourly PSI vs the bundle's training reference; ≥2
  features over 0.25 → logged retrain recommendation. Drift *recommends*, never
  auto-swaps.
- **Never floods.** Per-entity dedup (cooldown fold) + per-server daily budget
  (default 50) → overflow to a visible digest, never dropped (FR-34).
- **Three modes.** observe/shadow/live, per the cold-start staging; shadow
  records every score and delivers nothing (verified).
- **Cold start.** `--allow-cold-start` buffers live traffic, trains, promotes,
  and begins scoring — turnkey for a greenfield environment (verified end to end
  in tests: no model → learns → catches the scanner).
- **No silent failure.** Health JSON on a timer + shutdown; missing model is a
  loud refusal; DLQ for unparseable input.

**Real-data validation.** Full cycle on 400k live nginx events: `train`
(12,643 windows, 12 anomalous dropped) → `promote` → `run --mode live` streamed
at ~3,800 events/s, flat memory, **caught the real attacker 203.0.113.199**
plus other scanners, dedup folding repeats.

**Honest limitation, recorded not hidden.** On that slice the single detector
delivered 26 alerts over ~5h (~125/day) — above the ≤3/day/server target,
because p99.7 gating fires on ~0.3% of windows by construction and the
false-positive *suppression* layer (UC-04 crawler filtering, UC-12 campaign
folding, corroboration) is Phase 3. The daily budget bounds the flood *today*
(delivery is capped, overflow digested); precision rises as those use cases land.
This is exactly the spec's predicted trajectory and why UC-04 is "build second".

**113 tests passing.** New suites: `test_registry.py`,
`test_detection_lifecycle.py` (dedup, budget, drift, runtime cold-start /
checkpoint-resume / shadow).

**Lives in.** `training/`, `detection/`, `registry/`, `drift/`, `cli/main.py`,
`DEPLOYMENT.md`, `deploy/foss-soc-ml.service`.

---

## 2026-07-27 — Phase 1: the web_recon vertical slice

### D-016 · Human-readable naming: slug + spec ID + title, everywhere, CI-enforced

**Decision.** Every use case carries a triple identity (docs/NAMING.md):
canonical **slug** (`web_recon` — module name, `Plugin.name`, config key, CLI
arg, alert `usecase` field, artifact paths), **spec ID** (`UC-02` — emitted as
`rule.id`, cross-reference to SPEC_DIGEST), and **title** ("Web Reconnaissance
& Directory Enumeration" — emitted as `rule.name`). The full 15+12 catalog is
pre-named in NAMING.md; slugs are immutable after first release. Enforced by
`tests/test_naming.py` (slug shape, module==slug, catalog membership, feature
name namespacing).

**Why.** User requirement, and correct: "UC-02" means nothing to an analyst
triaging at 3 a.m. or to a new contributor grepping the codebase. But dropping
the spec IDs entirely would sever traceability to the 54K-token specification.
Industry alert schemas (ECS `rule.id`/`rule.name`, Sigma `id`/`title`) use
exactly this dual form. Naming the whole catalog up front prevents the
alternative failure: fifteen developers inventing fifteen naming styles.

**Rules out.** Code paths keyed on `UC-nn`; improvised slugs (catalog or it
fails CI); renaming a slug post-release.

**Lives in.** `docs/NAMING.md`, `tests/test_naming.py`, `UseCase` base class,
`config/default.yaml`, alert schema.

---

### D-017 · Phase-1 slice: tumbling windows, conservative floor, canary, and scope honesty

**Decision.** The web_recon slice makes five deliberate engineering calls:

1. **Tumbling 5-minute windows** (not the spec's sliding windows) for offline
   training/backtest. Sliding matters for live *latency* — an attack should not
   wait for a bucket boundary; offline, the vector distribution is equivalent
   and tumbling costs a fraction. The live sliding path arrives with the live
   loop; feature definitions are identical, so models transfer.
2. **Evidence floor ≥5 events / ≥3 distinct paths.** The spec leaves UC-02's
   floor implicit (unlike UC-06/09/15); per the ambiguity rule we take the
   conservative reading. Floors live in the use case class — they are spec
   constants, not config (FR-62 untouched).
3. **A deterministic canary** (150-event enumeration burst, TEST-NET-2 IP,
   arithmetic jitter) injected into the **scoring stream only** — every
   backtest self-checks "can this pipeline see a textbook scan?" without ever
   contaminating training (FR-58). The CLI fails the run if the canary is
   missed.
4. **Population-deviation attributions** (value vs server p50/p99) rather than
   TreeSHAP for now — model-agnostic, analyst-readable, no heavy dependency;
   per-model attribution slots in later without an alert-schema change.
   `asset_weight` ships neutral (1.0) until its producers (UC-15 roles,
   response profiles) exist — the severity formula is wired to final shape.
5. **Registry-lite artifacts**: `data/models/web_recon/<version>/` with models,
   calibration grid, feature stats, and metadata carrying the **sha256 of the
   feature code** — reproducibility anchor until the real registry (Phase 2).

**First real-data result (validates the thesis).** On 300k events of live
production nginx traffic (5.03h, 2m10s runtime, flat memory): the slice **detected a
genuine directory-enumeration attacker** — 203.0.113.199 scanning the
mailserver at ~150 req/5min across ~95 never-served paths (IDF 1.0 vs server
median 0.59), ~100 404s, no referrers — plus the canary, with **zero literal
thresholds anywhere**. Raw alert count was 9 in a 2-hour scoring window, 6 of
them successive windows of that one attacker: exactly the alert-storm shape the
spec's campaign folding / progressive alerting (Phase 3 fusion) exists to
collapse, and the honest current reading of "alerts/day/server" — entity-level
dedup will bring the number inside budget, and the metric itself needs a
small-window caveat until scoring spans are longer.

**Known future optimization.** Ingestion uses stdlib `json` (~2,300 events/s
end-to-end through 4 passes); `orjson` is already a dependency and would cut
wall-clock ~2-3× on the full 14 GB file. Deliberately not done mid-slice.

**Lives in.** `features/window_features.py`, `usecases/web_recon.py`,
`evaluation/{backtest,canary}.py`, `fusion/`, `explain/context.py`,
`tests/test_backtest_e2e.py`.

---

## 2026-07-27 — Real data added

### D-015 · Multi-GB real-traffic dumps: streaming-only, guarded in code and docs

**Decision.** Two full production dumps now live in `log_samples/`:
`moodle_last60daysrealdata.json` (~26 GB) and `nginxrealdata.json` (~14 GB).
They are **streaming-only input**, never opened whole. Guards added at three
levels: (1) a large-data warning in `docs/DEVELOPING.md` and the deployment
docs; (2) a dedicated `log_samples/README.md`; (3) `.gitignore` excluding
`*realdata*` / `*.ndjson`
while re-including the `*_sample.json` fixtures.

**Why.** A Read/`cat`/`json.load` on a 26 GB file hangs the editor and can take
the machine down — a real hazard for any human or AI session that treats
`log_samples/` as "just samples". The rule has to be loud, repeated at every
entry point, and enforced in code, because a single careless open is
unrecoverable mid-session.

**Two real code bugs fixed alongside the docs** (docs alone would not have
prevented a crash):
- `cmd_sessions` did `list(src.read())` — a full materialization that would OOM
  on 26 GB. Now streams a bounded prefix (`--limit`, default 1,000,000) and
  labels the output as a sample.
- `cmd_validate` accumulated a `stamps` Counter keyed by timestamp; the real
  nginx data has microsecond precision, so that Counter would grow to ~one key
  per event and OOM. Distinct-tracking structures (`stamps`, `entities`,
  `servers`) are now capped at `_TRACK_CAP` (2,000,000); exact counts
  (parsed/failed/coverage) are unaffected.

**Validation.** `soc-ml sessions --input nginxrealdata.json --limit 50000` runs
in seconds at flat memory; the real data shows healthy human variance
(inter-arrival CV median 3.40, sessions up to 506 requests) — good backtest and
training material.

**Consequence for design.** This is the vindication of P2/P3 (streaming,
progressive infra): the framework must process 40 GB on a laptop by streaming,
holding only models + per-entity state, never the event set. Any component that
cannot is wrong. Backtest/train commands must take a **named file**, never glob
the directory (which would pull in 40 GB plus the fixtures at once).

**Lives in.** `cli/main.py` (`_TRACK_CAP`, bounded `cmd_sessions`/`cmd_validate`),
`log_samples/README.md`, `.gitignore`, `docs/DEVELOPING.md`.

---

## 2026-07-21 — Phase 0 corrections

### D-014 · The parser was right; the fixture was stale. Correct both the data and the check

**Decision.** Regenerated `log_samples/nginx_sample.json` by replaying its raw
lines through the **current** engine. Kept a 300-line excerpt of the old output
as `tests/fixtures/nginx_stale_ingest_time.json`. Rewrote the FR-08 check to
trust `event.timestamp_source` first and use a *sub-second* collision heuristic
only as a fallback. **Closes OQ-05 — there is no parser bug.**

**Why.** D-012 concluded the nginx rule lacked a `timestamp:` block. That was
wrong, and the error was one of inference: I diagnosed a live component from a
stale artifact without reading the component. `rules/nginx.yaml` declares
`timestamp: {group: timestamp, format: clf}` at the top level and per-pattern
`nginx_error` overrides for the error formats. Replaying the same raw lines
through the current engine yields `@timestamp: 2026-07-06T11:40:34+00:00` with
`event.timestamp_source: log` — correct event time, correctly converted from
`+0530`. The sample file was simply output from a superseded engine version.

**The original heuristic was also wrong**, and would have been a permanent
false-positive source in the tool built to reduce false positives. It flagged a
low distinct/total timestamp ratio. But CLF has **one-second resolution**, so a
server taking 200 requests/second legitimately produces 200 events per instant —
healthy traffic that the check would have condemned forever. The corrected
version keys on *microsecond-precision* collisions, which real event times do not
produce, and defers entirely to the parser's own attestation when it exists.

**Evidence the correction matters.** On the regenerated data, median
inter-arrival CV is **3.41**; on the stale data it was **0.00**. Near-zero CV is
the "machine-regular" signature UC-01/UC-04 treat as strong bot evidence, so the
stale fixture would have made ~every entity look like a bot. The finding was real
and the consequence was real — only the cause was misattributed.

**Rules out.** Diagnosing upstream components from downstream artifacts without
reading the component. Ratio-based timestamp heuristics.

**Kept.** FR-08 and the `--strict` gate, now correct. The stale file is a
regression fixture rather than a deleted embarrassment: it is genuine
old-engine output and exactly the shape the check must catch, and the framework
must defend against it because the contract is meant to support foreign shippers
(Filebeat, Vector) with no attestation field at all.

**Lives in.** `cli/main.py::_check_timestamp_quality`, `tests/test_validate.py`,
`tests/fixtures/nginx_stale_ingest_time.json`, FR-08.

---

## 2026-07-21 — Phase 0 build

### D-013 · Cap per-session sequences, and record when it happens

**Decision.** `Sessionizer` caps `paths` / `status_codes` / `methods` /
`inter_arrivals` at 10,000 entries per session and sets `Session.truncated`.
`event_count`, `bytes_total`, and timing stay exact.

**Why.** The sessions this framework most wants to catch are precisely the ones
that blow up memory: a content-harvesting run (UC-06) or an enumeration sweep
(UC-02) can issue hundreds of thousands of requests inside one session. An
uncapped per-session list is an out-of-memory bug that triggers on the attack
rather than on normal traffic. Truncation is recorded rather than silent because
a quietly shortened sequence would corrupt any sequence-based feature (UC-10's
HMM decoding especially) with no indication.

**Lives in.** `preprocess/sessionize.py`, `contracts.Session.truncated`.

---

### D-012 · Validate timestamp quality at ingest, and let CI fail on it

**Decision.** `soc-ml validate` detects `@timestamp` carrying *ingest* time
instead of *event* time, and `--strict` turns that into a non-zero exit code.
New requirement **FR-08**.

**Why.** Found by running the new sessionizer over the real nginx sample: 2000
events but only **40 distinct `@timestamp` values, with 1000 events sharing a
single instant**. `event.original_time` holds the true time
(`06/Jul/2026:17:10:34 +0530`), so the nginx parser rule has no working
`timestamp:` block and is stamping at parse time. The Moodle sample, by
contrast, is correct — 1500 events, 1500 distinct timestamps.

This defect is invisible to every check we already had: `@timestamp` is present,
well-formed, and 100% populated. It is simply the wrong clock.

It is also **worse than data loss**. A flushed batch sharing one instant yields
an inter-arrival CV of ~0, and near-zero CV is exactly the "machine-regular"
signature that UC-01 and UC-04 treat as strong bot evidence. Corrupt timestamps
therefore *manufacture confident false positives* rather than merely weakening
detection — the opposite of this project's stated goal. Everything in the timing
family is affected: `interarrival_cv`, `fano_factor`, `activity_hour_entropy`,
UC-08's Lomb-Scargle periodicity, activity calendars, and AU-01/02 time-of-week
normalization.

**Rules out.** Trusting the upstream parser's `@timestamp` implicitly. The
framework validates its input rather than assuming a correct producer, which
also matters for the non-`foss-soc-engine` shippers the contract is meant to
support.

**Note.** The *fix* is upstream (a `timestamp:` block on the nginx rule, per the
parser's WRITING_RULES.md §5) and is deliberately not made here — D-001 keeps
the coupling one-directional. Tracked as **OQ-05**.

**Lives in.** `cli/main.py::_check_timestamp_quality`, `tests/test_validate.py`,
FR-08.

---

## 2026-07-21 — Project inception

### D-001 · Build the ML framework as a separate project alongside the parser

**Decision.** `foss-soc-ml/` is a sibling of `foss-soc-engine/`, coupled only by
the ECS event contract, one-directionally (parser → framework).

**Why.** The parser is mature and already open-sourced on its own terms. Coupling
the two would force joint releases and make the ML framework useless to anyone
using Filebeat/Vector/Logstash instead. The contract (SPEC_DIGEST §3) is stable
enough to be a real interface.

**Rules out.** Adding ML stages inside the parser; importing parser code.

**Lives in.** `ARCHITECTURE.md` §12, NFR-14.

---

### D-002 · Python 3.11+

**Decision.** Python, despite the free choice of language.

**Why.** Three reasons in order of weight: (1) the spec's algorithm list —
`river`, `hmmlearn`, `ruptures`, `datasketch`, `statsmodels`, scikit-learn,
PyTorch — exists as a coherent set in Python and effectively nowhere else;
(2) the parser is Python, so one language spans the SOC stack and operators
already have the toolchain; (3) plugin authors in a SOC write Python.

**Rules out.** Go/Rust cores. Throughput is addressed with `orjson`, vectorized
NumPy, optional `confluent-kafka`, and Flink at the top profile — not a rewrite.

**Lives in.** `ARCHITECTURE.md` §11.

---

### D-003 · Progressive infrastructure — three profiles

**Decision.** `standalone` (no infra) / `cluster` (Kafka+Redis) / `enterprise`
(full stack), selected by one config key, behind identical interfaces.

**Why.** The spec targets an enterprise estate, but the project is open source
and its natural audience — smaller teams, public institutions — cannot stand up
Kafka + Redis + MLflow + ES to try a detection framework. Making zero-infra the
*default* rather than a demo mode is what makes the project adoptable. It also
makes CI and backtesting trivial.

**Rules out.** Kafka as a hard dependency; any design that assumes a broker.

**Lives in.** `ARCHITECTURE.md` §3, NFR-07.

---

### D-004 · File-tail ingestion as the default source

**Decision.** Default `Source` tails the parser's ECS output directory. Kafka and
Elasticsearch are adapters behind the same interface.

**Why.** User decision, and it aligns with D-003: it works offline, needs no
infrastructure, and makes replay (which cold-start, backtest, and SAIF all depend
on) a matter of re-reading files.

**Lives in.** FR-02, `ingest/`.

---

### D-005 · Plugins in Python, policy in YAML

**Decision.** Six plugin interfaces (`Source`, `FeatureGroup`, `UseCase`,
`Model`, `StateStore`, `Sink`), discovered by directory drop-in and entry points.
Use cases declare features/model/gate declaratively but are Python.

**Why.** The parser uses declarative YAML rules because parsing is pattern
matching. Detection here is statistical — Lomb-Scargle, BOCPD, permutation
entropy, HMM state decoding. Forcing that into YAML would produce a worse DSL
than Python already is. Splitting *policy* (YAML: budgets, modes, cadences) from
*algorithms* (Python) keeps the easy things easy without capping the hard things.

**Rules out.** A rules-engine DSL for detection logic.

**Lives in.** `ARCHITECTURE.md` §5, NFR-12.

---

### D-006 · No detector may read a literal threshold from config

**Decision.** Config carries policy only — modes, budgets, cadences, toggles.
Any number compared against data comes from the learned Environment Profile.
Enforced by a CI lint, built **before** the first use case.

**Why.** This is the single mechanism that makes alerts environment-specific
rather than generic (G1). Stated as a principle it erodes within weeks; stated as
a lint it holds. The spec's own severity formula already learns `asset_weight`
rather than requiring a crown-jewels list — this generalizes that stance.

**Rules out.** `config: max_404_per_min: 50` and everything shaped like it.

**Lives in.** FR-62, `ARCHITECTURE.md` §7.

---

### D-007 · Three run modes, selectable per use case

**Decision.** `offline` / `shadow` / `live`, orthogonal to profile, overridable
per use case.

**Why.** The user requires offline-first validation before real-time deployment.
The spec independently requires an "observe mode" for cold-start and a ≥72 h
shadow soak for champion-challenger. These are the same mechanism, so it is
modelled once. Per-use-case granularity is what makes staged cold-start
expressible (Tier-1 live while Tier-2 still observes).

**Lives in.** `ARCHITECTURE.md` §4, FR-70.

---

### D-008 · Build UC-04 second, not third

**Decision.** Deviate from the spec's use-case ranking: build UC-04 (bot/crawler
detection) immediately after UC-02.

**Why.** UC-04 produces the known-crawler cluster and human-likeness features
that suppress false positives in UC-02, UC-06, and UC-15. Building it late means
tuning those use cases against noise UC-04 would have removed, then re-tuning.

**Lives in.** `ROADMAP.md` Phase 3.

---

### D-009 · First vertical slice before a complete platform

**Decision.** Phase 1 drives UC-02 end-to-end (file → features → model → fusion →
explanation → metrics) on a thin version of every layer, rather than completing
the feature platform first.

**Why.** A feature platform with no consumer is unverifiable, and the spec is
detailed enough to over-build against. One working path validates the contract,
the plugin interfaces, the calibration approach, and the metric harness at once.

**Lives in.** `ROADMAP.md` Phase 1.

---

### D-010 · Ship UC-09's cheap tier first

**Decision.** Character 4-gram LM before the convolutional autoencoder.

**Why.** The spec itself notes the n-gram tier gives ~80% of the value at 5% of
the cost. It also keeps PyTorch an optional extra rather than a practical
requirement, protecting the zero-infra default (NFR-07/08).

**Lives in.** `ROADMAP.md` Phase 5.

---

### D-011 · Distil the .docx into `SPEC_DIGEST.md`

**Decision.** The 54K-token Word document is distilled once into a digest that is
authoritative for daily work; the .docx remains authoritative on conflict.

**Why.** The Word document is very large and slow to read in full. Distilling it
once means contributors work from a concise, complete reference instead of
re-reading tens of thousands of words. The digest keeps every load-bearing number.

**Lives in.** `docs/SPEC_DIGEST.md`, `docs/DEVELOPING.md`.

---

## Open questions carried forward

See `REQUIREMENTS.md` §10. Currently **OQ-01** (confirm "minimise application
traffic volume" means reducing SOC alert volume, not throttling HTTP traffic) is
the only one that could change framing rather than detail.
