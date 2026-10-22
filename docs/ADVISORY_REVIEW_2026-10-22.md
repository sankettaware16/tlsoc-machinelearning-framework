# Advisory review — foss-soc-ml at `cbf1e34` (2026-10-22)

*An outside read of the whole repository — every document, the journal D-001..D-033, all 82 source
files, the scripts and the tests — by someone who has spent the last weeks measuring the same
mechanisms (percentile calibration, drift triggers, challenger exams, contamination, seed variance)
on the same IITB nginx feed in a sister research project. Where that work bears on a decision here
I cite the measurement, not the project. Nothing below is a verdict on the team's choices; it is the
list a senior engineer would leave on the table after a visit.*

Basis: `tests/` — **213 passed, 20 skipped** (the real-data tests, absent on this machine);
`ruff check src tests scripts` — **74 findings, 44 auto-fixable**; working tree clean at `cbf1e34`.

---

## 1. Where the project stands

- **Stage:** Phase 3.6, two Tier-1 detectors (`web_recon`, `bot_detection`) live on one university
  edge since 6 August (revived 8 October), 8 days unattended with 0 restarts, a reboot survived, a
  genuine headless-browser botnet and several UA-rotating scanners caught, the first fusion stage
  (progressive alerting, D-033) landed today after a measured week. `bot_detection`'s retrain is
  blocked by a label-design problem the team diagnosed correctly (D-032).
- **What is strong, and should be protected:** the journal (every decision with *why*, *what it
  rules out*, *where it lives*, and measured numbers); the FR-62 lint (policy in config, thresholds
  learned); NFR-09 (every suppression, fold, digest and skip leaves a record — and the places where
  it did not were found on production and fixed, D-023/D-024); FR-72 (one scoring path for backtest,
  candidate check and live — `Scorer.score_many`); the operational hardening D-025..D-030 (error
  channel, BLAS pins, batch scoring, inode rotation, delivery state in the checkpoint, stop on an
  idle feed) is real production maturity, not scaffolding; the README's "honest about limitations".
- **What is thin, and where the next risk sits:** the *evidence layer*. Promotion is a button with
  no recorded evidence behind it; measurements are judged after the numbers exist; serving-vs-candidate
  comparisons rest on one random seed; detection quality is measured only by "can it still see what
  it saw". None of these bit yet — D-032's incident gate caught the blind retrain because someone
  ran the script. The suggestions below are mostly about making that luck structural.

---

## 2. Findings, ranked

### P1 · Promotion is not gated on evidence (FR-55 is documented, not implemented)

**What.** `soc-ml promote` (`cli/main.py` `cmd_promote`) and the dashboard's `/api/models/promote`
(`web/server.py`, `web/state.py:promote`) call `ModelRegistry.promote` directly.
`scripts/check_candidate.py` is deliberately read-only and writes nothing; its verdict lives in a
terminal. Bundle metadata carries the feature-code hash but not the code commit.

**Why it matters.** D-032 is the proof: a candidate that passed its canary and lowered the fire rate
was blind to the live botnet. The incident replay refused it — but nothing *required* that replay
before the button. On this same feed, a sister project's stability exam refused every one of 189
retrained candidates across four experiments; most of them looked fine on volume alone. A promote
path that does not demand a recorded verdict is the single largest open risk in the framework.

**Do.**
1. `check_candidate` writes `data/models/<slug>/<version>/approval_check.json`: verdict
   (`PASS` / `WARN` / `DO_NOT_APPROVE`), fire rates, canary result, per-incident addresses caught by
   serving and candidate, the inputs by sha256, the code commit, the timestamp.
2. `ModelRegistry.promote` refuses a version without a `PASS`/`WARN` report, unless
   `--force --reason "<text>"`, and the reason is written into the bundle's metadata. The dashboard
   shows the verdict beside the button and greys it out otherwise.
3. `promote` records `rollback_target` (the version it displaced) in the new bundle's metadata;
   `rollback` uses that instead of "the newest other version" (`registry/store.py:rollback`), which
   can land on the wrong bundle once a candidate has been pruned or promoted in between.
4. Add `code_commit` (`git rev-parse HEAD` + a dirty flag) to `train_bundle`'s metadata next to
   `feature_code_sha256` — a bundle is reproducible only if both are known (REQUIREMENTS FR-53 asks
   for exactly this).

### P1 · Write the decision rule for the 7-day re-measure *before* it starts

**What.** ROADMAP 3.6's open gate: "re-measure on elkcc for 7 days with progressive alerting
deployed, then decide". The journal's measurements are excellent after the fact; none has a rule
written down before the run.

**Why it matters.** A rule chosen after the numbers exist is a result, not a rule — and it is the
easiest way to fool yourself in good faith. Two lessons from the sister project, both paid for: a
two-sided band once *refuted* a hypothesis because the adaptive arm did better than the band allowed
(the band should have been one-sided); and a sealed metric once named a quantity ("both detectors at
gate") different from the observation it was testing (the fused first-window catch). Check every
sealed metric against the observation it cites before sealing.

**Do.** Before the window opens, commit `docs/measurements/M-001-progressive-7d.md` (ten lines of
YAML is enough): the question; H1 *queued alerts ≤ 3 per day per server on at least 5 of the 7 days*
(one-sided — fewer is not a failure); H2 *every captured incident address that persists ≥ 30 min is
queued*; H3 *every captured burst scanner appears as a candidate in the digest with its stage*; H4
*0 restarts not caused by the operator*; the exact files read (`web_recon_scores.ndjson`,
`alerts/*.ndjson`, `*_digest.ndjson`, `*_health.json`); the script that computes the numbers,
committed first; the start and end timestamps; what "not testable" means. Judge by the letter; record
the verdict and the numbers in the journal as D-034 even if the answer is awkward.

### P1 · The frozen calibration drifts — D-033's diagnosis is half right

**What.** D-033 reads the week's volume as "a percentile gate fires on a fixed share of windows, so
volume followed traffic". The calibration grid (`fusion/calibration.py`) is fitted once at training
and frozen in the bundle, so the share is *not* fixed: D-032 measured the serving model's background
fire rate at **1.63 % against a 0.3 % design (5.4×)**. Two separate things happened — traffic rose
6×, *and* the gate's share drifted — and they have different remedies.

**Measured on the same feed** (sister project, pre-registered): a frozen reference's fire share
leaves the [0.5×, 2×] design band within 5–20 hours (a night-trained gate over-fires the morning ramp
2–6×; weekday and weekend differ by an order of magnitude at the server scope). A rolling reference
that admits only windows below *its own* quarantine percentile ratchets (4× → 17× in five hours,
8× → 70× in a day) because each refit truncates its own tail; an uncensored rolling reference sits
near 2×; an hour-of-day-aware reference repairs the snapshot but not cold mornings. On labelled public
attack days a rolling calibration halved false alarms (0.37–0.59× of the frozen arm's) while catching
the same attack windows. **But** a restored 0.3 % share of 3,500 windows per bucket is still ~10
fires every five minutes: calibration buys *comparability* (across hours, servers, versions — which
severity and the drift monitor depend on), persistence buys the *queue*. The team's choice of
progressive alerting as the lever was right; the calibration drift is a second, quieter problem.

**Do, cheapest first.**
1. Put the fire share per local hour, and its ratio to the design share, in `*_health.json` and the
   dashboard. It is the one number that tells you whether the gate still means "the top 0.3 %".
2. An optional hour-stratified calibration: fit 24 grids (or four day-parts) at training; score with
   the window's local-hour grid; fall back to the global grid when an hour has fewer than N rows.
   This is a *scoring* change — behind a flag, measured in a backtest first (the hour you train on
   decides which hours are cold).
3. If a rolling reference is ever added: admission is decided by a reference that is *not* the one
   being fitted (the frozen training grid is fine), fired windows are never admitted, and the
   reference warms up before it judges.

### P1 · `bot_detection`'s blocked retrain (D-032): split the export from the alert, and give the alert memory

**What.** The team's diagnosis stands: `bot.declared_bot` cannot teach "headless browser", and the
botnet's only tells were temporal (hour entropy 0.17 vs 0.06, machine-regular timing).

**Do.**
- **(a) Keep the GBM as the human-likeness export.** Its job is suppressing crawler-shaped false
  positives in `web_recon`, and it does that. Do not retrain it on a schedule (D-032 decision 1 —
  agreed).
- **(b) Give the spoofing *alert* its own unsupervised component** over the rhythm features that
  separate the botnet: `timing.fano_factor`, `timing.interarrival_cv`, `bot.activity_hour_entropy`,
  a per-address request-rate CV across windows, asset-to-page ratio — an Isolation Forest (or river's
  Half-Space Trees for the continuous rung) calibrated on browser-declared windows (the same
  `calibration_rows` hook). Gate = max(GBM percentile, rhythm percentile), sustained 30 min as now.
  The captured botnet under `data/incidents/bot_detection/` is this component's known-bad set.
- **(c) Fix the memory.** `EntityMemory.hour_counts` (`features/bot_features.py`) is per *entity*
  (server, ip, ua_hash), never persisted, and "under-reads for a while" after a restart. Under a
  watchdog that restarts the service, that bias is a recurring detection event: P(bot) shifts after
  every restart → the exported human-likeness shifts → `web_recon`'s suppression decisions shift,
  silently. Three changes: key the activity histogram by *address* (the botnet shared one UA across
  30 addresses; the scanners shared one address across 34 UAs — the address is the stable actor);
  persist it in the checkpoint, bounded (24 small ints per address, 50k most-recent addresses ≈ 5 MB);
  add `memory_hours_observed` to the window evidence so a cold memory is visibly "unknown" rather than
  read as "human-like". (Lesson from the sister project: "warm" must mean distinct earlier days
  observed, not a count of buckets today.)

### P2 · Build a small synthetic-attack harness now, not in Phase 3b

**What.** Detection quality is measured by one deterministic canary and the captured incidents. Both
answer "can it still see what it saw" — neither gives recall at a stated false-alarm rate, nor
first-window latency, nor *how far a miss missed*.

**Do.** A `saif/` module in three parts, all through the real engine (FR-72): a generator per use
case (scanner: rate, duration, UA-rotation count, a path pool drawn from the server's never-served
space, 404 share; spoofer: cadence, asset ratio), placing K instances at chosen points of a replay
day from TEST-NET-2 addresses (never trainable, as the canary already guarantees); a runner that
replays and joins the planted windows to the score log; a report with catches, first-window catches,
latency, *and the day's benign fire share beside them* — never a detection number without its
false-alarm number. When a planted instance is missed, read where its windows ranked among the day's
(top 3 %? top 0.1 %?) before changing anything — the rank is what the next design needs. Register every
run (id, inputs by hash, seeds, config, verdict) as one YAML under `measurements/`.

### P2 · Never compare serving against a candidate on one seed

**What.** `RANDOM_STATE = 7` throughout (`models/isolation_forest.py`, `gbm.py`, `gmm.py`) gives
determinism — good — and one realisation of each model. Measured on this feed: eight seeds of one
training range caught 1 to 14 of 16 planted scanners in their first window; entity-scope fire counts
spread about 5× across seeds. A candidate that "fires less" or "catches more" than serving may differ
by seed alone.

**Do.** `check_candidate --seeds 7,101,211`: refit the candidate's bundle under each seed (minutes
for IForest/LOF), report min / median / max of the fire rate and of the incident catches, and judge
on the *worst* seed. Record `seeds` in the bundle metadata.

### P2 · The PSI drift monitor measures the first five minutes of every hour

**What.** `DetectionRuntime._collect_drift` appends a value only while `len(bucket) < 4000`;
`_check_drift` halves the reservoir after each hourly check. So every hour's PSI compares the training
reference against the *first ~2,000 windows after the previous check* — on a feed with ~3,500 windows
per five-minute bucket, that is the first bucket of the hour, labelled as the hour.

**Do.** Reservoir-sample over the hour (Vitter's algorithm R, or one stratified take per bucket).
Then, before the trigger drives anything: derive the "significant" level from ≥ 48 quiet hourly
batches of *this* deployment rather than the textbook 0.25, and record the quiet-day alarm rate. On
this feed, drift levels derived from too few quiet batches declared "out of control" every 1.6 quiet
hours, and a drift-triggered retrain schedule asked for 2.6× a daily cadence's retrains at no gain.
Keep drift as a *recommendation recorder* beside a weekly cadence (the spec's own posture — the
runtime already only logs) until live weeks show its rate.

### P2 · The flood blind spot (D-024): the server-scoped window is smaller than it looks

**What.** The documented 17 August flood (SIR-2026-08-17-001: one path, ~3,868 addresses, two-minute
bursts) is invisible to every entity-scoped gate by construction, and the journal pins that with a
test. It defers the fix as an architectural change.

**Do.** The minimal version is one more accumulator in `WindowFeatureBuilder` keyed `(server, bucket)`
with about six counts — events, distinct addresses, distinct paths, 4xx share, share of never-seen
entities, top-path share — emitted as a `FeatureVector(entity=EntityKey(server, "*", "*"), window="5m")`
and consumed by a small use case (`ops_health`-lite, AU-11's seed) in observe mode, scored by an
IForest or Half-Space Trees calibrated on the server's own history. The same aggregate is what the
spec's fleet-simultaneity suppressor (>30 % of entities anomalous → reroute) needs, so one builder
change serves two spec items. The sister framework computes exactly these population windows beside
entity windows; the flood is visible there in its first window. Keep `test_volumetric_blind_spot.py`
and add its sibling: the server window *does* fire on the report's numbers.

### P2 · Progressive alerting's price: a learned burst stage, and local days

**What.** D-033 states the cost honestly: a burst scanner never reaches the queue, a sustained one
waits 30 minutes. All nine captured scanners are bursts (360–880 requests in 6–100 s).

**Do.** Two refinements that stay inside FR-62 because every number is learned from the profile:
1. A *burst* escalation: a one-window episode whose `source_distinct_paths` or `web.mean_path_idf`
   exceeds the server's own p99.9 of that quantity (the profile's `feature_stats` already carries
   p50/p99 — add p99.9) earns `medium` at once and is written to the queue's candidate list with the
   reason.
2. The spec's transition-to-success band: a 2xx on a path with IDF ≈ 1.0 inside a firing window
   (+10). Both are evidence-derived and readable in the narrative. Replay them over the week's 30,856
   fires (the replay the team already ran for D-033) before shipping.

Also: `AlertBudget` and `Progression` reset "the day" on the UTC date; the deployment and its SOC
think in IST, so the daily promise resets at 05:30 local. Use the local day for per-day promises.

### P3 · Smaller engineering items

- **Per-use-case run mode (FR-70, ARCHITECTURE §4) is in config but not in the runtime.**
  `_handle_many` reads `self.cfg.mode` for every runner; `Config.mode_for(slug)` is never consulted.
  Staged cold-start (Tier-1 live while Tier-2 shadows) needs a per-runner mode.
- **Corpus hygiene vs slow ramps.** The top-0.1 % drop (`training/trainer.py:_drop_most_anomalous`)
  uses a preliminary Isolation Forest on the same corpus — right for bursts, blind to a slow scanner
  spread across the corpus (D-032: "a corpus full of scanners teaching that scanning is partly
  normal"). On this feed a 72-hour slow ramp got ~40 % of its windows admitted into a rolling
  calibration; a trusted pool with a per-entity cap and a batch gate held the attacker to 3 rows in
  ~20,000. For batch training: cap any one *address*'s share of the corpus at a learned quantile (the
  p99 of per-address windows), and print the top contributors in the training log.
- **Durability of the checkpoint.** `tmp.write_text` + `replace` is atomic but not durable; an
  `os.fsync` on the temp file before the rename costs nothing at 30-second intervals.
- `check_candidate` materialises the whole stream (`list(events(...))`) — bounded by `--limit`; say
  so in its docstring.
- **Lint.** 74 ruff findings (24 UP017, 13 UP037, 11 E402, 5 I001, 4 UP042, 3 B905, …), 44 fixable:
  run `ruff check --fix` once, then make `ruff` and `mypy` part of the test command so they stay
  clean. (`mypy` is configured in `pyproject.toml`; I did not run it.)
- **Tests to add after the fixes above:** `promote` refuses a version without an approval report;
  the hour-sampled drift reservoir; the server-scoped window fires on the flood's numbers; the
  per-runner mode.

---

## 3. The evidence layer — how to get it without slowing the product

The journal already has the voice. What it lacks is the *sealed-before-the-run* part and the
*registered inputs* part. Concretely:

- `measurements/M-nnn.yaml` per measurement: id, question, hypotheses with their falsification rules
  (one-sided where "better" has a direction), the inputs by sha256, the code commit, the seeds, the
  start and end, the verdict, the limitations. Written before the run; the verdict appended after.
- Vocabulary that survives review: a false-alarm rate (benign fires per day) beside every detection
  claim; never a "detection rate" without ground truth; "pseudonymised" for hashed identifiers, never
  "anonymised"; drift as real/virtual and sudden/gradual/recurring; the adaptation metrics — average
  run length of false alarms, detection delay, recovery time — when drift handling is discussed.
- Do not claim novelty for Isolation Forest, LOF, percentile calibration or champion–challenger. The
  defensible contribution here is *zero-threshold deployability measured on a live university edge*:
  eight unattended days with volume, catches and misses recorded is already an operational result —
  it becomes a citable one the first time the rule is written before the week.

---

## 4. A two-week order

1. Evidence-gated promotion: `approval_check.json`, the refusal in `promote`, `rollback_target`,
   `code_commit` in metadata — 1–2 days.
2. The pre-registration for the 7-day re-measure — half a day, *before* the window opens.
3. Fire share per local hour in health and the dashboard — half a day.
4. Address-level persisted activity histogram + `memory_hours_observed` — 1–2 days.
5. `--seeds` in `check_candidate` — 1 day.
6. The synthetic-attack harness (scanner generator, placement, join, report) — 3–4 days.
7. The server-scoped window in observe mode — 2–3 days.
8. The burst stage and the transition-to-success band, replayed on the week's fires — 1–2 days.

## 5. What not to do

- Do not widen the gate percentile or raise the budget to "fix" volume (the team already refuses
  this — keep refusing).
- Do not retrain `bot_detection` on schedule until its alert has features that can represent a
  headless browser.
- Do not add Kafka/Redis/MLflow before the standalone profile has pre-registered measurements behind
  it; the zero-infra default is the adoption story.
- Do not read a one-seed comparison as a model comparison.
- Do not let any path — CLI or dashboard — promote without a recorded verdict.
