# Decision Journal

Append-only log of decisions and their reasoning. **Newest first.**

Write an entry when a decision is non-obvious, closes an open question, reverses
an earlier choice, or would otherwise make a future reader ask *"why on earth is
it done this way?"*. Do not log routine implementation.

Format: date · decision · why · what it rules out · where it lives.

---

## 2026-10-27 — One botnet, thirty alerts: campaign folding

### D-039 · Fold one user-agent's co-arriving addresses into one alert

**Context.** M-001's H1 (≤ 3 queued/day on ≥ 5 of 7 days) is already
arithmetically lost on day 4: 23 Oct queued 32, 25 Oct 8, 26 Oct 35. The 23rd
and 26th are each one actor — a single user-agent hash (`dc0402b6…`) across
28-30 Alibaba addresses (47.82/16, 47.79/16, the D-032 headless botnet), every
address reaching the queue stage in the *same* five-minute window. Per-address
delivery turned one campaign into thirty alerts. M-001's pre-registered
consequence for an H1 failure names this lever: campaign folding, not the
gate percentile, not the budget.

**Decision.** A fourth fold rule in `Progression`: an alert about to be queued
folds into the alert of another address with the same (server, user-agent)
that reached the queue within `EPISODE_GAP` (10 min, sliding with each
member). A finding folds only into a campaign alert that carried a finding
(the C1 rule); otherwise it is queued and starts its own campaign. Members
are recorded as the address's queued alert, so their later fires that day
fold by "episode" as before. State rides the checkpoint.

**Measured** with `scripts/replay_progression.py`, which replays the score
log's fires through `Progression` and first had to reproduce the recorded
queue exactly on the serving code (it did, every day): queued per day for
23-27 Oct goes 32/2/8/35/33 → **3/2/3/7/6**; 89 campaign folds. The residue
on 26-27 Oct is distinct user-agents at distinct times — real volume, not a
folding defect — so H1 would still fail on those days.

**Rules out.** Keying a campaign on user-agent alone: a common browser string
is not an actor, so co-arrival is required (a test pins two same-UA addresses
an hour apart as two alerts; with both the co-arrival check and the eviction
removed, it fails). Folding a finding into an alert without one.

**Not deployed.** It changes web_recon's delivery, which voids M-001; it ships
after the window closes (2026-10-30 00:00 IST) under a new pre-registration.

**Lives in.** `src/soc_ml/fusion/progressive.py`, `scripts/replay_progression.py`,
`tests/test_progressive.py`.

### D-038 · A quiet feed is not a stopped detector

**Context.** 2026-10-23 15:22 IST: the logserver's disk filled (`sso.log`,
17 GB, had no rotation rule) and every feed stopped upstream of Kafka. The
runtime was alive but did its periodic work per event, so it wrote no health;
the console reported STOPPED, pointing at the wrong layer.

**Decision.** `FileSource` takes an `on_idle` callback, called between polls;
the runtime runs its tick from it (health, checkpoint, flush; drift skips an
empty sample). Health and the checkpoint carry `last_event_at`; the console
shows **LIVE · NO INPUT** when health is fresh but nothing was read for
2 minutes. STOPPED now means only that health stopped. Deployed 2026-10-26
(d874e29); an operator restart inside M-001's window, recorded there.

**Lives in.** `ingest/file.py`, `detection/runtime.py`, `web/state.py`,
`web/dashboard.html`.

---

## 2026-10-22 (late) — Two redesigns, then an adversarial review of the day

### D-037 · Seventeen defects in a day's work, found by trying to refute it

**Context.** In one day the framework gained finding escalation (D-034), a
promotion gate, local days, per-use-case modes, an hour-wide drift sample
(D-035), and bot_detection's address rhythm (D-036) — most of it deployed
mid-measurement. Before trusting it, five independent reviewers (delivery,
state, features, measurement, gate integrity) read the diff `cbf1e34..` and
reported defects; every report went to two skeptics with different lenses
(code truth; reproduction and impact) told to refute it. 22 reports → **17
upheld by both, 1 split, 4 refuted**, most reproduced with scratch scripts.

**What it found that mattered most.**

* **M-001 could not fail** — the very trap D-035 claimed to avoid. H1
  counted empty and future days as passing; H2 and H3 chose their population
  by fields only the branch under test writes; H4 counted tracebacks from
  before the window. Fixed before the window opened (the document records
  the revision): H1 is "not testable" until the window closes and if any day
  has no rows; H2's population is the score row's own `findings` count,
  written before delivery decides; H3 is cross-checked against the digest
  file; runtime log lines are timestamped so H4 counts only the window.
* **A finding could be folded away** into an earlier alert that had none,
  and findings competed with ordinary alerts for the daily cap — the exact
  shape of the 10-21 git-dump miss. Findings now fold only into an alert
  that carried one, bypass the cap (recorded), and override crawler
  suppression (a verified crawler getting `/.env` back means it is public).
  An episode running across midnight is no longer delivered twice.
* **Rollback bypassed the gate.** Its fallback ("the newest other version")
  could serve the pending — even DO_NOT_APPROVE — candidate. Rollback now
  goes only to a version that has served, else refuses; the console agrees.
* **Snapshot memory double-counted** the replayed events and let training
  read its own future; **profiles learned "served"** from one attacker's
  successes; **findings** could be crowded out by catch-all pages or hidden
  by a HEAD probe; a **13-minute replay** judged a 30-minute gate (the first
  rhythm candidate's PASS rested on it, and was superseded). All fixed.

**Also found by testing the tests:** a midnight test whose clock never
crossed midnight, and a findings test that passed only because the catch-all
filter removed its inputs first. Both rewritten; every new test was run
against the previous code and fails there.

**Rules out.** Shipping a measurement or a gate without first asking how it
could fail; reading a passing test as evidence without checking it can fail.

**Lives in.** commits `f98742e`, `475c2f6`; `tests/test_{progressive,findings,
registry,address_rhythm,approval_gate,measure_m001}.py`.

### D-036 · bot_detection: address rhythm memory and a label-free rhythm model

**Context.** D-032: a GBM retrained on current traffic scored the live
headless botnet P(bot) 0.22 and fired on none of its 756 windows; the label
("admits to being a bot") cannot teach "headless browser", and the botnet's
only tells were temporal. The advisory review (P1) proposed exactly the split
taken here.

**Decision.**
1. **Address memory**, keyed by (server, address) — the stable actor (the
   botnet shared one user-agent across 30 addresses; the scanners one address
   across 34 user-agents): a 24-hour activity histogram, days seen, and recent
   per-bucket counts. Features `bot.addr_hour_entropy`, `bot.addr_active_ratio`,
   `bot.addr_rate_cv`; evidence `addr_memory_hours`, `addr_days_observed`, so a
   cold memory reads "unknown", not "human". Persisted every 10 minutes and at
   shutdown (a separate file — it reaches megabytes; the checkpoint is written
   every 30 s), restored at start. The LRU holds 50,000 addresses; at today's
   traffic it is full within the hour — an address active every five minutes
   is never least-recent, so the bots it exists for keep their history.
2. **`rhythm_iforest`**: an Isolation Forest over rhythm and browser-likeness
   (`RHYTHM_INPUTS`), fitted and calibrated on browser-declared windows only
   (new `UseCase.training_rows` hook), joining the spoofing gate's max-fusion.
   The GBM stays the human-likeness export and, after review S1, never sees the
   address features — its inputs are what they were.
3. Training and `check_candidate` take `--memory-from` the runtime's snapshot,
   restored history-only (D-037).
4. A bundle trained before a declared model loads without it (visible warning).

**First measurement (before the review fixes).** On the captured botnet, a
candidate trained on today's traffic fired on 926 windows, **every one carried
by `rhythm_iforest`** (3,035 windows over the gate vs the GBM's 20 and the
GMM's 15) — 28 of 68 addresses, as the serving model. The same retraining
without the rhythm model catches none (D-032). The corrected candidate's
numbers follow below once its check completes.

**The corrected candidate** (`v20261022T165316`, after the D-037 fixes),
checked on 2.05 h of live traffic (1.9M events, 535k windows) with the
runtime's history-only memory: canary 4/10 like serving; the captured botnet
28/68 addresses like serving, **all 981 fired windows carried by
`rhythm_iforest`** (GBM 8, GMM 21 over the gate); live fire rate 0.212%
against serving's 0.125% → WARN. By address: 36 fired by both (the Alibaba
botnet), 2 by serving only, **73 by the candidate only** — and those are
mixed. Inspected: an `xmlrpc.php` brute-forcer posing as a browser (350
xmlrpc hits, 1,131 × 404) and a PDF scraper — real bots the serving model
misses — but also **Roundcube webmail tabs** polling
`/?_task=mail&_action=refresh` every minute from campus and ISP addresses:
people with their mail open. Not approvable; recorded DO_NOT_APPROVE with
these reasons (the console blocks it).

**Why, probably, and what next.** `addr_active_ratio` counts the last hour's
buckets; a training replay starts with cold recent history (history-only
restore drops it, rightly), so for its first hour no address is "active
every five minutes" and the rhythm model learns that always-on is rare —
while live, every open webmail tab is. Next: a warm-up-free active ratio
(active buckets over buckets observed, within the hour) or excluding the
replay's first hour from the rhythm model's fit; then a *benign* regression
set (webmail pollers must not fire) beside the attack incidents, and a fresh
check. The design point stands: the label-free component catches what the
label cannot.

**Lives in.** `features/bot_features.py` (`AddressMemory`),
`features/window_features.py`, `models/rhythm.py`, `usecases/bot_detection.py`,
`core/plugins.py` (`training_rows`), `training/trainer.py`,
`detection/runtime.py`, `registry/store.py`, `tests/test_address_rhythm.py`.

---

## 2026-10-22 — An outside review, and the evidence layer it asked for

### D-035 · Promotion needs a recorded verdict; measurements are ruled before they run

**Context.** A researcher measuring the same mechanisms on the same IITB feed
reviewed the repository at `cbf1e34` (`docs/ADVISORY_REVIEW_2026-10-22.md`).
Its summary: the operational hardening is real; the *evidence layer* is thin —
promotion is a button with no recorded verdict behind it, measurements are
judged after the numbers exist, comparisons rest on one seed. D-032's blind
retrain was refused only because someone ran the replay.

**Done the same day** (each with tests; 247 passing):

1. **Promotion is gated** (P1). `check_candidate` writes `approval_check.json`
   into the candidate's bundle — verdict PASS / WARN / DO_NOT_APPROVE, fire
   rates, canary, per-incident addresses caught by each bundle, a SHA-256
   over the replayed events, the code commit. `ModelRegistry.promote` refuses
   a version without PASS/WARN *checked against the bundle serving now*, from
   the CLI, the dashboard and `train --promote` alike. Exceptions are recorded
   in the bundle: the first model (`bootstrap`) and `--force --reason`.
   Promotion records the displaced version; rollback returns to it (it used to
   pick "the newest other version", which can be a never-served candidate);
   pruning keeps it. Bundles carry `code_commit`. The console shows each
   verdict and greys Approve without one.
2. **The day is the deployment's day** (P2). Budgets and once-per-day folds
   counted UTC dates; the IST SOC's promise reset at 05:30 and on 10-21 the
   three deliveries were spent before the git dump arrived (D-034).
3. **Per-use-case run modes** (FR-70) are honoured; they were config only.
4. **Drift samples the whole hour** (algorithm R). It kept the first ~2,000
   windows after each check — under two minutes of traffic on this feed.
5. **The checkpoint is fsynced** before its rename.
6. **Gate fire share per local hour** vs the design share is in health and the
   console, flagged outside [0.5×, 2×] — the drift the frozen calibration
   suffers (the serving web_recon bundle measured 5.4× in D-032).
7. **M-001 is pre-registered** (`docs/measurements/M-001-progressive-7d.md`,
   script and tests committed first): 2026-10-23 → 10-30 IST. Writing it
   caught a vacuous metric: with `--daily-budget 3`, "delivered ≤ 3" passes by
   construction; H1 counts what was *queued before the cap*.

**Not taken as written.** The review's transition-to-success wording ("a 2xx on
a path with IDF ≈ 1.0") was replayed against the narrower rule: 11
escalations, nearly all new news images and JS chunks, against 1 real git dump
(D-034). The narrower rule stands.

**Queued, from the review** (ROADMAP "Advisory review"): bot_detection's
rhythm component and address-keyed persisted activity memory (in progress);
`--seeds` in `check_candidate`; a synthetic-attack harness; the server-scoped
window for floods; per-address corpus caps in hygiene; a learned burst stage;
hour-stratified calibration behind a flag; one `ruff --fix` pass with lint in
the test command.

**Lives in.** `registry/store.py`, `core/provenance.py`,
`scripts/check_candidate.py`, `web/`, `detection/{runtime,budget}.py`,
`fusion/progressive.py`, `scripts/measure_m001.py`, `docs/measurements/`.

---

## 2026-10-22 — A scan that finds something; a real git dump, missed twice

### D-034 · Escalate a success on a never-served file type — and the attack that proved why

**Correction to D-033 first.** D-033 said the nine captured scanners "found
nothing": every sensitive probe 404'd and their successes were public pages.
That was read off a top-15 listing that cut one line: **six of the nine got
HTTP 200 for `/web.config` from www.iitb.ac.in** (4,039 bytes each — most
likely Drupal's stock IIS file, still a posture issue for the web team).

**Decision.** A *finding* is a 2xx on a file type the server never serves, at a
path it was never seen *serving* — both learned. The profile now also learns
served hidden segments (`/.env`, `/.git/HEAD` have no extension; `.well-known`
is served and stays quiet) and served paths (`path_ok`, 2xx only: scanners
*request* `/.env` all day, so "requested before" would whitelist the one file
whose first success matters). Findings are kept per address and bucket so
user-agent rotation cannot split them off. A fired window with a finding gets
the spec's context band (+10, "transition-to-success") and is queued at once
with no progressive ceiling, once per address per day.

**A catch-all page is not a file.** The first replay escalated two scanners:
webmail.iitb.ac.in answered 123 probes (`/secrets.env`, `/terraform.tfstate`,
`/proc/self/environ` …) with the same 2,848 bytes, and www.medic.iitb.ac.in
answered six `/.env*` variants with 431. A size shared by two never-served
paths in one address-bucket is the site's answer to everything (soft 404);
those are dropped. Both escalations disappeared; real files keep their own
sizes.

**Measured, serving bundle, live traffic.** Implemented rule: 600k events → 0
escalations; the next 269k → **1**. The reviewer's broader wording (any 2xx on
a never-requested path, IDF ≈ 1.0) → 11, nearly all new news images and JS
chunks. The narrow rule stays.

**The one it caught.** `143.198.179.38` (DigitalOcean) downloaded
`gymkhana.iitb.ac.in/~hostel5/.git/` on 2026-10-22 between 20:45 and 20:49 IST:
7,208 requests, 6,554 successes at 3,192 distinct sizes, **6,519 git objects,
the index and config** — a completed git-dumper run; `HEAD` was 21 bytes,
`ref: refs/heads/main`. The same address made the same 7,208 requests on
**2026-10-21 at 05:35 IST**. The framework fired both times and delivered
neither:

| | fired | delivered? | why not |
|---|---|---|---|
| 10-21 05:35 IST | critical | no | the UTC day's 3 deliveries went to the first window after 00:00 UTC |
| 10-22 20:45 IST | yes | no | one burst → progressive "low" candidate (D-033's stated price) |

Replayed through the serving bundle with this rule: **escalated**. Deployed
2026-10-22 20:55 IST, ahead of the remaining fixes, because the attacker had
already returned once. The raw events are kept as
`data/incidents/web_recon/2026-10-22-git-dump-gymkhana-hostel5.ndjson` — the
approval gate now replays them for every web_recon candidate. Operator action
raised the same evening: deny `/.git` on that vhost; treat the repository's
history as disclosed and rotate anything secret in it.

**Rules out.** "A burst that found nothing" as a safe description of any burst;
judging success by status code alone; a daily cap that is spent by midnight.

**Lives in.** `baseline/profile.py` (`served_types`, `path_served`,
`file_type`), `features/window_features.py` (`_is_finding`, catch-all filter),
`detection/scorer.py` (context band, `links.findings`), `fusion/progressive.py`
(escalation), `explain/context.py`, `tests/test_findings.py`.

---

## 2026-10-22 — The 7-day measurement, and the first fusion stage it called for

### D-033 · Progressive alerting: lone weak signals stay low, sustained scanners reach the queue

**The measurement (2026-10-13 → 10-20).** Stability and detection passed: 8
days unattended, 0 restarts, 0 parse failures, 110M events; real scanners and
the headless botnet caught. The alert budget passed **only through the cap**:
exactly 3 delivered per day per detector, over web_recon fires of 4,408/day on
~3,000 distinct addresses/day. Traffic had risen ~6× (82% of events now one
vhost), and a percentile gate fires on a fixed share of windows — so volume
followed traffic, exactly as [percentile-gating-sets-the-floor] predicted.
Tuning cannot fix that; the spec's fusion stage is the designed answer.

**What the week's fires looked like.** 91% of addresses fired once and never
again (median 15 requests, 7% 404s). Persistence separated cleanly:

| address keeps firing | episodes/day | addresses (week) |
|---|---|---|
| 1 window | ~3,500 | ~20,500 |
| ≥ 10 min | 181 | 574 |
| ≥ 15 min | 51 | 106 |
| ≥ 30 min | 9 | 14 (404 share 0.96) |

Corroboration by a second detector occurred once all week — the spec step,
but not the lever on this feed yet.

**Decision.** `fusion/progressive.py` implements the spec's UC-02 progressive
alerting at the delivery layer, per (server, address), in event time: an
episode is a run of firing windows with gaps ≤ 10 min; severity is capped by
stage — one window **low**, persisting over 10 min **medium**, sustained 30 min
**high** (critical is left to the additive bands; one detector alone never
claims it); only **high** reaches the queue, once per address per day, later
fires folding into it. Everything below is digested as a candidate with its
stage and reason. Same-window user-agent fragments fold (D-031). State rides
the checkpoint (D-029). `UseCase.progressive` opts in; web_recon does,
bot_detection does not (its gate already demands 30 min). Backtest uses the
same decision (FR-72). The dashboard separates candidates from budget overflow.

**Measured.** The implemented class replayed over the week's 30,856 real fires:
**3.9 queued alerts/day (1-6 every day)**, 27 in total, without the cap.
Severity now carries information: 89% of fires low, 9% medium, 1% high
(before: all critical).

**The price, measured rather than assumed.** A scanner that finishes in one
burst never reaches the queue. The 9 captured real scanners
(`data/incidents/web_recon/`) each fired 360-880 requests within 6-100 s and
become low candidates. Every sensitive probe they made returned 404; their 504
successes were public pages and Drupal assets — they found nothing, and "low"
is the right verdict. A burst that *does* succeed on a path the server never
serves is the spec's context band ("transition-to-success") and is the next
fusion refinement; it would not have fired for these. Second cost: a
sustained scanner is queued 30 minutes after it began (its first window is in
the digest at once).

**Rules out.** Raising the gate percentile per traffic volume (a data
threshold in disguise); dropping lone fires (they stay recorded and visible);
claiming the budget is met by the cap.

**Lives in.** `fusion/progressive.py`, `detection/runtime.py` (`_deliver`,
`alerts_candidates`), `evaluation/backtest.py`, `core/plugins.py`
(`UseCase.progressive`), `web/` (candidates), `tests/test_progressive.py`.

---

## 2026-10-12 — A retrain that passes every check and is blind to the live attack

### D-032 · Real incidents are regression gates; bot_detection is not safe to retrain yet

**Context.** After D-031 both detectors were retrained on the longest corpus
the box still held (17 h: the parser now rotates at 2 GB and keeps one old
file). web_recon's candidate looked fine. bot_detection's first candidate
caught its synthetic spoofer canary and fired on 0.010% of windows — and on
replay **fired on none of 756 windows of the Alibaba headless botnet** the
serving model caught 176 times (P(bot) 0.22 vs 0.9998). The canary had
passed, so the existing approval check would have let it through.

**Quarantine did not fix it.** Retrained with both botnet /24s removed from
the corpus, the candidate got *worse*: 0/10 canary, 0 botnet fires. So the
cause is not contamination. Measured on the training corpus:

| class | rotating | 404 | asset fetch | no referrer | hour spread |
|---|---|---|---|---|---|
| declared bots | 16% | 0.19 | 0.54 | 0.53 | 0.06 |
| browsers | 2% | 0.04 | 0.42 | 0.14 | 0.06 |
| the botnet | 0% | 0.00 | **1.00** | **0.00** | **0.17** |

The botnet is a headless browser: it fetches page assets and sends
referrers, so on the features that best separate *declared* bots from
browsers it looks more browser-like than browsers do. Its only tells are
temporal (round-the-clock activity, regular timing). UC-04's label teaches
"behaves like something that admits to being a bot"; a spoofer that imitates
a browser rather than a crawler is outside what that label can teach. The
August-era model catching it is a property of that training sample, not of
the method — it cannot be reproduced by retraining today.

**Decisions.**

1. **Keep serving bot_detection `v20261007T162845`.** Neither new candidate
   is approvable. Retraining UC-04 is blocked until its label or features
   are redesigned for the headless-browser shape (temporal features carrying
   more weight, or a positive class not defined by the user-agent claim) —
   a design task, not a calibration one.
2. **Captured real attacks become approval gates.** `check_candidate`
   replays every file under `data/incidents/<use case>/` through serving and
   candidate; a candidate that catches none of what serving catches is DO
   NOT APPROVE, one that misses addresses serving catches is a WARNING.
   Filed per use case: the botnet replayed through web_recon made the
   candidate look "blind" for correctly not calling a headless browser a
   scan. Judged by **addresses**, not windows: since D-031 one address is one
   alert. Incidents are raw production logs and stay on the box
   (`data/incidents/*` and `*.ndjson` are gitignored). Seeded with
   `bot_detection/2026-10-09-alibaba-headless-botnet` (25k events, 68
   addresses) and `web_recon/2026-10-12-ua-rotating-scanners` (9 scanners,
   34 user-agents each, captured after the candidates' training window).
3. **web_recon `v20261012T132802` is approvable:** canary 2/2, all 9 real
   scanners caught (as serving), background fire rate 1.63% → 0.66%. Its
   per-scanner margin is thinner — it fires on 77 of 306 fragments against
   serving's 241, two scanners on a single window — consistent with a corpus
   full of scanners teaching that scanning is partly normal. Folding makes
   the SOC-visible result identical; the margin is worth watching.

**Rules out.** Approving on canary plus fire rate alone; treating "fires
less" as "better" without a by-address replay of known attacks; retraining
UC-04 on schedule while its label cannot represent the attack it is
catching today.

**Lives in.** `scripts/check_candidate.py` (`incidents`, `fired_ips`),
`.gitignore` (`data/incidents/*`).

---

## 2026-10-12 — One address, many user-agents: seen together, folded together

### D-031 · Address-level evidence and folding; low human-likeness is no longer a mitigation

**Context.** Four days of live data after the revival made the dominant
noise source unambiguous: cloud scanners rotating user-agents. The entity
key is `(server, ip, ua_hash)`, so one address became 36 entities and 36
fires in a window (D-027), spent the day's budget on fragments of itself,
and — because D-022 down-weights low human-likeness — got a *softer*
severity for claiming to be a bot. 34% of all web_recon fires came from
such addresses; the three alerts delivered each day were whichever fragments
arrived first after midnight.

**Decisions.**

1. **Every window carries its address's aggregate** for the bucket —
   `source_event_count`, `source_ua_count`, `source_distinct_paths` — kept
   by the builder per `(server, ip, bucket)` and released when the bucket's
   windows close. Evidence only, never model input: the models are trained on
   entity windows and stay so. The alert document carries it as
   `links.source` and the narrative says "the same address used N different
   user-agents in this window".
2. **Delivery folds by address.** `AlertDeduplicator` keeps an open alert
   per `(server, ip)` beside the per-entity one; a fire from the same address
   under another user-agent folds into it with `folded_by: "source"` in the
   score log and the rotation counted on the open alert. Detection is
   untouched (every fragment still fires and is recorded). State rides the
   checkpoint; a pre-D-031 checkpoint rebuilds the address view from its
   open entities so the deploying restart does not re-deliver.
3. **web_recon no longer down-weights for low human-likeness alone**
   (reversing that clause of D-022). Verified-and-polite still suppresses,
   verified-but-impolite and known-cluster still down-weight. For a
   reconnaissance alert, "behaves like a machine" is the finding.

**Measured** on 400k real events from elkcc (2026-10-12 10:34–13:04 UTC,
216 addresses with ≥5 user-agents), same bundle both runs: raw fires 112 →
112, delivered **105 → 45** (61 of the 105 were extra fragments of an
address already alerted), distinct addresses 44 → 44, canary caught both
times. On the Oct 8 live run the same change turns 36 alerts into one.

**Deliberately not done: a floor that reads the address aggregate.** With
enough rotation every fragment falls under the 5-request floor and the scan
is invisible; `source_event_count` on every window makes the fix a one-line
change. But the same rule would admit every 1-2 request fragment behind a
busy NAT (a campus gateway has hundreds of user-agents and thousands of
requests per window), and the floor exists precisely because tiny windows
have degenerate features. Pinned by
`test_known_gap_fragments_under_the_floor_are_not_detected`; closing it
needs either a rotation signal the models are trained on (user-agent churn:
each UA used once and dropped — NATs reuse theirs) or address-level windows
in training. Also deferred: the daily cap prefers arrival order over
severity; folding removes most of the pressure, a severity-aware cap is a
separate decision.

**Lives in.** `features/window_features.py` (`_SourceAgg`),
`detection/dedup.py` (`_OpenSource`, `folded_by`), `detection/runtime.py`,
`detection/scorer.py` (`links.source`), `explain/context.py`,
`usecases/web_recon.py`, `tests/test_source_folding.py`.

---

## 2026-10-12 — First reboot: the detector came back by itself, the console did not

### D-030 · A stop request must end an idle runtime; the watchdog keeps the console too

**Context.** elkcc was rebooted for a RAM upgrade (32 → 64 GB). The runtime
drained cleanly on the OS's SIGTERM (`stopped — 9,450,137 events … 18
delivered`), the cron watchdog restarted it four minutes after boot, and it
resumed from the checkpoint with the day's budget and cooldowns intact — the
D-027/D-029 chain held end to end. The operator console stayed down: it had
been started by hand with `nohup` and nothing supervised it.

**A latent bug found while preparing for the reboot.** The SIGTERM handler
only set `_stop`, which the event loop checks *per event*; a following
`FileSource` sleeps between polls and never returns. On a quiet feed — the
parser stopped first at shutdown, a rotated-away input, a paused upstream —
the runtime would ignore SIGTERM until the OS force-killed it, losing up to a
checkpoint interval of state. It did not bite this time only because events
were still flowing. `request_stop()` now also stops the source, so `read()`
returns after its current pass and the normal drain runs. Pinned by a test
that stops a following runtime on a static file; the old code never returns.

**Decision.** `deploy/soc-ml-watchdog.sh` also restarts the console (opt out
with `SOC_ML_UI_PORT=`). Every restart of either is logged.

**Lives in.** `detection/runtime.py` (`request_stop`),
`deploy/soc-ml-watchdog.sh`, `tests/test_detection_lifecycle.py`.

---

## 2026-10-10 — Delivery state rides the checkpoint

### D-029 · The daily cap and open cooldowns must survive a restart

**Context.** The first 24-hour review after the revival showed web_recon
with **6 delivered on 2026-10-08 against a 3/day budget**: three at 08:20 UTC
from the morning run, three at 14:10 UTC — minutes after the D-028 restart.
`AlertBudget` counts and `AlertDeduplicator` cooldowns lived only in memory,
so every restart granted a fresh day's allowance and re-delivered entities
whose alert was still open. A crash loop would deliver the budget per
restart; the watchdog (D-027) makes restarts routine, which makes this worse,
not better.

**Decision.** Both carry `export_state()` / `restore_state()` and ride the
runtime checkpoint under `delivery[slug]`, next to the crawler-politeness
memory (D-023) and the inode-tracked offsets (D-027). Legacy checkpoints
restore as empty state. The checkpoint is written every 30 s, so at most
30 s of delivery decisions can be lost on an unclean kill — the same bound
the read offset already has. The pre-fix elkcc checkpoint was seeded once
from the alerts files and score logs so the deploying restart did not itself
re-trigger the bug.

**Also recorded here: bot_detection's first production catch** (2026-10-09
02:50–12:15 UTC). Thirty Alibaba Cloud addresses (`47.82.11.x`, `47.79.13.x`)
sharing one browser user-agent, each fetching 5–8 page assets per 5 minutes
with machine-regular timing around the clock: P(bot|behaviour) 1.0,
human-likeness 0.0003, sustained through the 30-minute gate. 1,857 fires →
3 delivered, 1,518 folded, 336 digested. Whether it is hostile or a benign
scraper is the analyst's verdict (`benign-true-positive` exists for this);
the detector's logic held.

**Lives in.** `detection/budget.py`, `detection/dedup.py`,
`detection/runtime.py` (`_save_checkpoint`, `_restore_checkpoint`),
`tests/test_detection_lifecycle.py`.

---

## 2026-10-08 — The console said STOPPED every four minutes; the runtime was scoring

### D-028 · Score a closed bucket as one batch, and tick health per window

**Context.** Six hours after the revival the console showed STOPPED ("nothing
scored for 2m 25s") while the process was alive, in state R, on a full core,
with the input file growing and the event counter frozen. Sampling the health
file every 5 s showed the shape: ~90 s of events flowing, then a 2-3 minute
stall, then the `windows` counter jumping by ~2,500 — one 5-minute bucket's
worth of entities (3,000-3,700 open windows on the post-upgrade feed) closing
on a single watermark sweep and being scored **one row at a time at ~78 ms
each**. Health is written from the event loop, so none was written for the
duration; the dashboard's 60 s liveness window called it dead. Lag reset to
near zero after each burst, so the runtime was keeping up — at a ~60% duty
cycle, one traffic increase away from falling behind for good.

**Decision.** `Scorer.score_many()` scores a batch: each model is asked once
via its existing `score_batch` (the training path already relied on these);
calibration, fusion, the gate, alert building, suppression and annotation
still run **per window in input order**, so streak-keeping gates and
annotations read by a later window of the same entity behave exactly as
before. `score()` is now `score_many([w])[0]` — one code path for live,
backtest and `check_candidate` (FR-72), and `tests/test_batch_scoring.py`
pins outcome-for-outcome equality against the per-window path. The runtime's
periodic duties moved into `_tick()`, called per event *and* per handled
window, so a long batch still writes health and checkpoints.

**Measured.** Same 300k-event bot_detection backtest, same results: 82 s →
25 s locally. Full test suite: 54 s → 22 s.

**Rejected.** A health-writer thread (hides the stall rather than removing
it, and shares mutable stats across threads for no gain); widening the
dashboard's liveness window (a 3-minute blind spot is not liveness).

**Lives in.** `detection/scorer.py` (`score_many`), `detection/runtime.py`
(`_handle_many`, `_tick`), `evaluation/backtest.py`,
`scripts/check_candidate.py`, `tests/test_batch_scoring.py`.

---

## 2026-10-08 — Revived on elkcc; the first window caught a UA-rotating scanner

### D-027 · Inode-tracked checkpoints, a cron watchdog, and two weaknesses the first live catch exposed

**Context.** Fresh bundles (bot_detection `v20261007T162845`, web_recon
`v20261007T163432`) were approved in the console, both beating the August
bundles in `check_candidate` (the August bot_detection bundle caught **0/10**
spoofer canary windows; the new one 5/10). The runtime restarted 2026-10-08
13:52 IST with August outputs archived to `data/state/archive/2026-08-run/`,
so the Phase 3.6 measurement starts clean.

**Fixed before start: rotation while down.** `FileSource` only detected
rotation if the file had *shrunk* below the saved offset. A runtime down
across a rotation returns to a new file that may already be larger (45 MB
offset vs 760 MB `nginx.json`) and would seek into the middle of a different
file. Checkpoints now carry inodes; legacy ones keep the size check.

**Supervision.** No root on elkcc, so `deploy/soc-ml-watchdog.sh` runs from
the user crontab every 5 minutes and logs every restart to `runtime.log`.

**First window, first catch.** `34.39.165.91` (GCP) made 193 requests in 18 s
to `landing.iitb.ac.in` — 163 distinct paths, 179 × 404, probing `/.env`,
`/@fs/.env` (Vite file disclosure), `/graphql`, source maps — while rotating
**34 user-agents impersonating AI crawlers** (Grok, ClaudeBot, CCBot,
Bytespider, DuckAssistBot). web_recon fired critical. Two weaknesses showed:

1. **UA rotation shatters the entity.** The key is `(server, ip, ua_hash)`,
   so one scanner became 36 entities and 36 fires: dedup could not fold them,
   and they spent the whole day's delivery budget (3 delivered, 35 digested)
   in one window. Worse, most fragments had 5-12 events against a floor of 5.
   With ~2× more user-agents, every fragment drops under the floor and **the
   scan goes undetected**. That is cheap, deliberate evasion.
2. **Claiming to be a bot buys a down-weight.** 36 of 38 fires carried
   `downweighted_by: known/borderline automation`. Unverified claims to be a
   crawler lower the human-likeness score, and D-022 down-weights low
   human-likeness, so the impersonation reduces severity. This is the D-024
   open question with a concrete exploit attached.

**Not decided here.** Both are detection-semantics changes: an IP-level
aggregate alongside the entity key (folding and floor), and reversing D-022's
borderline down-weight for web_recon. They wait for the operator's call.

**Lives in.** `ingest/file.py`, `tests/test_ingest.py`,
`deploy/soc-ml-watchdog.sh`.

---

## 2026-10-07 — Reviving the elkcc deployment after 46 days down

### D-026 · Pin BLAS/OpenMP pools to one thread in the CLI entry point

**Context.** The live runtime died 2026-08-22 00:39 (SIGKILL mid-checkpoint;
launched via `nohup`, so nothing restarted it) and sat dead for 46 days. The
revival validation pass re-ran both backtests on current traffic. `web_recon`
passed in 14 minutes; `bot_detection` burned **10+ CPU-hours without
finishing** on the same 300k events — on a 4-core host whose background load
(Elasticsearch, Logstash) had risen to ~20.

**Diagnosis, measured.** The same backtest on the same 300k-event slice,
locally: 12m19s CPU with default thread pools, **78s CPU with
`OPENBLAS_NUM_THREADS=1`** — a 9.5× inflation from threading alone, with
identical results (PASS, canary detected). Profile: 98 of 152 seconds inside
`CalibratedClassifierCV.predict_proba`, called once per window on a single
15-feature row (22,483 windows, 254M Python calls). Every such call wakes the
BLAS pool for matrix work measured in microseconds; the pool's spin-wait
synchronization costs more than the math, and on a box where the cores are
already saturated the spinning multiplies to ~50×. The framework's workload
shape — one tiny row at a time, forever (FR-72 makes live and backtest share
it) — is the pathological case for thread pools.

**Decision.** `cli/main.py` sets `OPENBLAS_NUM_THREADS` / `OMP_NUM_THREADS` /
`MKL_NUM_THREADS` to 1 via `setdefault` before numpy can load, so an operator
export still wins. The systemd unit repeats it (`deploy/foss-soc-ml.service`)
for anything that bypasses the CLI. Not done per-call with `threadpoolctl`:
the pools are process-global, every soc-ml workload is small-matrix, and a
scoped limiter would leave training — GMM BIC selection is the same tiny-GEMM
shape — unprotected.

**Rules out.** Trusting library threading defaults on shared hosts; reading
high `%CPU` as progress (10 CPU-hours here bought less than 78 CPU-seconds of
work); sizing this detector's cost from a contended-box measurement.

**Lives in.** `cli/main.py` (env pins), `deploy/foss-soc-ml.service`.

---

## 2026-08-18 — Every production alert was an artifact of the error channel

### D-025 · A web log is not all requests: nginx's error stream was being scored as traffic

**Context.** An operator pulled the raw events behind one `web_recon` alert —
157.51.4.183, severity high, 46 "distinct paths" — and found an iPhone loading
the IIT Bombay homepage. Nginx rate-limited the browser's asset burst; the alert
was the rate-limiting, not an attacker.

**What actually happened.** The parser writes nginx's **error channel** into the
same stream as access records, correctly labelled `event.type: "error"`,
`log.level: "error"`, `event.reason: "nginx_limit_req"`. `Event.from_ecs` never
read `event.type`, so the framework could not tell the two apart. On the live
elkcc feed that is **32.1% of all events** — measured, not estimated.

Error records name a URL but carry no user-agent, no status and no bytes. Three
consequences, each visible in the production data:

1. **A phantom entity.** No user-agent means `ua_hash` is SHA-256 of the empty
   string. Every entity that fired carried `e3b0c44298fc1c14` — one bucket
   collecting the rate-limited fragments of every real visitor on the server.
2. **A fabricated top feature.** Error records log the whole request target, so
   `url.path` arrives as `/core/misc/drupal.js?v=9.3.22`. `_extension` documented
   the assumption "query strings never reach here" and therefore never stripped
   one, so the extension read as `js?v=9` — not alphanumeric, hence unknown.
   `web.unknown_ext_ratio` reached **0.6522 against a population median of 0.0**
   (deviation 999) and became the top feature in the alert. Roughly every
   versioned asset a CMS serves counted as "a file type this app does not serve".
3. **A third of the work, wasted**, and multiplied by every use case.

**Decision.** `Event` now carries `event.category`/`event.type`, and `FileSource`
drops non-request records at ingest — before any feature fold, since that is
where the cost multiplies. The skip is **counted** (`skipped_non_request`,
surfaced in health and the console), never silent: a third of a stream
disappearing must be a number an operator can read (NFR-09). Only a *positive*
non-access label excludes a record — a producer that sets no `event.type`
(Filebeat, Vector) is still processed, because assuming the worst about a silent
producer would drop real traffic. `_extension` strips the query string
defensively, the contract notwithstanding.

**Why the filter is at ingest and not in the gate.** Tightening a gate to reject
these would have hidden the cause and kept paying for it. The records are not
bad requests; they are not requests.

**This is D-014's lesson again**, and it is worth naming: that entry concluded
*"diagnosing a live component from a stale artifact"* was the error. Here the
error was trusting the contract's word — "query strings never reach here" — over
the stream. The framework validates its input rather than assuming a correct
producer (D-012); that discipline had not been extended to `event.type`.

**Rules out.** Treating every record in a web log as a request; trusting the
contract's field separation without checking; any silent input filter.

**Measured on the box.** With two use cases at 12-25 events/s the detector cost
**31% of one core and 150 MB RSS** — while Elasticsearch on the same 4-core host
held 19.4 GB and most of the CPU. soc-ml was never the load; but the per-event
cost is paid once *per use case* (D-020's private feature builders), so the
32% cut matters most for the 10-15 use cases the deployment is aiming at.

**Lives in.** `core/contracts.py` (`Event.event_type`, `Event.is_request`),
`ingest/file.py` (`skipped_non_request`), `baseline/profile.py` (`_extension`),
`detection/runtime.py` (health), `web/` (console),
`tests/test_non_request_records.py`.

---

## 2026-08-18 — Ground truth: the 17 August DDoS, measured against the live run

### D-024 · The engine ingested a 6M-request flood and said nothing — by construction, not by defect

**Context.** `bot_detection,web_recon` has been running `--mode live` on elkcc
since 6 August (11.76 days, 18,392,000 events, 943,153 windows). On 17 August
04:14 and 04:41 IST, www.iitb.ac.in absorbed two application-layer floods
totalling **5,955,459 requests**, 99.99% of them `GET /` from ~3,868 addresses,
each burst about two minutes long (TLSOC SIR-2026-08-17-001). This is the first
time this framework has been measured against an independently documented
incident on its own input.

**The engine emitted nothing.** No alert, no digest row, no suppression, in
either burst window, and not one of the report's attacker addresses appears
anywhere in its output.

**It did see the traffic.** The feed is the right one — `service.name`
`nvh_iitb` on `vh3`/`vh4`, top path `/`, Drupal `iitb_bootstrap` assets. And
the arithmetic closes: the feed's baseline rate is 12.3 events/s (571,993
events over 12.87 h), so 11.76 days of normal traffic is ~12.5M events against
the 18.39M the runtime counted. The 5.9M excess is the attack, to within a
rounding error.

**Why nothing fired — two independent structural exclusions, before any score
is consulted.**

1. `web_recon.gate` requires `MIN_DISTINCT_PATHS` (3) distinct paths. The flood
   used **one** path. D-017 chose that floor as the conservative reading of an
   implicit spec floor; against a single-path flood it is a total exclusion.
2. `bot_detection.gate` requires `SUSTAINED_WINDOWS` (6) *consecutive*
   5-minute windows — the spec's "sustained ≥30 min". A two-minute burst
   produces one window, so the streak can never exceed 1.

Both would otherwise have scored it highly: per attacker the window holds
~1,228 events, one path, ~94% 4xx (429 *is* a 4xx), no referrer and near-zero
inter-arrival CV — a browser-declared UA behaving like a machine, which is
precisely UC-04's spoofing shape.

**The deeper reason, which outlives both constants.** Every gate in the
framework is **entity-scoped**: it reasons about one `(server, ip, ua_hash)`
window and nothing about the rest of the server's traffic in that window. A
flood's defining signal is not any entity's property — it is that 3,868
entities arrived simultaneously. No entity-scoped gate can express that, so
loosening either constant would not fix the class; it would only add noise to a
detector already 100× over its alert budget.

**Decision.** Record the blind spot as a known, tested property rather than
quietly widening a floor. `tests/test_volumetric_blind_spot.py` pins both
exclusions with the report's own numbers, so closing the gap has to be a
deliberate act. Closing it properly needs a **server-scoped** window alongside
the entity-scoped one, which is an architectural change to
`WindowFeatureBuilder`, and a use case to consume it — there is no slot for one
in the UC-01…UC-15 catalog, which covers behavioral analytics and not
availability. That is a spec extension, deferred here to a decision rather than
taken unilaterally.

**Rules out.** Lowering `MIN_DISTINCT_PATHS` or `SUSTAINED_WINDOWS` to catch
floods; treating the miss as a calibration or drift problem; any claim that the
deployed detectors cover availability attacks.

**Also fixed here, both found by the same investigation.**

- **Live mode wrote no score log at all.** `_handle` called `_shadow_record`
  only in the non-live branch, so `ScoreResult.record()` — documented as "the
  always-written audit line" — was written never. `downweighted_by` survived
  only on *delivered* alerts, via `Alert.links` (34 of elkcc's 42 carried it),
  and was therefore invisible for the ~98% of fires that were folded, digested
  or suppressed. That is the invisibility D-023 called a defect in itself,
  reintroduced for every live deployment. Live mode now writes one row per fire
  to `<slug>_scores.ndjson`, carrying the delivery `disposition` (delivered /
  folded / digested / suppressed). Separate file from the shadow log
  deliberately: shadow records every window and live only the fires, so one
  file would mix two populations — and a stale shadow file would read as
  current, which is how eleven days of elkcc data was nearly misread.

  **First five minutes on the restarted runtime already paid for it:** all 11
  `web_recon` fires carried `downweighted_by: known/borderline automation`, and
  every firing entity had `ua_hash e3b0c44298fc1c14` — SHA-256 of the empty
  string, i.e. no user-agent. Across the previous eleven days the same
  down-weight sits on 34 of 42 delivered alerts. A modifier that applies to
  ~81-100% of alerts is not discriminating between them; it is a constant
  severity offset. Whether D-022's `BORDERLINE_HUMAN_LIKENESS` rule belongs on
  a *reconnaissance* detector at all is now an open question — for UC-02, low
  human-likeness arguably aggravates rather than mitigates — and it is a
  question that could not even be asked before the score log existed.
- **Records only reached disk at shutdown.** No periodic flush existed, so
  `SIGHUP`/`SIGKILL` lost whatever sat in a buffer; on elkcc that hid 7 of 76
  suppressions. Flushing now rides the checkpoint tick, deliberately not later
  than the checkpoint that claims those events were processed.

**Lives in.** `detection/runtime.py` (`_score_record`, `_flush_outputs`,
`_deliver` now returns its disposition), `tests/test_volumetric_blind_spot.py`,
`tests/test_detection_lifecycle.py`, `scripts/verify_36.py`.

---

## 2026-07-30 — First combined shadow run on production (3.6)

### D-023 · Politeness is an operator property: scope robots.txt to (server, verified family)

**Context.** The first bot_detection + web_recon shadow run on elkcc's live
nginx showed the export working (39k windows, ~20k entities annotated, zero
spoofing false-fires) but Googlebot `66.249.64.168` still firing web_recon
un-suppressed — the exact false positive Phase 3 exists to remove.

**Diagnosis.** D-022 defined "polite" as *this entity* fetched robots.txt.
Real crawler pools rotate addresses: the whole 66.249.x pool made only 3
robots.txt fetches in the file, from different addresses (and UA variants)
than the recrawling one. Per-(ip, ua_hash) scoping can essentially never see
a pool member's politeness, so verified crawlers were down-weighted instead
of suppressed — and down-weights were not surfaced in shadow rows, so the
mis-scoping was invisible until the entity listing was inspected by hand.

**Decision.** Two changes. (1) The window builder tracks `(server, family)`
pairs where a **verified** member of a crawler family fetched robots.txt;
window evidence carries it as `family_robots_txt`, and the crawler export's
`crawler.robots_txt` is entity-level OR family-level. An *unverified*
claimant's robots.txt fetch never whitelists the family — verification
gates the write, so the flag cannot be planted by a spoofer. (2)
`ScoreResult.record()` now surfaces `downweighted_by` alongside
`suppressed_by` — a delivery modification that cannot be measured from the
shadow log is treated as a defect in itself.

**Rules out.** Politeness per entity as the only scope; any delivery-layer
decision (suppress, down-weight, future corroboration) that does not appear
in the always-written score record.

**Lives in.** `features/window_features.py` (`_family_robots`),
`usecases/bot_detection.py` (`annotate`), `detection/scorer.py`
(`record`), tests `test_bot_features.py` /
`test_web_recon_suppression.py` (the e2e now fetches robots.txt from a
different pool address than the one that recrawls).

---

## 2026-07-27 — Phase 3.5: crawler suppression semantics

### D-022 · Suppress at the delivery layer, define "polite" as robots.txt, down-weight one band

**Decision.** `web_recon`'s crawler suppression runs *after* its gate fires,
in the scorer's fusion "suppress" stage: the alert is built, then
`UseCase.suppression(evidence)` may mark it `suppressed_by`/`delivered=False`
(verified **and** robots.txt-fetching crawler) or lower `severity_score` by
one 25-point band with a `downweighted_by` reason (verified-but-impolite,
known-cluster, or `human_likeness < 0.5`). Suppressed alerts go to a per-slug
`*_suppressed.ndjson`, the shadow/score log carries `suppressed_by`, and the
alert document carries the annotation snapshot the decision saw. D-019's
"polite" is operationalized as **has fetched robots.txt** (from the entity
memory) — a verified identity that never fetched robots.txt is down-weighted,
not suppressed.

**Why.** Suppressing inside the gate (returning False) was the rejected
alternative: it erases the fired fact, which makes the before/after
fire-rate measurement impossible and violates NFR-09's "every suppression
leaves a record" — and it would entangle detection with delivery, exactly
what the spec's fusion pipeline (calibrate → corroborate → **suppress** →
fold → budget) separates. Firing unchanged also literally satisfies "no
change to web_recon's learned thresholds". Robots.txt as politeness is the
one behavior marker that is (a) already computed, (b) near-universal for
legitimate search engines, and (c) cheap for an attacker to fake *only by
also being polite*. The failure mode is benign: a freshly restarted runtime
hasn't seen the fetch yet, so a verified crawler is down-weighted (still
delivered) instead of suppressed until it refetches — degradation in the
conservative direction.

**Rules out.** Gate-level suppression; silent drops; a config list of
"crawler IPs to ignore" (identity comes from the published-range check inside
UC-04, never from deployment config).

**Lives in.** `core/plugins.py` (`UseCase.suppression`),
`usecases/web_recon.py`, `detection/scorer.py` (`_apply_suppression`),
`detection/runtime.py` (`*_suppressed.ndjson`, `alerts_suppressed`),
`evaluation/backtest.py` (report field). Exit test:
`tests/test_web_recon_suppression.py` — one runtime, Googlebot suppressed
with the reason on record, the browser-declared scanner still delivered.

---

## 2026-07-27 — Phase 3.3: the UA-spoofing gate

### D-021 · UC-04's gate models calibrate against browser-declared windows, not all traffic

**Decision.** A new `UseCase.calibration_rows(model_slug, rows)` hook lets a
use case narrow the population whose scores define a model's percentile
reference. `bot_detection` calibrates `gbm_bot`/`gmm` against
**browser-declared** windows only; `hdbscan_cluster` keeps the full
population. The trainer falls back to all rows when the subset is thinner
than the minimum training-window floor.

**Why.** The spec's gate is "browser-UA entity with P(bot|behavior) ≥ p99.5
sustained ≥ 30 min". Calibrated over *all* windows, the p99.5 bar rises with
crawler prevalence: on a server where a fifth of traffic is actual Googlebot
scoring P(bot) ≈ 1, a spoofer at 0.99 lands near the 80th percentile forever —
the gate could structurally never fire, and the failure would be silent. The
spoofing question is "more bot-like than the *browsers* here", so that is the
correct reference population. The rejected alternative — gating on the raw
isotonic probability (≥ 0.995) — reads naturally but breaks FR-22
(percentiles, never raw scores) and loses per-server comparability.

**Rules out.** Gating any UC-04 alert on raw probabilities; "fixing" the
dilution by tuning the percentile constant per deployment (that would be a
config threshold, FR-62).

**Lives in.** `core/plugins.py` (`UseCase.calibration_rows`),
`training/trainer.py`, `usecases/bot_detection.py`. Verified end to end in
`tests/test_bot_detection_usecase.py` (the spoofer canary fires on windows
6-10 of 10 — the sustained gate exactly).

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
