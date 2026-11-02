# M-001 — Progressive alerting, 7 days on prod

*Written and committed before the window opened (advisory review 2026-10-22,
P1: a rule chosen after the numbers exist is a result, not a rule). The verdict
is appended below the line after the window closes and is judged by the letter
of what is written here, even if the answer is awkward.*

```yaml
id: M-001
question: >
  With progressive alerting (D-033) and finding escalation (D-034) deployed,
  does web_recon's queue stay inside the spec's alert budget on its own —
  without the delivery cap doing the work — while still queueing what matters?
deployment: prod (10.0.0.11), use cases bot_detection,web_recon, --mode live,
  --daily-budget 3, local day Asia/Kolkata
code: the build deployed on 2026-10-22 before 23:59 IST (commit recorded in
  the verdict); web_recon serving bundle v20261012T132802
window:
  start: 2026-10-23T00:00:00+05:30
  end:   2026-10-30T00:00:00+05:30     # seven full local days
script: scripts/measure_m001.py (committed with this file; tests/test_measure_m001.py)
inputs:
  - data/state/web_recon_scores.ndjson   # one row per fire, with disposition
  - data/state/runtime.log               # watchdog restarts, tracebacks
  - data/alerts/web_recon.ndjson, data/state/web_recon_digest.ndjson (read for context)
  - data/state/web_recon_health.json      # fire share per local hour (informational)
definitions:
  queued: >
    reached the queue before the delivery cap — disposition "delivered", or
    "digested" with digest_reason "budget". Delivered alone is capped at 3 by
    construction and would prove nothing.
  day: local calendar day in Asia/Kolkata
hypotheses:   # one-sided: fewer queued alerts is never a failure
  H1: queued <= 3 per day per server on at least 5 of the 7 days
  H2: every fire whose score row records findings (findings > 0, written
      before and regardless of delivery) was queued, or folded into an alert
      that itself carried a finding (into_finding: true)
  H3: every one-window fire without a finding that was not folded is a
      digested candidate carrying its stage AND appears in
      web_recon_digest.ndjson (entity + window end) with a progressive-
      candidate reason — checked against the digest file, not the score log
  H4: zero watchdog restarts ("runtime not running") and zero tracebacks
      inside the window; runtime.log lines are timestamped from this build,
      and a traceback is placed at the last timestamped line before it
not_testable: >
  H1 is not testable before the window has closed, or if any local day of the
  window has no score rows at all ("the score log is missing days" — an empty
  day is never a passing day). H2 is not testable if no fire carried a
  finding; H3 if there was no one-window fire; H4 before the window closes.
  "Not testable" is reported as such, never as a pass.
allowed_during_window: >
  operator restarts; bot_detection model or code changes that touch only its
  own alert path (D-032 redesign). Any change to web_recon's scoring, features
  or delivery voids the window, which then restarts as M-001b.
consequence:
  H1 and H4 pass: Phase 3.6's alert-budget gate passes for web_recon.
  H1 fails: read the per-day numbers; the next lever is campaign folding
    (UC-12) across addresses — not the gate percentile, not the budget.
  H2 or H3 fails: a delivery-path defect; fix before any further measurement.
informational: fires per day; gate fire share per local hour vs design;
  bot_detection fires and queue; findings escalated and what they were.
```

---

## Revisions before the window opened

An adversarial review of the day's changes (2026-10-22, five reviewers, two
skeptics per finding) found that the first version of this document and its
script could not fail: H1 counted empty or not-yet-elapsed days as passing
days; H2 and H3 selected their population by fields that only the branch under
test writes; H4 counted tracebacks from before the window. It also found two
web_recon delivery defects that H2 is about: a finding folded into an earlier
alert that had none, and findings competing with ordinary alerts for the daily
cap. All were fixed, with tests that fail on the earlier code, and deployed
before the window opened. The hypotheses above are the revised ones; their
intent is unchanged.

## Events during the window

*Recorded as they happened, before the window closed. The hypotheses above are
unchanged; these are facts for whoever writes the verdict.*

- **2026-10-23 15:22 → ~15:55 IST: input outage, not a runtime fault.** The
  logserver's root disk filled (sso.log, 17 GB, had no rotation rule); every
  feed stopped upstream of Kafka. The runtime stayed up and resumed on its own.
  Fires for 23 Oct are therefore a lower bound; H1 is one-sided, so this can
  only help it, and the day still has score rows.
- **2026-10-26 00:14 IST: operator restart for a deploy (commit 4c3ed5b).**
  The change touches health, checkpoint and dashboard only (idle-feed health,
  `last_event_at`); web_recon's scoring, features and delivery are unchanged,
  so the window is not void. The runtime was stopped by SIGTERM at 00:14:21
  (runtime.log line 787, clean drain at 00:14:28) and started 21 s later by
  running `deploy/soc-ml-watchdog.sh` by hand. That writes
  `[watchdog] 2026-10-26T00:14:49+05:30 runtime not running; restarting`
  (line 789) — the exact line H4 counts. It is an operator restart (allowed
  above), not a crash the watchdog papered over. By the letter, H4's count
  will include it; the verdict must report that count and this note together
  rather than drop either.

## Verdict

*(appended after 2026-10-30T00:00 IST)*

Measured 2026-11-02 on prod by `scripts/measure_m001.py --start
2026-10-23T00:00:00+05:30 --end 2026-10-30T00:00:00+05:30`.

**Code.** 1c96023 (pulled and started 2026-10-22 22:20 IST) until 2026-10-26
00:14 IST, then 4c3ed5b (health, checkpoint and dashboard only; see above).
web_recon served bundle v20261012T132802 throughout; bot_detection
v20261007T162845. (Repository history was rewritten on 2026-11-02 to remove
real host and address details; the deployment's reflog records the same two
commits under their earlier hashes, 475c2f6 and d874e29.)

| day (IST) | fires | queued | delivered |
|---|---:|---:|---:|
| 2026-10-23 | 4,039 | 32 | 4 |
| 2026-10-24 | 10,119 | 2 | 2 |
| 2026-10-25 | 9,648 | 8 | 8 |
| 2026-10-26 | 7,012 | 35 | 3 |
| 2026-10-27 | 1,858 | 63 | 8 |
| 2026-10-28 | 23,737 | 43 | 12 |
| 2026-10-29 | 10,308 | 2 | 2 |

- **H1 — FAIL.** Queued <= 3 on 2 of 7 days (24 and 29 Oct); 5 were required.
- **H2 — PASS.** 23 fires recorded findings; 0 were lost (each was queued or
  folded into an alert that itself carried a finding).
- **H3 — PASS.** 8,551 one-window fires without a finding; 0 missing from the
  digest file.
- **H4 — FAIL, by the letter.** 1 watchdog restart, 0 tracebacks. The one
  restart is the 2026-10-26 00:14 operator deploy recorded above (runtime.log
  line 789), not a crash. No other watchdog line and no traceback fell inside
  the window.

**Consequence, as written.** Phase 3.6's alert-budget gate does not pass for
web_recon. H2 and H3 pass, so there is no delivery-path defect to fix first.
H1 failed, so the next lever is campaign folding across addresses (D-039,
branch `campaign-folding`), not the gate percentile and not the budget.

**Informational.**

- *Queue composition.* Finding escalations per day were 1 / 0 / 7 / 0 / 5 / 9
  / 0 (22 in all); the rest were 30-minute sustained scanners: 31 / 2 / 1 / 35
  / 58 / 34 / 2. The 23, 26 and 27 Oct peaks are botnets (one user-agent,
  dozens of addresses at once); the 28 Oct fire peak is one 203.0.x source
  rotating ~860 user-agents, which source folding (D-031) held to one alert per
  address.
- *What the findings were.* Of the 22 escalated alerts, 17 were new legitimate
  services the 12 Oct bundle had never seen served: 10 Anubis challenge pages
  (`/.within.website/x/cmd/anubis/...`, from 25 Oct) and 7 ONLYOFFICE editor
  loads (`docs.example.edu`, `sdkjs/.../fonts.wasm`, `Editor.bin`, from
  27 Oct). Served-ness is learned only at training time, so each new service
  escalates for every user whose window also fires, at critical, outside the
  budget. The other 5: 3 Pulse Secure HostChecker probes (`/dana-cached/hc/`),
  1 `/.well-known/security.txt` (public by design), and 1 true exposure,
  www.example.edu serving Drupal's `/.htaccess`, `/web.config` and `/README.md`
  to a fingerprinting scan (28 Oct 03:38 IST).
- *Gate fire share per local hour.* Not retained for the whole window: the
  health file keeps the last 24 local hours. Samples on 28-29 Oct ran
  0.66-0.86% against a 0.3% design share (2.2-2.9x).
- *bot_detection.* 7,046 fires on 23 Oct (3 delivered), then 2 on 25 Oct and 2
  on 29 Oct. It went quiet at 23 Oct 17:20 IST while one Chrome user-agent over
  ~160 Alibaba Cloud addresses (198.19/16, 198.18/16) stayed ~60% of the feed;
  the site's answers to it changed (502, then 301/410), and the 7 Oct bundle
  scores those windows as ordinary browsers (median p0.43). web_recon still
  fired on the same addresses.
- *Campaign folding, replayed on this window* (`scripts/replay_progression.py`,
  whose `--check` on the serving code reproduces the queue above exactly):
  3 / 2 / 3 / 7 / 7 / 16 / 2 queued, <= 3 on 4 of 7 days. Of those, 1 / 0 / 2 /
  0 / 3 / 9 / 0 are finding escalations. Campaign folding alone would not have
  passed H1; with it, the largest remaining share on the worst day is the stale
  served-ness above.
