# M-001 — Progressive alerting, 7 days on elkcc

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
deployment: elkcc (10.204.60.11), use cases bot_detection,web_recon, --mode live,
  --daily-budget 3, local day Asia/Kolkata
code: build afad343 or later; web_recon serving bundle v20261012T132802
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
  H2: every fire escalated by a finding (escalated_by: finding) was queued
  H3: every one-window fire that was not escalated is a digested candidate
      carrying its stage
  H4: zero watchdog restarts ("runtime not running") and zero tracebacks in
      the window; operator restarts for deploys do not count
not_testable: >
  H2 is not testable if nothing was escalated; H3 if there was no one-window
  fire; H1 if fewer than 7 days of the window have elapsed or the score log
  is missing days. "Not testable" is reported as such, never as a pass.
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

## Verdict

*(appended after 2026-10-30T00:00 IST)*
