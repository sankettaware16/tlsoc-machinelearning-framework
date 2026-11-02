# M-002 — Campaign folding, 7 days on prod

*Written and committed before the window opened, as M-001 was: a rule chosen
after the numbers exist is a result, not a rule. The verdict is appended below
the line after the window closes and is judged by the letter of what is
written here, even if the answer is awkward.*

```yaml
id: M-002
question: >
  M-001 failed H1 and named campaign folding (D-039) as the next lever. With
  it deployed, does web_recon's queue stay inside the spec's alert budget,
  and does the live runtime fold exactly as the offline replay says it does?
follows: M-001 (verdict 2026-11-02)
deployment: prod (10.0.0.11), use cases bot_detection,web_recon, --mode live,
  --daily-budget 3, local day Asia/Kolkata
code: main at or after 1b9cda3 (merge of campaign-folding), the commit recorded
  in the verdict; web_recon bundle v20261012T132802, bot_detection
  v20261007T162845 (both unchanged from M-001)
window:
  start: 2026-11-03T00:00:00+05:30   # if the build is running by 2026-11-02 23:00 IST
  end:   2026-11-10T00:00:00+05:30   # seven full local days
  otherwise: >
    the window starts at the first local midnight at least one hour after the
    build starts, and ends seven local days later; the verdict records both.
    (The hour lets every episode and campaign opened under the old code end or
    reach the queue, so H5's one-day replay warmup sees the state the runtime
    actually had.)
scripts:
  - scripts/measure_m001.py --start <start> --end <end>   # same H1-H4 rules as M-001
  - scripts/replay_progression.py --start <start> --end <end> --check   # H5
inputs:
  - data/state/web_recon_scores.ndjson
  - data/state/runtime.log
  - data/alerts/web_recon.ndjson, data/state/web_recon_digest.ndjson
definitions:
  queued: as M-001 — disposition "delivered", or "digested" with
    digest_reason "budget"
  day: local calendar day in Asia/Kolkata
hypotheses:   # H1-H4 are M-001's, word for word; one-sided where M-001's were
  H1: queued <= 3 per day per server on at least 5 of the 7 days
  H2: every fire whose score row records findings was queued, or folded into
      an alert that itself carried a finding (into_finding: true) — campaign
      folds included
  H3: every one-window fire without a finding that was not folded is a
      digested candidate carrying its stage AND appears in
      web_recon_digest.ndjson with a progressive-candidate reason
  H4: zero watchdog restarts ("runtime not running") and zero tracebacks
      inside the window
  H5: replay_progression.py --check exits 0 on the window — the live queue
      equals the replay's on every day, so campaign state survives the live
      runtime (ordering, checkpoints, restarts) exactly as tested offline
prediction: >
  Stated before the window so that a pass is news, not a relief. Replayed on
  M-001's traffic, campaign folding queues 3 / 2 / 3 / 7 / 7 / 16 / 2 — <= 3 on
  4 of 7 days, so H1 is expected to FAIL on comparable traffic. The residue on
  the worst day is mostly finding escalations from services the 12 Oct bundle
  never saw served (Anubis, ONLYOFFICE); that is not what this measurement
  changes.
not_testable: >
  As M-001: H1 before the window closes or if any local day has no score rows;
  H2 if no fire carried a finding; H3 if there was no one-window fire; H4 and
  H5 before the window closes. "Not testable" is reported as such, never as a
  pass.
allowed_during_window: >
  operator restarts started with the launch command (never by running the
  watchdog script by hand — that writes the line H4 counts). Any change to
  web_recon's scoring, features or delivery voids the window, and so does a
  bot_detection model promotion or code change: its crawler export feeds
  web_recon's suppression. A voided window restarts as M-002b.
consequence:
  H1 and H4 pass: Phase 3.6's alert-budget gate passes for web_recon.
  H1 fails: read the per-day queue split (escalations vs sustained). If the
    escalations are mostly never-before-served legitimate services, the next
    lever is learning served-ness live; if the sustained residue is over
    budget on its own, it is distinct actors and the budget question goes to
    the spec owner, not to another fold.
  H2, H3 or H5 fails: a delivery-path defect; fix before any further measurement.
informational: fires per day; queued per day split into finding escalations
  and sustained (replay_progression.py queued_escalated); campaign folds per
  day; what the findings were; bot_detection fires and queue.
```

---

## Events during the window

*Recorded as they happen, before the window closes.*

- **2026-11-02 13:22 IST, before the window: build c18e149 deployed.** Clean
  SIGTERM drain (3 s), started with the launch command 7 s later, resumed from
  the checkpoint (episodes and queue carried over, campaigns empty), same
  bundles. No watchdog line was written. The build is running more than an hour
  before 2026-11-03 00:00 IST, so the window opens then.

- **2026-11-02 (evening IST), before the window opened: M-002 is voided.**
  The window was to open at 2026-11-03 00:00 IST. The exposure alerts (D-040)
  change web_recon's delivery and are deployed before or during the window,
  which voids it by its own rule. The reasons it is stopped rather than run
  first: its outcome is already predicted (the replay queues 3 / 2 / 3 / 7 /
  7 / 16 / 2 on M-001's traffic, H1 fails), and what it measures, the volume
  of sustained-scanner alerts, is no longer what the deployment pages on.
  Campaign folding stays deployed. The next measurement is M-003: the
  exposure alerts' precision as judged by analysts, 7 days.

## Verdict

**Void** (see the last event above). No hypothesis was evaluated.
