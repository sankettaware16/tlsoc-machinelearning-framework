# M-003 — Sensitive-file exposure alerts, 7 days on prod

*Written and committed before the window opened, as M-001 and M-002 were. The
verdict is appended below the line after the window closes and is judged by
the letter of what is written here.*

This is the acceptance run for the first use case declared production-ready:
web_recon's exposure alerts (D-040). It replaces M-002, voided the same day.

```yaml
id: M-003
question: >
  Are the exposure alerts the ones an analyst wants — real, few, and
  complete — on a week of live traffic?
follows: M-002 (void, 2026-11-02)
deployment: prod (10.0.0.11), use cases bot_detection (shadow) and
  web_recon (live), --daily-budget 3, local day Asia/Kolkata; console with
  the exposure verifier; SIEM shipper when its API key exists
code: the exposure-alerts merge on main, commit recorded in the verdict;
  web_recon bundle v20261012T132802, bot_detection v20261007T162845
window:
  start: 2026-11-03T00:00:00+05:30   # if the build runs by 2026-11-02 23:00 IST
  end:   2026-11-10T00:00:00+05:30
  otherwise: the first local midnight at least one hour after the build
    starts, and seven local days from there
inputs:
  - data/alerts/web_recon.ndjson            # delivered alerts (category)
  - data/state/web_recon_exposures.ndjson   # every download
  - data/state/web_recon_verifications.ndjson
  - data/state/triage.ndjson                # analyst verdicts (console)
  - data/state/runtime.log
definitions:
  exposure alert: a delivered web_recon alert with alert.category "exposure"
  correct: an analyst verdict of true_positive or benign (benign = real but
    authorised: the detection was right)
  verdict of record: the analyst's latest verdict; if an alert has none by
    2026-11-12 00:00 IST, the verifier's stands in — confirmed counts as
    true_positive, not_reproducible as false_positive, anything else as
    untriaged — and the verdict reports how many were filled in this way
hypotheses:
  H1: of exposure alerts with a verdict of record, >= 80% are correct, and
      at most 2 of the week's exposure alerts are untriaged
  H2: exposure alerts <= 3 per day on at least 5 of the 7 days
  H3: completeness — re-running the offline rule check
      (the ES export the D-040 numbers came from) over the window finds no
      exposure of an alertable kind that was not delivered live, or folded
      into an alert of the same key
  H4: zero watchdog restarts ("runtime not running") and zero tracebacks
      inside the window
prediction: >
  From 29 Oct - 2 Nov: about 1.6 exposures a day, 6 of 7 confirmed by
  content. H1 and H2 are expected to pass; H3 is the open question, because
  the offline check and the live table see the catch-all sizes in a
  different order.
not_testable: >
  H1 if no exposure alert was delivered (reported as such, never as a pass);
  H3 if the ES indices for the window have expired before it is run; all
  before the window closes.
allowed_during_window: >
  operator restarts with the launch command (never the watchdog by hand);
  console and SIEM-shipper changes (they do not decide what is delivered);
  exposure.allow entries for exposures the site owner confirms are
  intentional — each recorded below with its reason. Any change to how
  exposures are detected, judged catch-all or delivered voids the window.
consequence:
  H1-H4 pass: the exposure alerts are declared production-ready.
  H1 fails: read the false positives; a kind or the catch-all rule is wrong —
    fix, and re-run as M-003b.
  H3 fails: a delivery or ordering defect — fix before any further measurement.
informational: exposure alerts per day by kind and severity; distinct
  downloaders per exposure; verifier verdict vs analyst verdict; scanner
  (low) alerts per day; exposures fixed during the window (re-check
  blocked_now).
```

---

## Events during the window

*Recorded as they happen, before the window closes.*

## Verdict

*(appended after the window closes)*
