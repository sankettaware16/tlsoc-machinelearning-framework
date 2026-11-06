# M-003b — Sensitive-file exposure alerts with the echo catch-all rule, 7 days on prod

*Written and committed before the window opened, as M-001 to M-003 were. The
verdict is appended below the line after the window closes and is judged by
the letter of what is written here.*

M-003 was voided on 6 Nov (see its events): a mid-window read found two of
the week's eight exposure alerts to be catch-all pages the exact-size rule
cannot see, and M-003's own consequence for that failure is "fix, re-run as
M-003b". This is that re-run, with the echo rule (D-041). Everything else is
M-003's protocol.

```yaml
id: M-003b
question: >
  With pages that echo the path recognised as catch-all, are the exposure
  alerts the ones an analyst wants — real, few, and complete — on a week of
  live traffic?
follows: M-003 (void, 2026-11-06)
deployment: prod (10.0.0.11), use cases bot_detection (shadow) and
  web_recon (live), --daily-budget 3, local day Asia/Kolkata; console with
  the exposure verifier; SIEM shipper running
code: main at or after the merge of catchall-echo, the commit recorded in the
  verdict; web_recon bundle v20261012T132802, bot_detection v20261007T162845
window:
  start: 2026-11-07T00:00:00+05:30   # if the build runs by 2026-11-06 23:00 IST
  end:   2026-11-14T00:00:00+05:30
  otherwise: the first local midnight at least one hour after the build
    starts, and seven local days from there
inputs:
  - data/alerts/web_recon.ndjson            # delivered alerts (category)
  - data/state/web_recon_exposures.ndjson   # every download
  - data/state/web_recon_verifications.ndjson
  - data/state/triage.ndjson                # analyst verdicts (console)
  - data/state/runtime.log
  - data/corpus/m003b/                      # the log server's raw nginx files
definitions:
  exposure alert: a delivered web_recon alert with alert.category "exposure"
  correct: an analyst verdict of true_positive or benign (benign = real but
    authorised: the detection was right)
  verdict of record: the analyst's latest verdict; if an alert has none by
    2026-11-16 00:00 IST, the verifier's latest per exposure stands in — an
    alert with any exposure confirmed counts as true_positive, one whose
    exposures are all not_reproducible as false_positive, anything else as
    untriaged — and the verdict reports how many were filled in this way
hypotheses:
  H1: of exposure alerts with a verdict of record, >= 80% are correct, and
      at most 2 of the week's exposure alerts are untriaged
  H2: exposure alerts <= 3 per day on at least 5 of the 7 days
  H3: completeness — scripts/check_exposures.py over the window's raw log
      files, run on the deployed commit, finds no exposure that was not
      recorded live (delivered or folded); files missing from the corpus are
      reported, not counted against
  H4: zero watchdog restarts ("runtime not running") and zero tracebacks
      inside the window
prediction: >
  The replay of M-003's window to 6 Nov 09:25 IST under this rule: 6
  exposure alerts in 3.4 days (3 / 1 / 2), every one confirmed by content,
  and none missing against the live record. Expected: H1, H2 and H4 pass.
  H3 is expected to pass because the replay ran the same builder and
  tracker; the risk is the per-directory memory (32 answers, 10,000
  directories) behaving differently live, where every site's traffic
  shares it.
not_testable: >
  H1 if no exposure alert was delivered (reported as such, never as a pass);
  H3 if the log server's files for the window are gone before they are
  copied; all before the window closes.
allowed_during_window: >
  operator restarts with the launch command (never the watchdog by hand);
  console and SIEM-shipper changes (they do not decide what is delivered);
  exposure.allow entries for exposures the site owner confirms are
  intentional — each recorded below with its reason. Any change to how
  exposures are detected, judged catch-all or delivered voids the window.
consequence:
  H1-H4 pass: the exposure alerts are declared production-ready.
  H1 fails: read the false positives; a kind or the catch-all rule is wrong —
    fix, and re-run as M-003c.
  H3 fails: a delivery or ordering defect — fix before any further measurement.
informational: exposure alerts per day by kind and severity; distinct
  downloaders per exposure; verifier verdict vs analyst verdict; scanner
  (low) alerts per day; exposures fixed during the window (re-check
  blocked_now); exposures the echo rule dropped that the exact-size rule
  would have delivered (the same script on the previous commit).
```

---

## Events during the window

*Recorded as they happen, before the window closes.*

## Verdict

*(appended after the window closes)*
