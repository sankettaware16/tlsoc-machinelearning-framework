# M-003c — Exposure alerts checked by content before delivery, 7 days on prod

*Written and committed before the window opened, as M-001 to M-003b were.
The verdict is appended below the line after the window closes and is judged
by the letter of what is written here.*

M-003b failed H1 on 16 Nov: two of its seven exposure alerts were pages that
no rule over the log can tell from a file (a second app's shell under
`/beta/`, a search route that prints the term). Its consequence for that
failure is "fix, and re-run as M-003c". The fix is D-042: the runtime fetches
each new exposure once before alerting it and holds back an ordinary web
page. The crawler down-weight no longer lowers an exposure's severity.
Everything else is M-003b's protocol, plus H5, which checks the cost of the
fix: that nothing real was held back.

```yaml
id: M-003c
question: >
  With each new exposure fetched before it is alerted, are the exposure
  alerts real, few and complete on a week of live traffic — and is nothing
  real held back?
follows: M-003b (H1 fail, 2026-11-16)
deployment: prod (10.0.0.11), use cases bot_detection (shadow) and
  web_recon (live), --daily-budget 3, local day Asia/Kolkata;
  exposure.verify_domains set (unchanged); console with the verifier; SIEM
  shipper running
code: main at or after the merge of D-042, the commit recorded in the
  verdict; web_recon bundle v20261012T132802, bot_detection v20261007T162845
window:
  start: 2026-11-17T00:00:00+05:30   # if the build runs by 2026-11-16 23:00 IST
  end:   2026-11-24T00:00:00+05:30
  otherwise: the first local midnight at least one hour after the build
    starts, and seven local days from there
inputs:
  - data/alerts/web_recon.ndjson            # delivered alerts (category)
  - data/state/web_recon_exposures.ndjson   # every download, with the verdict
                                            # of any check made before delivery
  - data/state/web_recon_verifications.ndjson  # the runtime's ("by": "runtime")
                                               # and the console's checks
  - data/state/web_recon_digest.ndjson      # withheld exposures' alerts
  - data/state/triage.ndjson                # analyst verdicts (console)
  - data/state/runtime.log
  - data/corpus/m003c/                      # the log server's raw nginx files
definitions:
  exposure alert: a delivered web_recon alert with alert.category "exposure"
  withheld exposure: a download record in the window with verdict
    "not_reproducible" and new false, for a key the runtime checked
  correct: an analyst verdict of true_positive or benign (benign = real but
    authorised: the detection was right)
  verdict of record: the analyst's latest verdict; if an alert has none by
    2026-11-26 00:00 IST, the verifier's latest per exposure key (runtime or
    console) stands in — an alert with any exposure confirmed counts as
    true_positive, one whose exposures are all not_reproducible as
    false_positive, anything else as untriaged — and the verdict reports how
    many were filled in this way
hypotheses:
  H1: of exposure alerts with a verdict of record, >= 80% are correct, and
      at most 2 of the week's exposure alerts are untriaged
  H2: exposure alerts <= 3 per day on at least 5 of the 7 days
  H3: completeness — scripts/check_exposures.py over the window's raw log
      files, run on the deployed commit, finds no exposure that was not
      recorded live (delivered, folded or withheld); files missing from the
      corpus are reported, not counted against
  H4: zero watchdog restarts ("runtime not running") and zero tracebacks
      inside the window
  H5: nothing real is held back — every withheld exposure is a page. Each
      is read in the raw log and put in one class: (a) a size the site
      returned for another path, (b) a 206 slice, (c) a page whose size
      moves with the path (another path in its directory or route within
      1% of its size), (d) none of these. A (d) is fetched again at the
      verdict, in full up to 64 KB, and read; it fails H5 if it is the
      file its kind names. The class and reason are written down for each.
prediction: >
  M-003b's own records, under D-042 (a counterfactual from its verifier's
  checks two minutes after each delivery, not a replay — a replay cannot
  fetch the past): 5 exposure alerts (0 / 1 / 0 / 0 / 3 / 0 / 1), all
  confirmed, and 2 withheld, both class (a)-(c) pages. Expected: H1-H5
  pass. The risk to H1 is that the verifier standing in for the analyst is
  the same check that gates delivery, so untriaged alerts mostly measure
  the gate; analyst verdicts are the evidence that does not. The risk to
  H5 is a real file of a non-debug kind served as HTML.
not_testable: >
  H1 if no exposure alert was delivered and H5 if nothing was withheld
  (each reported as such, never as a pass); H3 if the log server's files
  for the window are gone before they are copied; all before the window
  closes.
allowed_during_window: >
  operator restarts with the launch command (never the watchdog by hand);
  console and SIEM-shipper changes (they do not decide what is delivered);
  exposure.allow entries for exposures the site owner confirms are
  intentional — each recorded below with its reason. Any change to how
  exposures are detected, judged catch-all, checked or delivered, or to
  exposure.verify_domains, voids the window.
consequence:
  H1-H5 pass: the exposure alerts are declared production-ready.
  H1 fails: read the false positives; a kind, the catch-all rule or the
    check is wrong — fix, and re-run as M-003d.
  H3 fails: a delivery or ordering defect — fix before any further
    measurement.
  H5 fails: the check holds back real files — withheld exposures are
    delivered at low with their verdict instead, and re-run as M-003d.
informational: exposure alerts per day by kind and severity; checks made
  before delivery and their verdicts; withheld exposures per day; distinct
  downloaders per exposure; verifier verdict vs analyst verdict; scanner
  (low) alerts per day; exposures fixed during the window (re-check
  blocked_now); the exposures M-003b's week alerted that are still served.
```

---

## Events during the window

*Recorded as they happen, before the window closes.*

- **2026-11-16 14:31 IST, before the window: build bdcff4a deployed** (D-042).
  Clean SIGTERM drain (16 s), started with the launch command at 14:31:18,
  resumed from the checkpoint with the open exposures, same bundles. No
  watchdog line. The window therefore opens 2026-11-17 00:00 IST.
- **Wiring checked on prod, 14:40 IST**, with the runtime's `run` stubbed (a
  scratch output directory, nothing delivered): the launch command builds the
  check from `config/site.local.yaml`; a known catch-all `.env` reads
  not_reproducible, a confirmed `web.config` confirmed, a domain outside
  `verify_domains` is refused, and `--once` builds no check.
- **2026-11-16, before the window: the console gains a Measurement view**
  (`#measure`), which reads this doc and counts H1, H2, H4 and the withheld
  exposures live by its rules. A console change: nothing it does decides what
  is delivered. Checked against M-003b's files, it gives that week's figures
  (0/1/0/0/5/0/1 per day, 5 of 7 correct). Its counts are a view; the verdict
  is still computed and written here after the window.

## Verdict

*(appended after the window closes)*
