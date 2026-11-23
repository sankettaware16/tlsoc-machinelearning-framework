# M-003d — Exposure alerts the SOC itself could read, 7 days on prod

*Written and committed before the window opened, as M-001 to M-003c were.
The verdict is appended below the line after the window closes and is judged
by the letter of what is written here.*

M-003c is projected to fail H1. Read on 21 Nov with three days of its window
left (it closes 24 Nov; its verdict of record is fixed 26 Nov 00:00 IST and
written there), two of its exposure alerts, both critical, are the same
answer served twice: on one site, a
portal, a scanner whose user-agent named a known crawler got HTTP 200 and
exactly 2,102 bytes for `/.env.production` and again for `/.env.save`; its
other probes got that site's 970-byte page or a 404. A browser got 404 for the
same path, and so did the SOC's own check, four and six minutes after each
download. D-042 delivered both: its rule holds back only "an ordinary web page
now" and lets "blocked now" through, in case the file was removed between the
download and the check. No check has ever found that — a file there at the
download and gone after it. Of the 38 made so far, 19 read confirmed, 16 not
reproducible, 1 likely, and the 2 blocked now are these two, 404 to a browser
as well. By M-003c's letter the two are untriaged until the analyst judges
them: unjudged, H1 reads 5 of 5 correct with 2 untriaged, the limit, and
passes; judged for what they are, 5 of 7 and it fails. D-044 is made on the
evidence either way. M-003c's consequence for an H1 failure is "fix, and
re-run as M-003d". The fix is D-044: no exposure alert for a download the SOC could not
itself read — `blocked_now` (4xx now) and `redirected` (3xx now) withhold
exactly as `not_reproducible` does; `unreachable`, `refused` and a check that
raised still deliver. Everything else is M-003c's protocol, with two changes.
H5 gains a class for the new withheld verdicts: neither 2,102-byte answer is a
class (a)-(c) page — the size was served for no ordinary path — so M-003c's H5
would have fetched them again, got 404 again and learned nothing. H1 no
longer lets the verifier stand in for the analyst: from D-044 on every
delivered exposure is one the verifier passed, and the stand-in would measure
the gate with its own instrument.

```yaml
id: M-003d
question: >
  With no exposure alert for a download the SOC could not itself read, are
  the exposure alerts real, few and complete on a week of live traffic, is
  nothing real held back — and does the analyst judge them?
follows: M-003c (H1 projected fail, read 2026-11-21; window closes
  2026-11-24, its H1 is fixed 2026-11-26 00:00 IST)
deployment: prod (10.0.0.11), use cases bot_detection (shadow) and
  web_recon (live), --daily-budget 3, local day Asia/Kolkata;
  exposure.verify_domains set (unchanged); console with the verifier; SIEM
  shipper running
code: main at or after the merge of D-044, the commit recorded in the
  verdict; web_recon bundle v20261012T132802, bot_detection v20261007T162845
window:
  start: 2026-11-25T00:00:00+05:30   # if the build runs by 2026-11-24 23:00 IST
  end:   2026-12-02T00:00:00+05:30
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
  - data/corpus/m003d/                      # the log server's raw nginx files
definitions:
  exposure alert: a delivered web_recon alert with alert.category "exposure"
  withheld exposure: a download record in the window with a verdict of
    not_reproducible, blocked_now or redirected and new false — a key the
    runtime checked and did not alert
  correct: an analyst verdict of true_positive or benign (benign = real but
    authorised: the detection was right)
  analyst verdict: the latest triage row the console wrote for the alert's
    own id (true_positive, false_positive or benign)
  verdict of record: the analyst verdict, if there is one by 2026-12-04
    00:00 IST (the deadline); nothing stands in for it. An alert without
    one is unjudged.
hypotheses:
  H1: every exposure alert of the week has an analyst verdict by the
      deadline, and >= 80% of them are correct. One unjudged alert makes H1
      not testable (reported as such, never as a pass): from D-044 on every
      delivered exposure is one the verifier passed, so the verifier
      standing in for the analyst would only measure the gate with its own
      instrument. The verifier's figure is reported beside it, as
      information.
  H2: exposure alerts <= 3 per day on at least 5 of the 7 days
  H3: completeness — scripts/check_exposures.py over the window's raw log
      files, run on the deployed commit, finds no exposure that was not
      recorded live (delivered, folded or withheld); files missing from the
      corpus are reported, not counted against
  H4: zero watchdog restarts ("runtime not running") and zero tracebacks
      inside the window
  H5: nothing real is held back — every withheld exposure, read in the raw
      log with scripts/classify_withheld.py, is in one class: (a) a size the
      site returned for another, ordinary path (not itself a sensitive name:
      two sensitive names of one size from one client are (e)'s evidence),
      (b) a 206 slice, (c) a page whose size
      moves with the path (another path in its directory — or in its route,
      when the directory has no other answer — within 1% of its size and not
      equal to it), (e) for blocked_now or redirected only: another client,
      not the SOC's own verifier, got a 4xx, 5xx or a 3xx other than 304 for
      the same path in the window, or the same client got the same size for
      another sensitive path; (d) none of these. A (d) is
      fetched again at the verdict, in full up to 64 KB, and read; it fails
      H5 if it is the file its kind names. The class and reason are written
      down for each.
prediction: >
  M-003c's own records under D-044 (a counterfactual from the runtime's
  checks before each delivery, not a replay — a replay cannot fetch the
  past): its five confirmed alerts delivered (1 / 1 / 3 / 0 / 0 on its first
  five days; the blocked_now ones fell on days 2 and 3) and its two
  blocked_now ones withheld, both class (e) by its
  first clause — for each, another client got a non-2xx for the same path
  inside the window (a browser's 404 two seconds before the second
  download; a 302 the next day). The two 2,102-byte answers came from two
  addresses of one network, so the second clause (one client, one size,
  two sensitive paths) would not have caught them. Expected: H2-H5 pass.
  M-003c's three withheld pages, read the same way on 21 Nov: one (a) (its
  size served for "/" and 13 other paths), two (d) (a search route nobody
  else requested that week, to be fetched at the verdict). H1 depends
  entirely on the
  analyst's triage. Zero analyst verdicts were written during M-003b and
  M-003c (one ever, 3 Nov), so the realistic risk to H1 is "not testable",
  and that is by design: a measurement the verifier could pass on its own
  would not measure whether the alerts are the ones an analyst wants. The
  risk to H5 is a real file of a non-debug kind served as HTML, or a real
  file removed between the download and the check (never recorded): the
  second would read as class (e) by its first clause, which is why the
  class and reason are written down for each and not only for a (d).
not_testable: >
  H1 if no exposure alert was delivered, or if any exposure alert is
  unjudged at the deadline; H5 if nothing was withheld; H3 if the log
  server's files for the window are gone before they are copied. Each is
  reported as such, never as a pass — before the window closes, except H1,
  which is settled at the deadline two days after it.
allowed_during_window: >
  operator restarts with the launch command (never the watchdog by hand);
  console and SIEM-shipper changes (they do not decide what is delivered);
  exposure.allow entries for exposures the site owner confirms are
  intentional — each recorded below with its reason. Any change to how
  exposures are detected, judged catch-all, checked or delivered, or to
  exposure.verify_domains, voids the window.
consequence:
  H1-H5 pass: the exposure alerts are declared production-ready.
  H1 not testable: the alerts are not declared. Nothing is fixed, because
    nothing was found. The measurement is repeated only once the analyst
    commits to judging every exposure alert of a week within two days of
    its close; a week nobody judges proves nothing and is not run again
    until then.
  H1 fails: read the false positives; a kind, the catch-all rule or the
    check is wrong — fix, and re-run as M-003e.
  H3 fails: a delivery or ordering defect — fix before any further
    measurement.
  H5 fails: the check holds back real files — withheld exposures are
    delivered at low with their verdict instead, and re-run as M-003e.
informational: exposure alerts per day by kind and severity; checks made
  before delivery and their verdicts; withheld exposures per day, and the
  blocked_now / redirected ones with the status the site gave the SOC;
  distinct downloaders per exposure; verifier verdict vs analyst verdict,
  and H1 as M-003c's stand-in rule would compute it (the console's
  Measurement view reads "nothing stands in" above and counts only analyst
  verdicts for this window: not testable while any alert is unjudged at
  the deadline); scanner (low) alerts per day; downloads
  whose client user-agent names a known crawler but whose requests are a
  scanner's (sensitive paths probed in a burst on one site, as the
  2,102-byte client of 18-19 Nov); exposures fixed during the window (every
  confirmed key re-checked at the verdict); the exposures M-003b's and
  M-003c's weeks alerted that are still served.
```

---

## Events during the window

*Recorded as they happen, before the window closes.*

- **2026-11-24 00:01 IST, before the window: build 8dc1477 deployed** (D-044;
  the commit after c3d6dd7 changes only a measurement doc). `deploy/rollout.sh`
  stopped the runtime at minute%5==1 with TERM (clean drain, 14 s), started it
  with the launch command, resumed from the checkpoint, same bundles
  (web_recon v20261012T132802, bot_detection v20261007T162845), no watchdog
  line, exit 0. The window therefore opens 2026-11-25 00:00 IST.

## Verdict

*(appended after the window closes)*
