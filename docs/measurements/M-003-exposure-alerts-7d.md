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

- **2026-11-02 18:51 IST, before the window: build 2e07445 deployed.** Clean
  SIGTERM drain (3 s), started with the launch command and
  `SOC_ML_CONFIG=config/site.local.yaml` (bot_detection shadow, web_recon
  live, IST day, verify domains set), resumed from the checkpoint. The
  exposure tracker starts empty, so the first download of an exposure that
  the old rule had already alerted on is alerted once more. No watchdog line
  was written.
- **18:53 IST: console-only update (d277f91)** — alerts written before D-040 are
  shown as "legacy" and kept out of the tally; the tally counts benign as
  correct, as H1 does. Detection and delivery unchanged.
- **SIEM shipper not running yet:** creating its Elasticsearch API key needs
  the operator. Until the key exists, alerts reach the SIEM only through the
  alert files; this does not affect H1-H4.
- **2026-11-03 11:30 IST: SIEM shipper started** by the watchdog once the
  operator created the key; it created `tlsoc-ml-alerts` and
  `tlsoc-ml-alerts-downloads` and backfilled 157 alerts and 2 downloads
  (both `metadata`, recorded and not alerted). The key was created twice;
  at 11:48 the shipper was restarted by hand to load the second, and the
  first is to be invalidated. Shipper only: detection and delivery unchanged.
  The operator invalidated the first key the same morning.
- **2026-11-03, on main, not restarted into the runtime: exposure alerts
  belong to web_recon only.** The full-pipeline replay of 2 Nov on prod
  showed bot_detection, run live, queuing the same web.config and .htaccess
  exposures as web_recon. On prod bot_detection is in shadow and delivers
  nothing (no `bot_detection_exposures.ndjson` exists), so the running
  build's web_recon output is unaffected; the change takes effect only for
  a use case other than web_recon, and is required before bot_detection
  goes live.
- **2026-11-06 19:18 IST: console-only update (0924539), verifier
  signatures.** A
  mid-window read found alert 698774b0 (`/error_log` on a department site, 350 KB) marked
  "likely": it is a public PHP error log (`[04-Apr-2025 09:25:09 UTC] PHP
  Warning: …`), and the log signature knew only ISO timestamps. The verifier
  now also recognises PHP and Apache error-log timestamps, and ASP.NET
  trace / ELMAH pages (HTML by nature, like server-status). The console was
  restarted with its launch command (SIGTERM, runtime untouched) and the
  alert re-checked at 19:19 IST: confirmed, "log file". Its earlier "likely"
  record stays in the file. Detection and delivery unchanged.
- **Same read, recorded for the verdict, nothing changed:** two alerts of
  6 Nov (84c087c6, 671f314d: `trace.axd` under one site's `/project/N/` and
  another's `/<module>/<tab>/`) are entirely not reproducible. Both sites answer
  the path with an ordinary page whose size varies per path (the second's
  page echoes the path; the first serves the parent page), so the exact-size
  catch-all rule did not see them. Fixing it changes how exposures are judged
  catch-all and would void this window: it is built offline for M-003b.
- **H3's input.** Elasticsearch keeps about five days, so the window's first
  days would expire before the verdict. The same raw lines Logstash indexes
  are kept on the log server (12 × 2 GB rotations); the window's files were
  copied to `data/corpus/m003/` on prod on 6 Nov (2 Nov 15:21 UTC – 6 Nov
  03:55 UTC so far, gzip-tested; 54 s missing at the 4 Nov 08:20 UTC
  rotation, copytruncate). H3 runs the offline rule check over these files
  instead of an ES export; the rest of the window is copied after it closes.

- **2026-11-06 (evening IST), inside the window: M-003 is voided.** The
  echo catch-all rule (D-041) changes how exposures are judged catch-all and
  is deployed, which voids the window by its own rule. Why it is stopped
  rather than run out: the two false positives above are understood and
  their fix is measured (the replay of this window keeps the six confirmed
  exposures and drops exactly the ten not-reproducible ones); with H1
  projected at 6 of 8 (75%), the remaining four days would only confirm the
  failure the protocol already names the consequence for. The week is
  re-run as M-003b from 7 Nov.

## Verdict

**Void** (see the last event above). Partial read at the void, recorded for
the record and not as a verdict: 3-6 Nov (to the void) delivered 0 / 3 / 1 / 4 exposure
alerts; of the eight, none had an analyst verdict; the verifier confirmed
five, found two entirely not reproducible (catch-all pages, D-041) and one
mixed (a confirmed files-directory .htaccess beside three catch-all
answers). H4 held: no runtime restart, no traceback. H3, run with
`scripts/check_exposures.py` over the log server's files to 6 Nov 09:25 IST:
all 16 alertable exposures found offline were recorded live, none missing.
