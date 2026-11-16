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

- **2026-11-06 21:31 IST, before the window: build 57b4520 deployed** (the
  echo rule). Clean SIGTERM drain (5 s), started with the launch command,
  resumed from the checkpoint with the 16 open exposures, same bundles. No
  watchdog line.
- **The feed had stopped at 19:39 IST, before that deploy.** The parser began
  writing one file per worker (`nginx.w0..w2.json`) and `nginx.json` stopped
  growing; the runtime, tailing that one file, read nothing for two hours.
  Nothing on the soc-ml side was changed at 19:39.
- **21:41 IST: build 29c9484 deployed** — `--input` is now the quoted glob
  `/var/log/soc_output/nginx*.json`, the worker files merged by event time;
  the checkpoint's position in `nginx.json` carried over by inode (not
  re-read). Clean drain (3 s), launch command with the glob, no watchdog
  line. The two-hour backlog was read from the worker files' start, so the
  gap is closed rather than skipped. The workers re-deliver about 0.44% of
  lines (0.01% before the change); not deduplicated by this build. Both
  deploys are before the window, which opens 2026-11-07 00:00 IST.
- **Launch command from this build:** `SOC_ML_CONFIG=config/site.local.yaml
  nohup setsid .venv/bin/soc-ml run --uc bot_detection,web_recon --input
  "/var/log/soc_output/nginx*.json" --mode live --daily-budget 3`; the
  watchdog's default input is the same glob.

## Verdict

*Read 2026-11-16, after the analyst deadline (00:00 IST). Code in the window:
29c9484 throughout (no deploy inside it). Corpus: the log server's four
rotations covering 6 Nov 03:56 → 15 Nov 11:25 UTC, copied to
`data/corpus/m003b/` and checksummed; rotation gaps of 34 s (8 Nov), 32 s
(11 Nov) and 81 s (13 Nov) are reported, not counted.*

**H1 FAIL · H2 pass · H3 FAIL · H4 pass.** The exposure alerts are not
production-ready.

### H1 — 5 of 7 correct (71%), 0 untriaged: FAIL

No analyst verdict was recorded in the window, so all seven are the
verifier's stand-in (its latest check per exposure key), as the definition
allows. Read strictly — only a check made for the alert's own id — four are
untriaged and H1 fails either way.

| delivered (IST) | exposure | severity | verifier | of record |
|---|---|---|---|---|
| 8 Nov 12:30 | `web.config` on a research site, +7 files on 4 other sites | low 35 | confirmed | true positive |
| 11 Nov 03:30 | `/beta/.env` on a department site | critical | not reproducible | false positive |
| 11 Nov 08:15 | `web.config`, main site (7-day reminder) | medium | confirmed | true positive |
| 11 Nov 15:05 | `web.config`, helpdesk site (reminder) | medium | confirmed | true positive |
| 11 Nov 16:30 | `/search/.env` on a department site | critical | not reproducible | false positive |
| 11 Nov 19:10 | `.htaccess`, main site, +1 (reminder) | medium | confirmed | true positive |
| 13 Nov 18:50 | `web.config`, main site, +2 (reminder) | medium | confirmed | true positive |

Both false positives are pages no rule over the log can tell from a file:
a second app's shell under `/beta/` (4,103 bytes against the site's 3,929),
and a search route that prints the term (7,868 / 7,874 / 7,881 bytes, not
proportional to the path). The 8 Nov alert went out as low, not medium:
bot_detection's known-crawler down-weight lowered an exposure (a defect).

### H2 — 6 of 7 days at 3 or fewer: pass

0 / 1 / 0 / 0 / 5 / 0 / 1. 11 Nov had five (two of them the false positives,
three reminders).

### H3 — one exposure found offline was never recorded live: FAIL

`scripts/check_exposures.py` over the corpus (21,490,161 events; the rule
identical to 29c9484's — the only change since is a method the replay does
not call): 7 exposure deliveries and 34 folded downloads offline; every live
exposure key is found offline. One offline delivery has no live record:
11 Nov 19:23 IST, `/.env` on a portal, 200, 1,754 bytes, one request from
one address.

It is not a real file: 1,754 bytes is that site's home page, which it
returned for `/` about a thousand times that week and for `wp-login.php`,
`xmlrpc.php` and dozens more; the verifier reads the URL as an ordinary page
today. Live dropped it as the catch-all, correctly. The replay delivered it
because the per-site size memory (20,000 sizes) evicted the **oldest-inserted**
size when full: the site answered ~25,000 distinct 2xx sizes that week
(an API), and the replay, which began remembering twelve hours before the
runtime's last restart, filled up first and evicted 1,754 at 19:00 IST,
23 minutes before `/.env`. A simulation of that site's memory from both
start points reproduces both outcomes (replay: 1 other path known, live: 2).
The live runtime held 17,552 of that site's sizes then; it would have hit the
same eviction within days and delivered the home page as a critical `.env`.

By the letter H3 fails: the offline replay found an exposure not recorded
live. The defect is in the catch-all memory both share, not in delivery or
ordering; the consequence applies regardless. **Fixed before any further
measurement: D-043** (least recently *seen* size goes first); the same
simulation under D-043 keeps 1,754 from both start points.

### H4 — 0 watchdog restarts, 0 tracebacks: pass

The only "runtime not running" lines in `runtime.log` are from 12 and
26 Oct.

### Informational

- Scanner (low) alerts per day: 3 / 3 / 3 / 3 / 3 / 2 / 1 (18).
- Download records: 60 (37 server_config, 20 metadata, 2 secrets, 1 debug).
  Distinct downloaders: main-site `web.config` 11, helpdesk `web.config` 10,
  main-site `.htaccess` 9, research-site `web.config` 2, the rest 1.
- Verifier vs analyst: no analyst verdict in the window (one ever, 3 Nov).
- Exposures fixed during the window: none. Re-checked 16 Nov, all nine
  confirmed exposures are still served, including two critical
  `settings.php.old` files (PHP source) on two department sites, first
  alerted 14 Nov 01:35 IST, after the window.
- Exposures the echo rule dropped that the exact-size rule would have
  delivered: none. The same replay with the echo rule off gives the same 7
  deliveries.
- Under D-042 (a counterfactual from the verifier's checks two minutes after
  each delivery): 5 alerts, 0 / 1 / 0 / 0 / 3 / 0 / 1, all confirmed.

### Consequence

H1 fails → D-042 (fetch each new exposure once before alerting; hold back an
ordinary page) and the down-weight fix, deployed 16 Nov 14:31 IST. H3 fails
→ D-043, deployed before M-003c opens. Re-run as **M-003c**, 17-24 Nov IST.
