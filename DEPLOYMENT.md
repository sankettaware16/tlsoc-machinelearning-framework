# Deploying foss-soc-ml (web_recon)

How to take the `web_recon` (UC-02) detector from nothing to a running,
self-updating service in front of an environment that uses **foss-soc-engine**
for parsing. No Kafka, no Redis, no Elasticsearch required.

This is the reference for **one** use case. Every future use case follows the
identical flow — that is the whole point of getting this one right.

---

## 0. Prerequisites

- The **parser** (`foss-soc-engine`) is running and writing ECS JSON to an
  output directory (default `/var/log/soc_output/`). That directory is the only
  integration point.
- Python 3.11+ on the box that will run detection (can be the same box).

```bash
cd foss-soc-ml
python3 -m venv .venv && .venv/bin/pip install -e .
```

Confirm the parser output satisfies the contract before anything else:

```bash
soc-ml validate --input /var/log/soc_output/ --limit 200000
```

A `PASS` means you can proceed. A timestamp-quality **warning** here (ingest-time
`@timestamp`) must be fixed in the parser rule first — timing features depend on
it (see `docs/JOURNAL.md` D-012).

---

## 1. The lifecycle in five commands

```bash
# 1. TRAIN a model from historical logs (the more history, the better the baseline)
soc-ml train --input /var/log/soc_output/ --limit 2000000

# 2. REVIEW what it learned, then PROMOTE it to serving
soc-ml status
soc-ml promote            # promotes the candidate -> "current" (serving)

# 3. RUN in shadow first — scores real traffic, delivers nothing, records everything
soc-ml run --input /var/log/soc_output/ --mode shadow

# 4. When shadow output looks right, RUN live — delivers alerts
soc-ml run --input /var/log/soc_output/ --mode live

# 5. Watch it
soc-ml status
```

That is the entire production cycle. Adding use case #2 later means: `soc-ml
train --uc <slug>`, review, promote, run — the same five commands.

---

## 2. The staged rollout (recommended for a new environment)

Do not jump to `--mode live` on day one. The detector needs to learn *this*
environment's normal, and you need to trust it. Follow the spec's staging:

| Stage | Command | What happens | Duration |
|---|---|---|---|
| **Train** | `soc-ml train --input <history>` | Learn the baseline from history | once |
| **Shadow** | `soc-ml run --mode shadow` | Scores live traffic, writes `data/state/web_recon_shadow.ndjson`, delivers nothing | days 1–7 |
| **Review** | inspect the shadow log | Confirm real attacks score high and benign traffic does not | — |
| **Live** | `soc-ml run --mode live` | Delivers alerts to the sink | day 7+ |

**No historical logs to train on?** Use cold start — the runtime learns from live
traffic before it starts judging:

```bash
soc-ml run --input /var/log/soc_output/ --mode shadow --allow-cold-start
```

It buffers `warmup_events` (default 200k) of live traffic, trains a first model,
promotes it, and begins scoring — all automatically.

---

## 3. Where everything goes

```
data/
├── models/web_recon/<version>/   the trained bundle (models, calibration, profile,
│                                  drift reference, metadata w/ feature-code SHA)
├── models/web_recon/current       -> the serving version
├── alerts/web_recon.ndjson        DELIVERED alerts (live mode) — your SIEM reads this
└── state/
    ├── web_recon_checkpoint.json   resume position (restart-safe)
    ├── web_recon_health.json       live health: EPS, counts, mode, drift band
    ├── web_recon_shadow.ndjson     every score (observe/shadow mode)
    ├── web_recon_digest.ndjson     alerts folded for exceeding the daily budget
    └── web_recon_drift.json        latest PSI drift report
```

Point Filebeat/Wazuh at `data/alerts/web_recon.ndjson` (already ECS-shaped, with
`event.kind: alert`, `rule.id`, `rule.name`) and at `data/state/*health.json` for
monitoring.

---

## 4. Running as a service (systemd)

A unit template ships at [`deploy/foss-soc-ml.service`](deploy/foss-soc-ml.service).

```bash
sudo cp deploy/foss-soc-ml.service /etc/systemd/system/
# edit paths + user in the unit, then:
sudo systemctl daemon-reload
sudo systemctl enable --now foss-soc-ml
journalctl -u foss-soc-ml -f
```

It restarts on failure, and because state is checkpointed, a restart resumes
exactly where it stopped — no reprocessing, no lost events. `systemctl stop`
drains cleanly (SIGTERM → flush windows, checkpoint, exit).

---

## 5. Keeping it fresh (never goes stale)

The runtime computes **PSI drift** hourly (live features vs the training
reference) and writes `data/state/web_recon_drift.json`. When drift is
significant on ≥2 features it logs a **retrain recommendation**.

Retraining is a safe, gated operation — it never silently swaps the serving model:

```bash
# retrain on recent traffic -> registered as CANDIDATE (does NOT auto-serve)
soc-ml train --input /var/log/soc_output/ --limit 2000000

# the candidate soaks; when you're satisfied, promote it (Tier-1 = human gate)
soc-ml promote

# if a promoted model misbehaves, roll back instantly (3 versions kept hot)
soc-ml promote --rollback
```

Automate the retrain with cron/systemd-timer (weekly is the spec cadence); keep
`promote` manual for Tier-1, or wire it behind your own checks.

---

## 6. Alert volume — set expectations

A single use case gating at the 99.7th percentile fires on ~0.3% of windows.
Two mechanisms keep that from flooding the queue **today**:

- **Per-entity dedup** — a scanner active for 20 minutes is one alert, not four.
- **Daily budget** (default 50/server/day) — overflow goes to
  `web_recon_digest.ndjson`, never to the live queue, never silently dropped.

Per-alert *precision* keeps improving as more use cases land: `bot_detection`
(UC-04) suppresses crawler false positives, and campaign clustering (UC-12) folds
distributed scans into single incidents. Those are the next build steps. For a
single detector, tune the budget to your team's appetite and review the digest
periodically.

---

## 7. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `run` exits with "no trained model" | `soc-ml train` + `soc-ml promote` first, or add `--allow-cold-start` |
| Everything scores anomalous | model trained on too little/greenfield data — train on more history |
| Zero alerts ever | check `data/state/*_shadow.ndjson` for scores; the evidence floor (≥5 events, ≥3 paths) suppresses tiny windows by design |
| Alert flood | lower the daily budget; wait for UC-04 crawler suppression; check the model isn't stale (drift report) |
| High memory on huge input | you pointed at a directory containing a multi-GB dump — point at the parser's rolling output, or use `--limit` for one-shot runs |
| Restart reprocessed data | the checkpoint file was deleted or the input path changed |
