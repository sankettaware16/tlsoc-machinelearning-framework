# foss-soc-ml

**Security alerts that learn your environment instead of guessing it.**

foss-soc-ml watches your web server traffic and learns what *normal* looks like
for **your** website — which pages exist, which visitors are typical, when your
users are active — and then alerts you when something breaks that pattern. No
rules to write, no thresholds to tune.

Free and open source, Apache-2.0.

---

## Why this exists (in one minute)

Traditional security rules look like *"alert if someone gets more than 100 errors
per minute."* Someone picks that number once, and then:

- it **misses** the careful attacker who stays under the limit,
- it **false-alarms** on your own new search bot,
- and it needs a human to re-tune it every time the website changes.

The problem is simple: **a fixed rule can't know what's normal for your specific
site.** A university portal, a hospital login page, and a shopping cart look
nothing alike — but they get the same generic rules.

foss-soc-ml learns each site's normal from its own logs, so an alert means
*"this is unusual **here**"* — and it comes with the evidence to prove it.

---

## What it does today

The first detector, **`web_recon`**, finds attackers **mapping out your site** —
scanning for hidden pages, admin panels, backup files (`.env`, `backup.sql`,
`.git`), the reconnaissance that comes before a real attack. It catches this by
the *shape* of the behaviour, so it works even when the attacker goes slow to
stay hidden.

Real example, from live traffic — an actual alert it produced:

> **Web Reconnaissance & Directory Enumeration** — `203.0.113.199` made 153
> requests to 51 different paths (99 were "not found") in 5 minutes. It asked for
> pages this server has **never served**, arrived with no referrer, using a
> scripted client. *Severity: critical.*

It hands your analyst the verdict, the reasoning, **and** the raw log lines —
not just a number.

More detectors are on the way (login attacks, scraping, data exfiltration, and
more); each one plugs into the same machinery.

---

## Requirements

- **Python 3.11 or newer.**
- Your web logs in a normalized JSON format. If you use
  [**foss-soc-engine**](../foss-soc-engine/) (the companion log parser) you
  already have this — it writes exactly the format foss-soc-ml reads. Any shipper
  that produces the same JSON (Filebeat, Vector, Logstash, or your own script)
  works too.
- **Nothing else.** No Kafka, no database, no cloud service. It runs on a laptop.

---

## Install

```bash
git clone <this-repo>
cd foss-soc-ml
python3 -m venv .venv
.venv/bin/pip install -e .
```

Now the `soc-ml` command is available:

```bash
.venv/bin/soc-ml --help
```

*(Tip: run `source .venv/bin/activate` once and you can just type `soc-ml`.)*

---

## Use it in 5 steps

Point it at the folder where your parser writes logs (the examples use
`/var/log/soc_output/` — change it to yours).

```bash
# 1. Check your logs are in the right format
soc-ml validate --input /var/log/soc_output/ --limit 200000

# 2. Learn what's normal, from your own history
soc-ml train --input /var/log/soc_output/ --limit 2000000

# 3. See what it learned, then turn it on
soc-ml status
soc-ml promote

# 4. Watch quietly first (records alerts, delivers none)
soc-ml run --input /var/log/soc_output/ --mode shadow

# 5. Go live (delivers alerts)
soc-ml run --input /var/log/soc_output/ --mode live
```

Alerts are written to `data/alerts/web_recon.ndjson` — one JSON alert per line,
ready for any SIEM.

**No historical logs to learn from?** Let it learn from live traffic first:

```bash
soc-ml run --input /var/log/soc_output/ --mode shadow --allow-cold-start
```

**Just want to see it work right now, without deploying anything?** Run a
backtest over any folder of logs — it trains, scores, and shows you the results
in one command:

```bash
soc-ml backtest --input /var/log/soc_output/ --limit 300000
```

Full production walkthrough (staged rollout, running as a service, keeping it
fresh): **[DEPLOYMENT.md](DEPLOYMENT.md)**.

---

## The commands

| Command | What it does |
|---|---|
| `soc-ml validate` | Check your logs are in the right format (and healthy) |
| `soc-ml backtest` | Train + score over historical logs and show the results — the quickest way to try it |
| `soc-ml train` | Learn a model from historical logs and save it |
| `soc-ml promote` | Turn a trained model on (or `--rollback` to undo) |
| `soc-ml run` | The live service — watch traffic and alert |
| `soc-ml status` | Show what's trained, what's serving, and live health |
| `soc-ml sessions` | Summarize visitor behaviour in your logs |
| `soc-ml lint-config` | Check your config file is valid |

Every command has `--help`.

---

## How it works (the short version)

```
   your web logs
        │
   ┌────▼─────────────────────────────────────────────────┐
   │ 1. LEARN    build a picture of your site's normal:     │
   │             which pages are common, which visitors are │
   │             typical, what file types you actually serve│
   ├────────────────────────────────────────────────────── │
   │ 2. WATCH    group live traffic into 5-minute windows   │
   │             per visitor and turn each into numbers      │
   ├─────────────────────────────────────────────────────── │
   │ 3. SCORE    two ML models rate how unusual each window  │
   │             is, compared to what was learned            │
   ├─────────────────────────────────────────────────────── │
   │ 4. DECIDE   only genuinely unusual + backed by enough   │
   │             evidence becomes an alert                   │
   ├─────────────────────────────────────────────────────── │
   │ 5. EXPLAIN  each alert says why, in plain language,     │
   │             with the raw log lines attached             │
   └───────────────────────────────────────────────────────┘
```

It also **keeps itself current**: it watches for your traffic patterns drifting
over time and tells you when to retrain, so the model never goes stale. And it
**won't flood you** — repeated activity from one attacker becomes one alert, and
there's a daily cap so a noisy day can never bury your queue.

Want the full design? See **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**.

---

## Project layout

```
foss-soc-ml/
├── src/soc_ml/       the framework (one folder per job: ingest, features,
│                     models, detection, alerting, ...)
├── config/           settings — what to turn on, not thresholds
├── data/             what it learns (models, alerts) — stays on your machine
├── tests/            automated tests
├── docs/             design and reference documentation
├── DEPLOYMENT.md     production deployment guide
└── deploy/           systemd service file
```

## Documentation

| Document | For |
|---|---|
| [DEPLOYMENT.md](DEPLOYMENT.md) | Deploying it for real, step by step |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | How it's built and why |
| [docs/SPEC_DIGEST.md](docs/SPEC_DIGEST.md) | The full detection specification |
| [docs/NAMING.md](docs/NAMING.md) | Naming conventions (for contributors) |
| [docs/DEVELOPING.md](docs/DEVELOPING.md) | Working on the codebase |
| [docs/ROADMAP.md](docs/ROADMAP.md) | What's built and what's next |

---

## Honest about limitations

A security tool that oversells itself wastes your trust, so:

- **It needs a couple of weeks to learn** a new environment before it's fully
  trustworthy — it ships in a "watch only" mode and earns its way to alerting.
- **It sees traffic patterns, not payloads** — no request bodies or TLS details,
  so it detects attacks by behaviour, not by signature.
- **One detector alone can be chatty** until more detectors (which suppress each
  other's false alarms) are added — the daily cap keeps that manageable meanwhile.

## Status

Early but real: the `web_recon` detector is deployable end to end. Expect more
detectors and refinements. Feedback and contributions welcome.

## Licence

Apache-2.0 — see [LICENSE](LICENSE). Use it, change it, ship it, commercially or
not.
