# Project Brief

## The problem

A SOC watching web application traffic drowns in alerts it cannot trust.

Threshold rules ("alert if >100 req/min", "alert on /admin") are written once
against someone's idea of a normal environment, then quietly rot. They fire on
the marketing team's new crawler, miss the attacker who reads 40 pages an hour,
and need a human to re-tune every time the application changes. The result is a
queue nobody reads and a detection posture nobody can measure.

The failure is structural: **a generic rule cannot know what is normal for
*this* deployment.** A university Moodle site, a hospital portal, and a
e-commerce checkout have nothing in common in their traffic shape — but they get
the same rules.

## What this project is

An open-source, self-learning behavioral analytics framework that sits behind an
existing log parser and learns what normal looks like **for the environment it
is actually deployed in** — then alerts on deviation from that learned normal
rather than from a shipped default.

It consumes ECS-normalized web traffic events (from
[`foss-soc-engine`](../../foss-soc-engine/) or any shipper emitting the same
contract), builds a continuously-updated statistical portrait of the deployment,
and runs 15 behavioral detection use cases and 12 analytics use cases against it.

## Goals

| # | Goal | How it is measured |
|---|---|---|
| G1 | **Environment-specific detection** — zero threshold tuning to deploy | No detector reads a literal threshold from config (CI-enforced); every alert cites the learned baseline it was judged against |
| G2 | **Cut alert volume** without cutting detection | Campaign folding, corroboration, operational rerouting, per-UC daily budgets; **FP ≤ 3/day/server** |
| G3 | **Accuracy** — earn analyst trust | **PR-AUC ≥ 0.85** (Tier-1), precision ≥ 0.80 on a 28-day rolling analyst-verdict window |
| G4 | **Never goes stale** | Cadence ladder + drift triggers (PSI/KS/ADWIN); model aging is detected, not waited out |
| G5 | **Offline before live** | Every component runs over historical data; backtest is the development loop |
| G6 | **Extensible without forking** | Six plugin interfaces; a new use case is a drop-in file, no core edit |
| G7 | **Runs anywhere** | `standalone` profile needs no Kafka, no Redis, no MLflow — scales up to them |
| G8 | **Explainable** | Every alert carries per-feature attributions, population context, and verbatim evidence lines |

## Non-goals

Being explicit here prevents scope creep later.

- **Not a log parser.** `foss-soc-engine` does that. This framework starts from
  normalized ECS JSON.
- **Not a SIEM or a case manager.** It emits ECS alerts that existing SIEM/SOAR
  tooling consumes.
- **Not payload inspection.** Request bodies, response contents, headers, and TLS
  details are not in the input contract. Injection is detected *behaviorally*
  (UC-09), not by signature.
- **Not network-layer defense.** Volumetric DDoS is somebody else's layer.
- **Not a replacement for signatures.** A thin Sigma layer keeps "free precision"
  on known-bad indicators; ML owns behavior.
- **Not supervised threat classification.** Labels don't exist in production
  logs. Primary detectors are unsupervised, always.

## Who it is for

- **SOC analysts** — a queue with fewer, better, self-explaining alerts.
- **Detection engineers** — a place to add a use case without touching the core.
- **Smaller teams and public institutions** — enterprise-grade behavioral
  analytics without an enterprise licence or an enterprise platform team. This is
  the audience the `standalone` profile exists for.

## Constraints that shaped the design

1. **The input contract is fixed** (SPEC_DIGEST §3). No usernames, no bodies, no
   latency. Identity is reconstructed as `(server, IP, UA-hash)` and is
   *approximate* — the design says so out loud rather than pretending otherwise.
2. **Cold start is real** — 2–8 weeks before full confidence. The staged
   observe→live protocol makes that a managed rollout instead of a nasty surprise.
3. **Drift is the normal operating condition** for web traffic, not an exception.
4. **Fully open source** (Apache-2.0, matching the parser) — so no dependency may
   require a commercial licence, and the default path must not assume paid infra.

## Success criteria

The project is working when a new deployment can:

1. Point the framework at a parser output directory and run a **backtest on
   historical logs the same day**, with no infrastructure to install.
2. Reach live Tier-1 alerting in **~4 weeks** through the staged cold-start,
   having tuned **no thresholds**.
3. Hand an analyst an alert that says *"this entity requested 47 unique paths
   this server has never served, at machine-regular intervals; normal p99 here is
   3"* — with the raw log lines attached.
4. Add a 16th use case by dropping one file into `plugins/usecases/`.

## Current status

Design and scaffold complete; no detection logic implemented yet. Build order
follows [`ROADMAP.md`](ROADMAP.md); decisions are logged in
[`JOURNAL.md`](JOURNAL.md).
