# Research Notes — how enterprise ML detection actually works

External research backing the design decisions, with sources. This exists so that
choices in `ARCHITECTURE.md` can be checked against industry practice rather than
taken on faith, and so future sessions don't re-run the same searches.

Last reviewed: 2026-07-21.

---

## 1. The MLOps reference architecture

Industry consensus on the building blocks of a production ML system is
remarkably stable across vendors: **data estate → feature pipelines → training
environment → model registry → CI/CD/CT → serving layer → monitoring &
observability → governance.**

Our module map is a direct instance of this: `ingest`+`preprocess` (data),
`features`+`state` (feature pipelines), `training` (training env), `registry`
(registry + governance), `detection`+`fusion` (serving), `drift`+health
(monitoring).

**What this validates:** separating the registry from the trainer, and treating
governance as a first-class stage rather than a manual step.

Sources: [MLOps Architecture: End-to-End Design for Production-Grade ML](https://dev.to/apprecode/mlops-architecture-end-to-end-design-for-production-grade-ml-and-llm-systems-425g) ·
[MLOps workflows on Databricks](https://docs.databricks.com/aws/en/machine-learning/mlops/mlops-workflow) ·
[MLOps Pipeline Automation Best Practices in 2026 (MLflow)](https://mlflow.org/articles/mlops-pipeline-automation-best-practices-in-2026/)

---

## 2. Model registry — "nothing unversioned may serve"

Standard practice: every retraining run registers an artifact under an
**immutable version ID**, and the registry logs the inputs that produced it —
the **data snapshot ID, hyperparameters, and the source-code commit SHA**.

This is exactly the spec's requirement (SPEC_DIGEST §8) and it is why FR-53
demands the *feature-code git SHA* specifically: a model is only reproducible if
you know which feature code computed its inputs. Feature-code drift is the
classic silent breaker — the model artifact is fine, but the features feeding it
changed meaning.

**Design consequence:** `registry/` stores metadata alongside the artifact, and
an alert records model versions (FR-44) so any alert is reconstructable from
*config + replay + registry* (NFR-10).

Source: [Advanced MLOps Architecture for Model/Feature Drift Detection](https://www.devopsroles.com/mlops-model-feature-drift-detection/)

---

## 3. Champion–challenger and the governance gate

The pattern our spec calls "significant change → human approval" is the
industry's **champion–challenger**: the champion serves production; a challenger
is trained and evaluated on the same holdout; if it wins by a meaningful margin
it is promoted.

The mature form adds gates in sequence:

> candidate trained and registered → evaluated against the incumbent on held-out
> and challenge sets (**eval gate**) → reviewed and approved (**governance gate,
> enterprise-mandatory**) → deployed by **canary or shadow**.

Two refinements worth stealing, both already in the spec:

- **Shadow before canary.** The challenger scores live traffic without acting.
  Our spec's ≥72 h soak is this, and it is stronger than a holdout because it
  tests on the true live distribution.
- **Automated rollback** with the previous champion kept warm. Our spec keeps
  **3 versions hot** (FR-54).

**Design consequence:** promotion is not a score comparison. It is four gates —
no SAIF regression, KS p>0.01 on benign traffic, alert volume within ±20%, and
human sign-off for Tier-1 (FR-55). The **alert-volume gate is the unusual one**
and it is the most valuable for a SOC: a challenger that is 2% more accurate but
triples alert volume is a regression, and a pure-accuracy gate would promote it.

Sources: [Automated Model Retraining & Deployment (Snowflake)](https://www.snowflake.com/en/developers/guides/ml-champion-challenger-model-deployment/) ·
[Deployment Evaluation Strategies in MLOps](https://medium.com/@fraidoonomarzai99/deployment-evaluation-strategies-in-mlops-c208585aa3bd) ·
[MLOps Architecture: Diagrams, Reference Patterns, and Scaling](https://apprecode.com/blog/mlops-architecture-mlops-diagrams-and-best-practices)

---

## 4. Streaming / online learning and concept drift

The core problem for a detector that must "never become outdated": batch models
have **high maintenance cost and adapt poorly to changing behavior**, while
streaming learning integrates online and incremental learning with drift
detection to stay robust.

**River** is the reference Python library for online ML on streaming data and
ships drift detectors directly. It is the spec's choice for Half-Space Trees
(UC-01), and it is what makes the "continuous" rung of the cadence ladder
practical — O(1) per event, no retraining pause.

Empirical signal worth noting: a 2025 study on streaming IoT traffic anomaly
detection under concept drift reported a **Hoeffding Adaptive Tree at
F1 0.910 ± 0.007 while reducing computational cost fourfold** versus the
alternatives — i.e. adaptive streaming models are not a quality compromise made
for speed.

**Design consequence:** the cadence ladder is not a hierarchy of "real" (batch)
and "approximate" (online) models. The continuous rung carries genuine detection
weight (UC-01 Layer A, BOCPD onset, EWMA/CUSUM control limits), and the batch
rungs handle what genuinely needs a corpus (autoencoders, GMMs, clustering).

Sources: [River: machine learning for streaming data in Python (JMLR)](https://jmlr.csail.mit.edu/papers/volume22/20-1380/20-1380.pdf) ·
[Binary Anomaly Detection in Streaming IoT Traffic under Concept Drift (2025)](https://arxiv.org/abs/2510.27304) ·
[PWPAE: Concept Drift Detection and Adaptation (IEEE GlobeCom)](https://github.com/Western-OC2-Lab/PWPAE-Concept-Drift-Detection-and-Adaptation) ·
[Autoencoder-based Anomaly Detection in Streaming Data with Incremental Learning and Concept Drift Adaptation](https://arxiv.org/pdf/2305.08977)

---

## 5. Drift detection methods

Two families, and the design needs both because they answer different questions:

| Family | Method | Answers |
|---|---|---|
| **Distribution drift** (inputs) | **PSI** per feature; **KS** test | "Has the world changed?" |
| **Score/concept drift** (outputs) | **ADWIN** on score streams; CUSUM/EWMA | "Has my model's behavior changed?" |

`Frouros` and River both provide these as libraries; the spec names PSI, KS, and
ADWIN explicitly, which maps cleanly onto available implementations.

The subtlety the spec gets right: **drift triggers retraining, it does not
*replace* the schedule.** A drift-only policy never retrains during a stable
period and then retrains everything at once during a migration. A
schedule-plus-trigger policy keeps models fresh and reacts to shocks.

Also worth carrying: cost-awareness. Recent work frames retraining as a decision
that **balances performance improvement against computational cost** rather than
an automatic response to any detected shift — relevant because our weekly rung
retrains autoencoders and VAEs.

Sources: [Frouros: A Python library for drift detection](https://arxiv.org/pdf/2208.06868) ·
[A Multi-Criteria Automated MLOps Pipeline for Cost-Effective Retraining under Data Distribution Shifts](https://arxiv.org/pdf/2512.11541) ·
[concept-drift (GitHub topic)](https://github.com/topics/concept-drift)

---

## 6. Where our spec goes beyond generic MLOps

Generic MLOps guidance assumes a **supervised** model with labels and a business
metric. Security anomaly detection breaks three of those assumptions, and the
spec's answers are the interesting part of the design:

| Generic assumption | Reality here | Spec's answer |
|---|---|---|
| Labels exist | Production logs have no attack labels | Unsupervised primary detectors; self-supervised where labels come free (`declared_bot`, benign IP-hop pairs); **synthetic labels for evaluation only, never training** |
| Accuracy is the metric | Attacks are rare; ROC-AUC flatters badly | **PR-AUC as the gated metric**, plus FP/day/server and analyst-verdict precision |
| The model output is the product | A raw score is useless to an analyst | Mandatory explainability: attributions + population context + verbatim evidence |
| Retraining data is trustworthy | An attacker can poison the next corpus | **Corpus hygiene**: exclude top 0.1% anomalous windows, clip at p99.9, permanently quarantine confirmed-incident windows |
| One model, one decision | A single detector fires constantly | **Fusion**: corroboration, fleet-simultaneity suppression, campaign folding, rate budgets |

The **poisoning-resistance** point deserves emphasis: a continuously-retraining
detector that learns from live traffic will happily learn an attacker's slow
ramp as normal. Excluding the most anomalous windows from the next corpus is the
cheapest effective defense, and it is the kind of thing that is nearly impossible
to retrofit — the trainer has to enforce it from the start (FR-56).

---

## 7. Practices adopted, and things consciously rejected

**Adopted:** registry with immutable versions + code SHA · shadow-then-promote ·
alert-volume regression as a promotion gate · schedule + drift triggers ·
online learning for the continuous rung · PSI/KS/ADWIN · PR-AUC as primary ·
graceful degradation on missing optional dependencies.

**Rejected, with reasons:**

- **Feature store as a service** (Feast/Tecton). Real value at multi-team scale;
  here it would add a dependency for a benefit our `state/` module already
  provides, and it breaks the zero-infra default.
- **Kubeflow/Airflow for orchestration.** The cadence ladder is five scheduled
  jobs. A scheduler inside the process, with cron as the escape hatch, is
  proportionate. Revisit at the `enterprise` profile.
- **Auto-promotion on metric win.** Standard in MLOps, wrong for Tier-1 security
  detection — hence the mandatory human gate.
- **LLM-generated alert narratives.** The spec explicitly chooses deterministic
  templates for AU-12 for auditability. An alert that must stand up in an
  incident review cannot have non-reproducible prose.
- **Deep models as the default tier.** Cheap tiers first (4-gram LM before
  conv-AE), keeping PyTorch an extra.

---

## 8. Still to research

- Practical HLL/MinHash sizing at our entity cardinality (`datasketch` tuning).
- Lomb-Scargle parameter selection for beaconing detection on sparse series
  (UC-08) — the spec mandates it over FFT for uneven sampling but doesn't tune it.
- Calibration under low traffic: percentile estimates on a small server are noisy,
  which is exactly where the spec's fleet-level fallback should engage.
- Whether ADWIN on score streams gives usable signal at Tier-3 alert volumes.
