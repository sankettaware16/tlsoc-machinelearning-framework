# Naming Standard

One canonical name per thing, one casing rule per kind of thing, enforced by
tests (`tests/test_naming.py`). This exists because "UC-02" means nothing to an
analyst at 3 a.m. and inconsistent names mean merge conflicts between
collaborators. Follow it for **all** development.

---

## 1. Use cases — the triple identity

Every detection (UC-nn) and analytics (AU-nn) case has exactly three names, each
with one job:

| Field | Example | Rule | Used in |
|---|---|---|---|
| **slug** (canonical) | `web_recon` | `snake_case`, 2–3 words, stable forever | module name, class registry key, config key, CLI arg, alert `usecase` field, model/artifact paths, metrics |
| **spec ID** | `UC-02` | fixed by SPEC_DIGEST, never re-numbered | `rule.id` in alerts, spec cross-reference, docs |
| **title** | `Web Reconnaissance & Directory Enumeration` | human sentence-case | `rule.name` in alerts, dashboards, reports |

**The slug is what code and operators use.** The spec ID is a cross-reference,
not an interface. Never invent a fourth name.

### The catalog (canonical slugs — do not improvise new ones)

| Spec ID | slug | title |
|---|---|---|
| UC-01 | `credential_stuffing` | Credential Stuffing & Password Spraying |
| UC-02 | `web_recon` | Web Reconnaissance & Directory Enumeration |
| UC-03 | `distributed_scan` | Low-and-Slow & Distributed Scanning |
| UC-04 | `bot_detection` | Bot & Abnormal Crawler Detection |
| UC-05 | `ua_spoofing` | User-Agent Spoofing & Anomalies |
| UC-06 | `content_scraping` | Web Scraping & Content Harvesting |
| UC-07 | `http_exfiltration` | Data Exfiltration via HTTP Responses |
| UC-08 | `beaconing` | Beaconing & Periodic Automation |
| UC-09 | `injection_probing` | Injection Probing & URL Grammar Anomalies |
| UC-10 | `status_sequences` | Response-Code Sequence Anomalies |
| UC-11 | `session_abuse` | Session Abuse & Token Replay |
| UC-12 | `campaign_clustering` | Distributed Campaign Clustering |
| UC-13 | `attack_chain` | Attack-Chain Progression |
| UC-14 | `novel_behavior` | Novel-Behavior Ensemble |
| UC-15 | `app_abuse` | Application Abuse (Living-off-the-App) |
| AU-01 | `traffic_baselines` | Traffic Baselines & Forecasts |
| AU-02 | `seasonal_patterns` | Seasonal Pattern Decomposition |
| AU-03 | `geo_drift` | Geo-Distribution Drift |
| AU-04 | `client_population` | Client Population Evolution |
| AU-05 | `resource_popularity` | Resource Popularity Drift |
| AU-06 | `capacity_forecast` | Capacity & Egress Forecasting |
| AU-07 | `endpoint_roles` | Endpoint Role Map & Usage Drift |
| AU-08 | `client_segments` | Client Behavior Segmentation |
| AU-09 | `org_trends` | Org-Unit Trends |
| AU-10 | `shadow_content` | Rare & Shadow Content Emergence |
| AU-11 | `ops_health` | Operational Anomaly & Service Health |
| AU-12 | `exec_digest` | Executive KPI Digest |

### Where each appears

```
module   src/soc_ml/usecases/web_recon.py        (= slug)
class    class WebRecon(UseCase)                  (PascalCase of slug)
           name       = "web_recon"               (Plugin registry key = slug)
           usecase_id = "UC-02"
           title      = "Web Reconnaissance & Directory Enumeration"
config   usecases: { web_recon: {...} }           # UC-02 in a comment
CLI      soc-ml backtest --uc web_recon           (accepts - or _)
alert    {"usecase": "web_recon",
          "rule": {"id": "UC-02", "name": "Web Reconnaissance & …"}}
models   data/models/web_recon/<version>/
tests    tests/test_web_recon_usecase.py
```

---

## 2. Everything else

| Thing | Rule | Example |
|---|---|---|
| Python modules / packages | `snake_case`, singular purpose | `window_features.py` |
| Classes | `PascalCase`; plugin classes named after their slug | `IsolationForestModel` |
| Functions / variables | `snake_case`; no abbreviations that save <3 chars | `ratio_404`, not `r404` |
| Plugin names (`Plugin.name`) | `snake_case` slug, globally unique per kind | `isolation_forest`, `file`, `sqlite` |
| **Feature names** | `<group>.<feature>` — both snake_case. The window is a property of the vector, not part of the name | `web.ratio_404`, `timing.interarrival_cv`, `ua.rarity` |
| Config keys | `snake_case`; policy only (FR-62) | `daily_alert_budget` |
| CLI commands / flags | `kebab-case` | `lint-config`, `--train-frac` |
| Test files | `test_<module or slug>_<aspect>.py`; test functions state behavior | `test_gate_holds_below_evidence_floor` |
| Model artifact dirs | `data/models/<slug>/<version>/` | `data/models/web_recon/v20260727T1200/` |
| Metrics / stats keys | `snake_case` | `windows_scored`, `alerts_emitted` |
| Requirement / decision IDs | `FR-nn`, `NFR-nn`, `D-nnn`, `OQ-nn` — never re-used | `FR-62` |
| Docs | `SCREAMING_SNAKE.md` for project docs | `SPEC_DIGEST.md` |

### Hard rules

1. **One canonical slug per concept, everywhere.** If the module is
   `web_recon.py`, the config key is `web_recon` and the CLI arg is
   `web_recon`/`web-recon` — never `recon`, `webrecon`, or `uc02`.
2. **Slugs are immutable after first release.** Renaming a slug breaks configs,
   dashboards, and saved models. Getting it right up front is why this file
   exists.
3. **Spec IDs are metadata.** No new code paths keyed on `UC-nn`.
4. **Feature names are analyst-facing** (they appear in alert explanations).
   `web.unknown_ext_ratio` reads; `f7` does not.
5. Naming compliance is CI-tested — a use case with a malformed slug, missing
   title, or module/slug mismatch fails `tests/test_naming.py`.
