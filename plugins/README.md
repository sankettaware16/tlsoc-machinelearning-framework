# Drop-in plugins

Anything you put under `plugins/<kind>/` is imported at startup and registers
itself. **No packaging, no registration file, no core edits.** This is the "copy
a file and it works" path.

```
plugins/
├── usecases/   your detections        (UseCase)
├── features/   your derived numbers   (FeatureGroup)
├── ingest/     your event sources     (Source)
└── sinks/      where results go       (Sink)
```

Models and state stores are pluggable too — drop them in any of these
directories; discovery is by base class, not by folder name. The folders exist to
keep things findable.

For a pip-installable plugin package, publish under the entry-point groups
`soc_ml.usecases`, `soc_ml.features`, `soc_ml.models`, `soc_ml.sources`,
`soc_ml.states`, `soc_ml.sinks` instead. Both paths land in the same registry.

## Minimal example

`plugins/sinks/slack.py`:

```python
from soc_ml.core import Sink, Alert

class SlackSink(Sink):
    name = "slack"                       # the config key; must be unique
    description = "post alerts to Slack"

    def emit_alert(self, alert: Alert) -> None:
        ...
```

Then in `config/default.yaml`:

```yaml
sinks: ["file", "slack"]
```

Check it was found:

```bash
soc-ml plugins
```

## Writing a use case

Use the `add-usecase` skill — it walks the whole process. The short version:

```python
from soc_ml.core import UseCase, Score, FeatureVector, Model, RunMode

class MyDetection(UseCase):
    name = "UC-LOCAL-01"
    usecase_id = "UC-LOCAL-01"
    tier = 2
    requires = (("path", "5m"), ("status", "5m"), ("identity", "30m"))
    model_name = "iforest"
    default_mode = RunMode.SHADOW      # earn your way to live

    def score(self, fv: FeatureVector, model: Model) -> Score | None:
        x = fv.subset([n for n, _ in self.requires])
        ...

    def gate(self, score: Score, context: dict) -> bool:
        pct = score.require_calibrated()   # never compare score.raw
        ...
```

## The rules that will get your plugin rejected

These are enforced by CI and by the `spec-auditor` agent, not by convention:

1. **No literal detection threshold in config or code.** Any number compared
   against observed traffic comes from the learned Environment Profile. If your
   plugin needs "alert above N", you are building the thing this framework
   exists to replace.
2. **Never compare raw scores.** Use `score.require_calibrated()`. A raw score
   means nothing across servers.
3. **Never read `event.original`** (it is human evidence) **or `observer.*`**
   (namespace keys). Using them as features teaches a model that a *server* is
   suspicious instead of teaching it what suspicious behaviour looks like.
4. **Two-level gating and an evidence floor.** A single event must never alert
   alone. Decide the minimum volume below which you refuse to judge, and enforce
   it in `gate()`.
5. **Declare dependencies, don't recompute.** If a feature group already
   produces what you need, require it.
6. **Fail loudly.** A missing optional dependency should disable your plugin with
   a clear message, never crash the engine and never silently do nothing.

## Testing yours

```bash
soc-ml validate --input /path/to/logs      # contract still satisfied?
soc-ml plugins                             # discovered?
soc-ml backtest --input /path/to/logs --uc UC-LOCAL-01
```

Start in `shadow` mode against real traffic before going `live`. The framework
is built on the assumption that detections earn trust rather than assume it.
