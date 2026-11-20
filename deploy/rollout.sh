#!/bin/bash
# Roll the soc-ml runtime forward to a named commit, unattended: pull, prove
# the build imports, stop the running process with TERM and start the new one
# with the launch command — the restart the operator otherwise does by hand.
#
# Run once from cron (user crontab, no sudo), a couple of minutes after a
# watchdog tick so the wait in step 5 is short. The pull runs inside the same
# redirect as the script, so a pull that fails before it still leaves a trace:
#   2 0 24 11 * [ "$(date +\%Y)" = 2026 ] && cd $HOME/tlsoc-machinelearning-framework && { date -Is; git pull --ff-only; deploy/rollout.sh <commit>; } >> data/state/rollout.log 2>&1
# The year guard is why the line fires once: "2 0 24 11 *" alone fires every
# year. Delete the line after it has run. In a crontab a literal % must be
# written \% (a bare % ends the command and starts its stdin), hence date +\%Y.
# Rehearse first; this pulls and smokes but kills and launches nothing:
#   deploy/rollout.sh <commit> --dry-run
#
# Safe to re-run: when HEAD already is the commit and the runtime started after
# the code last moved, it says so and exits 0.
#
# Exit codes: 0 done or nothing to do; 1 usage, or another rollout holds the
# lock; 2 git did not land on the commit (nothing is reset or checked out);
# 3 the build does not import (the running process stays); 4 the old runtime
# did not exit on TERM, more than one matched, or the watchdog's own test finds
# a process the pattern did not — nothing gets KILL, nothing is launched beside
# it, the operator decides; 5 the new runtime did not come up clean (the
# watchdog keeps the host alive; read data/state/runtime.log).
#
# Env: ROLLOUT_PGREP (pattern that finds the runtime), ROLLOUT_NO_WAIT=1 (skip
# the minute%5 wait), ROLLOUT_DRAIN_S (90), ROLLOUT_VERIFY_S (120),
# ROLLOUT_SETTLE_S (15), ROLLOUT_LAUNCH (the whole launch command, trailing &
# included, run with eval), SOC_ML_USECASES/SOC_ML_INPUT/SOC_ML_DAILY_BUDGET as
# the watchdog takes them.
#
# Why each step is what it is (prod, Oct-Nov 2026):
# - the runtime to stop is found by its interpreter path, never by the words
#   "soc-ml run": a shell whose own command line carries those words matches
#   itself, and the kill then took the SSH session instead of the runtime
#   (8, 10 and 26 Oct).
# - before anything is launched the watchdog's own test (those words, which
#   this script's argv never carries) must find nothing but the pid being
#   replaced: a runtime started in another form — "python" for "python3",
#   another path — is invisible to the anchored pattern but alive to the
#   watchdog, and the launch would have made a twin (review, Nov 2026).
# - the stop waits for minute%5==1, just after the watchdog's tick: a tick
#   between TERM and launch starts a second runtime and writes "runtime not
#   running", which every measurement's H4 counts as a crash (26 Oct).
# - TERM, never KILL: TERM drains the windows and writes the checkpoint that
#   carries the read offset, the daily budget and the open cooldowns.
# - setsid: the runtime handles TERM and INT but not HUP; without it the
#   launching session's teardown took the process with it.
# - the watchdog is never run by hand: its restart line is a counted crash.
set -u
cd "$(dirname "$0")/.." || exit 1
REPO=$(pwd -P)

log() { echo "[rollout] $(date -Is) $*"; }
# ps prints nothing for a pid that is gone; a zombie is not alive either.
alive() { ps -o stat= -p "$1" 2>/dev/null | grep -qv '^ *Z'; }
tracebacks_since() { tail -n +"$(($1 + 1))" "$LOG" 2>/dev/null | grep -c '^Traceback'; }
restarts_since() { tail -n +"$(($1 + 1))" "$LOG" 2>/dev/null | grep -c 'runtime not running'; }
# Pids the watchdog's test finds other than $1, space separated; empty if none.
strays_besides() {
    local s
    s=$(pgrep -f "$WD_PATTERN" | grep -vx "${1:-0}" | tr '\n' ' ')
    printf '%s' "${s% }"
}

TARGET="${1:-}"
TARGET="${TARGET,,}"
DRY=""
case "${2:-}" in
    "") ;;
    --dry-run) DRY=1 ;;
    *) echo "usage: $0 <commit> [--dry-run]" >&2; exit 1 ;;
esac
# Seven is git's own floor for an abbreviation; one character names anything.
case "$TARGET" in
    "" | *[!0-9a-f]*) echo "usage: $0 <commit> [--dry-run]  (commit is a hex prefix, 7 chars or more)" >&2; exit 1 ;;
esac
if [ "${#TARGET}" -lt 7 ]; then
    echo "usage: $0 <commit> [--dry-run]  (commit is a hex prefix, 7 chars or more)" >&2; exit 1
fi

# A site config (gitignored) wins over the defaults: verify domains, SIEM, modes.
if [ -z "${SOC_ML_CONFIG:-}" ] && [ -f config/site.local.yaml ]; then
    export SOC_ML_CONFIG=config/site.local.yaml
fi

USECASES="${SOC_ML_USECASES:-bot_detection,web_recon}"
INPUT="${SOC_ML_INPUT:-/var/log/soc_output/nginx*.json}"  # every parser worker's file
BUDGET="${SOC_ML_DAILY_BUDGET:-3}"
LOG=data/state/runtime.log
PATTERN="${ROLLOUT_PGREP:-^$REPO/.venv/bin/python3? .venv/bin/soc-ml run}"
WD_PATTERN="soc-ml run --uc $USECASES "   # the watchdog's test for the runtime, verbatim
DRAIN_S="${ROLLOUT_DRAIN_S:-90}"
VERIFY_S="${ROLLOUT_VERIFY_S:-120}"
SETTLE_S="${ROLLOUT_SETTLE_S:-15}"
# The documented launch command, glob quoted so the runtime merges the worker
# files itself. The env prefix is kept so the line in the log is the one the
# operator would type.
LAUNCH="${ROLLOUT_LAUNCH:-${SOC_ML_CONFIG:+SOC_ML_CONFIG=$SOC_ML_CONFIG }nohup setsid .venv/bin/soc-ml run --uc $USECASES --input \"$INPUT\" --mode live --daily-budget $BUDGET >> $LOG 2>&1 < /dev/null &}"

# Two rollouts at once would TERM the same pid and launch twice.
mkdir -p data/state
exec 9>>data/state/rollout.lock
if ! flock -n 9; then
    log "another rollout holds data/state/rollout.lock; exit 1"
    exit 1
fi

# 1-2. pull, then prove HEAD is the commit asked for.
log "rollout to $TARGET in $REPO, HEAD $(git rev-parse --short HEAD)${DRY:+, dry-run}"
log "git fetch origin"
if ! git fetch origin; then
    log "git fetch failed; nothing restarted; exit 2"
    exit 2
fi
log "git pull --ff-only"
if ! git pull --ff-only; then
    log "git pull --ff-only failed (local commits? resolve by hand, this script never resets); nothing restarted; exit 2"
    exit 2
fi
HEAD=$(git rev-parse HEAD)
# --verify --quiet names one commit or nothing: an unknown prefix and an
# ambiguous one both fail here, and HEAD must then equal it, not start with it.
FULL=$(git rev-parse --verify --quiet "$TARGET^{commit}")
if [ -z "$FULL" ]; then
    log "$TARGET names no single commit here (unknown or ambiguous prefix); nothing restarted; exit 2"
    exit 2
fi
if [ "$HEAD" != "$FULL" ]; then
    log "HEAD $HEAD is not $FULL ($TARGET); nothing restarted; exit 2"
    exit 2
fi
log "HEAD $HEAD is $TARGET"

# 3. A build that cannot import must never replace a running one.
if ! .venv/bin/python -c "import soc_ml.detection.runtime, soc_ml.features.exposure"; then
    log "build $HEAD does not import; the running process stays; exit 3"
    exit 3
fi
log "smoke: soc_ml.detection.runtime and soc_ml.features.exposure import"

# 4. Find the runtime. More than one is a state this script did not make.
mapfile -t PIDS < <(pgrep -f "$PATTERN")
if [ "${#PIDS[@]}" -gt 1 ]; then
    log "${#PIDS[@]} processes match '$PATTERN': ${PIDS[*]}; the operator decides; exit 4"
    exit 4
fi
OLD="${PIDS[0]:-}"
if [ -n "$OLD" ]; then
    ETIMES=$(ps -o etimes= -p "$OLD" 2>/dev/null | tr -d ' ')
    if [ -z "$ETIMES" ]; then
        log "runtime $OLD vanished between pgrep and ps"
        OLD=""
    fi
fi
# Whatever else the watchdog counts as the runtime would get a twin from the
# launch: stop here, before the TERM, so what runs now keeps running.
STRAYS=$(strays_besides "$OLD")
if [ -n "$STRAYS" ]; then
    log "pgrep -f '$WD_PATTERN' finds $STRAYS${OLD:+ besides $OLD}; the watchdog counts that as the runtime; nothing killed, nothing launched; exit 4"
    exit 4
fi
if [ -n "$OLD" ]; then
    STARTED=$(( $(date +%s) - ETIMES ))
    # The HEAD reflog is written each time HEAD moves and never by a pull that
    # had nothing to do, so its mtime is when the code on disk last changed.
    # Whole-second arithmetic: a start within 2 s of that counts as before it,
    # which costs one harmless restart rather than a missed one.
    CODE_AT=$(stat -c %Y "$(git rev-parse --git-path logs/HEAD)" 2>/dev/null || date +%s)
    if [ "$STARTED" -gt $((CODE_AT + 2)) ]; then
        log "runtime $OLD started $(date -Is -d "@$STARTED"), after the code last moved ($(date -Is -d "@$CODE_AT")); already on $HEAD, nothing to do; exit 0"
        exit 0
    fi
    log "runtime $OLD started $(date -Is -d "@$STARTED"), before the code last moved ($(date -Is -d "@$CODE_AT")); will restart"
else
    log "no process matches '$PATTERN'; will start one with the launch command"
fi

if [ -n "$DRY" ]; then
    if [ -n "$OLD" ]; then
        M=$((10#$(date +%M))); S=$((10#$(date +%S)))
        R=$(( (6 - M % 5) % 5 ))
        [ "$R" -gt 0 ] && WAIT=$(( R * 60 - S )) || WAIT=0
        log "dry-run: would wait ${WAIT} s for minute%5==1, then kill -TERM $OLD and wait up to ${DRAIN_S} s"
    fi
    log "dry-run: would launch: $LAUNCH"
    log "dry-run: would verify within ${VERIFY_S} s that a new pid matches '$PATTERN', lives ${SETTLE_S} s, and $LOG gains no Traceback; exit 0"
    exit 0
fi

LOG_LINES=$(wc -l < "$LOG" 2>/dev/null || echo 0)

if [ -n "$OLD" ]; then
    # 5. Just after a watchdog tick, so no tick falls between TERM and launch.
    if [ "${ROLLOUT_NO_WAIT:-0}" = 1 ]; then
        log "ROLLOUT_NO_WAIT=1: not waiting for minute%5==1"
    else
        T0=$(date +%s)
        while [ $((10#$(date +%M) % 5)) -ne 1 ]; do sleep 2; done
        log "waited $(( $(date +%s) - T0 )) s for minute%5==1"
    fi

    # 6. TERM and drain. Still alive after the limit: stop here, old code keeps
    # running, the operator decides.
    echo "[rollout] $(date -Is) stopping $OLD for $HEAD" >> "$LOG"
    log "kill -TERM $OLD"
    kill -TERM "$OLD"
    T0=$(date +%s)
    while alive "$OLD"; do
        if [ $(( $(date +%s) - T0 )) -ge "$DRAIN_S" ]; then
            log "runtime $OLD still alive ${DRAIN_S} s after TERM; no KILL sent, nothing launched, old code keeps running; exit 4"
            exit 4
        fi
        sleep 1
    done
    log "runtime $OLD exited $(( $(date +%s) - T0 )) s after TERM"
fi

# 7. Launch. A runtime that appeared meanwhile (a watchdog tick after the pull)
# already runs the new code; do not start a second one. Anything else the
# watchdog counts as the runtime: launch nothing, the operator decides.
mapfile -t PIDS < <(pgrep -f "$PATTERN")
if [ "${#PIDS[@]}" -gt 0 ]; then
    log "runtime ${PIDS[*]} appeared meanwhile; not launching a second one"
else
    STRAYS=$(strays_besides "$OLD")
    if [ -n "$STRAYS" ]; then
        log "pgrep -f '$WD_PATTERN' finds $STRAYS; the watchdog counts that as the runtime; nothing launched${OLD:+ (runtime $OLD was stopped)}; exit 4"
        exit 4
    fi
    log "launch: $LAUNCH"
    # fd 9 is the lock; a child that inherited it would hold it for good.
    ( exec 9>&-; eval "$LAUNCH" )
fi

# 8. A new pid must match, outlive the settle time, and leave no traceback.
T0=$(date +%s)
NEW=""
while :; do
    NEW=$(pgrep -f "$PATTERN" | grep -vx "${OLD:-0}" | head -1)
    [ -n "$NEW" ] && break
    TB=$(tracebacks_since "$LOG_LINES")
    if [ "$TB" -gt 0 ]; then
        log "FAILED: no runtime and $TB traceback(s) in $LOG since the rollout began; exit 5"
        exit 5
    fi
    if [ $(( $(date +%s) - T0 )) -ge "$VERIFY_S" ]; then
        log "FAILED: no process matched '$PATTERN' within ${VERIFY_S} s; exit 5"
        exit 5
    fi
    sleep 1
done
log "runtime $NEW up $(( $(date +%s) - T0 )) s after launch; settling ${SETTLE_S} s"
sleep "$SETTLE_S"
if ! pgrep -f "$PATTERN" | grep -qx "$NEW"; then
    log "FAILED: runtime $NEW died within ${SETTLE_S} s; exit 5"
    exit 5
fi
TB=$(tracebacks_since "$LOG_LINES")
if [ "$TB" -gt 0 ]; then
    log "FAILED: $TB traceback(s) in $LOG since the rollout began (runtime $NEW is up); exit 5"
    exit 5
fi
echo "[rollout] $(date -Is) started $NEW at $HEAD" >> "$LOG"
log "done: runtime $NEW at $HEAD; $(restarts_since "$LOG_LINES") 'runtime not running' line(s) in $LOG since the rollout began; exit 0"
exit 0
