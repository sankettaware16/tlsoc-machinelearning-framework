#!/bin/bash
# Restart the soc-ml runtime (and the operator console) if not running — for hosts without root,
# where the systemd unit (Restart=on-failure) cannot be installed.
#
# Install from cron (user crontab, no sudo):
#   */5 * * * * $HOME/tlsoc-machinelearning-framework/deploy/soc-ml-watchdog.sh
#
# Every restart is written to runtime.log: a crash that the watchdog quietly
# papers over is still a crash, and the operator must be able to count them.
set -u
cd "$(dirname "$0")/.." || exit 1

USECASES="${SOC_ML_USECASES:-bot_detection,web_recon}"
INPUT="${SOC_ML_INPUT:-/var/log/soc_output/nginx.json}"
MODE="${SOC_ML_MODE:-live}"
BUDGET="${SOC_ML_DAILY_BUDGET:-3}"
LOG=data/state/runtime.log

UI_PORT="${SOC_ML_UI_PORT:-8888}"   # empty disables the dashboard check

# A site config (gitignored) wins over the defaults: verify domains, SIEM, modes.
if [ -z "${SOC_ML_CONFIG:-}" ] && [ -f config/site.local.yaml ]; then
    export SOC_ML_CONFIG=config/site.local.yaml
fi

if ! pgrep -f "soc-ml run --uc ${USECASES} " >/dev/null; then
    echo "[watchdog] $(date -Is) runtime not running; restarting" >> "$LOG"
    PYTHONUNBUFFERED=1 setsid nohup .venv/bin/soc-ml run --uc "$USECASES" \
        --input "$INPUT" --mode "$MODE" --daily-budget "$BUDGET" \
        >> "$LOG" 2>&1 < /dev/null &
fi

# The operator console is loopback-only and has no supervisor of its own;
# after a reboot it would stay down until someone noticed.
if [ -n "$UI_PORT" ] && ! pgrep -f "soc-ml ui " >/dev/null; then
    echo "[watchdog] $(date -Is) console not running; restarting" >> "$LOG"
    setsid nohup .venv/bin/soc-ml ui --out data --host 127.0.0.1 --port "$UI_PORT" \
        >> data/state/ui.log 2>&1 < /dev/null &
fi

# The SIEM shipper runs once the site config names a key file that exists.
if [ -n "${SOC_ML_CONFIG:-}" ] && grep -q "^ *api_key_file:" "$SOC_ML_CONFIG" \
        && ! pgrep -f "soc-ml ship " >/dev/null; then
    KEY=$(sed -n 's/^ *api_key_file: *"\{0,1\}\([^"]*\)"\{0,1\}.*/\1/p' "$SOC_ML_CONFIG" | head -1)
    KEY="${KEY/#\~/$HOME}"
    if [ -f "$KEY" ]; then
        echo "[watchdog] $(date -Is) siem shipper not running; restarting" >> "$LOG"
        setsid nohup .venv/bin/soc-ml ship --out data >> data/state/siem.log 2>&1 < /dev/null &
    fi
fi
