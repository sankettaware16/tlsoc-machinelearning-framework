#!/bin/bash
# Restart the soc-ml runtime if it is not running — for hosts without root,
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

if pgrep -f "soc-ml run --uc ${USECASES} " >/dev/null; then
    exit 0
fi

echo "[watchdog] $(date -Is) runtime not running; restarting" >> "$LOG"
PYTHONUNBUFFERED=1 setsid nohup .venv/bin/soc-ml run --uc "$USECASES" \
    --input "$INPUT" --mode "$MODE" --daily-budget "$BUDGET" \
    >> "$LOG" 2>&1 < /dev/null &
