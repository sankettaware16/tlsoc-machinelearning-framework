"""Backtest harness, canary injection, metrics."""

from .backtest import run_backtest
from .canary import CANARY_IP, CANARY_UA, canary_events

__all__ = ["run_backtest", "canary_events", "CANARY_IP", "CANARY_UA"]
