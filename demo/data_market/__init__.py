"""Shared helpers for data market demo components."""

from pathlib import Path


def default_data_dir() -> Path:
    """
    Return the directory used to store demo artifacts (db files, MQ files).
    The folder is created lazily under python-sdk/demo/.data_market_runtime.
    """
    base = Path(__file__).resolve().parent / ".data_market_runtime"
    base.mkdir(parents=True, exist_ok=True)
    return base
