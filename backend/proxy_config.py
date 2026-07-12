"""Proxy configuration helpers.

This module manages loading and saving proxy definitions from a YAML file
mounted at `PROXIES_PATH`. It provides a small compatibility helper to
resolve inline proxy configs from session configuration structures.
"""

import asyncio
import logging
import threading
import time
from typing import Any

import yaml

from backend.paths import PROXIES_PATH

_LOCK = threading.Lock()
_logger: logging.Logger = logging.getLogger(__name__)
_last_resolve_log_time: dict[str, float] = {}
# Minimum seconds between identical resolve debug logs per proxy label/key
_resolve_log_min_interval = 60


def _rate_limited_debug(log_key: str, msg: str, *args: Any) -> None:
    """Emit `msg` at debug level for `log_key` at most once per `_resolve_log_min_interval` seconds."""
    now = time.monotonic()
    if now - _last_resolve_log_time.get(log_key, 0.0) >= _resolve_log_min_interval:
        _logger.debug(msg, *args)
        _last_resolve_log_time[log_key] = now


async def resolve_proxy_from_session_cfg(cfg: dict[str, Any]) -> dict[str, Any] | None:
    """Given a session config dict, return the full proxy config dict (from proxies.yaml) if a label is set,
    or the inline proxy config if present (for backward compatibility).
    Returns None if no proxy is set.
    """

    proxy = cfg.get("proxy", {})
    if not isinstance(proxy, dict):
        return None
    if proxy.get("label"):
        input_key = f"label:{proxy['label']}"
    elif proxy.get("host"):
        input_key = f"inline:{proxy['host']}"
    else:
        input_key = "no_proxy"
    _rate_limited_debug(input_key, "[resolve_proxy_from_session_cfg] Input cfg proxy: %s", proxy)
    if proxy.get("label"):
        label = proxy["label"]
        resolved = (await load_proxies()).get(label)
        _rate_limited_debug(
            f"label_lookup:{label}",
            "[resolve_proxy_from_session_cfg] Looking up label '%s' in proxies.yaml. Resolved: %s",
            label,
            resolved,
        )
        return resolved
    # fallback: legacy inline proxy config
    if proxy.get("host"):
        _rate_limited_debug(
            f"inline_use:{proxy['host']}",
            "[resolve_proxy_from_session_cfg] Using inline proxy config: %s",
            proxy,
        )
        return proxy
    _rate_limited_debug(
        "no_proxy_result", "[resolve_proxy_from_session_cfg] No proxy config found."
    )
    return None


async def load_proxies() -> dict[str, Any]:
    """Load proxies from PROXIES_PATH (I/O offloaded to a worker thread)."""
    return await asyncio.to_thread(_load_proxies)


def _load_proxies() -> dict[str, Any]:
    """Load proxies from PROXIES_PATH.

    Returns a dict parsed from YAML or an empty dict if the file does not
    exist or is empty. The _LOCK is used to synchronize file access.
    """
    try:
        with _LOCK, PROXIES_PATH.open(encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}
    except yaml.YAMLError as e:
        _logger.warning("[load_proxies] Malformed YAML at %s: %s", PROXIES_PATH, e)
        return {}


async def save_proxies(proxies: dict[str, Any]) -> None:
    """Persist the given proxies mapping to PROXIES_PATH (I/O offloaded)."""
    await asyncio.to_thread(_save_proxies, proxies)


def _save_proxies(proxies: dict[str, Any]) -> None:
    """Persist the given proxies mapping to PROXIES_PATH as YAML.

    Ensures the parent directory exists before attempting to write. Uses
    the _LOCK to synchronize concurrent access.
    """
    PROXIES_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _LOCK, PROXIES_PATH.open("w", encoding="utf-8") as f:
        yaml.safe_dump(proxies, f)
