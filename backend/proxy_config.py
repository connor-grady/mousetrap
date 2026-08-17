"""Proxy configuration helpers.

This module manages loading and saving proxy definitions from a YAML file
mounted at `PROXIES_PATH`. It provides a small compatibility helper to
resolve inline proxy configs from session configuration structures.
"""

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


def resolve_proxy_from_session_cfg(cfg: dict[str, Any]) -> dict[str, Any] | None:
    """Return the resolved proxy config for a session.

    Looks up the proxy by label in proxies.yaml when a label is set, falls back
    to an inline proxy config for backward compatibility, and returns None when
    no usable proxy is configured.
    """
    if not isinstance(proxy := cfg.get("proxy"), dict):
        return None
    label = proxy.get("label")
    host = proxy.get("host")
    input_key = f"label:{label}" if label else f"inline:{host}" if host else "no_proxy"
    _rate_limited_debug(input_key, "[resolve_proxy_from_session_cfg] Input cfg proxy: %s", proxy)
    if label:
        resolved = load_proxies().get(label)
        _rate_limited_debug(
            f"label_lookup:{label}",
            "[resolve_proxy_from_session_cfg] Looking up label '%s' in proxies.yaml. Resolved: %s",
            label,
            resolved,
        )
        return resolved
    if host:
        _rate_limited_debug(
            f"inline_use:{host}",
            "[resolve_proxy_from_session_cfg] Using inline proxy config: %s",
            proxy,
        )
        return proxy
    _rate_limited_debug("no_proxy_result", "[resolve_proxy_from_session_cfg] No proxy config found.")
    return None


def load_proxies() -> dict[str, Any]:
    """Load proxies from PROXIES_PATH.

    Returns a dict parsed from YAML, or an empty dict if the file is missing or
    empty. Access is serialized with `_LOCK`.
    """
    try:
        with _LOCK, PROXIES_PATH.open(encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}
    except yaml.YAMLError as e:
        _logger.warning("[load_proxies] Malformed YAML at %s: %s", PROXIES_PATH, e)
        return {}


def save_proxies(proxies: dict[str, Any]) -> None:
    """Persist `proxies` to PROXIES_PATH as YAML, creating the parent dir."""
    PROXIES_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _LOCK, PROXIES_PATH.open("w", encoding="utf-8") as f:
        yaml.safe_dump(proxies, f)
