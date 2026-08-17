"""Utility helpers for the backend."""

import logging
from typing import Any, Literal

from backend.env import LOGLEVEL

IpMonitoringMode = Literal["auto", "manual", "static"]


def setup_logging() -> None:
    """Set up global logging configuration for the backend.

    Call this once at app startup (e.g., in app.py).
    """
    level = getattr(logging, LOGLEVEL, logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    # Suppress overly verbose logs from dependencies unless DEBUG
    if level > logging.DEBUG:
        logging.getLogger("urllib3").setLevel(logging.INFO)
        logging.getLogger("httpx").setLevel(logging.INFO)
        logging.getLogger("requests").setLevel(logging.INFO)
    # Suppress APScheduler "missed run time" warnings which are common on Windows Docker Desktop
    # due to clock drift/sleep issues. Critical errors will still be logged.
    logging.getLogger("apscheduler.schedulers.base").setLevel(logging.ERROR)
    logging.getLogger("apscheduler").setLevel(logging.ERROR)


def parse_asn(value: str | int | None) -> int | None:
    """Return the numeric ASN from a provider string, passing None/int through unchanged.

    Provider strings put the AS number first: bare ("12345") or prefixed
    ("AS12345"), optionally followed by an org name. The leading token is taken
    and an optional "AS" prefix stripped; a non-numeric token yields None.
    """
    if not isinstance(value, str):
        return value
    token = value.strip().split(" ")[0].upper().removeprefix("AS")
    return int(token) if token.isdigit() else None


def build_status_message(status: dict[str, Any], ip_monitoring_mode: IpMonitoringMode = "auto") -> str:
    """Generate a user-friendly status message for the session based on the status dict."""
    # If error present, always show error
    if status.get("error"):
        return f"Error: {status['error']}"
    # If a static message is present (from mam_api or other), use it
    if status.get("message"):
        return status["message"]

    # Mode-specific status messages
    if ip_monitoring_mode == "static":
        return "Static IP mode - No monitoring active. Automation running normally."
    if ip_monitoring_mode == "manual":
        return "Manual IP mode - IP updates controlled by user. Automation running normally."

    # Auto mode - original logic
    # Fallbacks for legacy or unexpected cases
    if status.get("auto_update_seedbox"):
        result = status["auto_update_seedbox"]
        if isinstance(result, dict):
            if result.get("success"):
                return "IP Changed. Seedbox IP updated."
            return result.get("error", "Seedbox update failed.")
    return "No change detected. Update not needed."


# --- Proxy utility ---
def build_proxy_dict(proxy_cfg: dict[str, Any]) -> dict[str, Any] | None:
    """Given a proxy config dict, return a requests-compatible proxies dict or None.

    Handles host/port/username/password or direct URL fields.
    """
    if not proxy_cfg or not (host := proxy_cfg.get("host")):
        return None
    port = proxy_cfg.get("port")
    username = proxy_cfg.get("username")
    password = proxy_cfg.get("password")
    authority = f"{host}:{port}" if port else host
    credentials = f"{username}:{password}@" if username and password else ""
    proxy_url = f"http://{credentials}{authority}"
    return {"http": proxy_url, "https": proxy_url}


def redact_proxy_urls(proxies: dict[str, Any], proxy_cfg: dict[str, Any] | None) -> dict[str, Any]:
    """Return `proxies` with the proxy password masked in each URL, for safe logging."""
    password = proxy_cfg.get("password") if proxy_cfg else None
    if not password:
        return proxies
    return {k: v.replace(password, "***") for k, v in proxies.items()}


def handle_http_error(status: int, text: str = "", indexer_name: str = "Indexer") -> dict[str, Any]:
    """Handle common HTTP error status codes for indexer integrations.

    Args:
        status: HTTP status code
        text: Response text (optional)
        indexer_name: Name of the indexer for error messages

    Returns:
        dict with success=False and appropriate error message
    """
    match status:
        case 401:
            return {"success": False, "error": "Authentication failed. Check API key."}
        case 403:
            return {"success": False, "error": "Forbidden. Check API key permissions."}
        case 404:
            return {
                "success": False,
                "error": f"{indexer_name} indexer not found. Please configure it first.",
            }
        case _:
            return {
                "success": False,
                "error": f"HTTP {status} - {text[:100]}" if text else f"HTTP {status}",
            }
