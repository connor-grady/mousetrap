"""Utilities to automate purchases of perks (upload credit, VIP, wedges) via the MaM API.

Functions handle proxy configuration, make HTTP requests to the MaM JSON API,
and return structured result dictionaries.
"""

import logging
import time
from typing import Any

import aiohttp

from backend.utils import build_proxy_dict, redact_proxy_urls

_logger: logging.Logger = logging.getLogger(__name__)

# Shared headers for the VIP and wedge bonusBuy requests.
_BONUS_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36",
    "Accept": "application/json, text/javascript, */*; q=0.01",
    "Accept-Language": "en-US,en;q=0.5",
    "Referer": "https://www.myanonamouse.net/store.php",
}

# Base endpoint for all bonusBuy purchases (upload credit, VIP, wedges).
_BONUS_BUY_URL = "https://www.myanonamouse.net/json/bonusBuy.php/"


def _resolve_proxy(
    proxy_cfg: dict[str, Any] | None, log_tag: str
) -> tuple[str | None, aiohttp.BasicAuth | None]:
    """Resolve a proxy config to an aiohttp (proxy_url, proxy_auth) pair, logging the choice."""
    if proxy_cfg is None:
        return None, None
    proxies = build_proxy_dict(proxy_cfg)
    if not proxies:
        return None, None
    _logger.debug(
        "[%s] Using proxy label: %s, proxies: %s",
        log_tag,
        proxy_cfg.get("label"),
        redact_proxy_urls(proxies, proxy_cfg),
    )
    proxy_auth = None
    username = proxy_cfg.get("username")
    password = proxy_cfg.get("password")
    if username and password:
        proxy_auth = aiohttp.BasicAuth(username, password)
    return proxies.get("https") or proxies.get("http"), proxy_auth


async def _bonus_buy(
    url: str,
    mam_id: str,
    log_tag: str,
    proxy_cfg: dict[str, Any] | None,
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Perform a bonusBuy GET request and normalize the response (shared by VIP and wedge)."""
    cookies = {"mam_id": mam_id}
    proxy_url, proxy_auth = _resolve_proxy(proxy_cfg, log_tag)
    try:
        _logger.debug("[%s] Making request to: %s", log_tag, url)
        timeout = aiohttp.ClientTimeout(total=10)
        async with (
            aiohttp.ClientSession(timeout=timeout) as session,
            session.get(
                url,
                params=params,
                cookies=cookies,
                proxy=proxy_url,
                proxy_auth=proxy_auth,
                headers=_BONUS_HEADERS,
            ) as resp,
        ):
            _logger.debug("[%s] Response: status=%s", log_tag, resp.status)
            if resp.status != 200:
                text = await resp.text()
                return {
                    "success": False,
                    "error": f"HTTP {resp.status}",
                    "raw_response": text[:500],
                    "status_code": resp.status,
                }
            try:
                data = await resp.json()
            except Exception as json_e:
                text = await resp.text()
                return {
                    "success": False,
                    "error": f"Non-JSON response: {json_e}",
                    "raw_response": text[:500],
                    "status_code": resp.status,
                }
            if data.get("success") or data.get("Success"):
                return {"success": True, "response": data}
    except Exception as e:
        _logger.error("[%s] Exception: %s", log_tag, e)
        return {"success": False, "error": str(e)}
    else:
        return {"success": False, "response": data}


async def buy_upload_credit(
    gb: int, mam_id: str | None = None, proxy_cfg: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Purchase upload credit via the MaM API. Returns a result dict.

    mam_id: required session cookie for authentication
    proxy_cfg: optional proxy config dict
    """
    if not mam_id:
        return {
            "success": False,
            "error": "mam_id (cookie) required for upload credit purchase",
            "gb": gb,
        }
    timestamp = int(time.time() * 1000)
    params = {"spendtype": "upload", "amount": gb, "_": timestamp}
    result = await _bonus_buy(_BONUS_BUY_URL, mam_id, "buy_upload_credit", proxy_cfg, params=params)
    result["gb"] = gb
    return result


async def buy_vip(
    mam_id: str, duration: str = "max", proxy_cfg: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Purchase VIP status via the MaM API. Returns a result dict.

    mam_id: required session cookie for authentication
    duration: 'max', '4', '8', etc. (string)
    proxy_cfg: optional proxy config dict
    """

    timestamp = int(time.time() * 1000)
    params: dict[str, Any] = {"spendtype": "VIP", "duration": duration, "_": timestamp}
    return await _bonus_buy(_BONUS_BUY_URL, mam_id, "buy_vip", proxy_cfg, params=params)


async def buy_wedge(
    mam_id: str, method: str = "points", proxy_cfg: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Purchase a wedge using points or cheese via the MaM API.

    method: "points" or "cheese"
    proxy_cfg: optional proxy config dict
    """
    if method not in ("points", "cheese"):
        return {"success": False, "error": f"Unsupported wedge purchase method: {method}"}

    timestamp = int(time.time() * 1000)
    params: dict[str, Any] = {"spendtype": "wedges", "source": method, "_": timestamp}
    return await _bonus_buy(_BONUS_BUY_URL, mam_id, "buy_wedge", proxy_cfg, params=params)
