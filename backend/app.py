"""MouseTrap backend FastAPI application.

This module implements the main FastAPI application for the MouseTrap backend,
including API endpoints for session management, automation, background job
registration (APScheduler), and related helpers.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import logging
import re
import time
from typing import Annotated, Any
from zoneinfo import ZoneInfo

import aiohttp
from apscheduler.schedulers.asyncio import AsyncIOScheduler  # type: ignore[import-untyped]
from apscheduler.triggers.interval import IntervalTrigger  # type: ignore[import-untyped]
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.staticfiles import StaticFiles
from starlette.responses import FileResponse

from backend.api_automation import router as automation_router
from backend.api_event_log import router as event_log_router
from backend.api_notifications import router as notifications_router
from backend.api_port_monitor import router as port_monitor_router
from backend.api_proxy import router as proxy_router
from backend.audiobookrequest_integration import (
    sync_mam_id_to_audiobookrequest,
    test_audiobookrequest_connection,
)
from backend.autobrr_integration import sync_mam_id_to_autobrr, test_autobrr_connection
from backend.automation import run_all_automation_jobs
from backend.chaptarr_integration import (
    find_mam_indexer_id as find_mam_indexer_id_chaptarr,
    sync_mam_id_to_chaptarr,
    test_chaptarr_connection,
)
from backend.config import (
    delete_session,
    get_session_path,
    list_sessions,
    load_config,
    load_session,
    save_session,
)
from backend.env import APP_VERSION, TZ
from backend.event_log import append_ui_event_log, clear_ui_event_log_for_session
from backend.ip_lookup import get_asn_and_timezone_from_ip, get_ipinfo_with_fallback, get_public_ip
from backend.jackett_integration import sync_mam_id_to_jackett, test_jackett_connection
from backend.last_session_api import router as last_session_router, write_last_session
from backend.mam_api import get_mam_seen_ip_info, get_proxied_public_ip, get_status
from backend.notifications_backend import notify_event, safe_notify_event
from backend.paths import ASSETS_DIR, FRONTEND_BUILD_DIR, FRONTEND_PUBLIC_DIR, LOG_DIR
from backend.port_monitor import port_monitor_manager
from backend.prowlarr_integration import (
    find_mam_indexer_id,
    sync_mam_id_to_prowlarr,
    test_prowlarr_connection,
)
from backend.proxy_config import resolve_proxy_from_session_cfg
from backend.utils import (
    build_proxy_dict,
    build_status_message,
    extract_asn_number,
    redact_proxy_urls,
    setup_logging,
)

# Set up global logging configuration
setup_logging()
_logger: logging.Logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Manage startup and shutdown for the FastAPI app.

    On startup: initializes APScheduler — resetting check timers, running an
    initial session sweep, registering all session, automation, and
    port-monitor jobs, and starting the scheduler.
    """
    await reset_all_last_check_times()
    await run_initial_session_checks()

    # Register all jobs BEFORE starting the scheduler
    await register_all_session_jobs()

    # Register the automation jobs to run every 10 minutes
    try:
        scheduler.add_job(
            run_all_automation_jobs,
            trigger=IntervalTrigger(minutes=10),
            id="automation_jobs",
            replace_existing=True,
            coalesce=True,
            max_instances=1,
        )
        _logger.info("[APScheduler] Registered automation jobs to run every 10 min")
    except Exception as e:
        _logger.error("[APScheduler] Failed to register automation jobs: %s", e)

    # Register MAM session expiry check to run daily
    try:
        scheduler.add_job(
            check_mam_session_expiry,
            trigger=IntervalTrigger(hours=24),
            id="check_mam_expiry",
            replace_existing=True,
            coalesce=True,
            max_instances=1,
        )
        _logger.info("[APScheduler] Registered MAM session expiry check to run daily")
    except Exception as e:
        _logger.error("[APScheduler] Failed to register MAM expiry check: %s", e)

    # Poll the port-monitor stacks every 5s (blocking docker/socket work is offloaded to a thread)
    scheduler.add_job(
        port_monitor_manager.poll,
        trigger=IntervalTrigger(seconds=5),
        id="port_monitor",
        replace_existing=True,
        coalesce=True,
        max_instances=1,
    )

    # Start scheduler AFTER all jobs are registered
    scheduler.start()
    _logger.info("[APScheduler] Background scheduler started")

    yield

    # Shutdown: tear down background services in reverse of startup order
    scheduler.shutdown()
    _logger.info("[APScheduler] Background scheduler stopped")


# FastAPI app creation
app = FastAPI(title="MouseTrap API", lifespan=lifespan)

# Mount static files BEFORE any catch-all routes
# Serve logs directory as static files for UI event log access
if LOG_DIR.is_dir():
    app.mount("/logs", StaticFiles(directory=str(LOG_DIR)), name="logs")

if ASSETS_DIR.is_dir():
    app.mount("/assets", StaticFiles(directory=str(ASSETS_DIR)), name="assets")
else:
    _logger.warning(
        "Frontend assets directory %s does not exist; skipping /assets mount (dev mode?)",
        ASSETS_DIR,
    )

# Mount API routers
app.include_router(automation_router, prefix="/api")
app.include_router(last_session_router, prefix="/api")
app.include_router(proxy_router, prefix="/api")
app.include_router(event_log_router, prefix="/api")
app.include_router(notifications_router, prefix="/api")
app.include_router(port_monitor_router, prefix="/api/port-monitor")

# APScheduler setup
scheduler = AsyncIOScheduler()

session_status_cache: dict[str, Any] = {}
# Global cache for notification deduplication by UID (MAM account ID)
# Format: {uid: {event_type: {count_change_key: timestamp}}}
# Note: Uses UID not mam_id, since multiple sessions can share the same MAM account
notification_dedup_cache: dict[str, dict[str, dict[str, float]]] = {}


def redact_mam_id(mam_id: str, show_last: int = 8) -> str:
    """Redact MAM ID for security, showing only the last N characters.

    Args:
        mam_id: The full MAM ID
        show_last: Number of characters to show at the end (default 8)

    Returns:
        Redacted string like "MAM ID ending in ...abcd1234"
    """
    if not mam_id or len(mam_id) <= show_last:
        return "MAM ID ending in " + ("*" * show_last)

    return f"MAM ID ending in ...{mam_id[-show_last:]}"


def should_send_notification(
    dedup_key: str, event_type: str, old_count: int, new_count: int, dedup_window_minutes: int = 60
) -> bool:
    """Check if we should send a notification based on deduplication cache.

    Args:
        dedup_key: The deduplication key (typically UID for MAM account)
        event_type: Type of event (e.g., 'inactive_hit_and_run', 'inactive_unsatisfied')
        old_count: Previous count value
        new_count: New count value
        dedup_window_minutes: Minutes to prevent duplicate notifications (default 60)

    Returns:
        True if notification should be sent, False if it's a duplicate
    """
    if not dedup_key:
        return True  # Always allow if no dedup key

    # Create a unique key for this specific count change
    count_change_key = f"{old_count}→{new_count}"
    now = time.time()
    dedup_window_seconds = dedup_window_minutes * 60

    # Initialize nested dict structure if needed
    if dedup_key not in notification_dedup_cache:
        notification_dedup_cache[dedup_key] = {}
    if event_type not in notification_dedup_cache[dedup_key]:
        notification_dedup_cache[dedup_key][event_type] = {}

    # Check if we've recently notified about this exact change
    last_notification_time = notification_dedup_cache[dedup_key][event_type].get(count_change_key)

    if last_notification_time and (now - last_notification_time) < dedup_window_seconds:
        # Duplicate notification within window - skip it
        return False

    # Record this notification and clean up old entries
    notification_dedup_cache[dedup_key][event_type][count_change_key] = now

    # Clean up old entries to prevent memory growth
    cutoff_time = now - dedup_window_seconds
    for key in list(notification_dedup_cache[dedup_key][event_type].keys()):
        if notification_dedup_cache[dedup_key][event_type][key] < cutoff_time:
            del notification_dedup_cache[dedup_key][event_type][key]

    return True


def get_auto_update_val(status: dict[str, Any]) -> str:
    """Return a human-readable representation of the auto-update status.

    The input may be a dict containing keys like 'success', 'msg', 'reason',
    or 'error'. This helper normalizes those cases into a short string suitable
    for display in the UI or logs. If the value is missing or invalid, returns
    the string "N/A".
    """
    val = status.get("auto_update_seedbox")
    if val is None or val == "" or val is False:
        return "N/A"
    if isinstance(val, dict):
        msg = val.get("msg")
        reason = val.get("reason")
        error = val.get("error")
        if val.get("success") and msg:
            # If reason is present, append it for clarity
            return f"{msg} ({reason})" if reason else msg
        if error:
            return f"{error} ({reason})" if reason else error
        return "N/A"
    return str(val)


def _inactive_count(raw: dict[str, Any], key: str) -> int:
    """Extract the integer ``count`` for an inactivity bucket (``inactHnr``/``inactUnsat``).

    Tolerates missing keys, non-dict buckets, and string counts; returns 0 for
    anything not coercible to a non-negative integer.
    """
    bucket = raw.get(key)
    value = bucket.get("count", 0) if isinstance(bucket, dict) else 0
    return int(value) if isinstance(value, int | str) and str(value).isdigit() else 0


async def check_and_notify_count_increments(
    cfg: dict[str, Any], new_status: dict[str, Any]
) -> None:
    """Check for increments in hit & run and unsatisfied counts and send notifications."""
    # Get the previous status
    old_status = cfg.get("last_status", {})
    if not isinstance(old_status, dict):
        return

    # Get UID for deduplication (same account across different sessions)
    # UID is the actual MAM account identifier, mam_id is just a session cookie
    old_raw = old_status.get("raw", {})
    new_raw = new_status.get("raw", {})
    uid = new_raw.get("uid") or old_raw.get("uid")

    # Get username for notification display
    username = new_raw.get("username") or old_raw.get("username") or f"UID {uid}"

    # Fall back to mam_id if uid not available (shouldn't happen)
    dedup_key = str(uid) if uid else cfg.get("mam", {}).get("mam_id", "")

    # Check inactive hit & run increment
    old_inact_hnr = _inactive_count(old_raw, "inactHnr")
    new_inact_hnr = _inactive_count(new_raw, "inactHnr")

    if new_inact_hnr > old_inact_hnr:
        increment = new_inact_hnr - old_inact_hnr

        # Check deduplication - only notify if this change hasn't been reported recently for this account
        if should_send_notification(
            dedup_key, "inactive_hit_and_run", old_inact_hnr, new_inact_hnr
        ):
            await notify_event(
                event_type="inactive_hit_and_run",
                label=None,  # Don't include session - this is account-based
                status="INCREMENT",
                message=f"{username} (UID {uid}): Inactive Hit & Run count increased by {increment} (from {old_inact_hnr} to {new_inact_hnr})",
                details={
                    "old_count": old_inact_hnr,
                    "new_count": new_inact_hnr,
                    "increment": increment,
                    "uid": uid,
                    "username": username,
                },
            )

    # Check inactive unsatisfied increment
    old_inact_unsat = _inactive_count(old_raw, "inactUnsat")
    new_inact_unsat = _inactive_count(new_raw, "inactUnsat")

    if new_inact_unsat > old_inact_unsat:
        increment = new_inact_unsat - old_inact_unsat

        # Check deduplication - only notify if this change hasn't been reported recently for this account
        if should_send_notification(
            dedup_key, "inactive_unsatisfied", old_inact_unsat, new_inact_unsat
        ):
            await notify_event(
                event_type="inactive_unsatisfied",
                label=None,  # Don't include session - this is account-based
                status="INCREMENT",
                message=f"{username} (UID {uid}): Inactive Unsatisfied (Pre-H&R) count increased by {increment} (from {old_inact_unsat} to {new_inact_unsat})",
                details={
                    "old_count": old_inact_unsat,
                    "new_count": new_inact_unsat,
                    "increment": increment,
                    "uid": uid,
                    "username": username,
                },
            )


async def check_mam_session_expiry() -> None:
    """Check all sessions for approaching MAM session expiry and send notifications.

    This runs daily to check if any sessions with Prowlarr or Chaptarr integration have
    MAM sessions that are approaching the 30-day expiry limit.
    """
    _logger.info("[ExpiryCheck] Checking MAM session expiry for all sessions")

    try:
        sessions = await list_sessions()
        for label in sessions:
            try:
                cfg = await load_session(label)
                prowlarr_cfg = cfg.get("prowlarr", {})
                chaptarr_cfg = cfg.get("chaptarr", {})

                # Skip if neither Prowlarr nor Chaptarr is enabled
                if not prowlarr_cfg.get("enabled") and not chaptarr_cfg.get("enabled"):
                    continue

                created_date_str = cfg.get("mam_session_created_date")
                if not created_date_str:
                    continue

                # Parse the created date
                try:
                    created_date = datetime.fromisoformat(created_date_str)
                except (ValueError, AttributeError) as e:
                    _logger.warning(
                        "[ExpiryCheck] Invalid date format for session '%s': %s", label, e
                    )
                    continue

                # Calculate expiry (30 days from creation)
                expiry_date = created_date + timedelta(days=30)
                days_until_expiry = (expiry_date - datetime.now(UTC)).days

                # Check if we should notify - use the session-level setting
                notify_days = cfg.get("notify_before_expiry_days", 7)

                if days_until_expiry <= notify_days and days_until_expiry >= 0:
                    _logger.info(
                        "[ExpiryCheck] Session '%s' expires in %d days - sending notification",
                        label,
                        days_until_expiry,
                    )

                    # Get MAM ID and redact for security
                    mam_id = cfg.get("mam", {}).get("mam_id", "N/A")
                    redacted_mam_id = redact_mam_id(mam_id) if mam_id != "N/A" else "N/A"

                    # Build indexer info strings
                    indexer_info = []
                    if prowlarr_cfg.get("enabled") and prowlarr_cfg.get("host"):
                        indexer_info.append(
                            f"Prowlarr: {prowlarr_cfg['host']}:{prowlarr_cfg.get('port', 9696)}"
                        )
                    if chaptarr_cfg.get("enabled") and chaptarr_cfg.get("host"):
                        indexer_info.append(
                            f"Chaptarr: {chaptarr_cfg['host']}:{chaptarr_cfg.get('port', 8789)}"
                        )

                    # Prepare notification message
                    message = (
                        f"⚠️ MAM Session Expiring Soon!\n\n"
                        f"Session: {label}\n"
                        f"{redacted_mam_id}\n"
                        f"Created: {created_date.strftime('%Y-%m-%d %H:%M')}\n"
                        f"Expires: {expiry_date.strftime('%Y-%m-%d %H:%M')}\n"
                        f"Days Remaining: {days_until_expiry} day{'s' if days_until_expiry != 1 else ''}\n\n"
                        f"You will need to refresh your MAM session and update your indexer(s).\n"
                    )

                    if indexer_info:
                        message += "\n" + "\n".join(indexer_info)

                    details = {
                        "session_label": label,
                        "mam_id": redacted_mam_id,  # Use redacted version in details too
                        "created_date": created_date.isoformat(),
                        "expiry_date": expiry_date.isoformat(),
                        "days_remaining": days_until_expiry,
                        "prowlarr_host": prowlarr_cfg.get("host", "N/A")
                        if prowlarr_cfg.get("enabled")
                        else "N/A",
                        "chaptarr_host": chaptarr_cfg.get("host", "N/A")
                        if chaptarr_cfg.get("enabled")
                        else "N/A",
                    }

                    # Send notification
                    await notify_event(
                        event_type="mam_session_expiry",
                        label=label,
                        status="WARNING",
                        message=message,
                        details=details,
                    )

                elif days_until_expiry < 0:
                    _logger.warning(
                        "[ExpiryCheck] Session '%s' expired %d days ago!",
                        label,
                        abs(days_until_expiry),
                    )

            except Exception as e:
                _logger.error("[ExpiryCheck] Error checking session '%s': %s", label, e)

    except Exception as e:
        _logger.error("[ExpiryCheck] Error in MAM expiry check: %s", e)


@app.get("/api/automation/guardrails")
async def api_automation_guardrails() -> dict[str, Any]:
    """Returns a mapping of session labels to MaM usernames and enabled automations for guardrail logic.

    Example:
        {
            "Gluetun": {"username": "example_user", "autoUpload": true, "autoWedge": false, "autoVIP": false},
            ...
        }

    """
    sessions = await list_sessions()
    result: dict[str, Any] = {}
    for label in sessions:
        cfg = await load_session(label)
        # Try to get username from last_status.raw.username
        last_status = cfg.get("last_status", {})
        raw = last_status.get("raw", {})
        username = raw.get("username")
        # Fallback: try mam_id or proxy.username if username missing
        if not username:
            username = cfg.get("mam", {}).get("mam_id") or cfg.get("proxy", {}).get("username")
        perk_auto = cfg.get("perk_automation", {})
        result[label] = {
            "username": username,
            "autoUpload": perk_auto.get("upload_credit", {}).get("enabled", False),
            "autoWedge": perk_auto.get("wedge_automation", {}).get("enabled", False),
            "autoVIP": perk_auto.get("vip_automation", {}).get("enabled", False),
        }
    return result


async def keepalive_mam_session(cfg: dict[str, Any], label: str, now: datetime) -> bool:
    """Send a keepalive ping to MAM's dynamicSeedbox.php to prevent session expiry.

    MAM sessions expire after ~30 days of inactivity. Regular status checks via
    jsonLoad.php may not reset this timer. This function calls dynamicSeedbox.php
    explicitly to keep the session alive, regardless of whether the IP has changed.

    A 429 (rate-limited) response is treated as success for keepalive purposes —
    MAM received and processed the request, which is sufficient to reset the timer.
    Any other HTTP error or network exception is treated as a failure.

    On success (including 429), updates ``last_mam_keepalive`` and resets
    ``mam_session_created_date`` in the session config so the expiry notification
    timer reflects recent activity rather than the original creation date.

    Returns True if the keepalive was sent (or rate-limited), False on error.
    """
    mam_id: str = cfg.get("mam", {}).get("mam_id", "")
    if not mam_id:
        _logger.warning("[Keepalive] label=%s No mam_id; skipping keepalive.", label)
        return False

    proxy_cfg = await resolve_proxy_from_session_cfg(cfg)
    proxies = build_proxy_dict(proxy_cfg) if proxy_cfg else None
    proxy_url = (proxies.get("https") or proxies.get("http")) if proxies else None

    try:
        timeout = aiohttp.ClientTimeout(total=10)
        async with (
            aiohttp.ClientSession(timeout=timeout) as session,
            session.get(
                "https://t.myanonamouse.net/json/dynamicSeedbox.php",
                cookies={"mam_id": mam_id},
                proxy=proxy_url,
            ) as resp,
        ):
            status_code = resp.status
            try:
                result = await resp.json()
            except Exception:
                text = await resp.text()
                result = {"msg": text[:200]}

            if status_code == 429 or ("too recent" in str(result.get("msg", ""))):
                # Rate-limited — MAM still received the request; counts as keepalive activity
                _logger.info(
                    "[Keepalive] label=%s Rate-limited (429) — session activity confirmed.", label
                )
            elif status_code == 200:
                _logger.info(
                    "[Keepalive] label=%s Keepalive successful (200). msg=%s",
                    label,
                    result.get("msg", ""),
                )
            else:
                _logger.warning(
                    "[Keepalive] label=%s Unexpected response %s: %s",
                    label,
                    status_code,
                    result.get("msg", ""),
                )
                await append_ui_event_log(
                    {
                        "timestamp": now.isoformat(),
                        "label": label,
                        "event_type": "keepalive_failure",
                        "status_message": f"[Keepalive] Unexpected response {status_code} from MAM: {result.get('msg', '')}",
                    }
                )
                return False

    except Exception as e:
        _logger.warning("[Keepalive] label=%s Network error during keepalive: %s", label, e)
        await append_ui_event_log(
            {
                "timestamp": now.isoformat(),
                "label": label,
                "event_type": "keepalive_failure",
                "status_message": f"[Keepalive] Network error contacting MAM: {e}",
            }
        )
        return False

    # Update keepalive timestamp and reset the session creation date so the
    # expiry notification timer reflects this confirmed activity.
    try:
        fresh_cfg = await load_session(label)
        fresh_cfg["last_mam_keepalive"] = now.isoformat()
        fresh_cfg["mam_session_created_date"] = now.isoformat()
        await save_session(fresh_cfg, old_label=label)
        _logger.info(
            "[Keepalive] label=%s Updated last_mam_keepalive and reset mam_session_created_date.",
            label,
        )
    except Exception as e:
        _logger.warning("[Keepalive] label=%s Failed to save keepalive timestamp: %s", label, e)
        # Non-fatal — the network call succeeded

    return True


async def _persist_seedbox_ip(
    cfg: dict[str, Any], label: str, asn: str | None, now: datetime
) -> str | None:
    """Record a successful seedbox IP/ASN update on ``cfg`` and persist it; returns the new IP."""
    new_ip = cfg.get("proxied_public_ip") or await get_public_ip()
    cfg["last_seedbox_ip"] = new_ip
    cfg["mam_ip"] = new_ip
    cfg["last_seedbox_update"] = now.isoformat()
    cfg["last_seedbox_asn"] = asn
    try:
        await save_session(cfg, old_label=label)
    except Exception as e:
        _logger.error("[AutoUpdate][ERROR] label=%s save_session failed: %s", label, e)
    return new_ip


async def auto_update_seedbox_if_needed(
    cfg: dict[str, Any], label: str, ip_to_use: str | None, asn: str | None, now: datetime
) -> tuple[bool, dict[str, Any] | None]:
    """Check whether a seedbox auto-update should be performed and perform it.

    Args:
        cfg: Session configuration dict.
        label: Session label string.
        ip_to_use: IP address to compare/update.
        asn: ASN value associated with the IP (string or None).
        now: Current datetime (UTC).

    Returns:
        Tuple (update_performed: bool, result: dict|None). If an update was
        triggered, result contains details about success/error/msg/reason.
        Otherwise returns (False, None).

    """
    if not ip_to_use:
        return False, None
    session_type = cfg.get("mam", {}).get("session_type", "").lower()  # 'ip locked' or 'asn locked'
    last_seedbox_ip: str | None = cfg.get("last_seedbox_ip")
    last_seedbox_asn: str | None = cfg.get("last_seedbox_asn")
    last_seedbox_update = cfg.get("last_seedbox_update")
    mam_id: str = cfg.get("mam", {}).get("mam_id", "")
    # Do not log mam_id value
    update_needed = False
    reason: str | None = None
    # Remove all IP logic for the API call; only use mam_id and proxy
    proxy_cfg = await resolve_proxy_from_session_cfg(cfg)
    proxies = build_proxy_dict(proxy_cfg) if proxy_cfg else None
    # Do not log proxies dict (may contain sensitive info)
    # Only trigger update if something changed (IP or ASN)

    # If ASN-locked and ASN changed but IP did not, update ASN in config only
    if session_type == "asn locked":
        # Always get ASN using proxy if available
        proxied_ip = cfg.get("proxied_public_ip")
        asn_to_check, _ = await get_asn_and_timezone_from_ip(
            proxied_ip or ip_to_use, proxy_cfg if proxied_ip else None
        )

        # If ASN lookup failed, skip config update and logging
        if asn_to_check is None or asn_to_check == "Unknown ASN":
            _logger.info(
                "[AutoUpdate] label=%s ASN lookup failed or unavailable (likely fallback provider). Skipping ASN comparison to avoid false notifications.",
                label,
            )
            # Don't return an error - just skip ASN comparison for this check
            # Continue with normal processing without ASN change detection
        else:
            norm_last = extract_asn_number(last_seedbox_asn) if last_seedbox_asn else None
            norm_check = extract_asn_number(asn_to_check)
            # Always store the normalized ASN number if available
            if norm_check is not None:
                cfg["last_seedbox_asn"] = norm_check
                await save_session(cfg, old_label=label)
            # Log ASN compare and result at INFO level
            if norm_last != norm_check:
                reason = f"ASN changed: {norm_last} -> {norm_check}"
                _logger.info(
                    "[AutoUpdate] label=%s ASN changed. Will check for errors when updating IP. reason=%s",
                    label,
                    reason,
                )
                # For ASN Locked sessions, don't send notification here
                # Instead, let the IP update proceed and send enhanced notification if it fails
                # Continue to IP check...
            else:
                _logger.info(
                    "[AutoUpdate] label=%s ASN check: %s -> %s | No change needed",
                    label,
                    norm_last,
                    norm_check,
                )
    # For proxied sessions, use proxied IP; for non-proxied, use detected public IP
    proxied_ip = cfg.get("proxied_public_ip")
    # For non-proxied, get detected public IP (not mam_ip)
    ip_to_check = proxied_ip or await get_public_ip()
    # If IP lookup failed, skip config update and logging
    if ip_to_check is None:
        _logger.warning(
            "[AutoUpdate] label=%s Could not detect valid public IP. Skipping config update and ASN/IP change _logger.",
            label,
        )
        return False, {"success": False, "msg": "IP lookup failed. No update performed."}
    if last_seedbox_ip is None or ip_to_check != last_seedbox_ip:
        update_needed = True
        reason = f"IP changed: {last_seedbox_ip} -> {ip_to_check or 'N/A'}"
        _logger.info(
            "[AutoUpdate] label=%s IP changed: %s -> %s",
            label,
            last_seedbox_ip,
            ip_to_check or "N/A",
        )
    else:
        _logger.info(
            "[AutoUpdate] label=%s IP check: %s -> %s | No change needed",
            label,
            last_seedbox_ip,
            ip_to_check,
        )
    if update_needed:
        _logger.info(
            "[AutoUpdate] label=%s update_needed=True asn=%s reason=%s",
            label,
            asn,
            reason,
        )
        # If update is needed (IP or proxied IP changed), call seedbox API
        if not mam_id:
            _logger.warning(
                "[AutoUpdate] label=%s update_needed=True but mam_id is missing. Skipping seedbox API call.",
                label,
            )
            _logger.debug(
                "[AutoUpdate][RETURN] label=%s Returning due to missing mam_id. reason=%s",
                label,
                reason,
            )
            return False, {"success": False, "error": "mam_id missing", "reason": reason}
        # Only treat as rate-limited if the API actually returns 429 or 'too recent', not just based on timer
        try:
            _logger.debug(
                "[AutoUpdate][TRACE] label=%s About to call seedbox API (using proxy)",
                label,
            )
            cookies = {"mam_id": mam_id}
            proxy_url = None
            if proxies:
                proxy_url = proxies.get("https") or proxies.get("http")

            timeout = aiohttp.ClientTimeout(total=10)
            async with (
                aiohttp.ClientSession(timeout=timeout) as session,
                session.get(
                    "https://t.myanonamouse.net/json/dynamicSeedbox.php",
                    cookies=cookies,
                    proxy=proxy_url,
                ) as resp,
            ):
                _logger.debug(
                    "[AutoUpdate][TRACE] label=%s Seedbox API call complete. Status=%s",
                    label,
                    resp.status,
                )
                try:
                    result = await resp.json()
                    _logger.debug(
                        "[AutoUpdate][TRACE] label=%s Seedbox API response JSON received",
                        label,
                    )
                except Exception as e_json:
                    _logger.warning(
                        "[AutoUpdate][TRACE] label=%s Non-JSON response from seedbox API (error: %s)",
                        label,
                        e_json,
                    )
                    text = await resp.text()
                    result = {"Success": False, "msg": f"Non-JSON response: {text}"}

                if resp.status == 200 and result.get("Success"):
                    # Update last_seedbox_ip and mam_ip to the new detected/proxied IP
                    new_ip = await _persist_seedbox_ip(cfg, label, asn, now)
                    _logger.info(
                        "[AutoUpdate] label=%s result=success reason=%s",
                        label,
                        reason,
                    )
                    api_msg = str(result.get("msg", "")).strip()
                    if not api_msg or api_msg.lower() == "completed":
                        api_msg = "IP Changed. Seedbox IP updated."
                    await safe_notify_event(
                        event_type="seedbox_update_success",
                        label=label,
                        status="SUCCESS",
                        message=api_msg,
                        details={"reason": reason, "ip": new_ip, "asn": asn},
                    )
                    return True, {"success": True, "msg": api_msg, "reason": reason}
                if resp.status == 200 and result.get("msg") == "No change":
                    await _persist_seedbox_ip(cfg, label, asn, now)
                    _logger.info(
                        "[AutoUpdate] label=%s result=no_change reason=%s",
                        label,
                        reason,
                    )
                    return True, {
                        "success": True,
                        "msg": "No change: IP/ASN already set.",
                        "reason": reason,
                    }
                if resp.status == 429 or ("too recent" in str(result.get("msg", ""))):
                    # Do NOT update last_seedbox_ip or mam_ip if rate-limited; return rate-limit info for UI
                    rate_limit_minutes = 60
                    if last_seedbox_update:
                        last_update_dt = datetime.fromisoformat(last_seedbox_update)
                        elapsed = (now - last_update_dt).total_seconds() / 60
                        if elapsed < 0:
                            # If last update is in the future, treat as no cooldown
                            rate_limit_minutes = 0
                        elif elapsed < 60:
                            rate_limit_minutes = int(60 - elapsed)
                        else:
                            rate_limit_minutes = 0
                    await safe_notify_event(
                        event_type="seedbox_update_rate_limited",
                        label=label,
                        status="RATE_LIMITED",
                        message="Rate limit: last change too recent.",
                        details={"reason": reason, "rate_limit_minutes": rate_limit_minutes},
                    )
                    return True, {
                        "success": False,
                        "error": f"Rate limit: last change too recent. Try again in {rate_limit_minutes} minutes.",
                        "reason": reason,
                        "rate_limit_minutes": rate_limit_minutes,
                    }
                _logger.info(
                    "[AutoUpdate] label=%s result=error reason=%s",
                    label,
                    reason,
                )

                # Check if this is an ASN mismatch issue for ASN Locked sessions
                error_msg = str(result.get("msg", "Unknown error"))
                if session_type == "asn locked" and (
                    "Invalid session" in error_msg or resp.status == 403
                ):
                    # Check if ASN has changed recently
                    current_asn = asn or cfg.get("proxied_public_ip_asn")
                    if current_asn and last_seedbox_asn and current_asn != last_seedbox_asn:
                        enhanced_msg = (
                            f"{error_msg}\n\n"
                            f"⚠️ ASN Mismatch Detected!\n"
                            f"Your session is ASN Locked but the ASN has changed: {last_seedbox_asn} → {current_asn}\n\n"
                            f"Action Required:\n"
                            f"1. Log into MyAnonamouse.net → Preferences → Security\n"
                            f"2. Find your seedbox session and click 'Manage Session'\n"
                            f"3. Under 'Add additional ASN via IP address', enter an IP from ASN {current_asn}\n"
                            f"4. MAM will detect and add the ASN to your session automatically\n"
                            f"5. Your existing mam_id cookie will work once the ASN is added\n\n"
                            f"Note: If the cookie was already invalidated, you may need to generate a new one after updating"
                        )
                        _logger.warning(
                            "[AutoUpdate] label=%s ASN Locked session with ASN change detected: %s -> %s",
                            label,
                            last_seedbox_asn,
                            current_asn,
                        )
                        await safe_notify_event(
                            event_type="seedbox_update_failure",
                            label=label,
                            status="FAILED",
                            message=enhanced_msg,
                            details={
                                "reason": reason,
                                "old_asn": last_seedbox_asn,
                                "new_asn": current_asn,
                                "session_type": "ASN Locked",
                                "action_required": "Update MAM session and refresh mam_id cookie",
                            },
                        )
                        return True, {
                            "success": False,
                            "error": enhanced_msg,
                            "reason": reason,
                        }

                await safe_notify_event(
                    event_type="seedbox_update_failure",
                    label=label,
                    status="FAILED",
                    message=result.get("msg", "Unknown error"),
                    details={"reason": reason},
                )
                return True, {
                    "success": False,
                    "error": result.get("msg", "Unknown error"),
                    "reason": reason,
                }
        except Exception as e:
            _logger.warning(
                "[AutoUpdate] label=%s result=exception reason=%s error=%s",
                label,
                reason,
                e,
            )
            _logger.debug(
                "[AutoUpdate][RETURN] label=%s Returning after exception in seedbox API call. reason=%s",
                label,
                reason,
            )

            await safe_notify_event(
                event_type="seedbox_update_failure",
                label=label,
                status="EXCEPTION",
                message=str(e),
                details={"reason": reason},
            )
            return True, {"success": False, "error": str(e), "reason": reason}
    else:
        # Already logged IP/ASN compare and result above, so just add a single debug trace for return
        _logger.debug(
            "[AutoUpdate][RETURN] label=%s Returning default path (no update needed or triggered).",
            label,
        )
    return False, None


@app.get("/api/status")
async def api_status(
    label: Annotated[str | None, Query()] = None, force: Annotated[int, Query()] = 0
) -> dict[str, Any]:
    """Return the current status for a session label.

    If `force` is truthy, a fresh status check is performed even if a cached
    value exists. The returned dict contains status details expected by the
    frontend UI.
    """
    # Single API call for non-proxied IP/ASN detection (efficiency optimization)
    detected_ipinfo_data = await get_ipinfo_with_fallback()
    detected_public_ip = detected_ipinfo_data.get("ip")
    detected_public_ip_asn = None
    detected_public_ip_as = None
    if detected_public_ip:
        asn_full_pub = detected_ipinfo_data.get("asn")
        detected_public_ip_asn = extract_asn_number(asn_full_pub) or asn_full_pub
        detected_public_ip_as = asn_full_pub

    cfg = await load_session(label) if label else None
    if cfg is None:
        available = await list_sessions()
        if label is None:
            _logger.debug("No session label provided to status endpoint.")
            status_message = (
                f"No session label provided. Use ?label=<name>. Available sessions: {available}"
                if available
                else "No sessions configured yet. Please save session details to begin."
            )
        else:
            _logger.warning("Session '%s' not found or not configured.", label)
            status_message = (
                f"Session '{label}' not found. Available sessions: {available}"
                if available
                else f"Session '{label}' not found and no sessions are configured."
            )
        return {
            "configured": False,
            "status_message": status_message,
            "available_sessions": available,
            "last_check_time": None,
            "next_check_time": None,
            "details": {},
            "detected_public_ip": detected_public_ip,
            "detected_public_ip_asn": detected_public_ip_asn,
        }
    # Proxied public IP/ASN detection (single API call optimization)
    proxy_cfg = await resolve_proxy_from_session_cfg(cfg)
    proxied_public_ip, proxied_public_ip_asn, proxied_public_ip_as = None, None, None
    proxy_error = None
    if proxy_cfg and proxy_cfg.get("host"):
        # Single API call for proxied IP/ASN data
        try:
            proxied_ipinfo_data = await get_ipinfo_with_fallback(proxy_cfg=proxy_cfg)
            proxied_public_ip = proxied_ipinfo_data.get("ip")
            asn_full_proxied = proxied_ipinfo_data.get("asn")
            asn_str = str(asn_full_proxied) if asn_full_proxied is not None else ""
            proxied_public_ip_asn = extract_asn_number(asn_str) or asn_str
            proxied_public_ip_as = asn_full_proxied
            # Save to config if changed
            if proxied_public_ip and cfg.get("proxied_public_ip") != proxied_public_ip:
                cfg["proxied_public_ip"] = proxied_public_ip
                cfg["proxied_public_ip_asn"] = proxied_public_ip_asn
                await save_session(cfg, old_label=label)
        except Exception as e:
            proxy_error = f"Proxy/VPN connection failed: {e!s}"

            await notify_event(
                event_type="proxy_failure",
                label=label,
                status="FAILED",
                message=proxy_error,
                details={"proxy": proxy_cfg.get("label", "unknown"), "error": str(e)},
            )
    # Clear if no proxy
    elif cfg.get("proxied_public_ip") or cfg.get("proxied_public_ip_asn"):
        cfg["proxied_public_ip"] = None
        cfg["proxied_public_ip_asn"] = None
        await save_session(cfg, old_label=label)
    if not label:
        # Always return detected_public_ip and asn, even if label is missing
        return {
            "configured": False,
            "status_message": "Session label required.",
            "last_check_time": None,
            "next_check_time": None,
            "details": {},
            "detected_public_ip": detected_public_ip,
            "detected_public_ip_asn": detected_public_ip_asn,
        }
    # Always reload session config before every check to ensure latest proxy settings
    cfg = await load_session(label)
    mam_id = cfg.get("mam", {}).get("mam_id", "")
    mam_ip_override = cfg.get("mam_ip", "").strip()
    ip_monitoring_mode = cfg.get("mam", {}).get("ip_monitoring_mode", "auto")

    # Note: IP detection always happens for user convenience, regardless of monitoring mode
    # Only the monitoring/auto-update logic differs between modes

    # Always resolve proxy config immediately before every get_status call
    proxy_cfg = await resolve_proxy_from_session_cfg(cfg)
    # If session is not configured (no mam_id), return not configured status
    if not mam_id:
        return {
            "configured": False,
            "status_message": "Session not configured. Please save session details to begin.",
            "last_check_time": None,
            "next_check_time": None,
            "details": {},
            "detected_public_ip": detected_public_ip,
            "detected_public_ip_asn": detected_public_ip_asn,
        }
    # Use proxied public IP if available, else fallback
    ip_to_use: str | None = mam_ip_override or proxied_public_ip or detected_public_ip
    # Get ASN for configured IP
    asn_full, _ = await get_asn_and_timezone_from_ip(ip_to_use) if ip_to_use else (None, None)
    asn = extract_asn_number(asn_full) or asn_full
    mam_session_as = asn_full
    # Also get MAM's perspective for display only
    mam_seen = await get_mam_seen_ip_info(mam_id, proxy_cfg=proxy_cfg or {})
    mam_seen_asn = str(mam_seen.get("ASN")) if mam_seen.get("ASN") is not None else None
    mam_seen_as = mam_seen.get("AS")
    now = datetime.now(UTC)
    # Remove timer persistence: do not use session file for last_check_time
    cache = session_status_cache.get(label, {})
    status = cache.get("status", {})
    last_check_time = cache.get("last_check_time")
    # If session has never been checked (no last_status and not forced), return not configured
    if not force and (
        label not in session_status_cache or not session_status_cache[label].get("status")
    ):
        last_status = cfg.get("last_status")
        last_check_time = cfg.get("last_check_time")
        if not last_status or not last_check_time:
            return {
                "configured": False,
                "status_message": "Session not configured. Please save session details to begin.",
                "last_check_time": None,
                "next_check_time": None,
                "details": {},
            }

    def _status_payload(
        *, next_check_time: str | None, status_message: Any, **extra: Any
    ) -> dict[str, Any]:
        """Assemble the /api/status response body shared by the cached and fresh-check paths."""
        return {
            "mam_cookie_exists": status.get("mam_cookie_exists"),
            "points": status.get("points"),
            "wedge_active": status.get("wedge_active"),
            "vip_active": status.get("vip_active"),
            "current_ip": ip_to_use,
            "current_ip_asn": asn,
            "mam_session_as": mam_session_as,
            "mam_seen_asn": mam_seen_asn,
            "mam_seen_as": mam_seen_as,
            "configured_ip": ip_to_use,
            "configured_asn": asn,
            "check_freq": check_freq_minutes,
            "last_check_time": last_check_time,
            "next_check_time": next_check_time,
            "status_message": status_message,
            "details": status,
            "detected_public_ip": detected_public_ip,
            "detected_public_ip_asn": detected_public_ip_asn,
            "detected_public_ip_as": detected_public_ip_as,
            "proxied_public_ip": proxied_public_ip,
            "proxied_public_ip_asn": proxied_public_ip_asn,
            "proxied_public_ip_as": proxied_public_ip_as,
            "ip_monitoring_mode": ip_monitoring_mode,
            **extra,
        }

    # If we have cached data and not forcing, use it and calculate next_check_time
    if not force and status:
        # Use cached data with calculated timing
        check_freq_minutes = cfg.get("check_freq", 5)
        if last_check_time:
            try:
                last_check_dt = datetime.fromisoformat(last_check_time)
                next_check_dt = last_check_dt + timedelta(minutes=check_freq_minutes)
                next_check_time = next_check_dt.isoformat()
            except Exception:
                # Fallback if time parsing fails
                next_check_dt = now + timedelta(minutes=check_freq_minutes)
                next_check_time = next_check_dt.isoformat()
        else:
            next_check_dt = now + timedelta(minutes=check_freq_minutes)
            next_check_time = next_check_dt.isoformat()

        # Return cached status with calculated timing
        return _status_payload(
            next_check_time=next_check_time,
            status_message=status.get("status_message", "OK"),
            mam_id=mam_id,
            configured=True,
            auto_update_seedbox=status.get("auto_update_seedbox"),
        )

    # Always perform a fresh status check and update both cache and YAML.
    # cfg/proxy_cfg from above are still current — nothing has written the session file since.
    _logger.debug(
        "[SessionCheck][TRIGGER] label=%s source=%s",
        label,
        "forced_api_status" if force else "auto_api_status",
    )
    mam_status = await get_status(mam_id=mam_id, proxy_cfg=proxy_cfg)
    # Persist refreshed cookie immediately so the reload below picks it up
    _refreshed_mam_id = mam_status.pop("updated_mam_id", None)
    if _refreshed_mam_id and _refreshed_mam_id != mam_id:
        _prev_mam_id = mam_id
        mam_id = _refreshed_mam_id
        cfg["mam"]["mam_id"] = _refreshed_mam_id
        await save_session(cfg, old_label=label)
        _logger.info("[SessionCheck] mam_id cookie auto-refreshed for session '%s'", label)
        await _sync_integrations_if_mam_id_changed(cfg, label, mam_id, _prev_mam_id)
    if "proxy_error" not in mam_status and proxy_error:
        mam_status["proxy_error"] = proxy_error
    mam_status["configured_ip"] = ip_to_use
    mam_status["configured_asn"] = asn
    mam_status["mam_seen_asn"] = mam_seen_asn
    mam_status["mam_seen_as"] = mam_seen_as
    # Auto-update logic
    # Skip auto-update for static/manual modes since they don't need IP monitoring
    if ip_monitoring_mode == "auto":
        auto_update_triggered, auto_update_result = await auto_update_seedbox_if_needed(
            cfg, label, ip_to_use, asn, now
        )
    else:
        auto_update_triggered, auto_update_result = False, None
        _logger.debug(
            "[Status] Skipping auto-update for session '%s' in %s mode",
            label,
            ip_monitoring_mode,
        )

    if auto_update_triggered and auto_update_result:
        mam_status["auto_update_seedbox"] = auto_update_result
        # Always persist the correct status_message after an update
        if auto_update_result.get("error"):
            mam_status["status_message"] = auto_update_result.get("error")
        elif auto_update_result.get("success") is True and (
            auto_update_result.get("msg") or auto_update_result.get("reason")
        ):
            mam_status["status_message"] = auto_update_result.get("msg") or auto_update_result.get(
                "reason"
            )
        else:
            mam_status["status_message"] = build_status_message(mam_status, ip_monitoring_mode)
    else:
        mam_status["status_message"] = build_status_message(mam_status, ip_monitoring_mode)
    # Update in-memory cache and YAML file with the latest status
    session_status_cache[label] = {"status": mam_status, "last_check_time": now.isoformat()}
    status = mam_status
    last_check_time = now.isoformat()
    # cfg already holds the in-place updates from the mam_id refresh and auto-update above.
    # Check for increments in hit & run and unsatisfied counts before saving new status
    await check_and_notify_count_increments(cfg, status)
    # Save last status to session file
    cfg["last_status"] = status
    cfg["last_check_time"] = last_check_time
    await save_session(cfg, old_label=label)
    # If not force and status exists, do NOT update last_check_time or next_check_time; use cached values

    # Only log an event if a real check was performed (force=1 or no cached status),
    # and suppress the very first status check event after session creation

    suppress_next_event = False
    if label in session_status_cache and session_status_cache[label].get("suppress_next_event"):
        suppress_next_event = True
        session_status_cache[label].pop("suppress_next_event", None)
    try:
        just_created_session = not bool(cfg.get("last_status")) and not bool(
            cfg.get("last_check_time")
        )
    except Exception:
        just_created_session = False
    if (
        (force or not (label in session_status_cache and session_status_cache[label].get("status")))
        and not just_created_session
        and not suppress_next_event
    ):
        prev_ip = cfg.get("last_seedbox_ip")
        prev_asn = cfg.get("last_seedbox_asn")
        proxied_ip = cfg.get("proxied_public_ip")
        mam_ip_override = cfg.get("mam_ip", "").strip()
        detected_ip = detected_public_ip
        curr_ip = mam_ip_override or proxied_ip or detected_ip
        asn_full, _ = await get_asn_and_timezone_from_ip(curr_ip) if curr_ip else (None, None)
        curr_asn = extract_asn_number(asn_full) or asn_full

        # Handle None ASN gracefully - if we can't determine ASN, preserve previous value for comparison
        if curr_asn is None or curr_asn == "Unknown ASN":
            curr_asn = prev_asn  # Use previous ASN to avoid false change notifications

        error_val = auto_update_result.get("error") if (auto_update_result) else None
        # If rate limit, show attempted new IP/ASN in event log
        if error_val and isinstance(error_val, str) and "rate limit" in error_val.lower():
            event_status_message = error_val
            attempted_ip = None
            attempted_asn = None
            if auto_update_result:
                reason = auto_update_result.get("reason", "")
                ip_match = re.search(r"IP changed: ([^ ]+) -> ([^ ]+)", reason)
                asn_match = re.search(r"ASN changed: ([^ ]+) -> ([^ ]+)", reason)
                if ip_match:
                    attempted_ip = ip_match.group(2)
                if asn_match:
                    attempted_asn = asn_match.group(2)
            if not attempted_ip:
                attempted_ip = proxied_ip or detected_ip
            if not attempted_asn:
                attempted_asn = curr_asn
            event_ip_compare = f"{prev_ip} -> {attempted_ip}"
            event_asn_compare = f"{prev_asn} -> {attempted_asn}"
        else:
            event_status_message = build_status_message(status, ip_monitoring_mode)
            event_ip_compare = f"{prev_ip} -> {curr_ip}"
            event_asn_compare = f"{prev_asn} -> {curr_asn}"
        # Determine event type
        if force:
            event_type = "manual"
        elif auto_update_result is not None:
            event_type = "automation"
        else:
            event_type = "scheduled"
        # All variables are defined in this scope, so log event here
        auto_update_val = get_auto_update_val(status)
        event = {
            "timestamp": now.isoformat(),
            "label": label,
            "event_type": event_type,
            "details": {
                "ip_compare": event_ip_compare,
                "asn_compare": event_asn_compare,
                "auto_update": auto_update_val,  # Always a string
            },
            # Always show the real update message if an update occurred
            "status_message": (
                (
                    auto_update_result.get("msg")
                    or auto_update_result.get("reason")
                    or "IP Changed. Seedbox IP updated."
                )
                if auto_update_result
                and auto_update_result.get("success")
                and (auto_update_result.get("msg") or auto_update_result.get("reason"))
                else status.get("status_message")
                or event_status_message
                or build_status_message(status)
            ),
        }
        await append_ui_event_log(event)
    # Always include the current session's saved proxy config in status
    status["proxy"] = await resolve_proxy_from_session_cfg(cfg) or {}

    # Always provide detected IP for user convenience, regardless of monitoring mode
    status["detected_public_ip"] = detected_public_ip
    status["detected_public_ip_asn"] = detected_public_ip_asn
    status["detected_public_ip_as"] = detected_public_ip_as

    status["proxied_public_ip"] = proxied_public_ip
    status["proxied_public_ip_asn"] = proxied_public_ip_asn
    # Reuse the AS from the single proxied lookup above instead of re-fetching.
    status["proxied_public_ip_as"] = proxied_public_ip_as
    # Always set the top-level status message for the UI, prioritizing error/rate limit, then success, then fallback
    if auto_update_result is not None:
        status["auto_update_seedbox"] = auto_update_result
        # Priority: error (rate limit or other)
        error_val = auto_update_result.get("error")
        if error_val and isinstance(error_val, str):
            status["status_message"] = error_val
        # Next: explicit success message or reason
        elif auto_update_result.get("success") is True and (
            auto_update_result.get("msg") or auto_update_result.get("reason")
        ):
            status["status_message"] = auto_update_result.get("msg") or auto_update_result.get(
                "reason"
            )
        # Fallback: use build_status_message
        else:
            status["status_message"] = build_status_message(status, ip_monitoring_mode)
    elif status.get("error"):
        status["status_message"] = f"Error: {status['error']}"
    elif status.get("message"):
        status["status_message"] = status["message"]
    else:
        status["status_message"] = build_status_message(status, ip_monitoring_mode)
    # Calculate next_check_time (UTC ISO format)
    check_freq_minutes = cfg.get("check_freq", 5)
    # Use cached last_check_time unless a real check was just performed
    try:
        parsed_last_check_dt: datetime | None = (
            datetime.fromisoformat(last_check_time) if last_check_time else None
        )
    except Exception:
        parsed_last_check_dt = None
    if not parsed_last_check_dt:
        # Fallback: use now as last_check_time if missing/invalid
        parsed_last_check_dt = now
        last_check_time = now.isoformat()
    # Only update next_check_time if a real check was performed
    if force or not status:
        next_check_dt = parsed_last_check_dt + timedelta(minutes=check_freq_minutes)
        next_check_time_val: str = next_check_dt.isoformat()
    else:
        # Use cached next_check_time if available
        cached_next_check_time: str | None = cfg.get("next_check_time")
        if not cached_next_check_time:
            # If not present, calculate from last_check_time
            next_check_dt = parsed_last_check_dt + timedelta(minutes=check_freq_minutes)
            next_check_time_val = next_check_dt.isoformat()
        else:
            next_check_time_val = cached_next_check_time
    return _status_payload(
        next_check_time=next_check_time_val,
        status_message=status.get("status_message"),
        ip_source="configured",
        message=status.get("message", "Please provide your MaM ID in the configuration."),
        timezone=TZ,
    )


@app.post("/api/session/refresh")
async def api_session_refresh() -> dict[str, Any]:
    """Trigger a lightweight session refresh.

    This validates that a global MaM ID is configured and returns a simple
    success message. Used by the frontend to verify that session data are
    available.
    """
    cfg = await load_config()
    mam_id = cfg.get("mam", {}).get("mam_id", "")
    if not mam_id:
        raise HTTPException(status_code=400, detail="MaM ID not configured.")
    return {"success": True, "message": "Session refreshed."}


@app.get("/api/sessions")
async def api_list_sessions() -> dict[str, Any]:
    """Return a list of saved session labels.

    Response format: {"sessions": [...labels...]}
    """
    sessions = await list_sessions()
    _logger.debug("[Session] Listed sessions: count=%s", len(sessions))
    return {"sessions": sessions}


@app.get("/api/session/{label}")
async def api_load_session(label: str) -> dict[str, Any]:
    """Load and return a session configuration by label.

    Raises HTTPException(404) if the session does not exist.
    """
    return await load_session(label)


@dataclass(frozen=True)
class _IndexerService:
    """One MAM-ID-syncable indexer integration."""

    name: str
    cfg_key: str
    sync: Callable[[dict[str, Any], str], Awaitable[dict[str, Any]]]


async def _sync_jackett(cfg: dict[str, Any], mam_id: str) -> dict[str, Any]:
    """Adapt Jackett's host/port/key config to the common (cfg, mam_id) sync interface."""
    jc = cfg.get("jackett", {})
    host = jc.get("host", "").strip()
    port = jc.get("port", 9117)
    api_key = jc.get("api_key", "").strip()
    admin_password = jc.get("admin_password", "").strip()
    if not all([host, port, api_key, admin_password]):
        return {"success": False, "error": "incomplete configuration"}
    return await sync_mam_id_to_jackett(host, port, api_key, admin_password, mam_id)


async def _sync_audiobookrequest(cfg: dict[str, Any], mam_id: str) -> dict[str, Any]:
    """Adapt AudioBookRequest's host/port/key config to the common sync interface."""
    ac = cfg.get("audiobookrequest", {})
    host = ac.get("host", "").strip()
    port = ac.get("port", 3000)
    api_key = ac.get("api_key", "").strip()
    if not all([host, port, api_key]):
        return {"success": False, "error": "incomplete configuration"}
    return await sync_mam_id_to_audiobookrequest(host, port, api_key, mam_id)


async def _sync_autobrr(cfg: dict[str, Any], mam_id: str) -> dict[str, Any]:
    """Adapt Autobrr's host/port/key config to the common sync interface."""
    ac = cfg.get("autobrr", {})
    host = ac.get("host", "").strip()
    port = ac.get("port", 7474)
    api_key = ac.get("api_key", "").strip()
    if not all([host, port, api_key]):
        return {"success": False, "error": "incomplete configuration"}
    return await sync_mam_id_to_autobrr(host, port, api_key, mam_id)


_INDEXER_SERVICES: list[_IndexerService] = [
    _IndexerService("Prowlarr", "prowlarr", sync_mam_id_to_prowlarr),
    _IndexerService("Chaptarr", "chaptarr", sync_mam_id_to_chaptarr),
    _IndexerService("Jackett", "jackett", _sync_jackett),
    _IndexerService("AudioBookRequest", "audiobookrequest", _sync_audiobookrequest),
    _IndexerService("Autobrr", "autobrr", _sync_autobrr),
]


async def _sync_indexers(
    cfg: dict[str, Any],
    mam_id: str,
    label: str,
    *,
    require_auto_update_on_save: bool,
    verbose: bool,
    prev_mam_id: str | None = None,
) -> tuple[list[str], list[str]]:
    """Sync `mam_id` to every enabled indexer service, returning (updated, failed) names.

    `require_auto_update_on_save` additionally gates each service on its
    `auto_update_on_save` flag; `verbose` emits per-service info/warning logs.
    """
    updated: list[str] = []
    failed: list[str] = []
    for svc in _INDEXER_SERVICES:
        svc_cfg = cfg.get(svc.cfg_key, {})
        enabled = svc_cfg.get("enabled")
        if require_auto_update_on_save:
            enabled = enabled and svc_cfg.get("auto_update_on_save")
        if not enabled:
            continue
        if verbose:
            _logger.info(
                "[%s] Auto-update triggered for session '%s' (MAM ID changed: %s -> %s)",
                svc.name,
                label,
                prev_mam_id,
                mam_id,
            )
        try:
            result = await svc.sync(cfg, mam_id)
            if result.get("success"):
                if verbose:
                    _logger.info("[%s] Auto-update successful: %s", svc.name, result.get("message"))
                updated.append(svc.name)
            else:
                detail = result.get("error") or result.get("message") or "Unknown error"
                if verbose:
                    _logger.warning("[%s] Auto-update failed: %s", svc.name, detail)
                failed.append(f"{svc.name} ({detail})")
        except Exception as e:
            _logger.error("[%s] MAM ID sync error for session '%s': %s", svc.name, label, e)
            failed.append(f"{svc.name} ({e!s})")
    return updated, failed


async def _sync_integrations_if_mam_id_changed(
    cfg: dict[str, Any], label: str, new_mam_id: str | None, prev_mam_id: str | None
) -> None:
    """Push updated mam_id to all enabled integrations when it has changed."""
    any_enabled = any(
        cfg.get(svc.cfg_key, {}).get("enabled")
        and cfg.get(svc.cfg_key, {}).get("auto_update_on_save")
        for svc in _INDEXER_SERVICES
    )
    if not (any_enabled and new_mam_id and new_mam_id != prev_mam_id):
        if new_mam_id == prev_mam_id:
            _logger.debug(
                "[Indexers] Auto-update skipped for session '%s' (MAM ID unchanged: %s)",
                label,
                new_mam_id,
            )
        else:
            _logger.debug(
                "[Indexers] Auto-update skipped for session '%s' (no MAM ID provided or unchanged)",
                label,
            )
        return

    updated_services, failed_services = await _sync_indexers(
        cfg,
        new_mam_id,
        label,
        require_auto_update_on_save=True,
        verbose=True,
        prev_mam_id=prev_mam_id,
    )

    # Log event with detailed message
    if updated_services:
        status_msg = f"MAM ID synced to {', '.join(updated_services)}"
        if failed_services:
            status_msg += f". Failed: {', '.join(failed_services)}"
        await append_ui_event_log(
            {
                "event": "indexer_auto_updated",
                "label": label,
                "timestamp": datetime.now(UTC).isoformat(),
                "user_action": False,
                "status_message": status_msg,
            }
        )
    elif failed_services:
        await append_ui_event_log(
            {
                "event": "indexer_auto_update_failed",
                "label": label,
                "timestamp": datetime.now(UTC).isoformat(),
                "user_action": False,
                "status_message": f"Failed to sync MAM ID: {', '.join(failed_services)}",
            }
        )


async def _load_prev_session(old_label: str | None, label: str | None) -> dict[str, Any] | None:
    """Load the previous session config by ``old_label`` (preferred) or ``label``; None on any failure."""
    target = old_label or label
    if not target:
        return None
    try:
        return await load_session(target)
    except Exception:
        return None


@app.post("/api/session/save")
async def api_save_session(request: Request) -> dict[str, Any]:
    """Save or update a session configuration.

    This endpoint merges backend-managed fields from previous configs,
    preserves sensitive proxy passwords if omitted, persists the session
    YAML, and re-registers scheduler jobs as needed.
    """
    try:
        cfg = await request.json()
        old_label = cfg.get("old_label")
        proxy_cfg = cfg.get("proxy", {}) or {}
        prev_cfg = None

        if "proxy" in cfg:
            prev_cfg = await _load_prev_session(old_label, cfg.get("label"))
            # If password is missing but previous session had one, keep it
            if (
                isinstance(proxy_cfg, dict)
                and (not proxy_cfg.get("password"))
                and prev_cfg
                and prev_cfg.get("proxy", {})
                and prev_cfg.get("proxy", {}).get("password")
            ):
                proxy_cfg["password"] = prev_cfg["proxy"]["password"]
            cfg["proxy"] = proxy_cfg

        # Merge backend-managed fields from previous config unless explicitly overwritten
        backend_fields = [
            "last_seedbox_ip",
            "last_seedbox_asn",
            "last_seedbox_update",
            "last_status",
            "last_check_time",
            "proxied_public_ip",
            "proxied_public_ip_asn",
            "points",
            "vip_active",
            "perk_automation",
        ]
        # If prev_cfg not set above, try to load it now
        if prev_cfg is None:
            prev_cfg = await _load_prev_session(old_label, cfg.get("label"))
        if prev_cfg:
            for field in backend_fields:
                if field in prev_cfg and field not in cfg:
                    cfg[field] = prev_cfg[field]

        label = cfg.get("label")
        if not get_session_path(label).exists():
            # Clear any old event log entries for this session label

            await clear_ui_event_log_for_session(label)
            # Only log creation event
            await save_session(cfg, old_label=old_label)
            _logger.info("[Session] Created session: label=%s", label)
            await append_ui_event_log(
                {
                    "event": "session_created",
                    "label": label,
                    "timestamp": datetime.now(UTC).isoformat(),
                    "user_action": True,
                    "status_message": f"Session '{label}' created.",
                }
            )
            # Suppress the first status check event
            if label:
                session_status_cache[label] = session_status_cache.get(label, {})
                session_status_cache[label]["suppress_next_event"] = True
        else:
            # Only log save event (update)
            await save_session(cfg, old_label=old_label)
            _logger.info("[Session] Saved session: label=%s old_label=%s", label, old_label)
            await append_ui_event_log(
                {
                    "event": "session_saved",
                    "label": label,
                    "old_label": old_label,
                    "timestamp": datetime.now(UTC).isoformat(),
                    "user_action": True,
                    "status_message": f"Session '{label}' saved.",
                }
            )

        # Handle session job management for label changes and updates
        try:
            # If label changed, remove the old job
            if old_label and old_label != label:
                old_job_id = f"session_check_{old_label}"
                if scheduler.get_job(old_job_id):
                    scheduler.remove_job(old_job_id)
                    _logger.info("[APScheduler] Removed job for renamed session '%s'", old_label)

            # Register/update the job for the current session
            await register_session_job(label)
        except Exception as e:
            _logger.error(
                "[APScheduler] Failed to manage session job for '%s' after save: %s", label, e
            )

        # Auto-update integrations if MAM ID changed
        new_mam_id = cfg.get("mam", {}).get("mam_id")
        prev_mam_id = prev_cfg.get("mam", {}).get("mam_id") if prev_cfg else None
        await _sync_integrations_if_mam_id_changed(cfg, label, new_mam_id, prev_mam_id)

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save session: {e}") from e
    else:
        return {"success": True}


@app.delete("/api/session/delete/{label}")
async def api_delete_session(label: str) -> dict[str, Any]:
    """Delete a session by label and clear related UI event log entries.

    Returns a success flag or raises HTTPException on failure.
    """
    try:
        await delete_session(label)
        await clear_ui_event_log_for_session(label)
        # If no sessions remain, blank out last_session.yaml
        if len(await list_sessions()) == 0:
            await write_last_session(None)
        _logger.info("[Session] Deleted session: label=%s", label)
        await append_ui_event_log(
            {
                "event": "session_deleted",
                "label": label,
                "timestamp": datetime.now(UTC).isoformat(),
                "user_action": True,
                "status_message": f"Session '{label}' deleted.",
            }
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete session: {e}") from e
    else:
        return {"success": True}


@app.post("/api/session/perkautomation/save")
async def api_save_perkautomation(request: Request) -> dict[str, Any]:
    """Save perk automation settings for a session.

    Handles time-based triggers by setting or clearing last_purchase timestamps
    as appropriate, then persists the session config.
    """
    try:
        data = await request.json()
        label = data.get("label")
        if not label:
            raise HTTPException(status_code=400, detail="Session label required.")
        cfg = await load_session(label)
        # Save automation settings to session config
        new_pa = data.get("perk_automation", {})
        old_pa = cfg.get("perk_automation", {})
        now_iso = datetime.now(UTC).isoformat()

        # Helper: set/clear last_purchase timestamps for time-based automations
        def handle_time_trigger(automation_key: str) -> None:
            """Helper to set or clear last_purchase timestamps for an automation.

            This nested helper mutates the passed session automation config
            entry in-place based on whether the automation is enabled and its
            trigger type.
            """
            auto = new_pa.get(automation_key, {})
            enabled = auto.get("enabled", False)
            trigger_type = auto.get("trigger_type", "time")
            # Map automation_key to new timestamp field
            ts_field = {
                "upload_credit": "last_upload_time",
                "vip_automation": "last_vip_time",
                "wedge_automation": "last_wedge_time",
            }.get(automation_key)
            if not ts_field:
                return
            # If disabling, always clear timestamp
            if not enabled:
                if ts_field in auto:
                    auto.pop(ts_field, None)
                if ts_field in cfg.get("perk_automation", {}).get(automation_key, {}):
                    cfg["perk_automation"][automation_key].pop(ts_field, None)
                return
            # If enabling and time-based, set timestamp if missing
            if (
                enabled
                and trigger_type in ("time", "both")
                and not old_pa.get(automation_key, {}).get(ts_field)
            ):
                auto[ts_field] = now_iso
                _logger.info(
                    "[PerkAutomation] Timer initialized for '%s' automation in session '%s' at %s (settings save, not a purchase).",
                    automation_key,
                    label,
                    now_iso,
                )

        handle_time_trigger("upload_credit")
        handle_time_trigger("vip_automation")
        handle_time_trigger("wedge_automation")

        cfg["perk_automation"] = new_pa
        await save_session(cfg, old_label=label)
        _logger.info("[PerkAutomation] Saved automation settings for session '%s'.", label)
        await append_ui_event_log(
            {
                "event_type": "config",
                "label": label,
                "timestamp": now_iso,
                "user_action": True,
                "status_message": f"Perk automation settings saved for session '{label}'.",
            }
        )

    except Exception as e:
        _logger.warning("[PerkAutomation] Failed to save automation settings: %s", e)
        return {"success": False, "error": str(e)}
    else:
        return {"success": True}


@app.post("/api/session/update_seedbox")
async def api_update_seedbox(request: Request) -> dict[str, Any]:
    """Force-update the seedbox IP/ASN for a session using an entered IP.

    Validates input, performs the MaM API request, and updates the session
    config if the seedbox response indicates a change.
    """
    try:
        data = await request.json()
        label = data.get("label")
        if not label:
            raise HTTPException(status_code=400, detail="Session label required.")
        cfg = await load_session(label)
        mam_id = cfg.get("mam", {}).get("mam_id", "")
        if not mam_id:
            raise HTTPException(status_code=400, detail="MaM ID not configured in session.")
        mam_ip_override = cfg.get("mam_ip", "").strip()
        if not mam_ip_override:
            raise HTTPException(status_code=400, detail="Session mam_ip (entered IP) is required.")
        ip_to_use = mam_ip_override
        asn_full, _ = await get_asn_and_timezone_from_ip(ip_to_use)
        asn = extract_asn_number(asn_full) or asn_full
        last_seedbox_ip = cfg.get("last_seedbox_ip")
        last_seedbox_asn = cfg.get("last_seedbox_asn")
        last_seedbox_update = cfg.get("last_seedbox_update")
        now = datetime.now(UTC)
        update_needed = (ip_to_use != last_seedbox_ip) or (asn != last_seedbox_asn)
        if last_seedbox_update:
            last_update_dt = datetime.fromisoformat(last_seedbox_update)
            if (now - last_update_dt) < timedelta(hours=1):
                minutes_left = 60 - int((now - last_update_dt).total_seconds() // 60)
                return {
                    "success": False,
                    "error": f"Rate limit: wait {minutes_left} more minutes before updating seedbox IP/ASN.",
                }
        if not update_needed:
            return {"success": True, "msg": "No change: IP/ASN already set."}
        # Proxy config: always resolve from proxies.yaml using session config

        proxy_cfg = await resolve_proxy_from_session_cfg(cfg)
        cookies = {"mam_id": mam_id}
        proxies = None
        if proxy_cfg:
            proxies = build_proxy_dict(proxy_cfg)
        # Log proxy label and redacted URL for debugging
        if proxy_cfg and proxies:
            _logger.debug(
                "[SeedboxUpdate] Using proxy label: %s, proxies: %s",
                proxy_cfg.get("label"),
                redact_proxy_urls(proxies, proxy_cfg),
            )

        timeout = aiohttp.ClientTimeout(total=10)
        proxy_url = None
        if proxies:
            proxy_url = proxies.get("https") or proxies.get("http")
        try:
            async with (
                aiohttp.ClientSession(cookies=cookies) as session,
                session.get(
                    "https://t.myanonamouse.net/json/dynamicSeedbox.php",
                    timeout=timeout,
                    proxy=proxy_url,
                ) as resp,
            ):
                resp_status = resp.status
                resp_text = await resp.text()
                try:
                    result = await resp.json()
                except Exception:
                    result = {"Success": False, "msg": f"Non-JSON response: {resp_text}"}
        except Exception as e:
            _logger.warning("[SeedboxUpdate] HTTP request failed: %s", e)
            return {"success": False, "error": str(e)}

        _logger.info("[SeedboxUpdate] MaM API response: status=%s, text=%s", resp_status, resp_text)
        if resp_status == 200 and result.get("Success"):
            cfg["last_seedbox_ip"] = ip_to_use
            cfg["last_seedbox_asn"] = asn
            cfg["last_seedbox_update"] = now.isoformat()
            await save_session(cfg, old_label=label)
            # Use a user-friendly message if the API message is missing or generic
            api_msg = str(result.get("msg", "")).strip()
            if not api_msg or api_msg.lower() == "completed":
                api_msg = "IP Changed. Seedbox IP updated."
            return {"success": True, "msg": api_msg, "ip": ip_to_use, "asn": asn}
        if resp_status == 200 and result.get("msg") == "No change":
            cfg["last_seedbox_ip"] = ip_to_use
            cfg["last_seedbox_asn"] = asn
            cfg["last_seedbox_update"] = now.isoformat()
            await save_session(cfg, old_label=label)
            return {
                "success": True,
                "msg": "No change: IP/ASN already set.",
                "ip": ip_to_use,
                "asn": asn,
            }
        if resp_status == 429 or ("too recent" in str(result.get("msg", ""))):
            return {
                "success": False,
                "error": "Rate limit: last change too recent. Try again later.",
                "msg": result.get("msg"),
            }
        return {"success": False, "error": result.get("msg", "Unknown error"), "raw": result}
    except Exception as e:
        _logger.error("[SeedboxUpdate] Failed: %s", e)
        return {"success": False, "error": str(e)}


# PROWLARR INTEGRATION ENDPOINTS


@app.post("/api/prowlarr/test_expiry_notification")
async def api_test_expiry_notification(request: Request) -> dict[str, Any]:
    """Manually trigger a test MAM session expiry notification.

    Expects JSON with: label (session label)
    This is for testing the notification system without waiting for actual expiry.
    """
    try:
        data = await request.json()
        label = data.get("label", "").strip()

        if not label:
            return {"success": False, "message": "Session label required"}

        # Load session
        cfg = await load_session(label)
        if not cfg:
            return {"success": False, "message": f"Session '{label}' not found"}

        prowlarr_cfg = cfg.get("prowlarr", {})
        if not prowlarr_cfg.get("enabled"):
            return {"success": False, "message": "Prowlarr not enabled for this session"}

        # Get created date or simulate one
        created_date_str = cfg.get("mam_session_created_date")
        if created_date_str:
            try:
                created_date = datetime.fromisoformat(created_date_str)
            except Exception:
                created_date = datetime.now(UTC) - timedelta(days=25)
        else:
            # Simulate a session expiring in 5 days
            created_date = datetime.now(UTC) - timedelta(days=25)

        expiry_date = created_date + timedelta(days=30)
        days_until_expiry = (expiry_date - datetime.now(UTC)).days

        # Get MAM ID and redact for security
        mam_id = cfg.get("mam", {}).get("mam_id", "N/A")
        redacted_mam_id = redact_mam_id(mam_id) if mam_id != "N/A" else "N/A"

        # Prepare test notification message
        message = (
            f"⚠️ MAM Session Expiring Soon! [TEST NOTIFICATION]\n\n"
            f"Session: {label}\n"
            f"{redacted_mam_id}\n"
            f"Created: {created_date.strftime('%Y-%m-%d %H:%M')}\n"
            f"Expires: {expiry_date.strftime('%Y-%m-%d %H:%M')}\n"
            f"Days Remaining: {days_until_expiry} day{'s' if days_until_expiry != 1 else ''}\n\n"
            f"You will need to refresh your MAM session and update Prowlarr.\n"
        )

        if prowlarr_cfg.get("host"):
            message += f"Prowlarr: {prowlarr_cfg['host']}:{prowlarr_cfg.get('port', 9696)}"

        details = {
            "session_label": label,
            "mam_id": redacted_mam_id,  # Use redacted version in details too
            "created_date": created_date.isoformat(),
            "expiry_date": expiry_date.isoformat(),
            "days_remaining": days_until_expiry,
            "prowlarr_host": prowlarr_cfg.get("host", "N/A"),
            "test_notification": True,
        }

        _logger.info("[Prowlarr] Sending test expiry notification for session '%s'", label)

        # Send test notification
        await notify_event(
            event_type="mam_session_expiry",
            label=label,
            status="WARNING",
            message=message,
            details=details,
        )

        return {
            "success": True,
            "message": f"Test notification sent for session '{label}'",
            "details": {
                "created": created_date.strftime("%Y-%m-%d %H:%M"),
                "expires": expiry_date.strftime("%Y-%m-%d %H:%M"),
                "days_remaining": days_until_expiry,
            },
        }

    except Exception as e:
        _logger.exception("[Prowlarr] Failed to send test expiry notification")
        return {"success": False, "message": f"Error: {e!s}"}


@app.post("/api/session/test_asn_notifications")
async def api_test_asn_notifications(request: Request) -> dict[str, Any]:
    """Manually trigger test ASN mismatch notification for ASN Locked sessions.

    Expects JSON with: label (session label)
    Note: Only sends ASN mismatch (403 error) notification, as ASN change
    notifications are suppressed for ASN Locked sessions.
    """
    label = ""
    try:
        data = await request.json()
        label = data.get("label", "").strip()

        if not label:
            return {"success": False, "message": "Session label required"}

        # Load session
        cfg = await load_session(label)
        if not cfg:
            return {"success": False, "message": f"Session '{label}' not found"}

        session_type = cfg.get("mam", {}).get("session_type", "").lower()

        if session_type != "asn locked":
            return {
                "success": False,
                "message": f"Session '{label}' is not ASN Locked (current type: {session_type}). ASN notifications only apply to ASN Locked sessions.",
            }

        # Simulate ASN values
        old_asn = "11878"
        new_asn = "63018"

        # Test ASN Mismatch on 403 Error notification
        enhanced_msg = (
            f"[TEST NOTIFICATION]\n\n"
            f"Invalid session - Other\n\n"
            f"⚠️ ASN Mismatch Detected!\n"
            f"Your session is ASN Locked but the ASN has changed: {old_asn} → {new_asn}\n\n"
            f"Action Required:\n"
            f"1. Log into MyAnonamouse.net → Preferences → Security\n"
            f"2. Find your seedbox session and click 'Manage Session'\n"
            f"3. Under 'Add additional ASN via IP address', enter an IP from ASN {new_asn}\n"
            f"4. MAM will detect and add the ASN to your session automatically\n"
            f"5. Your existing mam_id cookie will work once the ASN is added\n\n"
            f"Note: If the cookie was already invalidated, you may need to generate a new one after updating"
        )

        await notify_event(
            event_type="seedbox_update_failure",
            label=label,
            status="FAILED",
            message=enhanced_msg,
            details={
                "reason": "IP changed: test -> test",
                "old_asn": old_asn,
                "new_asn": new_asn,
                "session_type": "ASN Locked",
                "action_required": "Update MAM session and refresh mam_id cookie",
                "test_notification": True,
            },
        )
    except Exception as e:
        _logger.error(
            "Failed to send test ASN mismatch notification for session '%s': %s",
            label,
            e,
        )
        return {"success": False, "error": str(e)}
    else:
        return {
            "success": True,
            "message": f"Test ASN mismatch notification sent for session '{label}'",
        }


@app.post("/api/prowlarr/test")
async def api_prowlarr_test(request: Request) -> dict[str, Any]:
    """Test Prowlarr API connectivity.

    Expects JSON with: host, port, api_key
    """
    try:
        data = await request.json()
        host = data.get("host", "").strip()
        port = data.get("port")
        api_key = data.get("api_key", "").strip()

        _logger.debug(
            "[Prowlarr] Test connection request - host: %s, port: %s (type: %s), api_key: %s",
            host,
            port,
            type(port).__name__,
            "***" + api_key[-4:] if api_key and len(api_key) > 4 else "***",
        )

        if not host or port is None or not api_key:
            return {"success": False, "message": "Missing required fields"}

        # Test connection and find MAM indexer
        conn_result = await test_prowlarr_connection(host, port, api_key)
        if not conn_result["success"]:
            return conn_result

        # If connection successful, try to find MAM indexer
        indexer_result = await find_mam_indexer_id(host, port, api_key)
        if indexer_result["success"]:
            # Merge results: keep connection success, add indexer_id
            return {
                "success": True,
                "message": conn_result["message"],
                "indexer_count": conn_result.get("indexer_count"),
                "indexer_id": indexer_result.get("indexer_id"),
            }

        # MAM indexer not found, but connection was successful
        return {
            "success": True,
            "message": f"{conn_result['message']} However, MyAnonamouse indexer not found.",
            "indexer_count": conn_result.get("indexer_count"),
            "warning": indexer_result.get("message"),
        }
    except Exception as e:
        _logger.exception("Prowlarr test failed")
        return {"success": False, "message": f"Error: {e!s}"}


@app.post("/api/prowlarr/find_indexer")
async def api_prowlarr_find_indexer(request: Request) -> dict[str, Any]:
    """Find MyAnonamouse indexer ID in Prowlarr.

    Expects JSON with: host, port, api_key
    """
    try:
        data = await request.json()
        host = data.get("host", "").strip()
        port = data.get("port")
        api_key = data.get("api_key", "").strip()

        if not all([host, port, api_key]):
            return {"success": False, "message": "Missing required fields"}

        return await find_mam_indexer_id(host, port, api_key)
    except Exception as e:
        _logger.exception("Failed to find MAM indexer")
        return {"success": False, "message": f"Error: {e!s}"}


@app.post("/api/prowlarr/update")
async def api_prowlarr_update(request: Request) -> dict[str, Any]:
    """Update MAM ID in Prowlarr for a session.

    Expects JSON with:
    - label: session label
    - mam_id: (optional) new MAM ID to sync. If not provided, uses session's MAM ID.
    """
    try:
        data = await request.json()
        label = data.get("label")
        if not label:
            return {"success": False, "message": "Session label required"}

        cfg = await load_session(label)

        # Use provided mam_id or fall back to session config
        mam_id = data.get("mam_id") or cfg.get("mam", {}).get("mam_id", "")
        if not mam_id:
            return {
                "success": False,
                "message": "MAM ID not configured in session and not provided",
            }

        result = await sync_mam_id_to_prowlarr(cfg, mam_id)
        if result["success"]:
            # Log success event
            await append_ui_event_log(
                {
                    "event": "prowlarr_manual_update",
                    "label": label,
                    "event_type": "prowlarr_update",
                    "status_message": f"Updated Prowlarr MAM ID to {mam_id}",
                    "user_action": True,
                    "timestamp": datetime.now(UTC).isoformat(),
                }
            )
        return result
    except Exception as e:
        _logger.exception("Failed to update Prowlarr")
        return {"success": False, "message": f"Error: {e!s}"}


@app.post("/api/chaptarr/test")
async def api_chaptarr_test(request: Request) -> dict[str, Any]:
    """Test Chaptarr API connectivity.

    Expects JSON with: host, port, api_key
    """
    try:
        data = await request.json()
        host = data.get("host", "").strip()
        port = data.get("port")
        api_key = data.get("api_key", "").strip()

        _logger.debug(
            "[Chaptarr] Test connection request - host: %s, port: %s (type: %s), api_key: %s",
            host,
            port,
            type(port).__name__,
            "***" + api_key[-4:] if api_key and len(api_key) > 4 else "***",
        )

        if not host or port is None or not api_key:
            return {"success": False, "message": "Missing required fields"}

        # Test connection and find MAM indexer
        conn_result = await test_chaptarr_connection(host, port, api_key)
        if not conn_result["success"]:
            return conn_result

        # If connection successful, try to find MAM indexer
        indexer_result = await find_mam_indexer_id_chaptarr(host, port, api_key)
        if indexer_result["success"]:
            # Merge results: keep connection success, add indexer_id
            return {
                "success": True,
                "message": conn_result["message"],
                "indexer_count": conn_result.get("indexer_count"),
                "indexer_id": indexer_result.get("indexer_id"),
            }

        # MAM indexer not found, but connection was successful
        return {
            "success": True,
            "message": f"{conn_result['message']} However, MyAnonaMouse indexer not found.",
            "indexer_count": conn_result.get("indexer_count"),
            "warning": indexer_result.get("message"),
        }
    except Exception as e:
        _logger.exception("Chaptarr test failed")
        return {"success": False, "message": f"Error: {e!s}"}


@app.post("/api/chaptarr/update")
async def api_chaptarr_update(request: Request) -> dict[str, Any]:
    """Update MAM ID in Chaptarr for a session.

    Expects JSON with:
    - label: session label
    - mam_id: (optional) new MAM ID to sync. If not provided, uses session's MAM ID.
    """
    try:
        data = await request.json()
        label = data.get("label")
        if not label:
            return {"success": False, "message": "Session label required"}

        cfg = await load_session(label)

        # Use provided mam_id or fall back to session config
        mam_id = data.get("mam_id") or cfg.get("mam", {}).get("mam_id", "")
        if not mam_id:
            return {
                "success": False,
                "message": "MAM ID not configured in session and not provided",
            }

        result = await sync_mam_id_to_chaptarr(cfg, mam_id)
        if result["success"]:
            # Log success event
            await append_ui_event_log(
                {
                    "event": "chaptarr_manual_update",
                    "label": label,
                    "event_type": "chaptarr_update",
                    "status_message": f"Updated Chaptarr MAM ID to {mam_id}",
                    "user_action": True,
                    "timestamp": datetime.now(UTC).isoformat(),
                }
            )
        return result
    except Exception as e:
        _logger.exception("Failed to update Chaptarr")
        return {"success": False, "message": f"Error: {e!s}"}


@app.post("/api/jackett/test")
async def api_jackett_test(request: Request) -> dict[str, Any]:
    """Test Jackett API connectivity with admin authentication.

    Expects JSON with: host, port, api_key, admin_password
    """
    try:
        data = await request.json()
        host = data.get("host", "").strip()
        port = data.get("port")
        api_key = data.get("api_key", "").strip()
        admin_password = data.get("admin_password", "").strip()

        _logger.debug(
            "[Jackett] Test connection request - host: %s, port: %s",
            host,
            port,
        )

        if not host or port is None or not api_key:
            return {"success": False, "message": "Missing required fields (host, port, api_key)"}

        # Test API connection with optional authentication
        return await test_jackett_connection(host, port, api_key, admin_password or "")
    except Exception as e:
        _logger.exception("Jackett test failed")
        return {"success": False, "message": f"Error: {e!s}"}


@app.post("/api/jackett/update")
async def api_jackett_update(request: Request) -> dict[str, Any]:
    """Update MAM ID in Jackett for a session via API.

    Expects JSON with:
    - label: session label
    - mam_id: (optional) new MAM ID to sync. If not provided, uses session's MAM ID.
    """
    try:
        data = await request.json()
        label = data.get("label")
        if not label:
            return {"success": False, "message": "Session label required"}

        cfg = await load_session(label)

        # Use provided mam_id or fall back to session config
        mam_id = data.get("mam_id") or cfg.get("mam", {}).get("mam_id", "")
        if not mam_id:
            return {
                "success": False,
                "message": "MAM ID not configured in session and not provided",
            }

        # Get Jackett config from session
        jackett_cfg = cfg.get("jackett", {})
        if not jackett_cfg.get("enabled"):
            return {"success": False, "message": "Jackett integration not enabled"}

        host = jackett_cfg.get("host", "").strip()
        port = jackett_cfg.get("port", 9117)
        api_key = jackett_cfg.get("api_key", "").strip()
        admin_password = jackett_cfg.get("admin_password", "").strip()

        if not all([host, port, api_key, admin_password]):
            return {
                "success": False,
                "message": "Jackett configuration incomplete (host, port, api_key, admin_password required)",
            }

        result = await sync_mam_id_to_jackett(host, port, api_key, admin_password, mam_id)
        if result.get("success"):
            # Log success event
            await append_ui_event_log(
                {
                    "event": "jackett_manual_update",
                    "label": label,
                    "event_type": "jackett_update",
                    "status_message": f"Updated Jackett MAM ID to {mam_id}",
                    "user_action": True,
                    "timestamp": datetime.now(UTC).isoformat(),
                }
            )
        return result
    except Exception as e:
        _logger.exception("Failed to update Jackett")
        return {"success": False, "message": f"Error: {e!s}"}


@app.post("/api/audiobookrequest/test")
async def api_audiobookrequest_test(request: Request) -> dict[str, Any]:
    """Test AudioBookRequest API connectivity.

    Expects JSON with: host, port, api_key
    """
    try:
        data = await request.json()
        host = data.get("host", "").strip()
        port = data.get("port")
        api_key = data.get("api_key", "").strip()

        _logger.debug(
            "[AudioBookRequest] Test connection request - host: %s, port: %s",
            host,
            port,
        )

        if not host or port is None or not api_key:
            return {"success": False, "message": "Missing required fields (host, port, api_key)"}

        return await test_audiobookrequest_connection(host, port, api_key)
    except Exception as e:
        _logger.exception("AudioBookRequest test failed")
        return {"success": False, "message": f"Error: {e!s}"}


@app.post("/api/audiobookrequest/update")
async def api_audiobookrequest_update(request: Request) -> dict[str, Any]:
    """Update MAM ID in AudioBookRequest for a session.

    Expects JSON with:
    - label: session label
    - mam_id: (optional) new MAM ID to sync. If not provided, uses session's MAM ID.
    """
    try:
        data = await request.json()
        label = data.get("label")
        if not label:
            return {"success": False, "message": "Session label required"}

        cfg = await load_session(label)

        # Use provided mam_id or fall back to session config
        mam_id = data.get("mam_id") or cfg.get("mam", {}).get("mam_id", "")
        if not mam_id:
            return {
                "success": False,
                "message": "MAM ID not configured in session and not provided",
            }

        # Get AudioBookRequest config from session
        abr_cfg = cfg.get("audiobookrequest", {})
        if not abr_cfg.get("enabled"):
            return {"success": False, "message": "AudioBookRequest integration not enabled"}

        host = abr_cfg.get("host", "").strip()
        port = abr_cfg.get("port", 3000)
        api_key = abr_cfg.get("api_key", "").strip()

        if not all([host, port, api_key]):
            return {
                "success": False,
                "message": "AudioBookRequest configuration incomplete (host, port, api_key required)",
            }

        result = await sync_mam_id_to_audiobookrequest(host, port, api_key, mam_id)
        if result.get("success"):
            # Log success event
            await append_ui_event_log(
                {
                    "event": "audiobookrequest_manual_update",
                    "label": label,
                    "event_type": "audiobookrequest_update",
                    "status_message": f"Updated AudioBookRequest MAM ID to {mam_id}",
                    "user_action": True,
                    "timestamp": datetime.now(UTC).isoformat(),
                }
            )
        return result
    except Exception as e:
        _logger.exception("Failed to update AudioBookRequest")
        return {"success": False, "message": f"Error: {e!s}"}


@app.post("/api/autobrr/test")
async def api_autobrr_test(request: Request) -> dict[str, Any]:
    """Test Autobrr API connectivity.

    Expects JSON with: host, port, api_key
    """
    try:
        data = await request.json()
        host = data.get("host", "").strip()
        port = data.get("port")
        api_key = data.get("api_key", "").strip()

        _logger.debug(
            "[Autobrr] Test connection request - host: %s, port: %s",
            host,
            port,
        )

        if not host or port is None or not api_key:
            return {"success": False, "message": "Missing required fields (host, port, api_key)"}

        return await test_autobrr_connection(host, port, api_key)
    except Exception as e:
        _logger.exception("Autobrr test failed")
        return {"success": False, "message": f"Error: {e!s}"}


@app.post("/api/autobrr/update")
async def api_autobrr_update(request: Request) -> dict[str, Any]:
    """Update MAM ID in Autobrr for a session.

    Expects JSON with:
    - label: session label
    - mam_id: (optional) new MAM ID to sync. If not provided, uses session's MAM ID.
    """
    try:
        data = await request.json()
        label = data.get("label")
        if not label:
            return {"success": False, "message": "Session label required"}

        cfg = await load_session(label)

        # Use provided mam_id or fall back to session config
        mam_id = data.get("mam_id") or cfg.get("mam", {}).get("mam_id", "")
        if not mam_id:
            return {
                "success": False,
                "message": "MAM ID not configured in session and not provided",
            }

        # Get Autobrr config from session
        autobrr_cfg = cfg.get("autobrr", {})
        if not autobrr_cfg.get("enabled"):
            return {"success": False, "message": "Autobrr integration not enabled"}

        host = autobrr_cfg.get("host", "").strip()
        port = autobrr_cfg.get("port", 7474)
        api_key = autobrr_cfg.get("api_key", "").strip()

        if not all([host, port, api_key]):
            return {
                "success": False,
                "message": "Autobrr configuration incomplete (host, port, api_key required)",
            }

        result = await sync_mam_id_to_autobrr(host, port, api_key, mam_id)
        if result.get("success"):
            # Log success event
            await append_ui_event_log(
                {
                    "event": "autobrr_manual_update",
                    "label": label,
                    "event_type": "autobrr_update",
                    "status_message": f"Updated Autobrr MAM ID to {mam_id}",
                    "user_action": True,
                    "timestamp": datetime.now(UTC).isoformat(),
                }
            )
        return result
    except Exception as e:
        _logger.exception("Failed to update Autobrr")
        return {"success": False, "message": f"Error: {e!s}"}


@app.post("/api/indexer/update")
async def api_indexer_update(request: Request) -> dict[str, Any]:
    """Update MAM ID in configured indexer(s) (Prowlarr, Chaptarr, Jackett, AudioBookRequest, and/or Autobrr).

    This is the unified endpoint that updates whichever services are enabled.

    Expects JSON with:
    - label: session label
    - mam_id: (optional) new MAM ID to sync. If not provided, uses session's MAM ID.
    """
    try:
        data = await request.json()
        label = data.get("label")
        if not label:
            return {"success": False, "message": "Session label required"}

        cfg = await load_session(label)

        # Use provided mam_id or fall back to session config
        mam_id = data.get("mam_id") or cfg.get("mam", {}).get("mam_id", "")
        if not mam_id:
            return {
                "success": False,
                "message": "MAM ID not configured in session and not provided",
            }

        if not any(cfg.get(svc.cfg_key, {}).get("enabled") for svc in _INDEXER_SERVICES):
            return {
                "success": False,
                "message": "No indexer integrations are enabled for this session",
            }

        updated_services, failed_services = await _sync_indexers(
            cfg, mam_id, label, require_auto_update_on_save=False, verbose=False
        )

        # Prepare response
        if updated_services and not failed_services:
            status_msg = f"Successfully updated MAM ID in {', '.join(updated_services)}"
            await append_ui_event_log(
                {
                    "event": "indexer_manual_update",
                    "label": label,
                    "event_type": "indexer_update",
                    "status_message": status_msg,
                    "user_action": True,
                    "timestamp": datetime.now(UTC).isoformat(),
                }
            )
            return {"success": True, "message": status_msg}
        if updated_services and failed_services:
            status_msg = f"Partially successful: Updated {', '.join(updated_services)}. Failed: {', '.join(failed_services)}"
            await append_ui_event_log(
                {
                    "event": "indexer_partial_update",
                    "label": label,
                    "event_type": "indexer_update",
                    "status_message": status_msg,
                    "user_action": True,
                    "timestamp": datetime.now(UTC).isoformat(),
                }
            )
            return {"success": True, "message": status_msg, "warning": True}
        # All failed
        status_msg = f"Failed to update all services: {', '.join(failed_services)}"
        return {"success": False, "message": status_msg}

    except Exception as e:
        _logger.exception("Failed to update indexer(s)")
        return {"success": False, "message": f"Error: {e!s}"}


@app.get("/api/server_time")
def api_server_time() -> dict[str, Any]:
    """Return current server time in local timezone (ISO format)."""
    try:
        tz = ZoneInfo(TZ)
    except Exception:
        tz = UTC

    return {"server_time": datetime.now(tz).isoformat()}


@app.get("/api/version")
def api_version() -> dict[str, str]:
    """Return the application version.

    The version is set via the APP_VERSION environment variable which is
    injected during the Docker build. Defaults to 'dev' for local builds.
    """
    return {"version": APP_VERSION}


@app.get("/favicon.ico", include_in_schema=False)
def favicon_ico() -> FileResponse:
    """Serve the glyphicon favicon.ico from the frontend public directory.

    Returns a FileResponse when the file exists, otherwise raises 404.
    """
    path = FRONTEND_PUBLIC_DIR / "favicon.ico"
    if path.exists():
        return FileResponse(str(path), media_type="image/x-icon")
    raise HTTPException(status_code=404, detail="favicon.ico not found")


@app.get("/favicon.svg", include_in_schema=False)
def favicon_svg() -> FileResponse:
    """Serve the favicon.svg from the frontend public directory.

    Returns a FileResponse when the file exists, otherwise raises 404.
    """
    path = FRONTEND_PUBLIC_DIR / "favicon.svg"
    if path.exists():
        return FileResponse(str(path), media_type="image/svg+xml")
    raise HTTPException(status_code=404, detail="favicon.svg not found")


@app.get("/", include_in_schema=False)
def serve_react_index() -> FileResponse:
    """Serve the React app index.html for the root path.

    This endpoint is used by the frontend catch-all route.
    """
    index_path = FRONTEND_BUILD_DIR / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    raise HTTPException(status_code=404, detail="Frontend index.html not found")


@app.get("/{full_path:path}", include_in_schema=False)
def serve_react_app() -> FileResponse:
    """Serve the React app for all frontend paths (catch-all).

    If the build index.html exists, it is returned. Otherwise a 404 is raised.
    """
    index_path = FRONTEND_BUILD_DIR / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    raise HTTPException(status_code=404, detail="Not Found")


async def session_check_job(label: str) -> None:
    """Scheduled job that checks a single session's MaM status and logs events.

    This function is intended to be registered with APScheduler. It performs
    status detection, optional auto-update attempts, persists last_status and
    last_check_time, and appends UI event log entries.
    """
    try:
        trigger_source = "scheduled"
        _logger.info("[SessionCheck] label=%s source=%s", label, trigger_source)
        cfg = await load_session(label)
        mam_id = cfg.get("mam", {}).get("mam_id", "")
        mam_ip_override = cfg.get("mam_ip", "").strip()
        proxy_cfg = await resolve_proxy_from_session_cfg(cfg)
        # Single API call for IP detection (optimization)
        detected_ipinfo_data = await get_ipinfo_with_fallback()
        detected_public_ip = detected_ipinfo_data.get("ip")
        # If proxy is configured, actively detect proxied public IP and update config
        if proxy_cfg and proxy_cfg.get("host"):
            proxied_ip: str | None = await get_proxied_public_ip(proxy_cfg)
            if proxied_ip:
                cfg["proxied_public_ip"] = proxied_ip
                # Reload from disk before saving to avoid overwriting concurrent changes
                fresh_cfg = await load_session(label)
                fresh_cfg["proxied_public_ip"] = proxied_ip
                await save_session(fresh_cfg, old_label=label)
        # Use mam_ip_override if set, else proxied_public_ip if set, else detected_public_ip
        ip_to_use: str | None = (
            mam_ip_override or cfg.get("proxied_public_ip") or detected_public_ip
        )
        # Get ASN for IP sent to MaM (current_ip)
        if ip_to_use:
            asn_full, _ = await get_asn_and_timezone_from_ip(
                ip_to_use,
                proxy_cfg
                if (
                    proxy_cfg
                    and proxy_cfg.get("host")
                    and ip_to_use == cfg.get("proxied_public_ip")
                )
                else None,
            )
            asn = extract_asn_number(asn_full) or asn_full
        else:
            asn = None
        now = datetime.now(UTC)
        if mam_id:
            proxy_cfg = await resolve_proxy_from_session_cfg(cfg)
            # Capture old IP/ASN before update
            prev_ip = cfg.get("last_seedbox_ip")
            prev_asn = cfg.get("last_seedbox_asn")
            # Determine new IP/ASN (reuse detected data - optimization)
            proxied_ip = cfg.get("proxied_public_ip")
            new_ip = proxied_ip or detected_public_ip  # Reuse data from earlier
            asn_full, _ = await get_asn_and_timezone_from_ip(new_ip) if new_ip else (None, None)
            new_asn = extract_asn_number(asn_full) or asn_full
            status = await get_status(mam_id=mam_id, proxy_cfg=proxy_cfg)
            _refreshed_mam_id = status.pop("updated_mam_id", None)
            if _refreshed_mam_id and _refreshed_mam_id != mam_id:
                _prev_mam_id = mam_id
                mam_id = _refreshed_mam_id
                cfg["mam"]["mam_id"] = _refreshed_mam_id
                _logger.info("[SessionCheck] mam_id cookie auto-refreshed for session '%s'", label)
                await _sync_integrations_if_mam_id_changed(cfg, label, mam_id, _prev_mam_id)
            session_status_cache[label] = {"status": status, "last_check_time": now.isoformat()}
            cfg["last_check_time"] = now.isoformat()
            # MAM session keepalive: call dynamicSeedbox.php every 7 days to prevent
            # the ~30-day session expiry, independent of whether the IP has changed.
            # Uses last_mam_keepalive if present, otherwise falls back to last_seedbox_update,
            # so existing installs get a keepalive on their first run after this change.
            if status.get("mam_cookie_exists"):
                _last_keepalive_str = cfg.get("last_mam_keepalive") or cfg.get(
                    "last_seedbox_update"
                )
                _needs_keepalive = True
                if _last_keepalive_str:
                    try:
                        _last_keepalive_dt = datetime.fromisoformat(_last_keepalive_str)
                        _days_since = (now - _last_keepalive_dt).days
                        _needs_keepalive = _days_since >= 7
                    except Exception:
                        _needs_keepalive = True  # Unparseable date — keepalive to be safe
                if _needs_keepalive:
                    _logger.info(
                        "[Keepalive] label=%s Triggering session keepalive (>= 7 days since last contact).",
                        label,
                    )
                    await keepalive_mam_session(cfg, label, now)
                    # Reload cfg so the fresh timestamps are visible to the save block below
                    cfg = await load_session(label)
            # Check for increments in hit & run and unsatisfied counts before auto-update logic
            await check_and_notify_count_increments(cfg, status)
            # Auto-update logic
            _, auto_update_result = await auto_update_seedbox_if_needed(
                cfg, label, ip_to_use, asn, now
            )
            if auto_update_result is not None:
                status["auto_update_seedbox"] = auto_update_result
                # Log the result of the update attempt for visibility
                if auto_update_result.get("success"):
                    _logger.info(
                        "[AutoUpdate] label=%s update result: %s reason=%s",
                        label,
                        auto_update_result.get("msg", "Success"),
                        auto_update_result.get("reason"),
                    )
                else:
                    _logger.info(
                        "[AutoUpdate] label=%s update result: %s reason=%s",
                        label,
                        auto_update_result.get("error", "Error"),
                        auto_update_result.get("reason"),
                    )
            else:
                status["auto_update_seedbox"] = "N/A"
            # Always update last_status with the latest automation result
            status["status_message"] = build_status_message(status)
            cfg["last_status"] = status
            # Reload from disk before saving to avoid overwriting concurrent changes
            # (e.g. perk_automation settings saved while awaiting network calls above)
            fresh_cfg = await load_session(label)
            if _refreshed_mam_id:
                fresh_cfg["mam"]["mam_id"] = _refreshed_mam_id
            fresh_cfg["last_check_time"] = now.isoformat()
            fresh_cfg["last_status"] = status
            await save_session(fresh_cfg, old_label=label)
            # Log event using pre-update (old) and detected/proxied (new) values
            # Ensure auto_update is always a string, never None/null in JSON
            auto_update_val = get_auto_update_val(status)
            # ...removed debug _logger...
            # If we are rate-limited, log a specific message instead of a generic warning
            rate_limit_result = status.get("auto_update_seedbox")
            is_rate_limited = False
            msg = None
            if isinstance(rate_limit_result, dict):
                err = rate_limit_result.get("error", "").lower()
                if "rate limit" in err or "try again in" in err:
                    is_rate_limited = True
                    msg = (
                        rate_limit_result.get("error")
                        or "Rate limited, waiting to update IP/ASN in config."
                    )
            base_event = {
                "timestamp": now.isoformat(),
                "label": label,
                "event_type": "scheduled",
                "details": {
                    "ip_compare": f"{prev_ip} -> {new_ip}",
                    "asn_compare": f"{prev_asn} -> {new_asn}",
                    "auto_update": auto_update_val,  # Always a string
                },
            }
            if is_rate_limited:
                msg_text = msg or "Rate limited, waiting to update IP/ASN in config."
                await append_ui_event_log({**base_event, "status_message": msg_text})
                _logger.info("[SessionCheck][INFO] label=%s %s", label, msg)
            elif prev_ip is None or prev_asn is None or new_ip is None or new_asn is None:
                warn_msg = "Unable to determine current or new IP/ASN—check connectivity or configuration. No update performed."
                await append_ui_event_log({**base_event, "status_message": warn_msg})
                _logger.warning("[SessionCheck][WARNING] label=%s %s", label, warn_msg)
            else:
                await append_ui_event_log(
                    {
                        **base_event,
                        "status_message": status.get("status_message", status.get("message", "OK")),
                    }
                )
    except Exception as e:
        _logger.error("[APScheduler] Error in job for '%s': %s", label, e)


async def _scheduled_session_check(label: str) -> None:
    """Run a session check on the event loop, bounded by a timeout to prevent hangs.

    The timeout must stay below the minimum interval (60s) so a hung check never
    blocks the next scheduled run.
    """
    try:
        await asyncio.wait_for(session_check_job(label), timeout=45)
    except TimeoutError:
        _logger.error(
            "[APScheduler] Session check job for '%s' timed out after 45 seconds. "
            "This may indicate network or system resource issues.",
            label,
        )
    except Exception as e:
        _logger.error("[APScheduler] Session check job for '%s' failed: %s", label, e)


# On startup, reset last_check_time to now for all sessions to keep timers in sync
async def reset_all_last_check_times() -> None:
    """Reset the `last_check_time` for all sessions to the current time.

    This is called on startup to align scheduled timers and prevent immediate
    rate-limit collisions after restart.
    """
    now = datetime.now(UTC).isoformat()
    session_labels = await list_sessions()
    for label in session_labels:
        try:
            cfg = await load_session(label)
            cfg["last_check_time"] = now
            await save_session(cfg, old_label=label)
        except Exception as e:
            _logger.warning(
                "[Startup] Failed to reset last_check_time for session '%s': %s", label, e
            )


# Register jobs for all sessions on startup
async def register_session_job(label: str) -> None:
    """Register APScheduler job for a single session.

    Args:
        label: The session label to register a job for
    """
    cfg = await load_session(label)
    check_freq = cfg.get("check_freq")
    mam_id = cfg.get("mam", {}).get("mam_id", "")

    # Only register if frequency is set and valid, and MaM ID is present
    if not check_freq or not isinstance(check_freq, int) or check_freq < 1 or not mam_id:
        _logger.info(
            "[APScheduler] Skipping job registration for session '%s' (missing or invalid input)",
            label,
        )
        return

    job_id = f"session_check_{label}"
    # Remove any existing job for this label
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)

    scheduler.add_job(
        _scheduled_session_check,
        trigger=IntervalTrigger(minutes=check_freq),
        args=[label],
        id=job_id,
        replace_existing=True,
        coalesce=True,
        max_instances=1,
        misfire_grace_time=30,  # 30s grace for Windows timing drift (must be < min interval)
    )
    _logger.info(
        "[APScheduler] Registered job for session '%s' every %s min",
        label,
        check_freq,
    )


async def register_all_session_jobs() -> None:
    """Register APScheduler jobs for all sessions with valid settings.

    For each saved session this creates a job that runs `session_check_job`
    at the configured `check_freq` interval if the session has a MaM ID and
    a valid integer frequency.
    """
    session_labels = await list_sessions()
    for label in session_labels:
        await register_session_job(label)


# Immediate session check for all sessions at startup
async def run_initial_session_checks() -> None:
    """Run an immediate check for all sessions at startup.

    Adds a small delay between checks to help avoid triggering external rate
    limits during application startup.
    """
    session_labels = await list_sessions()
    for i, label in enumerate(session_labels):
        try:
            # Add a small delay between session checks to prevent rate limiting
            if i > 0:
                await asyncio.sleep(2)
            _logger.info("[Startup] Running initial session check for '%s'", label)
            await session_check_job(label)
        except Exception as e:
            _logger.warning("[Startup] Initial session check failed for '%s': %s", label, e)
