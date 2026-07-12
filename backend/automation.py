"""Automation helpers for scheduled MaM perk purchases.

This module contains functions that implement scheduled automation jobs for
MyAnonamouse (MaM) perk purchases such as upload credit, VIP, and wedge.
Each job enumerates saved sessions, evaluates guardrails (session-level and
automation-level), and attempts purchases via helper functions in
`backend.perk_automation`. Events and status updates are recorded via
`append_ui_event_log` and `notify_event`.

Functions provided:
- run_all_automation_jobs: convenience runner that invokes each job.
- upload_credit_automation_job: automation for upload credit purchases.
- vip_automation_job: automation for VIP purchases.
- wedge_automation_job: automation for wedge purchases.
"""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import partial
import logging
import time
from typing import Any

from backend.config import list_sessions, load_session, save_session
from backend.event_log import append_ui_event_log
from backend.mam_api import get_status
from backend.notifications_backend import notify_event
from backend.perk_automation import buy_upload_credit, buy_vip, buy_wedge
from backend.proxy_config import resolve_proxy_from_session_cfg

_logger: logging.Logger = logging.getLogger(__name__)

# Point costs for the enforce-minimum-points guardrail
_WEDGE_POINTS_COST = 50_000
_VIP_POINTS_COST: dict[int, int] = {4: 5_000, 8: 10_000}  # weeks -> points; 90/max is variable
_UPLOAD_POINTS_PER_GB = 500

# MaM only accepts these upload-credit purchase amounts (GB); minimum 50 as of January 2026.
_VALID_UPLOAD_CREDIT_GB = (50, 100)


@dataclass(frozen=True)
class _AutomationSpec:
    """Per-perk descriptors shared by the automation guardrail/skip/finalize helpers."""

    cfg_key: str  # perk_automation sub-key: "upload_credit" / "vip_automation" / "wedge_automation"
    purchase_type: str  # event purchase_type: "upload_credit" / "vip" / "wedge"
    noun: str  # human noun for messages: "Upload Credit" / "VIP" / "Wedge"
    skip_tag: str  # skip log tag: "AutoUpload" / "AutoVIP" / "AutoWedge"
    result_tag: str  # result log tag: "UploadAuto" / "VIPAuto" / "WedgeAuto"
    timestamp_field: str  # last-purchase field: "last_upload_time" / "last_vip_time" / ...


def _parse_last_purchase(value: str | None) -> datetime | None:
    """Parse an ISO timestamp string into a datetime, returning None on any failure."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except Exception:
        return None


async def _append_skip_event(
    now: datetime, label: str, spec: _AutomationSpec, amount: Any, points: Any, status_message: str
) -> None:
    """Append a 'skipped' automation event with the standard shape."""
    await append_ui_event_log(
        {
            "timestamp": now.isoformat(),
            "label": label,
            "event_type": "automation",
            "trigger": "automation",
            "purchase_type": spec.purchase_type,
            "amount": amount,
            "details": {"points_before": points},
            "result": "skipped",
            "status_message": status_message,
        }
    )


async def _emit_skip(
    now: datetime, label: str, spec: _AutomationSpec, amount: Any, points: Any, reason: str
) -> None:
    """Log and record a guardrail skip for a perk automation."""
    _logger.info(
        "[%s] SKIP: Automated %s purchase for session '%s' skipped: %s",
        spec.skip_tag,
        spec.noun,
        label,
        reason,
    )
    await _append_skip_event(
        now, label, spec, amount, points, f"Automated {spec.noun} purchase skipped: {reason}"
    )


def _evaluate_guardrails(
    *,
    cfg: dict[str, Any],
    automation: dict[str, Any],
    points: Any,
    purchase_cost: int | None,
    last_purchase: datetime | None,
    now: datetime,
) -> str | None:
    """Return the first failing guardrail's reason, or None if all pass.

    Checks, in order: session-minimum points, the enforce-minimum-points
    spend guardrail, the time-based trigger, and the automation point
    threshold.
    """
    session_min_points = cfg.get("perk_automation", {}).get("min_points")
    if session_min_points is not None and int(points) < int(session_min_points):
        return f"Below session minimum points: {points} < {session_min_points}"

    enforce = cfg.get("perk_automation", {}).get("enforce_min_points_guardrail", False)
    if (
        enforce
        and session_min_points is not None
        and purchase_cost is not None
        and int(points) - purchase_cost < int(session_min_points)
    ):
        return (
            f"Purchase would drop below minimum points: "
            f"{points} - {purchase_cost} = {int(points) - purchase_cost} "
            f"< {session_min_points}"
        )

    trigger_type = automation.get("trigger_type", "points")
    trigger_days = automation.get("trigger_days", 7)
    trigger_point_threshold = automation.get("trigger_point_threshold", 50000)

    if trigger_type in ("time", "both"):
        if last_purchase is None:
            return (
                "No previous purchase timestamp found. "
                "Please toggle and save the automation to start the timer. "
                "(Time-based trigger not satisfied.)"
            )
        next_allowed = last_purchase + timedelta(days=int(trigger_days))
        if now < next_allowed:
            return (
                f"Time-based trigger not satisfied: next allowed after {next_allowed.isoformat()}"
            )

    if trigger_type in ("points", "both") and int(points) < int(trigger_point_threshold):
        return f"Below automation point threshold: {points} < {trigger_point_threshold}"

    return None


async def _finalize_automation(
    *,
    now: datetime,
    label: str,
    cfg: dict[str, Any],
    spec: _AutomationSpec,
    amount: Any,
    points: Any,
    result: dict[str, Any],
    success_message: str,
    fail_message: str,
    notify_detail: str,
    log_descriptor: str,
    retry_state: Callable[[bool], None] | None = None,
) -> None:
    """Record the event, persist state, notify, and log the outcome of a purchase.

    Persistence happens before notification so a raising `notify_event` can
    never leave the timestamp/retry state unsaved (which would risk a repeat
    purchase on the next run). On success the last-purchase timestamp is
    written; `retry_state` (VIP only) applies retry/cooldown mutations for
    either outcome.
    """
    success = result.get("success", False)
    error = None if success else (result.get("error") or result.get("response") or "Unknown error")
    event = {
        "timestamp": now.isoformat(),
        "label": label,
        "event_type": "automation",
        "trigger": "automation",
        "purchase_type": spec.purchase_type,
        "amount": amount,
        "details": {"points_before": points},
        "result": "success" if success else "failed",
        "error": error,
        "status_message": success_message if success else fail_message,
    }
    if success:
        _logger.info(
            "[%s] Automated purchase: %s for session '%s' succeeded.",
            spec.result_tag,
            log_descriptor,
            label,
        )
    else:
        _logger.warning(
            "[%s] Automated purchase: %s for session '%s' FAILED. Error: %s",
            spec.result_tag,
            log_descriptor,
            label,
            error,
        )

    persisted = False
    if success:
        cfg["perk_automation"][spec.cfg_key][spec.timestamp_field] = now.isoformat()
        persisted = True
    if retry_state is not None:
        retry_state(success)
        persisted = True
    if persisted:
        await save_session(cfg, old_label=label)

    if success:
        await notify_event(
            event_type="automation_success",
            label=label,
            status="SUCCESS",
            message=f"Automated {spec.noun} purchase succeeded: {notify_detail}",
            details={"amount": amount, "points_before": points},
        )
    else:
        await notify_event(
            event_type="automation_failure",
            label=label,
            status="FAILED",
            message=f"Automated {spec.noun} purchase failed: {notify_detail}",
            details={"amount": amount, "points_before": points, "error": error},
        )
    await append_ui_event_log(event)


def _apply_vip_retry_state(
    automation: dict[str, Any], now_ts: int, descriptor: Any, label: str, success: bool
) -> None:
    """Update VIP retry/cooldown state after a purchase attempt (reset on success)."""
    if success:
        automation["retry"] = 0
        automation.pop("cooldown_until", None)
        automation.pop("last_fail_time", None)
        return
    retries = automation.get("retry", 0) + 1
    automation["retry"] = retries
    automation["last_fail_time"] = now_ts
    # Retry up to 3 times, 1 minute apart; then cool down until the next run
    if retries >= 3:
        automation["cooldown_until"] = now_ts + 600
        _logger.warning(
            "[VIPAuto] Automated purchase: VIP (%s) for session '%s' retries_exceeded, cooldown_until=%s",
            descriptor,
            label,
            automation["cooldown_until"],
        )


# --- Automation Scheduler ---
async def run_all_automation_jobs() -> None:
    """Run all available automation jobs.

    Convenience function to sequentially run upload credit, wedge, and VIP
    automation jobs. Intended to be called by a scheduler or from startup
    code.
    """
    await upload_credit_automation_job()
    await wedge_automation_job()
    await vip_automation_job()


async def upload_credit_automation_job() -> None:
    """Evaluate and run upload credit automation for all sessions."""
    spec = _AutomationSpec(
        "upload_credit",
        "upload_credit",
        "Upload Credit",
        "AutoUpload",
        "UploadAuto",
        "last_upload_time",
    )
    now = datetime.now(UTC)
    for label in await list_sessions():
        try:
            cfg = await load_session(label)
            mam_id = cfg.get("mam", {}).get("mam_id", "")
            if not mam_id:
                continue
            automation = cfg.get("perk_automation", {}).get("upload_credit", {})
            if not automation.get("enabled", False):
                continue
            gb_amount = automation.get("gb", 10)

            # Validate upload credit amount - MaM only accepts certain values.
            if gb_amount not in _VALID_UPLOAD_CREDIT_GB:
                _logger.error(
                    "[UploadAuto] Invalid upload credit amount configured: %sGB. Skipping session '%s'. Valid amounts are: %s",
                    gb_amount,
                    label,
                    ", ".join(map(str, _VALID_UPLOAD_CREDIT_GB)),
                )
                continue

            proxy_cfg = await resolve_proxy_from_session_cfg(cfg)
            status = await get_status(mam_id=mam_id, proxy_cfg=proxy_cfg)
            points = status.get("points") or 0
            reason = _evaluate_guardrails(
                cfg=cfg,
                automation=automation,
                points=points,
                purchase_cost=int(gb_amount) * _UPLOAD_POINTS_PER_GB,
                last_purchase=_parse_last_purchase(automation.get("last_upload_time")),
                now=now,
            )
            if reason is not None:
                await _emit_skip(now, label, spec, gb_amount, points, reason)
                continue

            result = await buy_upload_credit(gb_amount, mam_id=mam_id, proxy_cfg=proxy_cfg)
            await _finalize_automation(
                now=now,
                label=label,
                cfg=cfg,
                spec=spec,
                amount=gb_amount,
                points=points,
                result=result,
                success_message=f"Automated purchase: Upload Credit ({gb_amount} GB)",
                fail_message=f"Automated Upload Credit purchase failed ({gb_amount} GB)",
                notify_detail=f"{gb_amount} GB",
                log_descriptor=f"Upload Credit ({gb_amount} GB)",
            )
        except Exception as e:
            _logger.error("[UploadAuto] Error for '%s': %s", label, e)


async def vip_automation_job() -> None:
    """Evaluate and run VIP automation for all sessions, including retry/cooldown handling."""
    spec = _AutomationSpec("vip_automation", "vip", "VIP", "AutoVIP", "VIPAuto", "last_vip_time")
    now = datetime.now(UTC)
    for label in await list_sessions():
        try:
            cfg = await load_session(label)
            mam_id = cfg.get("mam", {}).get("mam_id", "")
            if not mam_id:
                continue
            automation = cfg.get("perk_automation", {}).get("vip_automation", {})
            if not automation.get("enabled", False):
                continue
            weeks = automation.get("weeks", 4)
            is_max = str(weeks).lower() in ["max", "90"]

            proxy_cfg = await resolve_proxy_from_session_cfg(cfg)
            status = await get_status(mam_id=mam_id, proxy_cfg=proxy_cfg)
            points = status.get("points") or 0
            reason = _evaluate_guardrails(
                cfg=cfg,
                automation=automation,
                points=points,
                # Max/90-week VIP has variable cost; skip the spend guardrail for it.
                purchase_cost=None if is_max else _VIP_POINTS_COST.get(int(weeks)),
                last_purchase=_parse_last_purchase(automation.get("last_vip_time")),
                now=now,
            )
            if reason is not None:
                await _emit_skip(now, label, spec, weeks, points, reason)
                # Reset retry state if not eligible
                if "retry" in automation:
                    automation.pop("retry", None)
                    automation.pop("cooldown_until", None)
                    await save_session(cfg, old_label=label)
                continue

            # --- Retry/cooldown logic ---
            retry = automation.get("retry")
            cooldown_until = automation.get("cooldown_until")
            now_ts = int(time.time())
            if cooldown_until and now_ts < cooldown_until:
                _logger.info(
                    "[VIPAuto] label=%s trigger=automation result=skipped reason=cooldown active until %s",
                    label,
                    cooldown_until,
                )
                await _append_skip_event(
                    now, label, spec, weeks, points, f"Cooldown active until {cooldown_until}"
                )
                continue
            last_fail_time = automation.get("last_fail_time")
            if retry and last_fail_time and (now_ts - last_fail_time) < 60:
                _logger.info(
                    "[VIPAuto] label=%s trigger=automation result=skipped reason=waiting_between_retries retry=%s",
                    label,
                    retry,
                )
                await _append_skip_event(
                    now, label, spec, weeks, points, f"Waiting between retries (retry {retry})"
                )
                continue

            duration = "max" if is_max else str(weeks)
            detail = "Max me out!" if is_max else f"{weeks} weeks"
            descriptor = "max" if is_max else weeks

            result = await buy_vip(mam_id, duration=duration, proxy_cfg=proxy_cfg)
            await _finalize_automation(
                now=now,
                label=label,
                cfg=cfg,
                spec=spec,
                amount=weeks,
                points=points,
                result=result,
                success_message=f"Automated purchase: VIP ({detail})",
                fail_message=f"Automated VIP purchase failed ({detail})",
                notify_detail=detail,
                log_descriptor=f"VIP ({descriptor})",
                retry_state=partial(_apply_vip_retry_state, automation, now_ts, descriptor, label),
            )
        except Exception as e:
            _logger.error(
                "[VIPAuto] label=%s trigger=automation result=exception error=%s", label, e
            )


async def wedge_automation_job() -> None:
    """Evaluate and run wedge automation for all sessions."""
    spec = _AutomationSpec(
        "wedge_automation", "wedge", "Wedge", "AutoWedge", "WedgeAuto", "last_wedge_time"
    )
    now = datetime.now(UTC)
    for label in await list_sessions():
        try:
            cfg = await load_session(label)
            mam_id = cfg.get("mam", {}).get("mam_id", "")
            if not mam_id:
                continue
            automation = cfg.get("perk_automation", {}).get("wedge_automation", {})
            if not automation.get("enabled", False):
                continue

            proxy_cfg = await resolve_proxy_from_session_cfg(cfg)
            status = await get_status(mam_id=mam_id, proxy_cfg=proxy_cfg)
            points = status.get("points") or 0
            _logger.debug(
                "[AutoWedge][DEBUG] Session '%s': points=%s, session_min_points=%s",
                label,
                points,
                cfg.get("perk_automation", {}).get("min_points"),
            )
            reason = _evaluate_guardrails(
                cfg=cfg,
                automation=automation,
                points=points,
                purchase_cost=_WEDGE_POINTS_COST,  # Automation always uses the points method
                last_purchase=_parse_last_purchase(automation.get("last_wedge_time")),
                now=now,
            )
            if reason is not None:
                await _emit_skip(now, label, spec, 1, points, reason)
                continue

            result = await buy_wedge(mam_id, proxy_cfg=proxy_cfg)
            await _finalize_automation(
                now=now,
                label=label,
                cfg=cfg,
                spec=spec,
                amount=1,
                points=points,
                result=result,
                success_message="Automated purchase: Wedge (points)",
                fail_message="Automated Wedge purchase failed (points)",
                notify_detail="1",
                log_descriptor="Wedge (points)",
            )
        except Exception as e:
            _logger.error(
                "[WedgeAuto] label=%s trigger=automation result=exception error=%s", label, e
            )
