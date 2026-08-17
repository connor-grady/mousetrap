"""API endpoints for manual perk purchases (upload credit, wedge, VIP).

This module exposes FastAPI endpoints under `/automation/*` that allow a
client to trigger manual perk purchases for a configured session. Each
endpoint expects a JSON body containing at minimum a `label` that identifies
the saved session; additional fields vary by endpoint (for example,
`amount` for upload credits or `weeks` for VIP). Events are recorded via the
event log and notifications are attempted via the notifications backend.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Request

from backend.config import load_session
from backend.event_log import append_ui_event_log
from backend.mam_api import get_status
from backend.notifications_backend import notify_event
from backend.perk_automation import (
    UPLOAD_POINTS_PER_GB,
    VALID_UPLOAD_CREDIT_GB,
    VIP_POINTS_COST,
    WEDGE_POINTS_COST,
    WedgeMethod,
    buy_upload_credit,
    buy_vip,
    buy_wedge,
    parse_vip_weeks,
)
from backend.proxy_config import resolve_proxy_from_session_cfg
from backend.utils_redact import redact_sensitive

_logger: logging.Logger = logging.getLogger(__name__)

router = APIRouter()


@dataclass(frozen=True)
class _PerkSpec:
    """Per-perk descriptors shared by the guardrail and finalize helpers."""

    purchase_type: str
    log_tag: str
    noun: str
    amount: Any
    detail_summary: str
    log_descriptor: str
    status_success: str
    status_failed: str
    notify_details: dict[str, Any]
    event_details: dict[str, Any]


def redacted_error(result: Any) -> Any:
    """Redact `result` and return its error field for logging (or the value itself)."""
    redacted = redact_sensitive(result)
    return redacted.get("error") if isinstance(redacted, dict) else redacted


async def _min_points_guardrail(
    *,
    cfg: dict[str, Any],
    mam_id: str,
    proxy_cfg: dict[str, Any] | None,
    label: str,
    now: datetime,
    spec: _PerkSpec,
    purchase_cost: int,
) -> str | None:
    """Return a block reason if the purchase would drop below min points, else None.

    When the session's minimum-points guardrail is enabled, fetches the current
    balance and blocks the purchase (logging a `blocked` event) if spending
    `purchase_cost` would take it below the configured minimum.
    """
    perk_automation = cfg.get("perk_automation", {})
    enforce = perk_automation.get("enforce_min_points_guardrail", False)
    min_points = perk_automation.get("min_points")
    if not (enforce and min_points is not None):
        return None
    status = await get_status(mam_id=mam_id, proxy_cfg=proxy_cfg)
    current_points = status.get("points") or 0
    if int(current_points) - purchase_cost >= int(min_points):
        return None
    reason = (
        f"Purchase would drop below minimum points: "
        f"{current_points} - {purchase_cost} = {int(current_points) - purchase_cost} "
        f"< {min_points}"
    )
    _logger.info("[%s] BLOCKED for session '%s': %s", spec.log_tag, label, reason)
    append_ui_event_log(
        {
            "timestamp": now.isoformat(),
            "label": label,
            "event_type": "manual",
            "trigger": "manual",
            "purchase_type": spec.purchase_type,
            "amount": spec.amount,
            "details": {**spec.event_details, "points_before": current_points},
            "result": "blocked",
            "status_message": f"Manual {spec.noun} purchase blocked: {reason}",
        },
    )
    return reason


async def _finalize_manual_purchase(
    result: dict[str, Any], *, label: str, now: datetime, spec: _PerkSpec
) -> dict[str, Any]:
    """Record the event, notify, log, and build the response for a manual purchase."""
    success = result.get("success", False)
    append_ui_event_log(
        {
            "timestamp": now.isoformat(),
            "label": label,
            "event_type": "manual",
            "trigger": "manual",
            "purchase_type": spec.purchase_type,
            "amount": spec.amount,
            "details": spec.event_details,
            "result": "success" if success else "failed",
            "error": result.get("error") if not success else None,
            "status_message": spec.status_success if success else spec.status_failed,
        },
    )
    try:
        if success:
            await notify_event(
                event_type="manual_purchase_success",
                label=label,
                status="SUCCESS",
                message=f"Manual {spec.noun} purchase succeeded: {spec.detail_summary}",
                details=spec.notify_details,
            )
        else:
            await notify_event(
                event_type="manual_purchase_failure",
                label=label,
                status="FAILED",
                message=f"Manual {spec.noun} purchase failed: {spec.detail_summary}",
                details={**spec.notify_details, "error": result.get("error")},
            )
    except Exception:
        _logger.debug("[%s] Manual purchase notification failed.", spec.log_tag)
    if success:
        _logger.info(
            "[%s] Purchase: %s for session '%s' succeeded.",
            spec.log_tag,
            spec.log_descriptor,
            label,
        )
    else:
        _logger.warning(
            "[%s] Purchase: %s for session '%s' FAILED. Error: %s",
            spec.log_tag,
            spec.log_descriptor,
            label,
            redacted_error(result),
        )
    return {"success": success, **result}


async def _parse_manual_request(
    request: Request,
) -> tuple[dict[str, Any], str, dict[str, Any], str, dict[str, Any] | None, datetime]:
    """Parse a manual-purchase request into its shared parts.

    Returns ``(data, label, cfg, mam_id, proxy_cfg, now)``. Raises
    ``HTTPException(400)`` when the required ``label`` field is missing.
    """
    data = await request.json()
    label = data.get("label")
    if not label:
        raise HTTPException(status_code=400, detail="Session label required.")
    cfg = load_session(label)
    mam_id = cfg.get("mam", {}).get("mam_id", "")
    proxy_cfg = resolve_proxy_from_session_cfg(cfg)
    now = datetime.now(UTC)
    return data, label, cfg, mam_id, proxy_cfg, now


@router.post("/automation/upload_auto")
async def manual_upload_credit(request: Request) -> dict[str, Any]:
    """Trigger a manual upload-credit purchase for a session.

    Expects a JSON body with the following fields:
    - label: session label (required)
    - amount: number of GB to purchase (optional, defaults to 1)

    The endpoint will attempt the purchase, write an event to the UI event
    log, and attempt to notify configured notification backends. It returns
    a dict including a "success" boolean and any result details from the
    purchase attempt.

    Raises:
        HTTPException: If the required `label` field is missing from the
            request JSON.

    """
    data, label, cfg, mam_id, proxy_cfg, now = await _parse_manual_request(request)
    amount = data.get("amount", 1)
    if amount not in VALID_UPLOAD_CREDIT_GB:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid upload credit amount: {amount}GB. Valid amounts are: {', '.join(map(str, VALID_UPLOAD_CREDIT_GB))}GB",
        )

    spec = _PerkSpec(
        purchase_type="upload_credit",
        log_tag="ManualUpload",
        noun="Upload Credit",
        amount=amount,
        detail_summary=f"{amount}GB",
        log_descriptor=f"{amount}GB upload credit",
        status_success=f"Purchased {amount}GB Upload Credit",
        status_failed=f"Upload Credit purchase failed ({amount}GB)",
        notify_details={"amount": amount},
        event_details={},
    )
    reason = await _min_points_guardrail(
        cfg=cfg,
        mam_id=mam_id,
        proxy_cfg=proxy_cfg,
        label=label,
        now=now,
        spec=spec,
        purchase_cost=amount * UPLOAD_POINTS_PER_GB,
    )
    if reason:
        return {"success": False, "error": reason}
    result = await buy_upload_credit(amount, mam_id=mam_id, proxy_cfg=proxy_cfg)
    return await _finalize_manual_purchase(result, label=label, now=now, spec=spec)


@router.post("/automation/wedge")
async def manual_wedge(request: Request) -> dict[str, Any]:
    """Trigger a manual wedge purchase for a session.

    Expects a JSON body with the following fields:
    - label: session label (required)
    - method: purchase method (optional, defaults to "points")

    The endpoint logs the event, attempts the wedge purchase via the
    perk_automation module, and tries to notify configured notification
    backends. Returns a dict with a "success" boolean and details from the
    purchase attempt.

    Raises:
        HTTPException: If the required `label` field is missing from the
            request JSON.

    """
    data, label, cfg, mam_id, proxy_cfg, now = await _parse_manual_request(request)
    method: WedgeMethod = data.get("method", "points")
    spec = _PerkSpec(
        purchase_type="wedge",
        log_tag="ManualWedge",
        noun="Wedge",
        amount=1,
        detail_summary=method,
        log_descriptor=f"Wedge ({method})",
        status_success=f"Purchased Wedge ({method})",
        status_failed=f"Wedge purchase failed ({method})",
        notify_details={"method": method},
        event_details={"method": method},
    )
    # Guardrail only applies to the points method; the cheese method has no point cost
    if method == "points":
        reason = await _min_points_guardrail(
            cfg=cfg,
            mam_id=mam_id,
            proxy_cfg=proxy_cfg,
            label=label,
            now=now,
            spec=spec,
            purchase_cost=WEDGE_POINTS_COST,
        )
        if reason:
            return {"success": False, "error": reason}
    result = await buy_wedge(mam_id, method=method, proxy_cfg=proxy_cfg)
    return await _finalize_manual_purchase(result, label=label, now=now, spec=spec)


@router.post("/automation/vip")
async def manual_vip(request: Request) -> dict[str, Any]:
    """Trigger a manual VIP purchase for a session.

    Expects a JSON body with the following fields:
    - label: session label (required)
    - weeks: number of weeks for VIP (optional, defaults to 4). Special
      values like "max" or "90" are treated as max-duration purchases.

    The endpoint performs the VIP purchase, records an event, and attempts
    notifications. Returns a dict with a "success" boolean and purchase
    details.

    Raises:
        HTTPException: If the required `label` field is missing from the
            request JSON.

    """
    data, label, cfg, mam_id, proxy_cfg, now = await _parse_manual_request(request)
    try:
        weeks = parse_vip_weeks(data.get("weeks", 4))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    duration = str(weeks)
    label_desc = "Max me out!" if weeks == "max" else f"{weeks} weeks"
    spec = _PerkSpec(
        purchase_type="vip",
        log_tag="ManualVIP",
        noun="VIP",
        amount=weeks,
        detail_summary=label_desc,
        log_descriptor="VIP (max)" if weeks == "max" else f"VIP ({weeks} weeks)",
        status_success=f"Purchased VIP ({label_desc})",
        status_failed=f"VIP purchase failed ({label_desc})",
        notify_details={"weeks": weeks},
        event_details={},
    )
    # Max/90-week VIP has variable cost; the guardrail only applies to known fixed durations
    if weeks != "max":
        purchase_cost = VIP_POINTS_COST.get(weeks)
        if purchase_cost is not None:
            reason = await _min_points_guardrail(
                cfg=cfg,
                mam_id=mam_id,
                proxy_cfg=proxy_cfg,
                label=label,
                now=now,
                spec=spec,
                purchase_cost=purchase_cost,
            )
            if reason:
                return {"success": False, "error": reason}
    result = await buy_vip(mam_id, duration=duration, proxy_cfg=proxy_cfg)
    return await _finalize_manual_purchase(result, label=label, now=now, spec=spec)
