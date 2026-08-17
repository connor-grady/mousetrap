"""API endpoints for testing and configuring notification backends.

This module exposes FastAPI routes under `/notify/*` to read and write the
notification configuration and to trigger test notifications for webhook,
SMTP, Apprise-based, and Pushover notification backends. The endpoints
delegate to the utilities in :mod:`backend.notifications_backend` for the
actual sending logic.
"""

from typing import Any

from fastapi import APIRouter, HTTPException
import yaml

from backend.notifications_backend import (
    AppriseMode,
    apprise_config_valid,
    load_notify_config,
    send_apprise_notification,
    send_pushover_notification,
    send_smtp_notification,
    send_webhook_notification,
)
from backend.paths import NOTIFY_PATH

router = APIRouter()


def save_notify_config(cfg: dict[str, Any]) -> None:
    """Persist the notification configuration to disk.

    Args:
        cfg: Dictionary containing the notification configuration to save.

    """
    NOTIFY_PATH.parent.mkdir(parents=True, exist_ok=True)
    with NOTIFY_PATH.open("w", encoding="utf-8") as f:
        yaml.safe_dump(cfg, f)


@router.get("/notify/config")
def get_notify_config() -> dict[str, Any]:
    """Return the current notification configuration.

    The configuration is loaded from the configured notify config path and
    returned as a dictionary.
    """
    return load_notify_config()


@router.post("/notify/config")
def set_notify_config(cfg: dict[str, Any]) -> dict[str, Any]:
    """Save a new notification configuration.

    Args:
        cfg: Dict representing the notification configuration to persist.

    Returns:
        A dict with a "success" boolean indicating the write succeeded.

    """
    save_notify_config(cfg)
    return {"success": True}


@router.post("/notify/test/webhook")
async def test_webhook(payload: dict[str, Any]) -> dict[str, Any]:
    """Send a test payload to the configured webhook URL.

    Args:
        payload: Arbitrary dict that will be forwarded to the webhook.

    Returns:
        A dict with a "success" boolean indicating whether the notification
        was sent successfully.

    Raises:
        HTTPException: If no webhook URL is configured.

    """
    cfg = load_notify_config()
    if not (url := cfg.get("webhook_url")):
        raise HTTPException(status_code=400, detail="Webhook URL not set.")
    ok = await send_webhook_notification(url, payload, discord=cfg.get("discord_webhook", False))
    return {"success": ok}


@router.post("/notify/test/smtp")
def test_smtp(payload: dict[str, Any]) -> dict[str, Any]:
    """Send a test SMTP notification using the configured SMTP settings.

    Args:
        payload: A dict that may contain `subject` and `body` keys for the
            test message.

    Returns:
        A dict with a "success" boolean indicating whether the message was
        sent successfully.

    Raises:
        HTTPException: If the SMTP configuration is incomplete.

    """
    cfg = load_notify_config()
    smtp = cfg.get("smtp", {})
    if not all(k in smtp for k in ("host", "port", "username", "password", "to_email")):
        raise HTTPException(status_code=400, detail="SMTP config incomplete.")
    ok = send_smtp_notification(
        smtp["host"],
        smtp["port"],
        smtp["username"],
        smtp["password"],
        smtp["to_email"],
        payload.get("subject", "Test"),
        payload.get("body", "Test"),
        smtp.get("use_tls", True),
    )
    return {"success": ok}


@router.post("/notify/test/apprise")
async def test_apprise(payload: dict[str, Any]) -> dict[str, Any]:
    """Send a test notification via Apprise.

    The function builds a small test payload from the provided `payload`
    argument and dispatches it using the configured Apprise settings.
    Supports both stateless (URLs) and stateful (key/tags) modes.

    Args:
        payload: Dict that may include `event_type`, `label`, `status`,
            `message`, and `details` to include in the test notification.

    Returns:
        A dict with a "success" boolean indicating whether the notification
        was successfully queued/sent.

    Raises:
        HTTPException: If the Apprise configuration is incomplete.

    """
    cfg = load_notify_config()
    apprise_cfg = cfg.get("apprise", {})
    apprise_url = apprise_cfg.get("url")
    mode: AppriseMode = apprise_cfg.get("mode", "stateless")
    notify_url_string = apprise_cfg.get("notify_url_string", "")
    key = apprise_cfg.get("key", "")
    tags = apprise_cfg.get("tags", "")
    include_prefix = apprise_cfg.get("include_prefix", False)

    if not apprise_config_valid(mode, apprise_url, key, notify_url_string):
        raise HTTPException(
            status_code=400,
            detail="Apprise stateful config incomplete (need URL and key)."
            if mode == "stateful"
            else "Apprise config incomplete.",
        )

    test_payload = {
        "event_type": payload.get("event_type", "test"),
        "label": payload.get("label", "UI Test"),
        "status": payload.get("status", "TEST"),
        "message": payload.get(
            "message", "Session: UI Test, Test Apprise notification from MouseTrap"
        ),
        "details": payload.get("details", {}),
    }

    ok = await send_apprise_notification(
        apprise_url,
        notify_url_string,
        test_payload,
        include_prefix,
        mode=mode,
        key=key,
        tags=tags,
    )
    return {"success": ok}


@router.post("/notify/test/pushover")
async def test_pushover(payload: dict[str, Any]) -> dict[str, Any]:
    """Send a test notification via Pushover.

    Args:
        payload: Dict that may include `message` for the test notification body.

    Returns:
        A dict with a "success" boolean indicating whether the notification
        was sent successfully.

    Raises:
        HTTPException: If the Pushover configuration is incomplete.

    """
    cfg = load_notify_config()
    pushover_cfg = cfg.get("pushover", {})
    user_key = pushover_cfg.get("user_key", "")
    api_token = pushover_cfg.get("api_token", "")
    if not user_key or not api_token:
        raise HTTPException(
            status_code=400, detail="Pushover config incomplete (need user key and API token)."
        )
    ok = await send_pushover_notification(
        user_key,
        api_token,
        "MouseTrap: Test Notification",
        payload.get("message", "Test Pushover notification from MouseTrap"),
    )
    return {"success": ok}
