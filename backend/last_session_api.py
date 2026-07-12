"""API endpoints for storing and retrieving the last selected session label.

This module exposes two endpoints under `/last_session`:
- GET `/last_session`: returns the last saved session label (or None).
- POST `/last_session`: accepts JSON {"label": "..."} and persists it.

Persistence is a simple YAML file located at `LAST_SESSION_PATH`.
"""

import asyncio
from typing import Any

from fastapi import APIRouter, HTTPException, Request
import yaml

from backend.paths import LAST_SESSION_PATH

router = APIRouter()


async def read_last_session() -> str | None:
    """Read the last session label from disk (I/O offloaded to a worker thread)."""
    return await asyncio.to_thread(_read_last_session)


def _read_last_session() -> str | None:
    """Read the last session label from disk.

    Returns:
        The saved label string, or None if the file does not exist or is malformed.
    """
    if not LAST_SESSION_PATH.exists():
        return None
    with LAST_SESSION_PATH.open(encoding="utf-8") as f:
        data = yaml.safe_load(f)
        return data.get("label") if isinstance(data, dict) else None


async def write_last_session(label: str | None) -> None:
    """Persist the given session label to disk (I/O offloaded to a worker thread)."""
    await asyncio.to_thread(_write_last_session, label)


def _write_last_session(label: str | None) -> None:
    """Persist the given session label to disk as YAML.

    Args:
        label: The session label to persist.
    """
    LAST_SESSION_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LAST_SESSION_PATH.open("w", encoding="utf-8") as f:
        yaml.safe_dump({"label": label or ""}, f)


@router.get("/last_session")
async def get_last_session() -> dict[str, Any]:
    """HTTP GET handler that returns the last saved session label.

    Returns:
        A JSON object with the key "label" whose value is the saved label or None.
    """
    return {"label": await read_last_session()}


@router.post("/last_session")
async def set_last_session(request: Request) -> dict[str, Any]:
    """HTTP POST handler to set and persist the last session label.

    Expects a JSON body with key `label`. Returns the saved label on success.

    Raises:
        HTTPException(400) if `label` is missing from the request body.
    """
    data = await request.json()
    label = data.get("label")
    if not label:
        raise HTTPException(status_code=400, detail="Label required.")
    await write_last_session(label)
    return {"success": True, "label": label}
