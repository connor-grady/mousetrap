"""Persistent UI event log, backed by the shared SQLite database.

Records UI events (session checks, IP changes, purchases, port-monitor status,
integration syncs, etc.) for the frontend activity feed. Sensitive fields are
redacted before storage, and the log is capped at the newest ``_MAX_EVENTS``.

The public functions are async; the blocking SQLite work is offloaded to a
worker thread via ``asyncio.to_thread`` so the event loop is never blocked.
"""

import asyncio
import json
import logging
from typing import Any

from backend import db
from backend.utils_redact import redact_sensitive

_logger: logging.Logger = logging.getLogger(__name__)
_MAX_EVENTS = 1000


def _append(event: dict[str, Any]) -> None:
    redacted = redact_sensitive(event)
    with db.connection() as conn:
        conn.execute(
            "INSERT INTO events (label, event_type, ts, data) VALUES (?, ?, ?, ?)",
            (
                redacted.get("label"),
                redacted.get("event_type"),
                redacted.get("timestamp"),
                json.dumps(redacted),
            ),
        )
        conn.execute(
            "DELETE FROM events WHERE id <= (SELECT MAX(id) FROM events) - ?",
            (_MAX_EVENTS,),
        )
        conn.commit()


async def append_ui_event_log(event: dict[str, Any]) -> None:
    """Append a redacted event to the log, trimming to the newest ``_MAX_EVENTS``."""
    try:
        await asyncio.to_thread(_append, event)
    except Exception as e:
        _logger.error("[UIEventLog] Failed to append event: %s", e)


def _get() -> list[dict[str, Any]]:
    with db.connection() as conn:
        rows = conn.execute("SELECT data FROM events ORDER BY id").fetchall()
    return [json.loads(row["data"]) for row in rows]


async def get_ui_event_log() -> list[dict[str, Any]]:
    """Return the logged events in chronological (insertion) order.

    Returns an empty list if the log cannot be read.
    """
    try:
        return await asyncio.to_thread(_get)
    except Exception:
        return []


def _clear() -> None:
    with db.connection() as conn:
        conn.execute("DELETE FROM events")
        conn.commit()


async def clear_ui_event_log() -> bool:
    """Delete all events (all sessions)."""
    try:
        await asyncio.to_thread(_clear)
    except Exception as e:
        _logger.error("[UIEventLog] Failed to clear event log: %s", e)
        return False
    else:
        return True


def _clear_for_session(label: str) -> None:
    with db.connection() as conn:
        conn.execute("DELETE FROM events WHERE label = ?", (label,))
        conn.commit()


async def clear_ui_event_log_for_session(label: str) -> bool:
    """Delete all events for a specific session label."""
    try:
        await asyncio.to_thread(_clear_for_session, label)
    except Exception as e:
        _logger.error("[UIEventLog] Failed to clear event log for session '%s': %s", label, e)
        return False
    else:
        return True
