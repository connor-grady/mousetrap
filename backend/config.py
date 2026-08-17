"""Configuration helpers for session and global config files.

This module provides utilities to read/write session-specific YAML
configuration files, a default global config, and simple helpers used by
the backend to locate and manage session files.
"""

from pathlib import Path
import threading
from typing import Any

import yaml

from backend.paths import CONFIG_DIR, CONFIG_PATH

_LOCK = threading.Lock()

SESSION_PREFIX = "session-"
SESSION_SUFFIX = ".yaml"


def get_session_path(label: str) -> Path:
    """Return the filesystem path for a session identified by ``label``.

    The path is constructed using the module-level ``CONFIG_DIR`` and the
    session prefix/suffix constants.
    """
    return CONFIG_DIR / f"{SESSION_PREFIX}{label}{SESSION_SUFFIX}"


def list_sessions() -> list[str]:
    """Return the session labels present in the config directory.

    Scans the ``CONFIG_DIR`` for files that match the session naming
    convention and returns the extracted labels (without prefix/suffix).
    """
    return [
        f.name[len(SESSION_PREFIX) : -len(SESSION_SUFFIX)]
        for f in CONFIG_DIR.glob(f"{SESSION_PREFIX}*{SESSION_SUFFIX}")
    ]


def encrypt_password(password: str) -> str:
    """Placeholder for password encryption.

    Currently a no-op that returns the plain password. Intended to be
    replaced with a real encryption mechanism if/when needed.
    """
    # No-op: return plain text for now
    return password


def decrypt_password(token: str) -> str:
    """Placeholder for password decryption.

    Returns the original token in the current implementation.
    """
    # No-op: return plain text for now
    return token


def _apply_defaults(parent: dict[str, Any], key: str, defaults: dict[str, Any]) -> None:
    """Ensure ``parent[key]`` exists and contains every default not already set."""
    section = parent.setdefault(key, {})
    for k, v in defaults.items():
        section.setdefault(k, v)


def load_session(label: str) -> dict[str, Any]:
    """Load a session configuration by label.

    If the session file does not exist the default config is returned. The
    returned dictionary is guaranteed to contain keys expected by the
    application (some defaults are populated if missing).
    """
    if not (path := get_session_path(label)).exists():
        cfg = get_default_config(label)
    else:
        with _LOCK, path.open(encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or get_default_config(label)
    # --- Ensure all perk automation configs are always present and complete ---
    perk_auto = cfg.setdefault("perk_automation", {})
    _apply_defaults(
        perk_auto,
        "upload_credit",
        {
            "enabled": False,
            "gb": 1,
            "min_points": 0,
            "points_to_keep": 0,
            "trigger_type": "time",
            "trigger_days": 7,
            "trigger_point_threshold": 50000,
        },
    )
    _apply_defaults(
        perk_auto,
        "wedge_automation",
        {
            "enabled": False,
            "trigger_days": 7,
            "trigger_point_threshold": 50000,
            "trigger_type": "time",
        },
    )
    _apply_defaults(
        perk_auto,
        "vip_automation",
        {
            "enabled": False,
            "trigger_type": "time",
            "trigger_days": 7,
            "trigger_point_threshold": 50000,
            "weeks": 4,
        },
    )
    cfg.setdefault("mam_ip", "")
    cfg.setdefault("mam", {}).setdefault("ip_monitoring_mode", "auto")
    cfg.setdefault("last_check_time", None)
    cfg.setdefault("label", label)
    cfg.setdefault("browser_cookie", "")
    _apply_defaults(
        cfg,
        "prowlarr",
        {
            "enabled": False,
            "host": "",
            "port": 9696,
            "api_key": "",
            "auto_update_on_save": False,
        },
    )
    # MAM cookie-validity tracking (response-based, see classify_mam_response)
    cfg.setdefault("mam_invalid_notified", False)
    cfg.setdefault("mam_invalid_since", None)
    cfg.setdefault("last_mam_valid_check", None)
    return cfg


def save_session(cfg: dict[str, Any], old_label: str | None = None) -> None:
    """Persist a session configuration to disk.

    If ``old_label`` is provided and different from the new label the
    existing file will be renamed. The function ensures the containing
    directory exists and writes the YAML representation of ``cfg``.
    """
    if not (label := cfg.get("label")):
        raise ValueError("Session label is required to save a session.")
    path = get_session_path(label)
    if old_label and old_label != label and (old_path := get_session_path(old_label)).exists():
        old_path.rename(path)
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    cfg.setdefault("browser_cookie", "")
    with _LOCK, path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(cfg, f)


def get_default_config(label: str | None = None) -> dict[str, Any]:
    """Return a default configuration dictionary used for new sessions.

    The returned structure matches the shape expected by the rest of the
    application and is safe to mutate by callers.
    """
    return {
        "label": label or "",
        "mam": {
            "mam_id": "",
            "session_type": "ip",
            "ip_monitoring_mode": "auto",  # "auto", "manual", "static"
            "auto_purchase": {"wedge": False, "vip": False, "upload": False},
        },
        "browser_cookie": "",
        "mam_ip": "",
        "proxy": {"host": "", "port": 0, "username": "", "password": ""},
        "last_check_time": None,
        "perk_automation": {},
    }


def load_config() -> dict[str, Any]:
    """Load the global default configuration from CONFIG_PATH.

    If the config file does not exist returns a default config. Ensures a
    few expected keys are present before returning.
    """
    if not CONFIG_PATH.exists():
        return get_default_config()
    with _LOCK, CONFIG_PATH.open(encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or get_default_config()
    cfg.setdefault("mam_ip", "")
    cfg.setdefault("last_check_time", None)
    cfg.setdefault("label", "")
    return cfg


def save_config(cfg: dict[str, Any]) -> None:
    """Persist the given global configuration to CONFIG_PATH.

    Ensures the config directory exists and writes the YAML file.
    """
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with _LOCK, CONFIG_PATH.open("w", encoding="utf-8") as f:
        yaml.safe_dump(cfg, f)


def delete_session(label: str) -> None:
    """Delete the session file for a given label if it exists."""
    if (path := get_session_path(label)).exists():
        path.unlink()
